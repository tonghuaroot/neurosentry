// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/correlate"
	"github.com/neurosentry/neurosentry/pkg/fleet"
	"github.com/neurosentry/neurosentry/pkg/incident"
	"github.com/neurosentry/neurosentry/pkg/mcp"
	"github.com/neurosentry/neurosentry/pkg/platform"
)

//go:embed dashboard.html
var dashboardHTML string

type Config struct {
	Enabled    bool   `mapstructure:"enabled" yaml:"enabled"`
	ListenAddr string `mapstructure:"listen_addr" yaml:"listen_addr"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:    false,
		ListenAddr: ":8080",
	}
}

type StatusResponse struct {
	Version      string `json:"version"`
	Uptime       string `json:"uptime"`
	StartedAt    string `json:"started_at"`
	AuthRequired bool   `json:"auth_required"`
}

type AuditResponse struct {
	Total      int            `json:"total"`
	ChainValid bool           `json:"chain_valid"`
	Entries    []*audit.Entry `json:"entries"`
}

type Server struct {
	cfg            Config
	mux            *http.ServeMux
	server         *http.Server
	auditChain     *audit.Chain
	mcpInterceptor *mcp.Interceptor
	startedAt      time.Time

	sseClients   map[chan []byte]struct{}
	sseClientsMu sync.Mutex
	sseEventID   uint64

	limiter *rateLimiter

	// Platform control-plane (optional). When set via EnablePlatform, the
	// management API (auth, tenants, users) is served and protected by RBAC.
	auth       *platform.Authenticator
	mw         *platform.Middleware
	tenants    platform.TenantStore
	users      platform.UserStore
	loginGuard *platform.LoginGuard
	oidc       *platform.OIDCProvider
	oidcTenant string
	saml       *platform.SAMLProvider
	samlTenant string
	scimToken  string
	scimTenant string
	fleet      *fleet.Registry
	fleetToken string

	// correlationSource returns recent cross-layer findings for the dashboard.
	correlationSource func(limit int) []correlate.Finding
	eventsSource      func(limit int) []correlate.Signal
	// detections library management (rule catalog + enable/disable).
	detectionsList    func() []correlate.DetectionInfo
	detectionToggle   func(id string, on bool) bool
	detectionAdd      func(spec correlate.RuleSpec) (string, error)
	detectionUpdate   func(spec correlate.RuleSpec) (correlate.Rule, error)
	detectionRemove   func(id string) error
	detectionValidate func() []correlate.ValidationResult
	// kbSource, when set, is the live knowledge base (builtin + custom rules);
	// otherwise the static builtin KB is served.
	kbSource          func() []correlate.KBEntry
	suppressionList   func() []correlate.SuppressionInfo
	suppressionAdd    func(correlate.SuppressionSpec) (string, error)
	suppressionRemove func(id string) error
	learningGet       func() bool
	learningSet       func(bool)
	breakerGet        func() (bool, int64)
	breakerSet        func(bool)
	selfProtect       func() any
	durableAudit      audit.Store
	readyFn           func() (bool, map[string]any)
	// cases is the incident/case store (SOC workbench).
	cases *incident.Store
	// configProvider returns a redacted view of the effective configuration.
	configProvider func() map[string]any
	// notifyTest sends a test alert; returns (delivered, channels).
	notifyTest func() (int, int)
	// notifyConfigGet/Set expose the runtime-editable webhook/slack config.
	notifyConfigGet func() map[string]any
	notifyConfigSet func(webhook, slack, minSev string) (int, error)
	// inventory providers (typed data lives in pkg/agent; kept generic to
	// avoid an import cycle).
	inventoryAssets     func() any
	inventorySummary    func() any
	inventoryRescan     func() (any, error)
	inventoryScope      func() ([]string, []string)
	inventoryAddPath    func(string)
	inventoryRemovePath func(string)
	// responseHandler executes EDR-like response actions.
	responseHandler func(action string, params map[string]string) (string, error)

	// networkBlocklist returns (enforcing, blocked destinations) for the egress
	// blocklist view.
	networkBlocklist func() (bool, []string)

	// trends holds recent time-series samples for the Overview sparklines.
	trends *trendSeries
	stopCh chan struct{}
}

// trendSeries is a bounded ring of periodic metric samples.
type trendSeries struct {
	mu      sync.Mutex
	cap     int
	events  []float64
	threats []float64
	cases   []float64
	mcp     []float64
}

func newTrendSeries(capacity int) *trendSeries { return &trendSeries{cap: capacity} }

func (t *trendSeries) push(events, threats, cases, mcp float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	push := func(s []float64, v float64) []float64 {
		s = append(s, v)
		if len(s) > t.cap {
			s = s[len(s)-t.cap:]
		}
		return s
	}
	t.events = push(t.events, events)
	t.threats = push(t.threats, threats)
	t.cases = push(t.cases, cases)
	t.mcp = push(t.mcp, mcp)
}

func (t *trendSeries) snapshot() map[string][]float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := func(s []float64) []float64 { o := make([]float64, len(s)); copy(o, s); return o }
	return map[string][]float64{
		"events": cp(t.events), "threats": cp(t.threats), "cases": cp(t.cases), "mcp": cp(t.mcp),
	}
}

func (s *Server) handleTrends(w http.ResponseWriter, _ *http.Request) {
	if s.trends == nil {
		writeJSON(w, map[string][]float64{})
		return
	}
	writeJSON(w, s.trends.snapshot())
}

// sample records one time-series point from the current live sources.
func (s *Server) sample() {
	if s.trends == nil {
		return
	}
	var events, threats, cases, mcp float64
	if s.auditChain != nil {
		events = float64(s.auditChain.Len())
	}
	if s.correlationSource != nil {
		threats = float64(len(s.correlationSource(1000)))
	}
	if s.cases != nil {
		cases = float64(s.cases.Stats().Open)
	}
	if s.mcpInterceptor != nil {
		mcp = float64(s.mcpInterceptor.Stats().TotalCalls)
	}
	s.trends.push(events, threats, cases, mcp)
}

// SetCaseStore wires the incident/case store into the case-management API.
func (s *Server) SetCaseStore(store *incident.Store) { s.cases = store }

// SetConfigProvider wires a redacted effective-configuration view into the API.
func (s *Server) SetConfigProvider(fn func() map[string]any) { s.configProvider = fn }

// SetNotifyTester wires a "send a test alert" action; it returns how many
// channels the test reached and how many are configured.
func (s *Server) SetNotifyTester(fn func() (delivered, channels int)) { s.notifyTest = fn }

// SetNotifyConfigurator wires the runtime-editable webhook/slack notification
// config (view + set).
func (s *Server) SetNotifyConfigurator(get func() map[string]any, set func(webhook, slack, minSev string) (int, error)) {
	s.notifyConfigGet = get
	s.notifyConfigSet = set
}

// handleNotifyConfig views (GET) or sets (POST) the webhook/slack channels and
// threshold. Gated on PermManageAlerts (the view can include the URLs).
func (s *Server) handleNotifyConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if s.notifyConfigGet == nil {
			writeJSON(w, map[string]any{"channels": 0})
			return
		}
		writeJSON(w, s.notifyConfigGet())
		return
	}
	if s.notifyConfigSet == nil {
		writeError(w, http.StatusServiceUnavailable, "notifications not configurable")
		return
	}
	var req struct {
		WebhookURL  string `json:"webhook_url"`
		SlackURL    string `json:"slack_url"`
		MinSeverity string `json:"min_severity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	n, err := s.notifyConfigSet(req.WebhookURL, req.SlackURL, req.MinSeverity)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("notify:config", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"channels": n, "min_severity": req.MinSeverity})
	writeJSON(w, map[string]any{"ok": true, "channels": n})
}

// SetInventoryProvider wires the model-asset inventory (assets + summary).
func (s *Server) SetInventoryProvider(assets, summary func() any) {
	s.inventoryAssets = assets
	s.inventorySummary = summary
}

// SetInventoryControls wires on-demand rescan and editable scan scope (paths).
func (s *Server) SetInventoryControls(rescan func() (any, error), scope func() ([]string, []string), addPath, removePath func(string)) {
	s.inventoryRescan = rescan
	s.inventoryScope = scope
	s.inventoryAddPath = addPath
	s.inventoryRemovePath = removePath
}

// SetResponseHandler wires the response-action executor (EDR-like: trust a PID,
// add a protected extension, ...). Returns a human-readable result or an error.
func (s *Server) SetResponseHandler(fn func(action string, params map[string]string) (string, error)) {
	s.responseHandler = fn
}

func (s *Server) handleResponse(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string            `json:"action"`
		Params map[string]string `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Action == "" {
		writeError(w, http.StatusBadRequest, "action required")
		return
	}
	if s.responseHandler == nil {
		writeError(w, http.StatusServiceUnavailable, "no response handler configured")
		return
	}
	result, err := s.responseHandler(req.Action, req.Params)
	caller := platform.PrincipalFromContext(r.Context())
	if err != nil {
		s.recordAdminAudit("response:failed", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"action": req.Action, "error": err.Error()})
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A response action is a security-relevant control-plane change — audit it.
	s.recordAdminAudit("response:"+req.Action, audit.SeverityHigh, callerEmail(caller), callerID(caller), map[string]any{"params": fmt.Sprintf("%v", req.Params), "result": result})
	writeJSON(w, map[string]any{"ok": true, "result": result})
}

func (s *Server) handleInventory(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{}
	if s.inventoryAssets != nil {
		out["assets"] = s.inventoryAssets()
	}
	if s.inventorySummary != nil {
		out["summary"] = s.inventorySummary()
	}
	if s.inventoryScope != nil {
		paths, exts := s.inventoryScope()
		if paths == nil {
			paths = []string{}
		}
		if exts == nil {
			exts = []string{}
		}
		out["scan_paths"] = paths
		out["extensions"] = exts
	}
	writeJSON(w, out)
}

// handleInventoryRescan runs an on-demand model-asset scan.
func (s *Server) handleInventoryRescan(w http.ResponseWriter, r *http.Request) {
	if s.inventoryRescan == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory rescan not available")
		return
	}
	summary, err := s.inventoryRescan()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("inventory:rescan", audit.SeverityInfo, callerEmail(caller), callerID(caller), nil)
	writeJSON(w, map[string]any{"ok": true, "summary": summary})
}

// handleInventoryPaths adds or removes a scan path, then rescans.
func (s *Server) handleInventoryPaths(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"` // add | remove
		Path   string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeError(w, http.StatusBadRequest, "path required")
		return
	}
	switch req.Action {
	case "add":
		if s.inventoryAddPath == nil {
			writeError(w, http.StatusServiceUnavailable, "not available")
			return
		}
		s.inventoryAddPath(req.Path)
	case "remove":
		if s.inventoryRemovePath == nil {
			writeError(w, http.StatusServiceUnavailable, "not available")
			return
		}
		s.inventoryRemovePath(req.Path)
	default:
		writeError(w, http.StatusBadRequest, "action must be add or remove")
		return
	}
	var summary any
	if s.inventoryRescan != nil {
		summary, _ = s.inventoryRescan()
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("inventory:path_"+req.Action, audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"path": req.Path})
	writeJSON(w, map[string]any{"ok": true, "summary": summary})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if s.notifyTest == nil {
		writeJSON(w, map[string]any{"enabled": false, "message": "notifications not configured"})
		return
	}
	delivered, channels := s.notifyTest()
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("notify:test", audit.SeverityInfo, callerEmail(caller), callerID(caller), map[string]any{"delivered": delivered, "channels": channels})
	writeJSON(w, map[string]any{"enabled": true, "delivered": delivered, "channels": channels})
}

func (s *Server) handleConfig(w http.ResponseWriter, _ *http.Request) {
	if s.configProvider == nil {
		writeJSON(w, map[string]any{})
		return
	}
	writeJSON(w, s.configProvider())
}

func (s *Server) handleCases(w http.ResponseWriter, r *http.Request) {
	if s.cases == nil {
		writeJSON(w, map[string]any{"cases": []any{}, "stats": incident.Stats{}})
		return
	}
	f := incident.Filter{
		Status:   incident.Status(r.URL.Query().Get("status")),
		Severity: r.URL.Query().Get("severity"),
		Limit:    100,
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			f.Limit = n
		}
	}
	writeJSON(w, map[string]any{"cases": s.cases.List(f), "stats": s.cases.Stats()})
}

// handleCaseCreate promotes a finding to a managed case (idempotent — an active
// case for the same rule+PID is reused, matching the auto-grouping behavior).
func (s *Server) handleCaseCreate(w http.ResponseWriter, r *http.Request) {
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "case store unavailable")
		return
	}
	var f correlate.Finding
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding body")
		return
	}
	if f.Rule == "" && f.RuleID == "" {
		writeError(w, http.StatusBadRequest, "finding rule required")
		return
	}
	c := s.cases.Add(f)
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("case:created", audit.SeverityInfo, callerEmail(caller), callerID(caller), map[string]any{"case_id": c.ID, "rule": c.Rule, "pid": c.PID})
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"case": c})
}

func (s *Server) handleCaseStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id := r.PathValue("id")
	if s.cases == nil || !s.cases.SetStatus(id, incident.Status(req.Status)) {
		writeError(w, http.StatusNotFound, "unknown case or invalid status")
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("case:status_change", audit.SeverityInfo, callerEmail(caller), callerID(caller), map[string]any{"case_id": id, "status": req.Status})
	writeJSON(w, map[string]any{"id": id, "status": req.Status})
}

func (s *Server) handleCaseAssign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id := r.PathValue("id")
	if s.cases == nil || !s.cases.Assign(id, req.Assignee) {
		writeError(w, http.StatusNotFound, "unknown case")
		return
	}
	writeJSON(w, map[string]any{"id": id, "assignee": req.Assignee})
}

func (s *Server) handleCaseNote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
		writeError(w, http.StatusBadRequest, "note text required")
		return
	}
	id := r.PathValue("id")
	author := "operator"
	if p := platform.PrincipalFromContext(r.Context()); p != nil {
		author = p.Email
	}
	if s.cases == nil {
		writeError(w, http.StatusNotFound, "unknown case")
		return
	}
	n, ok := s.cases.AddNote(id, author, req.Text)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown case")
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("case:note:add", audit.SeverityLow, callerEmail(caller), callerID(caller), map[string]any{"case": id, "note": n.ID})
	writeJSON(w, map[string]any{"id": id, "ok": true, "note": n})
}

// handleCaseNoteEdit updates a note's text, keeping the prior text as a
// diffable revision. POST /api/cases/{id}/note/{noteId}/edit
func (s *Server) handleCaseNoteEdit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
		writeError(w, http.StatusBadRequest, "note text required")
		return
	}
	id, noteID := r.PathValue("id"), r.PathValue("noteId")
	editor := "operator"
	if p := platform.PrincipalFromContext(r.Context()); p != nil {
		editor = p.Email
	}
	if s.cases == nil {
		writeError(w, http.StatusNotFound, "unknown case")
		return
	}
	n, ok := s.cases.EditNote(id, noteID, editor, req.Text)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown case or note")
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("case:note:edit", audit.SeverityLow, callerEmail(caller), callerID(caller), map[string]any{"case": id, "note": noteID, "revisions": len(n.Revisions)})
	writeJSON(w, map[string]any{"id": id, "ok": true, "note": n})
}

// handleCaseNoteDelete soft-deletes a note (tombstone, reversible).
// POST /api/cases/{id}/note/{noteId}/delete
func (s *Server) handleCaseNoteDelete(w http.ResponseWriter, r *http.Request) {
	id, noteID := r.PathValue("id"), r.PathValue("noteId")
	actor := "operator"
	if p := platform.PrincipalFromContext(r.Context()); p != nil {
		actor = p.Email
	}
	if s.cases == nil {
		writeError(w, http.StatusNotFound, "unknown case or note")
		return
	}
	n, ok := s.cases.DeleteNote(id, noteID, actor)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown case or note")
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("case:note:delete", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"case": id, "note": noteID})
	writeJSON(w, map[string]any{"id": id, "ok": true, "note": n})
}

// handleCaseNoteRestore clears a note's deletion tombstone.
// POST /api/cases/{id}/note/{noteId}/restore
func (s *Server) handleCaseNoteRestore(w http.ResponseWriter, r *http.Request) {
	id, noteID := r.PathValue("id"), r.PathValue("noteId")
	if s.cases == nil {
		writeError(w, http.StatusNotFound, "unknown case or note")
		return
	}
	n, ok := s.cases.RestoreNote(id, noteID)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown case or note")
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("case:note:restore", audit.SeverityLow, callerEmail(caller), callerID(caller), map[string]any{"case": id, "note": noteID})
	writeJSON(w, map[string]any{"id": id, "ok": true, "note": n})
}

// SetCorrelationSource wires the correlation engine's recent-findings feed into
// the dashboard API.
func (s *Server) SetCorrelationSource(fn func(limit int) []correlate.Finding) {
	s.correlationSource = fn
}

// SetEventsSource wires the raw ingested-signal feed (telemetry behind findings)
// into the dashboard's Events view.
func (s *Server) SetEventsSource(fn func(limit int) []correlate.Signal) {
	s.eventsSource = fn
}

func (s *Server) handleRawEvents(w http.ResponseWriter, r *http.Request) {
	limit := 500
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	var sigs []correlate.Signal
	if s.eventsSource != nil {
		sigs = s.eventsSource(limit)
	}
	// Newest first for the table.
	out := make([]correlate.Signal, 0, len(sigs))
	for i := len(sigs) - 1; i >= 0; i-- {
		out = append(out, sigs[i])
	}
	writeJSON(w, map[string]any{"events": out, "total": len(out)})
}

// SetDetectionsProvider wires the detection rule catalog (list + toggle) into
// the management API.
func (s *Server) SetDetectionsProvider(list func() []correlate.DetectionInfo, toggle func(string, bool) bool) {
	s.detectionsList = list
	s.detectionToggle = toggle
}

// SetDurableAuditStore wires the durable audit backend (SQLite or Postgres) so
// the API can report retained volume and re-verify the hash chain at rest.
func (s *Server) SetDurableAuditStore(store audit.Store) { s.durableAudit = store }

func (s *Server) handleDurableAudit(w http.ResponseWriter, _ *http.Request) {
	if s.durableAudit == nil {
		writeError(w, http.StatusServiceUnavailable, "durable audit store not configured")
		return
	}
	retained, err := s.durableAudit.Count()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	verified, verr := s.durableAudit.VerifyChain()
	resp := map[string]any{
		"retained":      retained,
		"verified_rows": verified,
		"integrity_ok":  verr == nil,
	}
	if verr != nil {
		resp["integrity_error"] = verr.Error()
	}
	writeJSON(w, resp)
}

// SetSuppressionManager wires false-positive suppression management.
func (s *Server) SetSuppressionManager(list func() []correlate.SuppressionInfo, add func(correlate.SuppressionSpec) (string, error), remove func(string) error) {
	s.suppressionList = list
	s.suppressionAdd = add
	s.suppressionRemove = remove
}

func (s *Server) handleSuppressions(w http.ResponseWriter, _ *http.Request) {
	var list []correlate.SuppressionInfo
	if s.suppressionList != nil {
		list = s.suppressionList()
	}
	writeJSON(w, map[string]any{"suppressions": list, "total": len(list)})
}

func (s *Server) handleSuppressionCreate(w http.ResponseWriter, r *http.Request) {
	if s.suppressionAdd == nil {
		writeError(w, http.StatusServiceUnavailable, "suppressions unavailable")
		return
	}
	var spec correlate.SuppressionSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid suppression spec")
		return
	}
	id, err := s.suppressionAdd(spec)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("suppression:created", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"id": id, "rule_id": spec.RuleID, "reason": spec.Reason})
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": id})
}

func (s *Server) handleSuppressionDelete(w http.ResponseWriter, r *http.Request) {
	if s.suppressionRemove == nil {
		writeError(w, http.StatusServiceUnavailable, "suppressions unavailable")
		return
	}
	id := r.PathValue("id")
	if err := s.suppressionRemove(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("suppression:deleted", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"id": id})
	writeJSON(w, map[string]any{"id": id, "deleted": true})
}

// SetDetectionValidator wires the purple-team detection-efficacy check.
func (s *Server) SetDetectionValidator(fn func() []correlate.ValidationResult) {
	s.detectionValidate = fn
}

// SetSelfProtectProvider wires the anti-tamper self-protection status view.
func (s *Server) SetSelfProtectProvider(fn func() any) { s.selfProtect = fn }

func (s *Server) handleSelfProtect(w http.ResponseWriter, _ *http.Request) {
	if s.selfProtect == nil {
		writeError(w, http.StatusServiceUnavailable, "self-protection not enabled")
		return
	}
	writeJSON(w, s.selfProtect())
}

// SetBreakerManager wires the automated circuit breaker's arm/disarm + status.
func (s *Server) SetBreakerManager(get func() (bool, int64), set func(bool)) {
	s.breakerGet = get
	s.breakerSet = set
}

func (s *Server) handleBreaker(w http.ResponseWriter, r *http.Request) {
	if s.breakerSet == nil {
		writeError(w, http.StatusServiceUnavailable, "circuit breaker unavailable")
		return
	}
	var req struct {
		Armed bool `json:"armed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.breakerSet(req.Armed)
	caller := platform.PrincipalFromContext(r.Context())
	action := "breaker:disarmed"
	if req.Armed {
		action = "breaker:armed"
	}
	s.recordAdminAudit(action, audit.SeverityHigh, callerEmail(caller), callerID(caller), map[string]any{"armed": req.Armed})
	writeJSON(w, map[string]any{"armed": req.Armed})
}

// SetLearningManager wires baseline/learning-mode read+toggle.
func (s *Server) SetLearningManager(get func() bool, set func(bool)) {
	s.learningGet = get
	s.learningSet = set
}

func (s *Server) handleLearning(w http.ResponseWriter, r *http.Request) {
	if s.learningSet == nil {
		writeError(w, http.StatusServiceUnavailable, "learning mode unavailable")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.learningSet(req.Enabled)
	caller := platform.PrincipalFromContext(r.Context())
	action := "detections:enforce_enabled"
	if req.Enabled {
		action = "detections:learning_enabled"
	}
	s.recordAdminAudit(action, audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"learning": req.Enabled})
	writeJSON(w, map[string]any{"learning": req.Enabled})
}

func (s *Server) handleCoverage(w http.ResponseWriter, _ *http.Request) {
	if s.detectionsList == nil {
		writeError(w, http.StatusServiceUnavailable, "detection catalog unavailable")
		return
	}
	writeJSON(w, correlate.ComputeCoverage(s.detectionsList()))
}

func (s *Server) handleDetectionValidate(w http.ResponseWriter, _ *http.Request) {
	if s.detectionValidate == nil {
		writeError(w, http.StatusServiceUnavailable, "detection validation unavailable")
		return
	}
	results := s.detectionValidate()
	passed := 0
	for _, r := range results {
		if r.Fired {
			passed++
		}
	}
	writeJSON(w, map[string]any{
		"results": results,
		"total":   len(results),
		"passed":  passed,
		"healthy": passed == len(results),
	})
}

// SetDetectionMutators wires runtime custom-rule creation/removal (detection-as-code).
func (s *Server) SetDetectionMutators(add func(correlate.RuleSpec) (string, error), remove func(string) error) {
	s.detectionAdd = add
	s.detectionRemove = remove
}

// SetDetectionUpdater wires in-place editing of an existing custom rule.
func (s *Server) SetDetectionUpdater(update func(correlate.RuleSpec) (correlate.Rule, error)) {
	s.detectionUpdate = update
}

// SetKBSource wires the live knowledge base (builtin + custom rules). When unset,
// the static builtin KB is served.
func (s *Server) SetKBSource(fn func() []correlate.KBEntry) { s.kbSource = fn }

func (s *Server) handleDetectionCreate(w http.ResponseWriter, r *http.Request) {
	if s.detectionAdd == nil {
		writeError(w, http.StatusServiceUnavailable, "custom detections unavailable")
		return
	}
	var spec correlate.RuleSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule spec")
		return
	}
	id, err := s.detectionAdd(spec)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("detection:created", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"rule_id": id, "name": spec.Name})
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": id})
}

// handleDetectionUpdate edits an existing custom rule in place. The path ID wins
// over any ID in the body. Unknown or builtin rules -> 404; an invalid spec ->
// 400. On success the rule keeps its enabled state and fire count.
func (s *Server) handleDetectionUpdate(w http.ResponseWriter, r *http.Request) {
	if s.detectionUpdate == nil {
		writeError(w, http.StatusServiceUnavailable, "custom detections unavailable")
		return
	}
	var spec correlate.RuleSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule spec")
		return
	}
	spec.ID = r.PathValue("id")
	rule, err := s.detectionUpdate(spec)
	if err != nil {
		if errors.Is(err, correlate.ErrRuleNotFound) || errors.Is(err, correlate.ErrRuleNotCustom) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("detection:updated", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"rule_id": rule.ID, "name": rule.Name})
	writeJSON(w, map[string]any{"id": rule.ID})
}

func (s *Server) handleDetectionDelete(w http.ResponseWriter, r *http.Request) {
	if s.detectionRemove == nil {
		writeError(w, http.StatusServiceUnavailable, "custom detections unavailable")
		return
	}
	id := r.PathValue("id")
	if err := s.detectionRemove(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("detection:deleted", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"rule_id": id})
	writeJSON(w, map[string]any{"id": id, "deleted": true})
}

func (s *Server) handleDetections(w http.ResponseWriter, _ *http.Request) {
	var dets []correlate.DetectionInfo
	if s.detectionsList != nil {
		dets = s.detectionsList()
	}
	learning := false
	if s.learningGet != nil {
		learning = s.learningGet()
	}
	out := map[string]any{"detections": dets, "total": len(dets), "learning": learning}
	if s.breakerGet != nil {
		armed, trips := s.breakerGet()
		out["breaker"] = map[string]any{"armed": armed, "trips": trips}
	}
	writeJSON(w, out)
}

// SetNetworkBlocklist wires the egress-blocklist source (enforcing state + the
// blocked destinations). Add/remove is done through the response handler
// (block_destination / unblock_destination).
func (s *Server) SetNetworkBlocklist(fn func() (bool, []string)) { s.networkBlocklist = fn }

// handleNetworkBlocklist returns the egress enforcement state and the current
// blocked destinations.
func (s *Server) handleNetworkBlocklist(w http.ResponseWriter, _ *http.Request) {
	enforcing, dests := false, []string{}
	if s.networkBlocklist != nil {
		enforcing, dests = s.networkBlocklist()
	}
	if dests == nil {
		dests = []string{}
	}
	writeJSON(w, map[string]any{"enforcing": enforcing, "destinations": dests})
}

// handleKB serves the detection knowledge base: an analyst-facing article for
// every builtin rule (what it detects, why it matters, how to respond, common
// false positives) plus the signal/event glossary.
func (s *Server) handleKB(w http.ResponseWriter, _ *http.Request) {
	entries := correlate.KnowledgeBase()
	if s.kbSource != nil {
		entries = s.kbSource()
	}
	writeJSON(w, map[string]any{
		"entries":  entries,
		"glossary": correlate.SignalGlossary(),
	})
}

type toggleRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleDetectionToggle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req toggleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if s.detectionToggle == nil || !s.detectionToggle(id, req.Enabled) {
		writeError(w, http.StatusNotFound, "unknown detection rule")
		return
	}
	action := "detection:disabled"
	if req.Enabled {
		action = "detection:enabled"
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit(action, audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"rule_id": id})
	writeJSON(w, map[string]any{"id": id, "enabled": req.Enabled})
}

// handleSearch queries the audit chain with full-text, severity, event-type
// prefix, and time-range filters plus pagination — the SOC "search" surface.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(r.URL.Query().Get("q"))
	sev := r.URL.Query().Get("severity")
	typePrefix := r.URL.Query().Get("type")
	limit, offset := 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	var since, until time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		since, _ = time.Parse(time.RFC3339, v)
	}
	if v := r.URL.Query().Get("until"); v != "" {
		until, _ = time.Parse(time.RFC3339, v)
	}

	entries := s.auditChain.Entries()
	// Newest first.
	matched := make([]*audit.Entry, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if sev != "" && string(e.Severity) != sev {
			continue
		}
		if typePrefix != "" && !strings.HasPrefix(e.EventType, typePrefix) {
			continue
		}
		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		if !until.IsZero() && e.Timestamp.After(until) {
			continue
		}
		if q != "" && !entryMatchesText(e, q) {
			continue
		}
		matched = append(matched, e)
	}
	total := len(matched)
	end := offset + limit
	if offset > total {
		offset = total
	}
	if end > total {
		end = total
	}
	writeJSON(w, map[string]any{
		"total":   total,
		"offset":  offset,
		"limit":   limit,
		"results": matched[offset:end],
	})
}

// entryMatchesText reports whether q occurs in the entry's type or any detail.
func entryMatchesText(e *audit.Entry, q string) bool {
	if strings.Contains(strings.ToLower(e.EventType), q) {
		return true
	}
	for k, v := range e.Details {
		if strings.Contains(strings.ToLower(k), q) || strings.Contains(strings.ToLower(fmt.Sprintf("%v", v)), q) {
			return true
		}
	}
	if e.Actor != nil && strings.Contains(strings.ToLower(e.Actor.Comm), q) {
		return true
	}
	return false
}

func (s *Server) handleCorrelateFindings(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	var findings []correlate.Finding
	if s.correlationSource != nil {
		findings = s.correlationSource(limit)
	}
	writeJSON(w, map[string]any{"findings": findings, "total": len(findings)})
}

// EnablePlatform wires the multi-tenant control plane into the server: login,
// identity, and tenant/user management endpoints, each guarded by RBAC. Call
// after NewServer and before Start. Idempotent per server.
func (s *Server) EnablePlatform(auth *platform.Authenticator, tenants platform.TenantStore, users platform.UserStore) {
	s.auth = auth
	s.tenants = tenants
	s.users = users
	s.mw = platform.NewMiddleware(auth.Issuer(), users)
	s.loginGuard = platform.NewLoginGuard(5, 15*time.Minute, 15*time.Minute)
	s.registerPlatformRoutes()
	s.registerSCIMRoutes()
	s.registerFleetRoutes()
}

func NewServer(cfg Config, auditChain *audit.Chain, mcpInterceptor *mcp.Interceptor) *Server {
	s := &Server{
		cfg:            cfg,
		auditChain:     auditChain,
		mcpInterceptor: mcpInterceptor,
		startedAt:      time.Now(),
		sseClients:     make(map[chan []byte]struct{}),
		limiter:        newRateLimiter(50, 100), // 50 req/s, burst 100, per client IP
		trends:         newTrendSeries(120),     // ~20 min at 10s cadence
		stopCh:         make(chan struct{}),
	}

	mux := http.NewServeMux()

	// Open endpoints: liveness and status (status reports whether auth is required).
	mux.HandleFunc("/api/health", onlyGET(s.handleHealth))
	mux.HandleFunc("/healthz", onlyGET(s.handleLiveness))
	mux.HandleFunc("/readyz", onlyGET(s.handleReadiness))
	mux.HandleFunc("/api/status", onlyGET(s.handleStatus))
	// Security telemetry: open in demo mode, RBAC-gated when the platform is on.
	mux.HandleFunc("/api/audit", s.dataGuard(platform.PermViewAudit, s.handleAudit))
	mux.HandleFunc("/api/audit/verify", s.dataGuard(platform.PermViewAudit, s.handleAuditVerify))
	mux.HandleFunc("/api/audit/export", s.dataGuard(platform.PermExportAudit, s.handleAuditExport))
	mux.HandleFunc("/api/audit/durable", s.dataGuard(platform.PermViewAudit, s.handleDurableAudit))
	mux.HandleFunc("/api/export/siem", s.dataGuard(platform.PermExportAudit, s.handleSIEMExport))
	mux.HandleFunc("/api/report", s.dataGuard(platform.PermViewAudit, s.handleReport))
	mux.HandleFunc("/api/mcp/stats", s.dataGuard(platform.PermViewEvents, s.handleMCPStats))
	mux.HandleFunc("/api/mcp/events", s.dataGuard(platform.PermViewEvents, s.handleMCPEvents))
	mux.HandleFunc("/api/correlate/findings", s.dataGuard(platform.PermViewEvents, s.handleCorrelateFindings))
	mux.HandleFunc("/api/events", s.dataGuard(platform.PermViewEvents, s.handleRawEvents))
	mux.HandleFunc("/api/detections", s.dataGuard(platform.PermViewEvents, s.handleDetections))
	mux.HandleFunc("/api/detections/{id}/toggle", s.mutationGuard(platform.PermManagePolicy, s.handleDetectionToggle))
	mux.HandleFunc("/api/detections/validate", s.dataGuard(platform.PermViewEvents, s.handleDetectionValidate))
	mux.HandleFunc("/api/detections/coverage", s.dataGuard(platform.PermViewEvents, s.handleCoverage))
	mux.HandleFunc("/api/kb", s.dataGuard(platform.PermViewEvents, s.handleKB))
	mux.HandleFunc("/api/network/blocklist", s.dataGuard(platform.PermViewEvents, s.handleNetworkBlocklist))
	mux.HandleFunc("/api/detections/learning", s.mutationGuard(platform.PermManagePolicy, s.handleLearning))
	mux.HandleFunc("/api/breaker", s.mutationGuard(platform.PermManagePolicy, s.handleBreaker))
	mux.HandleFunc("/api/selfprotect", s.dataGuard(platform.PermViewEvents, s.handleSelfProtect))
	mux.HandleFunc("/api/suppressions", s.dataGuard(platform.PermViewEvents, s.handleSuppressions))
	mux.HandleFunc("/api/suppressions/create", s.mutationGuard(platform.PermManagePolicy, s.handleSuppressionCreate))
	mux.HandleFunc("/api/suppressions/{id}/delete", s.mutationGuard(platform.PermManagePolicy, s.handleSuppressionDelete))
	mux.HandleFunc("/api/detections/create", s.mutationGuard(platform.PermManagePolicy, s.handleDetectionCreate))
	mux.HandleFunc("/api/detections/{id}/update", s.mutationGuard(platform.PermManagePolicy, s.handleDetectionUpdate))
	mux.HandleFunc("/api/detections/{id}/delete", s.mutationGuard(platform.PermManagePolicy, s.handleDetectionDelete))
	mux.HandleFunc("/api/search", s.dataGuard(platform.PermViewAudit, s.handleSearch))
	mux.HandleFunc("/api/inventory", s.dataGuard(platform.PermViewInventory, s.handleInventory))
	mux.HandleFunc("/api/inventory/rescan", s.mutationGuard(platform.PermManagePolicy, s.handleInventoryRescan))
	mux.HandleFunc("/api/inventory/paths", s.mutationGuard(platform.PermManagePolicy, s.handleInventoryPaths))
	mux.HandleFunc("/api/response", s.mutationGuard(platform.PermManageSystem, s.handleResponse))
	mux.HandleFunc("/api/config", s.dataGuard(platform.PermViewEvents, s.handleConfig))
	mux.HandleFunc("/api/trends", s.dataGuard(platform.PermViewEvents, s.handleTrends))
	mux.HandleFunc("/api/notify/test", s.mutationGuard(platform.PermManageAlerts, s.handleNotifyTest))
	// notify config serves GET (view) + POST (set), so it can't use the
	// GET-only/POST-only guards — require the perm directly for both methods.
	mux.HandleFunc("/api/notify/config", func(w http.ResponseWriter, r *http.Request) {
		if s.mw != nil {
			s.mw.Require(platform.PermManageAlerts, s.handleNotifyConfig)(w, r)
			return
		}
		s.handleNotifyConfig(w, r)
	})
	mux.HandleFunc("/api/cases", s.dataGuard(platform.PermViewEvents, s.handleCases))
	mux.HandleFunc("/api/cases/create", s.mutationGuard(platform.PermManageAlerts, s.handleCaseCreate))
	mux.HandleFunc("/api/cases/{id}/status", s.mutationGuard(platform.PermManageAlerts, s.handleCaseStatus))
	mux.HandleFunc("/api/cases/{id}/assign", s.mutationGuard(platform.PermManageAlerts, s.handleCaseAssign))
	mux.HandleFunc("/api/cases/{id}/note", s.mutationGuard(platform.PermManageAlerts, s.handleCaseNote))
	mux.HandleFunc("/api/cases/{id}/note/{noteId}/edit", s.mutationGuard(platform.PermManageAlerts, s.handleCaseNoteEdit))
	mux.HandleFunc("/api/cases/{id}/note/{noteId}/delete", s.mutationGuard(platform.PermManageAlerts, s.handleCaseNoteDelete))
	mux.HandleFunc("/api/cases/{id}/note/{noteId}/restore", s.mutationGuard(platform.PermManageAlerts, s.handleCaseNoteRestore))
	mux.HandleFunc("/api/events/stream", s.handleSSE)
	mux.HandleFunc("/api/openapi.json", onlyGET(s.handleOpenAPI))
	mux.HandleFunc("/docs", onlyGET(s.handleDocs))
	mux.HandleFunc("/", s.handleDashboard)

	s.mux = mux
	return s
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// recordAdminAudit writes a control-plane action (login, user/tenant/API-key
// changes, permission denials) into the tamper-proof audit chain and pushes it
// to the live feed. This is the admin-action audit trail enterprise/compliance
// (SOC2, ISO 27001) deployments require.
func (s *Server) recordAdminAudit(eventType string, sev audit.Severity, actorEmail, actorID string, details map[string]any) {
	if s.auditChain == nil {
		return
	}
	d := make(map[string]any, len(details)+2)
	for k, v := range details {
		d[k] = v
	}
	if actorEmail != "" {
		d["actor_email"] = actorEmail
	}
	if actorID != "" {
		d["actor_user_id"] = actorID
	}
	e := audit.NewEntry(eventType, sev, d)
	e.SetCategory(audit.CategorySecurity, audit.ClassFinding)
	if err := s.auditChain.Append(e); err == nil {
		if data, err := json.Marshal(e); err == nil {
			s.BroadcastEvent(data)
		}
	}
}

// mutationGuard protects a POST endpoint: open in demo mode, requires the given
// permission when the platform control plane is enabled.
func (s *Server) mutationGuard(perm platform.Permission, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.mw != nil {
			s.mw.Require(perm, h)(w, r)
			return
		}
		h(w, r)
	}
}

func onlyGET(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func (s *Server) Name() string { return "web-dashboard" }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) Start(ctx context.Context) error {
	s.server = &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.limiter.middleware(securityHeaders(s.mux)),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Web dashboard listening on %s", s.cfg.ListenAddr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Web server error: %v", err)
		}
	}()

	// Sample metrics into the trend series for the Overview sparklines.
	go func() {
		s.sample()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.sample()
			}
		}
	}()

	return nil
}

func (s *Server) Stop() error {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) BroadcastEvent(data []byte) {
	s.sseClientsMu.Lock()
	defer s.sseClientsMu.Unlock()
	for ch := range s.sseClients {
		select {
		case ch <- data:
		default:
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// SetReadiness wires a readiness probe: it reports whether the agent is ready to
// serve (components started, kernel support adequate). Used by /readyz for
// Kubernetes readiness gating.
func (s *Server) SetReadiness(fn func() (bool, map[string]any)) {
	s.readyFn = fn
}

// handleLiveness is the Kubernetes liveness probe: 200 while the process is
// running and able to serve. Deliberately cheap and dependency-free so a
// liveness failure means "restart me", not "a dependency is down".
func (s *Server) handleLiveness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"status": "live"})
}

// handleReadiness is the Kubernetes readiness probe: 200 only when the agent is
// ready to do its job, 503 otherwise (so traffic/rollout gates on it). It is
// intentionally unauthenticated — probes cannot present credentials — and
// returns only coarse component/support state, never security telemetry.
func (s *Server) handleReadiness(w http.ResponseWriter, _ *http.Request) {
	ready := true
	detail := map[string]any{}
	if s.readyFn != nil {
		ready, detail = s.readyFn()
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["ready"] = ready
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	writeJSON(w, detail)
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, StatusResponse{
		Version:      "dev",
		Uptime:       time.Since(s.startedAt).Round(time.Second).String(),
		StartedAt:    s.startedAt.Format(time.RFC3339),
		AuthRequired: s.mw != nil,
	})
}

// dataGuard protects a read endpoint: it is open when the platform control
// plane is disabled (simple/demo mode) and requires the given permission when
// the platform is enabled — so no security telemetry is exposed pre-auth.
func (s *Server) dataGuard(perm platform.Permission, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.mw != nil {
			s.mw.Require(perm, h)(w, r)
			return
		}
		h(w, r)
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries := s.auditChain.Entries()
	err := s.auditChain.Verify()

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	writeJSON(w, AuditResponse{
		Total:      s.auditChain.Len(),
		ChainValid: err == nil,
		Entries:    entries,
	})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, _ *http.Request) {
	err := s.auditChain.Verify()
	result := map[string]any{
		"valid":       err == nil,
		"total":       s.auditChain.Len(),
		"verified_at": time.Now().Format(time.RFC3339),
	}
	if err != nil {
		result["error"] = err.Error()
	}
	writeJSON(w, result)
}

func (s *Server) handleAuditExport(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=neurosentry-audit.json")
	entries := s.auditChain.Entries()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"exported_at": time.Now().Format(time.RFC3339),
		"total":       s.auditChain.Len(),
		"chain_valid": s.auditChain.Verify() == nil,
		"entries":     entries,
	})
}

func (s *Server) handleMCPStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.mcpInterceptor.Stats())
}

func (s *Server) handleMCPEvents(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, s.mcpInterceptor.RecentEvents(limit))
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	// When the platform is enabled, the live event stream is security telemetry
	// and must be authenticated. EventSource cannot set headers, so the token is
	// passed as a query parameter (?token=) or via the standard header.
	if s.mw != nil {
		authed := false
		if tok := r.URL.Query().Get("token"); tok != "" {
			if _, err := s.auth.Issuer().Verify(tok); err == nil {
				authed = true
			}
		}
		if !authed && platform.PrincipalFromContext(r.Context()) == nil {
			if auth := r.Header.Get("Authorization"); auth != "" {
				authed = true // header path resolved by middleware elsewhere; best-effort
			}
		}
		if !authed {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan []byte, 64)
	s.sseClientsMu.Lock()
	s.sseClients[ch] = struct{}{}
	s.sseClientsMu.Unlock()

	defer func() {
		s.sseClientsMu.Lock()
		delete(s.sseClients, ch)
		s.sseClientsMu.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-ch:
			s.sseClientsMu.Lock()
			s.sseEventID++
			id := s.sseEventID
			s.sseClientsMu.Unlock()
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", id, data)
			flusher.Flush()
		}
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(dashboardHTML))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
