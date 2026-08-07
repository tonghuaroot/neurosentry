// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/bpf"
	"github.com/neurosentry/neurosentry/pkg/breaker"
	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/correlate"
	"github.com/neurosentry/neurosentry/pkg/fleet"
	"github.com/neurosentry/neurosentry/pkg/incident"
	"github.com/neurosentry/neurosentry/pkg/mcp"
	"github.com/neurosentry/neurosentry/pkg/notify"
	"github.com/neurosentry/neurosentry/pkg/platform"
	"github.com/neurosentry/neurosentry/pkg/policy"
	"github.com/neurosentry/neurosentry/pkg/selfprotect"
	"github.com/neurosentry/neurosentry/pkg/web"
)

// BuildVersion is the agent version reported to the fleet control plane. main
// sets it from the ldflags-injected version at startup.
var BuildVersion = "dev"

// Controller manages the NeuroSentry agent lifecycle
type Controller struct {
	cfg        *config.Config
	bpfMgr     *bpf.Manager
	policy     *policy.Policy
	eventChan  chan Event
	metrics    *MetricsCollector
	secMetrics *SecurityMetrics
	bpfMetrics *BPFMetricsCollector

	// Event processor with sampling support
	eventProcessor *EventProcessor

	// Alert manager (set by initComponents when AlertWebhook is configured)
	alertMgr *AlertManager

	// Audit chain for tamper-proof event logging
	auditChain *audit.Chain
	auditStore *audit.FileStore
	auditDB    audit.Store
	fleetReg   *fleet.Registry
	fleetID    string
	fleetMTLS  *http.Server // dedicated mutual-TLS agent listener (optional)

	// MCP protocol interceptor
	mcpInterceptor *mcp.Interceptor

	// Cross-layer correlation engine (intent x action)
	correlator *correlate.Correlator

	// Incident/case management (finding lifecycle)
	incidents *incident.Store

	// Automated circuit breaker (detection -> auto enforcement)
	breaker *breaker.Breaker

	// Anti-tamper self-defense (integrity baseline over the agent itself)
	selfGuard *selfprotect.Guard

	// Model asset inventory (integrity monitoring)
	inventory *Inventory

	// Alert notification router (Slack/webhook) + runtime-editable config.
	notifier      *notify.Router
	notifyMu      sync.Mutex
	notifyWebhook string
	notifySlack   string
	notifyMinSev  string

	// Web dashboard server
	webServer *web.Server

	// Multi-tenant control plane (identity/RBAC), enabled via config
	platformTenants *platform.MemTenantStore
	platformUsers   *platform.MemUserStore

	// Component management
	components []Component
	mu         sync.RWMutex

	// Readiness: true once all components have started (drives /readyz).
	ready atomic.Bool

	// Shutdown
	cancel     context.CancelFunc
	shutdownWG sync.WaitGroup
}

// Component represents an agent component that can be started/stopped
type Component interface {
	Start(ctx context.Context) error
	Stop() error
	Name() string
}

// NewController creates a new agent controller
func NewController(cfg *config.Config, bpfMgr *bpf.Manager, pol *policy.Policy) (*Controller, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if bpfMgr == nil {
		return nil, fmt.Errorf("BPF manager is required")
	}
	if pol == nil {
		return nil, fmt.Errorf("policy is required")
	}

	ctrl := &Controller{
		cfg:        cfg,
		bpfMgr:     bpfMgr,
		policy:     pol,
		eventChan:  make(chan Event, 1000),
		metrics:    NewMetricsCollector(),
		secMetrics: NewSecurityMetrics(),
		bpfMetrics: NewBPFMetricsCollector(bpfMgr),
		auditChain: audit.NewChain(),
	}

	// Initialize audit store
	if cfg.Audit.Enabled && cfg.Audit.LogPath != "" {
		store, err := audit.NewFileStore(cfg.Audit.LogPath)
		if err != nil {
			log.Printf("Warning: failed to open audit log %s: %v (audit logging disabled)", cfg.Audit.LogPath, err)
		} else {
			ctrl.auditStore = store
		}
	}

	// Durable, queryable audit store (pluggable: SQLite or Postgres). Attached
	// as a chain sink so every entry is persisted before Append returns —
	// surviving restart and the in-memory ring, and queryable at volume for
	// retention/compliance. The backend is selected by cfg.Audit.DBDriver:
	// sqlite uses DBPath, postgres uses DBDSN.
	if cfg.Audit.Enabled {
		driver := cfg.Audit.DBDriver
		if driver == "" {
			driver = "sqlite"
		}
		var dsn string
		switch strings.ToLower(strings.TrimSpace(driver)) {
		case "postgres", "postgresql", "pg", "pgx":
			dsn = cfg.Audit.DBDSN
		default:
			dsn = cfg.Audit.DBPath
		}
		if dsn != "" {
			store, err := audit.OpenStore(driver, dsn)
			if err != nil {
				log.Printf("Warning: failed to open durable audit store (driver=%s): %v", driver, err)
			} else {
				ctrl.auditDB = store
				ctrl.auditChain.AttachSink(store)
				if n, verr := store.Count(); verr == nil {
					log.Printf("Durable audit store online (driver=%s): %d entries retained", driver, n)
				}
			}
		}
	}

	// Initialize MCP interceptor
	mcpPolicy := mcp.NewPolicy()
	if len(cfg.MCP.AllowedTools) > 0 {
		mcpPolicy.SetAllowedTools(cfg.MCP.AllowedTools)
	}
	if len(cfg.MCP.BlockedTools) > 0 {
		mcpPolicy.SetBlockedTools(cfg.MCP.BlockedTools)
	}
	// Block any tool call carrying prompt-injection content flagged by the AI
	// guard, so the gateway enforces intent, not just a tool allowlist.
	_ = mcpPolicy.AddArgumentRule("", "injection", "malicious", "prompt-injection content flagged by the AI guard")
	ctrl.mcpInterceptor = mcp.NewInterceptor(mcpPolicy)

	// Cross-layer correlation engine. Its findings are the highest-signal
	// output NeuroSentry produces (intent x action), so route them to the
	// tamper-proof audit chain and the live dashboard.
	ctrl.correlator = correlate.NewCorrelator(correlate.BuiltinRules())
	ctrl.incidents = incident.NewStore()
	// Restore persisted cases so the SOC workbench survives restarts.
	if ctrl.auditDB != nil {
		if data, ok, _ := ctrl.auditDB.LoadSnapshot("cases"); ok {
			if err := ctrl.incidents.Restore(data); err != nil {
				log.Printf("cases: restore failed: %v", err)
			} else {
				log.Printf("cases: restored durable case store")
			}
		}
	}
	ctrl.inventory = NewInventory()
	ctrl.correlator.OnFinding(ctrl.handleCorrelationFinding)

	// Automated circuit breaker: closes the loop from a high-confidence finding
	// to a kernel-level mitigation. Disarmed unless explicitly enabled.
	ctrl.breaker = breaker.New(breaker.Policy{
		Enabled:       cfg.Breaker.Enabled,
		MinSeverity:   cfg.Breaker.MinSeverity,
		DefaultAction: cfg.Breaker.DefaultAction,
		CooldownSecs:  cfg.Breaker.CooldownSecs,
	})
	if cfg.Breaker.Enabled {
		log.Printf("circuit breaker ARMED (min_severity=%s action=%s) — findings will auto-mitigate",
			ctrl.breaker.Policy().MinSeverity, ctrl.breaker.Policy().DefaultAction)
	}

	// Anti-tamper self-defense: baseline the agent's own binary + config so a
	// later modification/deletion is a critical, tamper-evident finding.
	if cfg.SelfProtect.Enabled {
		ctrl.selfGuard = selfprotect.New()
		var protectPaths []string
		if exe, err := os.Executable(); err == nil {
			protectPaths = append(protectPaths, exe)
		}
		if cfg.ConfigPath != "" {
			protectPaths = append(protectPaths, cfg.ConfigPath)
		}
		if cfg.PolicyPath != "" {
			protectPaths = append(protectPaths, cfg.PolicyPath)
		}
		ctrl.selfGuard.Protect(protectPaths...)
		log.Printf("self-protection ENABLED — integrity baseline over %d agent files", len(protectPaths))
	}

	// Alert notification router — always created so channels can be configured
	// live from the console; seeded from config at startup.
	ctrl.notifier = notify.NewRouter(time.Minute)
	n := ctrl.applyNotify(cfg.Notify.WebhookURL, cfg.Notify.SlackWebhook, cfg.Notify.MinSeverity)
	if n > 0 {
		log.Printf("notify: alert routing enabled (%d channel(s), threshold=%s)", n, ctrl.notifyMinSev)
	}

	return ctrl, nil
}

// handleCorrelationFinding records a cross-layer finding to the audit chain,
// pushes it to the dashboard, and logs it. This is where a "tool call read a
// secret then phoned an LLM" chain becomes an alert.
func (c *Controller) handleCorrelationFinding(f correlate.Finding) {
	log.Printf("[CORRELATION] %s severity=%s pid=%d technique=%s: %s",
		f.Rule, f.Severity, f.PID, f.Technique, f.Description)

	// Open (or group into) a managed case for the SOC workbench.
	if c.incidents != nil {
		c.incidents.Add(f)
	}

	// Route a notification to external channels (threshold-filtered).
	if c.notifier != nil {
		c.notifier.Route(context.Background(), notify.Alert{
			Title:    f.Rule,
			Severity: f.Severity,
			Source:   "correlation",
			Message:  f.Description,
			Fields: map[string]string{
				"rule_id":   f.RuleID,
				"pid":       fmt.Sprintf("%d", f.PID),
				"technique": f.Technique,
			},
		})
	}

	severity := audit.SeverityHigh
	if f.Severity == "critical" {
		severity = audit.SeverityCritical
	} else if f.Severity == "medium" {
		severity = audit.SeverityMedium
	}
	entry := audit.NewEntry("correlation:"+f.Rule, severity, map[string]any{
		"technique":   f.Technique,
		"description": f.Description,
		"pid":         f.PID,
		"chain_len":   len(f.Chain),
	})
	entry.SetCategory(audit.CategorySecurity, audit.ClassFinding)
	if err := c.auditChain.Append(entry); err == nil {
		if c.auditStore != nil {
			_ = c.auditStore.Write(entry)
		}
		if c.webServer != nil {
			data, _ := json.Marshal(entry)
			c.webServer.BroadcastEvent(data)
		}
	}
	if c.secMetrics != nil {
		c.secMetrics.RecordCorrelationFinding(f.Rule, f.Severity, f.Technique)
	}

	// Circuit breaker: close the loop from detection to enforcement. When armed
	// and the finding meets the policy, automatically apply a kernel-level
	// mitigation (e.g. drop the process from the LSM trusted allowlist so its
	// next protected-file access is blocked).
	if c.breaker != nil {
		if d := c.breaker.Evaluate(f.Severity, f.RuleID, f.PID); d.Trip {
			result, rerr := c.executeResponse(d.Action, d.Params)
			brk := audit.NewEntry("breaker:auto_response", audit.SeverityCritical, map[string]any{
				"rule_id": f.RuleID, "action": d.Action, "pid": f.PID,
				"reason": d.Reason, "result": result, "error": errString(rerr),
			})
			brk.SetCategory(audit.CategorySecurity, audit.ClassFinding)
			if err := c.auditChain.Append(brk); err == nil {
				if c.auditStore != nil {
					_ = c.auditStore.Write(brk)
				}
				if c.webServer != nil {
					data, _ := json.Marshal(brk)
					c.webServer.BroadcastEvent(data)
				}
			}
			if rerr != nil {
				log.Printf("[BREAKER] auto-response FAILED action=%s pid=%d: %v", d.Action, f.PID, rerr)
			} else {
				log.Printf("[BREAKER] auto-response action=%s pid=%d: %s", d.Action, f.PID, result)
			}
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// persistCases writes the case store to the durable SQLite snapshot so the SOC
// workbench survives restarts.
func (c *Controller) persistCases() {
	if c.auditDB == nil || c.incidents == nil {
		return
	}
	data, err := c.incidents.Snapshot()
	if err != nil {
		return
	}
	_ = c.auditDB.SaveSnapshot("cases", data, time.Now())
}

// runSelfProtect periodically re-verifies the agent's integrity baseline and
// raises a critical finding on any tamper, routing it through the same
// detection -> audit -> notify -> breaker pipeline as any attack.
func (c *Controller) runSelfProtect(ctx context.Context) {
	c.shutdownWG.Add(1)
	defer c.shutdownWG.Done()

	every := time.Duration(c.cfg.SelfProtect.IntervalSecs) * time.Second
	if every <= 0 {
		every = 60 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, tamper := range c.selfGuard.Verify() {
				log.Printf("[SELF-PROTECT] TAMPER DETECTED %s (%s)", tamper.Path, tamper.Reason)
				// Synthesize a finding so the whole pipeline (audit chain, case,
				// notify, breaker) treats agent tampering as the critical attack
				// it is. PID 0: no single attacker process to auto-mitigate — the
				// value is the loud, tamper-evident alert.
				c.handleCorrelationFinding(correlate.Finding{
					Timestamp:   time.Now(),
					RuleID:      "NS-SELF-001",
					Rule:        "agent-self-tamper",
					Severity:    "critical",
					Technique:   "T1562.001", // Impair Defenses: Disable or Modify Tools
					Description: "the NeuroSentry agent's own " + tamper.Path + " was " + tamper.Reason + " — the security control itself may be under attack",
				})
			}
		}
	}
}

// eventToSignal maps a kernel-layer BPF event into a correlation signal. The
// event timestamp is left zero so the engine stamps ingest time — BPF timestamps
// are boot-relative (ktime), not wall-clock, and would break time windows.
func eventToSignal(e Event) (correlate.Signal, bool) {
	s := correlate.Signal{PID: e.Source.PID, Attributes: map[string]string{}}
	switch e.Type {
	case EventTypeFileAccess, EventTypeFileBlocked:
		s.Layer = correlate.LayerKernelFile
		s.Kind = "file_read"
		s.Attributes["path"] = e.Data.FilePath
	case EventTypeNetworkAllowed, EventTypeNetworkBlocked:
		s.Layer = correlate.LayerKernelNet
		s.Kind = "net_connect"
		s.Attributes["dst"] = e.Data.DstAddr
	case EventTypeModelLoad:
		s.Layer = correlate.LayerModel
		s.Kind = "load"
		s.Attributes["path"] = e.Data.FilePath
	default:
		return s, false
	}
	return s, true
}

// IngestSignal feeds a signal from any layer (MCP proxy, AI gateway, eBPF) into
// the correlation engine. Exported so out-of-controller sources can contribute.
func (c *Controller) IngestSignal(s correlate.Signal) {
	if c.correlator != nil {
		c.correlator.Ingest(s)
	}
	// Surface MCP tool activity on the AI Gateway view: route tool_call signals
	// through the same interceptor/policy the live MCP proxy uses, so replayed
	// and real tool calls both appear there with an allow/block decision.
	if c.mcpInterceptor != nil && s.Layer == correlate.LayerMCP && s.Kind == "tool_call" {
		tc := &mcp.ToolCall{Name: s.Attributes["tool"], Arguments: map[string]any{}}
		if tc.Name == "" {
			tc.Name = "tool_call"
		}
		for k, v := range s.Attributes {
			tc.Arguments[k] = v
		}
		c.mcpInterceptor.Evaluate(tc)
	}
}

// GetCorrelator exposes the correlation engine (e.g. for the web findings API).
func (c *Controller) GetCorrelator() *correlate.Correlator { return c.correlator }

// executeResponse runs an EDR-like response action against the kernel layer.
// Returns a human-readable result. Actions are audited by the caller.
func (c *Controller) executeResponse(action string, params map[string]string) (string, error) {
	switch action {
	case "trust_pid":
		pid, err := strconv.Atoi(params["pid"])
		if err != nil || pid <= 0 {
			return "", fmt.Errorf("valid pid required")
		}
		if err := c.bpfMgr.AddTrustedPID(uint32(pid)); err != nil { //nolint:gosec // G115
			return "", err
		}
		return fmt.Sprintf("PID %d added to the trusted allowlist", pid), nil
	case "untrust_pid":
		pid, err := strconv.Atoi(params["pid"])
		if err != nil || pid <= 0 {
			return "", fmt.Errorf("valid pid required")
		}
		if err := c.bpfMgr.RemoveTrustedPID(uint32(pid)); err != nil { //nolint:gosec // G115
			return "", err
		}
		return fmt.Sprintf("PID %d removed from the trusted allowlist", pid), nil
	case "protect_extension":
		ext := params["extension"]
		if ext == "" {
			return "", fmt.Errorf("extension required")
		}
		if err := c.bpfMgr.AddProtectedExtension(ext); err != nil {
			return "", err
		}
		return fmt.Sprintf("extension %s is now kernel-protected", ext), nil
	case "block_destination":
		ip := net.ParseIP(strings.TrimSpace(params["dst"]))
		if ip == nil {
			return "", fmt.Errorf("valid dst IP required")
		}
		if err := c.bpfMgr.AddBlockedIP(ip); err != nil {
			return "", err
		}
		return fmt.Sprintf("egress to %s is now blocked (drops when block_exfiltration is on)", ip), nil
	case "unblock_destination":
		ip := net.ParseIP(strings.TrimSpace(params["dst"]))
		if ip == nil {
			return "", fmt.Errorf("valid dst IP required")
		}
		if err := c.bpfMgr.RemoveBlockedIP(ip); err != nil {
			return "", err
		}
		return fmt.Sprintf("egress to %s is no longer blocked", ip), nil
	default:
		return "", fmt.Errorf("unknown response action %q", action)
	}
}

// runInventoryScanner scans the protected model paths on startup and every 5
// minutes, flagging integrity changes. It runs as a trusted process so the LSM
// hook lets it read protected model files to hash them.
// applyNotify rebuilds the alert router's channels from the given webhook/slack
// URLs plus any SIEM channels from config, and stores the current config.
// Returns the channel count.
func (c *Controller) applyNotify(webhook, slack, minSev string) int {
	if minSev == "" {
		minSev = "high"
	}
	c.notifyMu.Lock()
	c.notifyWebhook, c.notifySlack, c.notifyMinSev = webhook, slack, minSev
	c.notifyMu.Unlock()
	if c.notifier == nil {
		return 0
	}
	c.notifier.Reset()
	n := 0
	if webhook != "" {
		c.notifier.AddChannel(notify.NewWebhookChannel(webhook), minSev)
		n++
	}
	if slack != "" {
		c.notifier.AddChannel(notify.NewSlackChannel(slack), minSev)
		n++
	}
	// Enterprise SIEM channels stay config-only (sensitive tokens).
	if c.cfg.Notify.SplunkHECURL != "" && c.cfg.Notify.SplunkHECToken != "" {
		c.notifier.AddChannel(notify.NewSplunkHECChannel(c.cfg.Notify.SplunkHECURL, c.cfg.Notify.SplunkHECToken, c.cfg.Notify.SplunkIndex, ""), minSev)
		n++
	}
	if c.cfg.Notify.SentinelWorkspaceID != "" && c.cfg.Notify.SentinelSharedKey != "" {
		if s, err := notify.NewSentinelChannel(c.cfg.Notify.SentinelWorkspaceID, c.cfg.Notify.SentinelSharedKey, c.cfg.Notify.SentinelLogType); err == nil {
			c.notifier.AddChannel(s, minSev)
			n++
		}
	}
	return n
}

// notifyConfigView returns the current notification config for the console.
func (c *Controller) notifyConfigView() map[string]any {
	c.notifyMu.Lock()
	defer c.notifyMu.Unlock()
	chans := 0
	if c.notifier != nil {
		chans = c.notifier.Stats().Channels
	}
	return map[string]any{
		"webhook_url":  c.notifyWebhook,
		"slack_url":    c.notifySlack,
		"min_severity": c.notifyMinSev,
		"channels":     chans,
		"siem":         c.cfg.Notify.SplunkHECURL != "" || c.cfg.Notify.SentinelWorkspaceID != "",
	}
}

// setNotifyConfig reconfigures the webhook/slack channels + threshold at runtime.
func (c *Controller) setNotifyConfig(webhook, slack, minSev string) (int, error) {
	return c.applyNotify(strings.TrimSpace(webhook), strings.TrimSpace(slack), strings.TrimSpace(minSev)), nil
}

func (c *Controller) runInventoryScanner(ctx context.Context) {
	c.inventory.SetScope(c.cfg.Protection.ModelFIM.ProtectedPaths, c.cfg.Protection.ModelFIM.ProtectedExtensions)
	scan := func() {
		if err := c.inventory.Rescan(); err != nil {
			log.Printf("inventory scan: %v", err)
			return
		}
		s := c.inventory.Summary()
		if s.Modified > 0 {
			log.Printf("SECURITY: inventory found %d modified model file(s)", s.Modified)
		}
		if s.Unsafe > 0 {
			log.Printf("inventory: %d model file(s) use a code-execution-capable (pickle-backed) format", s.Unsafe)
		}
	}
	scan()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}

// rescanInventory runs an on-demand scan and returns the fresh summary (for the
// console's Rescan button).
func (c *Controller) rescanInventory() (any, error) {
	if err := c.inventory.Rescan(); err != nil {
		return nil, err
	}
	return c.inventory.Summary(), nil
}

// configSummary returns a redacted, read-only view of the effective policy for
// the console Configuration page. It never exposes secrets (passwords, keys).
func (c *Controller) configSummary() map[string]any {
	p := c.cfg.Protection
	notifyChannels := []string{}
	if c.cfg.Notify.WebhookURL != "" {
		notifyChannels = append(notifyChannels, "webhook")
	}
	if c.cfg.Notify.SlackWebhook != "" {
		notifyChannels = append(notifyChannels, "slack")
	}
	return map[string]any{
		"model_fim": map[string]any{
			"enabled":              p.ModelFIM.Enabled,
			"enforce_mode":         p.ModelFIM.EnforceMode,
			"protected_extensions": p.ModelFIM.ProtectedExtensions,
			"protected_paths":      p.ModelFIM.ProtectedPaths,
		},
		"network_containment": map[string]any{
			"enabled":            p.NetworkContainment.Enabled,
			"block_exfiltration": p.NetworkContainment.BlockExfiltration,
			"exfil_threshold_mb": p.NetworkContainment.ExfilThresholdMB,
		},
		"pickle_protection": map[string]any{
			"enabled":           p.PickleProtection.Enabled,
			"dangerous_symbols": p.PickleProtection.DangerousSymbols,
		},
		"sandbox": map[string]any{"enabled": c.cfg.Sandbox.Enabled},
		"mcp": map[string]any{
			"enabled":       c.cfg.MCP.Enabled,
			"allowed_tools": c.cfg.MCP.AllowedTools,
			"blocked_tools": c.cfg.MCP.BlockedTools,
		},
		"gateway": map[string]any{
			"enabled":           c.cfg.Gateway.Enabled,
			"listen_addr":       c.cfg.Gateway.ListenAddr,
			"block_on_detect":   c.cfg.Gateway.BlockOnDetect,
			"allowed_providers": c.cfg.Gateway.AllowedProviders,
		},
		"notify": map[string]any{
			"enabled":      c.cfg.Notify.Enabled,
			"min_severity": c.cfg.Notify.MinSeverity,
			"channels":     notifyChannels,
		},
		"platform": map[string]any{
			"enabled":       c.cfg.Platform.Enabled,
			"snapshot_path": c.cfg.Platform.SnapshotPath,
		},
		"audit": map[string]any{
			"enabled":  c.cfg.Audit.Enabled,
			"log_path": c.cfg.Audit.LogPath,
		},
	}
}

// Start starts the controller and all components
func (c *Controller) Start(ctx context.Context) error {
	ctx, c.cancel = context.WithCancel(ctx)

	log.Println("Starting NeuroSentry controller...")

	// Initialize components
	if err := c.initComponents(); err != nil {
		return fmt.Errorf("failed to initialize components: %w", err)
	}

	// Start event processor
	c.shutdownWG.Add(1)
	go c.processEvents(ctx)

	// Start trusted-PID death watcher (closes the PID-recycling TOCTOU
	// window — when a trusted process exits and the kernel later reuses
	// that PID for a new process, the new one would otherwise inherit
	// trust. The watcher prunes dead PIDs from trusted_pids on a tick.)
	c.shutdownWG.Add(1)
	go c.pruneTrustedPIDs(ctx)

	// Scan the model asset inventory (integrity monitoring) and keep it fresh.
	go c.runInventoryScanner(ctx)

	// Anti-tamper self-defense: periodically re-verify the agent's own integrity.
	if c.selfGuard != nil {
		go c.runSelfProtect(ctx)
	}

	// Persist the case store periodically so lifecycle changes (ack/resolve/
	// notes) survive a restart, not just imports.
	if c.auditDB != nil {
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					c.persistCases()
				}
			}
		}()
	}

	// Start the BPF ringbuf reader. The eBPF LSM hook writes
	// model_access_event records to the `events` ringbuf on every
	// blocked open; without an active user-space reader those records
	// pile up and never reach the policy engine, the [ALERT] log, or
	// the configured webhook. (Pre-1.1 the reader was missing — events
	// stayed in the ringbuf and the alert path was effectively dead.)
	if eventsMap := c.bpfMgr.EventsMap(); eventsMap != nil {
		rd, err := ringbuf.NewReader(eventsMap)
		if err != nil {
			log.Printf("ringbuf reader: failed to open: %v", err)
		} else {
			c.shutdownWG.Add(1)
			go c.readBPFEvents(ctx, rd)
		}
	}

	// Start all components
	for _, comp := range c.components {
		log.Printf("Starting component: %s", comp.Name())
		if err := comp.Start(ctx); err != nil {
			return fmt.Errorf("failed to start component %s: %w", comp.Name(), err)
		}
	}

	// Start BPF metrics collector
	if c.bpfMetrics != nil {
		c.bpfMetrics.Start()
	}

	c.ready.Store(true)

	// Fleet control plane: this node hosts the registry and self-registers so
	// the fleet view is populated. Remote agents enroll over HTTP; this node
	// updates its own record in-process on a heartbeat tick.
	if c.fleetReg != nil {
		// Use a stable, host-derived ID so a control-plane restart re-attaches to
		// the same record (restored from the snapshot) instead of minting a new
		// one and leaving a stale self-entry behind each restart.
		host, _ := os.Hostname()
		if host == "" {
			host = "control-plane"
		}
		id, _ := c.fleetReg.Enroll("self-"+host, c.selfAgentInfo())
		c.fleetID = id
		log.Printf("fleet: control plane enabled; this node enrolled as %s", id)
		go c.fleetHeartbeat(ctx)
		c.startFleetMTLS()
	}

	log.Printf("NeuroSentry controller started with %d components", len(c.components))
	return nil
}

// selfAgentInfo reports this node's current health for the fleet registry.
func (c *Controller) selfAgentInfo() fleet.AgentInfo {
	host, _ := os.Hostname()
	caps := bpf.DetectCapabilities()
	enforce := c.cfg.Protection.ModelFIM.Enabled && c.cfg.Protection.ModelFIM.EnforceMode
	return fleet.AgentInfo{
		Hostname: host,
		Version:  BuildVersion,
		Kernel:   caps.KernelVersion,
		Support:  string(caps.Assess(enforce).Level),
		Ready:    c.ready.Load(),
	}
}

// startFleetMTLS serves the agent-facing fleet endpoints (enroll/heartbeat) on a
// dedicated mutual-TLS listener when configured, so remote agents authenticate
// with a client certificate in addition to the shared token. Dev PKI is
// auto-generated under PKIDir when absent.
func (c *Controller) startFleetMTLS() {
	if !c.cfg.Fleet.MTLSEnabled || c.webServer == nil {
		return
	}
	dir := c.cfg.Fleet.PKIDir
	if dir == "" {
		dir = "/etc/neurosentry/pki"
	}
	if err := fleet.GenerateDevPKI(dir); err != nil {
		log.Printf("fleet mTLS: PKI bootstrap failed: %v", err)
		return
	}
	caPEM, err1 := os.ReadFile(filepath.Join(dir, "ca.crt"))
	certPEM, err2 := os.ReadFile(filepath.Join(dir, "server.crt"))
	keyPEM, err3 := os.ReadFile(filepath.Join(dir, "server.key"))
	if err1 != nil || err2 != nil || err3 != nil {
		log.Printf("fleet mTLS: reading certs from %s failed", dir)
		return
	}
	tlsCfg, err := fleet.ServerTLSConfig(caPEM, certPEM, keyPEM)
	if err != nil {
		log.Printf("fleet mTLS: %v", err)
		return
	}
	addr := c.cfg.Fleet.MTLSListen
	if addr == "" {
		addr = ":9443"
	}
	srv := &http.Server{Addr: addr, Handler: c.webServer.FleetAgentHandler(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}
	c.fleetMTLS = srv
	go func() {
		log.Printf("fleet: mutual-TLS agent listener on %s (client cert required; CA=%s)", addr, filepath.Join(dir, "ca.crt"))
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("fleet mTLS listener: %v", err)
		}
	}()
}

// fleetEvictAfter is how long an agent may go without a heartbeat before the
// control plane drops it from the registry (a decommissioned or long-dead node),
// keeping the persisted fleet bounded. Well above the stale threshold so a brief
// outage only marks an agent stale, never evicts it.
const fleetEvictAfter = time.Hour

// fleetHeartbeat refreshes this node's registry record until shutdown.
func (c *Controller) fleetHeartbeat(ctx context.Context) {
	every := time.Duration(c.cfg.Fleet.HeartbeatSecs) * time.Second
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if c.fleetID != "" {
				_ = c.fleetReg.Heartbeat(c.fleetID, c.selfAgentInfo())
				c.applyDesired(c.fleetReg.DesiredForAgent(c.fleetID))
			}
			// Evict long-dead agents so the persisted registry stays bounded,
			// then persist the whole registry each tick so remote agents'
			// enroll/heartbeat/desired changes (mutated from the HTTP handlers)
			// also survive a control-plane restart.
			if n := c.fleetReg.EvictStale(fleetEvictAfter); n > 0 {
				log.Printf("fleet: evicted %d agent(s) with no heartbeat for %s", n, fleetEvictAfter)
			}
			c.persistFleet()
		}
	}
}

// persistFleet writes the fleet registry to the durable snapshot store.
func (c *Controller) persistFleet() {
	if c.auditDB == nil || c.fleetReg == nil {
		return
	}
	data, err := c.fleetReg.Snapshot()
	if err != nil {
		log.Printf("fleet: snapshot: %v", err)
		return
	}
	if err := c.auditDB.SaveSnapshot("fleet", data, time.Now()); err != nil {
		log.Printf("fleet: save snapshot: %v", err)
	}
}

// applyDesired converges this node to the control plane's desired state. Only
// changes are applied (pointer fields are "unset = leave alone").
func (c *Controller) applyDesired(d fleet.DesiredState) {
	if d.LearningMode != nil && c.correlator != nil {
		if c.correlator.LearningMode() != *d.LearningMode {
			c.correlator.SetLearningMode(*d.LearningMode)
			log.Printf("fleet: converged learning_mode=%v (desired v%d)", *d.LearningMode, d.Version)
		}
	}
}

// readiness backs the /readyz probe: ready once components are up and the
// kernel provides at least the core capabilities. Returns coarse, non-sensitive
// state only.
func (c *Controller) readiness() (bool, map[string]any) {
	ready := c.ready.Load()
	caps := bpf.DetectCapabilities()
	enforce := c.cfg.Protection.ModelFIM.Enabled && c.cfg.Protection.ModelFIM.EnforceMode
	a := caps.Assess(enforce)
	if a.Level == bpf.SupportUnsupported {
		ready = false
	}
	return ready, map[string]any{
		"components": len(c.components),
		"support":    string(a.Level),
		"kernel":     caps.KernelVersion,
	}
}

// Stop gracefully shuts down the controller
func (c *Controller) Stop() {
	if c.cancel == nil {
		return // Not started
	}

	log.Println("Stopping NeuroSentry controller...")

	// Signal shutdown
	c.cancel()

	// Stop all components
	for _, comp := range c.components {
		log.Printf("Stopping component: %s", comp.Name())
		if err := comp.Stop(); err != nil {
			log.Printf("Error stopping component %s: %v", comp.Name(), err)
		}
	}

	// Stop BPF metrics collector
	if c.bpfMetrics != nil {
		c.bpfMetrics.Stop()
	}

	// Wait for event processor to finish
	c.shutdownWG.Wait()

	// Persist control-plane state + cases + fleet so they survive a restart.
	c.saveSnapshot()
	c.persistCases()
	c.persistFleet()
	if c.fleetMTLS != nil {
		_ = c.fleetMTLS.Close()
	}

	// Close audit store
	if c.auditStore != nil {
		c.auditStore.Close()
	}
	if c.auditDB != nil {
		c.auditDB.Close()
	}

	close(c.eventChan)
	log.Println("NeuroSentry controller stopped")
}

// initComponents initializes all agent components
func (c *Controller) initComponents() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Event processor component with sampling support
	sampleRate := c.cfg.Agent.EventSampleRate
	if sampleRate <= 0 {
		sampleRate = 1.0 // Default to no sampling
	}
	c.eventProcessor = NewEventProcessorWithSampling(c.eventChan, c.metrics, sampleRate)
	c.components = append(c.components, c.eventProcessor)

	if sampleRate < 1.0 {
		log.Printf("Event sampling enabled: %.1f%% of events will be processed", sampleRate*100)
	}

	// Policy engine component
	policyEngine := NewPolicyEngine(c.cfg, c.bpfMgr, c.policy, c.metrics)
	c.components = append(c.components, policyEngine)

	// Metrics server component
	metricsServer := NewMetricsServer(c.cfg.Agent.MetricsPort, c.metrics)
	c.components = append(c.components, metricsServer)

	// Alert manager if webhook configured. Stash the manager on the
	// controller so sendAlert() can actually invoke it (was previously
	// just logging "[ALERT]" with a TODO comment about wiring to the
	// alert manager; now wired).
	if c.cfg.Agent.AlertWebhook != "" {
		c.alertMgr = NewAlertManager(c.cfg.Agent.AlertWebhook, c.cfg.Agent.AlertSilenceSec)
		c.components = append(c.components, c.alertMgr)
	}

	// Inline AI gateway (OpenAI-compatible relay with inline guards)
	if c.cfg.Gateway.Enabled {
		gc := newGatewayComponent(c.cfg.Gateway, c.auditChain, c.secMetrics)
		c.components = append(c.components, gc)
		log.Printf("gateway: %s", gc.description())
	}

	// Web dashboard
	if c.cfg.Web.Enabled {
		webCfg := web.Config{
			Enabled:    true,
			ListenAddr: c.cfg.Web.ListenAddr,
		}
		c.webServer = web.NewServer(webCfg, c.auditChain, c.mcpInterceptor)
		if c.correlator != nil {
			c.webServer.SetCorrelationSource(c.correlator.RecentFindings)
			c.webServer.SetEventsSource(c.correlator.RecentSignals)
			c.webServer.SetNetworkBlocklist(func() (bool, []string) {
				ips, _ := c.bpfMgr.ListBlockedIPs()
				return c.bpfMgr.NetworkEnforcing(), ips
			})
			c.webServer.SetDetectionsProvider(c.correlator.Detections, c.correlator.SetEnabled)
			c.webServer.SetDetectionMutators(c.correlator.AddRule, c.correlator.RemoveRule)
			c.webServer.SetDetectionUpdater(c.correlator.UpdateRule)
			c.webServer.SetKBSource(c.correlator.KnowledgeBase)
			c.webServer.SetDetectionValidator(func() []correlate.ValidationResult {
				return correlate.ValidateRules(correlate.BuiltinScenarios())
			})
			c.webServer.SetSuppressionManager(c.correlator.Suppressions, c.correlator.AddSuppression, c.correlator.RemoveSuppression)
			c.webServer.SetLearningManager(c.correlator.LearningMode, c.correlator.SetLearningMode)
			if c.breaker != nil {
				c.webServer.SetBreakerManager(
					func() (bool, int64) { return c.breaker.Armed(), c.breaker.TripCount() },
					c.breaker.SetArmed)
			}
			if c.selfGuard != nil {
				c.webServer.SetSelfProtectProvider(func() any {
					tampers := c.selfGuard.Verify()
					return map[string]any{
						"baseline": c.selfGuard.Baseline(),
						"tampers":  tampers,
						"ok":       len(tampers) == 0,
					}
				})
			}
			if c.cfg.Fleet.Enabled {
				c.fleetReg = fleet.NewRegistry(0)
				// Restore the enrolled fleet + desired state so a control-plane
				// restart doesn't orphan agents or drop an in-progress rollout.
				if c.auditDB != nil {
					if data, ok, _ := c.auditDB.LoadSnapshot("fleet"); ok {
						if err := c.fleetReg.Restore(data); err != nil {
							log.Printf("fleet: restore snapshot: %v", err)
						} else {
							log.Printf("fleet: restored %d agent(s) from durable snapshot", len(c.fleetReg.List()))
						}
					}
				}
				c.webServer.SetFleetRegistry(c.fleetReg, c.cfg.Fleet.EnrollToken)
			}
			if c.auditDB != nil {
				c.webServer.SetDurableAuditStore(c.auditDB)
			}
			c.webServer.SetReadiness(c.readiness)
		}
		if c.incidents != nil {
			c.webServer.SetCaseStore(c.incidents)
		}
		c.webServer.SetConfigProvider(c.configSummary)
		if c.inventory != nil {
			c.webServer.SetInventoryProvider(
				func() any { return c.inventory.Assets() },
				func() any { return c.inventory.Summary() },
			)
			c.webServer.SetInventoryControls(
				c.rescanInventory,
				c.inventory.Scope,
				c.inventory.AddPath,
				c.inventory.RemovePath,
			)
		}
		c.webServer.SetResponseHandler(c.executeResponse)
		if c.notifier != nil {
			c.webServer.SetNotifyTester(func() (int, int) {
				delivered := c.notifier.Route(context.Background(), notify.Alert{
					Title:    "NeuroSentry test notification",
					Severity: "critical", // ensure it clears any threshold
					Source:   "console",
					Message:  "This is a test alert triggered from the NeuroSentry console.",
				})
				return delivered, c.notifier.Stats().Channels
			})
			c.webServer.SetNotifyConfigurator(c.notifyConfigView, c.setNotifyConfig)
		}
		// Multi-tenant control plane (identity/RBAC) is served by the same
		// web server when enabled.
		if c.cfg.Platform.Enabled {
			if err := c.setupPlatform(); err != nil {
				log.Printf("platform: setup failed: %v (control plane disabled)", err)
			}
		}
		c.components = append(c.components, c.webServer)
	}

	return nil
}

// setupPlatform wires the multi-tenant control plane into the web server:
// restore prior state, bootstrap a first-boot admin, and enable the auth API.
func (c *Controller) setupPlatform() error {
	tenants := platform.NewMemTenantStore()
	users := platform.NewMemUserStore()

	if c.cfg.Platform.SnapshotPath != "" {
		if ok, err := platform.LoadSnapshot(c.cfg.Platform.SnapshotPath, tenants, users); err != nil {
			log.Printf("platform: snapshot load failed: %v", err)
		} else if ok {
			log.Printf("platform: restored control-plane state from %s", c.cfg.Platform.SnapshotPath)
		}
	}

	secret := []byte(c.cfg.Platform.JWTSecret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
		log.Printf("platform: generated ephemeral JWT key (set platform.jwt_secret to keep sessions across restarts)")
	}
	issuer := platform.NewTokenIssuer(secret, "neurosentry", 12*time.Hour)
	auth := platform.NewAuthenticator(issuer, platform.NewLocalProvider(users))

	c.platformTenants = tenants
	c.platformUsers = users

	if list, _ := tenants.List(); len(list) == 0 {
		if err := c.bootstrapAdmin(tenants, users); err != nil {
			return err
		}
	}

	c.webServer.EnablePlatform(auth, tenants, users)
	log.Printf("platform: multi-tenant control plane enabled (identity, RBAC, %d tenant(s))", len(mustList(tenants)))
	return nil
}

// bootstrapAdmin creates the first-boot default tenant and owner account.
func (c *Controller) bootstrapAdmin(tenants *platform.MemTenantStore, users *platform.MemUserStore) error {
	slug := c.cfg.Platform.BootstrapTenant
	if slug == "" {
		slug = "default"
	}
	ten := &platform.Tenant{Slug: slug, Name: "Default Organization", Plan: platform.PlanEnterprise}
	if err := tenants.Create(ten); err != nil {
		return err
	}

	email := c.cfg.Platform.BootstrapEmail
	if email == "" {
		email = "admin@neurosentry.local"
	}
	password := c.cfg.Platform.BootstrapPassword
	generated := false
	if password == "" {
		password = generatePassword()
		generated = true
	}
	u := &platform.User{TenantID: ten.ID, Email: email, Roles: []platform.Role{platform.RoleOwner}}
	if err := u.SetPassword(password); err != nil {
		return err
	}
	if err := users.Create(u); err != nil {
		return err
	}

	if generated {
		log.Printf("======================================================")
		log.Printf("  NeuroSentry first-boot admin created")
		log.Printf("  tenant:   %s", slug)
		log.Printf("  email:    %s", email)
		log.Printf("  password: %s", password)
		log.Printf("  (shown once - change it after first login)")
		log.Printf("======================================================")
	} else {
		log.Printf("platform: bootstrapped admin %s in tenant %s", email, slug)
	}
	c.saveSnapshot()
	return nil
}

// saveSnapshot persists the control-plane state (best-effort).
func (c *Controller) saveSnapshot() {
	if c.cfg.Platform.SnapshotPath == "" || c.platformTenants == nil {
		return
	}
	if err := platform.SaveSnapshot(c.cfg.Platform.SnapshotPath, c.platformTenants, c.platformUsers); err != nil {
		log.Printf("platform: snapshot save failed: %v", err)
	}
}

func mustList(t *platform.MemTenantStore) []*platform.Tenant {
	l, _ := t.List()
	return l
}

func generatePassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// pruneTrustedPIDs periodically walks the trusted_pids BPF map and removes
// entries whose PID no longer exists in /proc. This runs every
// `PIDPruneInterval` (default 30s) and shuts down with the controller.
//
// Why: trusted_pids is keyed by PID. PIDs recycle (4M-default range, much
// smaller on busy nodes). When a trusted process exits and the kernel
// reuses its PID for an unrelated process, that new process would inherit
// trust without any explicit grant. Periodic pruning closes that window
// to roughly the prune interval.
func (c *Controller) pruneTrustedPIDs(ctx context.Context) {
	defer c.shutdownWG.Done()

	interval := c.cfg.Agent.PIDPruneInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := c.bpfMgr.PruneDeadTrustedPIDs()
			if err != nil {
				log.Printf("trusted-PID pruner: %v", err)
				continue
			}
			if n > 0 {
				log.Printf("SECURITY: pruned %d dead PID(s) from trusted_pids", n)
				if c.secMetrics != nil {
					c.secMetrics.RecordPIDsPruned(n)
				}
			}
		}
	}
}

// readBPFEvents pulls records from the LSM events ringbuf and forwards
// parsed Events into c.eventChan. Closes the reader on context cancel.
func (c *Controller) readBPFEvents(ctx context.Context, rd *ringbuf.Reader) {
	defer c.shutdownWG.Done()

	// Close the reader on context cancel so the blocking Read() returns.
	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	log.Println("ringbuf reader: started")
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				log.Println("ringbuf reader: shutting down")
				return
			}
			log.Printf("ringbuf reader: read error: %v", err)
			continue
		}
		event, perr := ParseEvent(rec)
		if perr != nil {
			log.Printf("ringbuf reader: parse error: %v", perr)
			if c.secMetrics != nil {
				c.secMetrics.RecordDrop("parse_error")
			}
			continue
		}
		select {
		case c.eventChan <- event:
		case <-ctx.Done():
			return
		default:
			// Channel full: the user-space pipeline is back-pressured. Drop
			// and account it so the "zero drops" SLO is directly observable
			// (neurosentry_events_dropped_total{reason="event_chan_full"}).
			if c.secMetrics != nil {
				c.secMetrics.RecordDrop("event_chan_full")
			}
		}
	}
}

// processEvents processes events from the BPF layer
func (c *Controller) processEvents(ctx context.Context) {
	defer c.shutdownWG.Done()

	for {
		select {
		case <-ctx.Done():
			log.Println("Event processor shutting down...")
			return

		case event := <-c.eventChan:
			c.handleEvent(event)
		}
	}
}

// handleEvent handles a single event
func (c *Controller) handleEvent(event Event) {
	// Always process high/critical severity events
	// Apply sampling only to info-level events
	if event.Severity != "high" && event.Severity != "critical" {
		if c.eventProcessor != nil && !c.eventProcessor.ShouldSample() {
			return // Skip this event due to sampling
		}
	}

	// Update metrics
	c.metrics.RecordEvent(event)

	// Write to tamper-proof audit chain
	c.recordAudit(event)

	// Feed the kernel-layer observation into the correlation engine so it can
	// be fused with AI-layer intent.
	if c.correlator != nil {
		if s, ok := eventToSignal(event); ok {
			c.correlator.Ingest(s)
		}
	}

	// Check if action needed based on policy
	action := c.policy.Evaluate(event)

	switch action {
	case policy.ActionAllow:
		// Event allowed, just logged

	case policy.ActionAlert:
		c.sendAlert(event)

	case policy.ActionBlock:
		c.handleBlock(event)
		// Block events also fire the alert path so the operator's
		// webhook / SOC pipeline sees what was blocked.
		c.sendAlert(event)
	}

	// Also fire an alert for any high/critical-severity event the
	// kernel surfaced — even if the YAML policy returned ActionAllow,
	// these are events the operator wants to know about (e.g. an LSM
	// `file_blocked` was already enforced by the kernel; the alert
	// path is what gets it to the SOC).
	if action == policy.ActionAllow && (event.Severity == "high" || event.Severity == "critical") {
		c.sendAlert(event)
	}
}

// sendAlert sends an alert for an event. Logs locally and forwards to the
// configured webhook (with rate limiting / silence period applied by
// AlertManager). No-op for the webhook side when no webhook is configured.
func (c *Controller) sendAlert(event Event) {
	log.Printf("[ALERT] %s pid=%d severity=%s file=%s",
		event.Type, event.Source.PID, event.Severity, event.Data.FilePath)

	if c.alertMgr != nil {
		if err := c.alertMgr.SendAlert(event); err != nil {
			log.Printf("alert webhook send failed: %v", err)
			if c.secMetrics != nil {
				c.secMetrics.RecordWebhookSent("error")
			}
		} else if c.secMetrics != nil {
			c.secMetrics.RecordWebhookSent("ok")
		}
	}
}

// handleBlock handles a blocked event
func (c *Controller) handleBlock(event Event) {
	log.Printf("[BLOCKED] %s: %+v", event.Type, event)
}

// recordAudit appends the event to the tamper-proof audit chain and persists it.
func (c *Controller) recordAudit(event Event) {
	severity := audit.SeverityInfo
	switch event.Severity {
	case "low":
		severity = audit.SeverityLow
	case "medium":
		severity = audit.SeverityMedium
	case "high":
		severity = audit.SeverityHigh
	case "critical":
		severity = audit.SeverityCritical
	}

	entry := audit.NewEntry(string(event.Type), severity, map[string]any{
		"file_path": event.Data.FilePath,
		"dst_addr":  event.Data.DstAddr,
	})
	entry.SetActor(event.Source.PID, event.Source.UID, event.Source.Comm)

	switch {
	case event.Type == EventTypeFileAccess || event.Type == EventTypeFileBlocked:
		entry.SetCategory(audit.CategorySecurity, audit.ClassFileSys)
	case event.Type == EventTypeNetworkAllowed || event.Type == EventTypeNetworkBlocked:
		entry.SetCategory(audit.CategoryNetwork, audit.ClassNetwork)
	default:
		entry.SetCategory(audit.CategorySecurity, audit.ClassFinding)
	}

	if err := c.auditChain.Append(entry); err != nil {
		log.Printf("audit chain append: %v", err)
		return
	}

	if c.auditStore != nil {
		entries := c.auditChain.Entries()
		last := entries[len(entries)-1]
		if err := c.auditStore.Write(last); err != nil {
			log.Printf("audit store write: %v", err)
		}
	}

	if c.webServer != nil {
		data, _ := json.Marshal(entry)
		c.webServer.BroadcastEvent(data)
	}
}

// GetMetrics returns the current metrics
func (c *Controller) GetMetrics() map[string]any {
	return c.metrics.Snapshot()
}

// GetSecurityMetrics returns the security metrics collector
func (c *Controller) GetSecurityMetrics() *SecurityMetrics {
	return c.secMetrics
}

// Status returns the controller status
func (c *Controller) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	componentStatus := make(map[string]string)
	for _, comp := range c.components {
		componentStatus[comp.Name()] = "running"
	}

	return Status{
		Running:         true,
		Components:      componentStatus,
		EventsProcessed: c.metrics.TotalEvents(),
		ThreatsDetected: c.metrics.TotalThreats(),
	}
}

// Status represents the controller status
type Status struct {
	Running         bool              `json:"running"`
	Components      map[string]string `json:"components"`
	EventsProcessed int64             `json:"events_processed"`
	ThreatsDetected int64             `json:"threats_detected"`
}

// GetAuditChain returns the audit chain for external inspection (web API, etc.)
func (c *Controller) GetAuditChain() *audit.Chain {
	return c.auditChain
}

// GetMCPInterceptor returns the MCP interceptor
func (c *Controller) GetMCPInterceptor() *mcp.Interceptor {
	return c.mcpInterceptor
}
