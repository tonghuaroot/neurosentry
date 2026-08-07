// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package aigateway is NeuroSentry's inline AI gateway: an OpenAI-compatible
// reverse proxy that inspects LLM traffic in-band and enforces policy before
// it reaches an upstream provider. It turns the passive detectors in pkg/aiguard
// into an active control point — the "your app is about to send an AWS key to
// ChatGPT, blocked" enforcement layer — and doubles as a unified relay
// (provider routing, key custody, quota, audit) across many AI providers.
package aigateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/neurosentry/neurosentry/pkg/aiguard"
)

// GuardVerdict is a guard's decision about a payload.
type GuardVerdict struct {
	Block    bool              `json:"block"`
	Reason   string            `json:"reason,omitempty"`
	Findings []aiguard.Finding `json:"findings,omitempty"`
}

// Guard is a composable inline inspection stage. Guards run on the extracted
// prompt (and, for output guards, the response) before/after forwarding.
type Guard interface {
	Name() string
	Inspect(text string) GuardVerdict
}

// Upstream forwards an already-vetted request to a provider and returns its
// response. Implementations own key custody and endpoint selection; a mock
// satisfies it in tests.
type Upstream interface {
	Forward(ctx context.Context, provider string, body []byte, header http.Header) (status int, respBody []byte, respHeader http.Header, err error)
}

// GatewayEvent is emitted for every request for audit/metrics.
type GatewayEvent struct {
	Timestamp        time.Time         `json:"timestamp"`
	Tenant           string            `json:"tenant,omitempty"`
	Provider         string            `json:"provider"`
	Model            string            `json:"model"`
	Action           string            `json:"action"` // "allowed" | "blocked"
	Reason           string            `json:"reason,omitempty"`
	PromptChars      int               `json:"prompt_chars"`
	PromptTokens     int64             `json:"prompt_tokens,omitempty"`
	CompletionTokens int64             `json:"completion_tokens,omitempty"`
	Findings         []aiguard.Finding `json:"findings,omitempty"`
}

// Config tunes the gateway.
type Config struct {
	// BlockOnDetect: when true a guard's Block verdict rejects the request;
	// when false the request is forwarded but the event is still recorded
	// (observe/monitor mode).
	BlockOnDetect bool
	// AllowedProviders restricts which upstream providers may be reached. Empty
	// means allow any provider the router recognizes.
	AllowedProviders []string
	// DefaultProvider routes requests whose model does not map to a provider.
	DefaultProvider string
}

// Gateway is the inline proxy handler.
type Gateway struct {
	guards       []Guard
	outputGuards []Guard
	upstream     Upstream
	catalog      *aiguard.Catalog
	cfg          Config
	allowed      map[string]struct{}
	onEvent      func(GatewayEvent)
	quota        *QuotaManager
	usage        *UsageTracker
}

// New builds a gateway. guards inspect the request prompt; outputGuards inspect
// the upstream response.
func New(cfg Config, upstream Upstream, guards []Guard, outputGuards []Guard) *Gateway {
	allowed := make(map[string]struct{})
	for _, p := range cfg.AllowedProviders {
		allowed[p] = struct{}{}
	}
	return &Gateway{
		guards:       guards,
		outputGuards: outputGuards,
		upstream:     upstream,
		catalog:      aiguard.NewCatalog(),
		cfg:          cfg,
		allowed:      allowed,
		onEvent:      func(GatewayEvent) {},
	}
}

// OnEvent registers a sink for gateway events (wire to the audit chain / metrics).
func (g *Gateway) OnEvent(fn func(GatewayEvent)) {
	if fn != nil {
		g.onEvent = fn
	}
}

// WithMetering attaches per-tenant quota enforcement and usage/cost tracking,
// turning the gateway into a metered relay. Either argument may be nil.
func (g *Gateway) WithMetering(q *QuotaManager, u *UsageTracker) *Gateway {
	g.quota = q
	g.usage = u
	return g
}

// chatRequest is the subset of the OpenAI chat-completions schema the gateway
// needs to inspect. Unknown fields are preserved by forwarding the raw body.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ServeHTTP implements the OpenAI-compatible endpoint. Mount at
// /v1/chat/completions.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeGatewayError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20)) // 8 MiB cap
	if err != nil {
		writeGatewayError(w, http.StatusBadRequest, "cannot read body")
		return
	}

	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid chat request")
		return
	}

	tenant := r.Header.Get("X-NeuroSentry-Tenant")
	provider := g.routeProvider(req.Model)
	prompt := extractPrompt(req.Messages)

	ev := GatewayEvent{
		Timestamp:   time.Now(),
		Tenant:      tenant,
		Provider:    provider,
		Model:       req.Model,
		PromptChars: len(prompt),
		Action:      "allowed",
	}

	// Provider allowlist (shadow-AI enforcement at the relay).
	if len(g.allowed) > 0 {
		if _, ok := g.allowed[provider]; !ok {
			ev.Action = "blocked"
			ev.Reason = "provider not allowed: " + provider
			g.onEvent(ev)
			writeGatewayError(w, http.StatusForbidden, ev.Reason)
			return
		}
	}

	// Pre-flight quota / rate-limit enforcement (denial-of-wallet guard).
	estTokens := estimateTokens(prompt)
	if g.quota != nil {
		if ok, reason := g.quota.Allow(tenant, estTokens); !ok {
			ev.Action = "blocked"
			ev.Reason = reason
			g.onEvent(ev)
			writeGatewayError(w, http.StatusTooManyRequests, reason)
			return
		}
	}

	// Inbound guard pipeline.
	var findings []aiguard.Finding
	for _, guard := range g.guards {
		v := guard.Inspect(prompt)
		findings = append(findings, v.Findings...)
		if v.Block {
			ev.Findings = findings
			if g.cfg.BlockOnDetect {
				ev.Action = "blocked"
				ev.Reason = guard.Name() + ": " + v.Reason
				g.onEvent(ev)
				writeGatewayBlocked(w, ev.Reason, findings)
				return
			}
		}
	}

	// Forward the vetted request upstream.
	status, respBody, respHeader, err := g.upstream.Forward(r.Context(), provider, body, r.Header)
	if err != nil {
		ev.Action = "error"
		ev.Reason = err.Error()
		g.onEvent(ev)
		writeGatewayError(w, http.StatusBadGateway, "upstream error")
		return
	}

	// Outbound (response) guard pipeline — e.g. DLP on model output.
	for _, guard := range g.outputGuards {
		v := guard.Inspect(string(respBody))
		findings = append(findings, v.Findings...)
		if v.Block && g.cfg.BlockOnDetect {
			ev.Action = "blocked"
			ev.Reason = "output " + guard.Name() + ": " + v.Reason
			ev.Findings = findings
			g.onEvent(ev)
			writeGatewayBlocked(w, ev.Reason, findings)
			return
		}
	}

	// Metering: reconcile estimated vs actual tokens and record usage/cost.
	if g.usage != nil || g.quota != nil {
		promptTok, complTok, ok := parseResponseUsage(respBody)
		if !ok {
			promptTok = estTokens // fall back to the pre-flight estimate
		}
		if g.usage != nil {
			g.usage.Record(tenant, req.Model, promptTok, complTok)
		}
		if g.quota != nil {
			g.quota.SettleTokens(tenant, estTokens, promptTok+complTok)
		}
		ev.PromptTokens = promptTok
		ev.CompletionTokens = complTok
	}

	ev.Findings = findings
	g.onEvent(ev)

	// Relay the upstream response verbatim.
	for k, vals := range respHeader {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_, _ = w.Write(respBody) //nolint:gosec // G705: relays the upstream provider's JSON response verbatim; this is an API endpoint, not HTML
}

// routeProvider maps a model name to a provider. Known prefixes route directly;
// otherwise the configured default applies.
func (g *Gateway) routeProvider(model string) string {
	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "gpt-"), strings.HasPrefix(m, "o1"), strings.HasPrefix(m, "o3"):
		return "OpenAI"
	case strings.HasPrefix(m, "claude"):
		return "Anthropic"
	case strings.HasPrefix(m, "gemini"):
		return "Google Gemini"
	case strings.HasPrefix(m, "mistral"), strings.HasPrefix(m, "mixtral"):
		return "Mistral"
	case strings.HasPrefix(m, "deepseek"):
		return "DeepSeek"
	case strings.HasPrefix(m, "grok"):
		return "xAI"
	}
	if g.cfg.DefaultProvider != "" {
		return g.cfg.DefaultProvider
	}
	return "unknown"
}

func extractPrompt(messages []chatMessage) string {
	var b strings.Builder
	for _, m := range messages {
		b.WriteString(m.Content)
		b.WriteByte('\n')
	}
	return b.String()
}

func writeGatewayError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": msg, "type": "neurosentry_gateway_error"},
	})
}

func writeGatewayBlocked(w http.ResponseWriter, reason string, findings []aiguard.Finding) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message":  "request blocked by NeuroSentry policy: " + reason,
			"type":     "neurosentry_policy_violation",
			"findings": findings,
		},
	})
}

// --- Built-in guards ---

// InjectionGuard blocks prompts the injection detector rates malicious.
type InjectionGuard struct {
	detector     *aiguard.InjectionDetector
	blockVerdict aiguard.Verdict
}

// NewInjectionGuard builds an injection guard. It blocks on "malicious" by
// default; pass aiguard.VerdictSuspicious to be stricter.
func NewInjectionGuard(d *aiguard.InjectionDetector, blockAt aiguard.Verdict) *InjectionGuard {
	if blockAt == "" {
		blockAt = aiguard.VerdictMalicious
	}
	return &InjectionGuard{detector: d, blockVerdict: blockAt}
}

func (g *InjectionGuard) Name() string { return "prompt_injection" }

func (g *InjectionGuard) Inspect(text string) GuardVerdict {
	r := g.detector.Detect(text)
	block := r.Verdict == aiguard.VerdictMalicious ||
		(g.blockVerdict == aiguard.VerdictSuspicious && r.Verdict != aiguard.VerdictClean)
	return GuardVerdict{
		Block:    block,
		Reason:   fmt.Sprintf("%s (score %.2f)", r.Verdict, r.Score),
		Findings: aiguard.EnrichInjection(r),
	}
}

// DLPGuard blocks payloads containing secrets/PII.
type DLPGuard struct {
	scanner *aiguard.SecretScanner
}

// NewDLPGuard builds a DLP guard over a secret scanner.
func NewDLPGuard(s *aiguard.SecretScanner) *DLPGuard { return &DLPGuard{scanner: s} }

func (g *DLPGuard) Name() string { return "dlp" }

func (g *DLPGuard) Inspect(text string) GuardVerdict {
	res := g.scanner.Scan(text)
	if !res.Leaked {
		return GuardVerdict{}
	}
	findings := make([]aiguard.Finding, 0, len(res.Findings))
	types := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		owasp, _ := aiguard.LookupOWASP("LLM02")
		findings = append(findings, aiguard.Finding{
			Source:  "dlp",
			Verdict: "blocked",
			OWASP:   &owasp,
			Detail:  string(f.Type) + "=" + f.Redacted,
		})
		types = append(types, string(f.Type))
	}
	return GuardVerdict{
		Block:    true,
		Reason:   "sensitive data detected: " + strings.Join(types, ", "),
		Findings: findings,
	}
}
