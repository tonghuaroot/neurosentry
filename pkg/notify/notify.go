// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package notify routes security alerts to external channels (Slack, generic
// webhook, syslog/file) with severity thresholds and per-alert deduplication —
// the notification layer every SOC product needs so findings reach responders
// where they already work.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Alert is a normalized notification payload.
type Alert struct {
	Timestamp time.Time         `json:"timestamp"`
	Title     string            `json:"title"`
	Severity  string            `json:"severity"`
	Source    string            `json:"source"` // "correlation", "lsm", "gateway", ...
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// severityRank orders severities for threshold comparisons.
var severityRank = map[string]int{
	"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

func meets(sev, threshold string) bool {
	return severityRank[sev] >= severityRank[threshold]
}

// Channel delivers an alert somewhere. Implementations must be safe for
// concurrent use and should not block indefinitely.
type Channel interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}

// Router fans an alert out to all channels whose severity threshold it meets,
// with time-based dedup so a recurring alert does not spam responders.
type Router struct {
	mu         sync.Mutex
	channels   []channelBinding
	lastSent   map[string]time.Time
	dedupEvery time.Duration
	now        func() time.Time
	delivered  int64
	suppressed int64
}

type channelBinding struct {
	ch        Channel
	threshold string
}

// NewRouter builds a router. dedupWindow suppresses identical (title+severity)
// alerts within the window (default 60s if <= 0).
func NewRouter(dedupWindow time.Duration) *Router {
	if dedupWindow <= 0 {
		dedupWindow = time.Minute
	}
	return &Router{
		lastSent:   make(map[string]time.Time),
		dedupEvery: dedupWindow,
		now:        time.Now,
	}
}

// Reset removes all registered channels (used when reconfiguring at runtime).
func (r *Router) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels = nil
}

// AddChannel registers a channel that receives alerts at or above threshold.
func (r *Router) AddChannel(ch Channel, threshold string) {
	if _, ok := severityRank[threshold]; !ok {
		threshold = "high"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels = append(r.channels, channelBinding{ch: ch, threshold: threshold})
}

// Route delivers an alert to eligible channels. Returns the number of channels
// it was delivered to. Dedup and threshold filtering are applied first.
func (r *Router) Route(ctx context.Context, a Alert) int {
	if a.Timestamp.IsZero() {
		a.Timestamp = r.now()
	}
	r.mu.Lock()
	key := a.Severity + "|" + a.Title
	if last, ok := r.lastSent[key]; ok && a.Timestamp.Sub(last) < r.dedupEvery {
		r.suppressed++
		r.mu.Unlock()
		return 0
	}
	r.lastSent[key] = a.Timestamp
	bindings := make([]channelBinding, len(r.channels))
	copy(bindings, r.channels)
	r.mu.Unlock()

	sent := 0
	for _, b := range bindings {
		if !meets(a.Severity, b.threshold) {
			continue
		}
		// Deliver best-effort; one channel failing must not block the others.
		if err := b.ch.Send(ctx, a); err == nil {
			sent++
		}
	}
	r.mu.Lock()
	r.delivered += int64(sent)
	r.mu.Unlock()
	return sent
}

// Stats reports delivery counters for observability.
type Stats struct {
	Channels   int   `json:"channels"`
	Delivered  int64 `json:"delivered"`
	Suppressed int64 `json:"suppressed"`
}

func (r *Router) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Stats{Channels: len(r.channels), Delivered: r.delivered, Suppressed: r.suppressed}
}

// --- Channels ---

// WebhookChannel POSTs the alert as JSON to a URL.
type WebhookChannel struct {
	URL    string
	client *http.Client
}

func NewWebhookChannel(url string) *WebhookChannel {
	return &WebhookChannel{URL: url, client: &http.Client{Timeout: 10 * time.Second}}
}

func (c *WebhookChannel) Name() string { return "webhook" }

func (c *WebhookChannel) Send(ctx context.Context, a Alert) error {
	body, _ := json.Marshal(a)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

// SlackChannel posts a formatted message to a Slack incoming webhook.
type SlackChannel struct {
	URL    string
	client *http.Client
}

func NewSlackChannel(url string) *SlackChannel {
	return &SlackChannel{URL: url, client: &http.Client{Timeout: 10 * time.Second}}
}

func (c *SlackChannel) Name() string { return "slack" }

// slackColor maps severity to a Slack attachment color bar.
var slackColor = map[string]string{
	"critical": "#ef4444", "high": "#f59e0b", "medium": "#3b82f6", "low": "#94a3b8", "info": "#94a3b8",
}

func (c *SlackChannel) Send(ctx context.Context, a Alert) error {
	var fields []map[string]any
	// Stable field order for readable, testable output.
	keys := make([]string, 0, len(a.Fields))
	for k := range a.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fields = append(fields, map[string]any{"title": k, "value": a.Fields[k], "short": true})
	}
	payload := map[string]any{
		"attachments": []map[string]any{{
			"color":     slackColor[a.Severity],
			"title":     fmt.Sprintf("[%s] %s", a.Severity, a.Title),
			"text":      a.Message,
			"footer":    "NeuroSentry · " + a.Source,
			"ts":        a.Timestamp.Unix(),
			"fields":    fields,
			"mrkdwn_in": []string{"text"},
		}},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}
