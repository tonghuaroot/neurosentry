// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package correlate is NeuroSentry's cross-layer correlation engine — the
// capability no userspace AI gateway can offer. It fuses AI-layer *intent*
// (MCP tool calls, LLM gateway requests) with kernel-layer *action* (the file,
// network, and process events those calls actually trigger, observed via eBPF)
// into per-process causal chains, and fires when a rule's cross-layer pattern
// is satisfied within a time window.
//
// A gateway sees a tool call named "search_files"; the correlation engine sees
// that same call read /etc/shadow and then opened a connection to an unknown
// host. Connecting intent to consequence is the differentiator.
package correlate

import (
	"sort"
	"sync"
	"time"
)

// Layer identifies which observation plane a signal came from.
type Layer string

const (
	LayerAI         Layer = "ai"          // LLM gateway request/response
	LayerMCP        Layer = "mcp"         // MCP tool call
	LayerKernelFile Layer = "kernel_file" // LSM file access
	LayerKernelNet  Layer = "kernel_net"  // TC/XDP network flow
	LayerKernelProc Layer = "kernel_proc" // process exec
	LayerModel      Layer = "model"       // model load (uprobe)
)

// Signal is a single normalized observation from any layer, tagged with the
// process and tenant it belongs to so signals can be correlated.
type Signal struct {
	Timestamp  time.Time
	PID        int
	TenantID   string
	Layer      Layer
	Kind       string            // e.g. "tool_call", "file_read", "net_connect"
	Attributes map[string]string // e.g. {"path": "/etc/shadow", "dst": "1.2.3.4"}
	Severity   string
}

// Attr is a nil-safe attribute accessor.
func (s Signal) Attr(key string) string {
	if s.Attributes == nil {
		return ""
	}
	return s.Attributes[key]
}

// Finding is emitted when a correlation rule fires.
type Finding struct {
	Timestamp   time.Time `json:"timestamp"`
	RuleID      string    `json:"rule_id,omitempty"`
	Rule        string    `json:"rule"`
	PID         int       `json:"pid"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Severity    string    `json:"severity"`
	Technique   string    `json:"technique,omitempty"`
	Description string    `json:"description"`
	Chain       []Signal  `json:"chain"` // the signals that made up the causal chain
}

// Correlator ingests signals and fires cross-layer findings. It keeps a bounded
// per-process window of recent signals. Safe for concurrent use.
type Correlator struct {
	mu               sync.Mutex
	rules            []Rule
	enabled          map[string]bool  // rule ID -> enabled
	fireCount        map[string]int64 // rule ID -> total fires
	custom           map[string]bool  // rule ID -> user-defined (removable)
	suppressions     map[string]*suppression
	learning         bool // baseline mode: observe + count, don't alert
	sessions         map[int]*pidSession
	maxSessions      int
	lastFired        map[string]time.Time // "pid:rule" -> last fire (cooldown)
	maxWindow        time.Duration
	onFinding        func(Finding)
	now              func() time.Time
	recent           []Finding // ring of recent findings for API/dashboard
	maxRecent        int
	recentSignals    []Signal // ring of raw ingested signals for the events view
	maxRecentSignals int
}

// RecentSignals returns up to limit most-recent raw ingested signals (newest
// last) — the telemetry underlying findings, for the events view.
func (c *Correlator) RecentSignals(limit int) []Signal {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 || limit > len(c.recentSignals) {
		limit = len(c.recentSignals)
	}
	out := make([]Signal, limit)
	copy(out, c.recentSignals[len(c.recentSignals)-limit:])
	return out
}

// DetectionInfo is the operator-facing view of a correlation rule for the
// detections library (metadata, enabled state, and how often it has fired).
type DetectionInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Technique   string   `json:"technique,omitempty"`
	MitreAttack string   `json:"mitre_attack,omitempty"`
	Description string   `json:"description"`
	References  []string `json:"references,omitempty"`
	Enabled     bool     `json:"enabled"`
	Custom      bool     `json:"custom"`
	FireCount   int64    `json:"fire_count"`
	WindowSecs  float64  `json:"window_secs"`
	Ordered     bool     `json:"ordered"`
	// Authoring detail so the console's rule editor can prefill an existing rule.
	Matchers       []MatcherSpec `json:"matchers,omitempty"`
	Rationale      string        `json:"rationale,omitempty"`
	Remediation    []string      `json:"remediation,omitempty"`
	FalsePositives []string      `json:"false_positives,omitempty"`
}

type pidSession struct {
	signals    []Signal
	lastActive time.Time
}

// Fail-safe bounds. A hostile or runaway workload (fork bomb, log flood) must
// not be able to grow the correlator's memory without limit. Two ceilings:
//   - per-session signal history is capped (sessionSignalCap), so a single
//     chatty PID can't accumulate unbounded state;
//   - the number of tracked sessions is capped (defaultMaxSessions), so a
//     churn of short-lived PIDs can't exhaust memory before the death-watcher
//     reaps them. Overflow triggers batch LRU eviction of the least-recently
//     active sessions.
const (
	sessionSignalCap   = 256
	defaultMaxSessions = 8192
)

// NewCorrelator builds an engine with the given rules. The retention window is
// derived from the widest rule window so no rule is starved of history.
func NewCorrelator(rules []Rule) *Correlator {
	maxWin := time.Minute
	for _, r := range rules {
		if r.Window > maxWin {
			maxWin = r.Window
		}
	}
	enabled := make(map[string]bool, len(rules))
	for _, r := range rules {
		enabled[r.ID] = true
	}
	return &Correlator{
		rules:            rules,
		enabled:          enabled,
		fireCount:        make(map[string]int64),
		sessions:         make(map[int]*pidSession),
		maxSessions:      defaultMaxSessions,
		lastFired:        make(map[string]time.Time),
		maxWindow:        maxWin,
		onFinding:        func(Finding) {},
		now:              time.Now,
		maxRecent:        5000,
		maxRecentSignals: 20000,
	}
}

// Detections returns the rule catalog with enabled state and fire counts for
// the management UI.
func (c *Correlator) Detections() []DetectionInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]DetectionInfo, 0, len(c.rules))
	for i := range c.rules {
		r := &c.rules[i]
		out = append(out, DetectionInfo{
			ID: r.ID, Name: r.Name, Category: r.Category, Severity: r.Severity,
			Technique: r.Technique, MitreAttack: r.MitreAttack, Description: r.Description,
			References: r.References, Enabled: c.enabled[r.ID], Custom: c.custom[r.ID], FireCount: c.fireCount[r.ID],
			WindowSecs: r.Window.Seconds(), Ordered: r.Ordered, Matchers: r.matcherSpecs(),
			Rationale: r.Rationale, Remediation: r.Remediation, FalsePositives: r.FalsePositives,
		})
	}
	return out
}

// SetEnabled toggles a detection rule by ID. Returns false if the ID is unknown.
func (c *Correlator) SetEnabled(id string, on bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.enabled[id]; !ok {
		return false
	}
	c.enabled[id] = on
	return true
}

// RecentFindings returns up to limit most-recent findings (newest last). Used by
// the web API / dashboard to render the causal-chain feed.
func (c *Correlator) RecentFindings(limit int) []Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 || limit > len(c.recent) {
		limit = len(c.recent)
	}
	out := make([]Finding, limit)
	copy(out, c.recent[len(c.recent)-limit:])
	return out
}

// OnFinding registers a sink (wire to the audit chain / alert router).
func (c *Correlator) OnFinding(fn func(Finding)) {
	if fn != nil {
		c.onFinding = fn
	}
}

// Ingest records a signal and returns any findings it completes. A rule fires
// on the signal that *completes* its pattern, so causality flows forward.
func (c *Correlator) Ingest(s Signal) []Finding {
	c.mu.Lock()

	if s.Timestamp.IsZero() {
		s.Timestamp = c.now()
	}

	// Keep a bounded ring of raw ingested signals so the console can show the
	// underlying telemetry (imported datasets, live events), not only findings.
	c.recentSignals = append(c.recentSignals, s)
	if len(c.recentSignals) > c.maxRecentSignals {
		c.recentSignals = c.recentSignals[len(c.recentSignals)-c.maxRecentSignals:]
	}

	sess := c.sessions[s.PID]
	if sess == nil {
		if len(c.sessions) >= c.maxSessions {
			c.evictLocked()
		}
		sess = &pidSession{}
		c.sessions[s.PID] = sess
	}
	sess.lastActive = s.Timestamp
	sess.signals = append(sess.signals, s)
	c.pruneLocked(sess, s.Timestamp)

	var findings []Finding
	for i := range c.rules {
		rule := &c.rules[i]
		// Skip disabled detections.
		if !c.enabled[rule.ID] {
			continue
		}
		// Only evaluate rules the new signal could complete.
		if !rule.touchedBy(s) {
			continue
		}
		chain, ok := rule.evaluate(sess.signals, s.Timestamp)
		if !ok {
			continue
		}
		key := fireKey(s.PID, rule.Name)
		if last, seen := c.lastFired[key]; seen && s.Timestamp.Sub(last) < rule.Window {
			continue // cooldown: don't restorm on the same episode
		}

		f := Finding{
			Timestamp:   s.Timestamp,
			RuleID:      rule.ID,
			Rule:        rule.Name,
			PID:         s.PID,
			TenantID:    s.TenantID,
			Severity:    rule.Severity,
			Technique:   rule.Technique,
			Description: rule.Description,
			Chain:       chain,
		}
		// False-positive tuning: an operator suppression silences a known-benign
		// match. Suppressed findings don't fire, aren't recorded, and don't start
		// a cooldown — but the suppression's counter is bumped for auditability.
		if c.suppressedLocked(f) {
			continue
		}
		c.lastFired[key] = s.Timestamp
		c.fireCount[rule.ID]++
		findings = append(findings, f)
		c.recent = append(c.recent, f)
		if len(c.recent) > c.maxRecent {
			c.recent = c.recent[len(c.recent)-c.maxRecent:]
		}
	}
	learning := c.learning
	c.mu.Unlock()

	// In learning/baseline mode, findings are still recorded (visible in the
	// dashboard, counted per rule) but external sinks — alerts, cases, notify —
	// are NOT fired. This lets an operator observe what would trigger and tune
	// suppressions before enabling enforcement, without paging anyone.
	if !learning {
		// Fire external sinks outside the lock so a sink can safely call back.
		for _, f := range findings {
			c.onFinding(f)
		}
	}
	return findings
}

// SetLearningMode toggles baseline mode. When on, findings are observed and
// counted but no alerts/cases/notifications fire.
func (c *Correlator) SetLearningMode(on bool) {
	c.mu.Lock()
	c.learning = on
	c.mu.Unlock()
}

// LearningMode reports whether baseline mode is active.
func (c *Correlator) LearningMode() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.learning
}

// pruneLocked drops signals older than the retention window and bounds memory.
func (c *Correlator) pruneLocked(sess *pidSession, now time.Time) {
	cutoff := now.Add(-c.maxWindow)
	i := 0
	for ; i < len(sess.signals); i++ {
		if !sess.signals[i].Timestamp.Before(cutoff) {
			break
		}
	}
	if i > 0 {
		sess.signals = sess.signals[i:]
	}
	if len(sess.signals) > sessionSignalCap {
		// Reslice to the most-recent cap signals. This is O(1); Go's append
		// reallocates the backing array once it fills, and the old array is
		// GC'd, so steady-state memory stabilizes at ~2×cap per session rather
		// than growing without bound.
		sess.signals = sess.signals[len(sess.signals)-sessionSignalCap:]
	}
}

// evictLocked drops the least-recently-active quarter of sessions when the
// session table overflows its cap. Batch eviction amortizes the O(n) scan so a
// steady churn of new PIDs doesn't pay it on every insert. Caller holds c.mu.
func (c *Correlator) evictLocked() {
	type aged struct {
		pid  int
		last time.Time
	}
	ages := make([]aged, 0, len(c.sessions))
	for pid, sess := range c.sessions {
		ages = append(ages, aged{pid, sess.lastActive})
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].last.Before(ages[j].last) })
	drop := len(ages) / 4
	if drop == 0 {
		drop = 1
	}
	for i := 0; i < drop; i++ {
		delete(c.sessions, ages[i].pid)
		delete(c.lastFired, fireKeyPrefix(ages[i].pid))
	}
}

// Reap drops per-process state for a PID that has exited (call from the
// trusted-PID death watcher). Keeps memory bounded on churny nodes.
func (c *Correlator) Reap(pid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, pid)
	delete(c.lastFired, fireKeyPrefix(pid))
}

func fireKey(pid int, rule string) string {
	return itoa(pid) + ":" + rule
}

func fireKeyPrefix(pid int) string {
	return itoa(pid) + ":"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
