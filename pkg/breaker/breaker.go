// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package breaker is NeuroSentry's automated circuit breaker: it closes the loop
// from detection to enforcement. When the cross-layer correlation engine fires a
// high-confidence finding (e.g. a process read a secret and then phoned an LLM),
// the breaker can automatically apply a kernel-level mitigation — dropping the
// offending process from the LSM trusted allowlist so its next protected-file
// access is blocked — without waiting for a human.
//
// It is DISARMED by default. Auto-response is powerful and dangerous, so it only
// acts when an operator explicitly enables it, at/above a configured severity,
// and with a per-process cooldown so one episode can't storm the same action.
package breaker

import (
	"sync"
	"time"
)

// severityRank orders severities for the threshold comparison.
var severityRank = map[string]int{
	"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// Policy configures automated response. The zero value is safe: Enabled=false
// means the breaker never trips.
type Policy struct {
	Enabled       bool              // must be explicitly armed
	MinSeverity   string            // trip at/above this severity (default "critical")
	DefaultAction string            // response action when no per-rule override (default "untrust_pid")
	RuleActions   map[string]string // rule ID -> action override
	CooldownSecs  float64           // per (pid:action) cooldown to avoid storming (default 60)
}

// Decision is the breaker's verdict for one finding.
type Decision struct {
	Trip   bool              `json:"trip"`
	Action string            `json:"action,omitempty"`
	Params map[string]string `json:"params,omitempty"`
	Reason string            `json:"reason,omitempty"`
}

// Breaker evaluates findings against a policy and enforces the cooldown. Safe
// for concurrent use.
type Breaker struct {
	mu        sync.Mutex
	policy    Policy
	lastTrip  map[string]time.Time // "pid:action" -> last trip
	tripCount int64
	now       func() time.Time
}

// New builds a breaker, applying safe defaults for unset policy fields.
func New(p Policy) *Breaker {
	if p.MinSeverity == "" {
		p.MinSeverity = "critical"
	}
	if p.DefaultAction == "" {
		p.DefaultAction = "untrust_pid"
	}
	if p.CooldownSecs <= 0 {
		p.CooldownSecs = 60
	}
	return &Breaker{policy: p, lastTrip: make(map[string]time.Time), now: time.Now}
}

// Policy returns a copy of the active policy (for logging / display).
func (b *Breaker) Policy() Policy {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.policy
}

// Armed reports whether the breaker will act.
func (b *Breaker) Armed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.policy.Enabled
}

// SetArmed toggles enforcement at runtime (operator control).
func (b *Breaker) SetArmed(on bool) {
	b.mu.Lock()
	b.policy.Enabled = on
	b.mu.Unlock()
}

// TripCount returns how many times the breaker has fired.
func (b *Breaker) TripCount() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tripCount
}

// Evaluate decides whether a finding should trigger an automated response. It is
// decoupled from the correlate package (takes only the fields it needs) so the
// decision logic is independently testable. A tripping call records the cooldown
// and increments the counter.
func (b *Breaker) Evaluate(severity, ruleID string, pid int) Decision {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.policy.Enabled {
		return Decision{Trip: false, Reason: "breaker disarmed"}
	}
	if pid <= 0 {
		return Decision{Trip: false, Reason: "no target pid"}
	}
	if severityRank[severity] < severityRank[b.policy.MinSeverity] {
		return Decision{Trip: false, Reason: "below min severity"}
	}

	action := b.policy.DefaultAction
	if a, ok := b.policy.RuleActions[ruleID]; ok && a != "" {
		action = a
	}

	key := itoa(pid) + ":" + action
	now := b.now()
	if last, seen := b.lastTrip[key]; seen {
		if now.Sub(last).Seconds() < b.policy.CooldownSecs {
			return Decision{Trip: false, Reason: "cooldown"}
		}
	}
	b.lastTrip[key] = now
	b.tripCount++

	return Decision{
		Trip:   true,
		Action: action,
		Params: map[string]string{"pid": itoa(pid)},
		Reason: "auto-response: " + severity + " finding " + ruleID,
	}
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
