// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"sync"
	"time"
)

// LoginGuard throttles repeated authentication failures per identity to blunt
// online brute-force and credential-stuffing attacks. It tracks failures within
// a sliding window and locks the identity out for a cooldown once a threshold is
// crossed. A successful login clears the record.
type LoginGuard struct {
	mu          sync.Mutex
	records     map[string]*attemptRecord
	maxFailures int
	window      time.Duration
	lockout     time.Duration
	now         func() time.Time // injectable for deterministic tests
}

type attemptRecord struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

// NewLoginGuard builds a guard. maxFailures failures within window trigger a
// lockout of the given duration. Sensible defaults are applied for non-positive
// arguments (5 failures / 15m window / 15m lockout).
func NewLoginGuard(maxFailures int, window, lockout time.Duration) *LoginGuard {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	if lockout <= 0 {
		lockout = 15 * time.Minute
	}
	return &LoginGuard{
		records:     make(map[string]*attemptRecord),
		maxFailures: maxFailures,
		window:      window,
		lockout:     lockout,
		now:         time.Now,
	}
}

// Allowed reports whether an authentication attempt for key may proceed. It is
// false while the identity is in a lockout cooldown.
func (g *LoginGuard) Allowed(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec, ok := g.records[key]
	if !ok {
		return true
	}
	if rec.lockedUntil.IsZero() {
		return true
	}
	if g.now().Before(rec.lockedUntil) {
		return false
	}
	// Lockout elapsed: reset so the identity gets a fresh window.
	delete(g.records, key)
	return true
}

// RecordFailure registers a failed attempt for key, opening or extending the
// window and applying a lockout once the failure threshold is reached.
func (g *LoginGuard) RecordFailure(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	rec, ok := g.records[key]
	if !ok || now.Sub(rec.windowStart) > g.window {
		rec = &attemptRecord{windowStart: now}
		g.records[key] = rec
	}
	rec.failures++
	if rec.failures >= g.maxFailures {
		rec.lockedUntil = now.Add(g.lockout)
	}
}

// RecordSuccess clears any failure state for key.
func (g *LoginGuard) RecordSuccess(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.records, key)
}

// LockedUntil returns the time the identity is locked until, or zero if not
// locked. Useful for surfacing Retry-After to clients.
func (g *LoginGuard) LockedUntil(key string) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	if rec, ok := g.records[key]; ok {
		return rec.lockedUntil
	}
	return time.Time{}
}
