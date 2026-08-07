// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"testing"
	"time"
)

// fakeClock lets tests advance time deterministically.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newGuardWithClock(max int, window, lockout time.Duration, c *fakeClock) *LoginGuard {
	g := NewLoginGuard(max, window, lockout)
	g.now = c.now
	return g
}

func TestLoginGuardAllowsUntilThreshold(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	g := newGuardWithClock(3, time.Minute, time.Minute, clock)

	if !g.Allowed("user@x") {
		t.Fatal("fresh identity should be allowed")
	}
	g.RecordFailure("user@x")
	g.RecordFailure("user@x")
	if !g.Allowed("user@x") {
		t.Error("should still be allowed below threshold")
	}
	g.RecordFailure("user@x") // 3rd failure hits threshold
	if g.Allowed("user@x") {
		t.Error("should be locked out at threshold")
	}
}

func TestLoginGuardUnlocksAfterCooldown(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	g := newGuardWithClock(2, time.Minute, 5*time.Minute, clock)

	g.RecordFailure("a")
	g.RecordFailure("a")
	if g.Allowed("a") {
		t.Fatal("should be locked")
	}
	clock.advance(4 * time.Minute)
	if g.Allowed("a") {
		t.Error("still within lockout, should be denied")
	}
	clock.advance(2 * time.Minute) // total 6m > 5m lockout
	if !g.Allowed("a") {
		t.Error("lockout elapsed, should be allowed")
	}
}

func TestLoginGuardSuccessClears(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	g := newGuardWithClock(3, time.Minute, time.Minute, clock)
	g.RecordFailure("a")
	g.RecordFailure("a")
	g.RecordSuccess("a")
	// After success, a fresh set of failures is needed to lock again.
	g.RecordFailure("a")
	if !g.Allowed("a") {
		t.Error("success should have reset failure count")
	}
}

func TestLoginGuardWindowExpiry(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	g := newGuardWithClock(3, time.Minute, time.Minute, clock)
	g.RecordFailure("a")
	g.RecordFailure("a")
	clock.advance(2 * time.Minute) // window (1m) elapsed
	g.RecordFailure("a")           // starts a new window, count = 1
	if !g.Allowed("a") {
		t.Error("failures outside window should not accumulate into lockout")
	}
}

func TestLoginGuardIsolatesKeys(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	g := newGuardWithClock(2, time.Minute, time.Minute, clock)
	g.RecordFailure("a")
	g.RecordFailure("a") // a is locked
	if g.Allowed("a") {
		t.Fatal("a should be locked")
	}
	if !g.Allowed("b") {
		t.Error("b must be unaffected by a's lockout")
	}
}

func TestLoginGuardLockedUntil(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	g := newGuardWithClock(1, time.Minute, 10*time.Minute, clock)
	g.RecordFailure("a")
	lu := g.LockedUntil("a")
	if !lu.Equal(clock.t.Add(10 * time.Minute)) {
		t.Errorf("LockedUntil wrong: %v", lu)
	}
}
