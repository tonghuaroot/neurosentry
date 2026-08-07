// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package breaker

import (
	"testing"
	"time"
)

func TestDisarmedByDefault(t *testing.T) {
	b := New(Policy{}) // Enabled defaults false
	if b.Armed() {
		t.Fatal("breaker must be disarmed by default (safe)")
	}
	d := b.Evaluate("critical", "NS-CORR-001", 4242)
	if d.Trip {
		t.Errorf("disarmed breaker must never trip, got %+v", d)
	}
}

func TestTripsOnCriticalWhenArmed(t *testing.T) {
	b := New(Policy{Enabled: true})
	d := b.Evaluate("critical", "NS-CORR-001", 4242)
	if !d.Trip {
		t.Fatalf("armed breaker should trip on critical: %+v", d)
	}
	if d.Action != "untrust_pid" || d.Params["pid"] != "4242" {
		t.Errorf("unexpected default action/params: %+v", d)
	}
	if b.TripCount() != 1 {
		t.Errorf("trip count should be 1, got %d", b.TripCount())
	}
}

func TestRespectsMinSeverity(t *testing.T) {
	b := New(Policy{Enabled: true, MinSeverity: "critical"})
	if b.Evaluate("high", "R", 10).Trip {
		t.Error("high should not trip when min severity is critical")
	}
	if !b.Evaluate("critical", "R", 10).Trip {
		t.Error("critical should trip")
	}

	b2 := New(Policy{Enabled: true, MinSeverity: "high"})
	if !b2.Evaluate("high", "R", 11).Trip {
		t.Error("high should trip when min severity is high")
	}
}

func TestRuleActionOverride(t *testing.T) {
	b := New(Policy{Enabled: true, RuleActions: map[string]string{"NS-CORR-008": "protect_extension"}})
	d := b.Evaluate("critical", "NS-CORR-008", 5)
	if d.Action != "protect_extension" {
		t.Errorf("per-rule action override not applied: %+v", d)
	}
	// A rule without an override falls back to the default.
	d2 := b.Evaluate("critical", "NS-CORR-001", 6)
	if d2.Action != "untrust_pid" {
		t.Errorf("expected default action, got %+v", d2)
	}
}

func TestCooldownPreventsStorm(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := New(Policy{Enabled: true, CooldownSecs: 60})
	b.now = func() time.Time { return now }

	if !b.Evaluate("critical", "R", 4242).Trip {
		t.Fatal("first should trip")
	}
	if b.Evaluate("critical", "R", 4242).Trip {
		t.Error("second within cooldown must NOT trip (anti-storm)")
	}
	// A different PID is independent.
	if !b.Evaluate("critical", "R", 9999).Trip {
		t.Error("different pid should trip independently")
	}
	// After the cooldown window, the same pid trips again.
	now = now.Add(61 * time.Second)
	if !b.Evaluate("critical", "R", 4242).Trip {
		t.Error("same pid should trip again after cooldown")
	}
}

func TestNoTargetPid(t *testing.T) {
	b := New(Policy{Enabled: true})
	if b.Evaluate("critical", "R", 0).Trip {
		t.Error("must not trip without a valid target pid")
	}
}

func TestRuntimeArmDisarm(t *testing.T) {
	b := New(Policy{Enabled: false})
	if b.Evaluate("critical", "R", 5).Trip {
		t.Error("disarmed should not trip")
	}
	b.SetArmed(true)
	if !b.Evaluate("critical", "R", 5).Trip {
		t.Error("should trip after arming")
	}
	b.SetArmed(false)
	if b.Evaluate("critical", "R", 6).Trip {
		t.Error("should not trip after disarming")
	}
}
