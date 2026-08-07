// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import "testing"

func fullCaps() Capabilities {
	return Capabilities{
		KernelVersion: "6.1.0", KernelMajor: 6, KernelMinor: 1,
		Privileged: true, BTF: true, Ringbuf: true, BPFLSM: true, TC: true, Uprobe: true,
	}
}

func TestAssessFullSupport(t *testing.T) {
	a := fullCaps().Assess(true)
	if a.Level != SupportFull {
		t.Fatalf("expected supported, got %s (%s)", a.Level, a)
	}
	if a.EnforceUnavailable {
		t.Error("enforce should be available with BPF LSM present")
	}
}

func TestAssessEnforceFailsSafeWithoutLSM(t *testing.T) {
	c := fullCaps()
	c.BPFLSM = false
	a := c.Assess(true) // operator asked to enforce
	if !a.EnforceUnavailable {
		t.Fatal("enforce requested without BPF LSM must flag EnforceUnavailable (fail-safe)")
	}
	if a.Level == SupportFull {
		t.Errorf("must not report full support when enforcement can't be honored: %s", a)
	}
	if len(a.Blocking) == 0 {
		t.Error("missing BPF LSM under enforce should be a blocking issue")
	}
}

func TestAssessMonitorOnlyWithoutLSM(t *testing.T) {
	c := fullCaps()
	c.BPFLSM = false
	a := c.Assess(false) // monitor-only mode
	if a.EnforceUnavailable {
		t.Error("monitor-only must not flag EnforceUnavailable")
	}
	if a.Level != SupportDegraded {
		t.Errorf("no-LSM monitor-only should be degraded, got %s", a.Level)
	}
	if len(a.Blocking) != 0 {
		t.Errorf("monitor-only should have no blocking issues, got %v", a.Blocking)
	}
}

func TestAssessUnsupportedWithoutCore(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Capabilities)
	}{
		{"no privilege", func(c *Capabilities) { c.Privileged = false }},
		{"no BTF", func(c *Capabilities) { c.BTF = false }},
		{"no ringbuf", func(c *Capabilities) { c.Ringbuf = false }},
	} {
		c := fullCaps()
		tc.mut(&c)
		if a := c.Assess(false); a.Level != SupportUnsupported {
			t.Errorf("%s: expected unsupported, got %s", tc.name, a.Level)
		}
	}
}

func TestAssessDegradedOnReducedFeatures(t *testing.T) {
	c := fullCaps()
	c.Uprobe = false
	c.TC = false
	a := c.Assess(true)
	if a.Level != SupportDegraded {
		t.Fatalf("missing uprobe/TC should be degraded, got %s", a.Level)
	}
	if len(a.Reduced) != 2 {
		t.Errorf("expected 2 reduced features, got %v", a.Reduced)
	}
}
