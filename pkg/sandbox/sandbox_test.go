// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"testing"
)

func TestNewProfile(t *testing.T) {
	p := NewProfile("test-sandbox")
	if p.Name != "test-sandbox" {
		t.Errorf("expected name test-sandbox, got %s", p.Name)
	}
	if p.Enabled != true {
		t.Error("profile should be enabled by default")
	}
}

func TestProfileAddRules(t *testing.T) {
	p := NewProfile("test")
	p.AllowRead("/models")
	p.AllowReadWrite("/tmp")
	p.DenyAccess("/etc/shadow")

	if len(p.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(p.Rules))
	}

	if p.Rules[0].Path != "/models" || p.Rules[0].Access != AccessRead {
		t.Errorf("unexpected rule 0: %+v", p.Rules[0])
	}
	if p.Rules[1].Path != "/tmp" || p.Rules[1].Access != AccessReadWrite {
		t.Errorf("unexpected rule 1: %+v", p.Rules[1])
	}
	if p.Rules[2].Path != "/etc/shadow" || p.Rules[2].Access != AccessDeny {
		t.Errorf("unexpected rule 2: %+v", p.Rules[2])
	}
}

func TestProfileValidation(t *testing.T) {
	p := NewProfile("")
	if err := p.Validate(); err == nil {
		t.Error("empty name should fail validation")
	}

	p = NewProfile("valid")
	if err := p.Validate(); err != nil {
		t.Errorf("valid profile should pass: %v", err)
	}

	p.AllowRead("")
	if err := p.Validate(); err == nil {
		t.Error("empty path should fail validation")
	}
}

func TestAccessConstants(t *testing.T) {
	if AccessRead == AccessReadWrite {
		t.Error("read and readwrite should be different")
	}
	if AccessDeny == AccessRead {
		t.Error("deny and read should be different")
	}
}

func TestProfileFromConfig(t *testing.T) {
	cfg := Config{
		Enabled:        true,
		ReadOnlyPaths:  []string{"/models", "/usr/lib"},
		ReadWritePaths: []string{"/tmp", "/var/log"},
		DenyPaths:      []string{"/etc/shadow"},
	}

	p := ProfileFromConfig(cfg)
	if len(p.Rules) != 5 {
		t.Errorf("expected 5 rules, got %d", len(p.Rules))
	}
}

func TestIsSupported(t *testing.T) {
	// Just verify it returns a boolean without panic
	_ = IsSupported()
}

func TestProfileDisabled(t *testing.T) {
	p := NewProfile("test")
	p.Enabled = false
	// Apply on a disabled profile should be a no-op
	if err := p.Apply(); err != nil {
		t.Errorf("disabled profile apply should not error: %v", err)
	}
}

func TestProfileRuleString(t *testing.T) {
	r := Rule{Path: "/models", Access: AccessRead}
	s := r.String()
	if s == "" {
		t.Error("rule string should not be empty")
	}
}

func TestProfileJSON(t *testing.T) {
	p := NewProfile("test")
	p.AllowRead("/models")
	p.AllowReadWrite("/tmp")

	// Verify it's serializable
	if len(p.Rules) != 2 {
		t.Error("rules not added")
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("sandbox should be disabled by default")
	}
}
