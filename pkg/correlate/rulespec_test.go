// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"testing"
	"time"
)

func TestAddCustomRuleFires(t *testing.T) {
	c := newEngine()
	// A user-defined rule: a tool call reading a path matching /secret/.
	id, err := c.AddRule(RuleSpec{
		Name: "custom-secret-tool", Severity: "high", WindowSecs: 5, Ordered: true,
		Matchers: []MatcherSpec{
			{Layer: "mcp", Kind: "tool_call"},
			{Layer: "kernel_file", Kind: "file_read", AttrKey: "path", AttrPattern: "(?i)/secret/"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Ingest(sig(900, LayerMCP, "tool_call", at(0), nil))
	f := c.Ingest(sig(900, LayerKernelFile, "file_read", at(1*time.Second), map[string]string{"path": "/data/secret/creds"}))
	fired := false
	for _, x := range f {
		if x.RuleID == id {
			fired = true
		}
	}
	if !fired {
		t.Errorf("custom rule should fire, got %+v", f)
	}
	// Appears in the catalog as custom.
	var found bool
	for _, d := range c.Detections() {
		if d.ID == id {
			found = true
			if !d.Custom {
				t.Error("custom rule should be flagged custom")
			}
		}
	}
	if !found {
		t.Error("custom rule missing from catalog")
	}
}

func TestRemoveCustomRuleOnly(t *testing.T) {
	c := newEngine()
	id, _ := c.AddRule(RuleSpec{Name: "x", Matchers: []MatcherSpec{{Layer: "model", Kind: "load"}}})
	if err := c.RemoveRule(id); err != nil {
		t.Fatalf("should remove custom rule: %v", err)
	}
	// Built-in rules cannot be removed.
	if err := c.RemoveRule("NS-CORR-001"); err == nil {
		t.Error("built-in rule must not be removable")
	}
}

func TestUpdateCustomRuleInPlace(t *testing.T) {
	c := newEngine()
	id, err := c.AddRule(RuleSpec{
		Name: "v1", Severity: "medium", WindowSecs: 5, Ordered: true,
		Matchers: []MatcherSpec{
			{Layer: "mcp", Kind: "tool_call"},
			{Layer: "kernel_file", Kind: "file_read", AttrKey: "path", AttrPattern: "(?i)/secret/"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fire once so we have a non-zero fire count and a disabled state to preserve.
	c.Ingest(sig(900, LayerMCP, "tool_call", at(0), nil))
	c.Ingest(sig(900, LayerKernelFile, "file_read", at(1*time.Second), map[string]string{"path": "/data/secret/creds"}))
	c.SetEnabled(id, false)

	// Update the rule in place: new name/severity, still custom.
	updated, err := c.UpdateRule(RuleSpec{
		ID: id, Name: "v2", Severity: "high", WindowSecs: 30, Ordered: true,
		Rationale:   "operator rationale",
		Remediation: []string{"do the thing"},
		Matchers: []MatcherSpec{
			{Layer: "mcp", Kind: "tool_call"},
			{Layer: "kernel_net", Kind: "net_connect", AttrKey: "dst", AttrPattern: "."},
		},
	})
	if err != nil {
		t.Fatalf("update should succeed: %v", err)
	}
	if updated.Name != "v2" || updated.Severity != "high" {
		t.Errorf("update did not apply: %+v", updated)
	}
	// Enabled state and fire count preserved across the swap.
	var d DetectionInfo
	for _, x := range c.Detections() {
		if x.ID == id {
			d = x
		}
	}
	if d.ID != id {
		t.Fatal("updated rule missing from catalog")
	}
	if d.Enabled {
		t.Error("enabled state (disabled) should be preserved across update")
	}
	if d.FireCount != 1 {
		t.Errorf("fire count should be preserved, got %d", d.FireCount)
	}
	if d.Name != "v2" {
		t.Errorf("catalog should reflect updated name, got %q", d.Name)
	}
}

func TestUpdateRuleRejectsBuiltinAndUnknown(t *testing.T) {
	c := newEngine()
	if _, err := c.UpdateRule(RuleSpec{ID: "NS-CORR-001", Name: "x", Matchers: []MatcherSpec{{Layer: "ai"}}}); err != ErrRuleNotCustom {
		t.Errorf("builtin update should be ErrRuleNotCustom, got %v", err)
	}
	if _, err := c.UpdateRule(RuleSpec{ID: "NS-CUSTOM-deadbeef", Name: "x", Matchers: []MatcherSpec{{Layer: "ai"}}}); err != ErrRuleNotFound {
		t.Errorf("unknown update should be ErrRuleNotFound, got %v", err)
	}
	// A custom rule with an invalid spec surfaces the compile error (not a 404).
	id, _ := c.AddRule(RuleSpec{Name: "ok", Matchers: []MatcherSpec{{Layer: "ai", Kind: "prompt"}}})
	if _, err := c.UpdateRule(RuleSpec{ID: id, Name: "bad", Matchers: []MatcherSpec{{Layer: "kernel_file", AttrKey: "path", AttrPattern: "([unclosed"}}}); err == nil || err == ErrRuleNotFound || err == ErrRuleNotCustom {
		t.Errorf("invalid regex on a custom rule should be a compile error, got %v", err)
	}
}

func TestInvalidRuleSpec(t *testing.T) {
	c := newEngine()
	if _, err := c.AddRule(RuleSpec{Name: "", Matchers: []MatcherSpec{{Layer: "mcp"}}}); err == nil {
		t.Error("empty name should error")
	}
	if _, err := c.AddRule(RuleSpec{Name: "bad-regex", Matchers: []MatcherSpec{{Layer: "kernel_file", AttrKey: "path", AttrPattern: "([unclosed"}}}); err == nil {
		t.Error("invalid regex should error")
	}
}
