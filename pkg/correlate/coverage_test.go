// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import "testing"

func TestComputeCoverageFromBuiltins(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	rep := ComputeCoverage(c.Detections())

	if rep.TotalRules < 11 {
		t.Errorf("expected the full built-in catalog, got %d rules", rep.TotalRules)
	}
	// Built-ins map to both frameworks.
	if rep.ATTACKCovered == 0 || rep.LLMCovered == 0 {
		t.Errorf("expected both ATT&CK and OWASP-LLM coverage, got attack=%d llm=%d", rep.ATTACKCovered, rep.LLMCovered)
	}
	// All built-ins are enabled, so covered == total techniques.
	if rep.CoveredTechs != rep.TotalTechs {
		t.Errorf("all built-ins enabled: expected covered==total, got %d/%d", rep.CoveredTechs, rep.TotalTechs)
	}

	// A known technique should be named and rule-counted.
	var found bool
	for _, tc := range rep.Techniques {
		if tc.ID == "T1041" {
			found = true
			if tc.Name != "Exfiltration Over C2 Channel" {
				t.Errorf("T1041 name wrong: %q", tc.Name)
			}
			if tc.RuleCount < 1 {
				t.Error("T1041 should have >=1 rule")
			}
		}
	}
	if !found {
		t.Error("expected T1041 in coverage")
	}
}

func TestCoverageReflectsDisabledRules(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	// Disable every rule; covered techniques should drop to zero while total
	// (known) techniques stay.
	for _, d := range c.Detections() {
		c.SetEnabled(d.ID, false)
	}
	rep := ComputeCoverage(c.Detections())
	if rep.EnabledRules != 0 {
		t.Errorf("expected 0 enabled rules, got %d", rep.EnabledRules)
	}
	if rep.CoveredTechs != 0 {
		t.Errorf("expected 0 covered techniques when all disabled, got %d", rep.CoveredTechs)
	}
	if rep.TotalTechs == 0 {
		t.Error("total techniques should still be known even when disabled")
	}
}
