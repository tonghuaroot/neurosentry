// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import "testing"

// TestEveryBuiltinRuleFires is the purple-team gate: each curated attack
// scenario must trip its target rule. A refactor that silently breaks a
// detection fails here.
func TestEveryBuiltinRuleFires(t *testing.T) {
	for _, r := range ValidateRules(BuiltinScenarios()) {
		if !r.Fired {
			t.Errorf("detection %s did NOT fire for scenario %q", r.RuleID, r.Scenario)
		}
	}
}

// TestScenarioCoverageIsComplete forces every built-in rule to ship with a
// proof-of-fire scenario — a new rule with no scenario fails the build.
func TestScenarioCoverageIsComplete(t *testing.T) {
	covered := map[string]bool{}
	for _, sc := range BuiltinScenarios() {
		covered[sc.WantRuleID] = true
	}
	for _, rule := range BuiltinRules() {
		if !covered[rule.ID] {
			t.Errorf("rule %s (%s) has no purple-team validation scenario", rule.ID, rule.Name)
		}
	}
}

// TestScenariosAreSpecific guards against a scenario that fires the wrong rule:
// each scenario should trip its target and not be entirely spurious.
func TestScenariosAreSpecific(t *testing.T) {
	for _, sc := range BuiltinScenarios() {
		c := NewCorrelator(BuiltinRules())
		var fired []string
		c.OnFinding(func(f Finding) { fired = append(fired, f.RuleID) })
		for _, s := range sc.Signals {
			c.Ingest(s)
		}
		hit := false
		for _, id := range fired {
			if id == sc.WantRuleID {
				hit = true
			}
		}
		if !hit {
			t.Errorf("scenario %q fired %v, expected %s", sc.Name, fired, sc.WantRuleID)
		}
	}
}
