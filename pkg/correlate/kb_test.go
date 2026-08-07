// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"strings"
	"testing"
)

func TestKnowledgeBaseCoversAllRules(t *testing.T) {
	kb := KnowledgeBase()
	if len(kb) != len(BuiltinRules()) {
		t.Fatalf("KB entries=%d, rules=%d — every rule needs an entry", len(kb), len(BuiltinRules()))
	}
	for _, e := range kb {
		if e.RuleID == "" || e.Summary == "" {
			t.Errorf("%s: missing id/summary", e.RuleID)
		}
		if e.Rationale == "" || len(e.Remediation) == 0 {
			t.Errorf("%s: missing curated guidance (rationale/remediation)", e.RuleID)
		}
		if e.MITRE != "" {
			found := false
			for _, r := range e.References {
				if strings.Contains(r, "attack.mitre.org/techniques/") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: MITRE %s but no attack.mitre.org reference", e.RuleID, e.MITRE)
			}
		}
	}
	// Sorted by rule ID.
	for i := 1; i < len(kb); i++ {
		if kb[i-1].RuleID > kb[i].RuleID {
			t.Errorf("KB not sorted: %s before %s", kb[i-1].RuleID, kb[i].RuleID)
		}
	}
	if len(SignalGlossary()) == 0 {
		t.Error("signal glossary is empty")
	}
}

func TestLiveKnowledgeBaseIncludesCustomRules(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	id, err := c.AddRule(RuleSpec{
		Name:        "Operator rule",
		Description: "detects a custom pattern",
		Severity:    "high",
		MitreAttack: "T1041",
		Rationale:   "why this custom rule matters",
		Remediation: []string{"respond step 1"},
		References:  []string{"https://example.com/runbook"},
		Matchers:    []MatcherSpec{{Layer: "mcp", Kind: "tool_call"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	kb := c.KnowledgeBase()
	if len(kb) != len(BuiltinRules())+1 {
		t.Fatalf("live KB should cover builtin+custom, got %d", len(kb))
	}
	var got KBEntry
	for _, e := range kb {
		if e.RuleID == id {
			got = e
		}
	}
	if got.RuleID != id {
		t.Fatal("custom rule missing from live KB")
	}
	// Custom rule draws its guidance from its own fields.
	if got.Rationale != "why this custom rule matters" || len(got.Remediation) != 1 {
		t.Errorf("custom KB entry should use rule's own guidance: %+v", got)
	}
	if got.Summary != "detects a custom pattern" {
		t.Errorf("custom KB summary should be the description, got %q", got.Summary)
	}
	// References merge the rule's own links with canonical MITRE/OWASP.
	var hasMitre, hasOwn bool
	for _, r := range got.References {
		if strings.Contains(r, "attack.mitre.org/techniques/T1041") {
			hasMitre = true
		}
		if r == "https://example.com/runbook" {
			hasOwn = true
		}
	}
	if !hasMitre || !hasOwn {
		t.Errorf("custom KB references should merge own + MITRE: %v", got.References)
	}
	// The package-level KB stays builtin-only for back-compat.
	if len(KnowledgeBase()) != len(BuiltinRules()) {
		t.Error("package-level KnowledgeBase must remain builtin-only")
	}
}

func TestKBSubTechniqueReference(t *testing.T) {
	// T1059.004 -> .../techniques/T1059/004/
	r := Rule{MitreAttack: "T1059.004"}
	refs := kbReferences(r)
	want := "https://attack.mitre.org/techniques/T1059/004/"
	found := false
	for _, u := range refs {
		if u == want {
			found = true
		}
	}
	if !found {
		t.Errorf("sub-technique link not built: %v", refs)
	}
}
