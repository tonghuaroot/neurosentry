// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"testing"
	"time"
)

// tool-then-external-egress chain that trips NS-CORR-002.
func exfilChain(dst string, base time.Time) []Signal {
	return []Signal{
		{PID: 30, Layer: LayerMCP, Kind: "tool_call", Attributes: map[string]string{"tool": "fetch"}, Timestamp: base},
		{PID: 30, Layer: LayerKernelNet, Kind: "net_connect", Attributes: map[string]string{"dst": dst}, Timestamp: base.Add(time.Second)},
	}
}

func TestSuppressionSilencesKnownBenign(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	var fired []Finding
	c.OnFinding(func(f Finding) { fired = append(fired, f) })

	// Suppress NS-CORR-002 when the destination is a known-good backup host.
	id, err := c.AddSuppression(SuppressionSpec{
		RuleID: "NS-CORR-002", AttrKey: "dst", AttrPattern: `^203\.0\.113\.7$`,
		Reason: "sanctioned backup egress",
	})
	if err != nil {
		t.Fatalf("add suppression: %v", err)
	}

	base := time.Unix(1_700_000_000, 0)
	for _, s := range exfilChain("203.0.113.7", base) { // benign dst -> suppressed
		c.Ingest(s)
	}
	if len(fired) != 0 {
		t.Fatalf("expected the finding to be suppressed, got %d", len(fired))
	}
	// The suppression counter should reflect the silenced match.
	sup := c.Suppressions()
	if len(sup) != 1 || sup[0].MatchCount != 1 {
		t.Errorf("expected 1 suppression with match_count 1, got %+v", sup)
	}

	// A DIFFERENT destination must still fire (suppression is specific).
	for _, s := range exfilChain("198.51.100.9", base.Add(time.Minute)) {
		c.Ingest(s)
	}
	if len(fired) != 1 {
		t.Errorf("non-benign egress should still fire, got %d findings", len(fired))
	}

	// Removing the suppression restores firing for the benign dst too.
	if err := c.RemoveSuppression(id); err != nil {
		t.Fatalf("remove: %v", err)
	}
	for _, s := range exfilChain("203.0.113.7", base.Add(2*time.Minute)) {
		c.Ingest(s)
	}
	if len(fired) != 2 {
		t.Errorf("after removing suppression the benign dst should fire, got %d", len(fired))
	}
}

func TestSuppressionValidation(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	if _, err := c.AddSuppression(SuppressionSpec{RuleID: "NS-CORR-002"}); err == nil {
		t.Error("suppression without attr_key/pattern should error")
	}
	if _, err := c.AddSuppression(SuppressionSpec{AttrKey: "dst", AttrPattern: "("}); err == nil {
		t.Error("invalid regex should error")
	}
	if err := c.RemoveSuppression("nope"); err == nil {
		t.Error("removing unknown suppression should error")
	}
}
