// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"os"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/correlate"
)

// The shipped sample dataset must actually populate the console: replaying it
// through the real engine should fire a healthy, varied set of findings. This
// guards the sample against silent breakage.
func TestSampleDatasetFiresRichFindings(t *testing.T) {
	f, err := os.Open("../../deploy/datasets/sample-mixed-telemetry.ndjson")
	if err != nil {
		t.Skipf("sample dataset not present: %v", err)
	}
	defer f.Close()

	events, err := ReadNDJSON(f, CombinedAdapter)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 80 {
		t.Fatalf("sample should carry substantial volume, got %d events", len(events))
	}

	c := correlate.NewCorrelator(correlate.BuiltinRules())
	rules := map[string]int{}
	c.OnFinding(func(f correlate.Finding) { rules[f.RuleID]++ })
	Replay(events, func(s correlate.Signal) { c.Ingest(s) })

	total := 0
	for _, n := range rules {
		total += n
	}
	if total < 15 {
		t.Errorf("sample should fire a healthy number of findings, got %d (%v)", total, rules)
	}
	// It should exercise multiple distinct detections, not just one.
	if len(rules) < 3 {
		t.Errorf("sample should trip several distinct rules, got %d: %v", len(rules), rules)
	}
	t.Logf("sample fired %d findings across %d rules: %v", total, len(rules), rules)
}
