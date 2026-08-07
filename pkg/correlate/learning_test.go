// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"testing"
	"time"
)

func TestLearningModeSuppressesAlertsButObserves(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	var alerted int
	c.OnFinding(func(Finding) { alerted++ })
	c.SetLearningMode(true)

	base := time.Unix(1_700_000_000, 0)
	// secret-read-then-llm chain (NS-CORR-001).
	c.Ingest(Signal{PID: 5, Layer: LayerKernelFile, Kind: "file_read",
		Attributes: map[string]string{"path": "/etc/shadow"}, Timestamp: base})
	found := c.Ingest(Signal{PID: 5, Layer: LayerKernelNet, Kind: "net_connect",
		Attributes: map[string]string{"ai_provider": "openai"}, Timestamp: base.Add(time.Second)})

	// The finding is produced and observable, but no external sink fired.
	if len(found) == 0 {
		t.Fatal("finding should still be produced in learning mode")
	}
	if alerted != 0 {
		t.Errorf("learning mode must not fire alerts, got %d", alerted)
	}
	if len(c.RecentFindings(0)) == 0 {
		t.Error("learning-mode findings should still be recorded for visibility")
	}
	// And the rule's fire count should reflect the observation.
	var counted bool
	for _, d := range c.Detections() {
		if d.ID == "NS-CORR-001" && d.FireCount >= 1 {
			counted = true
		}
	}
	if !counted {
		t.Error("learning-mode findings should still increment the rule fire count")
	}
}

func TestLeavingLearningModeRestoresAlerts(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	var alerted int
	c.OnFinding(func(Finding) { alerted++ })

	c.SetLearningMode(true)
	if !c.LearningMode() {
		t.Fatal("learning mode should be on")
	}
	c.SetLearningMode(false)
	if c.LearningMode() {
		t.Fatal("learning mode should be off")
	}

	base := time.Unix(1_700_000_000, 0)
	c.Ingest(Signal{PID: 6, Layer: LayerKernelFile, Kind: "file_read",
		Attributes: map[string]string{"path": "/etc/shadow"}, Timestamp: base})
	c.Ingest(Signal{PID: 6, Layer: LayerKernelNet, Kind: "net_connect",
		Attributes: map[string]string{"ai_provider": "openai"}, Timestamp: base.Add(time.Second)})

	if alerted == 0 {
		t.Error("with learning mode off, alerts should fire again")
	}
}
