// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
)

func TestNewPolicyEngine(t *testing.T) {
	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			ModelFIM: config.ModelFIMConfig{
				Enabled:             true,
				ProtectedExtensions: []string{".safetensors", ".pth"},
				TrustedPIDs:         []int{1000, 2000},
			},
			NetworkContainment: config.NetworkContainmentConfig{
				Enabled:       true,
				AllowedEgress: []string{"10.0.0.0/8"},
			},
			PickleProtection: config.PickleProtectionConfig{
				Enabled:          true,
				DangerousSymbols: []string{"os.system", "eval"},
			},
		},
	}

	pol := policy.DefaultPolicy()
	metrics := &MetricsCollector{}

	// Create policy engine without BPF manager (nil is acceptable for unit tests)
	engine := NewPolicyEngine(cfg, nil, pol, metrics)

	if engine == nil {
		t.Fatal("Expected non-nil policy engine")
	}
	if engine.Name() != "policy-engine" {
		t.Errorf("Expected name 'policy-engine', got '%s'", engine.Name())
	}
}

func TestPolicyEngineStartStop(t *testing.T) {
	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			ModelFIM: config.ModelFIMConfig{
				Enabled: false,
			},
			NetworkContainment: config.NetworkContainmentConfig{
				Enabled: false,
			},
			PickleProtection: config.PickleProtectionConfig{
				Enabled: false,
			},
		},
	}

	pol := policy.DefaultPolicy()

	engine := NewPolicyEngine(cfg, nil, pol, nil)

	ctx := context.Background()

	// Start should succeed even without BPF manager
	if err := engine.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Stop should always succeed
	if err := engine.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestPolicyEngineEvaluate(t *testing.T) {
	cfg := &config.Config{}
	pol := policy.DefaultPolicy()
	engine := NewPolicyEngine(cfg, nil, pol, nil)

	// Test with various events - default policy should allow
	events := []Event{
		{
			Type:     EventTypeFileAccess,
			Severity: "info",
			Source:   EventSource{PID: 1234},
		},
		{
			Type:     EventTypeNetworkAllowed,
			Severity: "info",
			Source:   EventSource{PID: 5678},
		},
		{
			Type:     EventTypeModelLoad,
			Severity: "info",
			Source:   EventSource{PID: 9012},
		},
	}

	for _, event := range events {
		action := engine.Evaluate(event)
		// Default policy should return allow for most events
		if action != policy.ActionAllow && action != policy.ActionAlert && action != policy.ActionBlock {
			t.Errorf("Evaluate() returned invalid action for event type %s", event.Type)
		}
	}
}

func TestPolicyEngineConcurrency(t *testing.T) {
	cfg := &config.Config{}
	pol := policy.DefaultPolicy()
	engine := NewPolicyEngine(cfg, nil, pol, nil)

	// Test concurrent evaluate calls
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			event := Event{
				Type:     EventTypeFileAccess,
				Severity: "info",
				Source:   EventSource{PID: id},
			}
			_ = engine.Evaluate(event)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
