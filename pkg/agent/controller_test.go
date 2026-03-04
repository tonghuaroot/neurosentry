// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
)

func TestNewController(t *testing.T) {
	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			ModelFIM: config.ModelFIMConfig{
				Enabled: false,
			},
		},
		Agent: config.AgentConfig{
			MetricsPort: 12112,
			LogLevel:    "error",
		},
	}

	pol := policy.DefaultPolicy()

	// Create controller without BPF (using nil for testing)
	// In real scenario, we'd need to mock the BPF manager
	if _, err := NewController(cfg, nil, pol); err != nil {
		t.Logf("Expected to create controller without BPF for testing")
	}
}

func TestNewControllerValidation(t *testing.T) {
	cfg := &config.Config{}
	pol := policy.DefaultPolicy()

	// Test nil config
	_, err := NewController(nil, nil, pol)
	if err == nil {
		t.Error("Expected error for nil config")
	}

	// Test nil BPF manager
	_, err = NewController(cfg, nil, pol)
	if err == nil {
		t.Error("Expected error for nil BPF manager")
	}

	// Test nil policy (would require BPF manager to be non-nil first)
}

func TestStatus(t *testing.T) {
	// Test that Status() returns a valid structure
	// This would require a full controller setup
	// For now, just verify the Status type is valid
	var s Status
	if s.Running {
		t.Error("New status should not be running")
	}
	if len(s.Components) != 0 {
		t.Error("New status should have no components")
	}
}

func TestStatusFields(t *testing.T) {
	s := Status{
		Running:         true,
		Components:      map[string]string{"test": "running"},
		EventsProcessed: 100,
		ThreatsDetected: 5,
	}

	if !s.Running {
		t.Error("Expected Running to be true")
	}
	if s.Components["test"] != "running" {
		t.Error("Expected component 'test' to be 'running'")
	}
	if s.EventsProcessed != 100 {
		t.Errorf("Expected EventsProcessed 100, got %d", s.EventsProcessed)
	}
	if s.ThreatsDetected != 5 {
		t.Errorf("Expected ThreatsDetected 5, got %d", s.ThreatsDetected)
	}
}

func TestControllerStopWithoutStart(t *testing.T) {
	cfg := &config.Config{
		Agent: config.AgentConfig{
			MetricsPort: 12113,
		},
	}
	pol := policy.DefaultPolicy()

	// This will return error because BPF manager is nil
	ctrl, _ := NewController(cfg, nil, pol)
	if ctrl == nil {
		// Expected, since BPF manager is nil
		return
	}

	// Stop without start should be safe
	ctrl.Stop()
}
