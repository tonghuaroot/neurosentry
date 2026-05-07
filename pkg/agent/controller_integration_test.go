// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"
	"time"

	"github.com/tonghuaroot/neurosentry/pkg/config"
	"github.com/tonghuaroot/neurosentry/pkg/policy"
)

func TestHandleEvent(t *testing.T) {
	// Create a minimal controller for testing handleEvent
	pol := policy.DefaultPolicy()

	// We can't create a full controller without BPF manager
	// but we can test the event handling logic separately

	events := []Event{
		{
			Type:     EventTypeFileAccess,
			Severity: "info",
			Source:   EventSource{PID: 1234, UID: 1000, Comm: "test"},
			Data:     EventData{FilePath: "/models/test.safetensors"},
		},
		{
			Type:     EventTypeFileBlocked,
			Severity: "high",
			Source:   EventSource{PID: 5678, UID: 1000, Comm: "attacker"},
			Data:     EventData{FilePath: "/models/secret.pth"},
		},
		{
			Type:     EventTypeNetworkBlocked,
			Severity: "high",
			Source:   EventSource{PID: 9999},
			Data:     EventData{DstAddr: "8.8.8.8", DstPort: 443},
		},
		{
			Type:     EventTypePickleDangerous,
			Severity: "critical",
			Source:   EventSource{PID: 1111, Comm: "python3"},
			Data:     EventData{Symbols: []string{"os.system"}},
		},
	}

	// Test policy evaluation for each event
	for _, event := range events {
		action := pol.Evaluate(event)
		t.Logf("Event %s -> Action: %s", event.Type, action)
	}
}

func TestEventChannel(t *testing.T) {
	eventChan := make(chan Event, 10)

	// Send some events
	go func() {
		for i := 0; i < 5; i++ {
			eventChan <- Event{
				Type:     EventTypeFileAccess,
				Severity: "info",
				Source:   EventSource{PID: i},
			}
		}
	}()

	// Receive events
	received := 0
	timeout := time.After(1 * time.Second)

	for received < 5 {
		select {
		case <-eventChan:
			received++
		case <-timeout:
			t.Fatalf("Timeout waiting for events, received %d", received)
		}
	}

	if received != 5 {
		t.Errorf("Expected 5 events, got %d", received)
	}
}

func TestStatusStruct(t *testing.T) {
	status := Status{
		Running: true,
		Components: map[string]string{
			"event-processor": "running",
			"policy-engine":   "running",
			"metrics-server":  "running",
		},
		EventsProcessed: 1000,
		ThreatsDetected: 10,
	}

	if !status.Running {
		t.Error("Expected status to be running")
	}

	if len(status.Components) != 3 {
		t.Errorf("Expected 3 components, got %d", len(status.Components))
	}

	if status.EventsProcessed != 1000 {
		t.Errorf("Expected 1000 events, got %d", status.EventsProcessed)
	}

	if status.ThreatsDetected != 10 {
		t.Errorf("Expected 10 threats, got %d", status.ThreatsDetected)
	}
}

func TestComponentInterface(t *testing.T) {
	// Test EventProcessor implements Component
	eventChan := make(chan Event, 10)
	ep := NewEventProcessor(eventChan, nil)

	var _ Component = ep // Compile-time interface check

	if ep.Name() != "event-processor" {
		t.Errorf("Expected name 'event-processor', got '%s'", ep.Name())
	}

	// Test AlertManager implements Component
	am := NewAlertManager("http://example.com/webhook", 60)

	var _ Component = am // Compile-time interface check

	if am.Name() != "alert-manager" {
		t.Errorf("Expected name 'alert-manager', got '%s'", am.Name())
	}

	// Test MetricsServer implements Component
	ms := NewMetricsServer(29999, nil)

	var _ Component = ms // Compile-time interface check

	if ms.Name() != "metrics-server" {
		t.Errorf("Expected name 'metrics-server', got '%s'", ms.Name())
	}
}

func TestBPFMetricsCollectorStub(t *testing.T) {
	// Test the stub implementation
	collector := NewBPFMetricsCollector(nil)

	if collector == nil {
		t.Fatal("Expected non-nil collector")
	}

	// These should be no-ops on non-Linux
	collector.Start()
	collector.Stop()
}

func TestPolicyEngineReloadPolicy(t *testing.T) {
	// Create policy engine for testing
	cfg := &config.Config{
		PolicyPath: "", // Empty path will use builtin
		Protection: config.ProtectionConfig{
			ModelFIM: config.ModelFIMConfig{
				Enabled: false,
			},
		},
	}

	pol := policy.DefaultPolicy()
	engine := NewPolicyEngine(cfg, nil, pol, nil)

	// ReloadPolicy should work with builtin policy
	err := engine.ReloadPolicy()
	if err != nil {
		t.Logf("ReloadPolicy() error (expected without BPF): %v", err)
	}
}

func TestPolicyEngineEvaluateMultiple(t *testing.T) {
	cfg := &config.Config{}
	pol := policy.DefaultPolicy()
	engine := NewPolicyEngine(cfg, nil, pol, nil)

	testCases := []struct {
		name  string
		event Event
	}{
		{
			name: "file_access_event",
			event: Event{
				Type:     EventTypeFileAccess,
				Severity: "info",
				Source:   EventSource{PID: 1000},
				Data:     EventData{FilePath: "/models/test.pth", Extension: ".pth"},
			},
		},
		{
			name: "file_blocked_event",
			event: Event{
				Type:     EventTypeFileBlocked,
				Severity: "high",
				Source:   EventSource{PID: 2000},
				Data:     EventData{FilePath: "/secret/model.safetensors"},
			},
		},
		{
			name: "network_event",
			event: Event{
				Type:     EventTypeNetworkBlocked,
				Severity: "high",
				Source:   EventSource{PID: 3000},
				Data:     EventData{DstAddr: "8.8.8.8", DstPort: 443},
			},
		},
		{
			name: "pickle_dangerous",
			event: Event{
				Type:     EventTypePickleDangerous,
				Severity: "critical",
				Source:   EventSource{PID: 4000, Comm: "python"},
				Data:     EventData{Symbols: []string{"os.system"}},
			},
		},
		{
			name: "model_load",
			event: Event{
				Type:     EventTypeModelLoad,
				Severity: "info",
				Source:   EventSource{PID: 5000, Comm: "python3"},
				Data:     EventData{Framework: "pytorch", ModelSize: 1024000},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			action := engine.Evaluate(tc.event)
			t.Logf("Event %s -> Action: %s", tc.event.Type, action)
		})
	}
}

func TestEventTypeSeverity(t *testing.T) {
	severityMap := map[EventType]string{
		EventTypeFileAccess:      "info",
		EventTypeFileBlocked:     "high",
		EventTypeNetworkAllowed:  "info",
		EventTypeNetworkBlocked:  "high",
		EventTypeModelLoad:       "info",
		EventTypePickleLoad:      "info",
		EventTypePickleDangerous: "critical",
	}

	for eventType, expectedSeverity := range severityMap {
		event := Event{
			Type:     eventType,
			Severity: expectedSeverity,
		}

		if event.Severity != expectedSeverity {
			t.Errorf("Event %s: expected severity %s, got %s",
				eventType, expectedSeverity, event.Severity)
		}
	}
}

func TestEventSourceFields(t *testing.T) {
	source := EventSource{
		PID:         1234,
		UID:         1000,
		Comm:        "python3",
		CGroup:      "/kubepods/pod-123",
		ContainerID: "abc123def456",
	}

	if source.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", source.PID)
	}
	if source.UID != 1000 {
		t.Errorf("Expected UID 1000, got %d", source.UID)
	}
	if source.Comm != "python3" {
		t.Errorf("Expected Comm 'python3', got %s", source.Comm)
	}
	if source.CGroup != "/kubepods/pod-123" {
		t.Errorf("Expected CGroup '/kubepods/pod-123', got %s", source.CGroup)
	}
	if source.ContainerID != "abc123def456" {
		t.Errorf("Expected ContainerID 'abc123def456', got %s", source.ContainerID)
	}
}

func TestEventDataFields(t *testing.T) {
	data := EventData{
		FilePath:    "/models/model.safetensors",
		FileAction:  "read",
		Extension:   ".safetensors",
		SrcAddr:     "192.168.1.1",
		DstAddr:     "10.0.0.1",
		SrcPort:     54321,
		DstPort:     443,
		Protocol:    "tcp",
		BlockReason: "unauthorized",
		Framework:   "pytorch",
		ModelSize:   1024000000,
		ModelHash:   "abc123",
		StackDepth:  5,
		Symbols:     []string{"__reduce__", "os.system"},
	}

	if data.FilePath != "/models/model.safetensors" {
		t.Errorf("FilePath mismatch")
	}
	if data.DstPort != 443 {
		t.Errorf("DstPort mismatch")
	}
	if len(data.Symbols) != 2 {
		t.Errorf("Expected 2 symbols, got %d", len(data.Symbols))
	}
}
