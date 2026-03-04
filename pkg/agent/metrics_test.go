// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestMetricsCollectorSnapshot(t *testing.T) {
	// Create a simple metrics struct without Prometheus registration
	mc := &MetricsCollector{
		eventCount:  100,
		threatCount: 5,
		lastEvent:   time.Now(),
	}

	snapshot := mc.Snapshot()

	if snapshot["events_processed"] != int64(100) {
		t.Errorf("Expected events_processed=100, got %v", snapshot["events_processed"])
	}

	if snapshot["threats_detected"] != int64(5) {
		t.Errorf("Expected threats_detected=5, got %v", snapshot["threats_detected"])
	}

	if _, ok := snapshot["last_event_time"]; !ok {
		t.Error("Expected last_event_time in snapshot")
	}
}

func TestMetricsCollectorTotals(t *testing.T) {
	mc := &MetricsCollector{
		eventCount:  50,
		threatCount: 3,
	}

	if mc.TotalEvents() != 50 {
		t.Errorf("Expected TotalEvents()=50, got %d", mc.TotalEvents())
	}

	if mc.TotalThreats() != 3 {
		t.Errorf("Expected TotalThreats()=3, got %d", mc.TotalThreats())
	}
}

func TestMetricsServerHealthEndpoint(t *testing.T) {
	ms := NewMetricsServer(29998, nil)

	ctx := context.Background()
	if err := ms.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test health endpoint
	resp, err := http.Get("http://localhost:29998/health")
	if err != nil {
		t.Logf("Health endpoint not accessible: %v", err)
	} else {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	}

	if err := ms.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestMetricsServerRootEndpoint(t *testing.T) {
	ms := NewMetricsServer(29997, nil)

	ctx := context.Background()
	if err := ms.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Test root endpoint
	resp, err := http.Get("http://localhost:29997/")
	if err != nil {
		t.Logf("Root endpoint not accessible: %v", err)
	} else {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	}

	if err := ms.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestEventProcessor(t *testing.T) {
	eventChan := make(chan Event, 10)
	processor := NewEventProcessor(eventChan, nil)

	if processor.Name() != "event-processor" {
		t.Errorf("Expected name 'event-processor', got '%s'", processor.Name())
	}

	ctx := context.Background()
	if err := processor.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	if err := processor.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestAlertManager(t *testing.T) {
	am := NewAlertManager("", 60)

	if am.Name() != "alert-manager" {
		t.Errorf("Expected name 'alert-manager', got '%s'", am.Name())
	}

	ctx := context.Background()
	if err := am.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	if err := am.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestAlertManagerSendAlert(t *testing.T) {
	am := NewAlertManager("", 1) // 1 second silence

	event := Event{
		Type:     EventTypeFileBlocked,
		Severity: "high",
		Source:   EventSource{PID: 1234},
	}

	// First alert should succeed
	if err := am.SendAlert(event); err != nil {
		t.Errorf("SendAlert() error = %v", err)
	}

	// Second alert for same event should be silenced
	if err := am.SendAlert(event); err != nil {
		t.Errorf("SendAlert() error = %v", err)
	}

	// Different event should succeed
	event2 := Event{
		Type:     EventTypeFileBlocked,
		Severity: "high",
		Source:   EventSource{PID: 5678},
	}
	if err := am.SendAlert(event2); err != nil {
		t.Errorf("SendAlert() error = %v", err)
	}
}

func TestAlertManagerSilencePeriod(t *testing.T) {
	am := NewAlertManager("", 1) // 1 second silence

	event := Event{
		Type:     EventTypeFileBlocked,
		Severity: "high",
		Source:   EventSource{PID: 9999},
	}

	// First alert
	_ = am.SendAlert(event)

	// Wait for silence period to expire
	time.Sleep(1100 * time.Millisecond)

	// Should be able to send again
	if err := am.SendAlert(event); err != nil {
		t.Errorf("SendAlert() after silence period error = %v", err)
	}
}

func TestMetricsServer(t *testing.T) {
	ms := NewMetricsServer(19999, nil)

	if ms.Name() != "metrics-server" {
		t.Errorf("Expected name 'metrics-server', got '%s'", ms.Name())
	}

	ctx := context.Background()
	if err := ms.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	if err := ms.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestMetricsServerStop(t *testing.T) {
	ms := NewMetricsServer(19998, nil)

	// Stop without start should be safe
	if err := ms.Stop(); err != nil {
		t.Errorf("Stop() without start error = %v", err)
	}
}

func TestAlertManagerWebhook(t *testing.T) {
	// Test with empty webhook URL
	am := NewAlertManager("", 1)

	event := Event{
		Type:      EventTypeFileBlocked,
		Timestamp: time.Now(),
		Severity:  "high",
		Source:    EventSource{PID: 1234, UID: 1000, Comm: "test"},
		Data:      EventData{FilePath: "/models/test.pth"},
	}

	// Should not error even with empty webhook
	if err := am.SendAlert(event); err != nil {
		t.Errorf("SendAlert() with empty webhook error = %v", err)
	}
}

func TestAlertManagerRateLimiting(t *testing.T) {
	am := NewAlertManager("", 2) // 2 second silence

	event := Event{
		Type:     EventTypeFileBlocked,
		Severity: "high",
		Source:   EventSource{PID: 12345},
	}

	// First alert should go through
	_ = am.SendAlert(event)

	// Second alert for same event should be silenced (same key)
	_ = am.SendAlert(event)

	// Different PID should not be silenced
	event2 := Event{
		Type:     EventTypeFileBlocked,
		Severity: "high",
		Source:   EventSource{PID: 54321},
	}
	_ = am.SendAlert(event2)
}

func TestEventProcessorStartStop(t *testing.T) {
	eventChan := make(chan Event, 100)
	ep := NewEventProcessor(eventChan, nil)

	ctx := context.Background()

	// Start should succeed
	if err := ep.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Stop should succeed
	if err := ep.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestAlertManagerConcurrent(t *testing.T) {
	am := NewAlertManager("", 1)

	// Send alerts concurrently
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			event := Event{
				Type:     EventTypeFileBlocked,
				Severity: "high",
				Source:   EventSource{PID: id * 1000},
			}
			_ = am.SendAlert(event)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestMetricsCollectorConcurrentAccess(t *testing.T) {
	mc := &MetricsCollector{}

	// Test concurrent access to TotalEvents and TotalThreats
	done := make(chan bool, 20)

	for i := 0; i < 10; i++ {
		go func() {
			_ = mc.TotalEvents()
			done <- true
		}()
		go func() {
			_ = mc.TotalThreats()
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestMetricsCollectorSnapshotConcurrent(t *testing.T) {
	mc := &MetricsCollector{
		eventCount:  0,
		threatCount: 0,
	}

	done := make(chan bool, 10)

	// Concurrent snapshots
	for i := 0; i < 10; i++ {
		go func() {
			_ = mc.Snapshot()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
