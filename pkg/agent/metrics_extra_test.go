// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"sync"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func TestRecordDrop(t *testing.T) {
	m := testSecurityMetrics
	if m.eventsDropped == nil {
		t.Fatal("eventsDropped counter not initialized")
	}
	counter := m.eventsDropped.WithLabelValues("event_chan_full")
	before := counterValue(t, counter)
	m.RecordDrop("event_chan_full")
	m.RecordDrop("event_chan_full")
	if got := counterValue(t, counter) - before; got != 2 {
		t.Errorf("expected 2 drops recorded, got delta %v", got)
	}
	// Nil receiver must be safe (metrics may be disabled).
	var nilM *SecurityMetrics
	nilM.RecordDrop("event_chan_full") // must not panic
}

func counterValue(t *testing.T, c interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var mm dto.Metric
	if err := c.Write(&mm); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return mm.GetCounter().GetValue()
}

// Global metrics instance for all tests (to avoid duplicate Prometheus registration)
var testSecurityMetrics = NewSecurityMetrics()

func TestNewSecurityMetrics(t *testing.T) {
	m := NewSecurityMetrics()
	if m == nil {
		t.Fatal("Expected non-nil SecurityMetrics")
	}

	if m.modelAccessTotal == nil {
		t.Error("Expected modelAccessTotal to be initialized")
	}
	if m.modelAccessBlocked == nil {
		t.Error("Expected modelAccessBlocked to be initialized")
	}
}

func TestRecordModelAccess(t *testing.T) {
	m := testSecurityMetrics

	// Test recording blocked access
	m.RecordModelAccess("blocked", ".safetensors", true)
	m.RecordModelAccess("blocked", ".gguf", true)

	// Test recording allowed access
	m.RecordModelAccess("allowed", ".pth", false)

	// Test concurrent recording (should not panic)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordModelAccess("blocked", ".pkl", true)
		}()
	}
	wg.Wait()
}

func TestRecordNetworkBlocked(t *testing.T) {
	m := testSecurityMetrics

	// Test recording various block reasons
	reasons := []string{"exfil", "invalid_dst", "rate_limit"}
	for _, reason := range reasons {
		m.RecordNetworkBlocked(reason)
	}

	// Test concurrent recording
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordNetworkBlocked("exfil")
		}()
	}
	wg.Wait()
}

func TestRecordExfilAttempt(t *testing.T) {
	m := testSecurityMetrics

	m.RecordExfilAttempt("detected")
	m.RecordExfilAttempt("blocked")

	// Test concurrent recording
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordExfilAttempt("detected")
		}()
	}
	wg.Wait()
}

func TestRecordFrameworkLoad(t *testing.T) {
	m := testSecurityMetrics

	// Test different frameworks
	frameworks := []string{"pytorch", "tensorflow", "onnx"}
	stages := []string{"load_start", "load_complete", "load_failed"}

	for _, fw := range frameworks {
		for _, stage := range stages {
			m.RecordFrameworkLoad(fw, stage)
		}
	}

	// Test unknown framework (should be ignored, not panic)
	m.RecordFrameworkLoad("unknown", "load_start")
}

func TestRecordPickleLoad(t *testing.T) {
	m := testSecurityMetrics

	// Test recording pickle events
	m.RecordPickleLoad("safe")
	m.RecordPickleLoad("dangerous")

	// Test concurrent recording
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordPickleLoad("safe")
		}()
	}
	wg.Wait()
}

func TestRecordPickleDangerous(t *testing.T) {
	m := testSecurityMetrics

	// Test recording dangerous symbols
	dangerousSymbols := []string{
		"__reduce__",
		"__reduce_ex__",
		"__setstate__",
		"__getinitargs__",
	}

	for _, symbol := range dangerousSymbols {
		m.RecordPickleDangerous(symbol)
	}

	// Test concurrent recording
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordPickleDangerous("__reduce__")
		}()
	}
	wg.Wait()
}

func TestSecurityMetricsConcurrency(t *testing.T) {
	m := testSecurityMetrics

	// Test all methods concurrently
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(7)
		go func() {
			defer wg.Done()
			m.RecordModelAccess("blocked", ".safetensors", true)
		}()
		go func() {
			defer wg.Done()
			m.RecordNetworkBlocked("exfil")
		}()
		go func() {
			defer wg.Done()
			m.RecordExfilAttempt("detected")
		}()
		go func() {
			defer wg.Done()
			m.RecordFrameworkLoad("pytorch", "load_start")
		}()
		go func() {
			defer wg.Done()
			m.RecordPickleLoad("safe")
		}()
		go func() {
			defer wg.Done()
			m.RecordPickleDangerous("__reduce__")
		}()
		go func() {
			defer wg.Done()
			m.RecordModelAccess("allowed", ".pth", false)
		}()
	}
	wg.Wait()
}

func TestRecordError(t *testing.T) {
	m := testSecurityMetrics

	// Test recording errors for various components
	components := []string{"bpf", "policy", "webhook", "config"}
	errorTypes := []string{"load_failed", "parse_error", "connection_failed", "validation_error"}

	for _, comp := range components {
		for _, errType := range errorTypes {
			m.RecordError(comp, errType)
		}
	}

	// Test concurrent error recording
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordError("bpf", "event_parse_error")
		}()
	}
	wg.Wait()
}

func TestRecordWebhookSent(t *testing.T) {
	m := testSecurityMetrics

	statuses := []string{"success", "failed", "timeout", "rate_limited"}
	for _, status := range statuses {
		m.RecordWebhookSent(status)
	}

	// Test concurrent recording
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordWebhookSent("success")
		}()
	}
	wg.Wait()
}

func TestRecordPolicyReload(t *testing.T) {
	m := testSecurityMetrics

	// Record multiple policy reloads
	for i := 0; i < 5; i++ {
		m.RecordPolicyReload()
	}
}

func TestRecordConfigReload(t *testing.T) {
	m := testSecurityMetrics

	// Record multiple config reloads
	for i := 0; i < 3; i++ {
		m.RecordConfigReload()
	}
}

func TestSetUptime(t *testing.T) {
	m := testSecurityMetrics

	// Set various uptime values
	uptimes := []float64{0, 60, 3600, 86400}
	for _, uptime := range uptimes {
		m.SetUptime(uptime)
	}
}

func TestSetLastEventTime(t *testing.T) {
	m := testSecurityMetrics

	// Set various timestamps
	timestamps := []float64{1704067200, 1704153600, 1704240000}
	for _, ts := range timestamps {
		m.SetLastEventTime(ts)
	}
}

func TestOperationalMetricsConcurrency(t *testing.T) {
	m := testSecurityMetrics

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(6)
		go func() {
			defer wg.Done()
			m.RecordError("test", "error")
		}()
		go func() {
			defer wg.Done()
			m.RecordWebhookSent("success")
		}()
		go func() {
			defer wg.Done()
			m.RecordPolicyReload()
		}()
		go func() {
			defer wg.Done()
			m.RecordConfigReload()
		}()
		go func() {
			defer wg.Done()
			m.SetUptime(float64(100))
		}()
		go func() {
			defer wg.Done()
			m.SetLastEventTime(float64(1704067200))
		}()
	}
	wg.Wait()
}
