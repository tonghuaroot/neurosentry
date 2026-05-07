// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"
	"time"

	"github.com/tonghuaroot/neurosentry/pkg/policy"
)

// BenchmarkPolicyEvaluate benchmarks policy evaluation performance
func BenchmarkPolicyEvaluate(b *testing.B) {
	pol := policy.DefaultPolicy()

	event := map[string]interface{}{
		"type":      "file_access",
		"extension": ".safetensors",
		"file_path": "/models/test.safetensors",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pol.Evaluate(event)
	}
}

// BenchmarkPolicyEvaluateStruct benchmarks policy evaluation with struct events
func BenchmarkPolicyEvaluateStruct(b *testing.B) {
	pol := policy.DefaultPolicy()

	event := Event{
		Type:     EventTypeFileAccess,
		Severity: "info",
		Source:   EventSource{PID: 1234, UID: 1000},
		Data:     EventData{FilePath: "/models/test.safetensors", Extension: ".safetensors"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pol.Evaluate(event)
	}
}

// BenchmarkEventChannel benchmarks event channel throughput
func BenchmarkEventChannel(b *testing.B) {
	eventChan := make(chan Event, 1000)

	// Start consumer
	done := make(chan bool)
	go func() {
		count := 0
		for range eventChan {
			count++
			if count >= b.N {
				break
			}
		}
		done <- true
	}()

	event := Event{
		Type:     EventTypeFileAccess,
		Severity: "info",
		Source:   EventSource{PID: 1234},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eventChan <- event
	}

	<-done
}

// BenchmarkCGoString benchmarks C string conversion
func BenchmarkCGoString(b *testing.B) {
	data := make([]byte, 256)
	copy(data, "test_process_name")
	data[17] = 0 // Null terminator

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cGoString(data)
	}
}

// BenchmarkUint32ToIP benchmarks IP conversion
func BenchmarkUint32ToIP(b *testing.B) {
	ip := uint32(0xC0A80001) // 192.168.0.1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uint32ToIP(ip)
	}
}

// BenchmarkProtocolToString benchmarks protocol conversion
func BenchmarkProtocolToString(b *testing.B) {
	protocols := []uint8{1, 6, 17, 99}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = protocolToString(protocols[i%len(protocols)])
	}
}

// BenchmarkAlertManagerSilenceCheck benchmarks alert silence period checking
func BenchmarkAlertManagerSilenceCheck(b *testing.B) {
	am := NewAlertManager("", 60)

	event := Event{
		Type:     EventTypeFileBlocked,
		Severity: "high",
		Source:   EventSource{PID: 1234},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = am.SendAlert(event)
	}
}

// BenchmarkMetricsSnapshot benchmarks metrics snapshot creation
func BenchmarkMetricsSnapshot(b *testing.B) {
	mc := &MetricsCollector{
		eventCount:  1000,
		threatCount: 10,
		lastEvent:   time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mc.Snapshot()
	}
}

// BenchmarkSecurityMetricsRecord benchmarks security metrics recording
func BenchmarkSecurityMetricsRecord(b *testing.B) {
	m := testSecurityMetrics

	b.Run("RecordModelAccess", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.RecordModelAccess("allowed", ".safetensors", false)
		}
	})

	b.Run("RecordNetworkBlocked", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.RecordNetworkBlocked("exfil")
		}
	})

	b.Run("RecordError", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.RecordError("bpf", "parse_error")
		}
	})
}

// BenchmarkEventCreation benchmarks event struct creation
func BenchmarkEventCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Event{
			Type:      EventTypeFileAccess,
			Timestamp: time.Now(),
			Severity:  "info",
			Source: EventSource{
				PID:  i,
				UID:  1000,
				Comm: "python3",
			},
			Data: EventData{
				FilePath:  "/models/model.safetensors",
				Extension: ".safetensors",
			},
		}
	}
}

// BenchmarkParallelPolicyEvaluate benchmarks parallel policy evaluation
func BenchmarkParallelPolicyEvaluate(b *testing.B) {
	pol := policy.DefaultPolicy()

	event := map[string]interface{}{
		"type":      "file_access",
		"extension": ".pth",
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = pol.Evaluate(event)
		}
	})
}
