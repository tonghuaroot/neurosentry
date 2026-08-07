// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"testing"
	"time"
)

// TestSessionCountBounded verifies a churn of short-lived PIDs cannot grow the
// session table without limit (fork-bomb fail-safe).
func TestSessionCountBounded(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	c.maxSessions = 128 // small cap for the test
	base := time.Unix(1_700_000_000, 0)

	// 10k distinct PIDs, far above the cap.
	for i := 0; i < 10000; i++ {
		c.Ingest(Signal{
			PID:       100000 + i,
			Layer:     LayerKernelFile,
			Kind:      "file_read",
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
		})
	}

	c.mu.Lock()
	n := len(c.sessions)
	c.mu.Unlock()
	if n > c.maxSessions {
		t.Fatalf("session table exceeded cap: %d > %d", n, c.maxSessions)
	}
	if n == 0 {
		t.Fatal("evicted everything; expected recent sessions retained")
	}
}

// TestPerSessionSignalsBounded verifies a single chatty PID cannot accumulate
// unbounded signal history.
func TestPerSessionSignalsBounded(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 5000; i++ {
		c.Ingest(Signal{
			PID:       4242,
			Layer:     LayerMCP,
			Kind:      "tool_call",
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
		})
	}
	c.mu.Lock()
	got := len(c.sessions[4242].signals)
	capacity := cap(c.sessions[4242].signals)
	c.mu.Unlock()
	if got > sessionSignalCap {
		t.Fatalf("session signal history %d exceeds cap %d", got, sessionSignalCap)
	}
	// Reslicing lets Go's append stabilize the backing array at ~2×cap; the
	// point is it does NOT grow with the 5000 signals ingested.
	if capacity > 2*sessionSignalCap+64 {
		t.Fatalf("underlying array grew to %d, not bounded near %d", capacity, sessionSignalCap)
	}
}

// TestEvictionKeepsMostRecent verifies eviction drops the least-recently-active
// sessions, not arbitrary ones.
func TestEvictionKeepsMostRecent(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	c.maxSessions = 100
	base := time.Unix(1_700_000_000, 0)

	// Fill to cap with old sessions, then push newer PIDs to force eviction.
	for i := 0; i < 200; i++ {
		c.Ingest(Signal{
			PID:       i,
			Layer:     LayerKernelNet,
			Kind:      "net_connect",
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// The most recent PID must still be tracked; the very first must be gone.
	if _, ok := c.sessions[199]; !ok {
		t.Error("most-recent session was evicted")
	}
	if _, ok := c.sessions[0]; ok {
		t.Error("oldest session should have been evicted first")
	}
}

// TestCorrelationStillFiresUnderBounds guards against the bounds breaking
// detection: a real cross-layer chain must still fire.
func TestCorrelationStillFiresUnderBounds(t *testing.T) {
	c := NewCorrelator(BuiltinRules())
	base := time.Unix(1_700_000_000, 0)
	var fired []Finding
	c.OnFinding(func(f Finding) { fired = append(fired, f) })

	// secret-read-then-llm: read a secret, then egress toward an LLM.
	c.Ingest(Signal{PID: 7, Layer: LayerKernelFile, Kind: "file_read",
		Attributes: map[string]string{"path": "/etc/shadow"}, Timestamp: base})
	c.Ingest(Signal{PID: 7, Layer: LayerKernelNet, Kind: "net_connect",
		Attributes: map[string]string{"dst": "api.openai.com", "ai_provider": "openai"}, Timestamp: base.Add(time.Second)})

	if len(fired) == 0 {
		t.Error("expected a correlation finding to still fire under fail-safe bounds")
	}
}
