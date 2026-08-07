// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"testing"
	"time"
)

var base = time.Unix(1_700_000_000, 0)

func at(offset time.Duration) time.Time { return base.Add(offset) }

func sig(pid int, layer Layer, kind string, ts time.Time, attrs map[string]string) Signal {
	return Signal{PID: pid, Layer: layer, Kind: kind, Timestamp: ts, Attributes: attrs, TenantID: "ten1"}
}

func newEngine() *Correlator { return NewCorrelator(BuiltinRules()) }

func TestSecretReadThenLLM(t *testing.T) {
	c := newEngine()
	// A tool/agent reads /etc/shadow, then 2s later traffic heads to an LLM.
	c.Ingest(sig(100, LayerKernelFile, "file_read", at(0), map[string]string{"path": "/etc/shadow"}))
	findings := c.Ingest(sig(100, LayerAI, "request", at(2*time.Second), map[string]string{"provider": "OpenAI"}))

	if len(findings) != 1 || findings[0].Rule != "secret-read-then-llm" {
		t.Fatalf("expected secret-read-then-llm, got %+v", findings)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("expected critical, got %s", findings[0].Severity)
	}
	if len(findings[0].Chain) != 2 {
		t.Errorf("expected 2-signal chain, got %d", len(findings[0].Chain))
	}
}

func TestSecretReadThenLLMOrderMatters(t *testing.T) {
	c := newEngine()
	// LLM request FIRST, then the file read — not the exfil pattern.
	c.Ingest(sig(100, LayerAI, "request", at(0), nil))
	findings := c.Ingest(sig(100, LayerKernelFile, "file_read", at(2*time.Second), map[string]string{"path": "/etc/shadow"}))
	for _, f := range findings {
		if f.Rule == "secret-read-then-llm" {
			t.Error("ordered rule must not fire when LLM precedes the secret read")
		}
	}
}

func TestSecretReadThenLLMWindow(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(100, LayerKernelFile, "file_read", at(0), map[string]string{"path": "/root/.ssh/id_rsa"}))
	// 30s later — outside the 10s window.
	findings := c.Ingest(sig(100, LayerAI, "request", at(30*time.Second), nil))
	if len(findings) != 0 {
		t.Errorf("out-of-window signals should not correlate, got %+v", findings)
	}
}

func TestNonSecretFileNoFire(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(100, LayerKernelFile, "file_read", at(0), map[string]string{"path": "/models/llama.safetensors"}))
	findings := c.Ingest(sig(100, LayerAI, "request", at(1*time.Second), nil))
	if len(findings) != 0 {
		t.Errorf("reading a normal model file then calling an LLM is benign, got %+v", findings)
	}
}

func TestToolTriggeredExfil(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(200, LayerMCP, "tool_call", at(0), map[string]string{"tool": "search_files"}))
	findings := c.Ingest(sig(200, LayerKernelNet, "net_connect", at(1*time.Second), map[string]string{"dst": "203.0.113.9"}))

	if len(findings) != 1 || findings[0].Rule != "tool-triggered-exfil" {
		t.Fatalf("expected tool-triggered-exfil, got %+v", findings)
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected high severity, got %s", findings[0].Severity)
	}
}

func TestToolTriggeredExfilInternalIgnored(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(200, LayerMCP, "tool_call", at(0), nil))
	// Internal RFC1918 destination — normal service-to-service traffic.
	findings := c.Ingest(sig(200, LayerKernelNet, "net_connect", at(1*time.Second), map[string]string{"dst": "10.0.3.4"}))
	if len(findings) != 0 {
		t.Errorf("internal destination should not trigger exfil rule, got %+v", findings)
	}
}

func TestToolSpawnedProcess(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(300, LayerMCP, "tool_call", at(0), map[string]string{"tool": "get_weather"}))
	findings := c.Ingest(sig(300, LayerKernelProc, "exec", at(500*time.Millisecond), map[string]string{"comm": "sh"}))

	if len(findings) != 1 || findings[0].Rule != "tool-spawned-process" {
		t.Fatalf("expected tool-spawned-process, got %+v", findings)
	}
}

func TestInjectionThenAction(t *testing.T) {
	c := newEngine()
	// An injection attempt is flagged, then a real kernel action follows.
	c.Ingest(sig(400, LayerMCP, "tool_call", at(0), map[string]string{"injection": "malicious"}))
	findings := c.Ingest(sig(400, LayerKernelProc, "exec", at(2*time.Second), map[string]string{"comm": "bash"}))

	var fired bool
	for _, f := range findings {
		if f.Rule == "injection-then-action" {
			fired = true
			if f.Severity != "critical" {
				t.Errorf("expected critical, got %s", f.Severity)
			}
		}
	}
	if !fired {
		t.Fatalf("injection-then-action should fire, got %+v", findings)
	}
}

func TestUnverifiedModelLoad(t *testing.T) {
	c := newEngine()
	findings := c.Ingest(sig(500, LayerModel, "load", at(0), map[string]string{"path": "/models/x.pt", "verified": "false"}))
	if len(findings) != 1 || findings[0].Rule != "unverified-model-load" {
		t.Fatalf("expected unverified-model-load, got %+v", findings)
	}
}

func TestVerifiedModelLoadNoFire(t *testing.T) {
	c := newEngine()
	findings := c.Ingest(sig(500, LayerModel, "load", at(0), map[string]string{"verified": "true"}))
	if len(findings) != 0 {
		t.Errorf("verified model load should not fire, got %+v", findings)
	}
}

func TestPIDIsolation(t *testing.T) {
	c := newEngine()
	// Secret read by PID 1, LLM call by PID 2 — unrelated processes.
	c.Ingest(sig(1, LayerKernelFile, "file_read", at(0), map[string]string{"path": "/etc/shadow"}))
	findings := c.Ingest(sig(2, LayerAI, "request", at(1*time.Second), nil))
	if len(findings) != 0 {
		t.Errorf("signals from different PIDs must not correlate, got %+v", findings)
	}
}

func TestCooldownNoRestorm(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(600, LayerKernelFile, "file_read", at(0), map[string]string{"path": "/etc/shadow"}))
	f1 := c.Ingest(sig(600, LayerAI, "request", at(1*time.Second), nil))
	// A second LLM request 1s later completes the pattern again, but cooldown
	// (rule window) suppresses a duplicate finding for the same episode.
	f2 := c.Ingest(sig(600, LayerAI, "request", at(2*time.Second), nil))
	if len(f1) != 1 {
		t.Fatalf("first completion should fire once, got %d", len(f1))
	}
	if len(f2) != 0 {
		t.Errorf("cooldown should suppress restorm, got %+v", f2)
	}
}

func TestOnFindingSink(t *testing.T) {
	c := newEngine()
	var got []Finding
	c.OnFinding(func(f Finding) { got = append(got, f) })
	c.Ingest(sig(700, LayerMCP, "tool_call", at(0), nil))
	c.Ingest(sig(700, LayerKernelNet, "net_connect", at(1*time.Second), map[string]string{"dst": "8.8.8.8"}))
	if len(got) != 1 {
		t.Errorf("OnFinding sink should have received 1 finding, got %d", len(got))
	}
}

func TestReapClearsState(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(800, LayerKernelFile, "file_read", at(0), map[string]string{"path": "/etc/shadow"}))
	c.Reap(800)
	// After reap, a following LLM call has no secret-read history to correlate.
	findings := c.Ingest(sig(800, LayerAI, "request", at(1*time.Second), nil))
	if len(findings) != 0 {
		t.Errorf("reaped PID should have no correlation history, got %+v", findings)
	}
}

func TestBenignTrafficNoFindings(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(900, LayerKernelFile, "file_read", at(0), map[string]string{"path": "/models/config.json"}))
	c.Ingest(sig(900, LayerMCP, "tool_call", at(1*time.Second), map[string]string{"tool": "list_files"}))
	f := c.Ingest(sig(900, LayerKernelNet, "net_connect", at(2*time.Second), map[string]string{"dst": "10.0.0.5"}))
	if len(f) != 0 {
		t.Errorf("benign internal activity should produce no findings, got %+v", f)
	}
}

func TestExternalDstDetection(t *testing.T) {
	tests := map[string]bool{
		"8.8.8.8":     true,
		"203.0.113.1": true,
		"10.0.0.1":    false,
		"172.16.5.5":  false,
		"192.168.1.1": false,
		"127.0.0.1":   false,
	}
	for dst, want := range tests {
		got := dstIsExternal(Signal{Attributes: map[string]string{"dst": dst}})
		if got != want {
			t.Errorf("dstIsExternal(%s) = %v, want %v", dst, got, want)
		}
	}
}

func TestDetectionsCatalog(t *testing.T) {
	c := newEngine()
	dets := c.Detections()
	if len(dets) < 10 {
		t.Fatalf("expected a rich rule catalog (>=10), got %d", len(dets))
	}
	// Every detection must carry an ID and be enabled by default.
	for _, d := range dets {
		if d.ID == "" || d.Name == "" {
			t.Errorf("detection missing ID/Name: %+v", d)
		}
		if !d.Enabled {
			t.Errorf("detection %s should be enabled by default", d.ID)
		}
	}
}

func TestDetectionDisableSuppressesFiring(t *testing.T) {
	c := newEngine()
	if !c.SetEnabled("NS-CORR-001", false) {
		t.Fatal("SetEnabled should succeed for a known rule")
	}
	// The disabled secret-read-then-llm rule must not fire.
	c.Ingest(sig(100, LayerKernelFile, "file_read", at(0), map[string]string{"path": "/etc/shadow"}))
	f := c.Ingest(sig(100, LayerAI, "request", at(2*time.Second), nil))
	for _, x := range f {
		if x.RuleID == "NS-CORR-001" {
			t.Error("disabled rule fired")
		}
	}
	// Unknown rule id returns false.
	if c.SetEnabled("NS-CORR-999", true) {
		t.Error("SetEnabled should return false for unknown id")
	}
}

func TestFireCountTracked(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(300, LayerMCP, "tool_call", at(0), nil))
	c.Ingest(sig(300, LayerKernelProc, "exec", at(1*time.Second), map[string]string{"comm": "sh"}))
	var got int64
	for _, d := range c.Detections() {
		if d.ID == "NS-CORR-003" {
			got = d.FireCount
		}
	}
	if got < 1 {
		t.Errorf("expected tool-spawned-process fire count >=1, got %d", got)
	}
}

func TestReverseShellDetection(t *testing.T) {
	c := newEngine()
	c.Ingest(sig(700, LayerKernelProc, "exec", at(0), map[string]string{"comm": "bash"}))
	f := c.Ingest(sig(700, LayerKernelNet, "net_connect", at(1*time.Second), map[string]string{"dst": "203.0.113.9"}))
	found := false
	for _, x := range f {
		if x.RuleID == "NS-CORR-008" {
			found = true
			if x.Severity != "critical" {
				t.Errorf("reverse shell should be critical, got %s", x.Severity)
			}
		}
	}
	if !found {
		t.Errorf("reverse-shell-indicator should fire, got %+v", f)
	}
}
