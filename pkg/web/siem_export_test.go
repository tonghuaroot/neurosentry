// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/correlate"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func siemServer() *Server {
	chain := audit.NewChain()
	e := audit.NewEntry("model.access.blocked", audit.SeverityCritical, map[string]any{
		"path": "/models/llama.safetensors", "reason": "unauthorized",
	})
	e.SetActor(4242, 0, "python3")
	chain.Append(e)

	srv := NewServer(Config{ListenAddr: ":0"}, chain, mcp.NewInterceptor(mcp.NewPolicy()))
	srv.SetCorrelationSource(func(limit int) []correlate.Finding {
		return []correlate.Finding{{
			Timestamp: time.Now(), RuleID: "NS-CORR-001", Rule: "secret-read-then-llm",
			PID: 4242, Severity: "critical", Technique: "LLM02",
			Description: "credential read then LLM egress",
			Chain: []correlate.Signal{
				{Layer: correlate.LayerKernelFile, Kind: "file_read", Attributes: map[string]string{"path": "/etc/shadow"}},
				{Layer: correlate.LayerKernelNet, Kind: "net_connect", Attributes: map[string]string{"dst": "1.2.3.4"}},
			},
		}}
	})
	return srv
}

func TestSIEMExportOCSF(t *testing.T) {
	srv := siemServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/export/siem?format=ocsf&type=all", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("expected NDJSON content type, got %q", ct)
	}
	sc := bufio.NewScanner(strings.NewReader(rec.Body.String()))
	lines := 0
	sawFinding := false
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		lines++
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			t.Fatalf("each line must be valid JSON (OCSF): %v — %s", err, string(line))
		}
		if _, ok := obj["class_uid"]; !ok {
			t.Error("OCSF object must carry class_uid")
		}
		if _, ok := obj["finding_info"]; ok {
			sawFinding = true
		}
	}
	if lines < 2 {
		t.Errorf("expected at least an audit line and a finding line, got %d", lines)
	}
	if !sawFinding {
		t.Error("expected a correlation finding in the OCSF export")
	}
}

func TestSIEMExportCEF(t *testing.T) {
	srv := siemServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/export/siem?format=cef&type=all", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "CEF:0|NeuroSentry|NeuroSentry|") {
		t.Errorf("expected CEF headers, got:\n%s", body)
	}
	// Every non-empty line must be a CEF record.
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "CEF:0|") {
			t.Errorf("non-CEF line in output: %q", line)
		}
	}
}

func TestSIEMExportBadFormat(t *testing.T) {
	srv := siemServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/export/siem?format=xml", nil))
	if rec.Code != 400 {
		t.Errorf("unknown format should be 400, got %d", rec.Code)
	}
}
