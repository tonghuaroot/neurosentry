// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/correlate"
	"github.com/neurosentry/neurosentry/pkg/incident"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func reportServer() *Server {
	chain := audit.NewChain()
	chain.Append(audit.NewEntry("agent.start", audit.SeverityInfo, nil))

	c := correlate.NewCorrelator(correlate.BuiltinRules())
	store := incident.NewStore()
	store.Add(correlate.Finding{
		RuleID: "NS-CORR-001", Rule: "secret-read-then-llm", Severity: "critical",
		Technique: "LLM02", PID: 4242, Description: "secret exfil",
	})

	srv := NewServer(Config{ListenAddr: ":0"}, chain, mcp.NewInterceptor(mcp.NewPolicy()))
	srv.SetDetectionsProvider(c.Detections, c.SetEnabled)
	srv.SetCaseStore(store)
	return srv
}

func TestReportJSON(t *testing.T) {
	srv := reportServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/report", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var rep PostureReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("report should be valid JSON: %v", err)
	}
	if rep.PostureScore < 0 || rep.PostureScore > 100 {
		t.Errorf("posture score out of range: %d", rep.PostureScore)
	}
	if rep.PostureGrade == "" {
		t.Error("report should carry a letter grade")
	}
	if rep.Detections.Total < 10 {
		t.Errorf("expected the built-in catalog counted, got %d", rep.Detections.Total)
	}
	if !rep.Integrity.Verified {
		t.Error("a fresh untampered chain should verify")
	}
	if rep.Cases.Total != 1 {
		t.Errorf("expected 1 case, got %d", rep.Cases.Total)
	}
	// The observed technique should surface in coverage.
	found := false
	for _, m := range rep.MitreCoverage {
		if m.Technique == "LLM02" && m.Cases == 1 {
			found = true
		}
	}
	if !found {
		t.Error("observed technique LLM02 should appear in coverage with 1 case")
	}
}

func TestReportHTML(t *testing.T) {
	srv := reportServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/report?format=html", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected HTML content type, got %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"Security Posture Report", "posture score", "MITRE Technique Coverage", "Evidence Integrity"} {
		if !strings.Contains(body, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}
