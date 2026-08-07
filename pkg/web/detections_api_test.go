// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/correlate"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func detectionsServer() *Server {
	c := correlate.NewCorrelator(correlate.BuiltinRules())
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.SetDetectionsProvider(c.Detections, c.SetEnabled)
	return srv
}

func TestListDetections(t *testing.T) {
	srv := detectionsServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/detections", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp struct {
		Detections []correlate.DetectionInfo `json:"detections"`
		Total      int                       `json:"total"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Total < 10 {
		t.Errorf("expected a rich detection catalog, got %d", resp.Total)
	}
	// Each detection should expose MITRE + enabled state.
	hasMitre := false
	for _, d := range resp.Detections {
		if d.MitreAttack != "" {
			hasMitre = true
		}
	}
	if !hasMitre {
		t.Error("detections should carry MITRE ATT&CK mapping")
	}
}

func TestCreateAndDeleteCustomDetection(t *testing.T) {
	c := correlate.NewCorrelator(correlate.BuiltinRules())
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.SetDetectionsProvider(c.Detections, c.SetEnabled)
	srv.SetDetectionMutators(c.AddRule, c.RemoveRule)

	spec := correlate.RuleSpec{
		Name:       "Exfil after tool call",
		Severity:   "high",
		WindowSecs: 10,
		Ordered:    true,
		Matchers: []correlate.MatcherSpec{
			{Layer: "mcp", Kind: "tool_call"},
			{Layer: "kernel_net", Kind: "net_connect", AttrKey: "dst", AttrPattern: "."},
		},
	}
	body, _ := json.Marshal(spec)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/detections/create", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create should return 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatal("create should return a rule id")
	}

	// The new rule shows up in the catalog as custom.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/detections", nil))
	var list struct {
		Detections []correlate.DetectionInfo `json:"detections"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	foundCustom := false
	for _, d := range list.Detections {
		if d.ID == created.ID && d.Custom {
			foundCustom = true
		}
	}
	if !foundCustom {
		t.Error("created rule should appear as a custom detection")
	}

	// Invalid spec (no matchers) -> 400.
	bad, _ := json.Marshal(correlate.RuleSpec{Name: "empty"})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/detections/create", bytes.NewReader(bad)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid spec should be 400, got %d", rec.Code)
	}

	// Delete the custom rule.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/detections/"+created.ID+"/delete", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete should return 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Deleting a built-in rule is rejected.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/detections/NS-CORR-001/delete", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("deleting a built-in rule should be 400, got %d", rec.Code)
	}
}

func TestUpdateCustomDetectionAndKB(t *testing.T) {
	c := correlate.NewCorrelator(correlate.BuiltinRules())
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.SetDetectionsProvider(c.Detections, c.SetEnabled)
	srv.SetDetectionMutators(c.AddRule, c.RemoveRule)
	srv.SetDetectionUpdater(c.UpdateRule)
	srv.SetKBSource(c.KnowledgeBase)

	// Create a custom rule with KB fields.
	spec := correlate.RuleSpec{
		Name:        "Custom exfil",
		Description: "tool call then external connect",
		Severity:    "high",
		MitreAttack: "T1041",
		WindowSecs:  10,
		Ordered:     true,
		Rationale:   "operator rationale",
		Remediation: []string{"isolate the pid"},
		References:  []string{"https://example.com/rb"},
		Matchers: []correlate.MatcherSpec{
			{Layer: "mcp", Kind: "tool_call"},
			{Layer: "kernel_net", Kind: "net_connect", AttrKey: "dst", AttrPattern: "."},
		},
	}
	body, _ := json.Marshal(spec)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/detections/create", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create should be 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// The detection list exposes matchers for prefill.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/detections", nil))
	var list struct {
		Detections []correlate.DetectionInfo `json:"detections"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	var di correlate.DetectionInfo
	for _, d := range list.Detections {
		if d.ID == created.ID {
			di = d
		}
	}
	if len(di.Matchers) != 2 {
		t.Errorf("detection list should expose matchers for prefill, got %+v", di.Matchers)
	}

	// Update it in place.
	spec.Name = "Custom exfil v2"
	spec.Severity = "critical"
	upBody, _ := json.Marshal(spec)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/detections/"+created.ID+"/update", bytes.NewReader(upBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("update should be 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Updating a builtin rule -> 404.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/detections/NS-CORR-001/update", bytes.NewReader(upBody)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("updating a builtin rule should be 404, got %d", rec.Code)
	}

	// KB now includes the custom rule with its own guidance.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/kb", nil))
	var kb struct {
		Entries []correlate.KBEntry `json:"entries"`
	}
	json.Unmarshal(rec.Body.Bytes(), &kb)
	found := false
	for _, e := range kb.Entries {
		if e.RuleID == created.ID {
			found = true
			if e.Rationale != "operator rationale" || e.Name != "Custom exfil v2" {
				t.Errorf("KB entry should reflect updated custom rule: %+v", e)
			}
		}
	}
	if !found {
		t.Error("KB should include the custom rule")
	}
}

func TestToggleDetection(t *testing.T) {
	srv := detectionsServer()

	body, _ := json.Marshal(toggleRequest{Enabled: false})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/detections/NS-CORR-001/toggle", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle should succeed, got %d", rec.Code)
	}

	// Unknown rule -> 404.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/detections/NS-CORR-999/toggle", bytes.NewReader(body)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown rule toggle should be 404, got %d", rec.Code)
	}

	// GET on the toggle endpoint -> 405.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/detections/NS-CORR-001/toggle", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on toggle should be 405, got %d", rec.Code)
	}
}
