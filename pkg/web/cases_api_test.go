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
	"github.com/neurosentry/neurosentry/pkg/incident"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func casesServer(t *testing.T) (*Server, *incident.Store) {
	t.Helper()
	store := incident.NewStore()
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.SetCaseStore(store)
	return srv, store
}

func TestCaseLifecycleViaAPI(t *testing.T) {
	srv, store := casesServer(t)
	c := store.Add(correlate.Finding{RuleID: "NS-CORR-001", Rule: "secret-read-then-llm", Severity: "critical", PID: 42})

	// List shows the open case + stats.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/cases", nil))
	if rec.Code != 200 {
		t.Fatalf("list: %d", rec.Code)
	}
	var lr struct {
		Cases []incident.Case `json:"cases"`
		Stats incident.Stats  `json:"stats"`
	}
	json.Unmarshal(rec.Body.Bytes(), &lr)
	if lr.Stats.Open != 1 || len(lr.Cases) != 1 {
		t.Fatalf("expected 1 open case, got %+v", lr.Stats)
	}

	// Acknowledge it.
	body, _ := json.Marshal(map[string]string{"status": "acknowledged"})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/cases/"+c.ID+"/status", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("status change: %d", rec.Code)
	}

	// Assign + note.
	body, _ = json.Marshal(map[string]string{"assignee": "soc@corp"})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/cases/"+c.ID+"/assign", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Errorf("assign: %d", rec.Code)
	}
	body, _ = json.Marshal(map[string]string{"text": "confirmed exfil attempt"})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/cases/"+c.ID+"/note", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Errorf("note: %d", rec.Code)
	}

	got, _ := store.Get(c.ID)
	if got.Status != incident.StatusAcknowledged || got.Assignee != "soc@corp" || len(got.Notes) != 1 {
		t.Errorf("case not updated via API: %+v", got)
	}

	// Invalid status -> 404/400.
	body, _ = json.Marshal(map[string]string{"status": "bogus"})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/cases/"+c.ID+"/status", bytes.NewReader(body)))
	if rec.Code == http.StatusOK {
		t.Error("invalid status should not be 200")
	}
}
