// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func TestResponseActionAuditedAndDispatched(t *testing.T) {
	chain := audit.NewChain()
	srv := NewServer(Config{ListenAddr: ":0"}, chain, mcp.NewInterceptor(mcp.NewPolicy()))

	var gotAction string
	var gotParams map[string]string
	srv.SetResponseHandler(func(action string, params map[string]string) (string, error) {
		gotAction = action
		gotParams = params
		if params["pid"] == "0" {
			return "", fmt.Errorf("valid pid required")
		}
		return "PID trusted", nil
	})

	body, _ := json.Marshal(map[string]any{"action": "trust_pid", "params": map[string]string{"pid": "1234"}})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/response", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if gotAction != "trust_pid" || gotParams["pid"] != "1234" {
		t.Errorf("handler not dispatched: %s %v", gotAction, gotParams)
	}
	// The action must be audited.
	found := false
	for _, e := range chain.Entries() {
		if e.EventType == "response:trust_pid" {
			found = true
		}
	}
	if !found {
		t.Error("response action should be recorded in the audit chain")
	}

	// A failing action -> 400 + response:failed audit.
	body, _ = json.Marshal(map[string]any{"action": "trust_pid", "params": map[string]string{"pid": "0"}})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/response", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("failing action should be 400, got %d", rec.Code)
	}
}
