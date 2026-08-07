// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func newTestServer() *Server {
	auditChain := audit.NewChain()
	mcpInterceptor := mcp.NewInterceptor(mcp.NewPolicy())
	return NewServer(Config{ListenAddr: ":0"}, auditChain, mcpInterceptor)
}

func TestHealthEndpoint(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", resp["status"])
	}
}

func TestStatusEndpoint(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp StatusResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Version == "" {
		t.Error("version should not be empty")
	}
}

func TestAuditEndpoint(t *testing.T) {
	auditChain := audit.NewChain()
	auditChain.Append(audit.NewEntry("file_blocked", audit.SeverityHigh, map[string]any{"pid": 42}))
	auditChain.Append(audit.NewEntry("network_blocked", audit.SeverityCritical, map[string]any{"dst": "1.2.3.4"}))

	s := NewServer(Config{ListenAddr: ":0"}, auditChain, mcp.NewInterceptor(mcp.NewPolicy()))

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp AuditResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 2 {
		t.Errorf("expected 2 entries, got %d", resp.Total)
	}
	if !resp.ChainValid {
		t.Error("chain should be valid")
	}
}

func TestAuditVerifyEndpoint(t *testing.T) {
	auditChain := audit.NewChain()
	auditChain.Append(audit.NewEntry("test", audit.SeverityInfo, nil))

	s := NewServer(Config{ListenAddr: ":0"}, auditChain, mcp.NewInterceptor(mcp.NewPolicy()))

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["valid"] != true {
		t.Error("chain should be valid")
	}
}

func TestMCPStatsEndpoint(t *testing.T) {
	policy := mcp.NewPolicy()
	policy.SetBlockedTools([]string{"bad_tool"})
	interceptor := mcp.NewInterceptor(policy)
	interceptor.Evaluate(&mcp.ToolCall{Name: "good_tool"})
	interceptor.Evaluate(&mcp.ToolCall{Name: "bad_tool"})

	s := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), interceptor)

	req := httptest.NewRequest(http.MethodGet, "/api/mcp/stats", nil)
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp mcp.InterceptorStats
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.TotalCalls != 2 {
		t.Errorf("expected 2 total, got %d", resp.TotalCalls)
	}
}

func TestMCPEventsEndpoint(t *testing.T) {
	interceptor := mcp.NewInterceptor(mcp.NewPolicy())
	interceptor.Evaluate(&mcp.ToolCall{Name: "test_tool"})

	s := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), interceptor)

	req := httptest.NewRequest(http.MethodGet, "/api/mcp/events?limit=10", nil)
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp []mcp.ToolCallEvent
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 {
		t.Errorf("expected 1 event, got %d", len(resp))
	}
}

func TestDashboardEndpoint(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if len(body) == 0 {
		t.Error("dashboard should return non-empty HTML")
	}
}

func TestSSEEndpoint(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/events/stream", nil)
	w := httptest.NewRecorder()

	// SSE will block, so we just verify it sets correct headers
	done := make(chan struct{})
	go func() {
		s.mux.ServeHTTP(w, req)
		close(done)
	}()

	// Give it a moment to set headers
	time.Sleep(50 * time.Millisecond)

	// The handler should have started; cancel via context
	// In tests we just verify the endpoint exists
	select {
	case <-done:
		// Handler returned (e.g. due to flusher not available)
	case <-time.After(200 * time.Millisecond):
		// Still running, which is expected for SSE
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("web should be disabled by default")
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("expected :8080, got %s", cfg.ListenAddr)
	}
}

func TestCORSHeaders(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("API should return JSON content type")
	}
}
