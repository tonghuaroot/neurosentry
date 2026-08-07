// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

// TestTelemetryOpenWithoutPlatform confirms that in simple/demo mode (no
// control plane) the security telemetry endpoints are reachable without auth.
func TestTelemetryOpenWithoutPlatform(t *testing.T) {
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	for _, path := range []string{"/api/audit", "/api/mcp/stats", "/api/correlate/findings", "/api/audit/verify"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("demo mode: %s should be open, got %d", path, rec.Code)
		}
	}
	// Status must advertise that auth is NOT required.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	var st StatusResponse
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st.AuthRequired {
		t.Error("auth_required should be false without platform")
	}
}

// TestTelemetryGatedWithPlatform confirms that once the control plane is
// enabled, the same telemetry endpoints reject unauthenticated requests and
// serve authenticated ones — closing the pre-auth data-exposure gap.
func TestTelemetryGatedWithPlatform(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)

	// Status stays open and now advertises auth_required=true.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	var st StatusResponse
	json.Unmarshal(rec.Body.Bytes(), &st)
	if !st.AuthRequired {
		t.Error("auth_required should be true with platform enabled")
	}

	// Telemetry without a token -> 401.
	for _, path := range []string{"/api/audit", "/api/mcp/stats", "/api/correlate/findings", "/api/audit/verify", "/api/audit/export"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("platform mode: %s without token should be 401, got %d", path, rec.Code)
		}
	}

	// With an owner token -> 200.
	token := login(t, srv, "system", "owner@system", "owner-password")
	for _, path := range []string{"/api/audit", "/api/mcp/stats", "/api/correlate/findings"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("platform mode: %s with token should be 200, got %d", path, rec.Code)
		}
	}

	// SSE stream without a token -> 401 (EventSource path).
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/events/stream", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("SSE without token should be 401, got %d", rec.Code)
	}

	// SSE with a token query param must not be 401. The handler streams, so use
	// an already-cancelled context to make it return immediately after the auth
	// check rather than blocking on the event loop.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/events/stream?token="+token, nil).WithContext(ctx)
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Error("SSE with valid token query param should be authorized")
	}
}
