// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func healthServer() *Server {
	return NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
}

func TestLivenessAlwaysOK(t *testing.T) {
	srv := healthServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("liveness should be 200, got %d", rec.Code)
	}
}

func TestReadinessReflectsProbe(t *testing.T) {
	srv := healthServer()

	// No probe wired -> ready by default.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("default readiness should be 200, got %d", rec.Code)
	}

	// Not-ready probe -> 503, with detail.
	srv.SetReadiness(func() (bool, map[string]any) {
		return false, map[string]any{"support": "unsupported", "components": 0}
	})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready should be 503, got %d", rec.Code)
	}
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["ready"] != false {
		t.Errorf("readiness body should carry ready=false, got %v", body["ready"])
	}

	// Ready probe -> 200.
	srv.SetReadiness(func() (bool, map[string]any) {
		return true, map[string]any{"support": "supported", "components": 5}
	})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready should be 200, got %d", rec.Code)
	}
}

// Readiness must be reachable without authentication (K8s probes can't auth)
// but must not leak security telemetry — only coarse component/support state.
func TestReadinessUnauthenticatedButCoarse(t *testing.T) {
	srv := healthServer()
	srv.SetReadiness(func() (bool, map[string]any) {
		return true, map[string]any{"support": "supported", "components": 5, "kernel": "6.1.0"}
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readiness should be reachable unauthenticated, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"chain", "finding", "prompt", "secret", "hash"} {
		if strings.Contains(body, leak) {
			t.Errorf("readiness body leaked %q: %s", leak, body)
		}
	}
}
