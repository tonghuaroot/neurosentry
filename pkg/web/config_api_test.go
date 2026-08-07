// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func TestConfigEndpoint(t *testing.T) {
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.SetConfigProvider(func() map[string]any {
		return map[string]any{"model_fim": map[string]any{"enabled": true, "enforce_mode": true}}
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/config", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var cfg map[string]any
	json.Unmarshal(rec.Body.Bytes(), &cfg)
	mf, _ := cfg["model_fim"].(map[string]any)
	if mf == nil || mf["enforce_mode"] != true {
		t.Errorf("config not returned: %v", cfg)
	}
}

func TestTrendsEndpoint(t *testing.T) {
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.sample()
	srv.sample()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/trends", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var tr map[string][]float64
	json.Unmarshal(rec.Body.Bytes(), &tr)
	if len(tr["events"]) != 2 {
		t.Errorf("expected 2 samples, got %d", len(tr["events"]))
	}
}

func TestNotifyTestEndpoint(t *testing.T) {
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	// Not configured -> enabled:false.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/notify/test", nil))
	var r1 map[string]any
	json.Unmarshal(rec.Body.Bytes(), &r1)
	if r1["enabled"] != false {
		t.Errorf("unconfigured notify should report enabled:false, got %v", r1)
	}
	// Configured tester -> reports delivery.
	srv.SetNotifyTester(func() (int, int) { return 2, 2 })
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/notify/test", nil))
	var r2 map[string]any
	json.Unmarshal(rec.Body.Bytes(), &r2)
	if r2["delivered"] != float64(2) {
		t.Errorf("expected delivered 2, got %v", r2["delivered"])
	}
}
