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
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func TestBreakerArmDisarm(t *testing.T) {
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	armed := false
	srv.SetBreakerManager(func() (bool, int64) { return armed, 3 }, func(on bool) { armed = on })

	// Arm.
	body, _ := json.Marshal(map[string]bool{"armed": true})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/breaker", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("arm should return 200, got %d", rec.Code)
	}
	if !armed {
		t.Error("breaker should be armed after POST armed=true")
	}

	// The detections endpoint surfaces breaker state.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/detections", nil))
	var resp struct {
		Breaker struct {
			Armed bool  `json:"armed"`
			Trips int64 `json:"trips"`
		} `json:"breaker"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Breaker.Armed || resp.Breaker.Trips != 3 {
		t.Errorf("detections should surface breaker state, got %+v", resp.Breaker)
	}

	// Disarm.
	body, _ = json.Marshal(map[string]bool{"armed": false})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/breaker", bytes.NewReader(body)))
	if armed {
		t.Error("breaker should be disarmed after POST armed=false")
	}
}

func TestBreakerUnconfigured(t *testing.T) {
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	body, _ := json.Marshal(map[string]bool{"armed": true})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/breaker", bytes.NewReader(body)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unconfigured breaker should be 503, got %d", rec.Code)
	}
}
