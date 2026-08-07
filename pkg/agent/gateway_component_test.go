// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/config"
)

func TestGatewayComponentBlocksAndAudits(t *testing.T) {
	chain := audit.NewChain()
	gc := newGatewayComponent(config.GatewayConfig{
		Enabled: true, ListenAddr: ":0", BlockOnDetect: true,
	}, chain, nil)

	// A prompt carrying a secret headed for an LLM must be blocked inline and audited.
	body, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "here is my key AKIAIOSFODNN7EXAMPLE debug it"}},
	})
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	gc.gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("secret leak should be blocked, got %d", rec.Code)
	}
	found := false
	for _, e := range chain.Entries() {
		if e.EventType == "gateway_blocked" {
			found = true
		}
	}
	if !found {
		t.Error("a blocked gateway request should be recorded in the audit chain")
	}
}

func TestGatewayComponentName(t *testing.T) {
	gc := newGatewayComponent(config.GatewayConfig{ListenAddr: ":0"}, audit.NewChain(), nil)
	if gc.Name() != "ai-gateway" {
		t.Errorf("unexpected name %q", gc.Name())
	}
	if gc.description() == "" {
		t.Error("description should be non-empty")
	}
}
