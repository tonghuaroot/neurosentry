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
	"github.com/neurosentry/neurosentry/pkg/correlate"
	"github.com/neurosentry/neurosentry/pkg/mcp"
)

func TestCorrelateFindingsEndpoint(t *testing.T) {
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))

	// Wire a source that returns one critical cross-layer finding.
	srv.SetCorrelationSource(func(limit int) []correlate.Finding {
		return []correlate.Finding{{
			Timestamp:   time.Now(),
			Rule:        "secret-read-then-llm",
			PID:         1234,
			Severity:    "critical",
			Technique:   "LLM02",
			Description: "secret read then sent toward an LLM",
			Chain: []correlate.Signal{
				{PID: 1234, Layer: correlate.LayerKernelFile, Kind: "file_read"},
				{PID: 1234, Layer: correlate.LayerAI, Kind: "request"},
			},
		}}
	})

	req := httptest.NewRequest("GET", "/api/correlate/findings", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp struct {
		Findings []correlate.Finding `json:"findings"`
		Total    int                 `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || len(resp.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", resp)
	}
	f := resp.Findings[0]
	if f.Rule != "secret-read-then-llm" || f.Severity != "critical" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if len(f.Chain) != 2 {
		t.Errorf("expected 2-signal causal chain, got %d", len(f.Chain))
	}
}

func TestCorrelateFindingsEmptyWhenNoSource(t *testing.T) {
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	req := httptest.NewRequest("GET", "/api/correlate/findings", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Total != 0 {
		t.Errorf("expected 0 findings with no source, got %d", resp.Total)
	}
}
