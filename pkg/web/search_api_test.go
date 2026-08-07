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

func TestSearchFiltersAndPaginates(t *testing.T) {
	chain := audit.NewChain()
	for i := 0; i < 5; i++ {
		e := audit.NewEntry("file_blocked", audit.SeverityHigh, map[string]any{"file_path": "/models/a.safetensors"})
		e.SetActor(100+i, 0, "cat")
		chain.Append(e)
	}
	chain.Append(audit.NewEntry("auth:login", audit.SeverityInfo, map[string]any{"tenant": "default"}))
	srv := NewServer(Config{ListenAddr: ":0"}, chain, mcp.NewInterceptor(mcp.NewPolicy()))

	do := func(qs string) map[string]any {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/search?"+qs, nil))
		if rec.Code != 200 {
			t.Fatalf("search %q: %d", qs, rec.Code)
		}
		var r map[string]any
		json.Unmarshal(rec.Body.Bytes(), &r)
		return r
	}

	// Type filter.
	if r := do("type=file_blocked"); r["total"].(float64) != 5 {
		t.Errorf("type filter: expected 5, got %v", r["total"])
	}
	// Severity filter.
	if r := do("severity=info"); r["total"].(float64) != 1 {
		t.Errorf("severity filter: expected 1, got %v", r["total"])
	}
	// Full-text over actor comm.
	if r := do("q=cat"); r["total"].(float64) != 5 {
		t.Errorf("text search on actor comm: expected 5, got %v", r["total"])
	}
	// Full-text over details value.
	if r := do("q=safetensors"); r["total"].(float64) != 5 {
		t.Errorf("text search on details: expected 5, got %v", r["total"])
	}
	// Pagination.
	r := do("limit=2&offset=0")
	if len(r["results"].([]any)) != 2 {
		t.Errorf("expected 2 results with limit=2, got %d", len(r["results"].([]any)))
	}
	if r["total"].(float64) != 6 {
		t.Errorf("total should be 6, got %v", r["total"])
	}
}
