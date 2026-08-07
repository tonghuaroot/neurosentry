// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/mcp"
	"github.com/neurosentry/neurosentry/pkg/sandbox"
	"github.com/neurosentry/neurosentry/pkg/web"
)

func TestAuditChainEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := fmt.Sprintf("%s/audit.jsonl", dir)

	chain := audit.NewChain()
	store, err := audit.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	events := []struct {
		typ      string
		severity audit.Severity
	}{
		{"file_blocked", audit.SeverityHigh},
		{"network_blocked", audit.SeverityCritical},
		{"pickle_dangerous", audit.SeverityCritical},
		{"file_access", audit.SeverityInfo},
		{"model_load", audit.SeverityInfo},
	}

	for _, ev := range events {
		entry := audit.NewEntry(ev.typ, ev.severity, map[string]interface{}{
			"pid":  1234,
			"comm": "python3",
		})
		if err := chain.Append(entry); err != nil {
			t.Fatal(err)
		}
		entries := chain.Entries()
		if err := store.Write(entries[len(entries)-1]); err != nil {
			t.Fatal(err)
		}
	}
	store.Close()

	loaded, err := audit.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Len() != 5 {
		t.Errorf("expected 5 entries, got %d", loaded.Len())
	}

	if err := loaded.Verify(); err != nil {
		t.Fatalf("chain verification failed after reload: %v", err)
	}

	entries := loaded.Entries()
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d: prev_hash linkage broken", i)
		}
	}
	if entries[0].PrevHash != audit.GenesisHash {
		t.Error("first entry should reference genesis hash")
	}
}

func TestMCPInterceptionEndToEnd(t *testing.T) {
	policy := mcp.NewPolicy()
	policy.SetAllowedTools([]string{"read_file", "list_dir"})
	interceptor := mcp.NewInterceptor(policy)

	calls := []struct {
		raw     string
		allowed bool
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/models/llama.safetensors"}}}`, true},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_command","arguments":{"cmd":"cat /etc/shadow"}}}`, false},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_dir","arguments":{"path":"/models"}}}`, true},
		{`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/exfil.tar.gz"}}}`, false},
	}

	auditChain := audit.NewChain()

	for _, tc := range calls {
		msg, err := mcp.ParseMessage([]byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}

		toolCall, err := mcp.ExtractToolCall(msg)
		if err != nil {
			t.Fatal(err)
		}

		result := interceptor.Evaluate(toolCall)

		severity := audit.SeverityInfo
		if result.Action == "blocked" {
			severity = audit.SeverityHigh
		}
		entry := audit.NewEntry("mcp_tool_call", severity, map[string]interface{}{
			"tool":   toolCall.Name,
			"action": result.Action,
			"reason": result.Reason,
		})
		auditChain.Append(entry)

		if tc.allowed && result.Action != "allowed" {
			t.Errorf("tool %s should be allowed", toolCall.Name)
		}
		if !tc.allowed && result.Action != "blocked" {
			t.Errorf("tool %s should be blocked", toolCall.Name)
		}
	}

	stats := interceptor.Stats()
	if stats.TotalCalls != 4 {
		t.Errorf("expected 4 total calls, got %d", stats.TotalCalls)
	}
	if stats.Allowed != 2 {
		t.Errorf("expected 2 allowed, got %d", stats.Allowed)
	}
	if stats.Blocked != 2 {
		t.Errorf("expected 2 blocked, got %d", stats.Blocked)
	}

	if auditChain.Len() != 4 {
		t.Errorf("expected 4 audit entries, got %d", auditChain.Len())
	}
	if err := auditChain.Verify(); err != nil {
		t.Fatalf("audit chain verification failed: %v", err)
	}
}

func TestWebDashboardEndToEnd(t *testing.T) {
	auditChain := audit.NewChain()
	mcpPolicy := mcp.NewPolicy()
	mcpPolicy.SetBlockedTools([]string{"exec_command"})
	interceptor := mcp.NewInterceptor(mcpPolicy)

	auditChain.Append(audit.NewEntry("file_blocked", audit.SeverityHigh, map[string]interface{}{
		"pid": 1234, "file_path": "/models/llama.safetensors",
	}))
	auditChain.Append(audit.NewEntry("network_blocked", audit.SeverityCritical, map[string]interface{}{
		"dst_addr": "evil.example.com",
	}))
	interceptor.Evaluate(&mcp.ToolCall{Name: "read_file", Arguments: map[string]interface{}{"path": "/tmp"}})
	interceptor.Evaluate(&mcp.ToolCall{Name: "exec_command", Arguments: map[string]interface{}{"cmd": "rm -rf /"}})

	srv := web.NewServer(web.Config{ListenAddr: ":0"}, auditChain, interceptor)

	t.Run("health", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("GET", "/api/health", nil))
		if w.Code != 200 {
			t.Errorf("health: got %d", w.Code)
		}
	})

	t.Run("audit", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("GET", "/api/audit", nil))
		var resp web.AuditResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Total != 2 {
			t.Errorf("expected 2 audit entries, got %d", resp.Total)
		}
		if !resp.ChainValid {
			t.Error("chain should be valid")
		}
	})

	t.Run("audit-verify", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("GET", "/api/audit/verify", nil))
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["valid"] != true {
			t.Error("chain should be valid")
		}
	})

	t.Run("mcp-stats", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("GET", "/api/mcp/stats", nil))
		var resp mcp.InterceptorStats
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.TotalCalls != 2 {
			t.Errorf("expected 2 calls, got %d", resp.TotalCalls)
		}
	})

	t.Run("mcp-events", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("GET", "/api/mcp/events?limit=10", nil))
		var resp []mcp.ToolCallEvent
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) != 2 {
			t.Errorf("expected 2 events, got %d", len(resp))
		}
	})

	t.Run("dashboard", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 200 {
			t.Errorf("dashboard: got %d", w.Code)
		}
	})
}

func TestSandboxProfileEndToEnd(t *testing.T) {
	cfg := sandbox.Config{
		Enabled:        true,
		ReadOnlyPaths:  []string{"/models", "/usr/lib/python3"},
		ReadWritePaths: []string{"/tmp", "/var/log/neurosentry"},
		DenyPaths:      []string{"/etc/shadow", "/root/.ssh"},
	}

	profile := sandbox.ProfileFromConfig(cfg)
	if err := profile.Validate(); err != nil {
		t.Fatalf("profile validation failed: %v", err)
	}

	if len(profile.Rules) != 6 {
		t.Errorf("expected 6 rules, got %d", len(profile.Rules))
	}

	readCount, rwCount, denyCount := 0, 0, 0
	for _, r := range profile.Rules {
		switch r.Access {
		case sandbox.AccessRead:
			readCount++
		case sandbox.AccessReadWrite:
			rwCount++
		case sandbox.AccessDeny:
			denyCount++
		}
	}
	if readCount != 2 || rwCount != 2 || denyCount != 2 {
		t.Errorf("rule counts: read=%d rw=%d deny=%d", readCount, rwCount, denyCount)
	}

	if err := profile.Apply(); err != nil {
		t.Errorf("apply should not error: %v", err)
	}
}

func TestFullPipelineEndToEnd(t *testing.T) {
	auditChain := audit.NewChain()
	interceptor := mcp.NewInterceptor(mcp.NewPolicy())
	srv := web.NewServer(web.Config{ListenAddr: ":0"}, auditChain, interceptor)

	eventTypes := []string{
		"file_access", "file_blocked", "file_blocked",
		"network_allowed", "network_blocked",
		"pickle_load", "pickle_dangerous",
	}
	severities := []audit.Severity{
		audit.SeverityInfo, audit.SeverityHigh, audit.SeverityHigh,
		audit.SeverityInfo, audit.SeverityCritical,
		audit.SeverityInfo, audit.SeverityCritical,
	}

	for i, et := range eventTypes {
		entry := audit.NewEntry(et, severities[i], map[string]interface{}{
			"pid":  1000 + i,
			"comm": "python3",
		})
		auditChain.Append(entry)
		data, _ := json.Marshal(entry)
		srv.BroadcastEvent(data)
	}

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/api/audit", nil))

	var resp web.AuditResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 7 {
		t.Errorf("expected 7 audit entries, got %d", resp.Total)
	}
	if !resp.ChainValid {
		t.Error("chain should be valid")
	}
}

func TestHighVolumeAuditChain(t *testing.T) {
	chain := audit.NewChain()
	dir := t.TempDir()
	path := fmt.Sprintf("%s/audit-stress.jsonl", dir)
	store, _ := audit.NewFileStore(path)

	const eventCount = 1000

	start := time.Now()
	for i := 0; i < eventCount; i++ {
		entry := audit.NewEntry("file_access", audit.SeverityInfo, map[string]interface{}{
			"pid":  i,
			"path": fmt.Sprintf("/models/model_%d.safetensors", i),
		})
		chain.Append(entry)
		entries := chain.Entries()
		store.Write(entries[len(entries)-1])
	}
	store.Close()
	writeTime := time.Since(start)

	if chain.Len() != eventCount {
		t.Errorf("expected %d entries, got %d", eventCount, chain.Len())
	}

	start = time.Now()
	if err := chain.Verify(); err != nil {
		t.Fatalf("high volume chain verification failed: %v", err)
	}
	verifyTime := time.Since(start)

	start = time.Now()
	loaded, err := audit.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(); err != nil {
		t.Fatalf("reloaded chain verification failed: %v", err)
	}
	reloadTime := time.Since(start)

	t.Logf("Volume: %d events, write=%v, verify=%v, reload+verify=%v",
		eventCount, writeTime, verifyTime, reloadTime)
}
