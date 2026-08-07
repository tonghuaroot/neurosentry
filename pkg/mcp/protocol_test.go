// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseToolCallRequest(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if msg.Method != "tools/call" {
		t.Errorf("expected method tools/call, got %s", msg.Method)
	}

	tc, err := ExtractToolCall(msg)
	if err != nil {
		t.Fatalf("extract tool call: %v", err)
	}

	if tc.Name != "read_file" {
		t.Errorf("expected tool name read_file, got %s", tc.Name)
	}
	if tc.Arguments["path"] != "/etc/passwd" {
		t.Errorf("expected path /etc/passwd, got %v", tc.Arguments["path"])
	}
}

func TestParseToolCallResponse(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"file contents here"}]}}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if msg.ID != float64(1) {
		t.Errorf("expected id 1, got %v", msg.ID)
	}
	if msg.Result == nil {
		t.Error("result should not be nil")
	}
}

func TestParseNonToolCallMethod(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{}}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	_, err = ExtractToolCall(msg)
	if err == nil {
		t.Error("non-tool-call method should return error")
	}
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := ParseMessage([]byte(`{invalid`))
	if err == nil {
		t.Error("invalid JSON should return error")
	}
}

func TestParseNotification(t *testing.T) {
	raw := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !msg.IsNotification() {
		t.Error("message without id should be notification")
	}
}

func TestToolCallPolicyAllow(t *testing.T) {
	p := NewPolicy()
	p.SetAllowedTools([]string{"read_file", "list_dir"})

	tc := &ToolCall{Name: "read_file", Arguments: map[string]any{"path": "/tmp"}}
	if !p.IsAllowed(tc) {
		t.Error("read_file should be allowed")
	}

	tc2 := &ToolCall{Name: "exec_command", Arguments: map[string]any{"cmd": "rm -rf /"}}
	if p.IsAllowed(tc2) {
		t.Error("exec_command should not be allowed")
	}
}

func TestToolCallPolicyBlock(t *testing.T) {
	p := NewPolicy()
	p.SetBlockedTools([]string{"exec_command", "write_file"})

	tc := &ToolCall{Name: "exec_command"}
	if p.IsAllowed(tc) {
		t.Error("exec_command should be blocked")
	}

	tc2 := &ToolCall{Name: "read_file"}
	if !p.IsAllowed(tc2) {
		t.Error("read_file should be allowed when not in block list")
	}
}

func TestToolCallPolicyAllowTakesPrecedence(t *testing.T) {
	p := NewPolicy()
	p.SetAllowedTools([]string{"read_file"})
	p.SetBlockedTools([]string{"read_file"})

	tc := &ToolCall{Name: "read_file"}
	if !p.IsAllowed(tc) {
		t.Error("allowlist should take precedence over blocklist")
	}
}

func TestToolCallPolicyEmpty(t *testing.T) {
	p := NewPolicy()

	tc := &ToolCall{Name: "anything"}
	if !p.IsAllowed(tc) {
		t.Error("empty policy should allow everything")
	}
}

func TestToolCallEvent(t *testing.T) {
	tc := &ToolCall{
		Name:      "read_file",
		Arguments: map[string]any{"path": "/models/llama.safetensors"},
	}

	event := tc.ToEvent("blocked", "tool not in allowlist")
	if event.ToolName != "read_file" {
		t.Error("event tool name mismatch")
	}
	if event.Action != "blocked" {
		t.Error("event action should be blocked")
	}
	if event.Timestamp.IsZero() {
		t.Error("event timestamp should not be zero")
	}
}

func TestToolCallEventJSON(t *testing.T) {
	tc := &ToolCall{
		Name:      "write_file",
		Arguments: map[string]any{"path": "/tmp/test"},
	}
	event := tc.ToEvent("allowed", "")

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ToolCallEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ToolName != "write_file" {
		t.Error("decoded tool name mismatch")
	}
}

func TestMessageIsRequest(t *testing.T) {
	tests := []struct {
		name    string
		msg     Message
		isReq   bool
		isNotif bool
		isResp  bool
	}{
		{"request", Message{ID: float64(1), Method: "tools/call"}, true, false, false},
		{"notification", Message{Method: "notifications/foo"}, false, true, false},
		{"response", Message{ID: float64(1), Result: json.RawMessage(`{}`)}, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.msg.IsRequest() != tt.isReq {
				t.Errorf("IsRequest() = %v, want %v", tt.msg.IsRequest(), tt.isReq)
			}
			if tt.msg.IsNotification() != tt.isNotif {
				t.Errorf("IsNotification() = %v, want %v", tt.msg.IsNotification(), tt.isNotif)
			}
			if tt.msg.IsResponse() != tt.isResp {
				t.Errorf("IsResponse() = %v, want %v", tt.msg.IsResponse(), tt.isResp)
			}
		})
	}
}

func TestInterceptorRecordsEvents(t *testing.T) {
	p := NewPolicy()
	p.SetBlockedTools([]string{"dangerous_tool"})
	interceptor := NewInterceptor(p)

	tc1 := &ToolCall{Name: "safe_tool", Arguments: map[string]any{}}
	tc2 := &ToolCall{Name: "dangerous_tool", Arguments: map[string]any{}}

	result1 := interceptor.Evaluate(tc1)
	result2 := interceptor.Evaluate(tc2)

	if result1.Action != "allowed" {
		t.Error("safe_tool should be allowed")
	}
	if result2.Action != "blocked" {
		t.Error("dangerous_tool should be blocked")
	}

	events := interceptor.RecentEvents(10)
	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}

func TestInterceptorRecentEventsLimit(t *testing.T) {
	p := NewPolicy()
	interceptor := NewInterceptor(p)

	for i := 0; i < 20; i++ {
		tc := &ToolCall{Name: "tool", Arguments: map[string]any{"i": i}}
		interceptor.Evaluate(tc)
	}

	events := interceptor.RecentEvents(5)
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestInterceptorStats(t *testing.T) {
	p := NewPolicy()
	p.SetBlockedTools([]string{"bad"})
	interceptor := NewInterceptor(p)

	interceptor.Evaluate(&ToolCall{Name: "good"})
	interceptor.Evaluate(&ToolCall{Name: "good"})
	interceptor.Evaluate(&ToolCall{Name: "bad"})

	stats := interceptor.Stats()
	if stats.TotalCalls != 3 {
		t.Errorf("expected 3 total, got %d", stats.TotalCalls)
	}
	if stats.Blocked != 1 {
		t.Errorf("expected 1 blocked, got %d", stats.Blocked)
	}
	if stats.Allowed != 2 {
		t.Errorf("expected 2 allowed, got %d", stats.Allowed)
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("MCP should be disabled by default")
	}
	if !cfg.LogToolCalls {
		t.Error("tool call logging should be enabled by default")
	}
}

func TestToolCallTimestamp(t *testing.T) {
	before := time.Now()
	event := (&ToolCall{Name: "test"}).ToEvent("allowed", "")
	after := time.Now()

	if event.Timestamp.Before(before) || event.Timestamp.After(after) {
		t.Error("event timestamp out of range")
	}
}
