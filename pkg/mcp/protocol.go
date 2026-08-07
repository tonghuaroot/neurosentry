// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"
)

type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (m *Message) IsRequest() bool      { return m.ID != nil && m.Method != "" }
func (m *Message) IsNotification() bool { return m.ID == nil && m.Method != "" }
func (m *Message) IsResponse() bool     { return m.ID != nil && m.Method == "" }

func ParseMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC message: %w", err)
	}
	return &msg, nil
}

type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	RequestID any            `json:"request_id,omitempty"`
}

type ToolCallEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	ToolName  string         `json:"tool_name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Action    string         `json:"action"`
	Reason    string         `json:"reason,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
}

func ExtractToolCall(msg *Message) (*ToolCall, error) {
	if msg.Method != "tools/call" {
		return nil, fmt.Errorf("not a tool call: method=%s", msg.Method)
	}

	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, fmt.Errorf("parse tool call params: %w", err)
	}

	return &ToolCall{
		Name:      params.Name,
		Arguments: params.Arguments,
		RequestID: msg.ID,
	}, nil
}

func (tc *ToolCall) ToEvent(action, reason string) ToolCallEvent {
	return ToolCallEvent{
		Timestamp: time.Now(),
		ToolName:  tc.Name,
		Arguments: tc.Arguments,
		Action:    action,
		Reason:    reason,
		SessionID: tc.SessionID,
	}
}

type ArgumentRule struct {
	ToolName string
	ArgName  string
	Pattern  *regexp.Regexp
	Action   string
	Reason   string
}

type Policy struct {
	allowedTools map[string]bool
	blockedTools map[string]bool
	argRules     []ArgumentRule
}

func NewPolicy() *Policy {
	return &Policy{
		allowedTools: make(map[string]bool),
		blockedTools: make(map[string]bool),
	}
}

func (p *Policy) SetAllowedTools(tools []string) {
	p.allowedTools = make(map[string]bool)
	for _, t := range tools {
		p.allowedTools[t] = true
	}
}

func (p *Policy) SetBlockedTools(tools []string) {
	p.blockedTools = make(map[string]bool)
	for _, t := range tools {
		p.blockedTools[t] = true
	}
}

func (p *Policy) AddArgumentRule(toolName, argName, pattern, reason string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	p.argRules = append(p.argRules, ArgumentRule{
		ToolName: toolName,
		ArgName:  argName,
		Pattern:  re,
		Action:   "block",
		Reason:   reason,
	})
	return nil
}

func (p *Policy) IsAllowed(tc *ToolCall) bool {
	if len(p.allowedTools) > 0 {
		return p.allowedTools[tc.Name]
	}
	if len(p.blockedTools) > 0 {
		return !p.blockedTools[tc.Name]
	}
	return true
}

func (p *Policy) CheckArguments(tc *ToolCall) (bool, string) {
	for _, rule := range p.argRules {
		if rule.ToolName != "" && rule.ToolName != tc.Name {
			continue
		}
		val, ok := tc.Arguments[rule.ArgName]
		if !ok {
			continue
		}
		valStr := fmt.Sprintf("%v", val)
		if rule.Pattern.MatchString(valStr) {
			return false, rule.Reason
		}
	}
	return true, ""
}

type EvalResult struct {
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

type InterceptorStats struct {
	TotalCalls int64            `json:"total_calls"`
	Allowed    int64            `json:"allowed"`
	Blocked    int64            `json:"blocked"`
	PerTool    map[string]int64 `json:"per_tool,omitempty"`
}

const maxEventHistory = 5000

type Interceptor struct {
	policy *Policy
	mu     sync.Mutex
	events []ToolCallEvent
	stats  InterceptorStats
}

func NewInterceptor(p *Policy) *Interceptor {
	return &Interceptor{
		policy: p,
		stats:  InterceptorStats{PerTool: make(map[string]int64)},
	}
}

func (i *Interceptor) Evaluate(tc *ToolCall) EvalResult {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.stats.TotalCalls++
	i.stats.PerTool[tc.Name]++

	var result EvalResult

	if !i.policy.IsAllowed(tc) {
		result = EvalResult{Action: "blocked", Reason: "tool not in allowlist"}
		i.stats.Blocked++
	} else if ok, reason := i.policy.CheckArguments(tc); !ok {
		result = EvalResult{Action: "blocked", Reason: reason}
		i.stats.Blocked++
	} else {
		result = EvalResult{Action: "allowed"}
		i.stats.Allowed++
	}

	event := tc.ToEvent(result.Action, result.Reason)
	i.events = append(i.events, event)
	if len(i.events) > maxEventHistory {
		i.events = i.events[len(i.events)-maxEventHistory:]
	}

	return result
}

func (i *Interceptor) RecentEvents(limit int) []ToolCallEvent {
	i.mu.Lock()
	defer i.mu.Unlock()

	if limit <= 0 || limit > len(i.events) {
		limit = len(i.events)
	}

	start := len(i.events) - limit
	result := make([]ToolCallEvent, limit)
	copy(result, i.events[start:])
	return result
}

func (i *Interceptor) Stats() InterceptorStats {
	i.mu.Lock()
	defer i.mu.Unlock()
	cp := i.stats
	cp.PerTool = make(map[string]int64, len(i.stats.PerTool))
	for k, v := range i.stats.PerTool {
		cp.PerTool[k] = v
	}
	return cp
}

type Config struct {
	Enabled      bool     `mapstructure:"enabled" yaml:"enabled"`
	ListenAddr   string   `mapstructure:"listen_addr" yaml:"listen_addr"`
	UpstreamAddr string   `mapstructure:"upstream_addr" yaml:"upstream_addr"`
	AllowedTools []string `mapstructure:"allowed_tools" yaml:"allowed_tools"`
	BlockedTools []string `mapstructure:"blocked_tools" yaml:"blocked_tools"`
	LogToolCalls bool     `mapstructure:"log_tool_calls" yaml:"log_tool_calls"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:      false,
		ListenAddr:   "127.0.0.1:8081",
		LogToolCalls: true,
	}
}
