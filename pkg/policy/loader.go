// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"net"
	"os"
	"reflect"

	"gopkg.in/yaml.v3"
)

// Action represents a policy action
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	ActionAlert Action = "alert"
)

// Policy represents a security policy
type Policy struct {
	Version    string              `yaml:"version"`
	Metadata   PolicyMetadata      `yaml:"metadata"`
	Rules      []Rule              `yaml:"rules"`
	Responses  map[string]Response `yaml:"responses"`
	Alerts     AlertConfig         `yaml:"alerts"`
	Trusted    TrustedConfig       `yaml:"trusted"`
	Exemptions ExemptionConfig     `yaml:"exemptions"`
}

// PolicyMetadata contains policy metadata
type PolicyMetadata struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
}

// Rule represents a single policy rule
type Rule struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Enabled     bool          `yaml:"enabled"`
	Condition   RuleCondition `yaml:"condition"`
	Action      Action        `yaml:"action"`
	Severity    string        `yaml:"severity"`
	Alert       bool          `yaml:"alert"`
	Response    string        `yaml:"response,omitempty"`
}

// RuleCondition defines when a rule matches
type RuleCondition struct {
	Type            string   `yaml:"type"`
	Extensions      []string `yaml:"extensions,omitempty"`
	Paths           []string `yaml:"paths,omitempty"`
	Destinations    []string `yaml:"destinations,omitempty"`
	SizeThresholdMB int      `yaml:"size_threshold_mb,omitempty"`
	Port            int      `yaml:"port,omitempty"`
	Protocol        string   `yaml:"protocol,omitempty"`
	HashMismatch    bool     `yaml:"hash_mismatch,omitempty"`
	CIDRMatch       string   `yaml:"cidr,omitempty"`
}

// Response defines a response action
type Response struct {
	Enabled           bool   `yaml:"enabled"`
	Method            string `yaml:"method,omitempty"`
	Duration          string `yaml:"duration,omitempty"`
	RequireKubernetes bool   `yaml:"require_kubernetes,omitempty"`
}

// AlertConfig contains alert configuration
type AlertConfig struct {
	Webhook         string `yaml:"webhook"`
	SilenceSeconds  int    `yaml:"silence_seconds"`
	RateLimit       int    `yaml:"rate_limit"`
	RateLimitWindow string `yaml:"rate_limit_window"`
}

// TrustedConfig contains trusted entity configuration
type TrustedConfig struct {
	Processes  []TrustedProcess   `yaml:"processes"`
	Containers []TrustedContainer `yaml:"containers"`
}

// TrustedProcess defines a trusted process pattern
type TrustedProcess struct {
	Name   string `yaml:"name"`
	Reason string `yaml:"reason"`
}

// TrustedContainer defines a trusted container selector
type TrustedContainer struct {
	Label string `yaml:"label"`
}

// ExemptionConfig contains exemption rules
type ExemptionConfig struct {
	Paths []string `yaml:"paths"`
	Users []string `yaml:"users"`
}

// Loader loads policies from files
type Loader struct {
	path string
}

// NewLoader creates a new policy loader
func NewLoader(path string) (*Loader, error) {
	// Empty path means use builtin default
	if path == "" {
		return &Loader{path: "builtin"}, nil
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Use default builtin policy
		return &Loader{path: "builtin"}, nil
	}

	return &Loader{path: path}, nil
}

// Load loads the policy from file
func (l *Loader) Load() (*Policy, error) {
	// If using builtin, return default policy
	if l.path == "builtin" {
		return DefaultPolicy(), nil
	}

	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Validate policy
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	return &policy, nil
}

// Validate validates the policy
func (p *Policy) Validate() error {
	if p.Version == "" {
		return fmt.Errorf("policy version is required")
	}

	if len(p.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}

	// Validate each rule
	for i, rule := range p.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule %d: name is required", i)
		}
		if rule.Condition.Type == "" {
			return fmt.Errorf("rule %d: condition type is required", i)
		}
		if rule.Action == "" {
			return fmt.Errorf("rule %d: action is required", i)
		}
		if rule.Action != ActionAllow && rule.Action != ActionBlock && rule.Action != ActionAlert {
			return fmt.Errorf("rule %d: invalid action %s", i, rule.Action)
		}
	}

	return nil
}

// Matches checks if a rule matches an event
func (r *Rule) Matches(event any) bool {
	if !r.Enabled {
		return false
	}

	// Try to match based on condition type
	switch r.Condition.Type {
	case "file_access":
		return r.matchFileAccess(event)
	case "pickle_dangerous":
		return r.matchPickleDangerous(event)
	case "network_egress":
		return r.matchNetworkEgress(event)
	case "model_load":
		return r.matchModelLoad(event)
	default:
		return false
	}
}

// matchFileAccess checks if a file access event matches the rule
func (r *Rule) matchFileAccess(event any) bool {
	// Extract event data using reflection or type assertion
	ev, ok := event.(map[string]any)
	if !ok {
		// Try struct-based event
		return r.matchFileAccessStruct(event)
	}

	eventType, _ := ev["type"].(string)
	if eventType != "file_access" && eventType != "file_blocked" {
		return false
	}

	// Check extension match
	if len(r.Condition.Extensions) > 0 {
		ext, _ := ev["extension"].(string)
		if ext == "" {
			if data, ok := ev["data"].(map[string]any); ok {
				ext, _ = data["extension"].(string)
			}
		}
		matched := false
		for _, allowedExt := range r.Condition.Extensions {
			if ext == allowedExt {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check path match
	if len(r.Condition.Paths) > 0 {
		filePath, _ := ev["file_path"].(string)
		if filePath == "" {
			if data, ok := ev["data"].(map[string]any); ok {
				filePath, _ = data["file_path"].(string)
			}
		}
		matched := false
		for _, path := range r.Condition.Paths {
			if len(filePath) >= len(path) && filePath[:len(path)] == path {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// matchFileAccessStruct handles struct-based events
func (r *Rule) matchFileAccessStruct(event any) bool {
	// Use reflection to extract fields
	// This handles the agent.Event struct type
	v := reflect.ValueOf(event)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}

	// Get Type field
	typeField := v.FieldByName("Type")
	if !typeField.IsValid() {
		return false
	}
	eventType := fmt.Sprintf("%v", typeField.Interface())
	if eventType != "file_access" && eventType != "file_blocked" {
		return false
	}

	// Get Data field for extension/path
	dataField := v.FieldByName("Data")
	if !dataField.IsValid() {
		return true // No data to check, type matched
	}

	// Check extension
	if len(r.Condition.Extensions) > 0 {
		extField := dataField.FieldByName("Extension")
		if extField.IsValid() {
			ext := extField.String()
			matched := false
			for _, allowedExt := range r.Condition.Extensions {
				if ext == allowedExt {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	return true
}

// matchPickleDangerous checks for dangerous pickle events
func (r *Rule) matchPickleDangerous(event any) bool {
	ev, ok := event.(map[string]any)
	if ok {
		eventType, _ := ev["type"].(string)
		return eventType == "pickle_dangerous"
	}

	// Struct-based check
	v := reflect.ValueOf(event)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}

	typeField := v.FieldByName("Type")
	if !typeField.IsValid() {
		return false
	}
	return fmt.Sprintf("%v", typeField.Interface()) == "pickle_dangerous"
}

// matchNetworkEgress checks network egress events
func (r *Rule) matchNetworkEgress(event any) bool {
	ev, ok := event.(map[string]any)
	if !ok {
		return r.matchNetworkEgressStruct(event)
	}

	eventType, _ := ev["type"].(string)
	if eventType != "network_allowed" && eventType != "network_blocked" {
		return false
	}

	// Check destination CIDR match
	if len(r.Condition.Destinations) > 0 {
		dstAddr, _ := ev["dst_addr"].(string)
		if dstAddr == "" {
			if data, ok := ev["data"].(map[string]any); ok {
				dstAddr, _ = data["dst_addr"].(string)
			}
		}
		if dstAddr != "" {
			for _, cidr := range r.Condition.Destinations {
				if matchCIDR(dstAddr, cidr) {
					return true
				}
			}
			return false
		}
	}

	return true
}

// matchNetworkEgressStruct handles struct-based network events
func (r *Rule) matchNetworkEgressStruct(event any) bool {
	v := reflect.ValueOf(event)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}

	typeField := v.FieldByName("Type")
	if !typeField.IsValid() {
		return false
	}
	eventType := fmt.Sprintf("%v", typeField.Interface())
	if eventType != "network_allowed" && eventType != "network_blocked" {
		return false
	}

	return true
}

// matchModelLoad checks model load events
func (r *Rule) matchModelLoad(event any) bool {
	ev, ok := event.(map[string]any)
	if ok {
		eventType, _ := ev["type"].(string)
		return eventType == "model_load"
	}

	v := reflect.ValueOf(event)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}

	typeField := v.FieldByName("Type")
	if !typeField.IsValid() {
		return false
	}
	return fmt.Sprintf("%v", typeField.Interface()) == "model_load"
}

// matchCIDR checks if an IP matches a CIDR range
func matchCIDR(ip, cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as plain IP
		return ip == cidr
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return ipNet.Contains(parsedIP)
}

// DefaultPolicy returns the default built-in policy
func DefaultPolicy() *Policy {
	return &Policy{
		Version: "1.0",
		Metadata: PolicyMetadata{
			Name:        "neurosentry-default",
			Description: "Default security policy for AI inference protection",
			Severity:    "medium",
		},
		Rules: []Rule{
			{
				Name:        "block-unauthorized-model-access",
				Description: "Block unauthorized access to model files",
				Enabled:     true,
				Condition: RuleCondition{
					Type:       "file_access",
					Extensions: []string{".safetensors", ".gguf", ".pth", ".pt", ".pkl"},
				},
				Action:   ActionBlock,
				Severity: "high",
				Alert:    true,
			},
			{
				Name:        "block-pickle-bombs",
				Description: "Block dangerous pickle operations",
				Enabled:     true,
				Condition: RuleCondition{
					Type: "pickle_dangerous",
				},
				Action:   ActionBlock,
				Severity: "critical",
				Alert:    true,
			},
			{
				Name:        "allow-k8s-internal",
				Description: "Allow internal Kubernetes traffic",
				Enabled:     true,
				Condition: RuleCondition{
					Type:         "network_egress",
					Destinations: []string{"10.0.0.0/8", "172.16.0.0/12"},
				},
				Action:   ActionAllow,
				Severity: "info",
			},
		},
		Alerts: AlertConfig{
			SilenceSeconds:  300,
			RateLimit:       10,
			RateLimitWindow: "1m",
		},
	}
}

// Evaluate evaluates an event against the policy and returns the action
func (p *Policy) Evaluate(event any) Action {
	for _, rule := range p.Rules {
		if rule.Matches(event) {
			return rule.Action
		}
	}
	return ActionAllow
}
