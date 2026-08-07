// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"testing"
)

func TestNewLoader(t *testing.T) {
	// Test with default (builtin) loader
	loader, err := NewLoader("")
	if err != nil {
		t.Fatalf("Failed to create loader: %v", err)
	}
	if loader == nil {
		t.Fatal("Loader is nil")
	}
}

func TestLoad(t *testing.T) {
	// Test loading builtin policy
	loader, _ := NewLoader("")
	pol, err := loader.Load()
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	if pol == nil {
		t.Fatal("Policy is nil")
	}
	if pol.Version == "" {
		t.Error("Policy version is empty")
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create test policy file
	tmpfile, err := os.CreateTemp("", "policy*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	content := `
version: "1.0"
metadata:
  name: "test-policy"
rules:
  - name: "test-rule"
    enabled: true
    condition:
      type: "file_access"
    action: "allow"
`
	if _, err := tmpfile.WriteString(content); err != nil {
		t.Fatal(err)
	}

	loader, err := NewLoader(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to create loader: %v", err)
	}

	pol, err := loader.Load()
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	if len(pol.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(pol.Rules))
	}
}

func TestValidate(t *testing.T) {
	// Test invalid policy
	pol := &Policy{}
	if err := pol.Validate(); err == nil {
		t.Error("Empty policy should fail validation")
	}

	// Test valid policy
	pol = DefaultPolicy()
	if err := pol.Validate(); err != nil {
		t.Errorf("Default policy should be valid: %v", err)
	}
}

func TestRuleMatches(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		event    any
		expected bool
	}{
		{
			name: "file_access_match_with_extension",
			rule: Rule{
				Name:    "test-rule",
				Enabled: true,
				Condition: RuleCondition{
					Type:       "file_access",
					Extensions: []string{".pth", ".safetensors"},
				},
				Action: ActionBlock,
			},
			event: map[string]any{
				"type":      "file_access",
				"extension": ".pth",
			},
			expected: true,
		},
		{
			name: "file_access_no_match_wrong_extension",
			rule: Rule{
				Name:    "test-rule",
				Enabled: true,
				Condition: RuleCondition{
					Type:       "file_access",
					Extensions: []string{".pth", ".safetensors"},
				},
				Action: ActionBlock,
			},
			event: map[string]any{
				"type":      "file_access",
				"extension": ".txt",
			},
			expected: false,
		},
		{
			name: "disabled_rule_no_match",
			rule: Rule{
				Name:    "test-rule",
				Enabled: false,
				Condition: RuleCondition{
					Type: "file_access",
				},
				Action: ActionBlock,
			},
			event: map[string]any{
				"type": "file_access",
			},
			expected: false,
		},
		{
			name: "pickle_dangerous_match",
			rule: Rule{
				Name:    "pickle-rule",
				Enabled: true,
				Condition: RuleCondition{
					Type: "pickle_dangerous",
				},
				Action: ActionBlock,
			},
			event: map[string]any{
				"type": "pickle_dangerous",
			},
			expected: true,
		},
		{
			name: "network_egress_match",
			rule: Rule{
				Name:    "network-rule",
				Enabled: true,
				Condition: RuleCondition{
					Type:         "network_egress",
					Destinations: []string{"10.0.0.0/8"},
				},
				Action: ActionAllow,
			},
			event: map[string]any{
				"type":     "network_blocked",
				"dst_addr": "10.1.2.3",
			},
			expected: true,
		},
		{
			name: "network_egress_no_match_outside_cidr",
			rule: Rule{
				Name:    "network-rule",
				Enabled: true,
				Condition: RuleCondition{
					Type:         "network_egress",
					Destinations: []string{"10.0.0.0/8"},
				},
				Action: ActionAllow,
			},
			event: map[string]any{
				"type":     "network_blocked",
				"dst_addr": "192.168.1.1",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Matches(tt.event)
			if result != tt.expected {
				t.Errorf("Rule.Matches() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestPolicyEvaluate(t *testing.T) {
	pol := DefaultPolicy()

	// Test pickle_dangerous event matches block rule
	event := map[string]any{
		"type": "pickle_dangerous",
	}
	action := pol.Evaluate(event)
	if action != ActionBlock {
		t.Errorf("Expected ActionBlock for pickle_dangerous, got %v", action)
	}

	// Test unknown event type defaults to allow
	unknownEvent := map[string]any{
		"type": "unknown_event",
	}
	action = pol.Evaluate(unknownEvent)
	if action != ActionAllow {
		t.Errorf("Expected ActionAllow for unknown event, got %v", action)
	}
}
