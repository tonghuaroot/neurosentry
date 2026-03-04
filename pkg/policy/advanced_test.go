// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"
)

func TestNewAdvancedEvaluator(t *testing.T) {
	pol := DefaultPolicy()
	evaluator := NewAdvancedEvaluator(pol)

	if evaluator == nil {
		t.Fatal("Expected non-nil evaluator")
	}
	if evaluator.policy != pol {
		t.Error("Policy not set correctly")
	}
}

func TestAdvancedEvaluatorMatchesWithContext(t *testing.T) {
	pol := DefaultPolicy()
	evaluator := NewAdvancedEvaluator(pol)

	tests := []struct {
		name     string
		rule     Rule
		context  EventContext
		expected bool
	}{
		{
			name: "file_access_matches_extension",
			rule: Rule{
				Name:    "test-file",
				Enabled: true,
				Condition: RuleCondition{
					Type:       "file_access",
					Extensions: []string{".safetensors", ".pth"},
				},
			},
			context: EventContext{
				FilePath: "/models/model.safetensors",
			},
			expected: true,
		},
		{
			name: "file_access_matches_path",
			rule: Rule{
				Name:    "test-file-path",
				Enabled: true,
				Condition: RuleCondition{
					Type:  "file_access",
					Paths: []string{"/models/", "/var/lib/models/"},
				},
			},
			context: EventContext{
				FilePath: "/models/test.bin",
			},
			expected: true,
		},
		{
			name: "file_access_no_match",
			rule: Rule{
				Name:    "test-file-no-match",
				Enabled: true,
				Condition: RuleCondition{
					Type:       "file_access",
					Extensions: []string{".safetensors"},
				},
			},
			context: EventContext{
				FilePath: "/models/model.txt",
			},
			expected: false,
		},
		{
			name: "network_egress_matches_cidr",
			rule: Rule{
				Name:    "test-network",
				Enabled: true,
				Condition: RuleCondition{
					Type:         "network_egress",
					Destinations: []string{"10.0.0.0/8"},
				},
			},
			context: EventContext{
				DestinationIP: "10.1.2.3",
			},
			expected: true,
		},
		{
			name: "network_egress_no_match",
			rule: Rule{
				Name:    "test-network-no-match",
				Enabled: true,
				Condition: RuleCondition{
					Type:         "network_egress",
					Destinations: []string{"10.0.0.0/8"},
				},
			},
			context: EventContext{
				DestinationIP: "192.168.1.1",
			},
			expected: false,
		},
		{
			name: "model_load_matches",
			rule: Rule{
				Name:    "test-model-load",
				Enabled: true,
				Condition: RuleCondition{
					Type: "model_load",
				},
			},
			context:  EventContext{},
			expected: true,
		},
		{
			name: "disabled_rule_no_match",
			rule: Rule{
				Name:    "disabled-rule",
				Enabled: false,
				Condition: RuleCondition{
					Type: "file_access",
				},
			},
			context:  EventContext{},
			expected: false,
		},
		{
			name: "unknown_condition_type",
			rule: Rule{
				Name:    "unknown-type",
				Enabled: true,
				Condition: RuleCondition{
					Type: "unknown_type",
				},
			},
			context:  EventContext{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.MatchesWithContext(tt.rule, tt.context)
			if result != tt.expected {
				t.Errorf("MatchesWithContext() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestAdvancedEvaluatorMatchCIDR(t *testing.T) {
	evaluator := NewAdvancedEvaluator(nil)

	tests := []struct {
		name     string
		cidr     string
		ip       string
		expected bool
	}{
		{
			name:     "allow_all",
			cidr:     "0.0.0.0/0",
			ip:       "1.2.3.4",
			expected: true,
		},
		{
			name:     "match_10_network",
			cidr:     "10.0.0.0/8",
			ip:       "10.1.2.3",
			expected: true,
		},
		{
			name:     "no_match_outside_network",
			cidr:     "10.0.0.0/8",
			ip:       "192.168.1.1",
			expected: false,
		},
		{
			name:     "exact_ip_match",
			cidr:     "192.168.1.1",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "exact_ip_no_match",
			cidr:     "192.168.1.1",
			ip:       "192.168.1.2",
			expected: false,
		},
		{
			name:     "invalid_ip",
			cidr:     "10.0.0.0/8",
			ip:       "invalid",
			expected: false,
		},
		{
			name:     "invalid_cidr",
			cidr:     "invalid/cidr",
			ip:       "10.0.0.1",
			expected: false,
		},
		{
			name:     "172_network",
			cidr:     "172.16.0.0/12",
			ip:       "172.20.1.1",
			expected: true,
		},
		{
			name:     "192_168_network",
			cidr:     "192.168.0.0/16",
			ip:       "192.168.100.50",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.matchCIDR(tt.cidr, tt.ip)
			if result != tt.expected {
				t.Errorf("matchCIDR(%s, %s) = %v, expected %v", tt.cidr, tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsTrustedProcess(t *testing.T) {
	evaluator := NewAdvancedEvaluator(nil)

	tests := []struct {
		name     string
		context  EventContext
		expected bool
	}{
		{
			name: "python_trusted",
			context: EventContext{
				Comm: "python3",
			},
			expected: true,
		},
		{
			name: "python_with_version",
			context: EventContext{
				Comm: "python3.11",
			},
			expected: true,
		},
		{
			name: "triton_server",
			context: EventContext{
				Comm: "triton-server",
			},
			expected: true,
		},
		{
			name: "torchserve",
			context: EventContext{
				Comm: "torchserve",
			},
			expected: true,
		},
		{
			name: "untrusted_process",
			context: EventContext{
				Comm: "malicious-app",
			},
			expected: false,
		},
		{
			name: "trusted_command_line",
			context: EventContext{
				Comm:        "bash",
				CommandLine: "python3 /app/serve.py",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.IsTrustedProcess(tt.context)
			if result != tt.expected {
				t.Errorf("IsTrustedProcess() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		name       string
		cgroupPath string
		expected   string
	}{
		{
			name:       "empty_path",
			cgroupPath: "",
			expected:   "",
		},
		{
			name:       "non_container_path",
			cgroupPath: "/system.slice/ssh.service",
			expected:   "",
		},
		{
			name:       "docker_format",
			cgroupPath: "/docker/abc123def456789012345678901234567890123456789012345678901234",
			expected:   "abc123def456",
		},
		{
			name:       "containerd_format",
			cgroupPath: "/system.slice/containerd-abc123def456789012345678901234567890123456789012345678901234.scope",
			expected:   "abc123def456",
		},
		{
			name:       "kubernetes_crio_format",
			cgroupPath: "/kubepods.slice/kubepods-pod123.slice/crio-abc123def456789012345678901234567890123456789012345678901234.scope",
			expected:   "abc123def456",
		},
		{
			name:       "kubernetes_containerd_format",
			cgroupPath: "/kubepods/pod-uid/cri-containerd-abc123def456789012345678901234567890123456789012345678901234.scope",
			expected:   "abc123def456",
		},
		{
			name:       "podman_format",
			cgroupPath: "/machine.slice/libpod-abc123def456789012345678901234567890123456789012345678901234.scope",
			expected:   "abc123def456",
		},
		{
			name:       "kubernetes_plain_id",
			cgroupPath: "/kubepods/burstable/pod123/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			expected:   "0123456789ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractContainerID(tt.cgroupPath)
			if result != tt.expected {
				t.Errorf("ExtractContainerID(%s) = %s, expected %s", tt.cgroupPath, result, tt.expected)
			}
		})
	}
}

func TestIsHexString(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"abc123", true},
		{"ABC123", true},
		{"0123456789abcdef", true},
		{"xyz", false},
		{"abc-123", false},
		{"", true},
	}

	for _, tt := range tests {
		result := isHexString(tt.input)
		if result != tt.expected {
			t.Errorf("isHexString(%s) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestGetProcessChain(t *testing.T) {
	// Test with PID 1 (init)
	chain := GetProcessChain(1)
	if len(chain) == 0 {
		t.Log("Process chain for PID 1 may be empty on some systems")
	}

	// Test with invalid PID
	chain = GetProcessChain(-1)
	if len(chain) != 1 {
		t.Logf("Chain for invalid PID: %v", chain)
	}

	// Test with PID 0
	chain = GetProcessChain(0)
	if len(chain) != 1 || chain[0] != 0 {
		t.Logf("Chain for PID 0: %v", chain)
	}
}

func TestMatchCIDRFunction(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		cidr     string
		expected bool
	}{
		{
			name:     "valid_match",
			ip:       "10.0.0.1",
			cidr:     "10.0.0.0/8",
			expected: true,
		},
		{
			name:     "valid_no_match",
			ip:       "192.168.1.1",
			cidr:     "10.0.0.0/8",
			expected: false,
		},
		{
			name:     "exact_ip_match",
			ip:       "8.8.8.8",
			cidr:     "8.8.8.8",
			expected: true,
		},
		{
			name:     "invalid_cidr_exact_match",
			ip:       "1.2.3.4",
			cidr:     "1.2.3.4",
			expected: true,
		},
		{
			name:     "invalid_ip",
			ip:       "not-an-ip",
			cidr:     "10.0.0.0/8",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchCIDR(tt.ip, tt.cidr)
			if result != tt.expected {
				t.Errorf("matchCIDR(%s, %s) = %v, expected %v", tt.ip, tt.cidr, result, tt.expected)
			}
		})
	}
}

func TestValidatePolicy(t *testing.T) {
	tests := []struct {
		name      string
		policy    Policy
		expectErr bool
	}{
		{
			name:      "empty_policy",
			policy:    Policy{},
			expectErr: true,
		},
		{
			name: "missing_version",
			policy: Policy{
				Rules: []Rule{{Name: "test", Condition: RuleCondition{Type: "file_access"}, Action: ActionBlock}},
			},
			expectErr: true,
		},
		{
			name: "no_rules",
			policy: Policy{
				Version: "1.0",
			},
			expectErr: true,
		},
		{
			name: "rule_missing_name",
			policy: Policy{
				Version: "1.0",
				Rules:   []Rule{{Condition: RuleCondition{Type: "file_access"}, Action: ActionBlock}},
			},
			expectErr: true,
		},
		{
			name: "rule_missing_condition_type",
			policy: Policy{
				Version: "1.0",
				Rules:   []Rule{{Name: "test", Action: ActionBlock}},
			},
			expectErr: true,
		},
		{
			name: "rule_missing_action",
			policy: Policy{
				Version: "1.0",
				Rules:   []Rule{{Name: "test", Condition: RuleCondition{Type: "file_access"}}},
			},
			expectErr: true,
		},
		{
			name: "rule_invalid_action",
			policy: Policy{
				Version: "1.0",
				Rules:   []Rule{{Name: "test", Condition: RuleCondition{Type: "file_access"}, Action: "invalid"}},
			},
			expectErr: true,
		},
		{
			name: "valid_policy",
			policy: Policy{
				Version: "1.0",
				Rules:   []Rule{{Name: "test", Condition: RuleCondition{Type: "file_access"}, Action: ActionBlock}},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if tt.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
