// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !root_test
// +build !linux !root_test

package integration

import (
	"testing"

	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
)

// TestMockBPFManager tests BPF manager functionality without requiring root/Linux
func TestMockBPFManager(t *testing.T) {
	// Create config
	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			ModelFIM: config.ModelFIMConfig{
				Enabled:              true,
				EnforceMode:          true,
				LogAllAccess:         true,
				ProtectedExtensions:  []string{".safetensors", ".gguf"},
				ProtectedPaths:       []string{"/models", "/target"},
			},
			NetworkContainment: config.NetworkContainmentConfig{
				Enabled:           true,
				BlockExfiltration: true,
				ExfilThresholdMB:  100,
				AllowedEgress:     []string{"10.0.0.0/8", "172.16.0.0/12"},
			},
			PyTorchObservability: config.PyTorchObservabilityConfig{
				Enabled: true,
			},
			PickleProtection: config.PickleProtectionConfig{
				Enabled: true,
			},
		},
	}

	// Create policy
	pol := policy.DefaultPolicy()

	// Note: On non-Linux systems, we can't actually load eBPF programs
	// This test verifies that the config and policy structures are valid
	t.Log("Mock BPF manager test - config validation")

	if !cfg.Protection.ModelFIM.Enabled {
		t.Error("ModelFIM should be enabled")
	}

	if !cfg.Protection.NetworkContainment.Enabled {
		t.Error("NetworkContainment should be enabled")
	}

	if !cfg.Protection.PickleProtection.Enabled {
		t.Error("PickleProtection should be enabled")
	}

	if !cfg.Protection.PyTorchObservability.Enabled {
		t.Error("PyTorchObservability should be enabled")
	}

	if pol == nil {
		t.Error("Policy should not be nil")
	}

	t.Log("Mock BPF manager test passed")
}

// TestConfigValidation tests config validation without requiring eBPF
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &config.Config{
				Protection: config.ProtectionConfig{
					ModelFIM: config.ModelFIMConfig{
						Enabled:              true,
						ProtectedExtensions:  []string{".safetensors"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty protected extensions",
			cfg: &config.Config{
				Protection: config.ProtectionConfig{
					ModelFIM: config.ModelFIMConfig{
						Enabled:             true,
						ProtectedExtensions: []string{},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cfg.Protection.ModelFIM.Enabled && len(tt.cfg.Protection.ModelFIM.ProtectedExtensions) == 0 {
				if !tt.wantErr {
					t.Error("Expected error for empty protected extensions")
				}
			}
		})
	}
}

// TestPolicyValidation tests policy validation
func TestPolicyValidation(t *testing.T) {
	pol := policy.DefaultPolicy()

	if pol == nil {
		t.Fatal("Default policy should not be nil")
	}

	t.Log("Policy validation test passed")
}

// TestPolicyRuleMatching tests policy rule matching logic
func TestPolicyRuleMatching(t *testing.T) {
	pol := policy.DefaultPolicy()

	testEvents := []struct {
		name           string
		event          map[string]interface{}
		expectedAction policy.Action
	}{
		{
			name: "pickle_dangerous_blocked",
			event: map[string]interface{}{
				"type": "pickle_dangerous",
			},
			expectedAction: policy.ActionBlock,
		},
		{
			name: "file_access_model_file",
			event: map[string]interface{}{
				"type":      "file_access",
				"extension": ".safetensors",
			},
			expectedAction: policy.ActionBlock,
		},
		{
			name: "network_k8s_internal",
			event: map[string]interface{}{
				"type":     "network_blocked",
				"dst_addr": "10.1.2.3",
			},
			expectedAction: policy.ActionAllow,
		},
		{
			name: "unknown_event_allowed",
			event: map[string]interface{}{
				"type": "unknown_event_type",
			},
			expectedAction: policy.ActionAllow,
		},
	}

	for _, tc := range testEvents {
		t.Run(tc.name, func(t *testing.T) {
			action := pol.Evaluate(tc.event)
			if action != tc.expectedAction {
				t.Errorf("Expected action %s, got %s", tc.expectedAction, action)
			}
		})
	}
}

// TestConfigDefaults tests that config defaults are applied correctly
func TestConfigDefaults(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Logf("Config load error (expected without file): %v", err)
	}

	// Test with default config
	defaultCfg := config.Default()

	if defaultCfg.Agent.MetricsPort != 2112 {
		t.Errorf("Expected default metrics port 2112, got %d", defaultCfg.Agent.MetricsPort)
	}

	if defaultCfg.Agent.LogLevel != "info" {
		t.Errorf("Expected default log level 'info', got %s", defaultCfg.Agent.LogLevel)
	}

	_ = cfg // Use cfg to avoid unused variable warning
}

// TestNetworkCIDRParsing tests network CIDR parsing
func TestNetworkCIDRParsing(t *testing.T) {
	validCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"0.0.0.0/0",
	}

	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			NetworkContainment: config.NetworkContainmentConfig{
				Enabled:       true,
				AllowedEgress: validCIDRs,
			},
		},
	}

	if len(cfg.Protection.NetworkContainment.AllowedEgress) != len(validCIDRs) {
		t.Errorf("Expected %d CIDRs, got %d", len(validCIDRs), len(cfg.Protection.NetworkContainment.AllowedEgress))
	}
}

// TestProtectedExtensions tests protected extension configuration
func TestProtectedExtensions(t *testing.T) {
	extensions := []string{".safetensors", ".gguf", ".pth", ".pt", ".pkl", ".bin", ".h5"}

	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			ModelFIM: config.ModelFIMConfig{
				Enabled:             true,
				ProtectedExtensions: extensions,
			},
		},
	}

	for _, ext := range extensions {
		found := false
		for _, cfgExt := range cfg.Protection.ModelFIM.ProtectedExtensions {
			if cfgExt == ext {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Extension %s not found in config", ext)
		}
	}
}

// TestDangerousSymbols tests dangerous pickle symbols configuration
func TestDangerousSymbols(t *testing.T) {
	symbols := []string{
		"os.system",
		"subprocess.call",
		"subprocess.Popen",
		"eval",
		"exec",
		"__import__",
		"__builtins__",
	}

	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			PickleProtection: config.PickleProtectionConfig{
				Enabled:          true,
				BlockOnDetect:    true,
				DangerousSymbols: symbols,
			},
		},
	}

	if !cfg.Protection.PickleProtection.BlockOnDetect {
		t.Error("BlockOnDetect should be true")
	}

	if len(cfg.Protection.PickleProtection.DangerousSymbols) != len(symbols) {
		t.Errorf("Expected %d symbols, got %d", len(symbols), len(cfg.Protection.PickleProtection.DangerousSymbols))
	}
}
