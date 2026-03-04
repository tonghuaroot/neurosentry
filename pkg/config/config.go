// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config represents the NeuroSentry configuration
type Config struct {
	Protection ProtectionConfig `mapstructure:"protection"`
	Agent      AgentConfig      `mapstructure:"agent"`
	BPF        BPFConfig        `mapstructure:"bpf"`
	PolicyPath string           `mapstructure:"policy_path"`
}

// ProtectionConfig defines which protection modules are enabled
type ProtectionConfig struct {
	ModelFIM            ModelFIMConfig            `mapstructure:"model_fim"`
	NetworkContainment  NetworkContainmentConfig  `mapstructure:"network_containment"`
	PickleProtection    PickleProtectionConfig    `mapstructure:"pickle_protection"`
	PyTorchObservability PyTorchObservabilityConfig `mapstructure:"pytorch_observability"`
}

// ModelFIMConfig configures File Integrity Monitoring for model files
type ModelFIMConfig struct {
	Enabled              bool     `mapstructure:"enabled"`
	ProtectedExtensions  []string `mapstructure:"protected_extensions"`
	ProtectedPaths       []string `mapstructure:"protected_paths"`
	TrustedPIDs          []int    `mapstructure:"trusted_pids"`
	TrustedContainers    []string `mapstructure:"trusted_containers"`
	EnforceMode          bool     `mapstructure:"enforce_mode"`
	LogAllAccess         bool     `mapstructure:"log_all_access"`
	AllowProcessWhitelist bool    `mapstructure:"allow_process_whitelist"`
}

// NetworkContainmentConfig configures XDP-based network filtering
type NetworkContainmentConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	AllowedEgress    []string `mapstructure:"allowed_egress"`
	BlockedIPs       []string `mapstructure:"blocked_ips"`
	BlockExfiltration bool    `mapstructure:"block_exfiltration"`
	ExfilThresholdMB int      `mapstructure:"exfil_threshold_mb"`
	Interfaces       []string `mapstructure:"interfaces"`
	AllowDNS         bool     `mapstructure:"allow_dns"`
}

// PickleProtectionConfig configures pickle bomb protection
type PickleProtectionConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	DangerousSymbols  []string `mapstructure:"dangerous_symbols"`
	BlockOnDetect     bool     `mapstructure:"block_on_detect"`
	StackTraceDepth   int      `mapstructure:"stack_trace_depth"`
}

// PyTorchObservabilityConfig configures PyTorch runtime monitoring
type PyTorchObservabilityConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	LibtorchPath      string   `mapstructure:"libtorch_path"`
	MonitorModelLoads bool     `mapstructure:"monitor_model_loads"`
	CalculateHashes   bool     `mapstructure:"calculate_hashes"`
}

// AgentConfig configures the user-space agent
type AgentConfig struct {
	MetricsPort       int      `mapstructure:"metrics_port"`
	LogLevel          string   `mapstructure:"log_level"`
	LogFormat         string   `mapstructure:"log_format"`
	AlertWebhook      string   `mapstructure:"alert_webhook"`
	AlertSilenceSec   int      `mapstructure:"alert_silence_sec"`
	KubernetesEnabled bool     `mapstructure:"kubernetes_enabled"`
	KubeletPath       string   `mapstructure:"kubelet_path"`
	EventSampleRate   float64  `mapstructure:"event_sample_rate"`   // 0.0-1.0, 1.0 = no sampling
	EventBufferSize   int      `mapstructure:"event_buffer_size"`   // Event channel buffer size
}

// BPFConfig configures eBPF program behavior
type BPFConfig struct {
	LogLevel          int      `mapstructure:"log_level"`
	RingBufferSizeKB  int      `mapstructure:"ring_buffer_size_kb"`
	PerCPUMapSize     int      `mapstructure:"per_cpu_map_size"`
	VerifierLogLevel  int      `mapstructure:"verifier_log_level"`
	DisableCORE       bool     `mapstructure:"disable_core"`
}

// Default returns the default configuration
func Default() *Config {
	return &Config{
		Protection: ProtectionConfig{
			ModelFIM: ModelFIMConfig{
				Enabled:             true,
				ProtectedExtensions: []string{".safetensors", ".gguf", ".pth", ".pt", ".pkl"},
				EnforceMode:         true,
				LogAllAccess:        false,
			},
			NetworkContainment: NetworkContainmentConfig{
				Enabled:          true,
				AllowedEgress:    []string{"10.0.0.0/8", "172.16.0.0/12"},
				BlockExfiltration: true,
				ExfilThresholdMB: 100,
				AllowDNS:         true,
			},
			PickleProtection: PickleProtectionConfig{
				Enabled:       true,
				DangerousSymbols: []string{"os.system", "eval", "exec", "__import__", "subprocess"},
				BlockOnDetect:  true,
			},
			PyTorchObservability: PyTorchObservabilityConfig{
				Enabled:           true,
				MonitorModelLoads:  true,
				CalculateHashes:    false,
			},
		},
		Agent: AgentConfig{
			MetricsPort:       2112,
			LogLevel:          "info",
			LogFormat:         "json",
			AlertSilenceSec:   300,
			KubernetesEnabled: true,
			EventSampleRate:   1.0, // No sampling by default
			EventBufferSize:   1000,
		},
		BPF: BPFConfig{
			RingBufferSizeKB: 256,
			PerCPUMapSize:     1024,
		},
		PolicyPath: "/etc/neurosentry/policy.yaml",
	}
}

// Load loads configuration from a file
func Load(path string) (*Config, error) {
	v := viper.New()

	// Set defaults
	cfg := Default()
	setDefaults(v, cfg)

	// Read from file if provided
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			v.SetConfigFile(path)
			v.SetConfigType("yaml")
			if err := v.ReadInConfig(); err != nil {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		}
	}

	// Apply environment variable overrides
	v.SetEnvPrefix("NEUROSENTRY")
	v.AutomaticEnv()

	// Unmarshal into config
	var result Config
	if err := v.Unmarshal(&result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate
	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &result, nil
}

func setDefaults(v *viper.Viper, cfg *Config) {
	v.SetDefault("protection.model_fim.enabled", cfg.Protection.ModelFIM.Enabled)
	v.SetDefault("protection.model_fim.protected_extensions", cfg.Protection.ModelFIM.ProtectedExtensions)
	v.SetDefault("protection.model_fim.enforce_mode", cfg.Protection.ModelFIM.EnforceMode)
	v.SetDefault("protection.network_containment.enabled", cfg.Protection.NetworkContainment.Enabled)
	v.SetDefault("protection.network_containment.block_exfiltration", cfg.Protection.NetworkContainment.BlockExfiltration)
	v.SetDefault("protection.network_containment.exfil_threshold_mb", cfg.Protection.NetworkContainment.ExfilThresholdMB)
	v.SetDefault("protection.pickle_protection.enabled", cfg.Protection.PickleProtection.Enabled)
	v.SetDefault("protection.pytorch_observability.enabled", cfg.Protection.PyTorchObservability.Enabled)
	v.SetDefault("agent.metrics_port", cfg.Agent.MetricsPort)
	v.SetDefault("agent.log_level", cfg.Agent.LogLevel)
	v.SetDefault("policy_path", cfg.PolicyPath)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Agent.MetricsPort < 1 || c.Agent.MetricsPort > 65535 {
		return fmt.Errorf("invalid metrics port: %d", c.Agent.MetricsPort)
	}

	if c.Protection.NetworkContainment.BlockExfiltration {
		if c.Protection.NetworkContainment.ExfilThresholdMB < 1 {
			return fmt.Errorf("exfil threshold must be positive")
		}
	}

	if c.Protection.ModelFIM.Enabled && len(c.Protection.ModelFIM.ProtectedExtensions) == 0 {
		return fmt.Errorf("model FIM enabled but no protected extensions specified")
	}

	// Validate event sampling rate
	if c.Agent.EventSampleRate < 0 || c.Agent.EventSampleRate > 1.0 {
		return fmt.Errorf("event_sample_rate must be between 0.0 and 1.0, got: %f", c.Agent.EventSampleRate)
	}

	// Validate event buffer size
	if c.Agent.EventBufferSize < 100 {
		c.Agent.EventBufferSize = 100 // Minimum buffer size
	}

	return nil
}

// IsModelProtected checks if a file extension is in the protected list
func (c *Config) IsModelProtected(ext string) bool {
	for _, protected := range c.Protection.ModelFIM.ProtectedExtensions {
		if ext == protected {
			return true
		}
	}
	return false
}
