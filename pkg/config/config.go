// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config represents the NeuroSentry configuration
type Config struct {
	Protection  ProtectionConfig  `mapstructure:"protection"`
	Agent       AgentConfig       `mapstructure:"agent"`
	BPF         BPFConfig         `mapstructure:"bpf"`
	Sandbox     SandboxConfig     `mapstructure:"sandbox"`
	MCP         MCPConfig         `mapstructure:"mcp"`
	Audit       AuditConfig       `mapstructure:"audit"`
	Web         WebConfig         `mapstructure:"web"`
	Platform    PlatformConfig    `mapstructure:"platform"`
	Notify      NotifyConfig      `mapstructure:"notify"`
	Gateway     GatewayConfig     `mapstructure:"gateway"`
	Fleet       FleetConfig       `mapstructure:"fleet"`
	Breaker     BreakerConfig     `mapstructure:"breaker"`
	SelfProtect SelfProtectConfig `mapstructure:"self_protect"`
	PolicyPath  string            `mapstructure:"policy_path"`
	// ConfigPath is the file this config was loaded from (set by the loader),
	// so self-protection can baseline it. Not a YAML field.
	ConfigPath string `mapstructure:"-"`
}

// SelfProtectConfig configures agent anti-tamper self-defense (integrity
// baseline over the agent binary + config, periodically re-verified).
type SelfProtectConfig struct {
	Enabled      bool `mapstructure:"enabled"`
	IntervalSecs int  `mapstructure:"interval_secs"` // re-verify cadence (default 60)
}

// BreakerConfig configures the automated circuit breaker (detection -> auto
// enforcement). DISARMED by default; enable deliberately.
type BreakerConfig struct {
	Enabled       bool    `mapstructure:"enabled"`
	MinSeverity   string  `mapstructure:"min_severity"`   // trip at/above (default critical)
	DefaultAction string  `mapstructure:"default_action"` // response action (default untrust_pid)
	CooldownSecs  float64 `mapstructure:"cooldown_secs"`  // per-pid anti-storm (default 60)
}

// FleetConfig configures at-scale control-plane participation.
type FleetConfig struct {
	// Enabled hosts the fleet registry on this node's web API (control plane).
	Enabled     bool   `mapstructure:"enabled"`
	EnrollToken string `mapstructure:"enroll_token"` // shared bearer token for agent enroll/heartbeat
	// HeartbeatSecs is how often this node reports its own health (default 30s).
	HeartbeatSecs int `mapstructure:"heartbeat_secs"`

	// MTLSEnabled serves the agent-facing endpoints (enroll/heartbeat) on a
	// dedicated mutual-TLS listener, so agents authenticate with a client
	// certificate (not just the shared token). MTLSListen is the address
	// (default :9443); PKIDir holds ca/server/client certs — auto-generated
	// there for demos when absent.
	MTLSEnabled bool   `mapstructure:"mtls_enabled"`
	MTLSListen  string `mapstructure:"mtls_listen"`
	PKIDir      string `mapstructure:"pki_dir"`
}

// SandboxConfig configures Landlock-based process sandboxing
type SandboxConfig struct {
	Enabled        bool     `mapstructure:"enabled"`
	ReadOnlyPaths  []string `mapstructure:"read_only_paths"`
	ReadWritePaths []string `mapstructure:"read_write_paths"`
	DenyPaths      []string `mapstructure:"deny_paths"`
}

// MCPConfig configures MCP protocol interception
type MCPConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	ListenAddr   string   `mapstructure:"listen_addr"`
	UpstreamAddr string   `mapstructure:"upstream_addr"`
	AllowedTools []string `mapstructure:"allowed_tools"`
	BlockedTools []string `mapstructure:"blocked_tools"`
	LogToolCalls bool     `mapstructure:"log_tool_calls"`
}

// AuditConfig configures tamper-proof audit logging
type AuditConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	LogPath   string `mapstructure:"log_path"`
	MaxSizeMB int    `mapstructure:"max_size_mb"`
	// DBDriver selects the durable audit store backend: "sqlite" (default,
	// embedded, CGO-free) or "postgres" (production/HA). Aliases "pg" and
	// "postgresql" are accepted.
	DBDriver string `mapstructure:"db_driver"`
	// DBPath is the SQLite database file path (used when DBDriver is sqlite).
	// When set, every audit entry is persisted (surviving restart and the
	// in-memory ring) and the trail becomes queryable at volume for
	// retention/compliance.
	DBPath string `mapstructure:"db_path"`
	// DBDSN is the Postgres connection string (used when DBDriver is postgres),
	// e.g. "postgres://user:pass@host:5432/neurosentry?sslmode=require".
	DBDSN string `mapstructure:"db_dsn"`
}

// WebConfig configures the web dashboard
type WebConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	ListenAddr string `mapstructure:"listen_addr"`
}

// GatewayConfig configures the inline AI gateway (OpenAI-compatible relay).
type GatewayConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	ListenAddr       string   `mapstructure:"listen_addr"`
	BlockOnDetect    bool     `mapstructure:"block_on_detect"`
	AllowedProviders []string `mapstructure:"allowed_providers"`
	DefaultProvider  string   `mapstructure:"default_provider"`
}

// NotifyConfig configures outbound alert notification channels.
type NotifyConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	WebhookURL   string `mapstructure:"webhook_url"`
	SlackWebhook string `mapstructure:"slack_webhook"`
	MinSeverity  string `mapstructure:"min_severity"` // info|low|medium|high|critical (default high)
	// Splunk HTTP Event Collector (real-time SIEM streaming).
	SplunkHECURL   string `mapstructure:"splunk_hec_url"`
	SplunkHECToken string `mapstructure:"splunk_hec_token"`
	SplunkIndex    string `mapstructure:"splunk_index"`
	// Microsoft Sentinel (Log Analytics HTTP Data Collector API).
	SentinelWorkspaceID string `mapstructure:"sentinel_workspace_id"`
	SentinelSharedKey   string `mapstructure:"sentinel_shared_key"`
	SentinelLogType     string `mapstructure:"sentinel_log_type"`
}

// PlatformConfig configures the multi-tenant control plane (identity, RBAC).
type PlatformConfig struct {
	Enabled           bool   `mapstructure:"enabled"`
	SnapshotPath      string `mapstructure:"snapshot_path"`
	JWTSecret         string `mapstructure:"jwt_secret"`         // if empty, a random key is generated at boot
	BootstrapTenant   string `mapstructure:"bootstrap_tenant"`   // default tenant slug created on first boot
	BootstrapEmail    string `mapstructure:"bootstrap_email"`    // default admin email
	BootstrapPassword string `mapstructure:"bootstrap_password"` // if empty, a random password is generated and logged once
}

// ProtectionConfig defines which protection modules are enabled
type ProtectionConfig struct {
	ModelFIM             ModelFIMConfig             `mapstructure:"model_fim"`
	NetworkContainment   NetworkContainmentConfig   `mapstructure:"network_containment"`
	PickleProtection     PickleProtectionConfig     `mapstructure:"pickle_protection"`
	PyTorchObservability PyTorchObservabilityConfig `mapstructure:"pytorch_observability"`
}

// ModelFIMConfig configures File Integrity Monitoring for model files
type ModelFIMConfig struct {
	Enabled               bool     `mapstructure:"enabled"`
	ProtectedExtensions   []string `mapstructure:"protected_extensions"`
	ProtectedPaths        []string `mapstructure:"protected_paths"`
	TrustedPIDs           []int    `mapstructure:"trusted_pids"`
	TrustedContainers     []string `mapstructure:"trusted_containers"`
	EnforceMode           bool     `mapstructure:"enforce_mode"`
	LogAllAccess          bool     `mapstructure:"log_all_access"`
	AllowProcessWhitelist bool     `mapstructure:"allow_process_whitelist"`
}

// NetworkContainmentConfig configures XDP-based network filtering
type NetworkContainmentConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	AllowedEgress     []string `mapstructure:"allowed_egress"`
	BlockedIPs        []string `mapstructure:"blocked_ips"`
	BlockExfiltration bool     `mapstructure:"block_exfiltration"`
	ExfilThresholdMB  int      `mapstructure:"exfil_threshold_mb"`
	Interfaces        []string `mapstructure:"interfaces"`
	AllowDNS          bool     `mapstructure:"allow_dns"`
}

// PickleProtectionConfig configures pickle bomb protection
type PickleProtectionConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	DangerousSymbols []string `mapstructure:"dangerous_symbols"`
	BlockOnDetect    bool     `mapstructure:"block_on_detect"`
	StackTraceDepth  int      `mapstructure:"stack_trace_depth"`
}

// PyTorchObservabilityConfig configures PyTorch runtime monitoring
type PyTorchObservabilityConfig struct {
	Enabled           bool   `mapstructure:"enabled"`
	LibtorchPath      string `mapstructure:"libtorch_path"`
	MonitorModelLoads bool   `mapstructure:"monitor_model_loads"`
	CalculateHashes   bool   `mapstructure:"calculate_hashes"`
}

// AgentConfig configures the user-space agent
type AgentConfig struct {
	MetricsPort       int     `mapstructure:"metrics_port"`
	LogLevel          string  `mapstructure:"log_level"`
	LogFormat         string  `mapstructure:"log_format"`
	AlertWebhook      string  `mapstructure:"alert_webhook"`
	AlertSilenceSec   int     `mapstructure:"alert_silence_sec"`
	KubernetesEnabled bool    `mapstructure:"kubernetes_enabled"`
	KubeletPath       string  `mapstructure:"kubelet_path"`
	EventSampleRate   float64 `mapstructure:"event_sample_rate"` // 0.0-1.0, 1.0 = no sampling
	EventBufferSize   int     `mapstructure:"event_buffer_size"` // Event channel buffer size
	// PIDPruneInterval controls how often the controller scans the
	// trusted_pids BPF map and removes entries whose process no longer
	// exists in /proc. Closes the PID-recycle TOCTOU window. Default 30s.
	PIDPruneInterval time.Duration `mapstructure:"pid_prune_interval"`
}

// BPFConfig configures eBPF program behavior
type BPFConfig struct {
	LogLevel         int  `mapstructure:"log_level"`
	RingBufferSizeKB int  `mapstructure:"ring_buffer_size_kb"`
	PerCPUMapSize    int  `mapstructure:"per_cpu_map_size"`
	VerifierLogLevel int  `mapstructure:"verifier_log_level"`
	DisableCORE      bool `mapstructure:"disable_core"`
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
				Enabled:           true,
				AllowedEgress:     []string{"10.0.0.0/8", "172.16.0.0/12"},
				BlockExfiltration: true,
				ExfilThresholdMB:  100,
				AllowDNS:          true,
			},
			PickleProtection: PickleProtectionConfig{
				Enabled:          true,
				DangerousSymbols: []string{"os.system", "eval", "exec", "__import__", "subprocess"},
				BlockOnDetect:    true,
			},
			PyTorchObservability: PyTorchObservabilityConfig{
				Enabled:           true,
				MonitorModelLoads: true,
				CalculateHashes:   false,
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
			// 5 s default — short enough to defend the PID-recycle TOCTOU
			// window even on inference servers that fork/restart workers
			// every few seconds (vLLM, Triton, Ray Serve). Operators with
			// quieter workloads can tune this up to reduce /proc churn.
			PIDPruneInterval: 5 * time.Second,
		},
		BPF: BPFConfig{
			RingBufferSizeKB: 256,
			PerCPUMapSize:    1024,
		},
		Sandbox: SandboxConfig{
			Enabled: false,
		},
		MCP: MCPConfig{
			Enabled:      false,
			ListenAddr:   "127.0.0.1:8081",
			LogToolCalls: true,
		},
		Audit: AuditConfig{
			Enabled:   true,
			LogPath:   "/var/log/neurosentry/audit.jsonl",
			MaxSizeMB: 100,
			DBDriver:  "sqlite",
		},
		Web: WebConfig{
			Enabled:    false,
			ListenAddr: ":8080",
		},
		Platform: PlatformConfig{
			Enabled:         false,
			SnapshotPath:    "/var/lib/neurosentry/control-plane.json",
			BootstrapTenant: "default",
			BootstrapEmail:  "admin@neurosentry.local",
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

	// Record the source path so self-protection can baseline it.
	result.ConfigPath = path

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
	v.SetDefault("audit.db_driver", cfg.Audit.DBDriver)
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
