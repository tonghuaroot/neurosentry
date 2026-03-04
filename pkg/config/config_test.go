package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	// Create temp config file
	tmpfile, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	content := `
protection:
  model_fim:
    enabled: true
    protected_extensions: [".safetensors"]
    enforce_mode: true
  network_containment:
    enabled: true
    block_exfiltration: true
    exfil_threshold_mb: 100
agent:
  metrics_port: 2112
  log_level: info
`
	if _, err := tmpfile.WriteString(content); err != nil {
		t.Fatal(err)
	}

	// Test loading
	cfg, err := Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if !cfg.Protection.ModelFIM.Enabled {
		t.Error("ModelFIM should be enabled")
	}
	if cfg.Agent.MetricsPort != 2112 {
		t.Errorf("Expected port 2112, got %d", cfg.Agent.MetricsPort)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default config is nil")
	}
	if cfg.Protection.ModelFIM.Enabled != true {
		t.Error("Default ModelFIM should be enabled")
	}
}
