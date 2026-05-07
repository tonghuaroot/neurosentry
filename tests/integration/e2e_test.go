// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux
// +build linux

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neurosentry/neurosentry/pkg/bpf"
	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
)

// TestE2ELSMFileProtection tests the complete LSM file protection flow
func TestE2ELSMFileProtection(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping test: requires root privileges")
	}

	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "neurosentry-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a fake model file
	modelPath := filepath.Join(tmpDir, "test-model.safetensors")
	if err := os.WriteFile(modelPath, []byte("fake model data"), 0600); err != nil {
		t.Fatalf("Failed to create test model: %v", err)
	}

	// Create config
	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			ModelFIM: config.ModelFIMConfig{
				Enabled:             true,
				EnforceMode:         true,
				LogAllAccess:        true,
				ProtectedExtensions: []string{".safetensors"},
				ProtectedPaths:      []string{tmpDir},
			},
		},
	}

	// Create policy
	pol := policy.DefaultPolicy()

	// Create BPF manager
	mgr, err := bpf.NewManager(cfg, pol)
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer mgr.Close()

	// Load eBPF programs
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- mgr.Load()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Failed to load BPF programs: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Loading BPF programs timed out")
	}

	// Attach LSM programs
	if err := mgr.AttachLSM(); err != nil {
		t.Fatalf("Failed to attach LSM programs: %v", err)
	}

	// Add current process to trusted PIDs so we can read the file
	currentPID := uint32(os.Getpid()) //nolint:gosec // G115: PID conversion is safe
	if err := mgr.AddTrustedPID(currentPID); err != nil {
		t.Logf("Warning: Failed to add trusted PID: %v", err)
	}

	// Test: Trusted process should be able to read the file
	data, err := os.ReadFile(modelPath)
	if err != nil {
		t.Errorf("Trusted process failed to read protected file: %v", err)
	}
	if len(data) != len("fake model data") {
		t.Errorf("Read unexpected data length: got %d, want %d", len(data), len("fake model data"))
	}

	// Note: Testing actual blocking would require spawning an untrusted process
	// which is complex in a unit test. In production, this would be tested
	// via the CTF challenge.
	t.Log("LSM file protection E2E test passed")
}

// TestE2ENetworkContainment tests the complete network containment flow
func TestE2ENetworkContainment(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping test: requires root privileges")
	}

	// Create config
	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			NetworkContainment: config.NetworkContainmentConfig{
				Enabled:           true,
				BlockExfiltration: true,
				ExfilThresholdMB:  100,
				AllowedEgress:     []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				Interfaces:        []string{}, // Empty will use default interface
			},
		},
	}

	// Create policy
	pol := policy.DefaultPolicy()

	// Create BPF manager
	mgr, err := bpf.NewManager(cfg, pol)
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer mgr.Close()

	// Load eBPF programs
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- mgr.Load()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Failed to load BPF programs: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Loading BPF programs timed out")
	}

	// Attach XDP programs
	if err := mgr.AttachXDP(); err != nil {
		// XDP attachment may fail in CI/CD environments without proper network interfaces
		t.Logf("Warning: Failed to attach XDP programs (may be expected in CI): %v", err)
		return
	}

	t.Log("Network containment E2E test passed")
}

// TestE2EUprobeAttachment tests the uprobe attachment functionality
func TestE2EUprobeAttachment(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping test: requires root privileges")
	}

	// Create config
	cfg := &config.Config{
		Protection: config.ProtectionConfig{
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

	// Create BPF manager
	mgr, err := bpf.NewManager(cfg, pol)
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer mgr.Close()

	// Load eBPF programs
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- mgr.Load()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Failed to load BPF programs: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Loading BPF programs timed out")
	}

	// Attach uprobes
	if err := mgr.AttachUprobes(); err != nil {
		// Uprobe attachment may fail if PyTorch/Python are not installed
		t.Logf("Warning: Failed to attach uprobes (may be expected if PyTorch/Python not installed): %v", err)
		return
	}

	t.Log("Uprobe attachment E2E test passed")
}

// TestE2EFullStack tests the complete NeuroSentry stack
func TestE2EFullStack(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping test: requires root privileges")
	}

	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "neurosentry-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a fake model file
	modelPath := filepath.Join(tmpDir, "test-model.gguf")
	if err := os.WriteFile(modelPath, []byte("fake model data"), 0600); err != nil {
		t.Fatalf("Failed to create test model: %v", err)
	}

	// Create config with all features enabled
	cfg := &config.Config{
		Protection: config.ProtectionConfig{
			ModelFIM: config.ModelFIMConfig{
				Enabled:             true,
				EnforceMode:         true,
				LogAllAccess:        true,
				ProtectedExtensions: []string{".safetensors", ".gguf", ".pth"},
				ProtectedPaths:      []string{tmpDir},
			},
			NetworkContainment: config.NetworkContainmentConfig{
				Enabled:           true,
				BlockExfiltration: true,
				ExfilThresholdMB:  100,
				AllowedEgress:     []string{"10.0.0.0/8"},
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

	// Create BPF manager
	mgr, err := bpf.NewManager(cfg, pol)
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer mgr.Close()

	// Load all eBPF programs
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- mgr.Load()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Failed to load BPF programs: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Loading BPF programs timed out")
	}

	// Attach all programs
	attachmentErrors := 0

	if err := mgr.AttachLSM(); err != nil {
		t.Errorf("Failed to attach LSM: %v", err)
		attachmentErrors++
	}

	if err := mgr.AttachXDP(); err != nil {
		t.Logf("Warning: Failed to attach XDP (may be expected in some environments): %v", err)
		// Don't count as error since XDP may not work in all environments
	}

	if err := mgr.AttachUprobes(); err != nil {
		t.Logf("Warning: Failed to attach uprobes (may be expected if PyTorch/Python not installed): %v", err)
		// Don't count as error since PyTorch/Python may not be installed
	}

	// Add current process to trusted PIDs
	currentPID := uint32(os.Getpid()) //nolint:gosec // G115: PID conversion is safe
	if err := mgr.AddTrustedPID(currentPID); err != nil {
		t.Logf("Warning: Failed to add trusted PID: %v", err)
	}

	// Test: Add protected extension
	if err := mgr.AddProtectedExtension(".bin"); err != nil {
		t.Logf("Warning: Failed to add protected extension: %v", err)
	}

	// Test: Add allowed IP
	if err := mgr.AddAllowedIP("192.168.1.1"); err != nil {
		t.Logf("Warning: Failed to add allowed IP: %v", err)
	}

	if attachmentErrors > 0 {
		t.Fatalf("Failed to attach %d eBPF program types", attachmentErrors)
	}

	t.Log("Full stack E2E test passed")
}
