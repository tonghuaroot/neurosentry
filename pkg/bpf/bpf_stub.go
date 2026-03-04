// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux
// +build !linux

package bpf

import (
	"fmt"
	"runtime"

	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
)

// Stub types for non-Linux platforms
type NeuroSentryLSMObjects struct{}
type NeuroSentryXDPObjects struct{}
type NeuroSentryUprobeObjects struct{}
type NeuroSentryTCObjects struct{}

func (o *NeuroSentryLSMObjects) Close()    {}
func (o *NeuroSentryXDPObjects) Close()    {}
func (o *NeuroSentryUprobeObjects) Close() {}
func (o *NeuroSentryTCObjects) Close()     {}

// Manager manages eBPF programs lifecycle (stub for non-Linux)
type Manager struct {
	cfg     *config.Config
	policy  *policy.Policy

	// eBPF objects (unused stubs)
	lsmObjs    *NeuroSentryLSMObjects
	xdpObjs    *NeuroSentryXDPObjects
	uprobeObjs *NeuroSentryUprobeObjects
	tcObjs     *NeuroSentryTCObjects //nolint:unused // Stub for non-Linux platforms

	// Event channels
	eventChan chan []byte
}

// NewManager creates a new BPF manager
func NewManager(cfg *config.Config, pol *policy.Policy) (*Manager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	return &Manager{
		cfg:       cfg,
		policy:    pol,
		eventChan: make(chan []byte, 1000),

		// Initialize stub objects
		lsmObjs:    &NeuroSentryLSMObjects{},
		xdpObjs:    &NeuroSentryXDPObjects{},
		uprobeObjs: &NeuroSentryUprobeObjects{},
	}, nil
}

// Load returns an error on non-Linux platforms
func (m *Manager) Load() error {
	return fmt.Errorf("eBPF is only supported on Linux. Current platform: %s", runtime.GOOS)
}

// AttachLSM is a no-op on non-Linux platforms
func (m *Manager) AttachLSM() error {
	return fmt.Errorf("LSM hooks are only supported on Linux")
}

// AttachXDP is a no-op on non-Linux platforms
func (m *Manager) AttachXDP() error {
	return fmt.Errorf("XDP programs are only supported on Linux")
}

// AttachTC is a no-op on non-Linux platforms
func (m *Manager) AttachTC() error {
	return fmt.Errorf("TC programs are only supported on Linux")
}

// AttachUprobes is a no-op on non-Linux platforms
func (m *Manager) AttachUprobes() error {
	return fmt.Errorf("uprobes are only supported on Linux")
}

// AddTrustedPID is a no-op on non-Linux platforms
func (m *Manager) AddTrustedPID(pid uint32) error {
	return nil
}

// RemoveTrustedPID is a no-op on non-Linux platforms
func (m *Manager) RemoveTrustedPID(pid uint32) error {
	return nil
}

// AddProtectedExtension is a no-op on non-Linux platforms
func (m *Manager) AddProtectedExtension(ext string) error {
	return nil
}

// AddAllowedIP is a no-op on non-Linux platforms
func (m *Manager) AddAllowedIP(ipStr string) error {
	return nil
}

// AddDangerousSymbol is a no-op on non-Linux platforms
func (m *Manager) AddDangerousSymbol(symbol string) error {
	return nil
}

// Close is a no-op on non-Linux platforms
func (m *Manager) Close() {}

// ClearMaps is a no-op on non-Linux platforms
func (m *Manager) ClearMaps() error {
	return nil
}

// GetStats returns nil on non-Linux platforms
func (m *Manager) GetStats() (*Stats, error) {
	return nil, nil
}

// GetTCStats returns nil on non-Linux platforms
func (m *Manager) GetTCStats() (map[string]uint64, error) {
	return nil, nil
}

// GetXDPStats returns nil on non-Linux platforms
func (m *Manager) GetXDPStats() (map[string]uint64, error) {
	return nil, nil
}

// GetUprobeStats returns nil on non-Linux platforms
func (m *Manager) GetUprobeStats() (map[string]uint64, error) {
	return nil, nil
}

// Stats represents BPF statistics (stub)
type Stats struct {
	TotalAccessAttempts uint64
	BlockedAccess       uint64
	ProtectedFilesSeen  uint64
}
