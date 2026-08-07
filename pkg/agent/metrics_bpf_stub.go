// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package agent

import (
	"github.com/neurosentry/neurosentry/pkg/bpf"
)

// BPFMetricsCollector stub for non-Linux systems
type BPFMetricsCollector struct{}

// NewBPFMetricsCollector creates a stub BPF metrics collector
func NewBPFMetricsCollector(bpfMgr *bpf.Manager) *BPFMetricsCollector {
	return &BPFMetricsCollector{}
}

// Start is a no-op on non-Linux systems
func (c *BPFMetricsCollector) Start() {}

// Stop is a no-op on non-Linux systems
func (c *BPFMetricsCollector) Stop() {}
