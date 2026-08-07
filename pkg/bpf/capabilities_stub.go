// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package bpf

// DetectCapabilities on a non-Linux build reports no eBPF capabilities, which
// Assess classifies as unsupported. NeuroSentry's enforcement path only runs on
// Linux; this keeps the package building (and the decision logic testable) on
// developer workstations.
func DetectCapabilities() Capabilities {
	return Capabilities{}
}
