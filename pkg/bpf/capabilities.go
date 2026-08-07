// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"fmt"
	"strings"
)

// Capabilities is the set of kernel/runtime features NeuroSentry's eBPF agent
// depends on, probed once at startup. It is the foundation of the multi-kernel
// support matrix: the raw booleans are gathered OS-specifically (see
// DetectCapabilities), but the *decision* about whether the host can run — and
// in which mode — is the pure, table-tested Assess method below.
type Capabilities struct {
	KernelVersion string `json:"kernel_version"`
	KernelMajor   int    `json:"kernel_major"`
	KernelMinor   int    `json:"kernel_minor"`
	Privileged    bool   `json:"privileged"` // CAP_BPF / root — required to load any program
	BTF           bool   `json:"btf"`        // /sys/kernel/btf/vmlinux — required for CO-RE
	Ringbuf       bool   `json:"ringbuf"`    // BPF ring buffer — kernel >= 5.8
	BPFLSM        bool   `json:"bpf_lsm"`    // "bpf" in the active LSM list — required to enforce
	TC            bool   `json:"tc"`         // TC/clsact BPF — network visibility
	Uprobe        bool   `json:"uprobe"`     // uprobes — pickle/deserialization detection
}

// SupportLevel is the overall verdict for a host.
type SupportLevel string

const (
	SupportFull        SupportLevel = "supported"   // full eBPF triad available
	SupportDegraded    SupportLevel = "degraded"    // runs, but with reduced capability
	SupportUnsupported SupportLevel = "unsupported" // cannot run safely
)

// Assessment is the result of evaluating Capabilities against a requested mode.
type Assessment struct {
	Level    SupportLevel `json:"level"`
	Blocking []string     `json:"blocking,omitempty"` // hard blockers for the requested mode
	Reduced  []string     `json:"reduced,omitempty"`  // features unavailable but non-fatal
	// EnforceUnavailable is true when enforcement (LSM blocking) was requested
	// but the kernel cannot provide it. A security product must fail safe here:
	// the operator believes reads are blocked when they are not.
	EnforceUnavailable bool `json:"enforce_unavailable"`
}

// Assess classifies a host. enforce=true means the operator asked for blocking
// (LSM enforcement), which raises the bar: without BPF LSM the request cannot
// be honored and the caller should fail safe rather than silently monitor-only.
func (c Capabilities) Assess(enforce bool) Assessment {
	a := Assessment{Level: SupportFull}

	// Core requirements to load and run any program at all.
	if !c.Privileged {
		a.Blocking = append(a.Blocking, "privileged (CAP_BPF or root)")
	}
	if !c.BTF {
		a.Blocking = append(a.Blocking, "BTF (/sys/kernel/btf/vmlinux) for CO-RE")
	}
	if !c.Ringbuf {
		a.Blocking = append(a.Blocking, "BPF ring buffer (kernel >= 5.8)")
	}
	coreOK := c.Privileged && c.BTF && c.Ringbuf

	// Enforcement requires BPF LSM.
	if enforce && !c.BPFLSM {
		a.EnforceUnavailable = true
		a.Blocking = append(a.Blocking,
			"BPF LSM required for enforce mode (add 'bpf' to CONFIG_LSM or the lsm= boot param)")
	}

	// Non-fatal reductions.
	if !c.TC {
		a.Reduced = append(a.Reduced, "TC network programs unavailable — no L3/L4 flow visibility")
	}
	if !c.Uprobe {
		a.Reduced = append(a.Reduced, "uprobes unavailable — no pickle/deserialization detection")
	}
	if !enforce && !c.BPFLSM {
		a.Reduced = append(a.Reduced, "BPF LSM unavailable — file access is observed, not blocked")
	}

	switch {
	case !coreOK:
		a.Level = SupportUnsupported
	case len(a.Blocking) > 0 || len(a.Reduced) > 0:
		a.Level = SupportDegraded
	default:
		a.Level = SupportFull
	}
	return a
}

// String renders a one-line human summary of the assessment.
func (a Assessment) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "support=%s", a.Level)
	if len(a.Blocking) > 0 {
		fmt.Fprintf(&b, " blocking=[%s]", strings.Join(a.Blocking, "; "))
	}
	if len(a.Reduced) > 0 {
		fmt.Fprintf(&b, " reduced=[%s]", strings.Join(a.Reduced, "; "))
	}
	return b.String()
}
