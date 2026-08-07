// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bpf

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// DetectCapabilities probes the running kernel for the features NeuroSentry's
// eBPF agent depends on. It is best-effort and never panics: a probe that can't
// be read is reported as unavailable, so the conservative (fail-safe) path is
// taken by Assess.
func DetectCapabilities() Capabilities {
	c := Capabilities{Privileged: os.Geteuid() == 0}

	if rel := unameRelease(); rel != "" {
		c.KernelVersion = rel
		c.KernelMajor, c.KernelMinor = parseKernelVersion(rel)
	}

	// CO-RE needs kernel BTF.
	c.BTF = fileExists("/sys/kernel/btf/vmlinux")

	// BPF ring buffer landed in 5.8.
	c.Ringbuf = kernelAtLeast(c.KernelMajor, c.KernelMinor, 5, 8)

	// BPF LSM must be in the active LSM list to enforce file_open.
	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		for _, name := range strings.Split(strings.TrimSpace(string(data)), ",") {
			if name == "bpf" {
				c.BPFLSM = true
				break
			}
		}
	}

	// TC/clsact BPF: available on essentially all modern kernels (>= 4.19).
	c.TC = kernelAtLeast(c.KernelMajor, c.KernelMinor, 4, 19)

	// Uprobes: tracefs must be present.
	c.Uprobe = fileExists("/sys/kernel/tracing/uprobe_events") ||
		fileExists("/sys/kernel/debug/tracing/uprobe_events")

	return c
}

func unameRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// parseKernelVersion extracts major.minor from a uname release like "6.1.176-...".
func parseKernelVersion(rel string) (major, minor int) {
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) >= 1 {
		major, _ = strconv.Atoi(digitsPrefix(parts[0]))
	}
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(digitsPrefix(parts[1]))
	}
	return major, minor
}

func digitsPrefix(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

func kernelAtLeast(major, minor, wantMajor, wantMinor int) bool {
	if major != wantMajor {
		return major > wantMajor
	}
	return minor >= wantMinor
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
