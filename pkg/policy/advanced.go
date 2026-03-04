// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Advanced policy evaluation
type AdvancedEvaluator struct {
	policy *Policy
}

// NewAdvancedEvaluator creates an advanced policy evaluator
func NewAdvancedEvaluator(policy *Policy) *AdvancedEvaluator {
	return &AdvancedEvaluator{policy: policy}
}

// MatchesWithContext performs advanced context-aware matching
func (e *AdvancedEvaluator) MatchesWithContext(rule Rule, context EventContext) bool {
	if !rule.Enabled {
		return false
	}

	// Fast path: basic type matching
	if rule.Condition.Type == "file_access" {
		return e.matchFileAccess(rule, context)
	}

	if rule.Condition.Type == "network_egress" {
		return e.matchNetworkEgress(rule, context)
	}

	if rule.Condition.Type == "model_load" {
		return e.matchModelLoad(rule, context)
	}

	return false
}

// EventContext provides additional context for evaluation
type EventContext struct {
	PID           int
	UID           int
	CGroup        string
	ContainerID   string
	Comm          string
	CommandLine   string
	ExePath       string
	Parents       []int
	DestinationIP string
	FilePath      string
}

func (e *AdvancedEvaluator) matchFileAccess(rule Rule, ctx EventContext) bool {
	// Check file extensions
	if len(rule.Condition.Extensions) > 0 {
		for _, ext := range rule.Condition.Extensions {
			if strings.HasSuffix(ctx.FilePath, ext) {
				return true
			}
		}
	}

	// Check protected paths
	if len(rule.Condition.Paths) > 0 {
		for _, path := range rule.Condition.Paths {
			if strings.HasPrefix(ctx.FilePath, path) {
				return true
			}
		}
	}

	return false
}

func (e *AdvancedEvaluator) matchNetworkEgress(rule Rule, ctx EventContext) bool {
	// Check size threshold (placeholder for future implementation)
	_ = rule.Condition.SizeThresholdMB

	// Check destinations
	if len(rule.Condition.Destinations) > 0 {
		// Check if destination matches allowed list
		for _, dest := range rule.Condition.Destinations {
			if e.matchCIDR(dest, ctx.DestinationIP) {
				return true
			}
		}
	}

	return false
}

func (e *AdvancedEvaluator) matchModelLoad(rule Rule, _ EventContext) bool {
	// Check hash mismatch (placeholder for future implementation)
	_ = rule.Condition.HashMismatch

	return true
}

func (e *AdvancedEvaluator) matchCIDR(cidr string, ip string) bool {
	// Handle "allow all" case
	if cidr == "0.0.0.0/0" {
		return true
	}

	// Parse the IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// If cidr doesn't contain a slash, treat it as a single IP
	if !strings.Contains(cidr, "/") {
		return cidr == ip
	}

	// Parse CIDR and check if IP is within the network
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return ipNet.Contains(parsedIP)
}

// IsTrustedProcess checks if a process is trusted
func (e *AdvancedEvaluator) IsTrustedProcess(ctx EventContext) bool {
	// Check against trusted process list
	trustedProcesses := []string{
		"python", "python3", "python3.9", "python3.10", "python3.11",
		"triton-server", "torchserve", "vllmserve",
	}

	for _, trusted := range trustedProcesses {
		if strings.HasPrefix(ctx.Comm, trusted) || strings.HasPrefix(ctx.CommandLine, trusted) {
			return true
		}
	}

	// Check if process is in a trusted container (placeholder for future implementation)
	_ = ctx.ContainerID

	return false
}

// ExtractContainerID extracts container ID from cgroup path
// Supports Docker, containerd, CRI-O, and Kubernetes cgroups
func ExtractContainerID(cgroupPath string) string {
	if cgroupPath == "" {
		return ""
	}

	// Docker format: /docker/<container-id>
	if strings.Contains(cgroupPath, "/docker/") {
		parts := strings.Split(cgroupPath, "/docker/")
		if len(parts) > 1 {
			id := strings.Split(parts[1], "/")[0]
			if len(id) >= 12 {
				return id[:12] // Return short ID
			}
		}
	}

	// containerd format: /system.slice/containerd-<container-id>.scope
	if strings.Contains(cgroupPath, "containerd-") {
		if idx := strings.Index(cgroupPath, "containerd-"); idx != -1 {
			rest := cgroupPath[idx+len("containerd-"):]
			if dotIdx := strings.Index(rest, "."); dotIdx > 0 {
				id := rest[:dotIdx]
				if len(id) >= 12 {
					return id[:12]
				}
			}
		}
	}

	// Kubernetes format: /kubepods/pod<pod-uid>/<container-id>
	// or: /kubepods.slice/kubepods-pod<pod-uid>.slice/cri-containerd-<container-id>.scope
	if strings.Contains(cgroupPath, "/kubepods") {
		parts := strings.Split(cgroupPath, "/")
		for _, part := range parts {
			// CRI-O format
			if strings.HasPrefix(part, "crio-") {
				id := strings.TrimPrefix(part, "crio-")
				id = strings.TrimSuffix(id, ".scope")
				if len(id) >= 12 {
					return id[:12]
				}
			}
			// containerd format in k8s
			if strings.HasPrefix(part, "cri-containerd-") {
				id := strings.TrimPrefix(part, "cri-containerd-")
				id = strings.TrimSuffix(id, ".scope")
				if len(id) >= 12 {
					return id[:12]
				}
			}
			// Plain container ID (64 hex chars)
			if len(part) == 64 && isHexString(part) {
				return part[:12]
			}
		}
	}

	// Podman format: /machine.slice/libpod-<container-id>.scope
	if strings.Contains(cgroupPath, "libpod-") {
		if idx := strings.Index(cgroupPath, "libpod-"); idx != -1 {
			rest := cgroupPath[idx+len("libpod-"):]
			if dotIdx := strings.Index(rest, "."); dotIdx > 0 {
				id := rest[:dotIdx]
				if len(id) >= 12 {
					return id[:12]
				}
			}
		}
	}

	return ""
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		isUpperHex := c >= 'A' && c <= 'F'
		if !isDigit && !isLowerHex && !isUpperHex {
			return false
		}
	}
	return true
}

// GetProcessChain gets the parent process chain by reading /proc/[pid]/status
func GetProcessChain(pid int) []int {
	var chain []int
	currentPid := pid

	// Walk up the process tree by reading /proc/[pid]/status
	for i := 0; i < 10 && currentPid > 0; i++ { // Max 10 levels, stop at init (PID 1) or invalid
		chain = append(chain, currentPid)

		// Stop at init process
		if currentPid == 1 {
			break
		}

		// Read parent PID from /proc/[pid]/status
		ppid, err := getParentPID(currentPid)
		if err != nil || ppid <= 0 {
			break
		}
		currentPid = ppid
	}

	return chain
}

// getParentPID reads the parent PID from /proc/[pid]/status
func getParentPID(pid int) (int, error) {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(statusPath) //nolint:gosec // G304: /proc path is constructed from validated PID
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ppid, err := strconv.Atoi(fields[1])
				if err != nil {
					return 0, err
				}
				return ppid, nil
			}
		}
	}

	return 0, fmt.Errorf("PPid not found in /proc/%d/status", pid)
}
