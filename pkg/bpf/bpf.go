// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux
// +build linux

package bpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Wno-visibility -I./headers" -tags linux NeuroSentryLSM ./neurosentry_lsm.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Wno-visibility -I./headers" -tags linux NeuroSentryXDP ./neurosentry_xdp.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Wno-visibility -I./headers" -tags linux NeuroSentryUprobe ./neurosentry_uprobe.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Wno-visibility -I./headers" -tags linux NeuroSentryTC ./neurosentry_tc.c

// Manager manages eBPF programs lifecycle
type Manager struct {
	cfg     *config.Config
	policy  *policy.Policy

	// eBPF objects
	lsmObjs    *NeuroSentryLSMObjects
	xdpObjs    *NeuroSentryXDPObjects
	uprobeObjs *NeuroSentryUprobeObjects
	tcObjs     *NeuroSentryTCObjects

	// Program links
	links []link.Link

	// TC qdisc handles (for cleanup)
	tcInterfaces []string

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
	}, nil
}

// Load loads all eBPF programs
func (m *Manager) Load() error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("neurosentry must be run as root")
	}

	// Check kernel version
	if err := checkKernelVersion(); err != nil {
		return fmt.Errorf("kernel version check failed: %w", err)
	}

	// Load LSM programs
	if m.cfg.Protection.ModelFIM.Enabled {
		if err := m.loadLSM(); err != nil {
			return fmt.Errorf("failed to load LSM programs: %w", err)
		}
	}

	// Load TC programs (replaces XDP for better cloud compatibility)
	if m.cfg.Protection.NetworkContainment.Enabled {
		if err := m.loadTC(); err != nil {
			return fmt.Errorf("failed to load TC programs: %w", err)
		}
	}

	// Load Uprobe programs
	if m.cfg.Protection.PickleProtection.Enabled || m.cfg.Protection.PyTorchObservability.Enabled {
		if err := m.loadUprobes(); err != nil {
			return fmt.Errorf("failed to load Uprobe programs: %w", err)
		}
	}

	return nil
}

// loadLSM loads LSM BPF programs
func (m *Manager) loadLSM() error {
	objs := &NeuroSentryLSMObjects{}

	// Load BPF objects
	if err := LoadNeuroSentryLSMObjects(objs, nil); err != nil {
		return fmt.Errorf("loading LSM objects: %w", err)
	}

	m.lsmObjs = objs

	// Initialize configuration
	if err := m.initLSMConfig(); err != nil {
		return fmt.Errorf("initializing LSM config: %w", err)
	}

	return nil
}

// loadXDP loads XDP BPF programs
func (m *Manager) loadXDP() error {
	objs := &NeuroSentryXDPObjects{}

	if err := LoadNeuroSentryXDPObjects(objs, nil); err != nil {
		return fmt.Errorf("loading XDP objects: %w", err)
	}

	m.xdpObjs = objs

	// Initialize XDP configuration
	if err := m.initXDPConfig(); err != nil {
		return fmt.Errorf("initializing XDP config: %w", err)
	}

	return nil
}

// loadUprobes loads Uprobe BPF programs
func (m *Manager) loadUprobes() error {
	objs := &NeuroSentryUprobeObjects{}

	if err := LoadNeuroSentryUprobeObjects(objs, nil); err != nil {
		return fmt.Errorf("loading Uprobe objects: %w", err)
	}

	m.uprobeObjs = objs

	return nil
}

// loadTC loads TC BPF programs
func (m *Manager) loadTC() error {
	objs := &NeuroSentryTCObjects{}

	if err := LoadNeuroSentryTCObjects(objs, nil); err != nil {
		return fmt.Errorf("loading TC objects: %w", err)
	}

	m.tcObjs = objs

	return nil
}

// AttachLSM attaches LSM hooks
func (m *Manager) AttachLSM() error {
	if m.lsmObjs == nil {
		return fmt.Errorf("LSM objects not loaded")
	}

	// Attach file_open hook
	l, err := link.AttachLSM(link.LSMOptions{
		Program: m.lsmObjs.RestrictModelFileAccess,
	})
	if err != nil {
		return fmt.Errorf("attaching file_open LSM: %w", err)
	}
	m.links = append(m.links, l)

	// Note: file_permission and mmap_file hooks are disabled in neurosentry_lsm.c
	// due to eBPF verifier issues on kernel 6.14. The file_open hook provides
	// sufficient coverage for file access monitoring.

	return nil
}

// AttachXDP attaches XDP programs
func (m *Manager) AttachXDP() error {
	if m.xdpObjs == nil {
		return fmt.Errorf("XDP objects not loaded")
	}

	// Get interfaces to attach to
	interfaces := m.cfg.Protection.NetworkContainment.Interfaces
	if len(interfaces) == 0 {
		// Try to find default interface
		iface, err := getDefaultInterface()
		if err != nil {
			return fmt.Errorf("finding default interface: %w", err)
		}
		interfaces = []string{iface}
	}

	for _, ifaceName := range interfaces {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Printf("Warning: interface %s not found: %v", ifaceName, err)
			continue
		}

		// Use ONLY Generic/SKB mode for maximum compatibility
		// Driver mode can cause network issues on cloud VMs (AWS, GCP, Azure)
		// Generic mode is slower but safe and works everywhere
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   m.xdpObjs.NeurosentryXdpFilter,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP to %s in generic mode: %w", ifaceName, err)
		}
		m.links = append(m.links, l)
		log.Printf("Attached XDP to %s in generic/SKB mode", ifaceName)
	}

	return nil
}

// AttachTC attaches TC (Traffic Control) eBPF programs for network monitoring
// TC is more compatible than XDP on cloud environments like AWS EC2
func (m *Manager) AttachTC() error {
	if m.tcObjs == nil {
		return fmt.Errorf("TC objects not loaded")
	}

	// Get interfaces to attach to
	interfaces := m.cfg.Protection.NetworkContainment.Interfaces
	if len(interfaces) == 0 {
		iface, err := getDefaultInterface()
		if err != nil {
			return fmt.Errorf("finding default interface: %w", err)
		}
		interfaces = []string{iface}
	} else if len(interfaces) == 1 && interfaces[0] == "all" {
		// Special case: attach to all non-loopback interfaces
		var err error
		interfaces, err = GetAllInterfaces()
		if err != nil {
			return fmt.Errorf("getting all interfaces: %w", err)
		}
		log.Printf("Attaching TC to all interfaces: %v", interfaces)
	}

	for _, ifaceName := range interfaces {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Printf("Warning: interface %s not found: %v", ifaceName, err)
			continue
		}

		// Try TCX first (kernel 6.6+), then fall back to legacy TC
		// Attach ingress
		ingressLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   m.tcObjs.NeurosentryTcIngress,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			log.Printf("TCX ingress not available on %s (kernel may be older): %v", ifaceName, err)
			// Fall back to legacy TC attachment
			if err := m.attachTCLegacy(ifaceName); err != nil {
				log.Printf("Warning: failed to attach TC to %s: %v", ifaceName, err)
				continue
			}
		} else {
			m.links = append(m.links, ingressLink)
			log.Printf("Attached TCX ingress to %s", ifaceName)

			// Attach egress
			egressLink, err := link.AttachTCX(link.TCXOptions{
				Interface: iface.Index,
				Program:   m.tcObjs.NeurosentryTcEgress,
				Attach:    ebpf.AttachTCXEgress,
			})
			if err != nil {
				log.Printf("Warning: failed to attach TCX egress to %s: %v", ifaceName, err)
			} else {
				m.links = append(m.links, egressLink)
				log.Printf("Attached TCX egress to %s", ifaceName)
			}
		}

		m.tcInterfaces = append(m.tcInterfaces, ifaceName)
	}

	return nil
}

// attachTCLegacy attaches TC programs using the legacy tc command approach
func (m *Manager) attachTCLegacy(ifaceName string) error {
	// Add clsact qdisc
	// Ignore error from delete - qdisc may not exist
	_ = exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact").Run()
	if err := exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact").Run(); err != nil {
		return fmt.Errorf("adding clsact qdisc: %w", err)
	}

	// For legacy TC, we need to use the fd-based approach
	// Pin the programs first
	ingressPath := fmt.Sprintf("/sys/fs/bpf/neurosentry_tc_ingress_%s", ifaceName)
	egressPath := fmt.Sprintf("/sys/fs/bpf/neurosentry_tc_egress_%s", ifaceName)

	os.Remove(ingressPath)
	os.Remove(egressPath)

	if err := m.tcObjs.NeurosentryTcIngress.Pin(ingressPath); err != nil {
		return fmt.Errorf("pinning ingress: %w", err)
	}
	if err := m.tcObjs.NeurosentryTcEgress.Pin(egressPath); err != nil {
		os.Remove(ingressPath)
		return fmt.Errorf("pinning egress: %w", err)
	}

	// Use tc with pinned path
	cmd := exec.Command("tc", "filter", "add", "dev", ifaceName, "ingress",
		"bpf", "da", "pinned", ingressPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("attaching ingress: %v (%s)", err, string(output))
	}
	log.Printf("Attached TC ingress (legacy) to %s", ifaceName)

	cmd = exec.Command("tc", "filter", "add", "dev", ifaceName, "egress",
		"bpf", "da", "pinned", egressPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("attaching egress: %v (%s)", err, string(output))
	}
	log.Printf("Attached TC egress (legacy) to %s", ifaceName)

	return nil
}

// AttachUprobes attaches user-space probes for PyTorch and Python pickle monitoring
func (m *Manager) AttachUprobes() error {
	if m.uprobeObjs == nil {
		return fmt.Errorf("Uprobe objects not loaded")
	}

	// Find and attach to PyTorch library
	if m.cfg.Protection.PyTorchObservability.Enabled {
		if err := m.attachPyTorchProbes(); err != nil {
			log.Printf("Warning: failed to attach PyTorch probes: %v", err)
		}
	}

	// Find and attach to Python pickle
	if m.cfg.Protection.PickleProtection.Enabled {
		if err := m.attachPickleProbes(); err != nil {
			log.Printf("Warning: failed to attach pickle probes: %v", err)
		}
	}

	return nil
}

// initLSMConfig initializes LSM configuration maps
func (m *Manager) initLSMConfig() error {
	// Set enforcement mode
	key := uint32(0)
	configData := struct {
		EnforceMode  uint8
		LogAllAccess uint8
		Padding      [2]uint8
	}{
		EnforceMode:  boolToUint8(m.cfg.Protection.ModelFIM.EnforceMode),
		LogAllAccess: boolToUint8(m.cfg.Protection.ModelFIM.LogAllAccess),
	}

	if err := m.lsmObjs.ConfigMap.Put(&key, &configData); err != nil {
		return fmt.Errorf("setting LSM config: %w", err)
	}

	// Add protected extensions
	// Note: Map key is uint32 (unsigned int in C), value is uint8
	extMap := map[string]uint32{
		".safetensors": 1,
		".gguf":        2,
		".pth":         3,
		".pt":          4,
		".pb":          5,
		".h5":          6,
		".pkl":         7,
		".bin":         8,
	}

	for _, ext := range m.cfg.Protection.ModelFIM.ProtectedExtensions {
		if code, ok := extMap[ext]; ok {
			val := uint8(1)
			if err := m.lsmObjs.ProtectedExtensions.Put(&code, &val); err != nil {
				return fmt.Errorf("adding protected extension %s: %w", ext, err)
			}
		}
	}

	return nil
}

// initXDPConfig initializes XDP configuration maps
func (m *Manager) initXDPConfig() error {
	key := uint32(0)
	// C struct is __attribute__((packed)), so we need exact 6-byte layout:
	// byte 0: block_exfil, bytes 1-4: threshold_bytes (LE), byte 5: enforce_mode
	configData := make([]byte, 6)
	configData[0] = boolToUint8(m.cfg.Protection.NetworkContainment.BlockExfiltration)
	binary.LittleEndian.PutUint32(configData[1:5], uint32(m.cfg.Protection.NetworkContainment.ExfilThresholdMB*1024*1024))
	// enforce_mode: only enable strict allowlist checking if block_exfiltration is true
	// When false, XDP still monitors traffic but doesn't block based on allowlist
	configData[5] = boolToUint8(m.cfg.Protection.NetworkContainment.BlockExfiltration)

	if err := m.xdpObjs.XdpConfigMap.Put(&key, &configData); err != nil {
		return fmt.Errorf("setting XDP config: %w", err)
	}

	// Add allowed IPs/CIDRs
	for _, cidr := range m.cfg.Protection.NetworkContainment.AllowedEgress {
		if err := m.addCIDRToAllowlist(cidr); err != nil {
			log.Printf("Warning: failed to add allowed CIDR %s: %v", cidr, err)
		}
	}

	return nil
}

// AddTrustedPID adds a PID to the trusted list
// Security: validates PID exists and logs the operation
func (m *Manager) AddTrustedPID(pid uint32) error {
	if m.lsmObjs == nil {
		return fmt.Errorf("LSM not loaded")
	}

	// Security validation: verify the PID exists
	procPath := fmt.Sprintf("/proc/%d", pid)
	if _, err := os.Stat(procPath); os.IsNotExist(err) {
		return fmt.Errorf("PID %d does not exist", pid)
	}

	// Log the operation for audit trail
	log.Printf("SECURITY: Adding PID %d to trusted list", pid)

	value := uint8(1)
	return m.lsmObjs.TrustedPids.Put(&pid, &value)
}

// RemoveTrustedPID removes a PID from the trusted list
// Security: logs the operation for audit trail
func (m *Manager) RemoveTrustedPID(pid uint32) error {
	if m.lsmObjs == nil {
		return fmt.Errorf("LSM not loaded")
	}

	// Log the operation for audit trail
	log.Printf("SECURITY: Removing PID %d from trusted list", pid)

	return m.lsmObjs.TrustedPids.Delete(&pid)
}

// AddProtectedExtension adds a protected file extension
// Security: validates extension and logs the operation
func (m *Manager) AddProtectedExtension(ext string) error {
	if m.lsmObjs == nil {
		return fmt.Errorf("LSM not loaded")
	}

	// Note: Map key is uint32 (unsigned int in C), value is uint8
	extMap := map[string]uint32{
		".safetensors": 1,
		".gguf":        2,
		".pth":         3,
		".pt":          4,
		".pb":          5,
		".h5":          6,
		".pkl":         7,
		".bin":         8,
	}

	code, ok := extMap[ext]
	if !ok {
		return fmt.Errorf("unknown extension: %s", ext)
	}

	// Log the operation for audit trail
	log.Printf("SECURITY: Adding protected extension %s (code=%d)", ext, code)

	value := uint8(1)
	return m.lsmObjs.ProtectedExtensions.Put(&code, &value)
}

// AddAllowedIP adds an IP or CIDR to the network allowlist
// Security: validates IP format and logs the operation
func (m *Manager) AddAllowedIP(ipStr string) error {
	if m.xdpObjs == nil {
		return fmt.Errorf("XDP not loaded")
	}

	// Log the operation for audit trail
	log.Printf("SECURITY: Adding allowed IP/CIDR: %s", ipStr)

	// Check if it's a CIDR notation
	if strings.Contains(ipStr, "/") {
		return m.addCIDRToAllowlist(ipStr)
	}

	// Single IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("IPv6 not supported: %s", ipStr)
	}

	ipUint := binary.LittleEndian.Uint32(ip)
	value := uint8(1)
	return m.xdpObjs.AllowedEgressIps.Put(&ipUint, &value)
}

// addCIDRToAllowlist adds a CIDR range to the allowlist
// For large ranges (/8, /16), it stores the network address and mask info
// For smaller ranges, it enumerates individual IPs
func (m *Manager) addCIDRToAllowlist(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}

	ip := ipNet.IP.To4()
	if ip == nil {
		return fmt.Errorf("IPv6 not supported: %s", cidr)
	}

	// Get the prefix length
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("invalid mask for IPv4: %s", cidr)
	}

	// For large ranges (/8 to /20), just add the network base address
	// The XDP program handles these via built-in private range checks
	// For smaller ranges (/21 to /32), enumerate IPs (max 2048 IPs)
	if ones <= 20 {
		// Large range - add network address as marker
		ipUint := binary.LittleEndian.Uint32(ip)
		value := uint8(1)
		if err := m.xdpObjs.AllowedEgressIps.Put(&ipUint, &value); err != nil {
			return fmt.Errorf("failed to add network base %s: %w", cidr, err)
		}
		log.Printf("Added CIDR %s (network base only, range checked in XDP)", cidr)
		return nil
	}

	// Smaller range - enumerate individual IPs
	numHosts := uint32(1) << uint(32-ones)
	if numHosts > 2048 {
		// Too many IPs, just add network base
		ipUint := binary.LittleEndian.Uint32(ip)
		value := uint8(1)
		return m.xdpObjs.AllowedEgressIps.Put(&ipUint, &value)
	}

	// Enumerate all IPs in the range
	baseIP := binary.BigEndian.Uint32(ip)
	addedCount := 0
	for i := uint32(0); i < numHosts; i++ {
		hostIP := baseIP + i
		ipBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ipBytes, hostIP)
		ipUint := binary.LittleEndian.Uint32(ipBytes)
		value := uint8(1)
		if err := m.xdpObjs.AllowedEgressIps.Put(&ipUint, &value); err != nil {
			log.Printf("Warning: failed to add IP in range %s: %v", cidr, err)
			continue
		}
		addedCount++
	}

	log.Printf("Added CIDR %s (%d IPs enumerated)", cidr, addedCount)
	return nil
}

// AddDangerousSymbol adds a dangerous symbol pattern
// Security: logs the operation for audit trail
func (m *Manager) AddDangerousSymbol(symbol string) error {
	if m.uprobeObjs == nil {
		return fmt.Errorf("Uprobes not loaded")
	}

	// Log the operation for audit trail
	log.Printf("SECURITY: Adding dangerous symbol pattern: %s", symbol)

	var key [32]byte
	copy(key[:], symbol)
	value := uint8(1)
	return m.uprobeObjs.DangerousSymbols.Put(&key, &value)
}

// ClearMaps clears all BPF maps for configuration reload
// This ensures old entries don't persist after SIGHUP reload
func (m *Manager) ClearMaps() error {
	var errs []error

	// Clear LSM maps
	if m.lsmObjs != nil {
		if err := clearBPFMap(m.lsmObjs.TrustedPids); err != nil {
			errs = append(errs, fmt.Errorf("clearing trusted_pids: %w", err))
		}
		if err := clearBPFMap(m.lsmObjs.ProtectedExtensions); err != nil {
			errs = append(errs, fmt.Errorf("clearing protected_extensions: %w", err))
		}
		log.Println("Cleared LSM maps")
	}

	// Clear XDP maps
	if m.xdpObjs != nil {
		if err := clearBPFMap(m.xdpObjs.AllowedEgressIps); err != nil {
			errs = append(errs, fmt.Errorf("clearing allowed_egress_ips: %w", err))
		}
		log.Println("Cleared XDP maps")
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors clearing maps: %v", errs)
	}
	return nil
}

// clearBPFMap iterates over a BPF map and deletes all entries
func clearBPFMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}

	var key, nextKey interface{}

	// Determine key type based on map key size
	keySize := int(m.KeySize())
	switch keySize {
	case 4:
		key = new(uint32)
		nextKey = new(uint32)
	case 32:
		key = new([32]byte)
		nextKey = new([32]byte)
	default:
		// Generic byte slice for other sizes
		key = make([]byte, keySize)
		nextKey = make([]byte, keySize)
	}

	// Iterate and collect keys to delete
	var keysToDelete []interface{}
	iter := m.Iterate()
	for iter.Next(key, nil) {
		// Copy the key value
		switch k := key.(type) {
		case *uint32:
			v := *k
			keysToDelete = append(keysToDelete, &v)
		case *[32]byte:
			v := *k
			keysToDelete = append(keysToDelete, &v)
		default:
			// For byte slices, make a copy
			if bs, ok := key.([]byte); ok {
				cp := make([]byte, len(bs))
				copy(cp, bs)
				keysToDelete = append(keysToDelete, cp)
			}
		}
		_ = nextKey // silence unused warning
	}

	// Delete collected keys
	for _, k := range keysToDelete {
		if err := m.Delete(k); err != nil && !isNotExistError(err) {
			return err
		}
	}

	return nil
}

// isNotExistError checks if the error indicates key doesn't exist
func isNotExistError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "key does not exist")
}

// Close closes all BPF resources
func (m *Manager) Close() {
	// Close all links
	for _, l := range m.links {
		l.Close()
	}
	m.links = nil

	// Clean up TC filters and qdiscs
	for _, ifaceName := range m.tcInterfaces {
		// Remove TC filters - log errors but continue cleanup
		if err := exec.Command("tc", "filter", "del", "dev", ifaceName, "ingress").Run(); err != nil {
			log.Printf("Warning: failed to remove TC ingress filter on %s: %v", ifaceName, err)
		}
		if err := exec.Command("tc", "filter", "del", "dev", ifaceName, "egress").Run(); err != nil {
			log.Printf("Warning: failed to remove TC egress filter on %s: %v", ifaceName, err)
		}
		// Remove pinned programs - log errors but continue cleanup
		ingressPath := fmt.Sprintf("/sys/fs/bpf/neurosentry_tc_ingress_%s", ifaceName)
		egressPath := fmt.Sprintf("/sys/fs/bpf/neurosentry_tc_egress_%s", ifaceName)
		if err := os.Remove(ingressPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to remove pinned ingress program %s: %v", ingressPath, err)
		}
		if err := os.Remove(egressPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to remove pinned egress program %s: %v", egressPath, err)
		}
	}
	m.tcInterfaces = nil

	// Close BPF objects
	if m.lsmObjs != nil {
		m.lsmObjs.Close()
	}
	if m.xdpObjs != nil {
		m.xdpObjs.Close()
	}
	if m.uprobeObjs != nil {
		m.uprobeObjs.Close()
	}
	if m.tcObjs != nil {
		m.tcObjs.Close()
	}
}

// checkKernelVersion checks if kernel version is sufficient
// Requires kernel 5.10+ for LSM BPF support
func checkKernelVersion() error {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return err
	}

	// Convert release to string
	release := make([]byte, 0, len(uname.Release))
	for _, b := range uname.Release {
		if b == 0 {
			break
		}
		release = append(release, byte(b))
	}

	// Parse version (e.g., "5.15.0-generic" or "6.1.0")
	var major, minor int
	_, err := fmt.Sscanf(string(release), "%d.%d", &major, &minor)
	if err != nil {
		return fmt.Errorf("failed to parse kernel version %q: %w", string(release), err)
	}

	// Require kernel 5.10+ for LSM BPF support
	const requiredMajor = 5
	const requiredMinor = 10

	if major < requiredMajor || (major == requiredMajor && minor < requiredMinor) {
		return fmt.Errorf("kernel version %d.%d is too old, requires %d.%d+ for LSM BPF support",
			major, minor, requiredMajor, requiredMinor)
	}

	log.Printf("Kernel version %d.%d detected (requires %d.%d+)", major, minor, requiredMajor, requiredMinor)
	return nil
}

// getDefaultInterface returns the default network interface
func getDefaultInterface() (string, error) {
	// Read /proc/net/route to find default interface
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}

	// Parse to find interface with destination 00000000
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) > 1 {
		fields := bytes.Fields(lines[1])
		if len(fields) > 0 {
			return string(fields[0]), nil
		}
	}

	return "", fmt.Errorf("no default interface found")
}

// GetAllInterfaces returns all non-loopback network interfaces
func GetAllInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	var result []string
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// Skip interfaces without addresses
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		result = append(result, iface.Name)
	}

	return result, nil
}

// attachPyTorchProbes attaches uprobe to PyTorch library
func (m *Manager) attachPyTorchProbes() error {
	// Find PyTorch library
	torchLib, err := findPyTorchModule()
	if err != nil {
		return fmt.Errorf("finding PyTorch library: %w", err)
	}

	// Resolve symbols from the library
	symbols, err := resolveELFSymbols(torchLib, getPyTorchSymbolPatterns())
	if err != nil {
		return fmt.Errorf("resolving PyTorch symbols in %s: %w", torchLib, err)
	}

	// Open the executable for uprobe attachment
	ex, err := link.OpenExecutable(torchLib)
	if err != nil {
		return fmt.Errorf("opening executable %s: %w", torchLib, err)
	}

	// Try to attach uprobe using resolved symbols
	var attached bool
	var lastErr error
	for _, sym := range symbols {
		l, err := ex.Uprobe(sym.Name, m.uprobeObjs.UprobeTorchLoad, nil)
		if err != nil {
			lastErr = err
			continue
		}
		m.links = append(m.links, l)
		attached = true
		log.Printf("Attached PyTorch uprobe to symbol %s at offset 0x%x", sym.Name, sym.Offset)

		// Try to attach uretprobe to the same symbol
		lr, err := ex.Uretprobe(sym.Name, m.uprobeObjs.UretprobeTorchLoad, nil)
		if err != nil {
			log.Printf("Warning: failed to attach PyTorch uretprobe to %s: %v", sym.Name, err)
		} else {
			m.links = append(m.links, lr)
		}
		break // Successfully attached, no need to try more symbols
	}

	if !attached {
		return fmt.Errorf("failed to attach PyTorch uprobe to any symbol: %w", lastErr)
	}

	log.Printf("Attached PyTorch probes to %s", torchLib)
	return nil
}

// attachPickleProbes attaches uprobe to Python pickle
func (m *Manager) attachPickleProbes() error {
	// Find _pickle C extension module
	pickleLib, err := findPickleModule()
	if err != nil {
		// Fall back to libpython if _pickle module not found
		pickleLib, err = findPythonLibrary()
		if err != nil {
			return fmt.Errorf("finding pickle module or Python library: %w", err)
		}
	}

	// Detect Python version for version-specific symbols
	pyVersion := detectPythonVersion(pickleLib)
	var patterns []string
	if pyVersion != "" {
		log.Printf("Detected Python version: %s", pyVersion)
		patterns = getPythonVersionSymbols(pyVersion)
	} else {
		patterns = getPickleSymbolPatterns()
	}

	// Resolve symbols from the library
	symbols, err := resolveELFSymbols(pickleLib, patterns)
	if err != nil {
		return fmt.Errorf("resolving pickle symbols in %s: %w", pickleLib, err)
	}

	// Open the executable for uprobe attachment
	ex, err := link.OpenExecutable(pickleLib)
	if err != nil {
		return fmt.Errorf("opening executable %s: %w", pickleLib, err)
	}

	// Try to attach uprobe using resolved symbols
	var attachedLoad bool
	var attachedReduce bool
	var lastErr error

	// Priority order for load-related symbols
	loadSymbolPriority := []string{
		"_pickle_loads", "_pickle_load", "_pickle_Unpickler_load", // Best: direct pickle functions
		"PyInit__pickle", // Good: module init (called on import)
		"PyPickleBuffer_FromObject", // Fallback: buffer operations
	}

	for _, sym := range symbols {
		symLower := strings.ToLower(sym.Name)

		// Attach to load-related symbols for UprobePickleLoad
		if !attachedLoad {
			isLoadSymbol := strings.Contains(symLower, "load") ||
				strings.Contains(symLower, "pickle") ||
				sym.Name == "PyInit__pickle" ||
				strings.HasPrefix(sym.Name, "PyPickleBuffer_")

			if isLoadSymbol {
				l, err := ex.Uprobe(sym.Name, m.uprobeObjs.UprobePickleLoad, nil)
				if err != nil {
					lastErr = err
					log.Printf("Debug: failed to attach to %s: %v", sym.Name, err)
					continue
				}
				m.links = append(m.links, l)
				attachedLoad = true
				log.Printf("Attached pickle load uprobe to symbol %s at offset 0x%x", sym.Name, sym.Offset)
			}
		}

		// Attach to reduce-related symbols for UprobePickleReduce (security-critical)
		if !attachedReduce && strings.Contains(symLower, "reduce") {
			l, err := ex.Uprobe(sym.Name, m.uprobeObjs.UprobePickleReduce, nil)
			if err != nil {
				log.Printf("Warning: failed to attach pickle reduce probe to %s: %v", sym.Name, err)
				continue
			}
			m.links = append(m.links, l)
			attachedReduce = true
			log.Printf("Attached pickle reduce uprobe to symbol %s at offset 0x%x", sym.Name, sym.Offset)
		}

		// Stop if we've attached both probes
		if attachedLoad && attachedReduce {
			break
		}
	}

	// Log if reduce probe not attached (it's optional, internal functions may not be exported)
	if !attachedReduce {
		log.Printf("Note: pickle reduce probe not attached (internal symbols not exported)")
	}

	if !attachedLoad {
		return fmt.Errorf("failed to attach pickle load uprobe to any symbol: %w", lastErr)
	}
	_ = loadSymbolPriority // Used for documentation of priority order

	log.Printf("Attached pickle probes to %s", pickleLib)
	return nil
}

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// findLibrary searches for a library matching one of the glob patterns
func findLibrary(patterns []string) (string, error) {
	for _, pattern := range patterns {
		// Expand glob pattern
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		// Return first match
		for _, match := range matches {
			if _, err := os.Stat(match); err == nil {
				return match, nil
			}
		}
	}
	return "", fmt.Errorf("no library found matching patterns: %v", patterns)
}

// findPythonLibrary finds the Python shared library
func findPythonLibrary() (string, error) {
	// Common Python library locations
	pythonPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libpython3*.so",
		"/usr/local/lib/libpython3*.so",
		"/lib/x86_64-linux-gnu/libpython3*.so",
		// Conda environments
		"/home/*/miniconda3/lib/libpython3*.so",
		"/opt/conda/lib/libpython3*.so",
	}

	// First try to find from running Python processes
	// by reading /proc/[pid]/maps
	entries, err := os.ReadDir("/proc")
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid := entry.Name()
			// Check if it's a number (PID)
			if _, err := fmt.Sscanf(pid, "%d", new(int)); err != nil {
				continue
			}
			// Read maps to find python library
			mapsPath := fmt.Sprintf("/proc/%s/maps", pid)
			mapsData, err := os.ReadFile(mapsPath)
			if err != nil {
				continue
			}
			// Look for libpython in maps
			lines := bytes.Split(mapsData, []byte{'\n'})
			for _, line := range lines {
				if bytes.Contains(line, []byte("libpython")) {
					fields := bytes.Fields(line)
					if len(fields) > 5 {
						libPath := string(fields[len(fields)-1])
						if strings.HasSuffix(libPath, ".so") {
							if _, err := os.Stat(libPath); err == nil {
								return libPath, nil
							}
						}
					}
				}
			}
		}
	}

	// Fall back to searching common paths
	return findLibrary(pythonPaths)
}
