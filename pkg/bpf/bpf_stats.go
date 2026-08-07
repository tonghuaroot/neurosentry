// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bpf

// StatisticsMapKey is the key for the stats map
type StatisticsMapKey uint32

// Stats represents BPF statistics
type Stats struct {
	TotalAccessAttempts uint64
	BlockedAccess       uint64
	ProtectedFilesSeen  uint64
}

// GetStats retrieves BPF statistics
func (m *Manager) GetStats() (*Stats, error) {
	if m.lsmObjs == nil {
		return &Stats{}, nil
	}

	key := StatisticsMapKey(0)
	var value NeuroSentryLSMStats
	if err := m.lsmObjs.StatsMap.Lookup(&key, &value); err != nil {
		return &Stats{}, err
	}

	return &Stats{
		TotalAccessAttempts: value.TotalAccessAttempts,
		BlockedAccess:       value.BlockedAccess,
		ProtectedFilesSeen:  value.AllowedAccess,
	}, nil
}

// GetXDPStats retrieves XDP statistics
func (m *Manager) GetXDPStats() (map[string]uint64, error) {
	if m.xdpObjs == nil {
		return nil, nil
	}

	stats := make(map[string]uint64)
	key := uint32(0)
	var value NeuroSentryXDPXdpStats

	// Get XDP stats
	if err := m.xdpObjs.XdpStatsMap.Lookup(&key, &value); err != nil {
		return stats, err
	}

	stats["total_packets"] = value.TotalPackets
	stats["passed_packets"] = value.PassedPackets
	stats["suspicious_packets"] = value.SuspiciousPackets
	stats["exfil_attempts"] = value.ExfilAttempts

	return stats, nil
}

// GetUprobeStats retrieves Uprobe statistics
func (m *Manager) GetUprobeStats() (map[string]uint64, error) {
	if m.uprobeObjs == nil {
		return nil, nil
	}

	stats := make(map[string]uint64)
	key := uint32(0)
	var value NeuroSentryUprobeUprobeStats

	// Get Uprobe stats
	if err := m.uprobeObjs.UprobeStatsMap.Lookup(&key, &value); err != nil {
		return stats, err
	}

	stats["model_loads"] = value.ModelLoadsTotal
	stats["pickle_loads"] = value.PickleLoadsTotal
	stats["dangerous_pickles"] = value.DangerousPickles

	return stats, nil
}

// GetTCStats retrieves TC (Traffic Control) statistics
func (m *Manager) GetTCStats() (map[string]uint64, error) {
	if m.tcObjs == nil {
		return nil, nil
	}

	stats := make(map[string]uint64)
	key := uint32(0)
	var value NeuroSentryTCNsTcStats

	// Get TC stats
	if err := m.tcObjs.NsTcStatsMap.Lookup(&key, &value); err != nil {
		return stats, err
	}

	stats["total_packets"] = value.TotalPackets
	stats["ingress_packets"] = value.IngressPackets
	stats["egress_packets"] = value.EgressPackets
	stats["suspicious_packets"] = value.SuspiciousPackets
	stats["bytes_in"] = value.BytesIn
	stats["bytes_out"] = value.BytesOut

	return stats, nil
}
