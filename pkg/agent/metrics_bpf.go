// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux
// +build linux

package agent

import (
	"sync"
	"time"

	"github.com/neurosentry/neurosentry/pkg/bpf"
	"github.com/prometheus/client_golang/prometheus"
)

// BPFMetricsCollector collects metrics from eBPF programs
type BPFMetricsCollector struct {
	bpfMgr *bpf.Manager

	// LSM Stats
	lsmAccessAttempts prometheus.Gauge
	lsmBlockedAccess  prometheus.Gauge
	lsmProtectedFiles prometheus.Gauge

	// XDP Stats
	xdpTotalPackets   prometheus.Gauge
	xdpPassedPackets  prometheus.Gauge
	xdpDroppedPackets prometheus.Gauge

	// Uprobe Stats
	uprobeModelLoads   prometheus.Gauge
	uprobePickleLoads  prometheus.Gauge
	uprobeDangerousOps prometheus.Gauge

	startTime time.Time
	stopCh    chan struct{}
	mu        sync.Mutex
}

// NewBPFMetricsCollector creates a new BPF metrics collector
func NewBPFMetricsCollector(bpfMgr *bpf.Manager) *BPFMetricsCollector {
	c := &BPFMetricsCollector{
		bpfMgr: bpfMgr,
		stopCh: make(chan struct{}),

		// LSM metrics (File Integrity Monitoring)
		lsmAccessAttempts: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "neurosentry_lsm_access_attempts_total",
			Help: "Total file access attempts monitored by LSM",
		}),
		lsmBlockedAccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "neurosentry_lsm_blocked_total",
			Help: "Total file accesses blocked by LSM",
		}),
		lsmProtectedFiles: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "neurosentry_lsm_protected_files_seen",
			Help: "Number of protected files seen",
		}),

		// XDP metrics (Network Containment)
		xdpTotalPackets: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "neurosentry_xdp_packets_total",
			Help: "Total packets processed by XDP",
		}),
		xdpPassedPackets: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "neurosentry_xdp_passed_total",
			Help: "Packets passed by XDP filter",
		}),
		xdpDroppedPackets: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "neurosentry_xdp_dropped_total",
			Help: "Packets dropped by XDP filter",
		}),

		// Uprobe metrics (PyTorch/Pickle monitoring)
		uprobeModelLoads: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "neurosentry_uprobe_model_loads_total",
			Help: "Total model loads monitored by uprobes",
		}),
		uprobePickleLoads: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "neurosentry_uprobe_pickle_loads_total",
			Help: "Total pickle loads monitored",
		}),
		uprobeDangerousOps: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "neurosentry_uprobe_dangerous_ops_total",
			Help: "Dangerous pickle operations detected",
		}),

		startTime: time.Now(),
	}

	// Register all metrics
	prometheus.MustRegister(
		c.lsmAccessAttempts,
		c.lsmBlockedAccess,
		c.lsmProtectedFiles,
		c.xdpTotalPackets,
		c.xdpPassedPackets,
		c.xdpDroppedPackets,
		c.uprobeModelLoads,
		c.uprobePickleLoads,
		c.uprobeDangerousOps,
	)

	return c
}

// Start starts the metrics collection loop
func (c *BPFMetricsCollector) Start() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.collect()
			}
		}
	}()
}

// Stop stops the metrics collection
func (c *BPFMetricsCollector) Stop() {
	close(c.stopCh)
}

// collect collects metrics from eBPF programs
func (c *BPFMetricsCollector) collect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.bpfMgr == nil {
		return
	}

	// Collect LSM stats
	if stats, err := c.bpfMgr.GetStats(); err == nil && stats != nil {
		c.lsmAccessAttempts.Set(float64(stats.TotalAccessAttempts))
		c.lsmBlockedAccess.Set(float64(stats.BlockedAccess))
		c.lsmProtectedFiles.Set(float64(stats.ProtectedFilesSeen))
	}

	// Collect TC stats (replaces XDP for better cloud compatibility)
	if stats, err := c.bpfMgr.GetTCStats(); err == nil && stats != nil {
		if v, ok := stats["total_packets"]; ok {
			c.xdpTotalPackets.Set(float64(v))
		}
		// Map ingress+egress to passed (all packets pass in monitor mode)
		if ingress, ok := stats["ingress_packets"]; ok {
			if egress, ok2 := stats["egress_packets"]; ok2 {
				c.xdpPassedPackets.Set(float64(ingress + egress))
			}
		}
		// Use suspicious_packets for dropped metric (monitor-only, shows what would be blocked)
		if v, ok := stats["suspicious_packets"]; ok {
			c.xdpDroppedPackets.Set(float64(v))
		}
	} else if stats, err := c.bpfMgr.GetXDPStats(); err == nil && stats != nil {
		// Fallback to XDP stats if TC not available
		if v, ok := stats["total_packets"]; ok {
			c.xdpTotalPackets.Set(float64(v))
		}
		if v, ok := stats["passed_packets"]; ok {
			c.xdpPassedPackets.Set(float64(v))
		}
		if v, ok := stats["suspicious_packets"]; ok {
			c.xdpDroppedPackets.Set(float64(v))
		}
	}

	// Collect Uprobe stats
	if stats, err := c.bpfMgr.GetUprobeStats(); err == nil && stats != nil {
		if v, ok := stats["model_loads"]; ok {
			c.uprobeModelLoads.Set(float64(v))
		}
		if v, ok := stats["pickle_loads"]; ok {
			c.uprobePickleLoads.Set(float64(v))
		}
		if v, ok := stats["dangerous_pickles"]; ok {
			c.uprobeDangerousOps.Set(float64(v))
		}
	}
}
