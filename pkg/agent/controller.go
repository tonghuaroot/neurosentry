// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/neurosentry/neurosentry/pkg/bpf"
	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
)

// Controller manages the NeuroSentry agent lifecycle
type Controller struct {
	cfg        *config.Config
	bpfMgr     *bpf.Manager
	policy     *policy.Policy
	eventChan  chan Event
	metrics    *MetricsCollector
	secMetrics *SecurityMetrics
	bpfMetrics *BPFMetricsCollector

	// Event processor with sampling support
	eventProcessor *EventProcessor

	// Alert manager (set by initComponents when AlertWebhook is configured)
	alertMgr *AlertManager

	// Component management
	components []Component
	mu         sync.RWMutex

	// Shutdown
	cancel     context.CancelFunc
	shutdownWG sync.WaitGroup
}

// Component represents an agent component that can be started/stopped
type Component interface {
	Start(ctx context.Context) error
	Stop() error
	Name() string
}

// NewController creates a new agent controller
func NewController(cfg *config.Config, bpfMgr *bpf.Manager, pol *policy.Policy) (*Controller, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if bpfMgr == nil {
		return nil, fmt.Errorf("BPF manager is required")
	}
	if pol == nil {
		return nil, fmt.Errorf("policy is required")
	}

	return &Controller{
		cfg:        cfg,
		bpfMgr:     bpfMgr,
		policy:     pol,
		eventChan:  make(chan Event, 1000),
		metrics:    NewMetricsCollector(),
		secMetrics: NewSecurityMetrics(),
		bpfMetrics: NewBPFMetricsCollector(bpfMgr),
	}, nil
}

// Start starts the controller and all components
func (c *Controller) Start(ctx context.Context) error {
	ctx, c.cancel = context.WithCancel(ctx)

	log.Println("Starting NeuroSentry controller...")

	// Initialize components
	if err := c.initComponents(); err != nil {
		return fmt.Errorf("failed to initialize components: %w", err)
	}

	// Start event processor
	c.shutdownWG.Add(1)
	go c.processEvents(ctx)

	// Start trusted-PID death watcher (closes the PID-recycling TOCTOU
	// window — when a trusted process exits and the kernel later reuses
	// that PID for a new process, the new one would otherwise inherit
	// trust. The watcher prunes dead PIDs from trusted_pids on a tick.)
	c.shutdownWG.Add(1)
	go c.pruneTrustedPIDs(ctx)

	// Start the BPF ringbuf reader. The eBPF LSM hook writes
	// model_access_event records to the `events` ringbuf on every
	// blocked open; without an active user-space reader those records
	// pile up and never reach the policy engine, the [ALERT] log, or
	// the configured webhook. (Pre-1.1 the reader was missing — events
	// stayed in the ringbuf and the alert path was effectively dead.)
	if eventsMap := c.bpfMgr.EventsMap(); eventsMap != nil {
		c.shutdownWG.Add(1)
		go c.readBPFEvents(ctx, eventsMap)
	}

	// Start all components
	for _, comp := range c.components {
		log.Printf("Starting component: %s", comp.Name())
		if err := comp.Start(ctx); err != nil {
			return fmt.Errorf("failed to start component %s: %w", comp.Name(), err)
		}
	}

	// Start BPF metrics collector
	if c.bpfMetrics != nil {
		c.bpfMetrics.Start()
	}

	log.Printf("NeuroSentry controller started with %d components", len(c.components))
	return nil
}

// Stop gracefully shuts down the controller
func (c *Controller) Stop() {
	if c.cancel == nil {
		return // Not started
	}

	log.Println("Stopping NeuroSentry controller...")

	// Signal shutdown
	c.cancel()

	// Stop all components
	for _, comp := range c.components {
		log.Printf("Stopping component: %s", comp.Name())
		if err := comp.Stop(); err != nil {
			log.Printf("Error stopping component %s: %v", comp.Name(), err)
		}
	}

	// Stop BPF metrics collector
	if c.bpfMetrics != nil {
		c.bpfMetrics.Stop()
	}

	// Wait for event processor to finish
	c.shutdownWG.Wait()

	close(c.eventChan)
	log.Println("NeuroSentry controller stopped")
}

// initComponents initializes all agent components
func (c *Controller) initComponents() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Event processor component with sampling support
	sampleRate := c.cfg.Agent.EventSampleRate
	if sampleRate <= 0 {
		sampleRate = 1.0 // Default to no sampling
	}
	c.eventProcessor = NewEventProcessorWithSampling(c.eventChan, c.metrics, sampleRate)
	c.components = append(c.components, c.eventProcessor)

	if sampleRate < 1.0 {
		log.Printf("Event sampling enabled: %.1f%% of events will be processed", sampleRate*100)
	}

	// Policy engine component
	policyEngine := NewPolicyEngine(c.cfg, c.bpfMgr, c.policy, c.metrics)
	c.components = append(c.components, policyEngine)

	// Metrics server component
	metricsServer := NewMetricsServer(c.cfg.Agent.MetricsPort, c.metrics)
	c.components = append(c.components, metricsServer)

	// Alert manager if webhook configured. Stash the manager on the
	// controller so sendAlert() can actually invoke it (was previously
	// just logging "[ALERT]" with a TODO comment about wiring to the
	// alert manager; now wired).
	if c.cfg.Agent.AlertWebhook != "" {
		c.alertMgr = NewAlertManager(c.cfg.Agent.AlertWebhook, c.cfg.Agent.AlertSilenceSec)
		c.components = append(c.components, c.alertMgr)
	}

	return nil
}

// pruneTrustedPIDs periodically walks the trusted_pids BPF map and removes
// entries whose PID no longer exists in /proc. This runs every
// `PIDPruneInterval` (default 30s) and shuts down with the controller.
//
// Why: trusted_pids is keyed by PID. PIDs recycle (4M-default range, much
// smaller on busy nodes). When a trusted process exits and the kernel
// reuses its PID for an unrelated process, that new process would inherit
// trust without any explicit grant. Periodic pruning closes that window
// to roughly the prune interval.
func (c *Controller) pruneTrustedPIDs(ctx context.Context) {
	defer c.shutdownWG.Done()

	interval := c.cfg.Agent.PIDPruneInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := c.bpfMgr.PruneDeadTrustedPIDs()
			if err != nil {
				log.Printf("trusted-PID pruner: %v", err)
				continue
			}
			if n > 0 {
				log.Printf("SECURITY: pruned %d dead PID(s) from trusted_pids", n)
				if c.secMetrics != nil {
					c.secMetrics.RecordPIDsPruned(n)
				}
			}
		}
	}
}

// readBPFEvents pulls records from the LSM events ringbuf and forwards
// parsed Events into c.eventChan. Closes the reader on context cancel.
func (c *Controller) readBPFEvents(ctx context.Context, m interface{ Close() error }) {
	defer c.shutdownWG.Done()

	em, ok := c.bpfMgr.EventsMap(), true
	if em == nil {
		ok = false
	}
	if !ok {
		log.Printf("ringbuf reader: events map not available")
		return
	}

	rd, err := ringbuf.NewReader(em)
	if err != nil {
		log.Printf("ringbuf reader: failed to open: %v", err)
		return
	}
	defer rd.Close()

	// Close the reader on context cancel so the blocking Read() returns.
	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	log.Println("ringbuf reader: started")
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				log.Println("ringbuf reader: shutting down")
				return
			}
			log.Printf("ringbuf reader: read error: %v", err)
			continue
		}
		event, perr := ParseEvent(rec)
		if perr != nil {
			log.Printf("ringbuf reader: parse error: %v", perr)
			continue
		}
		select {
		case c.eventChan <- event:
		case <-ctx.Done():
			return
		default:
			// channel full; drop and bump bpf_errors counter so the
			// operator knows the user-space pipeline is back-pressured.
			if c.secMetrics != nil {
				c.secMetrics.RecordError("ringbuf_reader", "event_chan_full")
			}
		}
	}
}

// processEvents processes events from the BPF layer
func (c *Controller) processEvents(ctx context.Context) {
	defer c.shutdownWG.Done()

	for {
		select {
		case <-ctx.Done():
			log.Println("Event processor shutting down...")
			return

		case event := <-c.eventChan:
			c.handleEvent(event)
		}
	}
}

// handleEvent handles a single event
func (c *Controller) handleEvent(event Event) {
	// Always process high/critical severity events
	// Apply sampling only to info-level events
	if event.Severity != "high" && event.Severity != "critical" {
		if c.eventProcessor != nil && !c.eventProcessor.ShouldSample() {
			return // Skip this event due to sampling
		}
	}

	// Update metrics
	c.metrics.RecordEvent(event)

	// Check if action needed based on policy
	action := c.policy.Evaluate(event)

	switch action {
	case policy.ActionAllow:
		// Event allowed, just logged

	case policy.ActionAlert:
		c.sendAlert(event)

	case policy.ActionBlock:
		c.handleBlock(event)
		// Block events also fire the alert path so the operator's
		// webhook / SOC pipeline sees what was blocked.
		c.sendAlert(event)
	}

	// Also fire an alert for any high/critical-severity event the
	// kernel surfaced — even if the YAML policy returned ActionAllow,
	// these are events the operator wants to know about (e.g. an LSM
	// `file_blocked` was already enforced by the kernel; the alert
	// path is what gets it to the SOC).
	if action == policy.ActionAllow && (event.Severity == "high" || event.Severity == "critical") {
		c.sendAlert(event)
	}
}

// sendAlert sends an alert for an event. Logs locally and forwards to the
// configured webhook (with rate limiting / silence period applied by
// AlertManager). No-op for the webhook side when no webhook is configured.
func (c *Controller) sendAlert(event Event) {
	log.Printf("[ALERT] %s pid=%d severity=%s file=%s",
		event.Type, event.Source.PID, event.Severity, event.Data.FilePath)

	if c.alertMgr != nil {
		if err := c.alertMgr.SendAlert(event); err != nil {
			log.Printf("alert webhook send failed: %v", err)
			if c.secMetrics != nil {
				c.secMetrics.RecordWebhookSent("error")
			}
		} else if c.secMetrics != nil {
			c.secMetrics.RecordWebhookSent("ok")
		}
	}
}

// handleBlock handles a blocked event
func (c *Controller) handleBlock(event Event) {
	log.Printf("[BLOCKED] %s: %+v", event.Type, event)

	// Additional handling for blocked events
	// Could include process termination, container shutdown, etc.
}

// GetMetrics returns the current metrics
func (c *Controller) GetMetrics() map[string]interface{} {
	return c.metrics.Snapshot()
}

// GetSecurityMetrics returns the security metrics collector
func (c *Controller) GetSecurityMetrics() *SecurityMetrics {
	return c.secMetrics
}

// Status returns the controller status
func (c *Controller) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	componentStatus := make(map[string]string)
	for _, comp := range c.components {
		componentStatus[comp.Name()] = "running"
	}

	return Status{
		Running:         true,
		Components:      componentStatus,
		EventsProcessed: c.metrics.TotalEvents(),
		ThreatsDetected: c.metrics.TotalThreats(),
	}
}

// Status represents the controller status
type Status struct {
	Running         bool              `json:"running"`
	Components      map[string]string `json:"components"`
	EventsProcessed int64             `json:"events_processed"`
	ThreatsDetected int64             `json:"threats_detected"`
}
