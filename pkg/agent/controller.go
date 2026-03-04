// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/neurosentry/neurosentry/pkg/bpf"
	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
)

// Controller manages the NeuroSentry agent lifecycle
type Controller struct {
	cfg       *config.Config
	bpfMgr    *bpf.Manager
	policy    *policy.Policy
	eventChan chan Event
	metrics   *MetricsCollector
	secMetrics *SecurityMetrics
	bpfMetrics *BPFMetricsCollector

	// Event processor with sampling support
	eventProcessor *EventProcessor

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

	// Alert manager if webhook configured
	if c.cfg.Agent.AlertWebhook != "" {
		alertMgr := NewAlertManager(c.cfg.Agent.AlertWebhook, c.cfg.Agent.AlertSilenceSec)
		c.components = append(c.components, alertMgr)
	}

	return nil
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
	}
}

// sendAlert sends an alert for an event
func (c *Controller) sendAlert(event Event) {
	log.Printf("[ALERT] %s: %+v", event.Type, event)

	// In production, this would send to the alert manager
	// which handles rate limiting and webhook delivery
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
