// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsCollector collects and exposes metrics
type MetricsCollector struct {
	mu sync.RWMutex

	// Prometheus metrics
	eventsTotal       *prometheus.CounterVec
	eventsByType      *prometheus.CounterVec
	threatsTotal      *prometheus.CounterVec
	bpfErrors         prometheus.Counter
	processingTime    *prometheus.HistogramVec
	activeConnections prometheus.Gauge

	// Local counters
	eventCount  int64
	threatCount int64
	lastEvent   time.Time
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	mc := &MetricsCollector{
		eventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_events_total",
				Help: "Total number of events processed",
			},
			[]string{"status"},
		),
		eventsByType: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_events_by_type_total",
				Help: "Total number of events by type",
			},
			[]string{"event_type"},
		),
		threatsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_threats_total",
				Help: "Total number of threats detected",
			},
			[]string{"threat_type", "severity"},
		),
		bpfErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "neurosentry_bpf_errors_total",
				Help: "Total number of BPF errors",
			},
		),
		processingTime: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "neurosentry_event_processing_seconds",
				Help:    "Time spent processing events",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"stage"},
		),
		activeConnections: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "neurosentry_active_connections",
				Help: "Number of active network connections being monitored",
			},
		),
	}

	// Register metrics with default registry
	prometheus.MustRegister(
		mc.eventsTotal,
		mc.eventsByType,
		mc.threatsTotal,
		mc.bpfErrors,
		mc.processingTime,
		mc.activeConnections,
	)

	return mc
}

// RecordEvent records an event
func (m *MetricsCollector) RecordEvent(event Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.eventCount++
	m.lastEvent = time.Now()

	// Update counters
	m.eventsTotal.WithLabelValues("processed").Inc()
	m.eventsByType.WithLabelValues(string(event.Type)).Inc()

	// Track threats
	if event.Severity == "high" || event.Severity == "critical" {
		m.threatCount++
		m.threatsTotal.WithLabelValues(string(event.Type), event.Severity).Inc()
	}
}

// RecordBPFError records a BPF error
func (m *MetricsCollector) RecordBPFError() {
	m.bpfErrors.Inc()
}

// RecordProcessingTime records event processing time
func (m *MetricsCollector) RecordProcessingTime(stage string, duration time.Duration) {
	m.processingTime.WithLabelValues(stage).Observe(duration.Seconds())
}

// TotalEvents returns the total number of events processed
func (m *MetricsCollector) TotalEvents() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.eventCount
}

// TotalThreats returns the total number of threats detected
func (m *MetricsCollector) TotalThreats() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.threatCount
}

// Snapshot returns a snapshot of current metrics
func (m *MetricsCollector) Snapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"events_processed": m.eventCount,
		"threats_detected": m.threatCount,
		"last_event_time":  m.lastEvent,
	}
}

// MetricsServer serves metrics over HTTP
type MetricsServer struct {
	port    int
	metrics *MetricsCollector
	server  *http.Server
}

// NewMetricsServer creates a new metrics server
func NewMetricsServer(port int, metrics *MetricsCollector) *MetricsServer {
	return &MetricsServer{
		port:    port,
		metrics: metrics,
	}
}

// Name returns the component name
func (m *MetricsServer) Name() string {
	return "metrics-server"
}

// Start starts the metrics server
func (m *MetricsServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body><h1>NeuroSentry Metrics</h1><p><a href="/metrics">Prometheus Metrics</a></p></body></html>`))
	})

	m.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", m.port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Metrics server listening on :%d", m.port)
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the metrics server
func (m *MetricsServer) Stop() error {
	if m.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return m.server.Shutdown(ctx)
	}
	return nil
}

// EventProcessor processes events from the BPF layer
type EventProcessor struct {
	eventChan   chan Event
	metrics     *MetricsCollector
	sampleRate  float64 // 0.0-1.0, 1.0 = no sampling
	sampleCount uint64  // Counter for deterministic sampling
}

// NewEventProcessor creates a new event processor
func NewEventProcessor(eventChan chan Event, metrics *MetricsCollector) *EventProcessor {
	return &EventProcessor{
		eventChan:  eventChan,
		metrics:    metrics,
		sampleRate: 1.0, // No sampling by default
	}
}

// NewEventProcessorWithSampling creates a new event processor with sampling
func NewEventProcessorWithSampling(eventChan chan Event, metrics *MetricsCollector, sampleRate float64) *EventProcessor {
	if sampleRate <= 0 {
		sampleRate = 0.01 // Minimum 1%
	}
	if sampleRate > 1.0 {
		sampleRate = 1.0
	}
	return &EventProcessor{
		eventChan:  eventChan,
		metrics:    metrics,
		sampleRate: sampleRate,
	}
}

// ShouldSample determines if an event should be sampled
// Uses deterministic sampling based on counter for consistent behavior
func (e *EventProcessor) ShouldSample() bool {
	if e.sampleRate >= 1.0 {
		return true // No sampling
	}
	e.sampleCount++
	// Sample every N events where N = 1/sampleRate
	sampleInterval := uint64(1.0 / e.sampleRate)
	return e.sampleCount%sampleInterval == 0
}

// SetSampleRate updates the sampling rate (thread-safe for hot reload)
func (e *EventProcessor) SetSampleRate(rate float64) {
	if rate <= 0 {
		rate = 0.01
	}
	if rate > 1.0 {
		rate = 1.0
	}
	e.sampleRate = rate
}

// Name returns the component name
func (e *EventProcessor) Name() string {
	return "event-processor"
}

// Start starts the event processor
func (e *EventProcessor) Start(ctx context.Context) error {
	// The event processing is done in the controller's processEvents loop
	// This component mainly sets up any additional processing needed
	return nil
}

// Stop stops the event processor
func (e *EventProcessor) Stop() error {
	return nil
}

// AlertManager handles alert notifications
type AlertManager struct {
	webhookURL string
	silenceSec int
	lastAlert  map[string]time.Time
	mu         sync.RWMutex
}

// NewAlertManager creates a new alert manager
func NewAlertManager(webhookURL string, silenceSec int) *AlertManager {
	return &AlertManager{
		webhookURL: webhookURL,
		silenceSec: silenceSec,
		lastAlert:  make(map[string]time.Time),
	}
}

// Name returns the component name
func (a *AlertManager) Name() string {
	return "alert-manager"
}

// Start starts the alert manager
func (a *AlertManager) Start(ctx context.Context) error {
	return nil
}

// Stop stops the alert manager
func (a *AlertManager) Stop() error {
	return nil
}

// SendAlert sends an alert (with rate limiting)
func (a *AlertManager) SendAlert(event Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := fmt.Sprintf("%s:%d", event.Type, event.Source.PID)

	// Check silence period
	if lastTime, exists := a.lastAlert[key]; exists {
		if time.Since(lastTime) < time.Duration(a.silenceSec)*time.Second {
			return nil // Silenced
		}
	}

	a.lastAlert[key] = time.Now()

	// Send webhook
	if a.webhookURL == "" {
		log.Printf("[ALERT] No webhook configured: %+v", event)
		return nil
	}

	go a.sendWebhookAsync(event)
	return nil
}

// sendWebhookAsync sends the webhook asynchronously
func (a *AlertManager) sendWebhookAsync(event Event) {
	payload := map[string]interface{}{
		"type":      event.Type,
		"timestamp": event.Timestamp.Format(time.RFC3339),
		"severity":  event.Severity,
		"source": map[string]interface{}{
			"pid":  event.Source.PID,
			"uid":  event.Source.UID,
			"comm": event.Source.Comm,
		},
		"data": event.Data,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[ALERT] Failed to marshal webhook payload: %v", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(a.webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[ALERT] Failed to send webhook to %s: %v", a.webhookURL, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		log.Printf("[ALERT] Webhook returned error status %d", resp.StatusCode)
		return
	}

	log.Printf("[ALERT] Webhook sent successfully to %s", a.webhookURL)
}
