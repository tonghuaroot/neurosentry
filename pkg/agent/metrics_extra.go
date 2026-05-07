// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	metricsRegistered bool
	metricsRegisterMu sync.Mutex
)

// SecurityMetrics contains security-specific metrics
type SecurityMetrics struct {
	// Model access metrics
	modelAccessTotal   *prometheus.CounterVec
	modelAccessBlocked *prometheus.CounterVec
	modelAccessByExt   *prometheus.CounterVec

	// Network metrics
	networkBlocked       *prometheus.CounterVec
	networkExfilAttempts *prometheus.CounterVec

	// Framework metrics
	pyTorchLoadsTotal    *prometheus.CounterVec
	tensorFlowLoadsTotal *prometheus.CounterVec
	onnxLoadsTotal       *prometheus.CounterVec

	// Pickle metrics
	pickleLoadsTotal        *prometheus.CounterVec
	pickleDangerousDetected *prometheus.CounterVec

	// Operational metrics
	errorsTotal      *prometheus.CounterVec
	webhookSentTotal *prometheus.CounterVec
	policyReloads    prometheus.Counter
	configReloads    prometheus.Counter
	uptime           prometheus.Gauge
	lastEventTime    prometheus.Gauge
	pidsPrunedTotal  prometheus.Counter

	mu sync.RWMutex
}

// RecordPIDsPruned bumps the counter for trusted PIDs removed by the
// periodic pruner (PID-recycle defence). Safe to call from any goroutine.
func (m *SecurityMetrics) RecordPIDsPruned(n int) {
	if m == nil || m.pidsPrunedTotal == nil || n <= 0 {
		return
	}
	m.pidsPrunedTotal.Add(float64(n))
}

// NewSecurityMetrics creates security-specific metrics
func NewSecurityMetrics() *SecurityMetrics {
	m := &SecurityMetrics{
		modelAccessTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_model_access_total",
				Help: "Total number of model file access attempts",
			},
			[]string{"status", "extension"},
		),
		modelAccessBlocked: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_model_access_blocked_total",
				Help: "Number of blocked model access attempts",
			},
			[]string{"extension"},
		),
		modelAccessByExt: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_model_access_by_extension_total",
				Help: "Model access by file extension",
			},
			[]string{"extension"},
		),
		networkBlocked: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_network_blocked_total",
				Help: "Number of blocked network packets",
			},
			[]string{"reason"},
		),
		networkExfilAttempts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_exfil_attempts_total",
				Help: "Number of detected exfiltration attempts",
			},
			[]string{"status"},
		),
		pyTorchLoadsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_pytorch_loads_total",
				Help: "Total PyTorch model load events",
			},
			[]string{"stage"},
		),
		tensorFlowLoadsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_tensorflow_loads_total",
				Help: "Total TensorFlow model load events",
			},
			[]string{"stage"},
		),
		onnxLoadsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_onnx_loads_total",
				Help: "Total ONNX model load events",
			},
			[]string{"stage"},
		),
		pickleLoadsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_pickle_loads_total",
				Help: "Total pickle deserialization events",
			},
			[]string{"status"},
		),
		pickleDangerousDetected: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_pickle_dangerous_total",
				Help: "Number of dangerous pickle operations detected",
			},
			[]string{"symbol"},
		),
		errorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_errors_total",
				Help: "Total number of errors by component and type",
			},
			[]string{"component", "error_type"},
		),
		webhookSentTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "neurosentry_webhook_sent_total",
				Help: "Total number of webhook notifications sent",
			},
			[]string{"status"},
		),
		policyReloads: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "neurosentry_policy_reloads_total",
				Help: "Total number of policy reloads",
			},
		),
		configReloads: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "neurosentry_config_reloads_total",
				Help: "Total number of configuration reloads",
			},
		),
		uptime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "neurosentry_uptime_seconds",
				Help: "Agent uptime in seconds",
			},
		),
		lastEventTime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "neurosentry_last_event_timestamp",
				Help: "Timestamp of the last processed event",
			},
		),
		pidsPrunedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "neurosentry_trusted_pids_pruned_total",
				Help: "Number of trusted PIDs removed by the periodic PID-death watcher",
			},
		),
	}

	// Register metrics (only once globally)
	metricsRegisterMu.Lock()
	defer metricsRegisterMu.Unlock()
	if !metricsRegistered {
		prometheus.MustRegister(m.modelAccessTotal)
		prometheus.MustRegister(m.modelAccessBlocked)
		prometheus.MustRegister(m.modelAccessByExt)
		prometheus.MustRegister(m.networkBlocked)
		prometheus.MustRegister(m.networkExfilAttempts)
		prometheus.MustRegister(m.pyTorchLoadsTotal)
		prometheus.MustRegister(m.tensorFlowLoadsTotal)
		prometheus.MustRegister(m.onnxLoadsTotal)
		prometheus.MustRegister(m.pickleLoadsTotal)
		prometheus.MustRegister(m.pickleDangerousDetected)
		prometheus.MustRegister(m.errorsTotal)
		prometheus.MustRegister(m.webhookSentTotal)
		prometheus.MustRegister(m.policyReloads)
		prometheus.MustRegister(m.configReloads)
		prometheus.MustRegister(m.uptime)
		prometheus.MustRegister(m.lastEventTime)
		prometheus.MustRegister(m.pidsPrunedTotal)
		metricsRegistered = true
	}

	return m
}

// RecordModelAccess records a model access event
func (m *SecurityMetrics) RecordModelAccess(status string, extension string, blocked bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if blocked {
		m.modelAccessBlocked.WithLabelValues(extension).Inc()
	}
	m.modelAccessTotal.WithLabelValues(status, extension).Inc()
	m.modelAccessByExt.WithLabelValues(extension).Inc()
}

// RecordNetworkBlocked records a blocked network packet
func (m *SecurityMetrics) RecordNetworkBlocked(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.networkBlocked.WithLabelValues(reason).Inc()
}

// RecordExfilAttempt records an exfiltration attempt
func (m *SecurityMetrics) RecordExfilAttempt(status string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.networkExfilAttempts.WithLabelValues(status).Inc()
}

// RecordFrameworkLoad records a model load event
func (m *SecurityMetrics) RecordFrameworkLoad(framework string, stage string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch framework {
	case "pytorch":
		m.pyTorchLoadsTotal.WithLabelValues(stage).Inc()
	case "tensorflow":
		m.tensorFlowLoadsTotal.WithLabelValues(stage).Inc()
	case "onnx":
		m.onnxLoadsTotal.WithLabelValues(stage).Inc()
	}
}

// RecordPickleLoad records a pickle event
func (m *SecurityMetrics) RecordPickleLoad(status string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pickleLoadsTotal.WithLabelValues(status).Inc()
}

// RecordPickleDangerous records a dangerous pickle operation
func (m *SecurityMetrics) RecordPickleDangerous(symbol string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pickleDangerousDetected.WithLabelValues(symbol).Inc()
}

// RecordError records an error occurrence
func (m *SecurityMetrics) RecordError(component, errorType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.errorsTotal.WithLabelValues(component, errorType).Inc()
}

// RecordWebhookSent records a webhook send attempt
func (m *SecurityMetrics) RecordWebhookSent(status string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.webhookSentTotal.WithLabelValues(status).Inc()
}

// RecordPolicyReload records a policy reload event
func (m *SecurityMetrics) RecordPolicyReload() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.policyReloads.Inc()
}

// RecordConfigReload records a config reload event
func (m *SecurityMetrics) RecordConfigReload() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.configReloads.Inc()
}

// SetUptime sets the current uptime value
func (m *SecurityMetrics) SetUptime(seconds float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.uptime.Set(seconds)
}

// SetLastEventTime sets the last event timestamp
func (m *SecurityMetrics) SetLastEventTime(timestamp float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastEventTime.Set(timestamp)
}
