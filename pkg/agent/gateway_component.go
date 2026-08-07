// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/neurosentry/neurosentry/pkg/aigateway"
	"github.com/neurosentry/neurosentry/pkg/aiguard"
	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/config"
)

// gatewayComponent runs the inline AI gateway as a managed daemon component on
// its own listener, routing gateway events to the audit chain and metrics.
type gatewayComponent struct {
	gw      *aigateway.Gateway
	vault   *aigateway.MemKeyVault
	usage   *aigateway.UsageTracker
	addr    string
	server  *http.Server
	audit   *audit.Chain
	metrics *SecurityMetrics
}

func newGatewayComponent(cfg config.GatewayConfig, auditChain *audit.Chain, sec *SecurityMetrics) *gatewayComponent {
	vault := aigateway.NewMemKeyVault()
	usage := aigateway.NewUsageTracker()
	quota := aigateway.NewQuotaManager()
	up := aigateway.NewHTTPUpstream(vault)

	guards := []aigateway.Guard{
		aigateway.NewInjectionGuard(aiguard.NewInjectionDetector(), aiguard.VerdictMalicious),
		aigateway.NewDLPGuard(aiguard.NewSecretScanner()),
	}
	gwCfg := aigateway.Config{
		BlockOnDetect:    cfg.BlockOnDetect,
		AllowedProviders: cfg.AllowedProviders,
		DefaultProvider:  cfg.DefaultProvider,
	}
	// Response-side DLP so model output leaking secrets is caught too.
	outGuards := []aigateway.Guard{aigateway.NewDLPGuard(aiguard.NewSecretScanner())}
	gw := aigateway.New(gwCfg, up, guards, outGuards).WithMetering(quota, usage)

	c := &gatewayComponent{gw: gw, vault: vault, usage: usage, addr: cfg.ListenAddr, audit: auditChain, metrics: sec}
	gw.OnEvent(c.onEvent)
	return c
}

func (c *gatewayComponent) Name() string { return "ai-gateway" }

func (c *gatewayComponent) Start(_ context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/v1/chat/completions", c.gw)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	c.server = &http.Server{Addr: c.addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("AI gateway listening on %s", c.addr)
		if err := c.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("AI gateway error: %v", err)
		}
	}()
	return nil
}

func (c *gatewayComponent) Stop() error {
	if c.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return c.server.Shutdown(ctx)
	}
	return nil
}

// onEvent routes a gateway request outcome to metrics and, when blocked, into
// the tamper-proof audit chain.
func (c *gatewayComponent) onEvent(e aigateway.GatewayEvent) {
	if c.metrics != nil {
		c.metrics.RecordGatewayRequest(e.Provider, e.Action)
	}
	if e.Action == "blocked" && c.audit != nil {
		sev := audit.SeverityHigh
		entry := audit.NewEntry("gateway_blocked", sev, map[string]any{
			"provider": e.Provider,
			"model":    e.Model,
			"reason":   e.Reason,
			"tenant":   e.Tenant,
		})
		entry.SetCategory(audit.CategorySecurity, audit.ClassFinding)
		_ = c.audit.Append(entry)
	}
}

func (c *gatewayComponent) description() string {
	return fmt.Sprintf("AI gateway on %s (block_on_detect wired, per-tenant key custody + metering)", c.addr)
}
