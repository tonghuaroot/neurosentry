// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log"
	"sync"

	bpfpkg "github.com/tonghuaroot/neurosentry/pkg/bpf"
	"github.com/tonghuaroot/neurosentry/pkg/config"
	"github.com/tonghuaroot/neurosentry/pkg/policy"
)

// PolicyEngine evaluates events against security policies
type PolicyEngine struct {
	cfg     *config.Config
	bpfMgr  *bpfpkg.Manager
	policy  *policy.Policy
	metrics *MetricsCollector

	mu sync.RWMutex
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(cfg *config.Config, bpfMgr *bpfpkg.Manager, pol *policy.Policy, metrics *MetricsCollector) *PolicyEngine {
	return &PolicyEngine{
		cfg:     cfg,
		bpfMgr:  bpfMgr,
		policy:  pol,
		metrics: metrics,
	}
}

// Name returns the component name
func (p *PolicyEngine) Name() string {
	return "policy-engine"
}

// Start starts the policy engine
func (p *PolicyEngine) Start(ctx context.Context) error {
	log.Println("Policy engine started")

	// Initial policy application
	if err := p.applyPolicy(); err != nil {
		return fmt.Errorf("failed to apply initial policy: %w", err)
	}

	return nil
}

// Stop stops the policy engine
func (p *PolicyEngine) Stop() error {
	log.Println("Policy engine stopped")
	return nil
}

// Evaluate evaluates an event against the policy
func (p *PolicyEngine) Evaluate(event Event) policy.Action {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check each rule in order
	for _, rule := range p.policy.Rules {
		if rule.Matches(event) {
			log.Printf("Policy rule matched: %s -> %s", rule.Name, rule.Action)
			return rule.Action
		}
	}

	// Default: allow if no rule matched
	return policy.ActionAllow
}

// applyPolicy applies the current policy to the BPF layer
func (p *PolicyEngine) applyPolicy() error {
	// Apply trusted PIDs
	for _, pid := range p.cfg.Protection.ModelFIM.TrustedPIDs {
		if err := p.bpfMgr.AddTrustedPID(uint32(pid)); err != nil { //nolint:gosec // G115: PID conversion is safe
			log.Printf("Warning: failed to add trusted PID %d: %v", pid, err)
		}
	}

	// Apply protected extensions
	for _, ext := range p.cfg.Protection.ModelFIM.ProtectedExtensions {
		if err := p.bpfMgr.AddProtectedExtension(ext); err != nil {
			log.Printf("Warning: failed to add protected extension %s: %v", ext, err)
		}
	}

	// Apply network allowlist
	for _, cidr := range p.cfg.Protection.NetworkContainment.AllowedEgress {
		if err := p.bpfMgr.AddAllowedIP(cidr); err != nil {
			log.Printf("Warning: failed to add allowed IP %s: %v", cidr, err)
		}
	}

	// Apply dangerous symbols for pickle detection
	for _, symbol := range p.cfg.Protection.PickleProtection.DangerousSymbols {
		if err := p.bpfMgr.AddDangerousSymbol(symbol); err != nil {
			log.Printf("Warning: failed to add dangerous symbol %s: %v", symbol, err)
		}
	}

	return nil
}

// ReloadPolicy reloads the policy from disk
func (p *PolicyEngine) ReloadPolicy() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	loader, err := policy.NewLoader(p.cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to create policy loader: %w", err)
	}

	newPolicy, err := loader.Load()
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	p.policy = newPolicy
	log.Println("Policy reloaded successfully")

	return p.applyPolicy()
}
