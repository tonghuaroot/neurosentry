// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/neurosentry/neurosentry/pkg/agent"
	"github.com/neurosentry/neurosentry/pkg/bpf"
	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "neurosentry",
	Short: "The eBPF-based Guardian for AI Inference Integrity",
	Long: `NeuroSentry is a runtime protection system for AI inference environments
that leverages eBPF technology to monitor and secure machine learning model
assets at the kernel level.`,
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	Run:     run,
}

var (
	cfgFile  string
	logLevel string
	skipBPF  bool
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/neurosentry/config.yaml", "Configuration file path")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().BoolVar(&skipBPF, "skip-bpf", false, "Skip eBPF loading (for development on non-Linux)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func run(cmd *cobra.Command, args []string) {
	// Load configuration
	cfg, err := config.Load(cfgFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set log level
	setupLogging(logLevel)

	log.Printf("Starting NeuroSentry %s", version)
	log.Printf("eBPF-based AI Inference Protection System")
	log.Printf("Configuration loaded from: %s", cfgFile)

	// Initialize context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load policy
	policyLoader, err := policy.NewLoader(cfg.PolicyPath)
	if err != nil {
		log.Fatalf("Failed to initialize policy loader: %v", err)
	}

	policy, err := policyLoader.Load()
	if err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}
	log.Printf("Loaded %d policy rules", len(policy.Rules))

	// Initialize eBPF programs
	log.Println("Initializing eBPF programs...")
	bpfManager, err := bpf.NewManager(cfg, policy)
	if err != nil {
		log.Fatalf("Failed to initialize eBPF manager: %v", err)
	}

	if err := bpfManager.Load(); err != nil {
		if skipBPF {
			log.Printf("Skipping eBPF (skip-bpf flag set): %v", err)
		} else {
			log.Printf("Warning: Failed to load eBPF programs: %v", err)
			log.Println("Continuing with reduced functionality (use --skip-bpf to suppress this warning)")
		}
	}

	// Attach eBPF programs based on configuration
	if cfg.Protection.ModelFIM.Enabled {
		log.Println("Enabling Model FIM (File Integrity Monitoring)")
		if err := bpfManager.AttachLSM(); err != nil {
			log.Printf("Warning: Failed to attach LSM hooks: %v (continuing without FIM)", err)
		} else {
			log.Println("  LSM hooks attached successfully")
		}
	}

	if cfg.Protection.NetworkContainment.Enabled {
		log.Println("Enabling Network Containment (TC)")
		if err := bpfManager.AttachTC(); err != nil {
			log.Printf("Warning: Failed to attach TC programs: %v (continuing without network monitoring)", err)
		} else {
			log.Println("  TC programs attached successfully")
		}
	}

	if cfg.Protection.PickleProtection.Enabled {
		log.Println("Enabling Pickle Bomb Protection (Uprobes)")
		if err := bpfManager.AttachUprobes(); err != nil {
			log.Printf("Warning: Failed to attach uprobes: %v (continuing without pickle protection)", err)
		} else {
			log.Println("  Uprobes attached successfully")
		}
	}

	// Start agent
	log.Println("Starting NeuroSentry agent...")
	agent, err := agent.NewController(cfg, bpfManager, policy)
	if err != nil {
		log.Fatalf("Failed to create agent controller: %v", err)
	}

	if err := agent.Start(ctx); err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	// Note: Metrics server is started by the agent controller as a component
	log.Println("NeuroSentry is now active and monitoring")
	log.Printf("Metrics available at http://:%d/metrics", cfg.Agent.MetricsPort)

	// Wait for shutdown or reload signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			log.Println("Received SIGHUP, reloading configuration...")
			if err := reloadConfig(cfgFile, bpfManager, agent); err != nil {
				log.Printf("Failed to reload configuration: %v", err)
			} else {
				log.Println("Configuration reloaded successfully")
			}
		case syscall.SIGINT, syscall.SIGTERM:
			log.Println("Received shutdown signal, cleaning up...")
			cancel()

			// Graceful shutdown with timeout
			shutdownDone := make(chan struct{})
			go func() {
				agent.Stop()
				bpfManager.Close()
				close(shutdownDone)
			}()

			select {
			case <-shutdownDone:
				log.Println("NeuroSentry shutdown complete")
			case <-time.After(30 * time.Second):
				log.Println("Shutdown timeout exceeded, forcing exit")
			}
			return
		}
	}
}

func setupLogging(level string) {
	// TODO: Implement proper structured logging
	switch level {
	case "debug":
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	case "info", "warn", "error":
		log.SetFlags(log.Ldate | log.Ltime)
	default:
		log.SetFlags(log.Ldate | log.Ltime)
	}
}

// reloadConfig reloads configuration and policy without restarting
func reloadConfig(cfgFile string, bpfMgr *bpf.Manager, ctrl *agent.Controller) error {
	// Reload configuration
	newCfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// Reload policy
	policyLoader, err := policy.NewLoader(newCfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to create policy loader: %w", err)
	}

	newPolicy, err := policyLoader.Load()
	if err != nil {
		return fmt.Errorf("failed to reload policy: %w", err)
	}

	log.Printf("Reloaded %d policy rules", len(newPolicy.Rules))

	// Clear old BPF map entries before applying new configuration
	log.Println("Clearing old BPF map entries...")
	if err := bpfMgr.ClearMaps(); err != nil {
		log.Printf("Warning: failed to clear BPF maps: %v", err)
	}

	// Re-apply protected extensions
	for _, ext := range newCfg.Protection.ModelFIM.ProtectedExtensions {
		if err := bpfMgr.AddProtectedExtension(ext); err != nil {
			log.Printf("Warning: failed to add protected extension %s: %v", ext, err)
		}
	}

	// Re-apply trusted PIDs
	for _, pid := range newCfg.Protection.ModelFIM.TrustedPIDs {
		if err := bpfMgr.AddTrustedPID(uint32(pid)); err != nil { //nolint:gosec // G115: PID conversion is safe
			log.Printf("Warning: failed to add trusted PID %d: %v", pid, err)
		}
	}

	// Re-apply allowed egress CIDRs
	for _, cidr := range newCfg.Protection.NetworkContainment.AllowedEgress {
		if err := bpfMgr.AddAllowedIP(cidr); err != nil {
			log.Printf("Warning: failed to add allowed IP %s: %v", cidr, err)
		}
	}

	// Update security metrics if available
	if secMetrics := ctrl.GetSecurityMetrics(); secMetrics != nil {
		secMetrics.RecordConfigReload()
	}

	return nil
}
