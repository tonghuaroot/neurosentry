// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/neurosentry/neurosentry/pkg/agent"
	"github.com/neurosentry/neurosentry/pkg/bpf"
	"github.com/neurosentry/neurosentry/pkg/config"
	"github.com/neurosentry/neurosentry/pkg/policy"
	"github.com/neurosentry/neurosentry/pkg/replay"
	"github.com/neurosentry/neurosentry/pkg/sandbox"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// starterData is a small, inspectable sample dataset in the same NDJSON schema
// the --replay import path consumes. It is loaded through that exact path (not
// a bespoke seeder) when no external dataset is supplied, so a fresh install
// isn't an empty console. Disable with --no-seed; override with --replay.
//
//go:embed starter.ndjson
var starterData []byte

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
	cfgFile       string
	logLevel      string
	skipBPF       bool
	noSeed        bool
	allowDegraded bool
	replayFile    string
	replayFormat  string
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/neurosentry/config.yaml", "Configuration file path")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().BoolVar(&skipBPF, "skip-bpf", false, "Skip eBPF loading (for development on non-Linux)")
	rootCmd.PersistentFlags().BoolVar(&noSeed, "no-seed", false, "Start with an empty console — skip loading the built-in sample dataset (ignored when --replay is set)")
	rootCmd.PersistentFlags().BoolVar(&allowDegraded, "allow-degraded", false, "Permit startup in monitor-only mode when enforce is requested but the kernel lacks BPF LSM (default: fail safe and refuse to start)")
	rootCmd.PersistentFlags().StringVar(&replayFile, "replay", "", "Import an external security dataset (NDJSON) through the correlation engine — populate the console with realistic data")
	rootCmd.PersistentFlags().StringVar(&replayFormat, "replay-format", "auto", "Dataset format for --replay: auto (mixed), host (OTRF/Mordor/auditd kernel telemetry), or injection (prompt-injection/jailbreak corpus)")
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
	setupLogging(logLevel, cfg.Agent.LogFormat)

	agent.BuildVersion = version
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

	// Kernel-capability preflight: probe the running kernel, log a support
	// report, and fail safe when enforcement was requested but cannot be
	// honored — otherwise the operator would believe model files are blocked
	// when they are only being observed.
	if !skipBPF {
		caps := bpf.DetectCapabilities()
		enforce := cfg.Protection.ModelFIM.Enabled && cfg.Protection.ModelFIM.EnforceMode
		assessment := caps.Assess(enforce)
		log.Printf("Kernel preflight: %s (kernel=%s BTF=%v BPF-LSM=%v ringbuf=%v TC=%v uprobe=%v)",
			assessment, caps.KernelVersion, caps.BTF, caps.BPFLSM, caps.Ringbuf, caps.TC, caps.Uprobe)
		for _, r := range assessment.Reduced {
			log.Printf("  reduced: %s", r)
		}
		if assessment.EnforceUnavailable && !allowDegraded {
			log.Fatalf("FAIL-SAFE: enforce mode requested but the kernel lacks BPF LSM — refusing to start "+
				"unprotected. Enable BPF LSM (add 'bpf' to the kernel lsm= list) or pass --allow-degraded "+
				"to run monitor-only. Blocking issues: %v", assessment.Blocking)
		}
		if assessment.EnforceUnavailable && allowDegraded {
			log.Printf("WARNING: enforce requested but BPF LSM unavailable; running MONITOR-ONLY per --allow-degraded")
		}
	}

	// Attach eBPF programs based on configuration
	if cfg.Protection.ModelFIM.Enabled {
		log.Println("Enabling Model FIM (File Integrity Monitoring)")
		if err := bpfManager.AttachLSM(); err != nil {
			log.Printf("Warning: Failed to attach LSM hooks: %v (continuing without FIM)", err)
		} else {
			log.Println("  LSM hooks attached successfully")
			// Trust the agent itself so its inventory scanner can read
			// protected model files to hash them for integrity monitoring.
			if err := bpfManager.AddTrustedPID(uint32(os.Getpid())); err != nil { //nolint:gosec // G115: PID is small
				log.Printf("Warning: could not self-trust agent PID: %v", err)
			}
		}
	}

	if cfg.Protection.NetworkContainment.Enabled {
		log.Println("Enabling Network Containment (TC)")
		if err := bpfManager.AttachTC(); err != nil {
			log.Printf("Warning: Failed to attach TC programs: %v (continuing without network monitoring)", err)
		} else {
			log.Println("  TC programs attached successfully")
			// Seed the egress blocklist from config and set the enforcement
			// gate. When block_exfiltration is true, egress to a blocked
			// destination is dropped (TC_ACT_SHOT); otherwise it is monitor-only.
			blocked := 0
			for _, s := range cfg.Protection.NetworkContainment.BlockedIPs {
				if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
					if err := bpfManager.AddBlockedIP(ip); err == nil {
						blocked++
					}
				}
			}
			if err := bpfManager.SetNetworkEnforce(cfg.Protection.NetworkContainment.BlockExfiltration); err != nil {
				log.Printf("Warning: could not set network enforcement: %v", err)
			} else if cfg.Protection.NetworkContainment.BlockExfiltration {
				log.Printf("  network egress ENFORCING — %d blocked destination(s); egress to them is dropped", blocked)
			} else {
				log.Printf("  network egress monitor-only — %d blocked destination(s) logged, not dropped", blocked)
			}
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

	// Apply Landlock sandbox if configured
	if cfg.Sandbox.Enabled {
		sandboxCfg := sandbox.Config{
			Enabled:        cfg.Sandbox.Enabled,
			ReadOnlyPaths:  cfg.Sandbox.ReadOnlyPaths,
			ReadWritePaths: cfg.Sandbox.ReadWritePaths,
			DenyPaths:      cfg.Sandbox.DenyPaths,
		}
		profile := sandbox.ProfileFromConfig(sandboxCfg)
		if err := profile.Apply(); err != nil {
			log.Printf("Warning: failed to apply Landlock sandbox: %v", err)
		} else {
			log.Println("Landlock sandbox applied successfully")
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

	// Populate the console through the single import path (replay). An explicit
	// --replay dataset wins; otherwise the built-in sample dataset is loaded so
	// a fresh install isn't empty. --no-seed opts out entirely. There is no
	// separate "demo" code path — sample data is just an imported dataset.
	switch {
	case replayFile != "":
		replayDataset(agent, replayFile, replayFormat)
	case !noSeed:
		loadStarterDataset(agent)
	}

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

// replayDataset imports an external security dataset (NDJSON) and replays it
// through the real correlation engine, so the console reflects realistic data
// volume from a public corpus (e.g. OTRF/Mordor host telemetry or a prompt-
// injection dataset) rather than only synthetic seeds.
func replayDataset(ctrl *agent.Controller, path, format string) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("replay: cannot open %s: %v", path, err)
		return
	}
	defer f.Close()

	var events []replay.Event
	if format == "auditd" {
		// Raw Linux auditd log text (e.g. real OTRF/Security-Datasets captures).
		events, err = replay.ReadAuditd(f)
	} else {
		events, err = replay.ReadNDJSON(f, replay.AdapterFor(format))
	}
	if err != nil {
		log.Printf("replay: read %s: %v", path, err)
		return
	}
	n := replay.Replay(events, ctrl.IngestSignal)
	log.Printf("replay: ingested %d signals from %s (format=%s) into the correlation engine", n, path, format)
}

// loadStarterDataset imports the embedded sample dataset through the same
// adapter/replay path as --replay, so the out-of-box console is populated
// without any bespoke seeding logic. Timestamps are rebased so the newest
// sample event lands at "now" (preserving intra-chain ordering and gaps),
// keeping the sample data current on every start.
func loadStarterDataset(ctrl *agent.Controller) {
	events, err := replay.ReadNDJSON(bytes.NewReader(starterData), replay.AdapterFor("auto"))
	if err != nil || len(events) == 0 {
		if err != nil {
			log.Printf("sample dataset: %v", err)
		}
		return
	}
	// Rebase to now: find the latest event and shift the whole set so it ends
	// at the present moment.
	var newest time.Time
	for _, e := range events {
		if e.TS.After(newest) {
			newest = e.TS
		}
	}
	if !newest.IsZero() {
		delta := time.Now().Add(-5 * time.Second).Sub(newest)
		for i := range events {
			if !events[i].TS.IsZero() {
				events[i].TS = events[i].TS.Add(delta)
			}
		}
	}
	n := replay.Replay(events, ctrl.IngestSignal)
	log.Printf("sample dataset: imported %d signals (built-in). Use --replay <file> for a real dataset or --no-seed to start empty", n)
}

func setupLogging(level, format string) {
	if format == "json" {
		lvl := slog.LevelInfo
		switch level {
		case "debug":
			lvl = slog.LevelDebug
		case "warn":
			lvl = slog.LevelWarn
		case "error":
			lvl = slog.LevelError
		}
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
		// Bridge the standard log package so existing log.Printf output is
		// emitted as structured JSON records (SIEM-ingestable). Findings and
		// security events already carry structured detail in the audit chain.
		log.SetFlags(0)
		log.SetOutput(slogBridge{})
		return
	}
	switch level {
	case "debug":
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	default:
		log.SetFlags(log.Ldate | log.Ltime)
	}
}

// slogBridge routes standard-library log output through slog as structured
// records, classifying by the leading tag NeuroSentry uses on notable lines.
type slogBridge struct{}

func (slogBridge) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	switch {
	case strings.Contains(msg, "[BLOCKED]"), strings.Contains(msg, "[CORRELATION]"), strings.HasPrefix(msg, "SECURITY:"):
		slog.Warn(msg, "kind", "security")
	case strings.Contains(msg, "Warning") || strings.Contains(msg, "warning"):
		slog.Warn(msg)
	default:
		slog.Info(msg)
	}
	return len(p), nil
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
