# NeuroSentry Architecture

## Overview

NeuroSentry is a kernel-level runtime protection system for AI inference environments. It leverages eBPF (extended Berkeley Packet Filter) to provide deep visibility and control over AI workloads without modifying application code or incurring significant performance overhead.

## System Architecture

<p align="center">
  <img src="diagrams/architecture-overview.svg" alt="System architecture: User-space Go agent (Controller, Policy Engine, Event Processor, Metrics Server) communicating with a three-program kernel-space eBPF triad (LSM file_open, TC ingress/egress, Uprobes) via shared eBPF maps and ring buffer" width="900"/>
</p>

The Go user-space agent loads and orchestrates a three-program eBPF triad in the kernel (LSM, TC, and uprobe); the programs read kernel events at the VFS, network, and uprobe layers and stream them up to user space through ring buffers. Policy decisions are pushed down via shared BPF maps. See the [LSM enforcement-path diagram](diagrams/lsm-eperm-flow.svg) for the deny path that returns `-EPERM` to the calling process before any byte of a protected file is read.

## Components

### 1. Kernel Space (eBPF Programs)

#### LSM Hooks (Linux Security Module)
- **Purpose**: Intercept file operations at the kernel VFS layer
- **Programs**:
  - `restrict_model_file_access` (`file_open` hook): Blocks unauthorized model file reads — the only LSM hook attached at runtime
  - `monitor_model_file_read` (`file_permission` hook): **Disabled / not attached** (eBPF verifier issues on kernel 6.14); the `file_open` hook provides sufficient coverage
  - `monitor_model_mmap` (`mmap_file` hook): **Disabled / not attached** (same verifier constraint)

#### TC Programs (Traffic Control) - Recommended for Cloud
- **Purpose**: Monitor network traffic at the Linux TC layer (cloud-compatible)
- **Programs**:
  - `neurosentry_tc_ingress`: Monitors incoming traffic
  - `neurosentry_tc_egress`: Monitors outgoing traffic for exfiltration attempts
- **Advantages**: Works on AWS EC2, GCP, Azure where XDP driver mode is unsupported
- **Mode**: Monitor-only (never blocks traffic, reports suspicious activity)

#### XDP Programs (eXpress Data Path) - Not loaded (reserved / roadmap)
- **Status**: **Not loaded at runtime.** The `loadXDP`/`AttachXDP` code paths and the `neurosentry_xdp.c` program are compiled but never invoked — the network layer ships as TC (above). This section is retained only as a record of the reserved, driver-level roadmap path.
- **Purpose (roadmap)**: Filter network packets at the driver level (before kernel stack)
- **Limitations**: Requires XDP-compatible network drivers (not available on most cloud VMs)
- **Programs**:
  - `neurosentry_xdp_filter`: The only XDP program that exists (packet filter). Note: the shipped program is PASS-only and never drops packets.

#### Uprobes (User-Space Probes)
- **Purpose**: Monitor AI framework internals
- **Programs (attached at runtime)**:
  - `uprobe_torch_load`: Hooks PyTorch `torch::load()` function
  - `uprobe_pickle_load`: Monitors Python pickle deserialization
  - `uprobe_pickle_reduce`: Monitors pickle `__reduce__` (security-critical) when the symbol is resolvable
- **Compiled but never attached**: `uprobe_tf_load` (TensorFlow) and `uprobe_onnx_load` (ONNX Runtime) are defined in `neurosentry_uprobe.c` but no runtime code attaches them — there are no TensorFlow or ONNX uprobes in the shipping agent.

### 2. User Space (Go Agent)

#### Controller
- Manages the entire agent lifecycle
- Coordinates all components
- Handles graceful shutdown

#### Policy Engine
- Evaluates events against security policies
- Updates eBPF maps based on policy changes
- Provides policy reload capability

#### Event Processor
- Consumes events from eBPF ring buffers
- Parses and normalizes event data
- Routes events to appropriate handlers

#### Metrics Collector
- Exposes Prometheus metrics
- Tracks performance and security events
- Provides health endpoints

#### Cross-Layer Correlation Engine (`pkg/correlate`)
- The core differentiator: fuses AI intent (LLM prompts, MCP tool calls) with kernel-observed actions (file, network, pickle, model-load events)
- Emits the `NS-CORR-001`..`NS-CORR-011` findings that link an AI decision to the kernel action it caused

#### MCP Interceptor / AI Gateway
- Sits in front of Model Context Protocol tool calls and the AI request path
- Feeds prompt/tool-call intent into the correlation engine

#### Durable Audit Chain
- Hash-chained, tamper-evident audit log persisted to a durable store (SQLite/Postgres)
- Resumes its sequence and hash chain across restarts with no dropped entries

#### Incident / Case Management
- Groups related findings into incidents and cases for triage and response

#### Multi-Tenant Platform
- OIDC/SAML SSO, SCIM provisioning, and RBAC for multi-tenant operation

#### Fleet Control Plane
- Centralized management and policy distribution across a fleet of agents

## Data Flow

### Event Flow
1. eBPF program intercepts kernel event (file open, network packet, etc.)
2. Event data written to ring buffer
3. User-space agent reads from ring buffer
4. Event parsed and normalized
5. Policy engine evaluates event
6. Action taken (allow/block/alert)
7. Metrics updated

### Configuration Flow
1. Admin updates YAML configuration
2. Controller signals reload
3. Policy engine loads new configuration
4. eBPF maps updated with new rules
5. Changes applied atomically

## eBPF Maps

| Map Name | Type | Purpose | Max Entries |
|----------|------|---------|-------------|
| `trusted_pids` | Hash | Whitelisted process IDs | 10,240 |
| `protected_extensions` | Hash | Protected file extensions | 32 |
| `allowed_egress_ips` | Hash | Network allowlist | 256 |
| `blocked_ips` | Hash | Blocked IP addresses (TC) | 256 |
| `ns_tc_stats_map` | Array | TC traffic statistics | 1 |
| `tc_events` | Ring Buffer | TC network events | 128 KB |
| `dangerous_symbols` | Hash | Dangerous pickle symbols | 128 |
| `events` | Ring Buffer | Event streaming | 256 KB |
| `config_map` | Array | Runtime configuration | 1 |
| `stats_map` | Array | Statistics counters | 1 |

## Security Model

### Threats Addressed

1. **Model Theft**: Unauthorized copying of model weight files
2. **Model Tampering**: Unauthorized modification of models in memory
3. **Pickle Bombs**: Malicious code execution via pickle deserialization
4. **Data Exfiltration**: Network transmission of stolen models
5. **Unauthorized Inference**: Running models without authorization

### Defense Layers

<p align="center">
  <img src="diagrams/defense-in-depth.svg" alt="Defense-in-depth: NeuroSentry sits between the application layer (inference servers, API gateways, frameworks) and the Linux kernel, intercepting model-asset access via three eBPF hook types. Threats (model theft, pickle bombs, memory scraping, container escape, network exfil, privileged insiders) hit NeuroSentry's enforcement layer before reaching the kernel." width="900"/>
</p>

NeuroSentry is positioned as a kernel-side gatekeeper rather than an application library: every protected-asset operation issued by the application layer flows through the LSM/TC/uprobe hooks before reaching the kernel's VFS or network stack. Threats targeting the model artifacts — file theft, pickle deserialization attacks, network exfiltration, container-escape paths — are intercepted at the layer where they cannot be opted out of by the calling process.

## Performance Characteristics

### Overhead
- **LSM Hooks**: <1% per file operation
- **TC**: ~100ns per packet (works on all platforms including cloud VMs) — this is the active network layer
- **XDP**: not an active layer (not loaded); the reserved driver-level path would be ~50ns per packet on compatible drivers
- **Uprobes**: <5% per hooked function call

### Scalability
- **Per-CPU Maps**: Avoids lock contention
- **Ring Buffers**: Lock-free event streaming
- **Bounded Memory**: Fixed-size maps prevent unbounded growth

## Integration Points

### Kubernetes
- DaemonSet deployment for cluster-wide coverage
- Service account for pod metadata access
- ConfigMap for policy distribution
- Service for metrics scraping

### Monitoring
- Prometheus metrics on port 2112
- Grafana dashboard templates provided
- Alert webhook integration

### Container Runtimes
- Works with Docker, containerd, CRI-O
- HostPID required for system-wide coverage
- Respects container boundaries (cgroup awareness)

## Future Extensions

1. **Windows Support**: Using eBPF-for-Windows or Windows ETW
2. **macOS Support**: Using DTrace or EndpointSecurity framework
3. **GPU Monitoring**: Direct monitoring of GPU memory operations
4. **ML Pipeline Integration**: SBOM verification for model provenance
5. **Federation**: Cluster-to-cluster policy synchronization
