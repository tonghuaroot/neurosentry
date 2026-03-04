# NeuroSentry User Guide

## Table of Contents
1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Deployment](#deployment)
4. [Monitoring](#monitoring)
5. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- **OS**: Linux 5.10+ (for LSM BPF support)
- **Kernel**: Must support `CONFIG_BPF_LSM=y`
- **Privileges**: Root access required for eBPF operations

### Quick Start

```bash
# Clone repository
git clone https://github.com/neurosentry/neurosentry.git
cd neurosentry

# Install dependencies
sudo ./scripts/install-deps.sh

# Build
./scripts/build.sh

# Run
sudo ./bin/neurosentry --config config.yaml
```

### Docker Installation

```bash
# Pull image
docker pull neurosentry:latest

# Run (requires privileged mode)
docker run --privileged --pid=host --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v $(pwd)/config.yaml:/etc/neurosentry/config.yaml \
  neurosentry:latest
```

## Configuration

### Basic Configuration

Create a `config.yaml` file:

```yaml
protection:
  model_fim:
    enabled: true
    protected_extensions:
      - .safetensors
      - .gguf
      - .pth
      - .pkl
    enforce_mode: true
    log_all_access: false

  network_containment:
    enabled: true
    allowed_egress:
      - 10.0.0.0/8
      - 172.16.0.0/12
    block_exfiltration: true
    exfil_threshold_mb: 100

  pickle_protection:
    enabled: true
    block_on_detect: true

agent:
  metrics_port: 2112
  log_level: info
```

### Configuration Options

#### Model FIM (File Integrity Monitoring)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable file access monitoring |
| `protected_extensions` | []string | See defaults | File extensions to protect |
| `protected_paths` | []string | `[]` | Specific directories to protect |
| `trusted_pids` | []int | `[]` | Whitelisted process IDs |
| `trusted_containers` | []string | `[]` | Trusted container labels |
| `enforce_mode` | bool | `true` | Block violations (false = audit only) |
| `log_all_access` | bool | `false` | Log all file access |

#### Network Containment

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable network filtering |
| `use_tc` | bool | `true` | Use TC instead of XDP (recommended for cloud) |
| `allowed_egress` | []string | See defaults | Allowed destination CIDRs |
| `blocked_ips` | []string | `[]` | Explicitly blocked IPs |
| `block_exfiltration` | bool | `true` | Block large data transfers |
| `exfil_threshold_mb` | int | `100` | Threshold (MB) for exfil detection |
| `allow_dns` | bool | `true` | Allow DNS queries |

> **Note**: TC mode is monitor-only and never drops packets. It reports suspicious traffic for alerting. Use TC for cloud deployments (AWS, GCP, Azure) where XDP driver mode is unsupported.

#### Pickle Protection

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable pickle monitoring |
| `dangerous_symbols` | []string | See defaults | Dangerous function names |
| `block_on_detect` | bool | `true` | Terminate dangerous operations |
| `stack_trace_depth` | int | `16` | Depth of stack trace on detection |

#### PyTorch Observability

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable PyTorch runtime monitoring |
| `libtorch_path` | string | `""` | Custom path to libtorch library (auto-detected if empty) |
| `monitor_model_loads` | bool | `true` | Monitor `torch.load()` and related functions |
| `calculate_hashes` | bool | `false` | Calculate SHA256 hashes of loaded models (performance impact) |

#### BPF Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log_level` | int | `0` | BPF program log verbosity (0-3) |
| `ring_buffer_size_kb` | int | `256` | Ring buffer size for events |
| `per_cpu_map_size` | int | `1024` | Per-CPU map entry limit |
| `verifier_log_level` | int | `0` | eBPF verifier log level |
| `disable_core` | bool | `false` | Disable CO-RE (Compile Once - Run Everywhere) |

### Policy Files

NeuroSentry uses YAML policy files for advanced rule configuration:

```yaml
# policy.yaml
version: "1.0"
rules:
  - name: "block-unauthorized-model-access"
    enabled: true
    condition:
      type: "file_access"
      extensions: [".safetensors", ".gguf"]
    action: "block"
    severity: "high"
    alert: true
```

## Deployment

### Standalone Deployment

```bash
# Install as system service
sudo ./scripts/install.sh

# Start service
sudo systemctl start neurosentry
sudo systemctl enable neurosentry

# Check status
sudo systemctl status neurosentry
```

### Kubernetes Deployment

```bash
# Apply manifests
kubectl apply -f deploy/kubernetes/

# Verify deployment
kubectl -n neurosentry get pods -l app=neurosentry
```

The DaemonSet includes:
- Privileged containers for eBPF access
- Host networking for TC/XDP
- ConfigMap for configuration
- Service for metrics

> **Cloud Note**: For AWS EC2, GCP, or Azure VMs, ensure `use_tc: true` is set in the ConfigMap.

### Docker Compose

```yaml
version: '3.8'
services:
  neurosentry:
    image: neurosentry:latest
    privileged: true
    pid: host
    network_mode: host
    volumes:
      - /sys/kernel/debug:/sys/kernel/debug
      - /sys/fs/bpf:/sys/fs/bpf
      - ./config.yaml:/etc/neurosentry/config.yaml
    ports:
      - "2112:2112"
```

## Monitoring

### Metrics Endpoint

NeuroSentry exposes Prometheus metrics on port 2112:

```bash
curl http://localhost:2112/metrics
```

### Available Metrics

```
# Event counters
neurosentry_events_total{status="processed"} 1234
neurosentry_events_by_type_total{event_type="file_access"} 567

# Threat detection
neurosentry_threats_total{threat_type="model_access",severity="high"} 12

# BPF statistics
neurosentry_bpf_errors_total 0
neurosentry_active_connections 5

# Processing time
neurosentry_event_processing_seconds{stage="parse"} 0.001
```

### Health Check

```bash
curl http://localhost:2112/health
# Response: OK
```

### Log Levels

Configure logging verbosity:

```yaml
agent:
  log_level: debug  # debug, info, warn, error
```

## Troubleshooting

### Common Issues

#### "Permission denied" on eBPF load

**Solution**: Ensure running as root with necessary capabilities:
```bash
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep ./bin/neurosentry
```

#### "Kernel does not support LSM BPF"

**Solution**: Check kernel configuration:
```bash
# Check if LSM BPF is available
cat /proc/config.gz | gunzip | grep BPF_LSM

# Or check available hooks
sudo cat /sys/kernel/security/lsm
```

#### High CPU usage

**Solution**: Adjust ring buffer size or disable verbose logging:
```yaml
bpf:
  ring_buffer_size_kb: 128  # Reduce from default 256

agent:
  log_level: warn  # Reduce logging verbosity
```

#### XDP attachment fails / Network disruption with XDP

XDP driver mode is not supported on most cloud VM network interfaces (AWS ENA, GCP virtio, Azure).

**Solution**: Use TC (Traffic Control) instead of XDP for cloud deployments:
```yaml
# config.yaml
protection:
  network_containment:
    enabled: true
    use_tc: true    # Use TC instead of XDP (recommended for cloud)
```

Or check if driver supports XDP generic mode (slower but more compatible):
```bash
# Check driver XDP support
ethtool -k eth0 | grep generic-xdp

# If XDP still fails, TC will work on kernel 6.6+
uname -r  # Should be 6.6 or higher for TCX API
```

### Debug Mode

Enable detailed debugging:

```bash
sudo ./bin/neurosentry --config config.yaml --log-level debug
```

### Verifier Logs

View BPF verifier output:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep neurosentry
```

## Advanced Topics

### Custom Policy Development

Create custom policies for specific threat models:

```yaml
rules:
  - name: "protect-production-models"
    enabled: true
    condition:
      type: "file_access"
      paths: ["/models/production/*"]
    action: "block"
    exempt_users: [1000]  # UID exemptions
```

### Integration with Alertmanager

Configure webhook alerts:

```yaml
agent:
  alert_webhook: "http://alertmanager:9093/api/v1/alerts"
  alert_silence_sec: 300
```

### Multi-Cluster Deployment

Deploy across multiple Kubernetes clusters:

```bash
kubectl apply --context=cluster1 -f deploy/kubernetes/
kubectl apply --context=cluster2 -f deploy/kubernetes/
```

## Support

- **Documentation**: https://docs.neurosentry.io
- **Issues**: https://github.com/neurosentry/neurosentry/issues
- **Discord**: https://discord.gg/neurosentry
- **Email**: security@neurosentry.io
