# NeuroSentry Testing Guide

## Test Environment

### Reference test host
- **OS**: Ubuntu 24.04 LTS
- **Kernel**: 6.14 (aarch64) or 6.8+ (x86_64) with `CONFIG_BPF_LSM=y` and
  `bpf` in the active LSM stack (`/sys/kernel/security/lsm` must contain `bpf`).
- **Python**: 3.12.x
- **PyTorch**: 2.x (CPU build is sufficient for the pickle/uprobe tests)

### Component Status
| Component | Status | Details |
|-----------|--------|---------|
| LSM Hooks | ✅ | File integrity monitoring active (`file_open` hook) |
| TC (network) | ✅ | ingress/egress via TCX (6.6+) or legacy clsact; monitor-only |
| Pickle Uprobe | ✅ | Attached to `PyInit__pickle` |
| PyTorch Uprobe | ✅ | Attached to `torch::serialize` symbols |
| Metrics Server | ✅ | Port 2112 |

### Startup Logs (All Components Attached)
```
2026/02/06 05:55:44 Starting NeuroSentry dev
2026/02/06 05:55:44 eBPF-based AI Inference Protection System
2026/02/06 05:55:44 Loaded 3 policy rules
2026/02/06 05:55:44 Initializing eBPF programs...
2026/02/06 05:55:44 Enabling Model FIM (File Integrity Monitoring)
2026/02/06 05:55:44   LSM hooks attached successfully
2026/02/06 05:55:44 Enabling Network Containment (TC)
2026/02/06 05:55:44 Attached TCX ingress to ens5
2026/02/06 05:55:44 Attached TCX egress to ens5
2026/02/06 05:55:44   TC programs attached successfully
2026/02/06 05:55:44 Enabling Pickle Bomb Protection (Uprobes)
2026/02/06 05:55:48 Attached PyTorch uprobe to symbol _ZNSt19_Sp_counted_deleter...
2026/02/06 05:55:48 Attached PyTorch probes to /home/ubuntu/.local/lib/.../libtorch_cpu.so
2026/02/06 05:55:48 Attached pickle load uprobe to symbol PyInit__pickle at offset 0x350180
2026/02/06 05:55:48 Attached pickle probes to /usr/lib/x86_64-linux-gnu/libpython3.12.so
2026/02/06 05:55:48   Uprobes attached successfully
2026/02/06 05:55:48 NeuroSentry is now active and monitoring
2026/02/06 05:55:48 Metrics available at http://:2112/metrics
```

## Test Cases

### Test 1: TC Network Monitoring

**Input:**
```bash
# Trigger network traffic
curl -s http://example.com > /dev/null
curl -s https://pytorch.org > /dev/null

# Check metrics
curl -s http://localhost:2112/metrics | grep tc
```

**Output:**
```
neurosentry_tc_ingress_packets_total <increases with observed traffic>
neurosentry_tc_egress_packets_total <increases with observed traffic>
```

**Explanation**: The TC ingress/egress programs attach to the interface and observe every packet, recording flow metadata (PID, destination IP, byte counts) for exfiltration analysis. In v1.0 the network layer is **monitor-only** — no packets are dropped. The counters rise as traffic flows; there is no "dropped" counter because TC does not block traffic here. (XDP is not loaded, so there are no `neurosentry_xdp_*` metrics.)

### Test 2: File Access Monitoring (LSM)

**Input:**
```bash
# Create protected model files
echo "fake model" > /tmp/test/model.safetensors
echo "fake model" > /tmp/test/model.pth
echo "fake model" > /tmp/test/model.pkl

# Access files multiple times
for i in 1 2 3 4 5; do
    cat /tmp/test/model.safetensors > /dev/null
    cat /tmp/test/model.pth > /dev/null
    cat /tmp/test/model.pkl > /dev/null
done
```

**Expected Output:**
```
neurosentry_lsm_access_attempts_total 15
neurosentry_lsm_protected_files_seen 3
```

**Note**: LSM statistics require proper CO-RE (Compile Once - Run Everywhere) setup for filename extraction. Current implementation logs events but stats collection needs kernel BTF support.

### Test 3: Pickle Deserialization (Uprobe)

**Input:**
```python
import pickle

# Multiple pickle operations
for i in range(5):
    data = {"model": "test", "weights": [1,2,3], "id": i}
    serialized = pickle.dumps(data)
    result = pickle.loads(serialized)
    print(f"Pickle round {i+1}: {result}")
```

**Output:**
```
Pickle round 1: {'model': 'test', 'weights': [1, 2, 3], 'id': 0}
Pickle round 2: {'model': 'test', 'weights': [1, 2, 3], 'id': 1}
Pickle round 3: {'model': 'test', 'weights': [1, 2, 3], 'id': 2}
Pickle round 4: {'model': 'test', 'weights': [1, 2, 3], 'id': 3}
Pickle round 5: {'model': 'test', 'weights': [1, 2, 3], 'id': 4}
```

**Uprobe Attachment Log:**
```
Attached pickle load uprobe to symbol PyInit__pickle at offset 0x350180
Attached pickle probes to /usr/lib/x86_64-linux-gnu/libpython3.12.so
```

**Note**: `PyInit__pickle` is called once during module initialization. Per-call metrics require internal symbols which are not exported in release Python builds.

### Test 4: PyTorch Model Operations (Uprobe)

**Input:**
```python
import torch

# Create and operate on tensors
t1 = torch.tensor([1.0, 2.0, 3.0])
t2 = torch.tensor([4.0, 5.0, 6.0])
result = t1 + t2
print(f"Tensor operation: {t1} + {t2} = {result}")

# Save and load model
model_path = "/tmp/test_model.pt"
torch.save({"weights": t1}, model_path)
loaded = torch.load(model_path, weights_only=True)
print(f"Model save/load: {loaded}")
```

**Output:**
```
Tensor operation: tensor([1., 2., 3.]) + tensor([4., 5., 6.]) = tensor([5., 7., 9.])
Model save/load: {'weights': tensor([1., 2., 3.])}
```

**Uprobe Attachment Log:**
```
Attached PyTorch uprobe to symbol _ZN5torch3jit16_load_for_mobileERKNSt7__cxx1112basic_string...
Attached PyTorch probes to /home/ubuntu/.local/lib/python3.12/site-packages/torch/lib/libtorch_cpu.so
```

### Test 5: Uptime Monitoring

**Input:**
```bash
# Let NeuroSentry run for some time
sleep 300
curl http://localhost:2112/metrics | grep uptime
```

**Output:**
```
neurosentry_uptime_seconds 70495.005163578
```

**Explanation**: Shows NeuroSentry has been running for ~19.5 hours continuously.

## Metrics Collection Verification

### All Metrics Query
```promql
{__name__=~"neurosentry_.+"}
```

### Sample Output (2026-02-06 Test)
| Metric | Value | Description |
|--------|-------|-------------|
| neurosentry_uptime_seconds | 5.00 | Uptime in seconds |
| neurosentry_tc_ingress_packets_total | (rises with traffic) | Ingress packets observed (monitor-only) |
| neurosentry_tc_egress_packets_total | (rises with traffic) | Egress packets observed (monitor-only) |
| neurosentry_lsm_access_attempts_total | 0 | File access events |
| neurosentry_uprobe_pickle_loads_total | 0 | Pickle loads monitored |
| neurosentry_uprobe_model_loads_total | 0 | Model loads monitored |
| neurosentry_active_connections | 0 | Active connections |
| neurosentry_bpf_errors_total | 0 | eBPF errors |

## Screenshots

### Prometheus - All NeuroSentry Metrics
Shows all 12 metrics being collected:

![All Metrics](images/final_all_metrics.png)

### Prometheus - Uptime Graph
Shows uptime increasing steadily over 15 minutes:

![Uptime Graph](images/final_uptime_graph.png)

## TC Attachment Fallback

The network layer is TC (not XDP), chosen for cloud compatibility. NeuroSentry attaches it in two tiers:

```
1. First attempts TCX attachment (kernel 6.6+, native and clean)
2. Falls back to legacy clsact qdisc + tc filter if TCX is unavailable (older kernels)
```

**Example log on AWS EC2 (ENA driver):**
```
Attached TCX ingress to ens5
Attached TCX egress to ens5
```

## Uprobe Symbol Resolution

NeuroSentry uses dynamic ELF symbol resolution for Uprobe attachment:

1. **Pickle**: Attaches to `PyInit__pickle` (module initialization)
2. **PyTorch**: Attaches to `torch::serialize` or `torch::jit::load` symbols

**Symbol patterns searched (in priority order):**
```
Pickle:  _pickle_loads, _pickle_load, PyInit__pickle, PyPickleBuffer_*
PyTorch: torch.*load, _load_from_file, THPModule_load, torch::jit::load
```

## Running the Test Suite

```bash
# Create test script
cat > test_neurosentry.sh << 'EOF'
#!/bin/bash
echo "=== NeuroSentry Test Suite ==="

# Test 1: Create model files
mkdir -p /tmp/test
echo "fake model" > /tmp/test/model.safetensors
echo "fake model" > /tmp/test/model.pth
echo "fake model" > /tmp/test/model.pkl

# Test 2: Access files
for i in $(seq 1 10); do
    cat /tmp/test/*.safetensors > /dev/null 2>&1
    cat /tmp/test/*.pth > /dev/null 2>&1
done

# Test 3: Check metrics
curl -s http://localhost:2112/metrics | grep neurosentry_
EOF

chmod +x test_neurosentry.sh
./test_neurosentry.sh
```
