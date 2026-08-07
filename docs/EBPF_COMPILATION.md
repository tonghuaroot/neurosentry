# NeuroSentry eBPF Compilation Guide

This guide explains how to compile the NeuroSentry eBPF programs for Linux kernels.

## Prerequisites

### Linux System Requirements
- Linux kernel 5.8+ with BTF (BPF Type Format) enabled
- Ubuntu 24.04 recommended (kernel 6.14 tested)
- Root/sudo access for loading eBPF programs

### Required Tools

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-$(uname -r) \
    linux-headers-$(uname -r)

# Verify BTF is available
ls -la /sys/kernel/btf/vmlinux
```

## Quick Start

### 1. Generate vmlinux.h from BTF

The `vmlinux.h` header file contains all kernel type definitions needed for eBPF compilation.

```bash
# On the target Linux system
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### 2. Compile eBPF Programs

```bash
# Using the build script
cd pkg/bpf
chmod +x build_ebpf.sh
./build_ebpf.sh

# Or compile manually
clang -target bpf -g -O2 -I./headers \
    -c neurosentry_lsm_simple.c \
    -o neurosentry_lsm_simple.o
```

### 3. Load and Test

```bash
# Load the LSM program
sudo bpftool prog load neurosentry_lsm_simple.o \
    /sys/fs/bpf/neurosentry_lsm

# Verify it's loaded
sudo bpftool prog show | grep neurosentry

# Check kernel logs
sudo dmesg | tail -20
```

## eBPF Programs

| Program | Type | Purpose | File |
|---------|------|---------|------|
| LSM Hook | file_open | Monitor file access to model files | neurosentry_lsm_simple.c |
| LSM Hook | file_permission | **Disabled** — not attached (verifier issues on kernel 6.14; `file_open` provides coverage). The `mmap_file` hook in this source is disabled for the same reason. | neurosentry_lsm.c |
| **TC (Recommended)** | tc | Network monitoring (cloud-compatible) | neurosentry_tc.c |
| XDP | xdp | Network packet filtering (limited cloud support) | neurosentry_xdp.c |
| Uprobe | uprobe/uretprobe | Framework monitoring (PyTorch, TensorFlow) | neurosentry_uprobe.c |

### TC vs XDP

| Feature | TC (Traffic Control) | XDP (eXpress Data Path) |
|---------|---------------------|-------------------------|
| **Cloud Support** | ✅ AWS, GCP, Azure | ❌ Limited (driver-dependent) |
| **Performance** | ~100ns/packet | ~50ns/packet |
| **Mode** | Monitor-only | Can drop packets |
| **Kernel Version** | 6.6+ (TCX API) | 5.10+ |
| **Attachment** | TCX Ingress/Egress | Driver or Generic |

**Recommendation**: Use TC for cloud deployments, XDP only on bare-metal with compatible NICs.

## Cross-Compilation from macOS

NeuroSentry's Go code builds on macOS, but eBPF programs must be compiled on Linux.

### Option 1: SSH to Linux Server

```bash
# Connect to test server
ssh -i ~/.ssh/your-key.pem ubuntu@your-linux-build-host

# Clone/pull repository
cd /tmp/neurosentry_test
git pull

# Run build script
cd pkg/bpf
./build_ebpf.sh
```

### Option 2: Docker

```bash
# Run a Linux container with BPF tools
docker run --rm -it \
    -v $(pwd):/workspace \
    --privileged \
    --network=host \
    quay.io/cilium/bpf-builder:latest \
    bash -c "cd /workspace/pkg/bpf && ./build_ebpf.sh"
```

### Option 3: Use libbpf-bootstrap Docker

```bash
docker run --rm -it \
    -v $(pwd):/workspace \
    --privileged \
    ghcr.io/libbpf/libbpf-bootstrap:latest \
    bash -c "cd /workspace/pkg/bpf && clang -target bpf -g -O2 -c *.c"
```

## Troubleshooting

### BTF Not Available

```
Error: Cannot find file /sys/kernel/btf/vmlinux
```

**Solution**: Your kernel doesn't have BTF enabled. Options:
1. Enable CONFIG_DEBUG_INFO_BTF=y and rebuild kernel
2. Use kernel headers instead (more complex, see below)

### Missing asm/types.h

```
fatal error: 'asm/types.h' file not found
```

**Solution**: Don't include system headers. Use the self-contained approach:
- Include `vmlinux.h` first
- Define BPF helpers inline
- Don't include `<linux/bpf.h>` or `<bpf/bpf_helpers.h>`

### bpftool Version Mismatch

```
WARNING: bpftool not found for kernel 6.14.0-1018
```

**Solution**: Use the bpftool from linux-tools:
```bash
/usr/lib/linux-tools-6.8.0-94/bpftool btf dump file /sys/kernel/btf/vmlinux format c
```

## Self-Contained Header Pattern

This project uses a self-contained header pattern to avoid system header conflicts:

```c
// Include vmlinux.h FIRST
#include "vmlinux.h"

// Define helpers inline - no system headers needed
#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static long (*bpf_map_update_elem)(...) = (void *)2;

char LICENSE[] SEC("license") = "GPL";

// Old-style C map definitions
struct map_name_t {
    unsigned int type;
    unsigned int max_entries;
} map_name SEC(".maps") = { ... };

SEC("lsm/file_open")
int program_name(void *ctx) { ... }
```

## Testing on Ubuntu 24.04

The reference test host runs Ubuntu 24.04 with kernel 6.14. Any equivalent
cloud or local VM with the kernel + clang + libbpf-dev prerequisites works.

```bash
# SSH to your build host
ssh -i ~/.ssh/your-key.pem ubuntu@your-linux-build-host

# Setup
mkdir -p /tmp/neurosentry_test
cd /tmp/neurosentry_test

# Generate headers
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile
clang -target bpf -g -O2 -I. -c neurosentry_lsm_simple.c -o neurosentry_lsm_simple.o

# Load
sudo bpftool prog load neurosentry_lsm_simple.o /sys/fs/bpf/neurosentry_lsm

# Verify
sudo bpftool prog show | grep neurosentry
```

## TC Compilation

TC programs use the TCX API (kernel 6.6+) for attachment:

```bash
# Compile TC program
clang -target bpf -g -O2 -I./headers \
    -c neurosentry_tc.c \
    -o neurosentry_tc.o

# Generate Go bindings
go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel \
    -cc clang -cflags "-O2 -g -Wall" \
    NeuroSentryTC ./neurosentry_tc.c -- -I./headers
```

### TC Attachment in Go

```go
import "github.com/cilium/ebpf/link"

// Attach TC ingress
ingressLink, err := link.AttachTCX(link.TCXOptions{
    Interface: iface.Index,
    Program:   tcObjs.NeurosentryTcIngress,
    Attach:    ebpf.AttachTCXIngress,
})

// Attach TC egress
egressLink, err := link.AttachTCX(link.TCXOptions{
    Interface: iface.Index,
    Program:   tcObjs.NeurosentryTcEgress,
    Attach:    ebpf.AttachTCXEgress,
})
```

## Integration with Go

The Go loader uses `cilium/ebpf` to load the compiled `.o` files:

```go
// Load compiled eBPF object
spec, err := ebpf.LoadCollectionSpec("neurosentry_lsm.o")
if err != nil {
    log.Fatal(err)
}

// Load into kernel
coll, err := ebpf.NewCollection(spec)
if err != nil {
    log.Fatal(err)
}
defer coll.Close()

// Attach LSM hooks
link, err := ebpf.LinkLSM(coll.Programs["restrict_model_file_access"])
if err != nil {
    log.Fatal(err)
}
defer link.Close()
```

## Further Reading

- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
- [BPF CO-RE (Compile Once, Run Everywhere)](https://nakryiko.com/posts/bpf-portability/)
