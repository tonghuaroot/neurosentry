# NeuroSentry

**eBPF-based Runtime Protection for AI Inference Environments**

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Go Report](https://img.shields.io/badge/go%20report-A+-brightgreen)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![eBPF](https://img.shields.io/badge/eBPF-Linux%205.10+-orange)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

> "Protecting AI model assets at the kernel level with eBPF technology"

NeuroSentry is a runtime protection system for AI inference environments using eBPF (extended Berkeley Packet Filter) to secure machine learning model assets at the kernel level—without modifying application code or incurring significant performance overhead.

---

## Demo: Capture The Model

Try the interactive demo environment that demonstrates NeuroSentry's protection capabilities:

```bash
cd demos/capture-the-model
sudo ./start.sh
```

**[Demo Documentation →](demos/capture-the-model/README.md)**

---

## Why NeuroSentry?

AI model assets represent millions of dollars in R&D investment. Traditional security tools operate at the application layer, missing critical attack vectors. NeuroSentry operates at the kernel level, providing:

| Protection Layer | What We Block |
|-----------------|---------------|
| **File Access (LSM)** | Unauthorized `.safetensors`, `.gguf`, `.pth` reads |
| **Network (TC/XDP)** | Model exfiltration via Traffic Control (cloud-compatible) or XDP |
| **Frameworks (Uprobes)** | Malicious pickle deserialization, unauthorized model loading |
| **Memory Mapping** | Direct memory access to model files |

---

## Features

- **Model FIM** - File Integrity Monitoring for AI model weights
- **Network Containment** - TC (Traffic Control) / XDP-based filtering to prevent exfiltration
- **Cloud Compatible** - TC mode for AWS EC2, GCP, Azure (where XDP driver mode is unsupported)
- **Pickle Protection** - Detect malicious pickle deserialization
- **Framework Observability** - Uprobes for PyTorch, TensorFlow, ONNX
- **Prometheus Metrics** - Built-in observability and alerting
- **Zero Code Change** - Pure kernel-level protection

---

## Quick Start

### Docker (Recommended)

```bash
# Build image
docker build -t neurosentry:latest .

# Run (requires Linux host)
docker run --privileged --pid=host --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v $(pwd)/deploy/neurosentry.yaml:/etc/neurosentry/config.yaml \
  neurosentry:latest
```

### From Source

```bash
# Install dependencies
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# Build
make build

# Run
sudo ./bin/neurosentry --config deploy/neurosentry.yaml

# View metrics
curl http://localhost:2112/metrics
```

### Kubernetes

```bash
kubectl apply -f deploy/kubernetes/
```

---

## Documentation

- **[Architecture](docs/architecture.md)** - System design and eBPF integration
- **[User Guide](docs/user-guide.md)** - Installation, configuration, deployment
- **[Developer Guide](docs/developer-guide.md)** - Building, testing, contributing
- **[Demo Guide](docs/demo-guide.md)** - Demo environment setup and usage
- **[Capture The Model](demos/capture-the-model/README.md)** - Interactive demo environment

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Linux 5.10+ (for LSM BPF support) |
| **Kernel** | `CONFIG_BPF_LSM=y` |
| **Go** | 1.24+ |
| **Clang/LLVM** | 12+ (for eBPF compilation) |
| **Privileges** | Root/CAP_BPF+CAP_SYS_ADMIN |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    User Space (Go Agent)                        │
│  Controller  │  Policy Engine  │  Events  │  Metrics (Prometheus) │
└───────────────────────────┬─────────────────────────────────────┘
                            │ eBPF Maps
┌───────────────────────────┴─────────────────────────────────────┐
│                     Kernel Space (eBPF)                         │
│  LSM Hooks  │  TC/XDP Filter  │  Uprobes  │  Kprobes             │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────────┐
│                      Linux Kernel                                │
└─────────────────────────────────────────────────────────────────┘
```

**[Full Architecture Documentation →](docs/architecture.md)**

---

## Performance

- **LSM Hooks**: <1% overhead per file operation
- **TC**: ~100ns per packet (works on all cloud platforms)
- **XDP**: ~50ns per packet (driver-level, limited cloud support)
- **Uprobes**: <5% per hooked function call

---

## Roadmap

- [ ] Windows support (via eBPF-for-Windows)
- [ ] GPU memory monitoring
- [ ] Model SBOM verification
- [ ] Distributed policy federation

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

---

## Contact

- **Issues**: [GitHub Issues](https://github.com/tonghuaroot/neurosentry/issues)
- **Discussions**: [GitHub Discussions](https://github.com/tonghuaroot/neurosentry/discussions)
