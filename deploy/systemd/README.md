# Running NeuroSentry with real eBPF enforcement

NeuroSentry's kernel layer (LSM file blocking, TC network monitoring, uprobe
framework observability) requires a Linux host — it does not run on macOS. Use
`--skip-bpf` only for developing the user-space layers off-Linux.

## Kernel requirements

| Capability | Requirement |
|---|---|
| LSM `file_open` blocking (core) | `bpf` present in `/sys/kernel/security/lsm` and `CONFIG_BPF_LSM=y`. Many distros need `lsm=...,bpf` on the kernel command line; **Amazon Linux 2023 (kernel 6.1) ships with `bpf` LSM enabled by default** — no reboot needed. |
| TC network (TCX) | kernel ≥ 6.6 for native TCX; older kernels fall back to legacy `tc` — install `iproute-tc` (AL2023) / `iproute2` (Debian). |
| CO-RE (portable eBPF) | BTF at `/sys/kernel/btf/vmlinux` (present on all modern kernels). |
| Load/attach | run as root (or `CAP_BPF`+`CAP_SYS_ADMIN`+`CAP_PERFMON`+`CAP_NET_ADMIN`); `LimitMEMLOCK=infinity`. |

## Install

```bash
sudo cp neurosentry /usr/local/bin/
sudo cp deploy/neurosentry-production.yaml /etc/neurosentry/config.yaml
sudo cp deploy/systemd/neurosentry.service /etc/systemd/system/
sudo mkdir -p /var/log/neurosentry /var/lib/neurosentry /models
sudo systemctl daemon-reload
sudo systemctl enable --now neurosentry
```

## Verify enforcement

```bash
# A protected model-file read is denied by the kernel LSM hook (-EPERM),
# even as root, and recorded in the tamper-proof audit chain:
sudo dd if=/dev/urandom of=/models/x.safetensors bs=1M count=1
cat /models/x.safetensors            # -> Operation not permitted
journalctl -u neurosentry | grep BLOCKED
```
