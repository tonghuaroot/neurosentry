#!/bin/sh
# NeuroSentry Docker Entrypoint
# Handles privilege escalation and eBPF setup

set -e

echo "Starting NeuroSentry..."

# Check if running with required privileges
if [ ! -w /sys/kernel/debug ] && [ "$EUID" -ne 0 ]; then
    echo "ERROR: NeuroSentry requires privileged mode for eBPF operations"
    echo "Please run with: --privileged --pid=host --network=host"
    echo "Or add capabilities: --cap-add=BPF --cap-add=NET_ADMIN --cap-add=SYS_ADMIN"
    exit 1
fi

# Mount debugfs if not already mounted
if ! mount | grep -q "/sys/kernel/debug"; then
    if [ "$EUID" -eq 0 ]; then
        echo "Mounting debugfs..."
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi
fi

# Mount BPF filesystem if not already mounted
if ! mount | grep -q "/sys/fs/bpf"; then
    if [ "$EUID" -eq 0 ]; then
        echo "Mounting BPF filesystem..."
        mount -t bpf none /sys/fs/bpf 2>/dev/null || true
    fi
fi

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
REQUIRED_VERSION="5.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$KERNEL_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "WARNING: Kernel version $KERNEL_VERSION may not support all eBPF features"
    echo "Recommended: Linux 5.10+"
fi

# Check for BTF support
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "WARNING: BTF not available. CO-RE eBPF programs may not work correctly."
    echo "Consider enabling CONFIG_DEBUG_INFO_BTF in your kernel."
fi

# Check if config exists
if [ ! -f "/etc/neurosentry/config.yaml" ]; then
    echo "WARNING: Config file not found, using defaults"
    mkdir -p /etc/neurosentry
    cat > /etc/neurosentry/config.yaml << 'EOF'
protection:
  model_fim:
    enabled: true
    protected_extensions:
      - .safetensors
      - .gguf
      - .pth
      - .pkl
    enforce_mode: true
  network_containment:
    enabled: true
    allowed_egress:
      - 10.0.0.0/8
      - 172.16.0.0/12
    block_exfiltration: true
  pickle_protection:
    enabled: true
agent:
  metrics_port: 2112
  log_level: info
EOF
fi

# Display configuration
echo "NeuroSentry Configuration:"
echo "  - Metrics Port: 2112"
echo "  - Config: /etc/neurosentry/config.yaml"
echo "  - eBPF Support: Checking..."

# If running as root, drop privileges for the main process
# (eBPF programs are already loaded by this point if needed)
if [ "$EUID" -eq 0 ] && [ -n "$NEUROSENTRY_USER" ]; then
    echo "Switching to user: $NEUROSENTRY_USER"
    exec su-exec "$NEUROSENTRY_USER" "$@"
else
    # Run as current user (might be root in privileged container)
    exec "$@"
fi
