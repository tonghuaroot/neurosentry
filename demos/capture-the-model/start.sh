#!/bin/bash
# Quick start script for Capture The Model Challenge

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "NeuroSentry: Capture The Model"
echo "Hands-on lab challenge"
echo "=========================================="
echo ""

# Check Docker (accept both v1 binary `docker-compose` and v2 plugin `docker compose`)
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

if command -v docker-compose &> /dev/null; then
    DC="docker-compose"
elif docker compose version &> /dev/null; then
    DC="docker compose"
else
    echo "Error: neither 'docker-compose' (v1) nor the 'docker compose' (v2) plugin is available"
    exit 1
fi

# Verify BPF LSM is in the active LSM stack — without this the agent will
# load but the LSM hook will silently fail to attach.
if [ -r /sys/kernel/security/lsm ]; then
    if ! grep -qw bpf /sys/kernel/security/lsm; then
        echo "Error: 'bpf' is not in the active LSM stack."
        echo "  current: $(cat /sys/kernel/security/lsm)"
        echo "  fix: add 'lsm=lockdown,capability,landlock,yama,apparmor,bpf' to"
        echo "       GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub.d/, run"
        echo "       'sudo update-grub', then reboot."
        exit 1
    fi
else
    echo "Warning: /sys/kernel/security/lsm not readable; cannot verify BPF LSM is active."
fi

# Check if running as root (required for eBPF)
if [ "$EUID" -ne 0 ]; then
    echo "Warning: Not running as root. eBPF requires privileged mode."
    echo "The docker-compose configuration uses privileged containers."
    echo ""
fi

# Create necessary directories
echo "[+] Setting up directories..."
mkdir -p workspace logs scoring/data config/grafana/dashboards config/grafana/datasources

# Check if NeuroSentry image exists, if not build it
if ! docker images neurosentry:ctf-latest -q | grep -q .; then
    echo "[+] Building NeuroSentry image..."
    docker build -t neurosentry:ctf-latest -f ../../deploy/docker/Dockerfile ../..
fi

# Generate model file if it doesn't exist
MODEL_FILE="model-data/llama-2-7b.safetensors"
if [ ! -f "$MODEL_FILE" ]; then
    echo "[+] Generating fake model file..."
    docker run --rm -v "$(pwd)/model-data:/models" alpine:3.19 \
        sh -c "dd if=/dev/urandom of=/models/llama-2-7b.safetensors bs=1M count=13312 2>/dev/null && \
               md5sum /models/llama-2-7b.safetensors > /models/llama-2-7b.md5"
    echo "[+] Model file generated"
else
    echo "[+] Model file already exists"
fi

# Start the challenge
echo "[+] Starting challenge environment..."
$DC up -d

# Wait for services to be ready
echo "[+] Waiting for services to initialize..."
sleep 5

# Check status
echo ""
echo "=========================================="
echo "Challenge Started!"
echo "=========================================="
echo ""
echo "Access the attacker container:"
echo "  docker exec -it attacker sh"
echo ""
echo "View NeuroSentry logs:"
echo "  docker logs -f neurosentry"
echo ""
echo "View scoring dashboard:"
echo "  curl http://localhost:8080/status"
echo ""
echo "View metrics:"
echo "  curl http://localhost:2112/metrics"
echo ""
echo "Mission brief is in the attacker container at:"
echo "  /workspace/mission.txt"
echo ""
echo "Good luck!"
