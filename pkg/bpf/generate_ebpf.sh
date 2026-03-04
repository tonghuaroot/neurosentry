#!/bin/bash
# Generate eBPF Go bindings using Docker
# This script can be run from macOS or any system with Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Generating eBPF Go bindings ==="
echo "Repository root: $REPO_ROOT"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required but not installed."
    exit 1
fi

# Build the Docker image from repo root
echo "Building Docker image for bpf2go..."
docker build -t neurosentry-bpf2go -f pkg/bpf/Dockerfile.bpf2go "$REPO_ROOT"

# Run the generation with volume mount to get output files
echo "Generating eBPF Go bindings..."
docker run --rm \
    -v "$SCRIPT_DIR:/app/pkg/bpf" \
    neurosentry-bpf2go

echo "=== Generation complete ==="
echo "Generated files:"
ls -la "$SCRIPT_DIR"/*_bpfel.go "$SCRIPT_DIR"/*_bpfel.o 2>/dev/null || echo "(no files found - check for errors)"
