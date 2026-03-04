#!/bin/bash
# NeuroSentry Build Script
# Compiles eBPF programs and Go binaries

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"
BIN_DIR="${PROJECT_ROOT}/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root - not recommended for build"
    fi
}

# Check dependencies
check_deps() {
    log_info "Checking dependencies..."

    local missing=0

    # Check for Go
    if ! command -v go &> /dev/null; then
        log_error "Go not found. Please install Go 1.21+"
        missing=1
    fi

    # Check for clang
    if ! command -v clang &> /dev/null; then
        log_error "clang not found. Please install clang"
        missing=1
    fi

    # Check for llvm-strip
    if ! command -v llvm-strip &> /dev/null; then
        log_error "llvm-strip not found. Please install LLVM toolchain"
        missing=1
    fi

    # Check for bpftool (optional but recommended)
    if ! command -v bpftool &> /dev/null; then
        log_warn "bpftool not found. Recommended for vmlinux.h generation"
    fi

    if [ $missing -eq 1 ]; then
        log_error "Missing required dependencies. Aborting."
        exit 1
    fi

    log_info "All dependencies satisfied"
}

# Generate vmlinux.h
generate_vmlinux() {
    log_info "Generating vmlinux.h..."

    local vmlinux_path="${PROJECT_ROOT}/pkg/bpf/headers/vmlinux.h"

    # Try to get vmlinux.h from BTF
    if [ -f "/sys/kernel/btf/vmlinux" ]; then
        if command -v bpftool &> /dev/null; then
            bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$vmlinux_path"
            log_info "Generated vmlinux.h from BTF"
            return 0
        fi
    fi

    log_warn "Could not generate vmlinux.h from BTF"
    log_warn "Using placeholder header - some features may not work"
}

# Build eBPF programs
build_bpf() {
    log_info "Building eBPF programs..."

    cd "${PROJECT_ROOT}/pkg/bpf"

    # Build each eBPF program
    for prog in neurosentry_lsm neurosentry_xdp neurosentry_uprobe; do
        log_info "Building ${prog}..."

        # Generate bpf2go code
        cd "${PROJECT_ROOT}"
        go generate ./pkg/bpf/...

        if [ $? -ne 0 ]; then
            log_error "Failed to generate ${prog}"
            exit 1
        fi
    done

    log_info "eBPF programs compiled successfully"
}

# Build Go binary
build_go() {
    log_info "Building NeuroSentry agent..."

    mkdir -p "$BIN_DIR"

    local version="dev"
    local commit="unknown"
    local build_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Try to get git info
    if git rev-parse HEAD &> /dev/null; then
        commit=$(git rev-parse --short HEAD)
        version=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
    fi

    # Build binary
    cd "$PROJECT_ROOT"

    CGO_ENABLED=0 go build \
        -ldflags="-X 'main.version=${version}' -X 'main.commit=${commit}' -X 'main.date=${build_time}'" \
        -o "$BIN_DIR/neurosentry" \
        ./cmd/neurosentry

    if [ $? -eq 0 ]; then
        log_info "Binary built: $BIN_DIR/neurosentry"
    else
        log_error "Failed to build binary"
        exit 1
    fi
}

# Build Docker image
build_docker() {
    log_info "Building Docker image..."

    cd "$PROJECT_ROOT"

    # Check if docker is available
    if ! command -v docker &> /dev/null; then
        log_warn "Docker not found. Skipping Docker build."
        return 0
    fi

    local version="dev"
    if git rev-parse HEAD &> /dev/null; then
        version=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
    fi

    docker build \
        -t neurosentry:${version} \
        -t neurosentry:latest \
        -f deploy/docker/Dockerfile \
        .

    if [ $? -eq 0 ]; then
        log_info "Docker image built: neurosentry:${version}"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi
}

# Main build process
main() {
    log_info "NeuroSentry Build Starting..."
    log_info "Project root: $PROJECT_ROOT"

    check_root
    check_deps

    # Create build directories
    mkdir -p "$BUILD_DIR"
    mkdir -p "$BIN_DIR"

    # Build components
    generate_vmlinux
    build_bpf
    build_go

    # Build Docker if requested
    if [ "$1" == "--docker" ]; then
        build_docker
    fi

    log_info "Build complete!"
    log_info "Binary: $BIN_DIR/neurosentry"
    log_info ""
    log_info "To run NeuroSentry:"
    log_info "  sudo $BIN_DIR/neurosentry --config config.yaml"
}

# Run main
main "$@"
