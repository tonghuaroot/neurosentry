#!/bin/bash
# NeuroSentry eBPF Build Script
# This script compiles eBPF programs for the target kernel
# Run this on a Linux system with BTF enabled (kernel 5.8+)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BPF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEADER_DIR="$BPF_DIR/headers"
BUILD_DIR="$BPF_DIR/build"
CLANG="clang"
LLVM_STRIP="llvm-strip"

# Check if we're on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${YELLOW}Warning: Not running on Linux. This script must be run on a Linux system.${NC}"
    echo "To compile eBPF programs:"
    echo "  1. SSH to a Linux build host with clang + libbpf-dev"
    echo "  2. Run this script there"
    echo "  (or use pkg/bpf/generate_ebpf.sh which builds via Docker)"
    exit 1
fi

# Check required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 not found. Please install: $2${NC}"
        exit 1
    fi
}

check_tool "$CLANG" "clang (llvm)"
check_tool "$LLVM_STRIP" "llvm-strip (llvm)"
check_tool "bpftool" "linux-tools"

# Create build directory
mkdir -p "$BUILD_DIR"

# Generate vmlinux.h from BTF if it doesn't exist or is outdated
VMLINUX_H="$HEADER_DIR/vmlinux.h"
BTF_FILE="/sys/kernel/btf/vmlinux"

if [[ ! -f "$VMLINUX_H" ]] || [[ "$BTF_FILE" -nt "$VMLINUX_H" ]]; then
    echo -e "${GREEN}Generating vmlinux.h from BTF...${NC}"

    if [[ ! -f "$BTF_FILE" ]]; then
        echo -e "${RED}Error: BTF not available at $BTF_FILE${NC}"
        echo "Please ensure your kernel has BTF enabled (CONFIG_DEBUG_INFO_BTF=y)"
        exit 1
    fi

    mkdir -p "$HEADER_DIR"
    bpftool btf dump file "$BTF_FILE" format c > "$VMLINUX_H"
    echo -e "${GREEN}Generated: $VMLINUX_H${NC}"
fi

# Compile eBPF programs
compile_bpf() {
    local src="$1"
    local obj="${src%.c}.o"
    local obj_name=$(basename "$obj")

    echo -e "${GREEN}Compiling: $obj_name${NC}"

    "$CLANG" -target bpf \
        -g \
        -O2 \
        -D__TARGET_ARCH_x86 \
        -I"$HEADER_DIR" \
        -c "$src" \
        -o "$BUILD_DIR/$(basename "$obj")"

    # Strip debug info (optional, reduces size)
    "$LLVM_STRIP" -g "$BUILD_DIR/$(basename "$obj")"

    echo -e "${GREEN}Built: $BUILD_DIR/$(basename "$obj")${NC}"
}

# Compile each eBPF program
echo -e "${GREEN}=== Building NeuroSentry eBPF programs ===${NC}"

# Simple LSM (for testing)
if [[ -f "$BPF_DIR/neurosentry_lsm_simple.c" ]]; then
    compile_bpf "$BPF_DIR/neurosentry_lsm_simple.c"
fi

# Main LSM program
if [[ -f "$BPF_DIR/neurosentry_lsm.c" ]]; then
    compile_bpf "$BPF_DIR/neurosentry_lsm.c"
fi

# XDP program
if [[ -f "$BPF_DIR/neurosentry_xdp.c" ]]; then
    compile_bpf "$BPF_DIR/neurosentry_xdp.c"
fi

# Uprobe program
if [[ -f "$BPF_DIR/neurosentry_uprobe.c" ]]; then
    compile_bpf "$BPF_DIR/neurosentry_uprobe.c"
fi

echo -e "${GREEN}=== Build complete ===${NC}"
echo -e "${GREEN}Output directory: $BUILD_DIR${NC}"
echo ""
echo "To test load an eBPF program:"
echo "  sudo bpftool prog load $BUILD_DIR/neurosentry_lsm_simple.o /sys/fs/bpf/neurosentry_lsm"
echo "  sudo bpftool prog show"
