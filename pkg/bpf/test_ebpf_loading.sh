#!/bin/bash
# NeuroSentry eBPF Loading Test Script
# Tests loading all eBPF programs on the Linux server

set -e

# Set bpftool path for kernel 6.14
export PATH="/usr/lib/linux-tools-6.8.0-94:$PATH"
BPFTOOL="/usr/lib/linux-tools-6.8.0-94/bpftool"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BPF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Use current directory if build doesn't exist (for remote testing)
if [[ -d "$BPF_DIR/build" ]]; then
    BUILD_DIR="$BPF_DIR/build"
else
    BUILD_DIR="$BPF_DIR"
fi

echo -e "${GREEN}=== NeuroSentry eBPF Loading Test ===${NC}"
echo ""

# Check if we're running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   echo "Please run: sudo $0"
   exit 1
fi

# Check if build directory exists
if [[ ! -d "$BUILD_DIR" ]]; then
    echo -e "${RED}Error: Build directory not found: $BUILD_DIR${NC}"
    echo "Please run build_ebpf.sh first to compile eBPF programs"
    exit 1
fi

# Function to test load an eBPF program
test_load() {
    local prog_name="$1"
    local obj_file="$2"
    local prog_path="$3"

    echo -e "${YELLOW}Testing: $prog_name${NC}"

    if [[ ! -f "$obj_file" ]]; then
        echo -e "${RED}  Object file not found: $obj_file${NC}"
        return 1
    fi

    # Check if program already loaded
    if $BPFTOOL prog show | grep -q "$prog_name"; then
        echo -e "${YELLOW}  Already loaded, removing old instance...${NC}"
        $BPFTOOL prog show | grep "$prog_name" | awk '{print $1}' | while read prog_id; do
            $BPFTOOL prog detach $prog_id 2>/dev/null || true
        done
    fi

    # Clean up old pin path if it exists
    if [[ -d "$prog_path" ]] || [[ -f "$prog_path" ]]; then
        rm -rf "$prog_path" 2>/dev/null || true
    fi

    # Load the program
    if $BPFTOOL prog load "$obj_file" "$prog_path" 2>&1; then
        echo -e "${GREEN}  ✓ Loaded successfully${NC}"

        # Show program info
        $BPFTOOL prog show | grep -A5 "$prog_name" || true

        # Detach (cleanup)
        $BPFTOOL prog detach "$prog_path" 2>/dev/null || true

        return 0
    else
        echo -e "${RED}  ✗ Failed to load${NC}"
        return 1
    fi
}

# Test each eBPF program
echo -e "${GREEN}1. Testing LSM (simple) program...${NC}"
test_load "restrict_model_file_access" \
    "$BUILD_DIR/neurosentry_lsm_simple.o" \
    "/sys/fs/bpf/neurosentry_lsm_simple"
echo ""

echo -e "${GREEN}2. Testing LSM (main) program...${NC}"
test_load "restrict_model_file_access" \
    "$BUILD_DIR/neurosentry_lsm.o" \
    "/sys/fs/bpf/neurosentry_lsm"
echo ""

echo -e "${GREEN}3. Testing XDP program...${NC}"
test_load "neurosentry_xdp_filter" \
    "$BUILD_DIR/neurosentry_xdp.o" \
    "/sys/fs/bpf/neurosentry_xdp"
echo ""

echo -e "${GREEN}4. Testing Uprobe program...${NC}"
test_load "uprobe_torch_load" \
    "$BUILD_DIR/neurosentry_uprobe.o" \
    "/sys/fs/bpf/neurosentry_uprobe"
echo ""

echo -e "${GREEN}=== Test complete ===${NC}"
echo ""
echo "To manually inspect loaded programs:"
echo "  $BPFTOOL prog show"
echo "  $BPFTOOL map show"
