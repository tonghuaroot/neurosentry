#!/bin/bash
# Build eBPF programs on remote Linux server

KEY="/Users/ben/Documents/99-Keys/java-sec-code.pem"
SERVER="ubuntu@13.209.69.99"
LOCAL_DIR="/Users/ben/Documents/04.Project/NeuroSentry"
REMOTE_DIR="/tmp/neurosentry_test"

echo "Building eBPF programs on remote server..."

# Create remote temp directory
ssh -i "$KEY" "$SERVER" "mkdir -p $REMOTE_DIR"

# Copy C files to remote server
scp -i "$KEY" "$LOCAL_DIR/pkg/bpf/neurosentry_xdp.c" "$SERVER:$REMOTE_DIR/"
scp -i "$KEY" "$LOCAL_DIR/pkg/bpf/neurosentry_uprobe.c" "$SERVER:$REMOTE_DIR/"

# Build XDP
ssh -i "$KEY" "$SERVER" << 'ENDSSH'
cd /tmp/neurosentry_test
clang -target bpf -g -O2 -I./headers/ -c neurosentry_xdp.c -o neurosentry_xdp.o
echo "XDP build complete"
file neurosentry_xdp.o
ENDSSH

# Build Uprobe
ssh -i "$KEY" "$SERVER" << 'ENDSSH'
cd /tmp/neurosentry_test
clang -target bpf -g -O2 -I./headers/ -c neurosentry_uprobe.c -o neurosentry_uprobe.o
echo "Uprobe build complete"
file neurosentry_uprobe.o
ENDSSH

# Copy back the built objects
scp -i "$KEY" "$SERVER:$REMOTE_DIR/neurosentry_xdp.o" "$LOCAL_DIR/pkg/bpf/build/"
scp -i "$KEY" "$SERVER:$REMOTE_DIR/neurosentry_uprobe.o" "$LOCAL_DIR/pkg/bpf/build/"

echo "Build complete! Objects copied to pkg/bpf/build/"
