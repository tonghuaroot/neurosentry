#!/bin/bash
# Build and test Uprobe program on remote Linux server

KEY="/Users/ben/Documents/99-Keys/java-sec-code.pem"
SERVER="ubuntu@13.209.69.99"
LOCAL_DIR="/Users/ben/Documents/04.Project/NeuroSentry"
REMOTE_DIR="/tmp/neurosentry_test"

echo "Building and testing Uprobe program on remote server..."

# Copy fixed C file to remote server
scp -i "$KEY" "$LOCAL_DIR/pkg/bpf/neurosentry_uprobe.c" "$SERVER:$REMOTE_DIR/"

# Build Uprobe
ssh -i "$KEY" "$SERVER" << 'ENDSSH'
cd /tmp/neurosentry_test
clang -target bpf -g -O2 -I./headers/ -c neurosentry_uprobe.c -o neurosentry_uprobe.o
echo "Uprobe build complete"
file neurosentry_uprobe.o
ENDSSH

# Test loading
ssh -i "$KEY" "$SERVER" "sudo /usr/lib/linux-tools-6.8.0-94/bpftool prog load /tmp/neurosentry_test/neurosentry_uprobe.o /sys/fs/bpf/neurosentry_uprobe" 2>&1

# Check if loaded
ssh -i "$KEY" "$SERVER" "sudo /usr/lib/linux-tools-6.8.0-94/bpftool prog show | grep neurosentry" 2>&1

echo "Done!"
