#!/bin/bash
# Test eBPF loading on remote Linux server

KEY="/Users/ben/Documents/99-Keys/java-sec-code.pem"
SERVER="ubuntu@13.209.69.99"

echo "Testing XDP program loading..."

# Test XDP loading
ssh -i "$KEY" "$SERVER" "sudo /usr/lib/linux-tools-6.8.0-94/bpftool prog load /tmp/neurosentry_test/neurosentry_xdp.o /sys/fs/bpf/neurosentry_xdp" 2>&1

# Check if loaded
ssh -i "$KEY" "$SERVER" "sudo /usr/lib/linux-tools-6.8.0-94/bpftool prog show | grep neurosentry" 2>&1

echo "Testing Uprobe program loading..."

# Test Uprobe loading
ssh -i "$KEY" "$SERVER" "sudo /usr/lib/linux-tools-6.8.0-94/bpftool prog load /tmp/neurosentry_test/neurosentry_uprobe.o /sys/fs/bpf/neurosentry_uprobe" 2>&1

# Check if loaded
ssh -i "$KEY" "$SERVER" "sudo /usr/lib/linux-tools-6.8.0-94/bpftool prog show | grep neurosentry" 2>&1

echo "Done!"
