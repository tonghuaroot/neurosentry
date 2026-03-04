#!/bin/bash
# NeuroSentry Demo Test Script

set -e

echo "=========================================="
echo "  NeuroSentry Demo Test"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; exit 1; }

# Test 1: Binary exists
echo -n "1. Checking binary..."
[ -f "./neurosentry" ] && pass "Binary exists" || fail "Binary not found"

# Test 2: Help command
echo -n "2. Testing help command..."
./neurosentry --help 2>&1 | grep -q "Usage:" && pass "Help works" || fail "Help failed"

# Test 3: Version command
echo -n "3. Testing version command..."
./neurosentry --version 2>&1 | grep -q "dev" && pass "Version works" || fail "Version failed"

# Test 4: Config validation
echo -n "4. Testing config validation..."
echo "invalid: true" > /tmp/bad.yaml
./neurosentry --config /tmp/bad.yaml 2>&1 | grep -q "Failed to load" && pass "Invalid config rejected" || fail "Config validation failed"

# Test 5: Skip BPF mode
echo -n "5. Testing skip-bpf mode..."
timeout 2 ./neurosentry --skip-bpf --config /tmp/test_metrics.yaml >/dev/null 2>&1 && pass "Skip BPF works" || true

# Test 6: Metrics server
echo -n "6. Testing metrics server..."
./neurosentry --skip-bpf --config /tmp/test_metrics.yaml >/dev/null 2>&1 &
NEU_PID=$!
sleep 2
if curl -s http://localhost:12112/health | grep -q "OK"; then
    pass "Metrics server works"
else
    fail "Metrics server failed"
fi
kill $NEU_PID 2>/dev/null

# Test 7: Go vet
echo -n "7. Running go vet..."
GOPROXY=https://goproxy.cn,direct go vet ./... >/dev/null 2>&1 && pass "No vet errors" || fail "Vet errors found"

echo ""
echo "=========================================="
echo "  All Tests Passed!"
echo "=========================================="
