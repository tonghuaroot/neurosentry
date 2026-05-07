#!/bin/bash
# NeuroSentry Test Script
# Runs unit tests and integration tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

cd "$PROJECT_ROOT"

log_info "Running NeuroSentry tests..."
echo ""

# Run Go tests
log_info "Running Go unit tests..."

# Test config package
log_info "Testing config package..."
go test -v ./pkg/config/...

# Test policy package
log_info "Testing policy package..."
go test -v ./pkg/policy/...

# Test agent package
log_info "Testing agent package..."
go test -v ./pkg/agent/...

echo ""
log_info "All tests passed!"
echo ""

# Run with coverage if requested
if [ "$1" == "--coverage" ]; then
    log_info "Generating coverage report..."
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    log_info "Coverage report: coverage.html"
fi

# Run linting if requested
if [ "$1" == "--lint" ]; then
    log_info "Running linters..."

    if command -v golangci-lint &> /dev/null; then
        golangci-lint run ./...
    else
        log_warn "golangci-lint not found. Install via distro package or:"
        log_warn "  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
        log_warn "Pre-built binaries: https://github.com/golangci/golangci-lint/releases"
    fi

    if command -v gofmt &> /dev/null; then
        log_info "Checking code formatting..."
        fmt_output=$(gofmt -l .)
        if [ -n "$fmt_output" ]; then
            log_warn "Files need formatting:"
            echo "$fmt_output"
            log_warn "Run: go fmt ./..."
        fi
    fi
fi

echo ""
log_info "Test suite complete!"
