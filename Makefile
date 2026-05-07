# NeuroSentry Makefile
# Used for building the project

.PHONY: all build clean test docker-build docker-run

# Variables
BINARY_NAME=neurosentry
BUILD_DIR=build
BIN_DIR=bin
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
LDFLAGS=-X 'main.version=$(VERSION)' -X 'main.commit=$(COMMIT)' -X 'main.date=$(BUILD_TIME)'

all: build

# Build Go binary
build:
	@echo "Building NeuroSentry..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/neurosentry
	@echo "Built: $(BIN_DIR)/$(BINARY_NAME)"

# Generate eBPF code (uses bpf2go)
# Note: This requires clang and llvm-strip to be in PATH
# On macOS with Homebrew: export PATH="/opt/homebrew/opt/llvm/bin:$$PATH"
generate:
	@echo "Generating eBPF code..."
	@cd pkg/bpf && go generate ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR) $(BUILD_DIR)
	@find . -name "*.bpf.o" -delete
	@find . -name "*.so" -delete
	@find . -name "*_bpfel.o" -delete
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./pkg/...

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t neurosentry:$(VERSION) -t neurosentry:latest -f deploy/docker/Dockerfile .
	@echo "Docker image built: neurosentry:$(VERSION)"

# Run Docker container
docker-run:
	@echo "Running NeuroSentry in Docker..."
	docker run --rm -it \
		--privileged \
		--pid=host \
		--network=host \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/fs/bpf:/sys/fs/bpf \
		-v $(PWD)/deploy/neurosentry.yaml:/etc/neurosentry/config.yaml \
		neurosentry:latest

# Development environment
dev:
	@echo "Starting development environment..."
	docker-compose -f demos/test-environment/docker-compose.yml up -d

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	golangci-lint run ./...

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Generate vmlinux.h from BTF (requires Linux with BTF enabled)
vmlinux:
	@echo "Generating vmlinux.h from BTF..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/bpf/headers/vmlinux.h; \
		echo "Generated: pkg/bpf/headers/vmlinux.h"; \
	else \
		echo "BTF not available at /sys/kernel/btf/vmlinux"; \
		echo "This command must be run on a Linux system with BTF enabled."; \
		echo "See docs/EBPF_COMPILATION.md for detailed instructions."; \
		exit 1; \
	fi

# Build eBPF programs (requires Linux)
ebpf:
	@echo "Building eBPF programs..."
	@if [ "$$(uname)" = "Linux" ]; then \
		cd pkg/bpf && chmod +x build_ebpf.sh && ./build_ebpf.sh; \
	else \
		echo "eBPF compilation requires Linux."; \
		echo "See docs/EBPF_COMPILATION.md for cross-compilation options."; \
		exit 1; \
	fi

# Build eBPF on remote server via SSH
# Usage: make ebpf-remote NEUROSENTRY_SSH_KEY=/path/to/key.pem [NEUROSENTRY_SSH_HOST=user@host]
NEUROSENTRY_SSH_HOST ?= ubuntu@localhost
NEUROSENTRY_SSH_USER ?= $(word 1,$(subst @, ,$(NEUROSENTRY_SSH_HOST)))
NEUROSENTRY_SSH_IP ?= $(word 2,$(subst @, ,$(NEUROSENTRY_SSH_HOST)))

ebpf-remote:
	@echo "Building eBPF programs on remote server..."
	@if [ -z "$$NEUROSENTRY_SSH_KEY" ]; then \
		echo "Error: NEUROSENTRY_SSH_KEY not set"; \
		echo "Usage: make ebpf-remote NEUROSENTRY_SSH_KEY=/path/to/key.pem NEUROSENTRY_SSH_HOST=user@host"; \
		exit 1; \
	fi
	@if [ "$(NEUROSENTRY_SSH_HOST)" = "ubuntu@localhost" ]; then \
		echo "Error: NEUROSENTRY_SSH_HOST not set"; \
		echo "Usage: make ebpf-remote NEUROSENTRY_SSH_KEY=/path/to/key.pem NEUROSENTRY_SSH_HOST=ubuntu@1.2.3.4"; \
		exit 1; \
	fi
	@echo "Copying files to remote server $(NEUROSENTRY_SSH_HOST)..."
	@ssh -i "$$NEUROSENTRY_SSH_KEY" -o StrictHostKeyChecking=accept-new $(NEUROSENTRY_SSH_HOST) "mkdir -p /tmp/neurosentry_build"
	@scp -i "$$NEUROSENTRY_SSH_KEY" -o StrictHostKeyChecking=accept-new -r pkg/bpf $(NEUROSENTRY_SSH_HOST):/tmp/neurosentry_build/
	@ssh -i "$$NEUROSENTRY_SSH_KEY" -o StrictHostKeyChecking=accept-new $(NEUROSENTRY_SSH_HOST) "cd /tmp/neurosentry_build/bpf && chmod +x build_ebpf.sh && ./build_ebpf.sh"
	@echo "Copying compiled objects back..."
	@scp -i "$$NEUROSENTRY_SSH_KEY" -o StrictHostKeyChecking=accept-new -r $(NEUROSENTRY_SSH_HOST):/tmp/neurosentry_build/bpf/build/*.o pkg/bpf/build/
	@echo "eBPF build complete!"

# Test eBPF loading on remote server
# Usage: make ebpf-test NEUROSENTRY_SSH_KEY=/path/to/key.pem NEUROSENTRY_SSH_HOST=user@host
ebpf-test:
	@echo "Testing eBPF program loading..."
	@if [ -z "$$NEUROSENTRY_SSH_KEY" ]; then \
		echo "Error: NEUROSENTRY_SSH_KEY not set"; \
		echo "Usage: make ebpf-test NEUROSENTRY_SSH_KEY=/path/to/key.pem NEUROSENTRY_SSH_HOST=user@host"; \
		exit 1; \
	fi
	@if [ "$(NEUROSENTRY_SSH_HOST)" = "ubuntu@localhost" ]; then \
		echo "Error: NEUROSENTRY_SSH_HOST not set"; \
		echo "Usage: make ebpf-test NEUROSENTRY_SSH_KEY=/path/to/key.pem NEUROSENTRY_SSH_HOST=ubuntu@1.2.3.4"; \
		exit 1; \
	fi
	@echo "Uploading test script and eBPF objects to $(NEUROSENTRY_SSH_HOST)..."
	@ssh -i "$$NEUROSENTRY_SSH_KEY" -o StrictHostKeyChecking=accept-new $(NEUROSENTRY_SSH_HOST) "mkdir -p /tmp/neurosentry_test/build"
	@scp -i "$$NEUROSENTRY_SSH_KEY" -o StrictHostKeyChecking=accept-new pkg/bpf/test_ebpf_loading.sh $(NEUROSENTRY_SSH_HOST):/tmp/neurosentry_test/
	@scp -i "$$NEUROSENTRY_SSH_KEY" -o StrictHostKeyChecking=accept-new pkg/bpf/build/*.o $(NEUROSENTRY_SSH_HOST):/tmp/neurosentry_test/build/
	@echo "Running eBPF loading test..."
	@ssh -i "$$NEUROSENTRY_SSH_KEY" -o StrictHostKeyChecking=accept-new $(NEUROSENTRY_SSH_HOST) "cd /tmp/neurosentry_test && chmod +x test_ebpf_loading.sh && sudo ./test_ebpf_loading.sh"
