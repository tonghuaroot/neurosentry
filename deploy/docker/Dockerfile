# NeuroSentry Docker Image
# Multi-stage build for minimal production image

# Build stage
FROM golang:1.26.3-alpine AS builder

# Install build dependencies (eBPF is pre-compiled, no need for clang/llvm)
RUN apk add --no-cache \
    git \
    make \
    libbpf-dev

WORKDIR /build

# Copy source code
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the eBPF programs and Go binary
RUN make build

# Production stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libbpf \
    iptables \
    ip6tables \
    iproute2

# Create non-root user
RUN addgroup -g 1000 neurosentry && \
    adduser -D -u 1000 -G neurosentry neurosentry

# Copy binary from builder
COPY --from=builder /build/bin/neurosentry /usr/local/bin/neurosentry

# Copy default configuration
COPY deploy/neurosentry.yaml /etc/neurosentry/config.yaml

# Copy entrypoint script
COPY deploy/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create necessary directories
RUN mkdir -p /var/log/neurosentry /run/neurosentry /etc/neurosentry && \
    chown -R neurosentry:neurosentry /var/log/neurosentry /run/neurosentry

# Expose metrics port
EXPOSE 2112

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:2112/health || exit 1

# For eBPF, container must run as root or with specific capabilities
# User can be set via NEUROSENTRY_USER environment variable
ENTRYPOINT ["/entrypoint.sh"]
CMD ["neurosentry", "--config", "/etc/neurosentry/config.yaml"]
