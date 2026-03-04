#!/bin/bash
# NeuroSentry Dependency Installation Script
# Installs required dependencies for building and running NeuroSentry

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    log_error "Cannot detect OS"
    exit 1
fi

log_info "Detected OS: $OS $VERSION"

case $OS in
    ubuntu|debian)
        log_info "Installing dependencies for Debian-based system..."

        sudo apt-get update

        # Core dependencies
        sudo apt-get install -y \
            build-essential \
            git \
            clang \
            llvm \
            libelf-dev \
            libbpf-dev \
            linux-headers-$(uname -r) \
            bpftool \
            make \
            wget

        # Install Go if not present
        if ! command -v go &> /dev/null; then
            log_info "Installing Go 1.21..."
            wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
            rm go1.21.6.linux-amd64.tar.gz

            # Add to PATH if not already
            if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            fi
            export PATH=$PATH:/usr/local/go/bin
        fi

        # Install Docker if not present
        if ! command -v docker &> /dev/null; then
            log_warn "Docker not found. Installing Docker..."
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            rm get-docker.sh
            sudo usermod -aG docker $USER
            log_warn "Docker installed. You may need to log out and back in."
        fi
        ;;

    fedora|rhel|centos)
        log_info "Installing dependencies for Red Hat-based system..."

        sudo dnf install -y \
            gcc \
            git \
            clang \
            llvm \
            elfutils-libelf-devel \
            libbpf-devel \
            kernel-devel \
            bpftool \
            make \
            wget

        # Install Go
        if ! command -v go &> /dev/null; then
            log_info "Installing Go 1.21..."
            wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
            rm go1.21.6.linux-amd64.tar.gz
            export PATH=$PATH:/usr/local/go/bin
        fi

        # Install Docker
        if ! command -v docker &> /dev/null; then
            sudo dnf install -y docker
            sudo systemctl enable --now docker
            sudo usermod -aG docker $USER
        fi
        ;;

    arch|manjaro)
        log_info "Installing dependencies for Arch-based system..."

        sudo pacman -S --needed \
            base-devel \
            git \
            clang \
            llvm \
            libelf \
            libbpf \
            linux-headers \
            bpftool \
            make \
            go \
            docker
        ;;

    alpine)
        log_info "Installing dependencies for Alpine..."

        apk add \
            build-base \
            git \
            clang \
            llvm \
            libelf-dev \
            libbpf-dev \
            linux-lts-dev \
            bpftool \
            make \
            go
        ;;

    *)
        log_warn "Unsupported OS: $OS"
        log_warn "Please manually install:"
        log_warn "  - Go 1.21+"
        log_warn "  - Clang + LLVM"
        log_warn "  - libbpf-dev"
        log_warn "  - kernel headers"
        exit 1
        ;;
esac

log_info "Dependency installation complete!"
echo ""
log_info "Installed versions:"
go version 2>/dev/null || log_warn "Go not found in PATH"
clang --version 2>/dev/null | head -1
docker --version 2>/dev/null || log_warn "Docker not found"

echo ""
log_info "You may need to restart your shell or run:"
log_warn "  source ~/.bashrc"
