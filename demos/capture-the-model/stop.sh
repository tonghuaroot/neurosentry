#!/bin/bash
# Stop and clean up the Capture The Model Challenge

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Stopping Capture The Model Challenge..."
docker-compose down

echo "Removing volumes (optional - comment out to keep data)..."
docker-compose down -v

echo "Challenge stopped."
