#!/bin/bash
# Stop and clean up the Capture The Model Challenge.
#
# Default: docker compose down (preserves volumes + the 13 GB model file).
# --purge: also remove docker volumes (Prometheus + Grafana data) AND wipe
#          the host-side ./model-data/ directory. Use this when you want a
#          fully clean slate; expect ~3-5 min on the next start.sh while
#          the model file regenerates.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PURGE=0
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        -h|--help)
            echo "Usage: $0 [--purge]"
            echo ""
            echo "  (default)  docker compose down — keeps model + dashboards"
            echo "  --purge    also docker compose down -v + rm -rf ./model-data/"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg (try $0 --help)"
            exit 1
            ;;
    esac
done

if command -v docker-compose &> /dev/null; then
    DC="docker-compose"
elif docker compose version &> /dev/null; then
    DC="docker compose"
else
    echo "Error: neither 'docker-compose' (v1) nor 'docker compose' (v2) is available"
    exit 1
fi

echo "[+] Stopping Capture The Model Challenge..."
$DC down

if [ "$PURGE" = "1" ]; then
    echo "[+] --purge: removing volumes (Prometheus + Grafana data)..."
    $DC down -v
    echo "[+] --purge: wiping host-side ./model-data/ ..."
    rm -rf ./model-data
    echo "[+] Purge complete. Next start.sh will regenerate the 13 GB model file."
else
    echo "[+] Volumes and ./model-data/ preserved. Re-run with --purge to wipe."
fi

echo "[+] Challenge stopped."
