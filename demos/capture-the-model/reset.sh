#!/bin/bash
# Between-visitors quick-reset for the Arsenal booth demo.
#
# Resets visitor state without restarting any containers (~5 seconds):
#   - clears /tmp/stolen/* and /tmp/* attempt artifacts in the attacker
#   - clears the attacker shell history
#   - clears the leaderboard / attempts in the scoring server
#
# It does NOT touch the agent, NeuroSentry's eBPF maps, the 13 GB model file,
# Grafana dashboards, or the Prometheus TSDB. If a previous visitor mutated
# trusted_pids via bpftool from the host, run `restart-agent.sh` instead.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[+] Wiping visitor scratch state in attacker container..."
docker exec attacker sh -c 'rm -rf /tmp/stolen/* /tmp/out /tmp/x /tmp/x.* /tmp/got* 2>/dev/null; true'
docker exec attacker sh -c 'history -c 2>/dev/null; true'

echo "[+] Resetting scoring server state..."
curl -fsS -X POST http://localhost:8080/reset >/dev/null 2>&1 \
    || echo "    (scoring /reset endpoint not implemented; leaderboard preserved)"

echo "[+] Reset complete in <5s. Ready for next visitor."
