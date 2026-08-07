#!/usr/bin/env bash
# Copyright 2025 NeuroSentry Contributors
# SPDX-License-Identifier: Apache-2.0
#
# A/B measurement of the per-open() overhead added by NeuroSentry's LSM
# file_open hook, on a live Linux host. Measures open() latency with the agent
# ACTIVE (hook attached) vs STOPPED (no hook), then diffs the distributions.
#
# Isolating the hook requires toggling enforcement, so this briefly stops the
# neurosentry service and restarts it. Run on the target host as root:
#
#   sudo ./lsm_latency.sh /usr/local/bin/lsm-latency
#
# Output: two JSON lines (agent-on, agent-off) — diff p50_ns / p99_ns for the
# per-open hook overhead. Keep ITERS identical across runs for comparability.
set -euo pipefail

BIN="${1:-/usr/local/bin/lsm-latency}"
SVC="${SVC:-neurosentry.service}"
ITERS="${ITERS:-200000}"
PROBE="${PROBE:-/tmp/nsbench.probe}"

if [[ ! -x "$BIN" ]]; then
  echo "lsm-latency binary not found/executable at $BIN" >&2
  exit 1
fi

was_active="no"
if systemctl is-active --quiet "$SVC"; then
  was_active="yes"
fi

echo "# agent-ON (LSM hook attached)"
if [[ "$was_active" != "yes" ]]; then
  systemctl start "$SVC"
  sleep 3
fi
"$BIN" -path "$PROBE" -iterations "$ITERS" -label agent-on

echo "# agent-OFF (baseline, no hook)"
systemctl stop "$SVC"
sleep 2
"$BIN" -path "$PROBE" -iterations "$ITERS" -label agent-off

# Restore prior state (default: bring protection back up).
if [[ "$was_active" == "yes" ]]; then
  systemctl start "$SVC"
  sleep 2
  systemctl is-active --quiet "$SVC" && echo "# $SVC restored to active"
fi
