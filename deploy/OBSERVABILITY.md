# Observability stack (Prometheus + Grafana)

NeuroSentry exposes Prometheus metrics on `:2112/metrics`. This directory ships
a one-command stack that scrapes them and renders a provisioned Grafana
dashboard.

```bash
docker compose -f deploy/docker-compose.yml up -d
# Grafana:      http://localhost:3000   (admin / neurosentry)
# Prometheus:   http://localhost:9090
# NeuroSentry:  http://localhost:8080   (console)  ·  :2112/metrics
```

The **"NeuroSentry — AI Runtime Security"** dashboard is auto-provisioned under
the *NeuroSentry* folder and includes:

- Agent uptime, total model-access blocks, total cross-layer findings, gateway cost (USD)
- Correlation findings by **severity** and by **detection rule** (rate/increase)
- AI gateway requests by **action** (allowed/blocked)
- Events processed rate

Key metric families:

| Metric | Meaning |
|---|---|
| `neurosentry_correlation_findings_total{rule,severity,technique}` | cross-layer detections |
| `neurosentry_gateway_requests_total{provider,action}` | AI gateway request outcomes |
| `neurosentry_gateway_cost_usd_total{tenant,provider}` | metered relay cost |
| `neurosentry_model_access_blocked_total{extension}` | kernel LSM file blocks |
| `neurosentry_events_total{status}` | processed events |
| `neurosentry_uptime_seconds` | agent uptime |

Alert rules live in `prometheus/alert_rules.yml`.

> The eBPF layer needs a Linux host kernel. On the compose stack, the
> `neurosentry` service runs privileged with host PID/network so LSM/TC/uprobe
> can attach; on non-Linux hosts it degrades to the user-space layers.
