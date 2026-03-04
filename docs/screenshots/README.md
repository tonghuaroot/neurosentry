# NeuroSentry Testing Screenshots

This directory contains screenshots and output logs from end-to-end testing.

## Files

| File | Description |
|------|-------------|
| `metrics-output.txt` | Terminal output showing metrics after attack simulation |
| `grafana-dashboard.png` | Grafana dashboard screenshot (add manually) |
| `prometheus-targets.png` | Prometheus targets page screenshot (add manually) |

## How to Take Screenshots

1. **Set up port forwarding**:
   ```bash
   ssh -L 3000:localhost:3000 -L 9090:localhost:9090 ubuntu@<server-ip>
   ```

2. **Open Grafana Dashboard**:
   - URL: http://localhost:3000/d/neurosentry/
   - Login: admin / admin
   - Take screenshot of the full dashboard

3. **Open Prometheus Targets**:
   - URL: http://localhost:9090/targets
   - Take screenshot showing NeuroSentry target as "UP"

4. **View Metrics**:
   - URL: http://localhost:2112/metrics
   - Take screenshot or save output

## Test Environment

- **Date**: 2026-02-11
- **Server**: AWS EC2 (Ubuntu 24.04, Kernel 6.14)
- **NeuroSentry Version**: dev
- **Attack Scenarios**: File access, Network exfiltration, Malicious pickle

## Key Metrics Captured

- **File Accesses**: 24,109 attempts monitored
- **Network Packets**: 25,509 packets captured via TC
- **Uptime**: 675+ seconds
- **Errors**: 0
