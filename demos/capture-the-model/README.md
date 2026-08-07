# Capture The Model — hands-on lab challenge

## Overview

Capture The Model is a 15-minute hands-on challenge: try to exfiltrate a 13 GB
"protected" AI model file from a containerized inference environment while
NeuroSentry runs live on the host kernel.

The headline change for this revision: **LSM enforcement now performs true
kernel-level blocking.** Open syscalls against protected file extensions return
`-EPERM` from the `security_file_open` LSM hook before any byte is read. There
is no user-space interception path — `glibc`, Python, Go, and `dd` all see the
same hard error.

## Challenge Setup

### Quick Start (Recommended)

```bash
cd demos/capture-the-model
sudo ./start.sh
```

This will:
1. Build the `neurosentry:ctf-latest` Docker image (if missing)
2. Generate a fake 13 GB model file at `model-data/llama-2-7b.safetensors`
3. Start all services via `docker-compose up -d`
4. Print access instructions

The challenge brings up:
- **neurosentry** container (privileged, `--pid=host`, `--network=host`, enforce mode)
- **attacker** container (Alpine 3.19, your workspace, `/target` is read-only mount)
- **scoring** server (Python HTTP, tracks attempts and verifies MD5 on success)
- **prometheus** (metrics scrape on `:2112`)
- **grafana** (dashboard at <http://localhost:3000>, login `admin` / `neurosentry`)

### Entering the Workspace

```bash
docker exec -it attacker sh
cat /workspace/mission.txt
```

The protected file is bind-mounted read-only at:

```
/target/llama-2-7b.safetensors
```

## What Is Actually Enforced

NeuroSentry attaches four eBPF program types. Their behavior in this demo
matches `config/neurosentry.yaml`:

| Layer | Hook | Mode in this demo | Effect |
|-------|------|-------------------|--------|
| LSM | `lsm/file_open` | **ENFORCE** | Returns `-EPERM` for protected extensions opened by untrusted PIDs |
| LSM | `lsm/file_permission` | Monitor | Logs read attempts on already-open fds |
| TC  | `tc/clsact` ingress + egress | Monitor-only | Logs egress flows; does not drop |
| XDP | `xdp/generic` | Monitor-only | Per-packet stats only |
| Uprobe | PyTorch / pickle / TF / ONNX | Observe + alert | Flags `__reduce__` to dangerous symbols |

Protected extensions (from `config/neurosentry.yaml`):
`.safetensors`, `.gguf`, `.pth`, `.pt`, `.pkl`, `.bin`

Protected paths: `/models`, `/target`

> **Why is the network layer monitor-only?** Aggressive XDP/TC drops on a host
> sharing its network namespace with the demo containers (`network_mode: host`)
> would knock out the scoring server, Grafana, and the host's own connectivity.
> In production, pair NeuroSentry with a real network policy (Cilium, AWS SG,
> nftables). The LSM enforcement layer is independent and remains hard.

## Expected First Contact

The first thing every participant tries:

```sh
/ # cp /target/llama-2-7b.safetensors /tmp/
cp: can't open '/target/llama-2-7b.safetensors': Operation not permitted
```

Same for every other read path:

```sh
/ # cat /target/llama-2-7b.safetensors > /tmp/out
cat: can't open '/target/llama-2-7b.safetensors': Operation not permitted

/ # dd if=/target/llama-2-7b.safetensors of=/tmp/out bs=1M
dd: can't open '/target/llama-2-7b.safetensors': Operation not permitted

/ # python3 -c "open('/target/llama-2-7b.safetensors','rb').read(1)"
PermissionError: [Errno 1] Operation not permitted: '/target/llama-2-7b.safetensors'
```

In all four cases the `-EPERM` is returned from the kernel by the LSM hook
before `read(2)` is ever issued. You can confirm the block in real time:

```sh
docker logs --tail 20 neurosentry | grep file_blocked
# {"event":"file_blocked","pid":1234,"comm":"cp","filename":"llama-2-7b.safetensors","action":"EPERM"}
```

See `challenge.md` for the full three-tier attack progression.

## Scoring Server

The scoring server listens on `:8080` (the container uses `network_mode: host`,
so it's on the host loopback).

```bash
# Status / countdown
curl http://localhost:8080/status

# Submit an attempt (record what you tried, success=false is fine)
curl -X POST http://localhost:8080/submit \
  -H 'Content-Type: application/json' \
  -d '{"method":"cp","success":false,"details":"EPERM from LSM"}'

# Verify exfiltration (MD5 check against the original)
curl -X POST http://localhost:8080/verify \
  -H 'Content-Type: application/json' \
  -d '{"file_path":"/tmp/stolen/llama-2-7b.safetensors"}'

# Leaderboard
curl http://localhost:8080/leaderboard

# All recorded attempts
curl http://localhost:8080/attempts
```

## Prize Tiers

| Hat | Criteria |
|-----|----------|
| Black Hat | Successfully exfiltrate the file (MD5 match at scoring server) |
| White Hat | 10+ documented creative attempts |
| Grey Hat  | Find a novel bypass we did not anticipate |
| Red Hat   | Find a real security bug in NeuroSentry — credit in `SECURITY.md` |

## Organizer Notes

### Pre-Flight Checklist

- [ ] Isolated host (no production access, no real model IP on disk)
- [ ] `uname -r` shows kernel 5.10+ with `CONFIG_BPF_LSM=y` (`grep BPF_LSM /boot/config-$(uname -r)`)
- [ ] At least 30 GB free disk for the 13 GB model + Docker overhead
- [ ] `docker compose` available (or `docker-compose` v1.29+)
- [ ] Rollback / emergency-stop procedure tested (see below)

### Emergency Stop

```bash
# Tear everything down
cd demos/capture-the-model
sudo ./stop.sh

# If stop.sh is unavailable
docker compose down -v
```

### Troubleshooting

**Issue:** All open attempts succeed (no `EPERM`).
**Check:** `docker logs neurosentry | grep -i 'lsm'`. Confirm `lsm/file_open`
attached. If `bpf_lsm` shows as unavailable, the kernel was built without
`CONFIG_BPF_LSM=y` or `lsm=` was not enabled on the cmdline.

**Issue:** Scoring server returns 404.
**Check:** `docker compose ps scoring`; verify `network_mode: host` and that
nothing else is bound to `:8080`.

**Issue:** Grafana shows no data.
**Check:** Prometheus target list at <http://localhost:9090/targets> — the
`neurosentry:2112` scrape should be UP.

## Post-Challenge

- All blocked-access events are in `logs/` (mounted from
  `./logs:/var/log/neurosentry`)
- Metrics: `curl -s http://localhost:2112/metrics | grep neurosentry_`
- Encourage participants to leave a note in `/workspace/` with what they tried

### Debrief talking points

1. Why LSM `file_open` returning `-EPERM` cannot be defeated from user space
   (no `LD_PRELOAD`, no syscall hook, no Python-level workaround).
2. The honest gap: extension-based detection. Renaming bypasses the policy.
   Real deployments need content-based detection (magic bytes, header parse).
3. What `bpftool prog show` and `bpftool map dump` look like during an active
   attempt; why root can read maps but every map mutation is audited.
4. Where the demo intentionally cuts corners (network monitor-only) and why.

## Contact

- **Issues / Discussions**: <https://github.com/tonghuaroot/neurosentry>
- **Security reports**: see [SECURITY.md](../../SECURITY.md)

## License

Apache 2.0. See repository root.
