# Deployment — One-Command Docker Compose Stack

NeuroSentry ships a full, self-contained stack so you can stand up the agent, a
production audit database, and the observability plane with a single command.

```bash
make compose-up
# equivalent to:
#   docker compose -f deploy/docker-compose.yml up -d
```

Then open:

| URL | What |
|---|---|
| http://localhost:8080 | NeuroSentry console |
| http://localhost:3000 | Grafana (login `admin` / `neurosentry`) |
| http://localhost:9090 | Prometheus |
| http://localhost:2112/metrics | NeuroSentry Prometheus metrics |

Tear down with `docker compose -f deploy/docker-compose.yml down` (add `-v` to
also drop the data/log volumes).

## The stack

| Service | Role | Ports | Notes |
|---|---|---|---|
| **neurosentry** | The agent: eBPF protection layers, web console, and the inline AI gateway. Runs `privileged`, `pid: host`, `network_mode: host` so the eBPF layer can attach to the host kernel. | console `8080`, metrics `2112`, gateway `8081` (host network) | Config mounted read-only from `deploy/neurosentry-compose.yaml`; state on the `ns-data` / `ns-logs` volumes. |
| **postgres** | Durable, HA audit database backend (see [database.md](database.md)). | `5432` | Point the agent at it via `audit.db_driver: postgres` + `audit.db_dsn`. Data on a named volume. |
| **prometheus** | Scrapes NeuroSentry metrics; evaluates alert rules (`deploy/prometheus/`). | `9090` | Config mounted read-only. |
| **grafana** | Auto-provisioned "NeuroSentry — AI Runtime Security" dashboard. | `3000` | Default login `admin` / `neurosentry`. |

> These credentials and the Postgres DSN are **development defaults**. Change the
> Grafana password, the Postgres user/password, and use `sslmode=require` before
> exposing this stack beyond a trusted host.

### Pointing NeuroSentry at Postgres

The stack's audit backend is selected in `deploy/neurosentry-compose.yaml`:

```yaml
audit:
  enabled: true
  db_driver: postgres
  db_dsn: "postgres://neurosentry:neurosentry@postgres:5432/neurosentry?sslmode=disable"
```

The `neurosentry` service uses host networking, so it can't resolve the
`postgres` service over Docker's bridge DNS; the compose file publishes Postgres
on the host and pins `postgres -> 127.0.0.1` via `extra_hosts`, so the `postgres`
hostname in the DSN resolves to the published port. The default password is
`neurosentry` — change it (and use `sslmode=require`) before exposing the stack
beyond a trusted host. See [database.md](database.md) for the DSN format, what is
stored, backup, and retention.

## eBPF / privileged requirements

The `neurosentry` container needs host-level access for its kernel layers:

- `privileged: true`
- `pid: "host"` — see and act on host processes
- `network_mode: "host"` — TC/XDP attach to host interfaces; console/metrics/
  gateway bind on the host
- bind mounts: `/sys/kernel/debug` (ro) and `/sys/fs/bpf` (pinned maps)

## Kernel prerequisites (full enforcement)

Full enforcement — in particular the LSM `file_open` blocking that stops
unauthorized model reads/writes — requires a **Linux host** with the BPF LSM
enabled:

- **Kernel 5.10+** (6.x recommended).
- **BTF** (CO-RE): `/sys/kernel/btf/vmlinux` present (standard on modern kernels).
- **BPF LSM**: `CONFIG_BPF_LSM=y` **and** `bpf` active in the LSM list.

Quick checks on the host:

```bash
# BTF available?
ls -l /sys/kernel/btf/vmlinux

# BPF LSM compiled in?
zcat /proc/config.gz 2>/dev/null | grep CONFIG_BPF_LSM   # expect CONFIG_BPF_LSM=y

# bpf active in the LSM stack?
cat /sys/kernel/security/lsm                             # expect a list containing "bpf"
```

Many distros need `bpf` added to the LSM stack via the kernel command line
(`lsm=...,bpf`) followed by a reboot. Amazon Linux 2023 (kernel 6.1) ships with
the `bpf` LSM enabled by default — no reboot needed. See
[EBPF_COMPILATION.md](EBPF_COMPILATION.md) for building/loading the eBPF objects.

### Non-Linux / dev hosts

On macOS, Windows, or a host without BPF LSM, the eBPF layer cannot attach.
NeuroSentry degrades gracefully to its user-space layers (audit chain, AI
gateway, MCP interception, correlation, console). Run the binary with
`--skip-bpf` to suppress the load warning:

```bash
neurosentry --config deploy/neurosentry.yaml --skip-bpf
```

The full observability stack (console, Postgres, Prometheus, Grafana) still runs
in this mode; only the kernel-enforced protections are inactive.

## See also

- [database.md](database.md) — audit backends, DSN format, backup, retention.
- [deploy/OBSERVABILITY.md](../deploy/OBSERVABILITY.md) — metrics and dashboards.
- [EBPF_COMPILATION.md](EBPF_COMPILATION.md) — building the eBPF programs.
