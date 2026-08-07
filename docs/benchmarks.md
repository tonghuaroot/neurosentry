# NeuroSentry Benchmarks (Phase 0)

Reproducible performance methodology and published results. This is the
**performance-regression gate** for the v2.0 commercial-hardening roadmap
(see `roadmap-v2-commercial-hardening.md`): every hardening change re-runs this
harness and must not regress beyond threshold.

## Flagship SLO (acceptance targets)

| Target | Threshold |
|---|---|
| p99 added inference latency (agent on vs off) | **< 2 ms** |
| Steady-state agent CPU at target event rate | **< 3 %** |
| Dropped events at target event rate | **0** (controlled, alerted drop only under defined burst) |

Kernel-path numbers (LSM `open()` overhead, TC throughput, end-to-end inference
p99) are measured on a live Linux host; userspace hot-path numbers are measured
by portable Go benchmarks and a deterministic runner.

## Harness layout

| Component | What it measures | How to run |
|---|---|---|
| `bench/hotpath_bench_test.go` | per-event cost of userspace security logic (Go `testing.B`, allocs) | `go test ./bench/ -bench=. -benchmem` |
| `bench/runner` | deterministic latency distribution (p50/p95/p99) + throughput, machine-readable JSON | `go run ./bench/runner -iterations 100000 -json results.json` |
| `bench/lsm_latency` + `bench/lsm_latency.sh` | per-`open()` LSM hook overhead, A/B agent-on vs agent-off, on a live host | see below |

### Userspace hot paths (`bench/runner`)

Deterministic: identical inputs every run, so results diff cleanly across
releases. JSON output carries `go_version`, `goos`, `goarch`, `cpus` so runs are
only compared within the same environment. Pass `-timestamp` for byte-stable
output in CI.

```
go run ./bench/runner -iterations 100000 -json results.json
```

### Kernel path — LSM open() overhead (`bench/lsm_latency`)

Isolating the hook requires toggling enforcement, so the A/B script briefly
stops and restarts the agent. On the target host, as root:

```
# cross-compile and ship the probe
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lsm-latency ./bench/lsm_latency
scp lsm-latency host:/usr/local/bin/            # or via your deploy channel
sudo ITERS=200000 ./bench/lsm_latency.sh /usr/local/bin/lsm-latency
```

It prints two JSON lines (`agent-on`, `agent-off`); the per-open hook overhead is
`agent-on.p99_ns - agent-off.p99_ns`. The page/dentry cache is warmed first so
the measurement reflects the hook, not I/O.

## Reproducibility rules

1. **Pin the environment.** Same instance type + kernel; compare only within
   one `(goos, goarch, go_version, cpus)`.
2. **Multiple runs.** Take ≥3 runs; report median and spread.
3. **Machine-readable first.** JSON is the source of truth; tables are derived.
4. **CI gate.** The runner feeds a regression check on each release; a hot path
   regressing beyond threshold fails the build.

## Published results

### Userspace hot paths — reference (dev workstation)

`go run ./bench/runner -iterations 100000` — darwin/arm64, 8 CPU, go1.26.1.
These are a **relative reference** (dev laptop, not the SLO environment); the
flagship SLO is evaluated on the target Linux host.

| path | p50 (µs) | p95 (µs) | p99 (µs) | mean (µs) | ops/sec |
|---|---|---|---|---|---|
| correlate.Ingest | 18.4 | 74.7 | 136.4 | 26.2 | 38,023 |
| aiguard.InjectionDetect | 32.0 | 34.2 | 48.8 | 30.8 | 32,474 |
| aiguard.DLPScan | 8.3 | 13.0 | 16.3 | 10.0 | 99,767 |
| audit.Append | 1.0 | 1.5 | 4.1 | 1.2 | 800,401 |

**First finding (gate working as intended):** `correlate.Ingest` allocates
~95 KB/op (30 allocs) under sustained per-PID load because a hot process's
in-window session grows unbounded until time-pruned. This is the concrete
bounded-memory target for **Phase 1 fail-safe hardening** — the benchmark
surfaced it before a customer did.

### Kernel path — LSM open() overhead

Measured on the live target — AWS AL2023, kernel 6.1.176, x86_64 — 200,000
`open()`/`close()` iterations on an allowed path, cache warmed:

| run | p50 (ns) | p95 (ns) | p99 (ns) | mean (ns) |
|---|---|---|---|---|
| agent-on (LSM hook attached) | 4,960 | 6,565 | 7,748 | 5,268 |
| agent-off (baseline) | 4,782 | 6,314 | 7,422 | 5,063 |
| **per-open hook overhead (Δ)** | **+178** | **+251** | **+326** | **+205** |

The LSM `file_open` hook adds **sub-microsecond** latency per open — ≈ **+0.33 µs
at p99**, ~3.7 % relative, **≈ 6,000× under the 2 ms flagship SLO**. Enforcement
(blocking a protected model read) is a single verdict on the same hook, so the
cost is bounded by this measurement.
