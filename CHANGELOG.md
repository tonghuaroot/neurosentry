# Changelog

All notable changes to NeuroSentry will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-07

First tagged release. The agent + four eBPF programs (LSM `file_open`,
TC ingress/egress, XDP, uprobes for PyTorch and CPython pickle) are
loadable and verified end to end on Linux 6.8 (aarch64) and Linux 6.14
(amd64). See `docs/testing-results.md` for the EC2 run that recorded
55,562 LSM events and 44,153 TC packets without verifier errors.

### Added
- Four SVG architecture diagrams under `docs/diagrams/` (architecture overview,
  defense-in-depth, LSM `-EPERM` enforcement path, Capture The Model attack tiers).
  Embedded in `README.md` and `docs/architecture.md` in place of the previous
  ASCII box-drawing diagrams.
- `demos/video/neurosentry-demo.mp4` — ~5-minute end-to-end demo video
  with poster image, embedded in `README.md`. Walks the cold-open data
  theft, kernel-level LSM blocking with full Prometheus → Grafana
  observability B-roll, pickle reduce-bomb detection, network exfil
  visibility with the webhook receiver panel, and the Capture The Model
  lab tour.
- `.dockerignore` — exclude the 13 GB demo model file and other local
  recording artifacts from the Docker build context (build was failing
  with "no space left on device" because the file was being fully copied
  into the layer; the file is dense `dd if=/dev/urandom` output when
  produced by `start.sh`).
- SECURITY.md with responsible disclosure guidelines (now points at
  `tonghuaroot@gmail.com`).
- Dependabot configuration for automated dependency updates
- Additional golangci-lint linters (gosec, stylecheck, unconvert, exhaustive)
- Proper CIDR matching using `net.ParseCIDR()` in policy evaluation
- Process chain tracking via `/proc/[pid]/status` parsing
- TC cleanup error logging for better debugging
- GitHub issue and PR templates
- CODEOWNERS file for PR review automation
- .gitattributes for proper binary file handling
- **Data-driven LSM extension matching.** `pkg/bpf/neurosentry_lsm.c`
  does not hard-code the protected extension list — the hook looks
  up the file's actual extension in the `protected_extensions` BPF map
  (key: 16-byte zero-padded extension string). Adding/removing
  extensions in YAML changes what the kernel blocks.
- **Trusted-PID death watcher.** `agent.pid_prune_interval` config
  (default 5 s). Periodic goroutine in the controller walks
  `trusted_pids`, removes entries whose process has exited
  (`/proc/<pid>` missing), bumps `neurosentry_trusted_pids_pruned_total`.
  Closes the PID-recycle TOCTOU window.
- **Active-LSM-stack startup check.** Agent reads
  `/sys/kernel/security/lsm` at startup and distinguishes three states:
  `bpf` present → INFO "Verified"; file readable but `bpf` missing →
  loud WARNING with the GRUB cmdline fix; file unreadable (agent in a
  container without securityfs) → INFO "could not verify, trusting
  loaded program." Closes the silent-enforcement-failure case.

### Changed
- Fixed typo: `DisableCOHRE` renamed to `DisableCORE` in BPF config
- Improved TC filter cleanup with proper error handling
- Updated documentation to clarify TC vs XDP usage
- Demo `protected_extensions` config aligned with what the LSM hook actually
  enforces (`.safetensors / .gguf / .pth / .pt / .onnx / .h5`); `.pkl` is
  covered by the `pickle_protection` uprobes and `.bin` is intentionally
  excluded to avoid false positives.
- Python library auto-discovery in `pkg/bpf/bpf.go` and `pkg/bpf/symbols.go`
  now searches the `aarch64-linux-gnu` and `lib64` multiarch directories in
  addition to `x86_64-linux-gnu`, so the uprobe attach succeeds on ARM64
  Linux distributions (Ubuntu 22.04+ aarch64, Amazon Linux 2023 graviton).
- README adds a "How NeuroSentry compares to existing tools" table
  positioning NeuroSentry against Falco, Tetragon, picklescan, modelscan,
  NVIDIA Garak, and confidential containers — NeuroSentry is the
  LSM-enforcement layer; it complements rather than replaces static
  scanners and confidential compute.
- Demo `docker-compose` defaults `block_exfiltration` and
  `block_on_detect` to `false` to match the monitor-only / observe-only
  semantics that ship in v1.0; opt-in comments inline.

### Fixed
- **LSM `BPF_PROG` macro silently passed the BPF ctx pointer to the C
  function as the first argument**, so every `&file->...` read in the
  `restrict_model_file_access` hook computed an offset against a bogus
  base; `bpf_probe_read_kernel` failed with `-EFAULT` on `dentry->d_name`,
  the filename came back empty, `is_protected_file` returned 0, and the
  hook returned 0 (allow) for every read open of a protected extension —
  even with `enforce_mode=true` and `bpf` in the active LSM stack. The
  bug was masked because some opens were coincidentally blocked by
  AppArmor returning EPERM on the same code path. Replaced the local
  `BPF_PROG` macro with a `ctx[i]` dispatch (1/2/3-arg variants), so the
  hook now sees the real `struct file *` pointer and uniformly returns
  `-EPERM` for read AND write opens across all filesystems.
- **Uprobe programs failed to load on aarch64 with "bad CO-RE relocation:
  invalid func unknown#NNN".** Two related bugs:
  1. `pkg/bpf/neurosentry_uprobe.c` accessed the first argument register
     as `ctx->di` (x86_64 register name); aarch64 `struct pt_regs` has no
     `di` field, so CO-RE could not relocate. Replaced with an
     architecture-aware `PT_REGS_PARM1(ctx)` macro.
  2. The local `bpf_probe_read_user_str` declaration mapped the symbol to
     helper ID 113, which is actually `bpf_probe_read_kernel` — every
     uprobe read of a user-space pointer was silently failing with
     `-EFAULT`. Corrected to helper ID 114.
  Uprobes now attach successfully on Colima/Ubuntu 24.04 aarch64 kernel
  6.8 (verified via `docker logs ns-smoke | grep "Uprobes attached"`).
- `GetProcessChain()` now actually reads `/proc` to build process tree
- `matchCIDR()` now uses proper CIDR parsing instead of string matching
- TC cleanup errors are now logged instead of silently ignored
- **`pkg/bpf/clearBPFMap` correctness.** The iterator passed nil as
  the value-out, which made `cilium/ebpf` Lookup fail to unmarshal and
  abort iteration after zero entries — so SIGHUP-driven config reload
  left removed extensions live in the kernel. Now allocates a value
  buffer matching the map's `ValueSize()` and passes `&value` to `Next`
  so the iterator advances.
- **`PruneDeadTrustedPIDs` race.** Snapshot-then-delete could remove a
  freshly-trusted PID if `AddTrustedPID(pid)` ran concurrently between
  the snapshot and the delete. Re-stat `/proc/<pid>` immediately
  before each delete; if alive again, leave it alone. Counter only
  bumps on actual deletes.
- **Long-filename truncation bypass.** Earlier filename buffer logic
  truncated names longer than 63 bytes, so the matcher silently missed
  the extension. The hook now reads the trailing 16 bytes for the
  extension match plus up to 64 bytes of leading filename for the
  audit event payload, so filenames of any reasonable length still
  hit the protected-extensions map. (The 16-byte tail-window padding
  bypass is a separate, structural limit — see Known limitations.)

### Removed
- Stale macOS arm64 binary committed at the repo root (build artifact;
  use `make build` or the Docker image instead).
- `TASKS.md` and `ralph_run.md` — internal planning docs with
  hard-coded user paths and credentials.

### Known limitations
- **LSM enforces on extension only, not on path.** The hook reads
  `dentry->d_name` (final component) and matches the last 16 bytes
  against the `protected_extensions` BPF map. `protected_paths` in YAML
  is informational. Path-prefix enforcement via `bpf_d_path()` is v1.2.
- **16-byte tail matcher misses any extension whose dot is outside the
  trailing 16 bytes of `d_name`.** The matcher reads exactly the last 16
  bytes of the filename and scans them for the trailing `.`. Any name
  whose last `.` falls outside that window — `foo.safetensors.<16+ char
  suffix>` is the canonical example, but it's a strictly more general
  failure: any filename where the dot is more than 15 characters from
  the end of the name produces "no extension" and is allowed. Extending
  the scan window does NOT close this — the attacker can pad arbitrarily
  far. Same root cause as the rename bypass; the structural fix is
  `bpf_d_path()` (path-prefix matching) plus magic-byte content checks
  (v1.2). For v1.0 we accept this and document it.
- **Short-filename buffer over-read.** For names shorter than 16 bytes,
  the LSM hook still issues a 16-byte `bpf_probe_read_kernel` from
  `d_name.name`. The dentry-name kmalloc'd buffer is on a single page
  so the read does not fault, and the loop boundary
  (`valid_in_tail = real_len`) ignores the bytes beyond the real
  filename — but it is technically a read past the trailing NUL. The
  matcher's behavior is correct (extension lookup is bounded), but
  noted here for correctness reviewers.
- **`lsm/file_permission` and `lsm/mmap_file` source is present but not
  attached** in v1.0 (commented `SEC()` in `pkg/bpf/neurosentry_lsm.c`,
  pending verifier work). Consequences: a process that already holds an
  open fd before the agent starts is not blocked on subsequent `read(2)`s,
  and `mmap`-based loaders (vLLM, Triton, HF `transformers` with
  `low_cpu_mem_usage=True`) are not covered by the LSM layer. Re-attaching
  these is on the v1.1 list.
- **The pickle uprobe does NOT do symbol-aware "dangerous symbol"
  matching.** `pkg/bpf/neurosentry_uprobe.c::check_dangerous_stack` is a
  stack-depth heuristic (`nr_stack > 8`); the `dangerous_symbols` BPF map
  is currently populated from YAML but not consulted from BPF. The map
  is informational only in v1.0. Real symbol-aware blocking — either via
  user-space stack symbolization or via attaching to higher-level Python
  frames — is on the v1.1 list.
- **The pickle uprobe attaches to `PyInit__pickle`**, which fires once at
  module-import time and not on subsequent `pickle.loads()` calls. Stock
  CPython 3.10+ does not export the per-call C entry points used as the
  preferred attach targets in `pkg/bpf/symbols.go`. Per-call observation
  needs either a Python-level shim or attachment to `PyEval_*` frame
  evaluation (v1.1).
- **CIDR allowlist coarseness.** `addAllowedIP("10.0.0.0/8")` inserts
  the network base IP only, not the whole /8 block. Use individual IPs
  in YAML for v1.0; LPM-trie BPF map for v1.1.
- **TC and XDP are monitor-only**: shipped XDP program is `XDP_PASS` on
  every code path. Drop-path is roadmap.
- **Uprobes for pickle / PyTorch attach to host-side libpython /
  libtorch**. Containers loading their own libpython are not covered by
  the host attachment; per-container symbol resolution is v1.1 wiring.
- **`bpftool map update trusted_pids` from outside the agent bypasses
  the agent's userspace audit log.** The `AddTrustedPID` /
  `RemoveTrustedPID` Go path emits an event; direct kernel-side
  mutation does not. If your threat model includes mutually-distrusting
  privileged co-tenants on the same host, do not rely on the agent log
  as the sole source of truth for trusted-PID changes.
- **PID-recycle window is bounded by the prune tick** (default 5 s,
  configurable via `agent.pid_prune_interval`). Trusted PIDs whose
  process has exited are removed on the next tick; tighter via
  per-process exit notifiers is roadmap.

[1.0.0]: https://github.com/tonghuaroot/neurosentry/releases/tag/v1.0.0
