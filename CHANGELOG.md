# Changelog

All notable changes to NeuroSentry will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-07

First tagged release. The agent + three eBPF programs (LSM `file_open`,
TC ingress/egress, uprobes for PyTorch and CPython pickle) are
loadable and verified end to end on Linux 6.8 (aarch64) and Linux 6.14
(amd64). See `docs/testing-results.md` for the EC2 run that recorded
55,562 LSM events and 44,153 TC packets without verifier errors.

### Added
- Four SVG architecture diagrams under `docs/diagrams/` (architecture overview,
  defense-in-depth, LSM `-EPERM` enforcement path, Capture The Model attack tiers).
  Embedded in `README.md` and `docs/architecture.md` in place of the previous
  ASCII box-drawing diagrams.
- `demos/record/` — end-to-end recording kit for the lab demo video:
  preflight checker, host setup script, scene drivers, asciinema capture,
  macOS `say`-based narration generator, ffmpeg muxing recipes, plus an
  Aria (Microsoft Edge Neural TTS) variant.
- `.dockerignore` — exclude the 13 GB demo model file and other local
  recording artifacts from the Docker build context (build was failing
  with "no space left on device" because the file was being fully copied
  into the layer; the file is dense `dd if=/dev/urandom` output when
  produced by `start.sh`, or a sparse stand-in when produced by
  `truncate` in the recording kit — either way it does not belong in
  the build context).
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

### Changed
- Fixed typo: `DisableCOHRE` renamed to `DisableCORE` in BPF config
- Improved TC filter cleanup with proper error handling
- Updated documentation to clarify TC vs XDP usage
- README and demo materials no longer carry conference-specific framing;
  the project is presented as a general-purpose open-source eBPF tool.
- Demo `protected_extensions` config aligned with what the LSM hook actually
  enforces (`.safetensors / .gguf / .pth / .pt / .onnx / .h5`); `.pkl` is
  covered by the `pickle_protection` uprobes and `.bin` is intentionally
  excluded to avoid false positives.
- Python library auto-discovery in `pkg/bpf/bpf.go` and `pkg/bpf/symbols.go`
  now searches the `aarch64-linux-gnu` and `lib64` multiarch directories in
  addition to `x86_64-linux-gnu`, so the uprobe attach succeeds on ARM64
  Linux distributions (Ubuntu 22.04+ aarch64, Amazon Linux 2023 graviton).

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

### Removed
- Stale macOS arm64 binary committed at the repo root (build artifact;
  use `make build` or the Docker image instead).
- `TASKS.md` and `ralph_run.md` — internal pre-Arsenal-era planning docs
  with hard-coded user paths and credentials. Already removed from `main`.

### Known limitations
- **LSM enforces on extension only, not on path.** The hook reads
  `dentry->d_name` (final component) and matches the last 16 bytes
  against the `protected_extensions` BPF map. `protected_paths` in YAML
  is informational. Path-prefix enforcement via `bpf_d_path()` is v1.2.
- **CIDR allowlist coarseness.** `addAllowedIP("10.0.0.0/8")` inserts
  the network base IP only, not the whole /8 block. Use individual IPs
  in YAML for v1.0; LPM-trie BPF map for v1.1.
- **TC and XDP are monitor-only**: shipped XDP program is `XDP_PASS` on
  every code path. Drop-path is roadmap.
- **Uprobes for pickle / PyTorch attach to host-side libpython /
  libtorch**. Containers loading their own libpython are not covered by
  the host attachment; per-container symbol resolution is v1.1 wiring.
- **SIGHUP-driven config reload does not yet update the
  `protected_extensions` BPF map** — startup populates it correctly,
  but a runtime YAML change requires a container restart in v1.0.
  Investigation pending in v1.1.
- **PID-recycle window is bounded by the prune tick** (default 30 s,
  configurable via `agent.pid_prune_interval`). Trusted PIDs whose
  process has exited are removed on the next tick; tighter via
  per-process exit notifiers is roadmap.

## [Unreleased]

### Added
- **Data-driven LSM extension matching.** `pkg/bpf/neurosentry_lsm.c` no
  longer hard-codes the protected extension list — the hook now looks
  up the file's actual extension in the `protected_extensions` BPF map
  (key: 16-byte zero-padded extension string). Adding/removing
  extensions in YAML now actually changes what the kernel blocks.
- **Trusted-PID death watcher.** New `agent.pid_prune_interval` config
  (default **5 s**, lowered from 30 s after Round-2 audit feedback that
  longer windows are indefensible on production AI inference pools that
  fork/restart workers every few seconds). Periodic goroutine in the
  controller walks `trusted_pids`, removes entries whose process has
  exited (`/proc/<pid>` missing), and bumps a new
  `neurosentry_trusted_pids_pruned_total` Prometheus counter. Closes
  the PID-recycle TOCTOU window.
- **Long-filename support.** LSM filename buffer logic re-architected
  to read only the last 16 bytes (where the extension lives) plus up
  to 64 bytes of leading filename for the audit event. Defeats the
  64-byte-filename-truncation bypass found in the v1.0 audit
  (filenames > 63 bytes had their extension truncated off and the
  matcher silently missed).
- **`pkg/bpf/clearBPFMap` correctness fix.** The iterator passed nil as
  the value-out, which made `cilium/ebpf` Lookup fail to unmarshal and
  abort iteration after zero entries. After the v1.0 round-1 change made
  `protected_extensions` data-driven, this directly broke the
  SIGHUP-driven config reload (removed extensions stayed live in the
  kernel after a YAML change). Allocate a value buffer matching the
  map's `ValueSize()` and pass `&value` to `Next` so the iterator
  actually advances.
- **`PruneDeadTrustedPIDs` race fix.** Previously snapshot-then-delete
  could remove a freshly-trusted PID if `AddTrustedPID(pid)` ran
  concurrently between the snapshot and the delete. Re-stat
  `/proc/<pid>` immediately before each delete; if alive again, leave
  it alone. Counter only bumps on actual deletes.

### Changed
- ARSENAL_SUBMISSION:
  - **§1** anchored with four real 2024–2025 incidents (Hugging Face
    pickles, JFrog "nullifAI", torchtriton, Ray Dashboard CVE).
  - **§3.2** added a competitive comparison table (Falco, Tetragon,
    picklescan, modelscan, Garak, confidential containers) so the
    "what's new" challenge is defused up front.
  - **§3.2 over-claim** ("no userspace can bypass without a kernel
    exploit") qualified to "extension-and-PID decision" with explicit
    forward-reference to the path bypass in §3.3.
  - **§3.3 honest limits** expanded from 5 → 10; collapsed a duplicate
    sentence Round-2 caught.
  - **§5 EU AI Act framing** tightened: explicit Annex IV §2(g) cite,
    explicit non-compliance-product disclaimer, explicit
    NeuroSentry-fills-which-row scoping.
- demo `docker-compose` config no longer ships with `block_exfiltration:
  true` and `block_on_detect: true` (both flatly contradicted §3.3 and
  would mislead operators). Defaults are now `false` with v1.1 opt-in
  comments inline.
- `MODELS_DIR` in `demos/record/scenes-vm.sh` is now derived from
  `git rev-parse --show-toplevel` instead of a hard-coded
  maintainer-machine absolute path.

[Unreleased]: https://github.com/tonghuaroot/neurosentry/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/tonghuaroot/neurosentry/releases/tag/v1.0.0
