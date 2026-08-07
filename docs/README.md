# NeuroSentry Documentation

Start here. This index groups every document by what you're trying to do. For a
project overview and quickstart, see the repository [`README.md`](../README.md).

> **New to the console?** Open the app and click the **?** (top-right) for the
> in-product guided orientation, or jump straight to the **Knowledge Base** view
> where every detection rule is explained.

---

## Getting started

| Doc | What it covers |
|-----|----------------|
| [`../README.md`](../README.md) | Project overview, architecture diagram, quickstart, feature highlights. |
| [demo-guide.md](demo-guide.md) | Running a live demo, the "Capture The Model" lab, and presentation scenarios. |
| [user-guide.md](user-guide.md) | Installing, configuring, and operating the agent: prerequisites, `config.yaml` reference, CLI flags, and monitoring. |

## Deploy & operate

| Doc | What it covers |
|-----|----------------|
| [deployment.md](deployment.md) | Installing and running the agent; one-click Docker Compose stack. |
| [database.md](database.md) | Durable audit/case storage: SQLite vs Postgres backends and configuration. |
| [datasets.md](datasets.md) | Populating the console with real data via `--replay` and `build-real-dataset.sh`. |
| [monitoring-guide.md](monitoring-guide.md) | **Canonical** monitoring/observability guide (Prometheus + Grafana). |
| [benchmarks.md](benchmarks.md) | Performance methodology and the flagship latency/CPU/drop SLOs. |

## Reference

| Doc | What it covers |
|-----|----------------|
| [architecture.md](architecture.md) | System design: the Go agent over the eBPF triad (LSM · TC · uprobe) + correlation. |
| [detection-rules.md](detection-rules.md) | Authoring custom cross-layer detection rules (RuleSpec, matchers, examples). |
| [EBPF_COMPILATION.md](EBPF_COMPILATION.md) | Building the eBPF objects (bpf2go), vmlinux/CO-RE notes. |
| [roadmap-v2-commercial-hardening.md](roadmap-v2-commercial-hardening.md) | The commercial-hardening roadmap and phase status. |

## Development & testing

| Doc | What it covers |
|-----|----------------|
| [developer-guide.md](developer-guide.md) | Building, project layout, contributing changes. |
| [testing.md](testing.md) | **Canonical** testing guide: how to run and write tests. |
| [testing-results.md](testing-results.md) | Recorded cross-distro / cross-kernel verification results. |

---

## Notes on overlap

A few documents cover adjacent ground; prefer the canonical one and treat the
other as historical detail:

- **Monitoring** — use [monitoring-guide.md](monitoring-guide.md); [monitoring.md](monitoring.md) is older background material.
- **Testing** — use [testing.md](testing.md) for how-to; [testing-results.md](testing-results.md) is a results log, not a guide.

Top-level project docs also worth knowing: [`../SECURITY.md`](../SECURITY.md)
(disclosure + SBOM), [`../CHANGELOG.md`](../CHANGELOG.md),
[`../CONTRIBUTING.md`](../CONTRIBUTING.md), and
[`../ARSENAL_SUBMISSION.md`](../ARSENAL_SUBMISSION.md).
