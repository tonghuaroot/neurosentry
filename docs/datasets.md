# Importing external security datasets

NeuroSentry can replay **external, public security datasets** through its real
correlation engine so the console reflects realistic data volume — not just a
handful of synthetic seeds. This is what makes the platform's value visible: a
detection engine is only as convincing as the data flowing through it.

```
neurosentry --config /etc/neurosentry/config.yaml --replay <file.ndjson>
neurosentry --config /etc/neurosentry/config.yaml --replay data.ndjson --replay-format host|injection|mcp|auditd|auto
```

The importer never vendors a dataset (licensing + size). It provides tolerant
adapters that normalize third-party records into NeuroSentry signals, and a
replayer that feeds them to the engine. A ready-to-run sample ships at
`deploy/datasets/sample-mixed-telemetry.ndjson` (mixed kernel + AI records; fires
model-theft, reverse-shell, container-escape, and injection-then-action chains).

## Recommended public sources

### Host / kernel attack telemetry → kernel signals
- **OTRF / Security-Datasets** (formerly *Mordor*) — pre-recorded attack
  telemetry as JSON, mapped to MITRE ATT&CK, including Linux **auditd** process /
  file / network events. <https://github.com/OTRF/Security-Datasets>
  Permissively licensed (attribution). Use `--replay-format host` (or `auto`).
- **EVTX-to-MITRE-Attack** — 270+ EVTX samples mapped to ATT&CK (Windows-centric;
  useful for technique coverage). <https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack>

### Prompt-injection / jailbreak corpora → AI-layer signals
- **rogue-security/prompt-injections-benchmark** — 5,000 labeled jailbreak/benign
  prompts (small, clean; start here).
- **Necent/llm-jailbreak-prompt-injection-dataset** — aggregated from 30+ safety
  datasets (volume).
- **JAILBREAKDB** — ~446k jailbreak + ~1.1M benign prompts (scale).

Use `--replay-format injection`. Each dataset should expose a `text`/`prompt`
field and a `label` (jailbreak/benign).

### MCP tool-call records → tool-layer signals
- Records shaped like MCP tool invocations (`tool`/`mcp_tool`/`tool_name`, plus
  `args`/`query` and an optional `injection` flag) normalize into an MCP-layer
  signal that drives the AI Gateway and the tool-based correlation rules. Use
  `--replay-format mcp` (or `auto`, which recognizes the MCP, kernel, and
  prompt-injection shapes in a single mixed dataset).

> ⚠️ **License check before commercial use.** Some Hugging Face datasets are
> **CC-BY-NC (non-commercial)** and must NOT ship in a commercial product. Prefer
> MIT / Apache-2.0 / CC-BY sources, and attribute them. NeuroSentry adapts, it
> does not relabel third-party data as its own.

## Adapter field mapping (tolerant to schema variance)

| NeuroSentry signal | Source fields recognized |
|---|---|
| `kernel_proc` (exec) | `event_type`/`action` contains `exec`/`process_create`, or `argv`/`CommandLine` present; `process_pid`/`pid`, `process_name`/`Image` |
| `kernel_file` | `file_path`/`TargetFilename`/`path`/`name` |
| `kernel_net` | `network_dest_ip`/`dest_ip`/`dst`/`DestinationIp` (public IPs flagged `external`) |
| `ai` (prompt) | `text`/`prompt`/`input`; `label` (jailbreak/injection/1/true → malicious) |
| timestamp | `@timestamp`/`timestamp`/`TimeGenerated`/`utc_time` (RFC3339 etc.) |

Records that don't map to any signal are skipped, so a partial or dirty dataset
still imports what it can. Timestamps are honored so **ordered** cross-layer
chains (e.g. injection → kernel action) fire correctly.

## Converting a dataset

Most sources are already NDJSON or convert trivially (`jq -c '.[]'` for a JSON
array; export a HF dataset to JSONL). Point `--replay` at the resulting file.

## Real datasets in this repo (verified)

The demo now runs on **real open-source data**, not synthetic seeds:

- **Cross-layer attack set** — `deploy/datasets/build-real-dataset.sh` fetches and
  correlates two real corpora and prints an NDJSON replay file:
  - [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) — real Linux
    `auditd` attack telemetry (Apache-2.0) → kernel signals
  - [verazuo/jailbreak_llms](https://github.com/verazuo/jailbreak_llms) — real
    jailbreak prompts (MIT) → AI-layer signals
  It **also emits MCP tool-call records** layered on the real telemetry: benign
  invocations, injection-flagged calls (SSRF/metadata, SQL injection, etc.), and
  paired cross-layer chains (tool-call → egress / exec / secret-read on the same
  PID). These drive the AI Gateway view and the tool-based correlation rules
  (NS-CORR-002/003/011) that no kernel or AI record alone can produce.
  Correlated by process, they fire genuine `injection-then-action` findings.
  Run: `deploy/datasets/build-real-dataset.sh > real.ndjson && neurosentry --replay real.ndjson`
- **Raw auditd** — real Linux audit logs (e.g. OTRF captures) are ingested directly
  with `--replay-format auditd` (the `ReadAuditd` parser handles the native
  SYSCALL/EXECVE/PATH text format).

Both sources are permissively licensed (Apache-2.0 / MIT); attribute them. NeuroSentry
adapts the data, it does not relabel it as its own.
