# Authoring Custom Detection Rules

NeuroSentry ships a catalog of built-in cross-layer correlation rules (`NS-CORR-*`),
but you can also author your own at runtime — no rebuild, no restart. This guide
explains the detection model, the `RuleSpec` shape, and how to create rules from
either the console or the API.

Source of truth: `pkg/correlate/rulespec.go`, `pkg/correlate/correlate.go`,
`pkg/correlate/rules.go`, `pkg/correlate/kb.go`.

---

## 1. The detection model

A **rule** is a set of **matchers**. It fires when **every** matcher is satisfied
by a **distinct signal from the same process (PID)** inside a sliding time
**window**. This is the cross-layer model: a rule fuses AI-layer *intent* (an MCP
tool call, an LLM request, a flagged prompt) with kernel-layer *consequence* (the
file read, network connection, or process exec that intent actually caused),
observed via eBPF — a correlation a userspace gateway structurally cannot make.

- **Window** — all matched signals must fall within `window_secs` of the signal
  that completes the pattern. Per-process signal history older than the widest
  rule window is pruned.
- **Ordered** — when `ordered: true`, the matched signals must occur in matcher
  order (a causal sequence: A *then* B *then* C). When `false`, mere
  co-occurrence within the window is enough.
- **Same PID** — matchers are evaluated only against signals belonging to one
  process session. Two processes each doing half the pattern do **not** fire it.
- **Fires forward** — a rule is evaluated on the signal that *completes* it, so
  causality flows forward in time. After firing, a rule is on cooldown for its
  own window length for that PID, so one episode does not re-storm.

Matching is a greedy distinct assignment: each matcher takes the earliest unused
in-window signal it matches. Because matchers are normally layer/kind-distinct,
this is exact. If `ordered` is set, the picked signals' timestamps must be
non-decreasing in matcher order or the rule does not fire.

---

## 2. RuleSpec fields

`RuleSpec` (`pkg/correlate/rulespec.go`) is the serializable form of a rule. This
is exactly the JSON body the create API and the console builder send.

| Field | JSON key | Meaning | Default if empty |
|-------|----------|---------|------------------|
| ID | `id` | Rule identifier. | auto-generated `NS-CUSTOM-xxxxxxxx` |
| Name | `name` | Human name (**required**). Also the cooldown/dedup key. | — (error if missing) |
| Category | `category` | Grouping in the detections library (e.g. `Data Exfiltration`). | `Custom` |
| Severity | `severity` | `critical` \| `high` \| `medium` \| `low`. | `medium` |
| Technique | `technique` | OWASP LLM Top-10 id, e.g. `LLM01`, `LLM06`. | — |
| MitreAttack | `mitre_attack` | MITRE ATT&CK technique id, e.g. `T1041`, `T1567`. | — |
| Description | `description` | One-line summary of what the rule detects; shown on the finding. | — |
| WindowSecs | `window_secs` | Correlation window in seconds (fractional allowed). | `10` if `<= 0` |
| Ordered | `ordered` | Require matchers to occur in sequence. | `false` |
| Matchers | `matchers` | The conditions — at least one is **required**. | — (error if empty) |

### Knowledge Base fields

Every rule gets a Knowledge Base article. Alongside the detection logic, a rule
carries analyst prose — **rationale** (`rationale`, why the pattern matters),
**remediation** (`remediation`, an array of response steps), **false_positives**
(`false_positives`, common benign causes), and **references** (`references`,
links). These are first-class fields of `RuleSpec`, so **custom rules carry their
own KB prose** and appear in the **Knowledge Base** view with their own article
(`Explain` works on them). Built-in rules use curated guidance keyed by rule ID
(`kbGuidance` in `pkg/correlate/kb.go`). For any rule, `references` are merged
with the canonical MITRE/OWASP links derived from its ids.

| KB field | JSON | Purpose |
|---|---|---|
| Rationale | `rationale` | Why this pattern is dangerous. |
| Remediation | `remediation` (array) | How to respond. |
| False positives | `false_positives` (array) | Common benign causes. |
| References | `references` (array) | Doc / CVE / technique links (MITRE & OWASP auto-added). |

---

## 3. Matchers

A matcher (`MatcherSpec`) selects the signals a rule cares about:

| Field | JSON key | Meaning |
|-------|----------|---------|
| Layer | `layer` | Observation plane. Empty = any layer. |
| Kind | `kind` | Signal kind (exact match). Empty = any kind. |
| AttrKey | `attr_key` | Attribute name to test (optional). |
| AttrPattern | `attr_pattern` | RE2 regex tested against that attribute's value. |

The attribute predicate is applied **only when both `attr_key` and
`attr_pattern` are non-empty**; the regex must compile or the rule is rejected.
A signal matches a matcher when its layer matches (or the matcher's layer is
empty), its kind matches (or empty), and — if present — the attribute predicate
holds.

### Valid layers

| `layer` | Plane |
|---------|-------|
| `ai` | LLM gateway request/response |
| `mcp` | MCP tool call |
| `kernel_file` | LSM file access |
| `kernel_net` | TC/XDP network flow |
| `kernel_proc` | process exec |
| `model` | model load (uprobe) |

### Common signal kinds (the glossary)

From `SignalGlossary()` in `pkg/correlate/kb.go` — the cross-layer vocabulary:

| `kind` | Typical layer | What it means |
|--------|---------------|---------------|
| `file_read` | `kernel_file` | A process opened a file for reading (LSM hook). |
| `file_write` | `kernel_file` | A process wrote to a file. |
| `net_connect` | `kernel_net` | An outbound connection (TC). Flagged external for a public destination. |
| `exec` | `kernel_proc` | A new process was executed. |
| `tool_call` | `mcp` | The model invoked an MCP tool. |
| `prompt` | `ai` | An inference request/prompt; may carry an injection verdict. |
| `request` | `ai` | Traffic bound for an LLM provider. |
| `model_load` | `model` | A model artifact was loaded. |
| `pickle_op` | `model` | A pickle/deserialization opcode observed during load. |

`kind` is matched as an exact string, so use the value your collectors actually
emit for the events you care about.

### Attribute predicate example

Attributes are set by the collectors (e.g. `path`, `dst`, `comm`, `external`,
`ai_provider`, `injection`, `verified`). To match a read of a shadow file:

```json
{ "layer": "kernel_file", "kind": "file_read", "attr_key": "path", "attr_pattern": "/etc/shadow" }
```

To match an outbound connection tagged external:

```json
{ "layer": "kernel_net", "kind": "net_connect", "attr_key": "external", "attr_pattern": "^true$" }
```

---

## 4. Authoring paths

### (a) The console rule builder

**Detections → “+ New detection”** opens the guided rule builder (a slide-over
drawer). It exposes:

- **Name** and **Description**.
- **Severity** (`critical`/`high`/`medium`/`low`, default `high`), **MITRE**
  (e.g. `T1041`), **Window** in seconds (default `10`), and an **ordered
  (causal sequence)** checkbox (default on).
- **Conditions** — one row per matcher: a **layer** dropdown, a **kind** input,
  and an optional **where `attr` ~ `regex`** attribute predicate. Add/remove
  rows freely.
- An optional **Knowledge Base** section — **OWASP** LLM id, **Rationale**, **How
  to respond** (remediation), **Common false positives**, and **References** — so
  the custom rule gets its own KB article.
- A live **plain-English preview**, e.g. *“Fires when mcp tool_call → then
  kernel·net net_connect where dst ~ /external/ occur for the same process
  within 5s.”* The joiner is “→ then” when ordered, “and” when not.

The builder opens as a centered modal and is used for both **create** and
**edit**. **Create detection** POSTs the assembled `RuleSpec` to
`/api/detections/create`; the custom rule appears immediately in the detections
library with a **custom** badge, its fire count, an enable/disable toggle, a
detail drawer, and its own **Knowledge Base** article.

**Editing:** open a custom rule's detail drawer and choose **Edit rule** — the
same modal reopens prefilled; **Save changes** PATCHes it via the update endpoint
(below). Built-in rules cannot be edited or deleted (only toggled on/off) and
each links to its Knowledge Base article.

### (b) The API

All routes require the `manage_policy` permission (send your auth header).

**Create** — `POST /api/detections/create`

Body: a `RuleSpec` JSON object (see §2). On success returns `201` with the
assigned id; on a bad spec (missing name, no matchers, or a regex that does not
compile) returns `400` with the error message.

```json
{
  "name": "secret-read-then-egress",
  "category": "Data Exfiltration",
  "severity": "critical",
  "technique": "LLM02",
  "mitre_attack": "T1041",
  "description": "a secret file was read and then egress went to an external host",
  "window_secs": 10,
  "ordered": true,
  "matchers": [
    { "layer": "kernel_file", "kind": "file_read", "attr_key": "path", "attr_pattern": "shadow|id_rsa|\\.aws/credentials" },
    { "layer": "kernel_net",  "kind": "net_connect", "attr_key": "external", "attr_pattern": "^true$" }
  ]
}
```

Response:

```json
{ "id": "NS-CUSTOM-a1b2c3d4" }
```

**Enable / disable** — `POST /api/detections/{id}/toggle` with `{"enabled": true|false}`.
Works for built-in and custom rules.

**Update** — `POST /api/detections/{id}/update` with the same `RuleSpec` body as
create. Only **custom** rules can be updated (updating a built-in returns `404`);
the rule is recompiled and swapped in place, preserving its enabled state and
fire count. Returns `200 {"id": ...}`.

**Delete** — `POST /api/detections/{id}/delete`. Only **custom** rules can be
removed; deleting a built-in returns an error.

**List** — `GET /api/detections` returns the full catalog with per-rule
`custom`, `enabled`, `fire_count`, `window_secs`, `ordered`, `matchers`, and the
KB fields — enough to prefill the editor.

The custom rule also appears in `GET /api/kb` with its own article, so `Explain`
in the console resolves it.

---

## 5. Worked examples

Each mirrors a real built-in rule. Paste any of these into
`POST /api/detections/create`.

### Tool-triggered exfiltration (mirrors `NS-CORR-002`)

Fires when an MCP tool call is **followed by** an outbound connection to an
external host within 5 seconds — data leaving through the tool boundary.

```json
{
  "name": "tool-triggered-exfil",
  "category": "Data Exfiltration",
  "severity": "high",
  "technique": "LLM06",
  "mitre_attack": "T1567",
  "description": "an MCP tool call was immediately followed by an outbound connection to an external host — possible data exfiltration via a tool",
  "window_secs": 5,
  "ordered": true,
  "matchers": [
    { "layer": "mcp", "kind": "tool_call" },
    { "layer": "kernel_net", "kind": "net_connect", "attr_key": "external", "attr_pattern": "^true$" }
  ]
}
```

### Injection then action (mirrors `NS-CORR-004`)

Fires when a prompt flagged as an injection attempt is **followed by** a real
kernel side effect (a process exec here) within 8 seconds — the strongest signal
that an injection actually crossed from text into action.

```json
{
  "name": "injection-then-action",
  "category": "Prompt Injection",
  "severity": "critical",
  "technique": "LLM01",
  "mitre_attack": "T1059",
  "description": "a prompt-injection attempt was followed by a real system action — the injection may have succeeded",
  "window_secs": 8,
  "ordered": true,
  "matchers": [
    { "layer": "ai", "kind": "prompt", "attr_key": "injection", "attr_pattern": "malicious|suspicious" },
    { "layer": "kernel_proc", "kind": "exec" }
  ]
}
```

### Tool then secret read (mirrors `NS-CORR-011`)

Fires when an MCP tool call is followed by a read of a credential/secret file
within 5 seconds — a tool reaching for secrets it should not touch.

```json
{
  "name": "tool-then-secret-read",
  "category": "Credential Access",
  "severity": "high",
  "technique": "LLM06",
  "mitre_attack": "T1552",
  "description": "an MCP tool call was followed by a read of a credential/secret file",
  "window_secs": 5,
  "ordered": true,
  "matchers": [
    { "layer": "mcp", "kind": "tool_call" },
    { "layer": "kernel_file", "kind": "file_read", "attr_key": "path", "attr_pattern": "shadow|/\\.ssh/|\\.env|kubeconfig" }
  ]
}
```

---

## 6. Testing and validation

- **Regexes must compile.** Every `attr_pattern` is compiled at create time
  (RE2). A bad pattern rejects the whole rule with `400` and the offending
  matcher index. Remember JSON string escaping: a literal `.` is `\\.` in the
  JSON body.
- **All matchers, one PID, one window.** The rule fires only when every matcher
  is satisfied by a distinct signal from the **same process** within
  `window_secs`. If `ordered`, the signals must also be in matcher order. A
  partial match, a match split across two PIDs, or matches spread beyond the
  window will not fire.
- **Watch it fire.** Drive the pattern (live traffic, or `--replay` of a
  dataset), then look in the **Threat Correlation** feed. Open the finding to
  see its **cross-layer attack chain** — the exact signals, time-ordered, that
  completed the rule, with the nodes lighting up in sequence. Each rule's
  **fire count** is visible in the detections library.
- **Baseline first.** Turn on **learning mode** to observe what *would* fire
  (findings are recorded and counted, but alerts/cases/notifications are
  suppressed) so you can tune a new rule before enforcing it. Use suppressions
  to silence known-benign matches.
</content>
</invoke>
