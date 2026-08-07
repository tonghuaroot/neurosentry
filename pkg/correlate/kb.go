// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"fmt"
	"sort"
	"strings"
)

// KBEntry is a knowledge-base article for a detection rule: the machine-readable
// rule metadata (from BuiltinRules) enriched with human-facing analyst guidance
// — why the pattern matters, how to respond, and what commonly causes false
// positives. It turns each finding into something an operator can understand and
// action, not just an opaque rule ID.
type KBEntry struct {
	RuleID         string   `json:"rule_id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	OWASP          string   `json:"owasp,omitempty"`       // OWASP LLM Top-10 id
	MITRE          string   `json:"mitre,omitempty"`       // MITRE ATT&CK technique id
	WindowSecs     float64  `json:"window_secs"`           // correlation window
	Ordered        bool     `json:"ordered"`               // must the steps occur in order
	Summary        string   `json:"summary"`               // one-line: what it detects
	Rationale      string   `json:"rationale"`             // why it matters
	Remediation    []string `json:"remediation,omitempty"` // what to do
	FalsePositives []string `json:"false_positives,omitempty"`
	References     []string `json:"references,omitempty"`
}

// kbExtra is the curated analyst guidance layered onto a rule's own metadata.
type kbExtra struct {
	rationale      string
	remediation    []string
	falsePositives []string
}

// kbGuidance maps rule ID -> curated guidance. Missing rules still produce a KB
// entry from their rule metadata; this only adds the analyst-facing prose.
var kbGuidance = map[string]kbExtra{
	"NS-CORR-001": {
		rationale: "Reading a credential/secret file and then sending traffic to an LLM is the classic AI-era exfiltration path: an agent (or a compromised process) scoops up secrets and leaks them inside a prompt, where DLP and egress filters rarely look. Because the data leaves as natural-language context, it evades content inspection tuned for structured formats.",
		remediation: []string{
			"Isolate the process/PID and rotate any credentials in the file that was read.",
			"Trace the outbound LLM request and confirm whether secret material was included in the prompt.",
			"Restrict the inference workload's filesystem access so secret paths are not readable (kernel LSM allowlist).",
		},
		falsePositives: []string{
			"A legitimate agent that reads a config file which merely lives under a secret-looking path but contains no live credentials.",
		},
	},
	"NS-CORR-002": {
		rationale: "An MCP tool call immediately followed by an outbound connection to an external host is data leaving through the tool boundary. Tools are granted network capability for their function, so exfiltration disguised as normal tool activity blends into expected traffic.",
		remediation: []string{
			"Review the tool invocation and the destination host; block the host if it is not an approved endpoint.",
			"Constrain the tool's allowed egress to a destination allowlist.",
			"Confirm the payload size/content of the outbound connection.",
		},
		falsePositives: []string{
			"A tool whose legitimate job is to call an external API (e.g. a web-search or fetch tool) to an approved host.",
		},
	},
	"NS-CORR-003": {
		rationale: "A tool call that spawns a new OS process is excessive agency: the model reached beyond its intended tool surface into arbitrary command execution. This is the pivot from 'assistant' to 'operator' and is a precondition for most hands-on-keyboard attacks.",
		remediation: []string{
			"Inspect the spawned process's command line and parent tool.",
			"Run the inference workload under a restricted execution policy (seccomp/no-new-privs) so tools cannot exec.",
			"If the exec was unexpected, isolate the PID and treat the tool as compromised.",
		},
		falsePositives: []string{
			"A tool explicitly designed to run a sandboxed subprocess (e.g. a code-interpreter tool) within policy.",
		},
	},
	"NS-CORR-004": {
		rationale: "A prompt flagged as injection followed by a real kernel-level side effect (file, network, or process action) is the strongest signal that an injection actually succeeded: the attacker's instructions crossed from text into action. This is the cross-layer correlation that a prompt-only or kernel-only tool cannot see.",
		remediation: []string{
			"Treat the action as attacker-controlled: isolate the PID and roll back any side effects (files written, connections made).",
			"Capture the injecting prompt for detection tuning and threat intel.",
			"Tighten input handling / add an injection guard upstream of the tool layer.",
		},
		falsePositives: []string{
			"A benign prompt that trips the injection heuristic (e.g. a security researcher pasting a jailbreak example) that coincidentally precedes unrelated activity.",
		},
	},
	"NS-CORR-005": {
		rationale: "Loading a model artifact that was never verified (no signature / integrity baseline) is a supply-chain risk: a tampered or backdoored model can carry code (via unsafe deserialization) or behavioral backdoors. Trust must be established before load, not after.",
		remediation: []string{
			"Block the load and verify the artifact against a known-good hash / signature.",
			"Source models only from a trusted registry with provenance (SBOM / signing).",
			"Add the artifact to the integrity baseline once verified.",
		},
		falsePositives: []string{
			"A newly-published internal model that simply hasn't been added to the integrity baseline yet.",
		},
	},
	"NS-CORR-006": {
		rationale: "Pickle (and similar) deserialization can execute arbitrary code on load — a single crafted .pkl/.pt file is remote code execution. Observing a dangerous deserialization opcode during a model load is a direct RCE indicator, not a theoretical one.",
		remediation: []string{
			"Kill the loading process immediately; assume code execution occurred.",
			"Quarantine the artifact and scan for the dangerous reduce/global opcodes.",
			"Migrate to a safe serialization format (safetensors) for untrusted models.",
		},
		falsePositives: []string{
			"A trusted first-party artifact that legitimately uses a custom class during unpickling — verify provenance before dismissing.",
		},
	},
	"NS-CORR-007": {
		rationale: "Reading a large model artifact and then staging it toward egress is model theft: the model weights are often the most valuable IP in the environment, and exfiltration is quiet because bulk reads look like normal loading.",
		remediation: []string{
			"Block the egress and identify the destination.",
			"Restrict which processes may read weight files and to where they may connect.",
			"Watermark / license-gate high-value weights so theft is attributable.",
		},
		falsePositives: []string{
			"A legitimate model-serving replica syncing weights to an approved internal store.",
		},
	},
	"NS-CORR-008": {
		rationale: "A process pattern consistent with a reverse shell (interactive shell wired to a socket) inside an inference workload means an attacker has hands-on control. Inference services should never open interactive shells to the network.",
		remediation: []string{
			"Isolate the host/PID and cut the connection immediately.",
			"Preserve the process tree and socket state for forensics.",
			"Hunt for the initial access vector (injection, unsafe deserialization, dependency).",
		},
		falsePositives: []string{
			"A debugging session or admin remote shell run intentionally on the node.",
		},
	},
	"NS-CORR-009": {
		rationale: "Probing for container-escape primitives (cloud metadata, host mounts, privileged devices) from an inference pod signals an attacker trying to break out of the sandbox toward the node and cloud credentials — the step that turns a single-workload compromise into an environment-wide one.",
		remediation: []string{
			"Isolate the pod and rotate any node/cloud credentials reachable from it (e.g. IMDS).",
			"Enforce metadata-service restrictions (IMDSv2 / hop limit) and drop unneeded capabilities.",
			"Review the pod's security context for privileged mounts.",
		},
		falsePositives: []string{
			"A platform agent that legitimately queries the metadata service for instance identity.",
		},
	},
	"NS-CORR-010": {
		rationale: "Egress to an unsanctioned AI provider ('shadow AI') means data is flowing to a model outside governance — no DPA, no retention control, no audit. Even benign use is a compliance and data-leak exposure.",
		remediation: []string{
			"Identify the destination provider and the data sent.",
			"Route AI traffic through the sanctioned gateway and block direct provider egress.",
			"Publish an approved-provider policy and educate the workload owners.",
		},
		falsePositives: []string{
			"A newly-approved provider not yet added to the sanctioned allowlist.",
		},
	},
	"NS-CORR-011": {
		rationale: "A tool call followed by a secret-file read is credential access driven by the model: the tool layer reached into secret material, often the first step before exfiltration or lateral movement. Ordering matters — the tool caused the read.",
		remediation: []string{
			"Determine which tool triggered the read and whether the secret left the host.",
			"Remove secret paths from the workload's readable set; broker secrets via a short-lived token service instead.",
			"Rotate any credential that was read.",
		},
		falsePositives: []string{
			"A provisioning tool that legitimately reads a credential file as part of an approved workflow.",
		},
	},
}

// GlossaryTerm documents one signal/event kind in the cross-layer vocabulary, so
// the console's events and chains are self-explaining.
type GlossaryTerm struct {
	Kind  string `json:"kind"`
	Layer string `json:"layer"`
	What  string `json:"what"`
}

// signalGlossary is the vocabulary of signal kinds the correlation engine emits
// and consumes across layers.
var signalGlossary = []GlossaryTerm{
	{Kind: "file_read", Layer: "kernel_file", What: "A process opened a file for reading, captured by the LSM hook. Secret/model paths are of particular interest."},
	{Kind: "file_write", Layer: "kernel_file", What: "A process wrote to a file — relevant for tampering with model or config artifacts."},
	{Kind: "net_connect", Layer: "kernel_net", What: "An outbound network connection observed at the TC layer. Flagged external when the destination is a public IP."},
	{Kind: "exec", Layer: "kernel_proc", What: "A new process was executed. Inside an inference workload this often indicates command execution / excessive agency."},
	{Kind: "tool_call", Layer: "mcp", What: "The model invoked an MCP tool. The tool boundary is where an agent reaches into files, network, or the OS."},
	{Kind: "prompt", Layer: "ai", What: "An inference request/prompt. May carry an injection verdict (clean/malicious) from the prompt guard."},
	{Kind: "request", Layer: "ai", What: "Traffic bound for an LLM provider — the AI-layer view of an outbound inference call."},
	{Kind: "model_load", Layer: "model", What: "A model artifact was loaded. Watched for unverified artifacts and unsafe deserialization opcodes."},
	{Kind: "pickle_op", Layer: "model", What: "A pickle/deserialization opcode observed during load via uprobe — dangerous reduce/global opcodes imply code execution."},
}

// kbEntryForRule builds one knowledge-base article from a rule. If the rule ID
// has curated analyst guidance (builtin rules), that prose is used; otherwise
// (custom, operator-authored rules) the rule carries its own Rationale/
// Remediation/FalsePositives. References always merge the rule's own links with
// the canonical MITRE/OWASP references.
func kbEntryForRule(r Rule) KBEntry {
	e := KBEntry{
		RuleID:     r.ID,
		Name:       r.Name,
		Category:   r.Category,
		Severity:   r.Severity,
		OWASP:      r.Technique,
		MITRE:      r.MitreAttack,
		WindowSecs: r.Window.Seconds(),
		Ordered:    r.Ordered,
		Summary:    r.Description,
		References: kbReferences(r),
	}
	if g, ok := kbGuidance[r.ID]; ok {
		e.Rationale = g.rationale
		e.Remediation = g.remediation
		e.FalsePositives = g.falsePositives
	} else {
		// Custom rule: draw guidance from the rule's own authoring fields.
		e.Rationale = r.Rationale
		e.Remediation = r.Remediation
		e.FalsePositives = r.FalsePositives
	}
	return e
}

// kbEntriesForRules builds a sorted (by rule ID) KB article set from a rule list.
func kbEntriesForRules(rules []Rule) []KBEntry {
	out := make([]KBEntry, 0, len(rules))
	for _, r := range rules {
		out = append(out, kbEntryForRule(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// KnowledgeBase returns a KB article for every builtin rule, sorted by rule ID.
// Kept for back-compat; the live per-Correlator view (which also includes custom
// rules) is Correlator.KnowledgeBase.
func KnowledgeBase() []KBEntry {
	return kbEntriesForRules(BuiltinRules())
}

// KnowledgeBase returns a KB article for every currently-installed rule (builtin
// and custom), sorted by rule ID — the live knowledge base for this engine.
func (c *Correlator) KnowledgeBase() []KBEntry {
	c.mu.Lock()
	rules := make([]Rule, len(c.rules))
	copy(rules, c.rules)
	c.mu.Unlock()
	return kbEntriesForRules(rules)
}

// SignalGlossary returns the documented signal/event vocabulary.
func SignalGlossary() []GlossaryTerm { return signalGlossary }

// kbReferences merges the rule's own references with canonical MITRE/OWASP links,
// de-duplicated and stable-ordered.
func kbReferences(r Rule) []string {
	seen := map[string]bool{}
	var refs []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			refs = append(refs, u)
		}
	}
	if r.MitreAttack != "" {
		base := r.MitreAttack
		sub := ""
		if i := strings.IndexByte(base, '.'); i >= 0 {
			sub = base[i+1:]
			base = base[:i]
		}
		if sub != "" {
			add(fmt.Sprintf("https://attack.mitre.org/techniques/%s/%s/", base, sub))
		} else {
			add(fmt.Sprintf("https://attack.mitre.org/techniques/%s/", base))
		}
	}
	if r.Technique != "" {
		add("https://owasp.org/www-project-top-10-for-large-language-model-applications/")
	}
	for _, u := range r.References {
		add(u)
	}
	return refs
}
