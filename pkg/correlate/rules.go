// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"net"
	"strings"
	"time"
)

// Matcher selects signals a rule cares about. Empty Layer/Kind means "any";
// Pred adds an attribute-level predicate (e.g. "path is a secret").
type Matcher struct {
	Layer Layer
	Kind  string
	Pred  func(Signal) bool
}

func (m Matcher) matches(s Signal) bool {
	if m.Layer != "" && s.Layer != m.Layer {
		return false
	}
	if m.Kind != "" && s.Kind != m.Kind {
		return false
	}
	if m.Pred != nil && !m.Pred(s) {
		return false
	}
	return true
}

// Rule fires when every matcher in All is satisfied by a distinct signal from
// the same process within Window. When Ordered is true the matched signals must
// occur in matcher order (causal sequence); otherwise co-occurrence suffices.
type Rule struct {
	ID          string
	Name        string
	All         []Matcher
	Window      time.Duration
	Ordered     bool
	Severity    string
	Technique   string   // OWASP LLM id (e.g. LLM01)
	MitreAttack string   // MITRE ATT&CK technique id (e.g. T1041)
	Category    string   // grouping for the detections library
	References  []string // doc/CVE/technique links
	Description string

	// Knowledge-base guidance carried on the rule itself. Builtin rules draw
	// their analyst prose from the curated kbGuidance map; custom (operator-
	// authored) rules carry their own Rationale/Remediation/FalsePositives here
	// so the knowledge base can render them too.
	Rationale      string
	Remediation    []string
	FalsePositives []string

	// Matchers is the serializable authoring form of All (custom rules only), so
	// the editor can round-trip a rule back into the form it was created from.
	Matchers []MatcherSpec
}

// matcherSpecs returns the serializable authoring form of the rule's matchers.
// Custom rules carry the exact spec they were compiled from; builtin rules
// (constructed in Go) expose their layer/kind selectors so the console can show
// what they key on.
func (r Rule) matcherSpecs() []MatcherSpec {
	if len(r.Matchers) > 0 {
		out := make([]MatcherSpec, len(r.Matchers))
		copy(out, r.Matchers)
		return out
	}
	out := make([]MatcherSpec, 0, len(r.All))
	for _, m := range r.All {
		out = append(out, MatcherSpec{Layer: string(m.Layer), Kind: m.Kind})
	}
	return out
}

// touchedBy reports whether the new signal could contribute to this rule, so the
// engine only evaluates relevant rules on ingest.
func (r *Rule) touchedBy(s Signal) bool {
	for _, m := range r.All {
		if m.matches(s) {
			return true
		}
	}
	return false
}

// evaluate checks the rule against the windowed signals ending at now. It
// returns the matched causal chain (time-ordered) and whether the rule fired.
func (r *Rule) evaluate(signals []Signal, now time.Time) ([]Signal, bool) {
	cutoff := now.Add(-r.Window)

	// Candidate signals within the window.
	var win []Signal
	for _, s := range signals {
		if !s.Timestamp.Before(cutoff) {
			win = append(win, s)
		}
	}

	used := make([]bool, len(win))
	chain := make([]Signal, len(r.All))
	// Greedy distinct assignment: each matcher takes the earliest unused signal
	// it matches. Matchers here are layer/kind-distinct, so greedy is exact.
	for mi, m := range r.All {
		picked := -1
		for si := range win {
			if used[si] || !m.matches(win[si]) {
				continue
			}
			picked = si
			break
		}
		if picked == -1 {
			return nil, false
		}
		used[picked] = true
		chain[mi] = win[picked]
	}

	if r.Ordered {
		for i := 1; i < len(chain); i++ {
			if chain[i].Timestamp.Before(chain[i-1].Timestamp) {
				return nil, false
			}
		}
	}
	return chain, true
}

// --- Built-in cross-layer rules ---

// BuiltinRules returns NeuroSentry's default correlation rules. Each links an
// AI-layer intent to a kernel-layer consequence — detections that a userspace
// gateway structurally cannot produce.
func BuiltinRules() []Rule {
	return []Rule{
		{
			ID: "NS-CORR-001", Name: "secret-read-then-llm", Category: "Data Exfiltration",
			All: []Matcher{
				{Layer: LayerKernelFile, Kind: "file_read", Pred: pathIsSecret},
				{Pred: isLLMBound},
			},
			Window: 10 * time.Second, Ordered: true, Severity: "critical",
			Technique: "LLM02", MitreAttack: "T1041",
			References:  []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
			Description: "a credential/secret file was read and then traffic went toward an LLM — likely secret exfiltration to an AI provider",
		},
		{
			ID: "NS-CORR-002", Name: "tool-triggered-exfil", Category: "Data Exfiltration",
			All: []Matcher{
				{Layer: LayerMCP, Kind: "tool_call"},
				{Layer: LayerKernelNet, Kind: "net_connect", Pred: dstIsExternal},
			},
			Window: 5 * time.Second, Ordered: true, Severity: "high",
			Technique: "LLM06", MitreAttack: "T1567",
			Description: "an MCP tool call was immediately followed by an outbound connection to an external host — possible data exfiltration via a tool",
		},
		{
			ID: "NS-CORR-003", Name: "tool-spawned-process", Category: "Excessive Agency",
			All: []Matcher{
				{Layer: LayerMCP, Kind: "tool_call"},
				{Layer: LayerKernelProc, Kind: "exec"},
			},
			Window: 3 * time.Second, Ordered: true, Severity: "high",
			Technique: "LLM06", MitreAttack: "T1059",
			Description: "an MCP tool call spawned a new process — excessive agency / possible command execution",
		},
		{
			ID: "NS-CORR-004", Name: "injection-then-action", Category: "Prompt Injection",
			All: []Matcher{
				{Pred: isInjectionFlagged},
				{Pred: isKernelSideEffect},
			},
			Window: 8 * time.Second, Ordered: true, Severity: "critical",
			Technique: "LLM01", MitreAttack: "T1059",
			Description: "a prompt-injection attempt was followed by a real system action — the injection may have succeeded",
		},
		{
			ID: "NS-CORR-005", Name: "unverified-model-load", Category: "Supply Chain",
			All: []Matcher{
				{Layer: LayerModel, Kind: "load", Pred: modelUnverified},
			},
			Window: time.Second, Severity: "medium",
			Technique: "LLM03", MitreAttack: "T1195",
			Description: "a model was loaded without integrity verification — supply-chain risk",
		},
		{
			ID: "NS-CORR-006", Name: "pickle-deserialization-rce", Category: "Supply Chain",
			All: []Matcher{
				{Layer: LayerModel, Kind: "pickle_load"},
				{Layer: LayerKernelProc, Kind: "exec"},
			},
			Window: 4 * time.Second, Ordered: true, Severity: "critical",
			Technique: "LLM03", MitreAttack: "T1059",
			Description: "a pickle/model deserialization was followed by process execution — classic deserialization RCE",
		},
		{
			ID: "NS-CORR-007", Name: "model-theft-staging", Category: "Model Theft",
			All: []Matcher{
				{Layer: LayerKernelFile, Kind: "file_read", Pred: pathIsModel},
				{Layer: LayerKernelNet, Kind: "net_connect", Pred: dstIsExternal},
			},
			Window: 15 * time.Second, Ordered: true, Severity: "high",
			Technique: "LLM10", MitreAttack: "T1030",
			Description: "a protected model file was read and then large egress went to an external host — possible model weight exfiltration",
		},
		{
			ID: "NS-CORR-008", Name: "reverse-shell-indicator", Category: "Command & Control",
			All: []Matcher{
				{Layer: LayerKernelProc, Kind: "exec", Pred: commIsShell},
				{Layer: LayerKernelNet, Kind: "net_connect", Pred: dstIsExternal},
			},
			Window: 3 * time.Second, Severity: "critical",
			MitreAttack: "T1059.004",
			Description: "a shell process opened an outbound connection to an external host — reverse-shell / C2 pattern",
		},
		{
			ID: "NS-CORR-009", Name: "container-escape-probe", Category: "Privilege Escalation",
			All: []Matcher{
				{Layer: LayerKernelFile, Pred: pathIsContainerEscape},
			},
			Window: time.Second, Severity: "high",
			MitreAttack: "T1611",
			Description: "access to a container-escape sensitive path (docker.sock, /proc/1/root, host mounts) — container breakout attempt",
		},
		{
			ID: "NS-CORR-010", Name: "shadow-ai-egress", Category: "Shadow AI",
			All: []Matcher{
				{Layer: LayerKernelNet, Kind: "net_connect", Pred: isUnsanctionedAI},
			},
			Window: time.Second, Severity: "medium",
			Technique: "LLM02", MitreAttack: "T1567",
			Description: "outbound traffic to an unsanctioned AI provider — shadow-AI usage that may leak data or bypass the gateway",
		},
		{
			ID: "NS-CORR-011", Name: "tool-then-secret-read", Category: "Credential Access",
			All: []Matcher{
				{Layer: LayerMCP, Kind: "tool_call"},
				{Layer: LayerKernelFile, Kind: "file_read", Pred: pathIsSecret},
			},
			Window: 5 * time.Second, Ordered: true, Severity: "high",
			Technique: "LLM06", MitreAttack: "T1552",
			Description: "an MCP tool call was followed by a read of a credential/secret file — a tool reaching for secrets it should not touch",
		},
	}
}

// --- Predicates ---

var secretPathHints = []string{
	"shadow", "/.ssh/", "id_rsa", "id_ed25519", ".aws/credentials",
	".env", "/etc/passwd", ".pem", ".pgpass", "kubeconfig", ".netrc",
}

var modelExtHints = []string{".safetensors", ".gguf", ".pth", ".pt", ".onnx", ".h5", ".ckpt", ".bin"}

func pathIsModel(s Signal) bool {
	p := strings.ToLower(s.Attr("path"))
	for _, e := range modelExtHints {
		if strings.HasSuffix(p, e) {
			return true
		}
	}
	return false
}

var shellComms = []string{"sh", "bash", "zsh", "dash", "ash", "ksh", "csh", "nc", "ncat", "socat"}

func commIsShell(s Signal) bool {
	c := strings.ToLower(s.Attr("comm"))
	for _, sh := range shellComms {
		if c == sh {
			return true
		}
	}
	return false
}

var containerEscapeHints = []string{"docker.sock", "/proc/1/root", "/var/run/docker", "/run/containerd", "/host/", ".dockerenv"}

func pathIsContainerEscape(s Signal) bool {
	p := strings.ToLower(s.Attr("path"))
	for _, h := range containerEscapeHints {
		if strings.Contains(p, h) {
			return true
		}
	}
	return false
}

// isUnsanctionedAI matches a network flow explicitly tagged as shadow AI (an AI
// provider destination that is not on the sanctioned allowlist).
func isUnsanctionedAI(s Signal) bool {
	return s.Layer == LayerKernelNet && s.Attr("shadow_ai") == "true"
}

func pathIsSecret(s Signal) bool {
	p := strings.ToLower(s.Attr("path"))
	if p == "" {
		return false
	}
	for _, h := range secretPathHints {
		if strings.Contains(p, h) {
			return true
		}
	}
	return false
}

// isLLMBound matches any AI/gateway signal or a kernel network flow to a known
// AI provider (attribute "ai_provider" set by the egress classifier).
func isLLMBound(s Signal) bool {
	if s.Layer == LayerAI {
		return true
	}
	if s.Layer == LayerKernelNet && s.Attr("ai_provider") != "" {
		return true
	}
	return false
}

// dstIsExternal reports whether a network signal targets a public (non-RFC1918)
// address, or is explicitly tagged external.
func dstIsExternal(s Signal) bool {
	if s.Attr("external") == "true" {
		return true
	}
	dst := s.Attr("dst")
	if dst == "" {
		return false
	}
	ip := net.ParseIP(dst)
	if ip == nil {
		return false
	}
	return isPublicIP(ip)
}

func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		case ip4[0] == 127:
			return false
		}
		return true
	}
	return ip.IsGlobalUnicast()
}

func isInjectionFlagged(s Signal) bool {
	v := s.Attr("injection")
	return v == "malicious" || v == "suspicious"
}

// isKernelSideEffect matches a concrete system action (process/network).
func isKernelSideEffect(s Signal) bool {
	return s.Layer == LayerKernelProc || s.Layer == LayerKernelNet
}

func modelUnverified(s Signal) bool {
	return s.Attr("verified") == "false"
}
