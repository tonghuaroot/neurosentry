// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aiguard

import (
	"regexp"
	"sort"
	"strings"
)

// Verdict is the classification of a piece of text.
type Verdict string

const (
	VerdictClean      Verdict = "clean"
	VerdictSuspicious Verdict = "suspicious"
	VerdictMalicious  Verdict = "malicious"
)

// InjectionRule is one weighted heuristic. Weight reflects how strongly a match
// indicates an attack; Technique maps it to the threat taxonomy.
type InjectionRule struct {
	Name      string
	re        *regexp.Regexp
	Weight    float64
	Technique string // OWASP LLM / MITRE ATLAS id
}

// Match records a fired rule.
type Match struct {
	Rule      string  `json:"rule"`
	Weight    float64 `json:"weight"`
	Technique string  `json:"technique"`
	Excerpt   string  `json:"excerpt,omitempty"`
}

// InjectionResult is the outcome of scanning text.
type InjectionResult struct {
	Verdict    Verdict  `json:"verdict"`
	Score      float64  `json:"score"`
	Matches    []Match  `json:"matches,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
}

// InjectionDetector scans text (prompts, tool inputs, tool outputs) for
// prompt-injection and jailbreak patterns. Thresholds map the accumulated score
// to a verdict.
type InjectionDetector struct {
	rules        []InjectionRule
	suspiciousAt float64
	maliciousAt  float64
}

// NewInjectionDetector builds a detector with the built-in rule set and
// default thresholds (suspicious >= 0.5, malicious >= 1.0).
func NewInjectionDetector() *InjectionDetector {
	d := &InjectionDetector{suspiciousAt: 0.5, maliciousAt: 1.0}
	d.rules = compileRules(builtinInjectionRules())
	return d
}

// SetThresholds overrides the score cutoffs for suspicious/malicious verdicts.
func (d *InjectionDetector) SetThresholds(suspicious, malicious float64) {
	d.suspiciousAt = suspicious
	d.maliciousAt = malicious
}

// AddRule registers a custom weighted pattern. Returns an error on a bad regex.
func (d *InjectionDetector) AddRule(name, pattern string, weight float64, technique string) error {
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return err
	}
	d.rules = append(d.rules, InjectionRule{Name: name, re: re, Weight: weight, Technique: technique})
	return nil
}

// Detect scans text and returns a scored verdict. Multiple distinct rules
// firing accumulate score, so layered/obfuscated attacks escalate.
func (d *InjectionDetector) Detect(text string) InjectionResult {
	var matches []Match
	var score float64
	techSet := make(map[string]struct{})

	for _, r := range d.rules {
		if loc := r.re.FindStringIndex(text); loc != nil {
			score += r.Weight
			techSet[r.Technique] = struct{}{}
			matches = append(matches, Match{
				Rule:      r.Name,
				Weight:    r.Weight,
				Technique: r.Technique,
				Excerpt:   excerpt(text, loc[0], loc[1]),
			})
		}
	}

	techniques := make([]string, 0, len(techSet))
	for t := range techSet {
		techniques = append(techniques, t)
	}
	sort.Strings(techniques)

	res := InjectionResult{Score: round2(score), Matches: matches, Techniques: techniques}
	switch {
	case score >= d.maliciousAt:
		res.Verdict = VerdictMalicious
	case score >= d.suspiciousAt:
		res.Verdict = VerdictSuspicious
	default:
		res.Verdict = VerdictClean
	}
	return res
}

func compileRules(specs []InjectionRule) []InjectionRule {
	for i := range specs {
		specs[i].re = regexp.MustCompile("(?i)" + specs[i].re.String())
	}
	return specs
}

// rawRule is a convenience for declaring rules with a pattern string.
func rawRule(name, pattern string, weight float64, technique string) InjectionRule {
	return InjectionRule{Name: name, re: regexp.MustCompile(pattern), Weight: weight, Technique: technique}
}

// builtinInjectionRules is the default heuristic corpus. Patterns are drawn from
// widely-documented prompt-injection / jailbreak techniques (OWASP LLM01;
// public jailbreak taxonomies). Weights are calibrated so a single strong
// indicator (e.g. explicit instruction override) reaches "malicious", while
// weaker signals require corroboration.
func builtinInjectionRules() []InjectionRule {
	return []InjectionRule{
		// Instruction override — the canonical injection.
		rawRule("instruction-override", `ignore\s+(all\s+)?(the\s+)?(previous|prior|above|preceding)\s+(instructions|prompts|rules|commands)`, 1.0, "LLM01"),
		rawRule("ignore-policy", `ignore\s+(your\s+|the\s+|any\s+)?(content\s+polic|safety|guidelines|rules|restrictions|ethics)`, 0.9, "LLM01"),
		rawRule("disregard-directive", `disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions|rules|guidelines)`, 1.0, "LLM01"),
		rawRule("forget-everything", `forget\s+(everything|all)\s+(you|that|above|before)`, 0.7, "LLM01"),
		// System-prompt exfiltration.
		rawRule("reveal-system-prompt", `(reveal|show|repeat|print|output|tell\s+me)\s+(your\s+)?(system\s+prompt|initial\s+instructions|the\s+(words|text)\s+above)`, 0.9, "LLM01"),
		rawRule("what-is-system-prompt", `what\s+(is|are)\s+your\s+(system\s+prompt|initial\s+instructions|original\s+instructions)`, 0.7, "LLM01"),
		// Role / persona manipulation.
		rawRule("role-override", `you\s+are\s+now\s+(a|an|in|the)`, 0.5, "LLM01"),
		rawRule("act-as", `(act|behave|respond)\s+as\s+(if\s+you\s+(are|were)|a|an)\b`, 0.4, "LLM01"),
		rawRule("pretend", `pretend\s+(to\s+be|you\s+are|that\s+you)`, 0.5, "LLM01"),
		// Named jailbreak personas.
		rawRule("dan-jailbreak", `\b(DAN|do\s+anything\s+now|developer\s+mode|jailbreak|jailbroken)\b`, 0.9, "LLM01"),
		rawRule("unrestricted-persona", `\b(AIM|STAN|DUDE|unrestricted\s+(ai|assistant|mode)|no\s+(restrictions|limitations|limits|rules))\b`, 0.7, "LLM01"),
		// Refusal / guardrail suppression.
		rawRule("no-refusal", `(do\s+not|don't|never)\s+(refuse|decline|apologize|warn|mention)`, 0.6, "LLM01"),
		rawRule("without-warning", `without\s+(any\s+)?(warning|disclaimer|ethical|moral|restriction)`, 0.5, "LLM01"),
		rawRule("bypass-guardrails", `(bypass|circumvent|override)\s+(your\s+|the\s+)?(guidelines|guardrails|safety|filters|restrictions)`, 0.9, "LLM01"),
		// Delimiter / format injection (breaking out of the prompt frame).
		rawRule("chat-template-injection", `<\|(im_start|im_end|system|user|assistant)\|>`, 0.8, "LLM01"),
		rawRule("inst-tag-injection", `\[/?(INST|SYS|SYSTEM)\]`, 0.6, "LLM01"),
		rawRule("fake-system-tag", `</?(system|admin|root)>`, 0.5, "LLM01"),
		// Encoding / obfuscation evasion.
		rawRule("decode-and-execute", `(decode|base64|rot13|reverse)\b.{0,40}?(and\s+)?(then\s+)?(execute|run|follow|do|comply)`, 0.8, "LLM01"),
		// Exfiltration intent embedded in a prompt.
		rawRule("print-file-contents", `(print|output|show|cat|read)\s+(the\s+)?(contents\s+of|file|/etc/|~/\.)`, 0.6, "LLM06"),
	}
}

func excerpt(s string, start, end int) string {
	const pad = 12
	from := start - pad
	if from < 0 {
		from = 0
	}
	to := end + pad
	if to > len(s) {
		to = len(s)
	}
	return strings.TrimSpace(s[from:to])
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
