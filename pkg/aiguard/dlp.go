// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aiguard

import (
	"regexp"
	"strings"
)

// DLP (Data Loss Prevention) for AI egress: detect secrets and PII in text
// destined for an external LLM API. This is the "your app is about to send an
// AWS key to ChatGPT" guard — the highest-value control an AI gateway offers.
// Maps to OWASP LLM02 (Sensitive Information Disclosure).

// SecretType categorizes a DLP finding.
type SecretType string

const (
	SecretOpenAIKey    SecretType = "openai_api_key"
	SecretAnthropicKey SecretType = "anthropic_api_key"
	SecretAWSKey       SecretType = "aws_access_key"
	SecretGitHubToken  SecretType = "github_token"
	SecretSlackToken   SecretType = "slack_token"
	SecretGoogleKey    SecretType = "google_api_key"
	SecretPrivateKey   SecretType = "private_key"
	SecretJWT          SecretType = "jwt"
	SecretGenericKey   SecretType = "generic_secret"
	PIIEmail           SecretType = "email"
	PIICreditCard      SecretType = "credit_card"
	PIISSN             SecretType = "ssn"
)

type dlpPattern struct {
	typ      SecretType
	re       *regexp.Regexp
	validate func(string) bool // optional secondary check (e.g. Luhn)
}

// DLPFinding is one detected sensitive item, with the value redacted so the
// finding itself never re-leaks the secret.
type DLPFinding struct {
	Type     SecretType `json:"type"`
	Redacted string     `json:"redacted"`
}

// DLPResult is the outcome of scanning text.
type DLPResult struct {
	Leaked   bool         `json:"leaked"`
	Findings []DLPFinding `json:"findings,omitempty"`
}

// SecretScanner detects secrets/PII. It is safe for concurrent use.
type SecretScanner struct {
	patterns []dlpPattern
}

// NewSecretScanner builds a scanner with the built-in secret and PII patterns.
func NewSecretScanner() *SecretScanner {
	return &SecretScanner{patterns: builtinDLPPatterns()}
}

// Scan inspects text and reports any secrets/PII found. The first-matched value
// per finding is redacted in the result.
func (s *SecretScanner) Scan(text string) DLPResult {
	var findings []DLPFinding
	for _, p := range s.patterns {
		matches := p.re.FindAllString(text, -1)
		for _, m := range matches {
			if p.validate != nil && !p.validate(m) {
				continue
			}
			findings = append(findings, DLPFinding{Type: p.typ, Redacted: redact(m)})
		}
	}
	return DLPResult{Leaked: len(findings) > 0, Findings: findings}
}

// ScanBytes is a convenience wrapper over Scan.
func (s *SecretScanner) ScanBytes(b []byte) DLPResult {
	return s.Scan(string(b))
}

func builtinDLPPatterns() []dlpPattern {
	return []dlpPattern{
		{typ: SecretOpenAIKey, re: regexp.MustCompile(`sk-(proj-)?[A-Za-z0-9_-]{20,}`)},
		{typ: SecretAnthropicKey, re: regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
		{typ: SecretAWSKey, re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{typ: SecretGitHubToken, re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
		{typ: SecretSlackToken, re: regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
		{typ: SecretGoogleKey, re: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
		{typ: SecretPrivateKey, re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
		{typ: SecretJWT, re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
		{typ: SecretGenericKey, re: regexp.MustCompile(`(?i)(api[_-]?key|secret|access[_-]?token|password)\s*[:=]\s*["']?[A-Za-z0-9/+_-]{16,}`)},
		{typ: PIIEmail, re: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)},
		{typ: PIICreditCard, re: regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), validate: luhnValid},
		{typ: PIISSN, re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	}
}

// AnyLeaked is a fast boolean check used by the gateway's inline path.
func (s *SecretScanner) AnyLeaked(text string) bool {
	for _, p := range s.patterns {
		if loc := p.re.FindString(text); loc != "" {
			if p.validate == nil || p.validate(loc) {
				return true
			}
		}
	}
	return false
}

// redact keeps a short prefix and masks the rest so findings are auditable
// without re-exposing the secret.
func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 6 {
		return "******"
	}
	return s[:4] + strings.Repeat("*", 6)
}

// luhnValid runs the Luhn checksum to cut credit-card false positives.
func luhnValid(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
