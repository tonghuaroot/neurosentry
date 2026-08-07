// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aiguard

import "testing"

func TestDLPDetectsSecrets(t *testing.T) {
	s := NewSecretScanner()
	cases := []struct {
		text string
		typ  SecretType
	}{
		{"my key is sk-proj-abcdefghij1234567890ABCDEFGH", SecretOpenAIKey},
		{"use sk-ant-api03-abcdefghij1234567890ABCDEF for anthropic", SecretAnthropicKey},
		{"aws creds AKIAIOSFODNN7EXAMPLE here", SecretAWSKey},
		{"token ghp_abcdefghijklmnopqrstuvwxyz0123456789", SecretGitHubToken},
		{"slack xoxb-1234567890-abcdefghij", SecretSlackToken},
		{"-----BEGIN RSA PRIVATE KEY-----", SecretPrivateKey},
		{"api_key = 'abcdef1234567890XYZ'", SecretGenericKey},
	}
	for _, c := range cases {
		r := s.Scan(c.text)
		if !r.Leaked {
			t.Errorf("expected leak for %q", c.text)
			continue
		}
		found := false
		for _, f := range r.Findings {
			if f.Type == c.typ {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: expected type %s, got %+v", c.text, c.typ, r.Findings)
		}
	}
}

func TestDLPRedactsValue(t *testing.T) {
	s := NewSecretScanner()
	r := s.Scan("sk-proj-supersecretkey1234567890ABCD")
	if len(r.Findings) == 0 {
		t.Fatal("expected finding")
	}
	red := r.Findings[0].Redacted
	if len(red) > 12 || red == "sk-proj-supersecretkey1234567890ABCD" {
		t.Errorf("value not properly redacted: %q", red)
	}
}

func TestDLPEmail(t *testing.T) {
	s := NewSecretScanner()
	if !s.Scan("contact alice@example.com for details").Leaked {
		t.Error("email should be detected")
	}
}

func TestDLPCreditCardLuhn(t *testing.T) {
	s := NewSecretScanner()
	// Valid Visa test number (passes Luhn).
	if !s.Scan("card 4111 1111 1111 1111").Leaked {
		t.Error("valid credit card should be detected")
	}
	// Fails Luhn -> not flagged as a card (reduces false positives).
	r := s.Scan("order number 1234 5678 9012 3456")
	for _, f := range r.Findings {
		if f.Type == PIICreditCard {
			t.Error("invalid Luhn number should not be flagged as credit card")
		}
	}
}

func TestDLPSSN(t *testing.T) {
	s := NewSecretScanner()
	if !s.Scan("ssn 123-45-6789").Leaked {
		t.Error("SSN should be detected")
	}
}

func TestDLPCleanText(t *testing.T) {
	s := NewSecretScanner()
	clean := []string{
		"Please summarize this document about renewable energy.",
		"What is the weather forecast for tomorrow?",
		"Translate this sentence into Spanish.",
	}
	for _, c := range clean {
		if s.Scan(c).Leaked {
			t.Errorf("clean text flagged: %q -> %+v", c, s.Scan(c).Findings)
		}
	}
}

func TestDLPAnyLeakedFastPath(t *testing.T) {
	s := NewSecretScanner()
	if !s.AnyLeaked("here is AKIAIOSFODNN7EXAMPLE") {
		t.Error("AnyLeaked should detect AWS key")
	}
	if s.AnyLeaked("just a normal prompt about cooking") {
		t.Error("AnyLeaked false positive on clean text")
	}
}

func TestDLPMultipleFindings(t *testing.T) {
	s := NewSecretScanner()
	r := s.Scan("key sk-proj-abcdefghij1234567890ABCDEFGH and email bob@corp.com and AKIAIOSFODNN7EXAMPLE")
	if len(r.Findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(r.Findings))
	}
}
