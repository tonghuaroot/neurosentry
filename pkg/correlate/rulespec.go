// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Errors returned by UpdateRule so callers can distinguish "no such rule" and
// "that rule is builtin, not editable" from a spec-validation failure.
var (
	ErrRuleNotFound  = errors.New("rule id not found")
	ErrRuleNotCustom = errors.New("rule is builtin and cannot be edited")
)

func newRuleID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "NS-CUSTOM-" + hex.EncodeToString(b)
}

// MatcherSpec is a data-driven matcher an operator can define at runtime — a
// layer/kind selector plus an optional attribute regex — so detection rules can
// be authored as data (detection-as-code) rather than compiled Go.
type MatcherSpec struct {
	Layer       string `json:"layer"`        // "" = any (ai|mcp|kernel_file|kernel_net|kernel_proc|model)
	Kind        string `json:"kind"`         // "" = any (file_read|net_connect|exec|tool_call|...)
	AttrKey     string `json:"attr_key"`     // optional attribute to test
	AttrPattern string `json:"attr_pattern"` // regex over the attribute value
}

// RuleSpec is the serializable form of a correlation rule.
type RuleSpec struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Category    string        `json:"category"`
	Severity    string        `json:"severity"`
	Technique   string        `json:"technique"`
	MitreAttack string        `json:"mitre_attack"`
	Description string        `json:"description"`
	WindowSecs  float64       `json:"window_secs"`
	Ordered     bool          `json:"ordered"`
	Matchers    []MatcherSpec `json:"matchers"`

	// Knowledge-base authoring fields. For custom rules these become the KB
	// article's analyst guidance (builtin rules use the curated kbGuidance map).
	Rationale      string   `json:"rationale"`
	Remediation    []string `json:"remediation"`
	FalsePositives []string `json:"false_positives"`
	References     []string `json:"references"`
}

// compile turns a RuleSpec into an executable Rule, validating the regexes.
func (spec RuleSpec) compile() (Rule, error) {
	if spec.Name == "" {
		return Rule{}, fmt.Errorf("rule name is required")
	}
	if len(spec.Matchers) == 0 {
		return Rule{}, fmt.Errorf("at least one matcher is required")
	}
	matchers := make([]Matcher, 0, len(spec.Matchers))
	for i, ms := range spec.Matchers {
		m := Matcher{Layer: Layer(ms.Layer), Kind: ms.Kind}
		if ms.AttrKey != "" && ms.AttrPattern != "" {
			re, err := regexp.Compile(ms.AttrPattern)
			if err != nil {
				return Rule{}, fmt.Errorf("matcher %d: invalid pattern %q: %w", i, ms.AttrPattern, err)
			}
			key := ms.AttrKey
			m.Pred = func(s Signal) bool { return re.MatchString(s.Attr(key)) }
		}
		matchers = append(matchers, m)
	}
	win := time.Duration(spec.WindowSecs * float64(time.Second))
	if win <= 0 {
		win = 10 * time.Second
	}
	sev := spec.Severity
	if sev == "" {
		sev = "medium"
	}
	id := spec.ID
	if id == "" {
		id = newRuleID()
	}
	return Rule{
		ID: id, Name: spec.Name, All: matchers, Window: win, Ordered: spec.Ordered,
		Severity: sev, Technique: spec.Technique, MitreAttack: spec.MitreAttack,
		Category: firstNonEmpty(spec.Category, "Custom"), Description: spec.Description,
		Rationale: spec.Rationale, Remediation: spec.Remediation,
		FalsePositives: spec.FalsePositives, References: spec.References,
		Matchers: spec.Matchers,
	}, nil
}

// AddRule compiles and installs a custom rule at runtime. Returns the rule ID.
func (c *Correlator) AddRule(spec RuleSpec) (string, error) {
	rule, err := spec.compile()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.enabled[rule.ID]; exists {
		return "", fmt.Errorf("rule id %q already exists", rule.ID)
	}
	c.rules = append(c.rules, rule)
	c.enabled[rule.ID] = true
	if c.custom == nil {
		c.custom = make(map[string]bool)
	}
	c.custom[rule.ID] = true
	if rule.Window > c.maxWindow {
		c.maxWindow = rule.Window
	}
	return rule.ID, nil
}

// UpdateRule recompiles a custom rule in place, preserving its enabled state and
// fire count. It is only valid for an existing custom rule; a builtin or unknown
// ID is rejected (ErrRuleNotCustom / ErrRuleNotFound). Enabled state and fire
// count live in maps keyed by rule ID, so swapping the compiled rule in the
// slice preserves them automatically.
func (c *Correlator) UpdateRule(spec RuleSpec) (Rule, error) {
	if spec.ID == "" {
		return Rule{}, ErrRuleNotFound
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.custom[spec.ID] {
		if _, exists := c.enabled[spec.ID]; exists {
			return Rule{}, ErrRuleNotCustom
		}
		return Rule{}, ErrRuleNotFound
	}
	rule, err := spec.compile()
	if err != nil {
		return Rule{}, err
	}
	rule.ID = spec.ID // compile honors spec.ID, but be explicit: keep the same ID
	for i := range c.rules {
		if c.rules[i].ID == spec.ID {
			c.rules[i] = rule
			break
		}
	}
	if rule.Window > c.maxWindow {
		c.maxWindow = rule.Window
	}
	return rule, nil
}

// RemoveRule deletes a custom rule by ID. Built-in rules cannot be removed.
func (c *Correlator) RemoveRule(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.custom[id] {
		return fmt.Errorf("rule %q is not a removable custom rule", id)
	}
	for i := range c.rules {
		if c.rules[i].ID == id {
			c.rules = append(c.rules[:i], c.rules[i+1:]...)
			break
		}
	}
	delete(c.enabled, id)
	delete(c.custom, id)
	delete(c.fireCount, id)
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
