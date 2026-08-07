// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync/atomic"
)

// False-positive tuning. Runtime detections are only useful if operators trust
// them, and trust dies with noise. A Suppression is an operator-authored rule
// that silences a specific detection when a known-benign attribute is present
// (e.g. NS-CORR-002 egress to a sanctioned backup host). Suppressions never
// delete a rule — they annotate and count what was silenced, so tuning stays
// auditable and reversible.

// SuppressionSpec is the serializable form of a suppression.
type SuppressionSpec struct {
	ID          string `json:"id"`
	RuleID      string `json:"rule_id"`      // detection to suppress ("" = any)
	AttrKey     string `json:"attr_key"`     // attribute to test on the finding's chain
	AttrPattern string `json:"attr_pattern"` // regex the attribute value must match
	Reason      string `json:"reason"`       // why this is benign (audit trail)
}

type suppression struct {
	spec    SuppressionSpec
	re      *regexp.Regexp
	matched atomic.Int64
}

// matches reports whether a finding should be silenced by this suppression.
func (s *suppression) matches(f Finding) bool {
	if s.spec.RuleID != "" && s.spec.RuleID != f.RuleID {
		return false
	}
	for _, sig := range f.Chain {
		if s.re.MatchString(sig.Attr(s.spec.AttrKey)) {
			return true
		}
	}
	return false
}

// SuppressionInfo is the operator-facing view (spec + how often it fired).
type SuppressionInfo struct {
	SuppressionSpec
	MatchCount int64 `json:"match_count"`
}

// AddSuppression installs a false-positive suppression and returns its ID.
func (c *Correlator) AddSuppression(spec SuppressionSpec) (string, error) {
	if spec.AttrKey == "" || spec.AttrPattern == "" {
		return "", fmt.Errorf("suppression requires attr_key and attr_pattern")
	}
	re, err := regexp.Compile(spec.AttrPattern)
	if err != nil {
		return "", fmt.Errorf("invalid pattern %q: %w", spec.AttrPattern, err)
	}
	if spec.ID == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		spec.ID = "NS-SUP-" + hex.EncodeToString(b)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.suppressions == nil {
		c.suppressions = map[string]*suppression{}
	}
	if _, exists := c.suppressions[spec.ID]; exists {
		return "", fmt.Errorf("suppression %q already exists", spec.ID)
	}
	c.suppressions[spec.ID] = &suppression{spec: spec, re: re}
	return spec.ID, nil
}

// RemoveSuppression deletes a suppression by ID.
func (c *Correlator) RemoveSuppression(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.suppressions[id]; !ok {
		return fmt.Errorf("suppression %q not found", id)
	}
	delete(c.suppressions, id)
	return nil
}

// Suppressions lists installed suppressions with their match counts.
func (c *Correlator) Suppressions() []SuppressionInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SuppressionInfo, 0, len(c.suppressions))
	for _, s := range c.suppressions {
		out = append(out, SuppressionInfo{SuppressionSpec: s.spec, MatchCount: s.matched.Load()})
	}
	return out
}

// suppressedLocked reports whether a finding is silenced by any suppression,
// bumping the matching suppression's counter. Caller holds c.mu.
func (c *Correlator) suppressedLocked(f Finding) bool {
	for _, s := range c.suppressions {
		if s.matches(f) {
			s.matched.Add(1)
			return true
		}
	}
	return false
}
