// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package selfprotect is NeuroSentry's anti-tamper self-defense. A security
// agent is only trustworthy if it can't be quietly disabled or modified: an
// attacker who lands on the host will try to neuter the guard before acting.
// The Guard establishes a cryptographic integrity baseline over the agent's own
// executable and configuration at startup, then re-verifies periodically. Any
// modification or deletion is a critical, tamper-evident finding that flows into
// the same detection -> audit -> circuit-breaker pipeline as any other attack —
// so the agent defends itself the way it defends the models it watches.
package selfprotect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// FileState is the recorded baseline for one protected file.
type FileState struct {
	Path   string `json:"path"`
	Hash   string `json:"hash"`
	Size   int64  `json:"size"`
	Exists bool   `json:"exists"`
}

// Tamper describes a detected change against the baseline.
type Tamper struct {
	Path    string `json:"path"`
	Reason  string `json:"reason"` // "modified" | "removed" | "unreadable"
	OldHash string `json:"old_hash,omitempty"`
	NewHash string `json:"new_hash,omitempty"`
}

// Guard holds the integrity baseline and detects drift from it.
type Guard struct {
	mu       sync.Mutex
	baseline map[string]FileState
	order    []string
	now      func() time.Time
}

// New returns an empty guard.
func New() *Guard {
	return &Guard{baseline: make(map[string]FileState), now: time.Now}
}

// Protect records the current state of each path as the trusted baseline. A path
// that doesn't exist yet is baselined as absent, so its later appearance is not
// itself flagged (only modification/removal of a present file is tamper).
func (g *Guard) Protect(paths ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, seen := g.baseline[p]; !seen {
			g.order = append(g.order, p)
		}
		g.baseline[p] = statOf(p)
	}
}

// Verify re-hashes every baselined file and returns any tamper detected. It does
// NOT mutate the baseline, so a modification keeps being reported until an
// operator re-baselines (via Protect) — tamper is sticky, as evidence should be.
func (g *Guard) Verify() []Tamper {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Tamper
	for _, p := range g.order {
		base := g.baseline[p]
		cur := statOf(p)
		switch {
		case base.Exists && !cur.Exists:
			out = append(out, Tamper{Path: p, Reason: "removed", OldHash: base.Hash})
		case base.Exists && cur.Hash == "":
			out = append(out, Tamper{Path: p, Reason: "unreadable", OldHash: base.Hash})
		case base.Exists && cur.Hash != base.Hash:
			out = append(out, Tamper{Path: p, Reason: "modified", OldHash: base.Hash, NewHash: cur.Hash})
		}
	}
	return out
}

// Baseline returns the recorded baseline states (for status/display).
func (g *Guard) Baseline() []FileState {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]FileState, 0, len(g.order))
	for _, p := range g.order {
		out = append(out, g.baseline[p])
	}
	return out
}

// statOf hashes a file; a missing/unreadable file yields Exists/Hash accordingly.
func statOf(path string) FileState {
	fs := FileState{Path: path}
	info, err := os.Stat(path)
	if err != nil {
		return fs // Exists=false
	}
	fs.Exists = true
	fs.Size = info.Size()
	h, err := hashFile(path)
	if err != nil {
		return fs // Exists=true, Hash="" -> "unreadable"
	}
	fs.Hash = h
	return fs
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// String renders a tamper for logs.
func (t Tamper) String() string {
	return fmt.Sprintf("%s: %s", t.Path, t.Reason)
}
