// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

// TestChainResumesAcrossRestart proves the fix: after a restart, a fresh Chain
// resumes the sequence + hash chain from the durable store instead of colliding
// at seq 0 (which silently dropped entries and forked the chain).
func TestChainResumesAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")

	// Run 1: 5 entries.
	store1, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	chain1 := NewChain()
	chain1.AttachSink(store1)
	for i := 0; i < 5; i++ {
		if err := chain1.Append(NewEntry("agent.start", SeverityInfo, nil)); err != nil {
			t.Fatal(err)
		}
	}
	store1.Close()

	// Run 2 (simulated restart): a FRESH chain over the same store.
	store2, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	chain2 := NewChain()
	chain2.AttachSink(store2)
	for i := 0; i < 3; i++ {
		if err := chain2.Append(NewEntry("model.access.blocked", SeverityHigh, nil)); err != nil {
			t.Fatal(err)
		}
	}

	// All 8 must be persisted (pre-fix: the 3 post-restart entries collided at
	// seq 0-2 and were dropped, leaving 5).
	n, _ := store2.Count()
	if n != 8 {
		t.Fatalf("expected 8 durable entries across restart, got %d (seq collision drops)", n)
	}
	// And the hash chain must still verify at rest — no fork at the restart seam.
	checked, err := store2.VerifyChain()
	if err != nil {
		t.Fatalf("chain must stay continuous across restart: %v", err)
	}
	if checked != 8 {
		t.Errorf("expected 8 verified entries, got %d", checked)
	}
}
