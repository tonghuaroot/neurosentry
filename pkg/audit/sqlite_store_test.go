// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

func TestSQLiteStorePersistsAndVerifies(t *testing.T) {
	store, err := OpenSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	chain := NewChain()
	chain.AttachSink(store)

	// Realistic entries: string + int details, actors.
	for i := 0; i < 50; i++ {
		e := NewEntry("model.access.blocked", SeverityHigh, map[string]any{
			"path": "/models/llama.safetensors", "pid": 4242 + i, "reason": "unauthorized",
		})
		e.SetActor(4242+i, 0, "python3")
		if err := chain.Append(e); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	n, err := store.Count()
	if err != nil || n != 50 {
		t.Fatalf("expected 50 persisted, got %d (err=%v)", n, err)
	}

	// The hash chain must re-verify straight from the database — this proves the
	// details JSON round-trips faithfully enough to recompute the hash.
	checked, err := store.VerifyChain()
	if err != nil {
		t.Fatalf("at-rest verification failed: %v", err)
	}
	if checked != 50 {
		t.Errorf("expected 50 entries verified, got %d", checked)
	}
}

func TestSQLiteStoreQueryFilters(t *testing.T) {
	store, err := OpenSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	chain := NewChain()
	chain.AttachSink(store)

	chain.Append(NewEntry("auth:login", SeverityInfo, nil))
	chain.Append(NewEntry("model.access.blocked", SeverityCritical, map[string]any{"path": "/m.safetensors"}))
	chain.Append(NewEntry("model.access.allowed", SeverityInfo, nil))

	crit, err := store.Query(QueryFilter{Severity: "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if len(crit) != 1 || crit[0].EventType != "model.access.blocked" {
		t.Errorf("severity filter wrong: %+v", crit)
	}

	models, err := store.Query(QueryFilter{TypePrefix: "model."})
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 {
		t.Errorf("type-prefix filter: expected 2, got %d", len(models))
	}
}

// Durability across a reopen: entries written, DB closed, reopened from disk,
// still present and verifiable.
func TestSQLiteStoreSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")

	store, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	chain := NewChain()
	chain.AttachSink(store)
	for i := 0; i < 10; i++ {
		chain.Append(NewEntry("agent.start", SeverityInfo, map[string]any{"n": i}))
	}
	store.Close()

	reopened, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	n, _ := reopened.Count()
	if n != 10 {
		t.Fatalf("expected 10 entries to survive reopen, got %d", n)
	}
	if _, err := reopened.VerifyChain(); err != nil {
		t.Errorf("reopened chain should verify: %v", err)
	}
}
