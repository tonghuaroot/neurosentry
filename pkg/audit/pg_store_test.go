// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"testing"
	"time"
)

// TestPostgresStoreRoundTrip exercises the same durable round-trip as the
// SQLite tests (write + at-rest verify + snapshot upsert) against a real
// Postgres instance. It is env-gated: set NEUROSENTRY_TEST_PG_DSN to a pgx
// connection string (e.g. "postgres://user:pass@localhost:5432/neurosentry")
// to run it; otherwise it is skipped so the default `go test` stays hermetic.
func TestPostgresStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("NEUROSENTRY_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set NEUROSENTRY_TEST_PG_DSN to run the Postgres integration test")
	}

	store, err := OpenStore("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	defer store.Close()

	// Start from a clean slate so the hash chain (which starts at genesis and
	// is verified over the whole table) is deterministic across repeated runs.
	s := store.(*SQLiteStore)
	if _, err := s.db.Exec(`TRUNCATE audit_entries, kv_snapshots`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	chain := NewChain()
	chain.AttachSink(store)

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

	checked, err := store.VerifyChain()
	if err != nil {
		t.Fatalf("at-rest verification failed: %v", err)
	}
	if checked != 50 {
		t.Errorf("expected 50 entries verified, got %d", checked)
	}

	// Query filters must behave identically to SQLite.
	models, err := store.Query(QueryFilter{TypePrefix: "model."})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(models) != 50 {
		t.Errorf("type-prefix filter: expected 50, got %d", len(models))
	}

	// Snapshot upsert round-trip.
	if _, ok, _ := store.LoadSnapshot("cases"); ok {
		t.Fatal("truncated store should have no snapshot")
	}
	if err := store.SaveSnapshot("cases", []byte(`[{"id":"c1"}]`), time.Now()); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	data, ok, err := store.LoadSnapshot("cases")
	if err != nil || !ok || string(data) != `[{"id":"c1"}]` {
		t.Fatalf("snapshot roundtrip failed ok=%v data=%s err=%v", ok, data, err)
	}
	// Upsert overwrites.
	if err := store.SaveSnapshot("cases", []byte(`[{"id":"c2"}]`), time.Now()); err != nil {
		t.Fatalf("save snapshot (upsert): %v", err)
	}
	data, _, _ = store.LoadSnapshot("cases")
	if string(data) != `[{"id":"c2"}]` {
		t.Errorf("snapshot upsert failed: %s", data)
	}
}
