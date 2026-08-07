// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewEntry(t *testing.T) {
	entry := NewEntry("file_blocked", SeverityCritical, map[string]any{
		"pid":       1234,
		"file_path": "/models/llama.safetensors",
	})

	if entry.EventType != "file_blocked" {
		t.Errorf("expected event_type file_blocked, got %s", entry.EventType)
	}
	if entry.Severity != SeverityCritical {
		t.Errorf("expected severity critical, got %s", entry.Severity)
	}
	if entry.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
	if entry.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestChainAppendAndVerify(t *testing.T) {
	chain := NewChain()

	e1 := NewEntry("file_access", SeverityInfo, map[string]any{"pid": 100})
	e2 := NewEntry("file_blocked", SeverityHigh, map[string]any{"pid": 200})
	e3 := NewEntry("network_blocked", SeverityCritical, map[string]any{"pid": 300})

	if err := chain.Append(e1); err != nil {
		t.Fatalf("append e1: %v", err)
	}
	if err := chain.Append(e2); err != nil {
		t.Fatalf("append e2: %v", err)
	}
	if err := chain.Append(e3); err != nil {
		t.Fatalf("append e3: %v", err)
	}

	if chain.Len() != 3 {
		t.Errorf("expected 3 entries, got %d", chain.Len())
	}

	if err := chain.Verify(); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func TestChainGenesisHash(t *testing.T) {
	chain := NewChain()
	e := NewEntry("test", SeverityInfo, nil)
	if err := chain.Append(e); err != nil {
		t.Fatal(err)
	}

	entries := chain.Entries()
	if entries[0].PrevHash != GenesisHash {
		t.Errorf("first entry prev_hash should be genesis, got %s", entries[0].PrevHash)
	}
}

func TestChainTamperDetection(t *testing.T) {
	chain := NewChain()

	for i := 0; i < 5; i++ {
		e := NewEntry("test", SeverityInfo, map[string]any{"i": i})
		if err := chain.Append(e); err != nil {
			t.Fatal(err)
		}
	}

	if err := chain.Verify(); err != nil {
		t.Fatalf("clean chain should verify: %v", err)
	}

	// Tamper with an entry
	chain.entries[2].Details = map[string]any{"i": 999}

	if err := chain.Verify(); err == nil {
		t.Error("tampered chain should fail verification")
	}
}

func TestChainPrevHashLinkage(t *testing.T) {
	chain := NewChain()

	e1 := NewEntry("a", SeverityInfo, nil)
	e2 := NewEntry("b", SeverityInfo, nil)
	chain.Append(e1)
	chain.Append(e2)

	entries := chain.Entries()
	if entries[1].PrevHash != entries[0].Hash {
		t.Error("second entry's prev_hash should equal first entry's hash")
	}
}

func TestStoreWriteAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	e1 := NewEntry("file_blocked", SeverityHigh, map[string]any{"pid": 42})
	e2 := NewEntry("network_blocked", SeverityCritical, map[string]any{"dst": "1.2.3.4"})

	chain := NewChain()
	chain.Append(e1)
	chain.Append(e2)

	for _, e := range chain.Entries() {
		if err := store.Write(e); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	store.Close()

	// Load and verify
	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Len() != 2 {
		t.Errorf("expected 2 entries, got %d", loaded.Len())
	}

	if err := loaded.Verify(); err != nil {
		t.Fatalf("loaded chain verification failed: %v", err)
	}
}

func TestStoreFileTamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	store, _ := NewFileStore(path)
	chain := NewChain()

	for i := 0; i < 3; i++ {
		e := NewEntry("test", SeverityInfo, map[string]any{"i": i})
		chain.Append(e)
		store.Write(chain.Entries()[i])
	}
	store.Close()

	// Tamper with file: modify a line
	data, _ := os.ReadFile(path)
	lines := splitLines(data)
	if len(lines) >= 2 {
		var entry Entry
		json.Unmarshal(lines[1], &entry)
		entry.Details = map[string]any{"i": 999}
		tampered, _ := json.Marshal(entry)
		lines[1] = tampered
		os.WriteFile(path, joinLines(lines), 0644)
	}

	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("load should succeed even with tampered data: %v", err)
	}

	if err := loaded.Verify(); err == nil {
		t.Error("tampered file should fail verification")
	}
}

func TestEntryJSON(t *testing.T) {
	e := NewEntry("file_blocked", SeverityHigh, map[string]any{
		"pid":  1234,
		"path": "/models/test.pth",
	})
	e.PrevHash = GenesisHash
	e.Hash = computeHash(e)

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Entry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.EventType != e.EventType {
		t.Errorf("event_type mismatch: %s vs %s", decoded.EventType, e.EventType)
	}
	if decoded.Hash != e.Hash {
		t.Errorf("hash mismatch")
	}
}

func TestChainConcurrentAppend(t *testing.T) {
	chain := NewChain()
	done := make(chan struct{})

	go func() {
		for i := 0; i < 100; i++ {
			chain.Append(NewEntry("test", SeverityInfo, map[string]any{"i": i}))
		}
		close(done)
	}()

	<-done

	if chain.Len() != 100 {
		t.Errorf("expected 100 entries, got %d", chain.Len())
	}
	if err := chain.Verify(); err != nil {
		t.Fatalf("concurrent chain verification failed: %v", err)
	}
}

func TestSeverityLevels(t *testing.T) {
	levels := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for _, l := range levels {
		if l == "" {
			t.Error("severity should not be empty")
		}
	}
}

func TestChainEntriesReturnsCopy(t *testing.T) {
	chain := NewChain()
	chain.Append(NewEntry("test", SeverityInfo, nil))

	entries := chain.Entries()
	entries[0].EventType = "tampered"

	original := chain.Entries()
	if original[0].EventType == "tampered" {
		t.Error("Entries() should return a copy, not a reference")
	}
}

func TestNewEntryTimestamp(t *testing.T) {
	before := time.Now()
	e := NewEntry("test", SeverityInfo, nil)
	after := time.Now()

	if e.Timestamp.Before(before) || e.Timestamp.After(after) {
		t.Error("timestamp should be between before and after")
	}
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

func joinLines(lines [][]byte) []byte {
	var result []byte
	for _, l := range lines {
		result = append(result, l...)
		result = append(result, '\n')
	}
	return result
}
