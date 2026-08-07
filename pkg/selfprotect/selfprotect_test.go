// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package selfprotect

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCleanBaselineHasNoTamper(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	cfg := filepath.Join(dir, "config.yaml")
	writeFile(t, bin, "ELFBINARY")
	writeFile(t, cfg, "enforce: true")

	g := New()
	g.Protect(bin, cfg)
	if tampers := g.Verify(); len(tampers) != 0 {
		t.Fatalf("unmodified files should show no tamper, got %v", tampers)
	}
}

func TestDetectsModification(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	writeFile(t, bin, "ORIGINAL")
	g := New()
	g.Protect(bin)

	writeFile(t, bin, "TROJANIZED") // attacker swaps the binary
	tampers := g.Verify()
	if len(tampers) != 1 || tampers[0].Reason != "modified" {
		t.Fatalf("expected one 'modified' tamper, got %v", tampers)
	}
	if tampers[0].OldHash == tampers[0].NewHash {
		t.Error("modified tamper should carry differing hashes")
	}

	// Tamper is sticky: still reported on a second verify (evidence persists).
	if len(g.Verify()) != 1 {
		t.Error("tamper should remain reported until re-baselined")
	}
}

func TestDetectsRemoval(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	writeFile(t, cfg, "policy")
	g := New()
	g.Protect(cfg)

	os.Remove(cfg) // attacker deletes the config to disable protection
	tampers := g.Verify()
	if len(tampers) != 1 || tampers[0].Reason != "removed" {
		t.Fatalf("expected one 'removed' tamper, got %v", tampers)
	}
}

func TestAbsentAtBaselineIsNotTamper(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.yaml")
	g := New()
	g.Protect(missing) // baselined as absent
	if tampers := g.Verify(); len(tampers) != 0 {
		t.Errorf("a file absent at baseline should not be tamper, got %v", tampers)
	}
}

func TestBaselineReports(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "agent")
	writeFile(t, f, "data")
	g := New()
	g.Protect(f)
	b := g.Baseline()
	if len(b) != 1 || !b[0].Exists || b[0].Hash == "" {
		t.Errorf("baseline should record a hashed, present file: %+v", b)
	}
}
