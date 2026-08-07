// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryScanAndSummary(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, content string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0644)
		return p
	}
	write("llama.safetensors", "weights-aaaa")
	write("whisper.gguf", "weights-bbbb")
	write("bert.pth", "weights-cccc")
	write("readme.txt", "not a model")

	inv := NewInventory()
	if err := inv.Scan([]string{dir}, []string{".safetensors", ".gguf", ".pth"}); err != nil {
		t.Fatal(err)
	}
	assets := inv.Assets()
	if len(assets) != 3 {
		t.Fatalf("expected 3 model assets (readme excluded), got %d", len(assets))
	}
	sum := inv.Summary()
	if sum.Total != 3 || sum.ByFramework["safetensors"] != 1 || sum.ByFramework["gguf"] != 1 || sum.ByFramework["pytorch"] != 1 {
		t.Errorf("unexpected summary: %+v", sum)
	}
	for _, a := range assets {
		if a.SHA256 == "" || a.Status != "indexed" {
			t.Errorf("asset should be hashed+indexed: %+v", a)
		}
	}
}

func TestInventoryDetectsModification(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.safetensors")
	os.WriteFile(p, []byte("original"), 0644)

	inv := NewInventory()
	_ = inv.Scan([]string{dir}, []string{".safetensors"})
	a, _ := inv.FindByPath(p)
	if a.Status != "indexed" {
		t.Fatal("first scan should be indexed")
	}
	// Tamper with the model file, rescan -> modified.
	os.WriteFile(p, []byte("TAMPERED WEIGHTS"), 0644)
	_ = inv.Scan([]string{dir}, []string{".safetensors"})
	a2, _ := inv.FindByPath(p)
	if a2.Status != "modified" {
		t.Errorf("modified file should be flagged, got %s", a2.Status)
	}
}
