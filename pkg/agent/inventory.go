// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ModelAsset is a discovered model file with integrity metadata. A security
// tool protecting model weights must know what it is protecting — this is the
// AI asset inventory.
type ModelAsset struct {
	Path      string    `json:"path"`
	Name      string    `json:"name"`
	Extension string    `json:"extension"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	SHA256    string    `json:"sha256,omitempty"`
	Framework string    `json:"framework"`
	Status    string    `json:"status"` // indexed | modified | unreadable
	Safety    string    `json:"safety"` // safe | caution | unsafe (deserialization risk)
}

// InventorySummary aggregates the inventory for the dashboard.
type InventorySummary struct {
	Total       int            `json:"total"`
	TotalSize   int64          `json:"total_size"`
	ByFramework map[string]int `json:"by_framework"`
	Modified    int            `json:"modified"`
	Unreadable  int            `json:"unreadable"`
	Unsafe      int            `json:"unsafe"` // pickle-backed formats (code-execution risk)
	ScannedAt   time.Time      `json:"scanned_at"`
}

// Inventory tracks discovered model assets. Safe for concurrent use.
type Inventory struct {
	mu       sync.RWMutex
	assets   map[string]*ModelAsset // by path
	scanTime time.Time
	paths    []string // scan scope (editable at runtime)
	exts     []string
}

// SetScope sets the scan scope (paths + extensions). Called once from config.
func (inv *Inventory) SetScope(paths, exts []string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.paths = append([]string(nil), paths...)
	inv.exts = append([]string(nil), exts...)
}

// Scope returns a copy of the current scan scope.
func (inv *Inventory) Scope() (paths, exts []string) {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	return append([]string(nil), inv.paths...), append([]string(nil), inv.exts...)
}

// AddPath adds a scan path (idempotent).
func (inv *Inventory) AddPath(p string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for _, x := range inv.paths {
		if x == p {
			return
		}
	}
	inv.paths = append(inv.paths, p)
}

// RemovePath drops a scan path.
func (inv *Inventory) RemovePath(p string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := inv.paths[:0]
	for _, x := range inv.paths {
		if x != p {
			out = append(out, x)
		}
	}
	inv.paths = out
}

// Rescan scans the current scope immediately.
func (inv *Inventory) Rescan() error {
	paths, exts := inv.Scope()
	return inv.Scan(paths, exts)
}

// NewInventory returns an empty inventory.
func NewInventory() *Inventory {
	return &Inventory{assets: make(map[string]*ModelAsset)}
}

var frameworkByExt = map[string]string{
	".safetensors": "safetensors", ".gguf": "gguf",
	".pth": "pytorch", ".pt": "pytorch", ".bin": "pytorch", ".ckpt": "pytorch",
	".onnx": "onnx", ".h5": "tensorflow", ".pb": "tensorflow", ".pkl": "pickle",
}

func frameworkForExt(ext string) (string, bool) {
	fw, ok := frameworkByExt[strings.ToLower(ext)]
	return fw, ok
}

// unsafeFormats can execute arbitrary code on load (pickle-backed serialization).
var unsafeFormats = map[string]bool{".pt": true, ".pth": true, ".bin": true, ".ckpt": true, ".pkl": true}

// cautionFormats are not safe-by-design (safetensors/gguf/onnx) but are not the
// classic pickle-RCE vector either.
var cautionFormats = map[string]bool{".h5": true, ".pb": true}

// formatSafety classifies a model file by deserialization risk: "unsafe" =
// pickle-backed (code execution on load), "caution" = legacy binary format,
// "safe" = safe-by-design (safetensors/gguf/onnx).
func formatSafety(ext string) string {
	e := strings.ToLower(ext)
	switch {
	case unsafeFormats[e]:
		return "unsafe"
	case cautionFormats[e]:
		return "caution"
	default:
		return "safe"
	}
}

// Scan walks the given paths, records model files matching the extensions, and
// hashes their contents (best-effort — a file the kernel LSM blocks for this
// process is recorded as "unreadable" rather than failing the scan). Files
// whose hash changed since the last scan are marked "modified".
func (inv *Inventory) Scan(paths, extensions []string) error {
	extSet := make(map[string]bool)
	for _, e := range extensions {
		extSet[strings.ToLower(e)] = true
	}

	found := make(map[string]*ModelAsset)
	for _, root := range paths {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if len(extSet) > 0 && !extSet[ext] {
				return nil
			}
			if _, known := frameworkForExt(ext); !known && len(extSet) == 0 {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			fw, _ := frameworkForExt(ext)
			a := &ModelAsset{
				Path: p, Name: filepath.Base(p), Extension: ext,
				Size: info.Size(), ModTime: info.ModTime(), Framework: fw, Status: "indexed",
				Safety: formatSafety(ext),
			}
			if sum, herr := hashFile(p); herr == nil {
				a.SHA256 = sum
			} else {
				a.Status = "unreadable"
			}
			found[p] = a
			return nil
		})
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()
	for path, a := range found {
		if prev, ok := inv.assets[path]; ok && prev.SHA256 != "" && a.SHA256 != "" && prev.SHA256 != a.SHA256 {
			a.Status = "modified"
		}
	}
	inv.assets = found
	inv.scanTime = time.Now()
	return nil
}

// Assets returns a copy of the current inventory.
func (inv *Inventory) Assets() []ModelAsset {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := make([]ModelAsset, 0, len(inv.assets))
	for _, a := range inv.assets {
		out = append(out, *a)
	}
	return out
}

// FindByPath returns the asset at path, if indexed.
func (inv *Inventory) FindByPath(path string) (ModelAsset, bool) {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	if a, ok := inv.assets[path]; ok {
		return *a, true
	}
	return ModelAsset{}, false
}

// Summary aggregates the inventory for the dashboard.
func (inv *Inventory) Summary() InventorySummary {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	s := InventorySummary{ByFramework: map[string]int{}, ScannedAt: inv.scanTime}
	for _, a := range inv.assets {
		s.Total++
		s.TotalSize += a.Size
		s.ByFramework[a.Framework]++
		if a.Status == "modified" {
			s.Modified++
		}
		if a.Status == "unreadable" {
			s.Unreadable++
		}
		if a.Safety == "unsafe" {
			s.Unsafe++
		}
	}
	return s
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // scanning operator-configured model paths
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
