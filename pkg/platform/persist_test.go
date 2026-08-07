// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "control-plane.json")

	tenants := NewMemTenantStore()
	users := NewMemUserStore()

	ten := &Tenant{Slug: "acme", Name: "Acme", Plan: PlanPro}
	if err := tenants.Create(ten); err != nil {
		t.Fatal(err)
	}
	u := &User{TenantID: ten.ID, Email: "admin@acme", Roles: []Role{RoleAdmin}}
	if err := u.SetPassword("password123"); err != nil {
		t.Fatal(err)
	}
	rawKey, _ := u.GenerateAPIKey()
	if err := users.Create(u); err != nil {
		t.Fatal(err)
	}

	if err := SaveSnapshot(path, tenants, users); err != nil {
		t.Fatal(err)
	}

	// File must be 0600.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("snapshot should be 0600, got %v", info.Mode().Perm())
	}

	// Restore into fresh stores.
	t2 := NewMemTenantStore()
	u2 := NewMemUserStore()
	ok, err := LoadSnapshot(path, t2, u2)
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}

	// Tenant survived.
	got, err := t2.GetBySlug("acme")
	if err != nil || got.Name != "Acme" || got.Plan != PlanPro {
		t.Errorf("tenant not restored: %+v %v", got, err)
	}

	// User survived, password still verifies (hash+salt persisted).
	gotUser, err := u2.GetByEmail(ten.ID, "admin@acme")
	if err != nil {
		t.Fatal(err)
	}
	if !gotUser.CheckPassword("password123") {
		t.Error("password should still verify after restore")
	}
	if gotUser.CheckPassword("wrong") {
		t.Error("wrong password must not verify")
	}

	// API key still resolves after restore.
	resolved, err := u2.ResolveAPIKey(rawKey)
	if err != nil || resolved.ID != u.ID {
		t.Errorf("API key not restored: %v", err)
	}
}

func TestLoadMissingSnapshotIsNotError(t *testing.T) {
	ok, err := LoadSnapshot(filepath.Join(t.TempDir(), "nope.json"), NewMemTenantStore(), NewMemUserStore())
	if err != nil {
		t.Errorf("missing snapshot should not error, got %v", err)
	}
	if ok {
		t.Error("missing snapshot should return ok=false")
	}
}

func TestSnapshotDoesNotLeakPlaintextPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cp.json")
	tenants := NewMemTenantStore()
	users := NewMemUserStore()
	ten := &Tenant{Slug: "t", Name: "T"}
	_ = tenants.Create(ten)
	u := &User{TenantID: ten.ID, Email: "a@b"}
	_ = u.SetPassword("SuperSecretPlaintext")
	_ = users.Create(u)

	if err := SaveSnapshot(path, tenants, users); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if contains(data, "SuperSecretPlaintext") {
		t.Error("snapshot must never contain the plaintext password")
	}
}

func contains(haystack []byte, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexOf(string(haystack), needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
