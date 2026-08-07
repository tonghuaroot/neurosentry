// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Snapshot is the on-disk form of the control-plane state. Credential material
// (already hashed) is included so operators do not lose logins across restarts.
// The file is written 0600 and should live on an encrypted volume in
// production; a full deployment would back the stores with an encrypted
// database instead.
type Snapshot struct {
	Version int            `json:"version"`
	SavedAt time.Time      `json:"saved_at"`
	Tenants []*Tenant      `json:"tenants"`
	Users   []userSnapshot `json:"users"`
}

type userSnapshot struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Email        string     `json:"email"`
	Username     string     `json:"username,omitempty"`
	Roles        []Role     `json:"roles"`
	Status       UserStatus `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	PasswordHash []byte     `json:"password_hash,omitempty"`
	PasswordSalt []byte     `json:"password_salt,omitempty"`
	APIKeyHashes []string   `json:"api_key_hashes,omitempty"`
}

// snapshotUsers exports every user (with credential material) for persistence.
func (s *MemUserStore) snapshotUsers() []userSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]userSnapshot, 0, len(s.byID))
	for _, u := range s.byID {
		keys := make([]string, 0, len(u.apiKeyHashes))
		for h := range u.apiKeyHashes {
			keys = append(keys, h)
		}
		out = append(out, userSnapshot{
			ID: u.ID, TenantID: u.TenantID, Email: u.Email, Username: u.Username,
			Roles: u.Roles, Status: u.Status, CreatedAt: u.CreatedAt,
			PasswordHash: u.passwordHash, PasswordSalt: u.passwordSalt, APIKeyHashes: keys,
		})
	}
	return out
}

// restoreUsers repopulates the store from snapshots, rebuilding all indexes.
func (s *MemUserStore) restoreUsers(snaps []userSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]*User)
	s.byEmail = make(map[string]*User)
	s.byAPIKey = make(map[string]string)
	for _, sn := range snaps {
		u := &User{
			ID: sn.ID, TenantID: sn.TenantID, Email: sn.Email, Username: sn.Username,
			Roles: sn.Roles, Status: sn.Status, CreatedAt: sn.CreatedAt,
			passwordHash: sn.PasswordHash, passwordSalt: sn.PasswordSalt,
			apiKeyHashes: make(map[string]struct{}, len(sn.APIKeyHashes)),
		}
		for _, h := range sn.APIKeyHashes {
			u.apiKeyHashes[h] = struct{}{}
			s.byAPIKey[h] = u.ID
		}
		s.byID[u.ID] = u
		s.byEmail[emailKey(u.TenantID, u.Email)] = u
	}
}

// snapshotTenants exports all tenants.
func (s *MemTenantStore) snapshotTenants() []*Tenant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Tenant, 0, len(s.byID))
	for _, t := range s.byID {
		cp := *t
		out = append(out, &cp)
	}
	return out
}

// restoreTenants repopulates the store.
func (s *MemTenantStore) restoreTenants(tenants []*Tenant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]*Tenant)
	s.bySlug = make(map[string]*Tenant)
	for _, t := range tenants {
		cp := *t
		s.byID[t.ID] = &cp
		s.bySlug[t.Slug] = &cp
	}
}

// SaveSnapshot atomically writes the control-plane state to path (0600).
func SaveSnapshot(path string, tenants *MemTenantStore, users *MemUserStore) error {
	snap := Snapshot{
		Version: 1,
		SavedAt: time.Now(),
		Tenants: tenants.snapshotTenants(),
		Users:   users.snapshotUsers(),
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create snapshot dir: %w", err)
		}
	}
	// Write to a temp file then rename for atomicity.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	return os.Rename(tmp, path)
}

// LoadSnapshot restores control-plane state from path into the given stores. A
// missing file is not an error (fresh install); it returns (false, nil).
func LoadSnapshot(path string, tenants *MemTenantStore, users *MemUserStore) (bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read snapshot: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return false, fmt.Errorf("parse snapshot: %w", err)
	}
	tenants.restoreTenants(snap.Tenants)
	users.restoreUsers(snap.Users)
	return true, nil
}
