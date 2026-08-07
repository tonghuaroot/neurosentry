// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package platform provides the multi-tenant control-plane primitives for
// NeuroSentry: tenants, identities, role-based access control, and token
// issuance. Storage and identity backends are interface-driven so the
// in-memory implementations shipped here can be swapped for Postgres, OIDC,
// LDAP, or SAML without touching callers.
package platform

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TenantStatus is the lifecycle state of a tenant.
type TenantStatus string

const (
	TenantActive    TenantStatus = "active"
	TenantSuspended TenantStatus = "suspended"
)

// TenantPlan is a coarse billing/entitlement tier. Entitlements are enforced
// elsewhere; the plan is carried on the tenant so quota logic can consult it.
type TenantPlan string

const (
	PlanFree       TenantPlan = "free"
	PlanPro        TenantPlan = "pro"
	PlanEnterprise TenantPlan = "enterprise"
)

// Tenant is an isolation boundary. Every user, policy, event, and audit entry
// belongs to exactly one tenant.
type Tenant struct {
	ID        string       `json:"id"`
	Slug      string       `json:"slug"`
	Name      string       `json:"name"`
	Plan      TenantPlan   `json:"plan"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
}

// TenantStore persists tenants. The in-memory MemTenantStore satisfies it;
// a SQL-backed store can be dropped in without changing callers.
type TenantStore interface {
	Create(t *Tenant) error
	Get(id string) (*Tenant, error)
	GetBySlug(slug string) (*Tenant, error)
	List() ([]*Tenant, error)
	Update(t *Tenant) error
	Delete(id string) error
}

// ErrNotFound is returned by stores when a lookup misses.
var ErrNotFound = fmt.Errorf("not found")

// ErrConflict is returned when a unique constraint (id/slug) is violated.
var ErrConflict = fmt.Errorf("already exists")

// MemTenantStore is a concurrency-safe in-memory TenantStore. Intended for
// single-node deployments, tests, and the default embedded control plane.
type MemTenantStore struct {
	mu     sync.RWMutex
	byID   map[string]*Tenant
	bySlug map[string]*Tenant
}

// NewMemTenantStore returns an empty in-memory tenant store.
func NewMemTenantStore() *MemTenantStore {
	return &MemTenantStore{
		byID:   make(map[string]*Tenant),
		bySlug: make(map[string]*Tenant),
	}
}

func (s *MemTenantStore) Create(t *Tenant) error {
	if t.Slug == "" || t.Name == "" {
		return fmt.Errorf("tenant slug and name are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	slug := normalizeSlug(t.Slug)
	if _, exists := s.bySlug[slug]; exists {
		return fmt.Errorf("tenant slug %q: %w", slug, ErrConflict)
	}
	if t.ID == "" {
		t.ID = newID("ten")
	}
	if _, exists := s.byID[t.ID]; exists {
		return fmt.Errorf("tenant id %q: %w", t.ID, ErrConflict)
	}
	t.Slug = slug
	if t.Status == "" {
		t.Status = TenantActive
	}
	if t.Plan == "" {
		t.Plan = PlanFree
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	cp := *t
	s.byID[t.ID] = &cp
	s.bySlug[slug] = &cp
	return nil
}

func (s *MemTenantStore) Get(id string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("tenant %q: %w", id, ErrNotFound)
	}
	cp := *t
	return &cp, nil
}

func (s *MemTenantStore) GetBySlug(slug string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.bySlug[normalizeSlug(slug)]
	if !ok {
		return nil, fmt.Errorf("tenant slug %q: %w", slug, ErrNotFound)
	}
	cp := *t
	return &cp, nil
}

func (s *MemTenantStore) List() ([]*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Tenant, 0, len(s.byID))
	for _, t := range s.byID {
		cp := *t
		out = append(out, &cp)
	}
	return out, nil
}

func (s *MemTenantStore) Update(t *Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.byID[t.ID]
	if !ok {
		return fmt.Errorf("tenant %q: %w", t.ID, ErrNotFound)
	}
	// Slug is immutable to keep the bySlug index consistent.
	t.Slug = existing.Slug
	t.CreatedAt = existing.CreatedAt
	cp := *t
	s.byID[t.ID] = &cp
	s.bySlug[t.Slug] = &cp
	return nil
}

func (s *MemTenantStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("tenant %q: %w", id, ErrNotFound)
	}
	delete(s.byID, id)
	delete(s.bySlug, t.Slug)
	return nil
}

// normalizeSlug lowercases and trims a slug so lookups are stable.
func normalizeSlug(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// newID returns a random, prefixed, URL-safe identifier (e.g. "ten_a1b2...").
func newID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
