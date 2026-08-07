// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aigateway

import (
	"fmt"
	"sync"
)

// KeyVault holds the upstream provider API keys the gateway forwards with, keyed
// by tenant + provider. This is the custody boundary that lets the gateway act
// as a relay: callers never see the real provider keys — they authenticate to
// NeuroSentry, which injects the right upstream key per tenant. The interface is
// the extension seam for a persistent, encrypted, or external-secrets backend.
type KeyVault interface {
	GetKey(tenantID, provider string) (string, bool)
	SetKey(tenantID, provider, key string) error
	DeleteKey(tenantID, provider string) error
	Providers(tenantID string) []string
}

// MemKeyVault is an in-memory KeyVault for single-node deployments and tests.
// Keys live only in process memory (they must be usable to forward requests);
// a persistent backend would encrypt them at rest.
type MemKeyVault struct {
	mu   sync.RWMutex
	keys map[string]string // tenant\x00provider -> key
}

// NewMemKeyVault returns an empty in-memory vault.
func NewMemKeyVault() *MemKeyVault {
	return &MemKeyVault{keys: make(map[string]string)}
}

func vaultKey(tenantID, provider string) string {
	return tenantID + "\x00" + provider
}

func (v *MemKeyVault) GetKey(tenantID, provider string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	k, ok := v.keys[vaultKey(tenantID, provider)]
	return k, ok
}

func (v *MemKeyVault) SetKey(tenantID, provider, key string) error {
	if tenantID == "" || provider == "" || key == "" {
		return fmt.Errorf("tenant, provider, and key are required")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys[vaultKey(tenantID, provider)] = key
	return nil
}

func (v *MemKeyVault) DeleteKey(tenantID, provider string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.keys, vaultKey(tenantID, provider))
	return nil
}

func (v *MemKeyVault) Providers(tenantID string) []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var out []string
	prefix := tenantID + "\x00"
	for k := range v.keys {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, k[len(prefix):])
		}
	}
	return out
}
