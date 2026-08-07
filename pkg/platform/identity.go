// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// pbkdf2Iterations is the work factor for password hashing. Tuned to be costly
// enough to blunt offline cracking while staying sub-millisecond per verify.
const pbkdf2Iterations = 210000
const pbkdf2KeyLen = 32
const saltLen = 16

// UserStatus is the lifecycle state of a user.
type UserStatus string

const (
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

// User is a tenant-scoped identity. Passwords are never stored in plaintext;
// only the salted PBKDF2-HMAC-SHA256 digest and its salt are kept.
type User struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Email        string     `json:"email"`
	Username     string     `json:"username"`
	Roles        []Role     `json:"roles"`
	Status       UserStatus `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	passwordHash []byte
	passwordSalt []byte
	apiKeyHashes map[string]struct{} // set of hashed API keys
}

// SetPassword hashes and stores a new password for the user.
func (u *User) SetPassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	u.passwordSalt = salt
	u.passwordHash = pbkdf2Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	return nil
}

// CheckPassword reports whether password matches the stored digest. Comparison
// is constant-time.
func (u *User) CheckPassword(password string) bool {
	if len(u.passwordHash) == 0 {
		return false
	}
	candidate := pbkdf2Key([]byte(password), u.passwordSalt, pbkdf2Iterations, pbkdf2KeyLen)
	return subtle.ConstantTimeCompare(candidate, u.passwordHash) == 1
}

// UserStore persists users. MemUserStore satisfies it; a SQL store can replace
// it transparently.
type UserStore interface {
	Create(u *User) error
	Get(id string) (*User, error)
	GetByEmail(tenantID, email string) (*User, error)
	ListByTenant(tenantID string) ([]*User, error)
	Update(u *User) error
	Delete(id string) error
	// ResolveAPIKey returns the user owning the given raw API key, or ErrNotFound.
	ResolveAPIKey(rawKey string) (*User, error)
}

// MemUserStore is a concurrency-safe in-memory UserStore.
type MemUserStore struct {
	mu       sync.RWMutex
	byID     map[string]*User
	byEmail  map[string]*User  // key: tenantID + "\x00" + lower(email)
	byAPIKey map[string]string // hashed key -> user id
}

// NewMemUserStore returns an empty in-memory user store.
func NewMemUserStore() *MemUserStore {
	return &MemUserStore{
		byID:     make(map[string]*User),
		byEmail:  make(map[string]*User),
		byAPIKey: make(map[string]string),
	}
}

func emailKey(tenantID, email string) string {
	return tenantID + "\x00" + strings.ToLower(strings.TrimSpace(email))
}

func (s *MemUserStore) Create(u *User) error {
	if u.TenantID == "" || u.Email == "" {
		return fmt.Errorf("user tenant_id and email are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ek := emailKey(u.TenantID, u.Email)
	if _, exists := s.byEmail[ek]; exists {
		return fmt.Errorf("email %q in tenant: %w", u.Email, ErrConflict)
	}
	if u.ID == "" {
		u.ID = newID("usr")
	}
	if _, exists := s.byID[u.ID]; exists {
		return fmt.Errorf("user id %q: %w", u.ID, ErrConflict)
	}
	if u.Status == "" {
		u.Status = UserActive
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	if u.apiKeyHashes == nil {
		u.apiKeyHashes = make(map[string]struct{})
	}
	s.byID[u.ID] = u
	s.byEmail[ek] = u
	for h := range u.apiKeyHashes {
		s.byAPIKey[h] = u.ID
	}
	return nil
}

func (s *MemUserStore) Get(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("user %q: %w", id, ErrNotFound)
	}
	return u, nil
}

func (s *MemUserStore) GetByEmail(tenantID, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byEmail[emailKey(tenantID, email)]
	if !ok {
		return nil, fmt.Errorf("user %q: %w", email, ErrNotFound)
	}
	return u, nil
}

func (s *MemUserStore) ListByTenant(tenantID string) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*User
	for _, u := range s.byID {
		if u.TenantID == tenantID {
			out = append(out, u)
		}
	}
	return out, nil
}

func (s *MemUserStore) Update(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[u.ID]; !ok {
		return fmt.Errorf("user %q: %w", u.ID, ErrNotFound)
	}
	s.byID[u.ID] = u
	s.byEmail[emailKey(u.TenantID, u.Email)] = u
	// Reindex API keys owned by this user.
	for h, uid := range s.byAPIKey {
		if uid == u.ID {
			delete(s.byAPIKey, h)
		}
	}
	for h := range u.apiKeyHashes {
		s.byAPIKey[h] = u.ID
	}
	return nil
}

func (s *MemUserStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("user %q: %w", id, ErrNotFound)
	}
	delete(s.byID, id)
	delete(s.byEmail, emailKey(u.TenantID, u.Email))
	for h, uid := range s.byAPIKey {
		if uid == id {
			delete(s.byAPIKey, h)
		}
	}
	return nil
}

func (s *MemUserStore) ResolveAPIKey(rawKey string) (*User, error) {
	h := hashAPIKey(rawKey)
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.byAPIKey[h]
	if !ok {
		return nil, fmt.Errorf("api key: %w", ErrNotFound)
	}
	return s.byID[uid], nil
}

// GenerateAPIKey creates a new API key for the user, stores only its hash, and
// returns the raw key exactly once (it cannot be recovered later). The caller
// must persist the user via UserStore.Update to index the new key.
func (u *User) GenerateAPIKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := "nsk_" + hex.EncodeToString(b)
	if u.apiKeyHashes == nil {
		u.apiKeyHashes = make(map[string]struct{})
	}
	u.apiKeyHashes[hashAPIKey(raw)] = struct{}{}
	return raw, nil
}

// RevokeAPIKey removes an API key (by its raw value) from the user.
func (u *User) RevokeAPIKey(rawKey string) {
	delete(u.apiKeyHashes, hashAPIKey(rawKey))
}

// hashAPIKey returns a hex SHA-256 of the raw key. Keys are stored hashed so a
// store compromise does not leak usable credentials.
func hashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// pbkdf2Key derives a key from a password using PBKDF2-HMAC-SHA256. Implemented
// against stdlib to avoid an external crypto dependency.
func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var dk []byte
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf)
		T := prf.Sum(nil)
		U := make([]byte, len(T))
		copy(U, T)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(U[:0])
			for i := range T {
				T[i] ^= U[i]
			}
		}
		dk = append(dk, T...)
	}
	return dk[:keyLen]
}
