// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func mustRotate(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	return k
}

// fakeIdPServer serves an OIDC discovery doc + JWKS for the fixture key.
func fakeIdPServer(t *testing.T, f *idpFixture, issuer func() string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(discoveryDoc{Issuer: issuer(), JWKSURI: issuer() + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := f.key.Public().(*rsa.PublicKey)
		json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{{
			Kty: "RSA", Kid: f.kid,
			N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	return httptest.NewServer(mux)
}

func TestOIDCProviderDiscoveryAndVerify(t *testing.T) {
	f := newIDP(t)
	var srv *httptest.Server
	srv = fakeIdPServer(t, f, func() string { return srv.URL })
	defer srv.Close()

	p, err := NewOIDCProvider(context.Background(), OIDCConfig{
		Issuer:       srv.URL,
		ClientID:     "neurosentry",
		RoleMap:      map[string]Role{"sec-admins": RoleAdmin},
		DefaultRoles: []Role{RoleViewer},
	}, srv.Client())
	if err != nil {
		t.Fatalf("provider setup failed: %v", err)
	}

	claims := baseClaims()
	claims["iss"] = srv.URL
	tok := f.sign(t, "RS256", claims)

	got, err := p.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify via provider failed: %v", err)
	}
	if got.Subject != "user-123" {
		t.Errorf("unexpected subject %q", got.Subject)
	}
	if roles := p.MapRoles(got.Groups); !hasRole(roles, RoleAdmin) {
		t.Errorf("expected admin role from group mapping, got %v", roles)
	}
}

func TestOIDCProviderRefetchesOnKeyRotation(t *testing.T) {
	f := newIDP(t)
	var srv *httptest.Server
	srv = fakeIdPServer(t, f, func() string { return srv.URL })
	defer srv.Close()

	p, err := NewOIDCProvider(context.Background(), OIDCConfig{
		Issuer: srv.URL, ClientID: "neurosentry", DefaultRoles: []Role{RoleViewer},
	}, srv.Client())
	if err != nil {
		t.Fatalf("provider setup failed: %v", err)
	}

	// Rotate the IdP's key to a new kid, and make the cache look stale so a
	// refetch is allowed.
	f.key = mustRotate(t)
	f.kid = "test-kid-2"
	p.mu.Lock()
	p.fetchedAt = p.fetchedAt.Add(-time.Hour)
	p.mu.Unlock()

	claims := baseClaims()
	claims["iss"] = srv.URL
	tok := f.sign(t, "RS256", claims)

	if _, err := p.Verify(context.Background(), tok); err != nil {
		t.Fatalf("provider should refetch rotated keys and verify: %v", err)
	}
}
