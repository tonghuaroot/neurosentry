// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/mcp"
	"github.com/neurosentry/neurosentry/pkg/platform"
)

// fakeIdP is a minimal OIDC IdP for the SSO endpoint test: discovery + JWKS +
// a token signer, all backed by one RSA key.
type fakeIdP struct {
	key *rsa.PrivateKey
	kid string
	srv *httptest.Server
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, kid: "kid-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL, "jwks_uri": f.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := f.key.Public().(*rsa.PublicKey)
		enc := base64.RawURLEncoding
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": f.kid,
			"n": enc.EncodeToString(pub.N.Bytes()),
			"e": enc.EncodeToString(bigBytes(pub.E)),
		}}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func bigBytes(e int) []byte {
	b := []byte{}
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}

func (f *fakeIdP) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": f.kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	digest := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	return in + "." + enc.EncodeToString(sig)
}

func ssoTestServer(t *testing.T) (*Server, *fakeIdP, *platform.MemUserStore, *platform.Tenant) {
	t.Helper()
	idp := newFakeIdP(t)

	tenants := platform.NewMemTenantStore()
	users := platform.NewMemUserStore()
	iss := platform.NewTokenIssuer([]byte("test-key"), "neurosentry", time.Hour)
	auth := platform.NewAuthenticator(iss, platform.NewLocalProvider(users))
	ten := &platform.Tenant{Slug: "acme", Name: "Acme"}
	if err := tenants.Create(ten); err != nil {
		t.Fatal(err)
	}

	provider, err := platform.NewOIDCProvider(context.Background(), platform.OIDCConfig{
		Issuer:       idp.srv.URL,
		ClientID:     "neurosentry",
		RoleMap:      map[string]platform.Role{"sec-admins": platform.RoleAdmin},
		DefaultRoles: []platform.Role{platform.RoleViewer},
	}, idp.srv.Client())
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.EnablePlatform(auth, tenants, users)
	srv.SetOIDCProvider(provider, "acme")
	return srv, idp, users, ten
}

func ssoClaims(idp *fakeIdP) map[string]any {
	return map[string]any{
		"iss": idp.srv.URL, "aud": "neurosentry", "sub": "okta-42",
		"email": "jane@acme.com", "groups": []any{"sec-admins"},
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
}

func postSSO(t *testing.T, srv *Server, idToken string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"id_token": idToken})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/auth/sso/oidc", bytes.NewReader(body)))
	return rec
}

func TestSSOLoginProvisionsAndIssues(t *testing.T) {
	srv, idp, users, ten := ssoTestServer(t)

	rec := postSSO(t, srv, idp.token(t, ssoClaims(idp)))
	if rec.Code != http.StatusOK {
		t.Fatalf("SSO login failed: %d (%s)", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Token == "" {
		t.Fatal("expected a session token")
	}
	// User JIT-provisioned with the admin role mapped from the group.
	u, err := users.GetByEmail(ten.ID, "jane@acme.com")
	if err != nil {
		t.Fatalf("user should be provisioned: %v", err)
	}
	if !hasPlatformRole(u.Roles, platform.RoleAdmin) {
		t.Errorf("expected admin role from group mapping, got %v", u.Roles)
	}
}

func TestSSOLoginRejectsBadToken(t *testing.T) {
	srv, _, _, _ := ssoTestServer(t)
	rec := postSSO(t, srv, "not.a.token")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token should be 401, got %d", rec.Code)
	}
}

func TestSSOLoginDisabledWhenUnconfigured(t *testing.T) {
	srv, _, _, _ := platformTestServer(t) // no SetOIDCProvider
	rec := postSSO(t, srv, "x.y.z")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("SSO not configured should be 503, got %d", rec.Code)
	}
}

func hasPlatformRole(roles []platform.Role, want platform.Role) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func TestSAMLACSDisabledWhenUnconfigured(t *testing.T) {
	srv, _, _, _ := platformTestServer(t) // no SetSAMLProvider
	body := bytes.NewBufferString("SAMLResponse=abc")
	req := httptest.NewRequest("POST", "/api/auth/sso/saml/acs", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unconfigured SAML ACS should be 503, got %d", rec.Code)
	}
}
