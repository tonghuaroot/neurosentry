// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// idpFixture is a self-contained fake IdP: an RSA key, its JWKS, and a token
// signer — so the OIDC verifier can be tested fully offline.
type idpFixture struct {
	key *rsa.PrivateKey
	kid string
}

func newIDP(t *testing.T) *idpFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return &idpFixture{key: key, kid: "test-kid-1"}
}

func (f *idpFixture) jwks(t *testing.T) map[string]*rsa.PublicKey {
	t.Helper()
	pub := f.key.Public().(*rsa.PublicKey)
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	doc, _ := json.Marshal(jwkSet{Keys: []jwk{{
		Kty: "RSA", Kid: f.kid,
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(eBytes),
	}}})
	keys, err := ParseJWKS(doc)
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	return keys
}

func (f *idpFixture) sign(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": f.kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + enc.EncodeToString(sig)
}

func baseClaims() map[string]any {
	return map[string]any{
		"iss":    "https://idp.example.com",
		"aud":    "neurosentry",
		"sub":    "user-123",
		"email":  "jane@example.com",
		"groups": []any{"sec-admins", "everyone"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
		"iat":    float64(time.Now().Add(-time.Minute).Unix()),
	}
}

func testVerifier(f *idpFixture, keys map[string]*rsa.PublicKey) *OIDCVerifier {
	return NewOIDCVerifier(OIDCConfig{
		Issuer:       "https://idp.example.com",
		ClientID:     "neurosentry",
		RoleMap:      map[string]Role{"sec-admins": RoleAdmin},
		DefaultRoles: []Role{RoleViewer},
	}, keys)
}

func TestOIDCVerifyValidToken(t *testing.T) {
	f := newIDP(t)
	v := testVerifier(f, f.jwks(t))
	claims, err := v.Verify(f.sign(t, "RS256", baseClaims()))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.Subject != "user-123" || claims.Email != "jane@example.com" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	roles := v.cfg.MapRoles(claims.Groups)
	if !hasRole(roles, RoleAdmin) || !hasRole(roles, RoleViewer) {
		t.Errorf("group mapping wrong: %v", roles)
	}
}

func TestOIDCRejectsAlgConfusion(t *testing.T) {
	f := newIDP(t)
	v := testVerifier(f, f.jwks(t))
	// "none" and HS256 must be rejected outright, regardless of signature.
	for _, alg := range []string{"none", "HS256"} {
		if _, err := v.Verify(f.sign(t, alg, baseClaims())); err == nil {
			t.Errorf("alg %q must be rejected", alg)
		}
	}
}

func TestOIDCRejectsTamperedSignature(t *testing.T) {
	f := newIDP(t)
	v := testVerifier(f, f.jwks(t))
	tok := f.sign(t, "RS256", baseClaims())
	if _, err := v.Verify(tok[:len(tok)-2] + "xy"); err == nil {
		t.Error("tampered signature must be rejected")
	}

	// A token signed by a DIFFERENT key must fail against our JWKS.
	other := newIDP(t)
	other.kid = f.kid // same kid, different key
	if _, err := v.Verify(other.sign(t, "RS256", baseClaims())); err == nil {
		t.Error("token from unknown key must be rejected")
	}
}

func TestOIDCRejectsBadIssuerAudienceExpiry(t *testing.T) {
	f := newIDP(t)
	v := testVerifier(f, f.jwks(t))

	badIss := baseClaims()
	badIss["iss"] = "https://evil.example.com"
	if _, err := v.Verify(f.sign(t, "RS256", badIss)); err == nil {
		t.Error("wrong issuer must be rejected")
	}

	badAud := baseClaims()
	badAud["aud"] = "some-other-app"
	if _, err := v.Verify(f.sign(t, "RS256", badAud)); err == nil {
		t.Error("wrong audience must be rejected")
	}

	expired := baseClaims()
	expired["exp"] = float64(time.Now().Add(-time.Hour).Unix())
	if _, err := v.Verify(f.sign(t, "RS256", expired)); err == nil {
		t.Error("expired token must be rejected")
	}
}

func hasRole(roles []Role, want Role) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}
