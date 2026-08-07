// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Claims is the JWT payload NeuroSentry issues. It is deliberately small:
// subject (user), tenant, roles, and standard time bounds. Authorization is
// recomputed from roles at verification time, so a role change takes effect on
// the next token without a revocation list.
type Claims struct {
	Subject   string   `json:"sub"`
	TenantID  string   `json:"tid"`
	Email     string   `json:"email,omitempty"`
	Roles     []string `json:"roles"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	Issuer    string   `json:"iss,omitempty"`
}

// TokenIssuer signs and verifies HS256 JWTs. The signing key never leaves the
// process. HS256 is chosen for the embedded single-node control plane; an
// RS256/asymmetric issuer can implement the same Sign/Verify surface for
// multi-node deployments.
type TokenIssuer struct {
	key    []byte
	issuer string
	ttl    time.Duration
}

// NewTokenIssuer returns an issuer. ttl bounds token lifetime; if <= 0 it
// defaults to 12h.
func NewTokenIssuer(signingKey []byte, issuer string, ttl time.Duration) *TokenIssuer {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &TokenIssuer{key: signingKey, issuer: issuer, ttl: ttl}
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Issue mints a signed token for a principal.
func (ti *TokenIssuer) Issue(p *Principal) (string, error) {
	now := time.Now()
	roles := make([]string, len(p.Roles))
	for i, r := range p.Roles {
		roles[i] = string(r)
	}
	claims := Claims{
		Subject:   p.UserID,
		TenantID:  p.TenantID,
		Email:     p.Email,
		Roles:     roles,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ti.ttl).Unix(),
		Issuer:    ti.issuer,
	}
	return ti.sign(claims)
}

func (ti *TokenIssuer) sign(claims Claims) (string, error) {
	hb, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(cb)
	sig := ti.mac(signingInput)
	return signingInput + "." + b64(sig), nil
}

// Verify checks the signature and expiry and returns the claims. A tampered or
// expired token returns an error.
func (ti *TokenIssuer) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	signingInput := parts[0] + "." + parts[1]
	expectedSig := ti.mac(signingInput)
	gotSig, err := unb64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("bad signature encoding: %w", err)
	}
	if subtle.ConstantTimeCompare(expectedSig, gotSig) != 1 {
		return nil, fmt.Errorf("signature mismatch")
	}

	var hdr jwtHeader
	hb, err := unb64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("bad header encoding: %w", err)
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("bad header: %w", err)
	}
	if hdr.Alg != "HS256" {
		return nil, fmt.Errorf("unexpected alg %q", hdr.Alg)
	}

	cb, err := unb64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad claims encoding: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, fmt.Errorf("bad claims: %w", err)
	}
	if claims.ExpiresAt != 0 && time.Now().Unix() >= claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}
	return &claims, nil
}

// PrincipalFromClaims reconstructs a Principal (with precomputed permissions)
// from verified claims.
func PrincipalFromClaims(c *Claims) *Principal {
	roles := make([]Role, len(c.Roles))
	for i, r := range c.Roles {
		roles[i] = Role(r)
	}
	return NewPrincipal(c.Subject, c.TenantID, c.Email, roles)
}

func (ti *TokenIssuer) mac(input string) []byte {
	h := hmac.New(sha256.New, ti.key)
	h.Write([]byte(input))
	return h.Sum(nil)
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func unb64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
