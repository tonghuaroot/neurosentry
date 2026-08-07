// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// OIDC single sign-on. NeuroSentry verifies an OpenID Connect ID token (RS256,
// keys from the provider's JWKS) issued by an enterprise IdP — Okta, Azure AD,
// Google, Keycloak — and maps the IdP's group claims onto NeuroSentry RBAC
// roles. This replaces password auth for enterprise tenants while the existing
// local provider stays as a break-glass fallback.
//
// Only asymmetric RS256 is accepted. The "none" algorithm and symmetric HS256
// are rejected outright to close the classic JWT algorithm-confusion attack.

// OIDCConfig describes one trusted identity provider.
type OIDCConfig struct {
	Issuer       string          `json:"issuer"`        // must equal the token "iss"
	ClientID     string          `json:"client_id"`     // must appear in the token "aud"
	GroupsClaim  string          `json:"groups_claim"`  // claim holding group membership (default "groups")
	RoleMap      map[string]Role `json:"role_map"`      // IdP group -> NeuroSentry role
	DefaultRoles []Role          `json:"default_roles"` // roles granted to any authenticated user
}

// OIDCClaims is the subset of verified ID-token claims NeuroSentry consumes.
type OIDCClaims struct {
	Subject string
	Email   string
	Groups  []string
}

// OIDCVerifier verifies ID tokens against one provider's signing keys.
type OIDCVerifier struct {
	cfg  OIDCConfig
	keys map[string]*rsa.PublicKey // kid -> public key (from JWKS)
	now  func() time.Time
}

// NewOIDCVerifier builds a verifier from a provider config and its JWKS keys
// (see ParseJWKS). Keys are typically refreshed periodically from the provider's
// jwks_uri; this type is agnostic to how they arrive.
func NewOIDCVerifier(cfg OIDCConfig, keys map[string]*rsa.PublicKey) *OIDCVerifier {
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	return &OIDCVerifier{cfg: cfg, keys: keys, now: time.Now}
}

type oidcHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Verify checks signature, issuer, audience, and time bounds of an ID token and
// returns its claims. It never trusts the token's own algorithm choice beyond
// RS256.
func (v *OIDCVerifier) Verify(idToken string) (*OIDCClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: malformed token")
	}
	headerRaw, err := b64url.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: bad header encoding: %w", err)
	}
	var hdr oidcHeader
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return nil, fmt.Errorf("oidc: bad header json: %w", err)
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("oidc: unsupported alg %q (only RS256 accepted)", hdr.Alg)
	}
	key, ok := v.keys[hdr.Kid]
	if !ok {
		return nil, fmt.Errorf("oidc: unknown signing key %q", hdr.Kid)
	}

	// Verify the RS256 signature over "header.payload".
	sig, err := b64url.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: bad signature encoding: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("oidc: signature verification failed: %w", err)
	}

	payloadRaw, err := b64url.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: bad payload encoding: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, fmt.Errorf("oidc: bad payload json: %w", err)
	}

	// Issuer must match exactly.
	if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
		return nil, fmt.Errorf("oidc: issuer mismatch")
	}
	// Audience must contain our client ID (aud may be a string or array).
	if !audienceContains(claims["aud"], v.cfg.ClientID) {
		return nil, fmt.Errorf("oidc: audience does not include client id")
	}
	// Time bounds.
	now := v.now().Unix()
	if exp, ok := numericClaim(claims["exp"]); ok && now >= exp {
		return nil, fmt.Errorf("oidc: token expired")
	}
	if nbf, ok := numericClaim(claims["nbf"]); ok && now < nbf {
		return nil, fmt.Errorf("oidc: token not yet valid")
	}

	out := &OIDCClaims{}
	out.Subject, _ = claims["sub"].(string)
	out.Email, _ = claims["email"].(string)
	out.Groups = stringSlice(claims[v.cfg.GroupsClaim])
	if out.Subject == "" {
		return nil, fmt.Errorf("oidc: token missing subject")
	}
	return out, nil
}

// MapRoles resolves IdP groups to NeuroSentry roles, always including the
// configured default roles. Returns Viewer as a safe floor if nothing maps.
func (cfg OIDCConfig) MapRoles(groups []string) []Role {
	seen := map[Role]struct{}{}
	var roles []Role
	add := func(r Role) {
		if _, dup := seen[r]; !dup {
			seen[r] = struct{}{}
			roles = append(roles, r)
		}
	}
	for _, r := range cfg.DefaultRoles {
		add(r)
	}
	for _, g := range groups {
		if r, ok := cfg.RoleMap[g]; ok {
			add(r)
		}
	}
	if len(roles) == 0 {
		add(RoleViewer)
	}
	return roles
}

var b64url = base64.RawURLEncoding

// ---- JWKS parsing ----

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// ParseJWKS parses a provider's JWKS document into a kid->RSA-public-key map.
func ParseJWKS(data []byte) (map[string]*rsa.PublicKey, error) {
	var set jwkSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	out := make(map[string]*rsa.PublicKey)
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := b64url.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwks: bad modulus for kid %q: %w", k.Kid, err)
		}
		eBytes, err := b64url.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwks: bad exponent for kid %q: %w", k.Kid, err)
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("jwks: no RSA keys found")
	}
	return out, nil
}

// ---- claim helpers ----

func audienceContains(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

func numericClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func stringSlice(v any) []string {
	switch s := v.(type) {
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case string:
		return []string{s}
	}
	return nil
}
