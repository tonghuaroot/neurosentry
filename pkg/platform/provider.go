// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"fmt"
)

// Credentials carries the inputs an IdentityProvider may consume. A given
// provider uses the subset it understands (LocalProvider uses Email+Password
// or APIKey; an OIDC provider would use the IDToken; LDAP uses Username+Password).
type Credentials struct {
	TenantID string
	Email    string
	Username string
	Password string
	APIKey   string
	IDToken  string // OIDC / SAML assertion, for future providers
}

// IdentityProvider authenticates credentials into a Principal. This is the
// extension seam: shipping LocalProvider today, with OIDC/LDAP/SAML providers
// implementing the same contract and registering into the same Authenticator.
type IdentityProvider interface {
	// Name is a stable identifier ("local", "oidc", "ldap", ...).
	Name() string
	// Authenticate resolves credentials to a Principal or returns an error.
	Authenticate(ctx context.Context, creds Credentials) (*Principal, error)
}

// LocalProvider authenticates against the built-in UserStore using passwords
// and API keys.
type LocalProvider struct {
	users UserStore
}

// NewLocalProvider builds a password/API-key provider over a UserStore.
func NewLocalProvider(users UserStore) *LocalProvider {
	return &LocalProvider{users: users}
}

func (p *LocalProvider) Name() string { return "local" }

// Authenticate supports two flows: API key (checked first, tenant-agnostic) and
// email+password within a tenant. Disabled users are rejected.
func (p *LocalProvider) Authenticate(_ context.Context, creds Credentials) (*Principal, error) {
	if creds.APIKey != "" {
		u, err := p.users.ResolveAPIKey(creds.APIKey)
		if err != nil {
			return nil, fmt.Errorf("invalid api key")
		}
		if u.Status != UserActive {
			return nil, fmt.Errorf("user disabled")
		}
		return principalOf(u), nil
	}

	if creds.Email == "" || creds.Password == "" {
		return nil, fmt.Errorf("email and password required")
	}
	u, err := p.users.GetByEmail(creds.TenantID, creds.Email)
	if err != nil {
		// Uniform error to avoid user enumeration.
		return nil, fmt.Errorf("invalid credentials")
	}
	if u.Status != UserActive {
		return nil, fmt.Errorf("user disabled")
	}
	if !u.CheckPassword(creds.Password) {
		return nil, fmt.Errorf("invalid credentials")
	}
	return principalOf(u), nil
}

func principalOf(u *User) *Principal {
	return NewPrincipal(u.ID, u.TenantID, u.Email, u.Roles)
}

// Authenticator dispatches to registered providers and mints tokens. It is the
// single entry point the web layer calls for login.
type Authenticator struct {
	providers map[string]IdentityProvider
	issuer    *TokenIssuer
}

// NewAuthenticator wires an issuer and an initial default (local) provider.
func NewAuthenticator(issuer *TokenIssuer, defaultProvider IdentityProvider) *Authenticator {
	a := &Authenticator{
		providers: make(map[string]IdentityProvider),
		issuer:    issuer,
	}
	if defaultProvider != nil {
		a.providers[defaultProvider.Name()] = defaultProvider
	}
	return a
}

// Register adds (or replaces) a provider by name, enabling OIDC/LDAP/SAML to be
// plugged in at startup without changing callers.
func (a *Authenticator) Register(p IdentityProvider) {
	a.providers[p.Name()] = p
}

// Login authenticates via the named provider (empty => "local") and returns a
// signed token plus the resolved principal.
func (a *Authenticator) Login(ctx context.Context, providerName string, creds Credentials) (string, *Principal, error) {
	if providerName == "" {
		providerName = "local"
	}
	p, ok := a.providers[providerName]
	if !ok {
		return "", nil, fmt.Errorf("unknown auth provider %q", providerName)
	}
	principal, err := p.Authenticate(ctx, creds)
	if err != nil {
		return "", nil, err
	}
	token, err := a.issuer.Issue(principal)
	if err != nil {
		return "", nil, err
	}
	return token, principal, nil
}

// Issuer exposes the token issuer for middleware verification.
func (a *Authenticator) Issuer() *TokenIssuer { return a.issuer }
