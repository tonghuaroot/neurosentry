// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey int

const principalKey ctxKey = 0

// PrincipalFromContext returns the authenticated principal attached by
// Authn/Require middleware, or nil if the request is unauthenticated.
func PrincipalFromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey).(*Principal)
	return p
}

// WithPrincipal returns a child context carrying the principal. Exported for
// tests and for handlers that authenticate out-of-band.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// Middleware provides authentication and authorization for HTTP handlers. It
// resolves a principal from either a Bearer JWT or an X-API-Key header.
type Middleware struct {
	issuer *TokenIssuer
	users  UserStore
}

// NewMiddleware builds auth middleware. users may be nil if API-key auth is not
// used; JWT auth needs only the issuer.
func NewMiddleware(issuer *TokenIssuer, users UserStore) *Middleware {
	return &Middleware{issuer: issuer, users: users}
}

// Authn resolves a principal from the request and stores it in context if
// present. It never rejects; use Require for enforcement. This lets some routes
// (health, login) stay open while still seeing an optional principal.
func (m *Middleware) Authn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := m.resolve(r); p != nil {
			r = r.WithContext(WithPrincipal(r.Context(), p))
		}
		next.ServeHTTP(w, r)
	})
}

// Require enforces that a request carries a valid principal with the given
// permission, returning 401 when unauthenticated and 403 when authorized but
// lacking the permission.
func (m *Middleware) Require(perm Permission, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFromContext(r.Context())
		if p == nil {
			p = m.resolve(r)
		}
		if p == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !p.Can(perm) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r.WithContext(WithPrincipal(r.Context(), p)))
	}
}

// resolve extracts a principal from a Bearer token or API key, or nil.
func (m *Middleware) resolve(r *http.Request) *Principal {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if claims, err := m.issuer.Verify(token); err == nil {
			return PrincipalFromClaims(claims)
		}
	}
	if key := r.Header.Get("X-API-Key"); key != "" && m.users != nil {
		if u, err := m.users.ResolveAPIKey(key); err == nil && u.Status == UserActive {
			return principalOf(u)
		}
	}
	return nil
}

// TenantScoped enforces that the principal belongs to the tenant identified by
// the given path/header value, blocking cross-tenant access. Returns 403 on
// mismatch. This is the core multi-tenant isolation guard.
func TenantScoped(requestedTenantID string, p *Principal) bool {
	if p == nil {
		return false
	}
	if p.Can(PermManageSystem) {
		return true // system/superadmin may cross tenants
	}
	return p.TenantID == requestedTenantID
}
