// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- Tenant store ---

func TestTenantCreateAndGet(t *testing.T) {
	s := NewMemTenantStore()
	ten := &Tenant{Slug: "Acme", Name: "Acme Corp", Plan: PlanPro}
	if err := s.Create(ten); err != nil {
		t.Fatal(err)
	}
	if ten.ID == "" {
		t.Error("expected generated ID")
	}
	if ten.Slug != "acme" {
		t.Errorf("slug should be normalized, got %q", ten.Slug)
	}
	if ten.Status != TenantActive {
		t.Errorf("expected active status, got %q", ten.Status)
	}

	got, err := s.GetBySlug("ACME")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != ten.ID {
		t.Error("GetBySlug returned wrong tenant")
	}
}

func TestTenantSlugConflict(t *testing.T) {
	s := NewMemTenantStore()
	_ = s.Create(&Tenant{Slug: "dup", Name: "One"})
	err := s.Create(&Tenant{Slug: "dup", Name: "Two"})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("expected ErrConflict, got %v", err)
	}
}

func TestTenantNotFound(t *testing.T) {
	s := NewMemTenantStore()
	_, err := s.Get("nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestTenantDelete(t *testing.T) {
	s := NewMemTenantStore()
	ten := &Tenant{Slug: "temp", Name: "Temp"}
	_ = s.Create(ten)
	if err := s.Delete(ten.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetBySlug("temp"); !errors.Is(err, ErrNotFound) {
		t.Error("tenant should be gone from slug index after delete")
	}
}

// --- RBAC ---

func TestRolePermissions(t *testing.T) {
	owner := NewPrincipal("u1", "t1", "o@x.com", []Role{RoleOwner})
	if !owner.Can(PermManageTenant) || !owner.Can(PermManageUsers) {
		t.Error("owner should have all permissions via wildcard")
	}

	viewer := NewPrincipal("u2", "t1", "v@x.com", []Role{RoleViewer})
	if !viewer.Can(PermViewEvents) {
		t.Error("viewer should view events")
	}
	if viewer.Can(PermManagePolicy) {
		t.Error("viewer must NOT manage policy")
	}
	if viewer.Can(PermManageUsers) {
		t.Error("viewer must NOT manage users")
	}
}

func TestAnalystPermissions(t *testing.T) {
	a := NewPrincipal("u3", "t1", "a@x.com", []Role{RoleAnalyst})
	if !a.Can(PermVerifyAudit) || !a.Can(PermManageAlerts) {
		t.Error("analyst should verify audit and manage alerts")
	}
	if a.Can(PermManageUsers) {
		t.Error("analyst must NOT manage users")
	}
}

func TestMultipleRolesUnion(t *testing.T) {
	p := NewPrincipal("u4", "t1", "m@x.com", []Role{RoleViewer, RoleAnalyst})
	if !p.Can(PermManageAlerts) {
		t.Error("union of roles should include analyst permissions")
	}
	if !p.HasRole(RoleViewer) || !p.HasRole(RoleAnalyst) {
		t.Error("HasRole should report both roles")
	}
}

func TestNilPrincipalCan(t *testing.T) {
	var p *Principal
	if p.Can(PermViewEvents) {
		t.Error("nil principal must not have permissions")
	}
}

// --- Password hashing ---

func TestPasswordHashing(t *testing.T) {
	u := &User{TenantID: "t1", Email: "a@x.com"}
	if err := u.SetPassword("supersecret"); err != nil {
		t.Fatal(err)
	}
	if len(u.passwordHash) == 0 {
		t.Fatal("hash not set")
	}
	if u.CheckPassword("wrong") {
		t.Error("wrong password accepted")
	}
	if !u.CheckPassword("supersecret") {
		t.Error("correct password rejected")
	}
}

func TestPasswordTooShort(t *testing.T) {
	u := &User{}
	if err := u.SetPassword("short"); err == nil {
		t.Error("expected error for short password")
	}
}

func TestPasswordSaltUniqueness(t *testing.T) {
	u1 := &User{}
	u2 := &User{}
	_ = u1.SetPassword("samepassword")
	_ = u2.SetPassword("samepassword")
	if string(u1.passwordHash) == string(u2.passwordHash) {
		t.Error("same password must produce different hashes (unique salt)")
	}
}

// --- User store + API keys ---

func TestUserStoreCreateAndEmailLookup(t *testing.T) {
	s := NewMemUserStore()
	u := &User{TenantID: "t1", Email: "User@X.com", Roles: []Role{RoleAdmin}}
	if err := s.Create(u); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetByEmail("t1", "user@x.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != u.ID {
		t.Error("email lookup should be case-insensitive")
	}
}

func TestUserEmailConflictWithinTenant(t *testing.T) {
	s := NewMemUserStore()
	_ = s.Create(&User{TenantID: "t1", Email: "a@x.com"})
	err := s.Create(&User{TenantID: "t1", Email: "a@x.com"})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("expected conflict, got %v", err)
	}
}

func TestSameEmailDifferentTenants(t *testing.T) {
	s := NewMemUserStore()
	if err := s.Create(&User{TenantID: "t1", Email: "a@x.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(&User{TenantID: "t2", Email: "a@x.com"}); err != nil {
		t.Errorf("same email in different tenant should be allowed: %v", err)
	}
}

func TestAPIKeyGenerateResolveRevoke(t *testing.T) {
	s := NewMemUserStore()
	u := &User{TenantID: "t1", Email: "k@x.com"}
	_ = s.Create(u)

	raw, err := u.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(u); err != nil {
		t.Fatal(err)
	}

	resolved, err := s.ResolveAPIKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ID != u.ID {
		t.Error("API key resolved to wrong user")
	}

	u.RevokeAPIKey(raw)
	_ = s.Update(u)
	if _, err := s.ResolveAPIKey(raw); !errors.Is(err, ErrNotFound) {
		t.Error("revoked API key should not resolve")
	}
}

// --- JWT ---

func TestTokenIssueVerify(t *testing.T) {
	iss := NewTokenIssuer([]byte("test-signing-key"), "neurosentry", time.Hour)
	p := NewPrincipal("u1", "t1", "a@x.com", []Role{RoleAdmin})

	token, err := iss.Issue(p)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := iss.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "u1" || claims.TenantID != "t1" {
		t.Error("claims mismatch")
	}
	rebuilt := PrincipalFromClaims(claims)
	if !rebuilt.Can(PermManageUsers) {
		t.Error("rebuilt principal lost admin permissions")
	}
}

func TestTokenTamperDetection(t *testing.T) {
	iss := NewTokenIssuer([]byte("key"), "ns", time.Hour)
	p := NewPrincipal("u1", "t1", "a@x.com", []Role{RoleViewer})
	token, _ := iss.Issue(p)

	// Flip a character in the payload segment.
	tampered := token[:len(token)-3] + "AAA"
	if _, err := iss.Verify(tampered); err == nil {
		t.Error("tampered token must fail verification")
	}
}

func TestTokenWrongKey(t *testing.T) {
	a := NewTokenIssuer([]byte("key-a"), "ns", time.Hour)
	b := NewTokenIssuer([]byte("key-b"), "ns", time.Hour)
	token, _ := a.Issue(NewPrincipal("u1", "t1", "", nil))
	if _, err := b.Verify(token); err == nil {
		t.Error("token signed with different key must fail")
	}
}

func TestTokenExpiry(t *testing.T) {
	iss := NewTokenIssuer([]byte("key"), "ns", time.Hour)
	// Craft a token whose exp is already in the past.
	expired := Claims{
		Subject:   "u1",
		TenantID:  "t1",
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	}
	token, err := iss.sign(expired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(token); err == nil {
		t.Error("expired token must fail")
	}
}

// --- Provider + Authenticator ---

func TestLocalProviderPasswordLogin(t *testing.T) {
	users := NewMemUserStore()
	u := &User{TenantID: "t1", Email: "a@x.com", Roles: []Role{RoleAdmin}}
	_ = u.SetPassword("password123")
	_ = users.Create(u)

	iss := NewTokenIssuer([]byte("key"), "ns", time.Hour)
	auth := NewAuthenticator(iss, NewLocalProvider(users))

	token, principal, err := auth.Login(context.Background(), "local", Credentials{
		TenantID: "t1", Email: "a@x.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || principal.UserID != u.ID {
		t.Error("login did not return expected token/principal")
	}
}

func TestLocalProviderRejectsBadPassword(t *testing.T) {
	users := NewMemUserStore()
	u := &User{TenantID: "t1", Email: "a@x.com"}
	_ = u.SetPassword("password123")
	_ = users.Create(u)

	auth := NewAuthenticator(NewTokenIssuer([]byte("k"), "ns", time.Hour), NewLocalProvider(users))
	if _, _, err := auth.Login(context.Background(), "", Credentials{
		TenantID: "t1", Email: "a@x.com", Password: "wrong",
	}); err == nil {
		t.Error("bad password should fail login")
	}
}

func TestLocalProviderDisabledUser(t *testing.T) {
	users := NewMemUserStore()
	u := &User{TenantID: "t1", Email: "a@x.com", Status: UserDisabled}
	_ = u.SetPassword("password123")
	_ = users.Create(u)

	auth := NewAuthenticator(NewTokenIssuer([]byte("k"), "ns", time.Hour), NewLocalProvider(users))
	if _, _, err := auth.Login(context.Background(), "", Credentials{
		TenantID: "t1", Email: "a@x.com", Password: "password123",
	}); err == nil {
		t.Error("disabled user should not log in")
	}
}

func TestLocalProviderAPIKeyLogin(t *testing.T) {
	users := NewMemUserStore()
	u := &User{TenantID: "t1", Email: "a@x.com", Roles: []Role{RoleViewer}}
	_ = users.Create(u)
	raw, _ := u.GenerateAPIKey()
	_ = users.Update(u)

	auth := NewAuthenticator(NewTokenIssuer([]byte("k"), "ns", time.Hour), NewLocalProvider(users))
	_, principal, err := auth.Login(context.Background(), "", Credentials{APIKey: raw})
	if err != nil {
		t.Fatal(err)
	}
	if principal.UserID != u.ID {
		t.Error("API key login resolved wrong user")
	}
}

func TestUnknownProvider(t *testing.T) {
	auth := NewAuthenticator(NewTokenIssuer([]byte("k"), "ns", time.Hour), nil)
	if _, _, err := auth.Login(context.Background(), "saml", Credentials{}); err == nil {
		t.Error("unknown provider should error")
	}
}

// --- Middleware ---

func TestMiddlewareRequirePermission(t *testing.T) {
	iss := NewTokenIssuer([]byte("key"), "ns", time.Hour)
	mw := NewMiddleware(iss, nil)

	adminToken, _ := iss.Issue(NewPrincipal("u1", "t1", "", []Role{RoleAdmin}))
	viewerToken, _ := iss.Issue(NewPrincipal("u2", "t1", "", []Role{RoleViewer}))

	handler := mw.Require(PermManageUsers, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No token -> 401
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: expected 401, got %d", rec.Code)
	}

	// Viewer -> 403
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer: expected 403, got %d", rec.Code)
	}

	// Admin -> 200
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("admin: expected 200, got %d", rec.Code)
	}
}

func TestMiddlewareAPIKeyAuth(t *testing.T) {
	users := NewMemUserStore()
	u := &User{TenantID: "t1", Email: "a@x.com", Roles: []Role{RoleAdmin}}
	_ = users.Create(u)
	raw, _ := u.GenerateAPIKey()
	_ = users.Update(u)

	iss := NewTokenIssuer([]byte("key"), "ns", time.Hour)
	mw := NewMiddleware(iss, users)
	handler := mw.Require(PermViewEvents, func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFromContext(r.Context())
		if p == nil || p.UserID != u.ID {
			t.Error("principal not in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-API-Key", raw)
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("api key auth: expected 200, got %d", rec.Code)
	}
}

// --- Tenant isolation ---

func TestTenantScopedIsolation(t *testing.T) {
	tenantA := NewPrincipal("u1", "tA", "", []Role{RoleAdmin})
	if TenantScoped("tB", tenantA) {
		t.Error("tenant A admin must NOT access tenant B")
	}
	if !TenantScoped("tA", tenantA) {
		t.Error("tenant A admin should access tenant A")
	}
}

func TestTenantScopedSystemAdmin(t *testing.T) {
	sysAdmin := NewPrincipal("root", "system", "", []Role{RoleOwner})
	if !TenantScoped("any-tenant", sysAdmin) {
		t.Error("owner/system admin should cross tenants")
	}
}
