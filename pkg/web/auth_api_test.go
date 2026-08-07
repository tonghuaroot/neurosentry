// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/mcp"
	"github.com/neurosentry/neurosentry/pkg/platform"
)

// platformTestServer builds a server with the control plane enabled and seeds a
// system owner plus one regular tenant with an admin user.
func platformTestServer(t *testing.T) (*Server, *platform.User, *platform.User, *platform.Tenant) {
	t.Helper()
	tenants := platform.NewMemTenantStore()
	users := platform.NewMemUserStore()
	iss := platform.NewTokenIssuer([]byte("test-key"), "neurosentry", time.Hour)
	auth := platform.NewAuthenticator(iss, platform.NewLocalProvider(users))

	// System tenant + owner (can cross tenants / manage system).
	sysTen := &platform.Tenant{Slug: "system", Name: "System"}
	if err := tenants.Create(sysTen); err != nil {
		t.Fatal(err)
	}
	owner := &platform.User{TenantID: sysTen.ID, Email: "owner@system", Roles: []platform.Role{platform.RoleOwner}}
	_ = owner.SetPassword("owner-password")
	if err := users.Create(owner); err != nil {
		t.Fatal(err)
	}

	// Customer tenant + admin.
	custTen := &platform.Tenant{Slug: "acme", Name: "Acme"}
	if err := tenants.Create(custTen); err != nil {
		t.Fatal(err)
	}
	admin := &platform.User{TenantID: custTen.ID, Email: "admin@acme", Roles: []platform.Role{platform.RoleAdmin}}
	_ = admin.SetPassword("admin-password")
	if err := users.Create(admin); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.EnablePlatform(auth, tenants, users)
	return srv, owner, admin, custTen
}

func login(t *testing.T, srv *Server, tenantSlug, email, password string) string {
	t.Helper()
	body, _ := json.Marshal(loginRequest{TenantSlug: tenantSlug, Email: email, Password: password})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Token == "" {
		t.Fatal("no token returned")
	}
	return resp.Token
}

func TestLoginSuccess(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)
	token := login(t, srv, "acme", "admin@acme", "admin-password")
	if token == "" {
		t.Error("expected token")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)
	body, _ := json.Marshal(loginRequest{TenantSlug: "acme", Email: "admin@acme", Password: "wrong"})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestLoginUnknownTenantUniformError(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)
	body, _ := json.Marshal(loginRequest{TenantSlug: "ghost", Email: "x@y", Password: "z"})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown tenant should give 401 (no enumeration), got %d", rec.Code)
	}
}

func TestMeEndpoint(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)
	token := login(t, srv, "acme", "admin@acme", "admin-password")

	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var me map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me["email"] != "admin@acme" {
		t.Errorf("me returned wrong email: %v", me["email"])
	}
}

func TestMeRequiresAuth(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)
	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("me without token should be 401, got %d", rec.Code)
	}
}

func TestAdminCannotManageSystem(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)
	token := login(t, srv, "acme", "admin@acme", "admin-password")

	// Listing tenants requires PermManageSystem, which admin lacks.
	req := httptest.NewRequest("GET", "/api/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("tenant admin listing all tenants should be 403, got %d", rec.Code)
	}
}

func TestOwnerCanListTenants(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)
	token := login(t, srv, "system", "owner@system", "owner-password")

	req := httptest.NewRequest("GET", "/api/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner should list tenants, got %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string][]platform.Tenant
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp["tenants"]) != 2 {
		t.Errorf("expected 2 tenants, got %d", len(resp["tenants"]))
	}
}

func TestCrossTenantUserListDenied(t *testing.T) {
	srv, _, admin, _ := platformTestServer(t)
	token := login(t, srv, "acme", "admin@acme", "admin-password")

	// Admin of acme tries to list users of a DIFFERENT tenant (owner's system tenant).
	// Find the system tenant id via a fresh lookup is not exposed; use a bogus id.
	req := httptest.NewRequest("GET", "/api/tenants/ten_other/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-tenant user list should be 403, got %d", rec.Code)
	}
	_ = admin
}

func TestAdminManagesOwnTenantUsers(t *testing.T) {
	srv, _, admin, custTen := platformTestServer(t)
	token := login(t, srv, "acme", "admin@acme", "admin-password")

	// Create a viewer in the admin's own tenant.
	body, _ := json.Marshal(createUserRequest{
		Email: "viewer@acme", Password: "viewer-password", Roles: []string{"viewer"},
	})
	req := httptest.NewRequest("POST", "/api/tenants/"+custTen.ID+"/users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin creating user in own tenant should be 201, got %d %s", rec.Code, rec.Body.String())
	}

	// List should now show 2 users (admin + viewer).
	req = httptest.NewRequest("GET", "/api/tenants/"+custTen.ID+"/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list users: %d", rec.Code)
	}
	var resp map[string][]platform.User
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp["users"]) != 2 {
		t.Errorf("expected 2 users in tenant, got %d", len(resp["users"]))
	}
	_ = admin
}

func TestAPIKeyIssuanceAndAuth(t *testing.T) {
	srv, _, admin, _ := platformTestServer(t)
	token := login(t, srv, "acme", "admin@acme", "admin-password")

	// Issue an API key for the admin user.
	req := httptest.NewRequest("POST", "/api/users/"+admin.ID+"/apikeys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("api key issuance should be 201, got %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	rawKey := resp["api_key"]
	if rawKey == "" {
		t.Fatal("no api key returned")
	}

	// Use the API key to hit an authenticated endpoint.
	req = httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("X-API-Key", rawKey)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("API key auth should work on /me, got %d", rec.Code)
	}
}

func TestUnknownRoleRejected(t *testing.T) {
	srv, _, _, custTen := platformTestServer(t)
	token := login(t, srv, "acme", "admin@acme", "admin-password")

	body, _ := json.Marshal(createUserRequest{
		Email: "x@acme", Password: "some-password", Roles: []string{"superhacker"},
	})
	req := httptest.NewRequest("POST", "/api/tenants/"+custTen.ID+"/users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown role should be 400, got %d", rec.Code)
	}
}

func TestLoginBruteForceLockout(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)

	// 5 consecutive failures should trigger lockout on the 6th attempt.
	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(loginRequest{TenantSlug: "acme", Email: "admin@acme", Password: "wrong"})
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}

	// Now locked out — even the CORRECT password should be refused with 429.
	body, _ := json.Marshal(loginRequest{TenantSlug: "acme", Email: "admin@acme", Password: "admin-password"})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after lockout, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on lockout")
	}
}

func TestExistingDemoEndpointsStayOpen(t *testing.T) {
	// With platform enabled, the legacy demo endpoints remain open (no token)
	// so the running Arsenal demo keeps working until a login UI ships.
	srv, _, _, _ := platformTestServer(t)
	req := httptest.NewRequest("GET", "/api/health", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("health should stay open, got %d", rec.Code)
	}
}
