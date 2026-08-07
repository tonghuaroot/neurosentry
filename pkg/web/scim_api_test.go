// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/mcp"
	"github.com/neurosentry/neurosentry/pkg/platform"
)

func scimTestServer(t *testing.T) (*Server, *platform.MemUserStore, *platform.Tenant) {
	t.Helper()
	tenants := platform.NewMemTenantStore()
	users := platform.NewMemUserStore()
	iss := platform.NewTokenIssuer([]byte("k"), "neurosentry", time.Hour)
	auth := platform.NewAuthenticator(iss, platform.NewLocalProvider(users))
	ten := &platform.Tenant{Slug: "acme", Name: "Acme"}
	if err := tenants.Create(ten); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.EnablePlatform(auth, tenants, users)
	srv.SetSCIMProvisioning("scim-secret", "acme")
	return srv, users, ten
}

func scimReq(t *testing.T, srv *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestSCIMUserLifecycle(t *testing.T) {
	srv, users, ten := scimTestServer(t)

	// Create.
	rec := scimReq(t, srv, "POST", "/scim/v2/Users", "scim-secret", map[string]any{
		"schemas":  []string{scimUserSchema},
		"userName": "jane@acme.com",
		"active":   true,
		"emails":   []map[string]any{{"value": "jane@acme.com", "primary": true}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var created scimUser
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" || !created.Active {
		t.Fatalf("unexpected created user: %+v", created)
	}

	// Get by id.
	rec = scimReq(t, srv, "GET", "/scim/v2/Users/"+created.ID, "scim-secret", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", rec.Code)
	}

	// List with userName filter.
	rec = scimReq(t, srv, "GET", "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "jane@acme.com"`), "scim-secret", nil)
	var list struct {
		TotalResults int `json:"totalResults"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if list.TotalResults != 1 {
		t.Errorf("filter list: expected 1 result, got %d", list.TotalResults)
	}

	// Deactivate via PATCH (the join/leave flow).
	rec = scimReq(t, srv, "PATCH", "/scim/v2/Users/"+created.ID, "scim-secret", map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d", rec.Code)
	}
	u, _ := users.GetByEmail(ten.ID, "jane@acme.com")
	if u.Status != platform.UserDisabled {
		t.Errorf("user should be deactivated, status=%s", u.Status)
	}

	// Delete.
	rec = scimReq(t, srv, "DELETE", "/scim/v2/Users/"+created.ID, "scim-secret", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", rec.Code)
	}
	if _, err := users.Get(created.ID); err == nil {
		t.Error("user should be deleted")
	}
}

func TestSCIMAuth(t *testing.T) {
	srv, _, _ := scimTestServer(t)

	// Missing/wrong token -> 401.
	rec := scimReq(t, srv, "GET", "/scim/v2/Users", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token should be 401, got %d", rec.Code)
	}
	rec = scimReq(t, srv, "GET", "/scim/v2/Users", "wrong", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token should be 401, got %d", rec.Code)
	}
}

func TestSCIMDisabledWhenUnconfigured(t *testing.T) {
	tenants := platform.NewMemTenantStore()
	users := platform.NewMemUserStore()
	iss := platform.NewTokenIssuer([]byte("k"), "neurosentry", time.Hour)
	auth := platform.NewAuthenticator(iss, platform.NewLocalProvider(users))
	srv := NewServer(Config{ListenAddr: ":0"}, audit.NewChain(), mcp.NewInterceptor(mcp.NewPolicy()))
	srv.EnablePlatform(auth, tenants, users) // no SetSCIMProvisioning

	rec := scimReq(t, srv, "GET", "/scim/v2/Users", "anything", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unconfigured SCIM should be 503, got %d", rec.Code)
	}
}

func TestSCIMCreateIsIdempotent(t *testing.T) {
	srv, _, _ := scimTestServer(t)
	body := map[string]any{"userName": "dup@acme.com", "active": true,
		"emails": []map[string]any{{"value": "dup@acme.com", "primary": true}}}
	if rec := scimReq(t, srv, "POST", "/scim/v2/Users", "scim-secret", body); rec.Code != http.StatusCreated {
		t.Fatalf("first create should be 201, got %d", rec.Code)
	}
	// Second create of the same user returns 200, not a duplicate/500.
	if rec := scimReq(t, srv, "POST", "/scim/v2/Users", "scim-secret", body); rec.Code != http.StatusOK {
		t.Errorf("repeat create should be idempotent 200, got %d", rec.Code)
	}
}
