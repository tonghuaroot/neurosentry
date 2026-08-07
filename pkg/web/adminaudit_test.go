// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// auditHas reports whether the chain contains an entry of the given event type.
func auditHas(srv *Server, eventType string) bool {
	for _, e := range srv.auditChain.Entries() {
		if e.EventType == eventType {
			return true
		}
	}
	return false
}

func TestAdminAuditRecordsLogin(t *testing.T) {
	srv, _, _, _ := platformTestServer(t)

	// A failed login must be audited.
	body, _ := json.Marshal(loginRequest{TenantSlug: "acme", Email: "admin@acme", Password: "wrong"})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body)))
	if !auditHas(srv, "auth:login_failed") {
		t.Error("failed login should be recorded in the audit chain")
	}

	// A successful login must be audited.
	login(t, srv, "acme", "admin@acme", "admin-password")
	if !auditHas(srv, "auth:login") {
		t.Error("successful login should be recorded in the audit chain")
	}
}

func TestAdminAuditRecordsUserCreation(t *testing.T) {
	srv, _, _, custTen := platformTestServer(t)
	token := login(t, srv, "acme", "admin@acme", "admin-password")

	body, _ := json.Marshal(createUserRequest{Email: "new@acme", Password: "new-password-123", Roles: []string{"viewer"}})
	req := httptest.NewRequest("POST", "/api/tenants/"+custTen.ID+"/users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user: %d", rec.Code)
	}

	// The action must be in the audit chain with the acting admin as actor.
	found := false
	for _, e := range srv.auditChain.Entries() {
		if e.EventType == "iam:user_created" {
			found = true
			if e.Details["actor_email"] != "admin@acme" {
				t.Errorf("expected actor admin@acme, got %v", e.Details["actor_email"])
			}
			if e.Details["new_user_email"] != "new@acme" {
				t.Errorf("expected new user recorded, got %v", e.Details["new_user_email"])
			}
		}
	}
	if !found {
		t.Error("user creation should be recorded in the audit chain")
	}
}

func TestAdminAuditChainStaysValid(t *testing.T) {
	srv, _, _, custTen := platformTestServer(t)
	token := login(t, srv, "acme", "admin@acme", "admin-password")

	// Generate a mix of admin actions.
	for i := 0; i < 3; i++ {
		body, _ := json.Marshal(createUserRequest{Email: "u" + string(rune('a'+i)) + "@acme", Password: "password-abc", Roles: []string{"analyst"}})
		req := httptest.NewRequest("POST", "/api/tenants/"+custTen.ID+"/users", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		srv.ServeHTTP(httptest.NewRecorder(), req)
	}
	// The tamper-proof chain must still verify after admin-action appends.
	if err := srv.auditChain.Verify(); err != nil {
		t.Fatalf("audit chain should stay valid after admin actions: %v", err)
	}
}
