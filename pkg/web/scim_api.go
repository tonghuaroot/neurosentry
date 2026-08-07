// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/platform"
)

// SCIM 2.0 (RFC 7644) user provisioning. Enterprise IdPs (Okta, Azure AD) push
// user lifecycle — create, deactivate, delete — to this endpoint so access is
// granted and, crucially, *revoked* automatically when someone joins or leaves.
// Authentication is a static bearer token shared with the IdP. Roles are not
// set here; they come from the OIDC group mapping at login (see sso_api.go).
// SCIM owns existence and active-state, OIDC owns authorization.

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

// SetSCIMProvisioning enables the SCIM endpoints, provisioning into tenantSlug
// and authenticating IdP requests with the given bearer token.
func (s *Server) SetSCIMProvisioning(token, tenantSlug string) {
	s.scimToken = token
	s.scimTenant = tenantSlug
}

func (s *Server) registerSCIMRoutes() {
	s.mux.HandleFunc("POST /scim/v2/Users", s.scimAuth(s.handleSCIMCreateUser))
	s.mux.HandleFunc("GET /scim/v2/Users", s.scimAuth(s.handleSCIMListUsers))
	s.mux.HandleFunc("GET /scim/v2/Users/{id}", s.scimAuth(s.handleSCIMGetUser))
	s.mux.HandleFunc("PATCH /scim/v2/Users/{id}", s.scimAuth(s.handleSCIMPatchUser))
	s.mux.HandleFunc("PUT /scim/v2/Users/{id}", s.scimAuth(s.handleSCIMPatchUser))
	s.mux.HandleFunc("DELETE /scim/v2/Users/{id}", s.scimAuth(s.handleSCIMDeleteUser))
}

// scimAuth gates a SCIM handler on the shared bearer token (constant-time
// compare) and returns 503 when SCIM is not configured.
func (s *Server) scimAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.scimToken == "" {
			writeSCIMError(w, http.StatusServiceUnavailable, "SCIM is not configured")
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.scimToken)) != 1 {
			writeSCIMError(w, http.StatusUnauthorized, "invalid SCIM token")
			return
		}
		h(w, r)
	}
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type scimUser struct {
	Schemas  []string    `json:"schemas"`
	ID       string      `json:"id,omitempty"`
	UserName string      `json:"userName"`
	Active   bool        `json:"active"`
	Emails   []scimEmail `json:"emails,omitempty"`
	Meta     *scimMeta   `json:"meta,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location"`
}

func (s *Server) scimTenantID(w http.ResponseWriter) (string, bool) {
	ten, err := s.tenants.GetBySlug(s.scimTenant)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "SCIM tenant not found")
		return "", false
	}
	return ten.ID, true
}

func (s *Server) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.scimTenantID(w)
	if !ok {
		return
	}
	var in scimUser
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required")
		return
	}
	email := primaryEmail(in)

	// Idempotent: if the user already exists, return it (200) as SCIM expects.
	if existing, err := s.users.GetByEmail(tenantID, email); err == nil {
		writeJSONStatus(w, http.StatusOK, s.toSCIM(existing, r))
		return
	}

	u := &platform.User{
		TenantID: tenantID,
		Email:    email,
		Username: in.UserName,
		Roles:    []platform.Role{platform.RoleViewer}, // authz comes from OIDC groups at login
		Status:   activeStatus(in.Active),
	}
	if err := s.users.Create(u); err != nil {
		writeSCIMError(w, http.StatusConflict, "could not create user")
		return
	}
	s.recordAdminAudit("scim:user_created", audit.SeverityInfo, email, u.ID, map[string]any{"tenant": s.scimTenant})
	writeJSONStatus(w, http.StatusCreated, s.toSCIM(u, r))
}

func (s *Server) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.users.Get(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSONStatus(w, http.StatusOK, s.toSCIM(u, r))
}

func (s *Server) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.scimTenantID(w)
	if !ok {
		return
	}
	all, _ := s.users.ListByTenant(tenantID)

	// Support the one filter IdPs actually use: userName eq "x".
	if f := r.URL.Query().Get("filter"); f != "" {
		want := parseUserNameEq(f)
		filtered := all[:0]
		for _, u := range all {
			if strings.EqualFold(u.Username, want) || strings.EqualFold(u.Email, want) {
				filtered = append(filtered, u)
			}
		}
		all = filtered
	}

	resources := make([]scimUser, 0, len(all))
	for _, u := range all {
		resources = append(resources, s.toSCIM(u, r))
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(resources),
		"Resources":    resources,
	})
}

// handleSCIMPatchUser handles the deactivation/reactivation IdPs send on
// join/leave. It accepts both PATCH (Operations) and PUT (full resource).
func (s *Server) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.users.Get(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	var body struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
		Active *bool `json:"active"` // PUT-style full replace
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid patch body")
		return
	}

	newActive := u.Status == platform.UserActive
	if body.Active != nil {
		newActive = *body.Active
	}
	for _, op := range body.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		// "active" may arrive as a bare value (path=active) or inside an object.
		if strings.EqualFold(op.Path, "active") {
			var b bool
			if json.Unmarshal(op.Value, &b) == nil {
				newActive = b
			}
			continue
		}
		var obj struct {
			Active *bool `json:"active"`
		}
		if json.Unmarshal(op.Value, &obj) == nil && obj.Active != nil {
			newActive = *obj.Active
		}
	}

	u.Status = activeStatus(newActive)
	if err := s.users.Update(u); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	action := "scim:user_deactivated"
	if newActive {
		action = "scim:user_activated"
	}
	s.recordAdminAudit(action, audit.SeverityInfo, u.Email, u.ID, map[string]any{"tenant": s.scimTenant})
	writeJSONStatus(w, http.StatusOK, s.toSCIM(u, r))
}

func (s *Server) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := s.users.Get(id)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err := s.users.Delete(id); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "could not delete user")
		return
	}
	s.recordAdminAudit("scim:user_deleted", audit.SeverityMedium, u.Email, id, map[string]any{"tenant": s.scimTenant})
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers ----

func (s *Server) toSCIM(u *platform.User, r *http.Request) scimUser {
	return scimUser{
		Schemas:  []string{scimUserSchema},
		ID:       u.ID,
		UserName: firstNonEmpty(u.Username, u.Email),
		Active:   u.Status == platform.UserActive,
		Emails:   []scimEmail{{Value: u.Email, Primary: true}},
		Meta: &scimMeta{
			ResourceType: "User",
			Location:     "/scim/v2/Users/" + u.ID,
		},
	}
}

func primaryEmail(in scimUser) string {
	for _, e := range in.Emails {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	for _, e := range in.Emails {
		if e.Value != "" {
			return e.Value
		}
	}
	return in.UserName // userName is often the email
}

func activeStatus(active bool) platform.UserStatus {
	if active {
		return platform.UserActive
	}
	return platform.UserDisabled
}

// parseUserNameEq extracts x from `userName eq "x"`.
func parseUserNameEq(filter string) string {
	i := strings.Index(filter, "\"")
	j := strings.LastIndex(filter, "\"")
	if i >= 0 && j > i {
		return filter[i+1 : j]
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func writeSCIMError(w http.ResponseWriter, code int, detail string) {
	writeJSONStatus(w, code, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  code,
	})
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
