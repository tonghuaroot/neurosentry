// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/platform"
)

// registerPlatformRoutes mounts the multi-tenant control-plane API. All
// mutating and cross-tenant routes are guarded by RBAC permissions; login is
// intentionally open.
func (s *Server) registerPlatformRoutes() {
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/sso/oidc", s.handleSSOLogin)
	s.mux.HandleFunc("POST /api/auth/sso/saml/acs", s.handleSAMLACS)
	s.mux.HandleFunc("GET /api/auth/me", s.mw.Require(platform.PermViewEvents, s.handleMe))

	s.mux.HandleFunc("GET /api/tenants", s.mw.Require(platform.PermManageSystem, s.handleListTenants))
	s.mux.HandleFunc("POST /api/tenants", s.mw.Require(platform.PermManageSystem, s.handleCreateTenant))

	s.mux.HandleFunc("GET /api/tenants/{id}/users", s.mw.Require(platform.PermManageUsers, s.handleListUsers))
	s.mux.HandleFunc("POST /api/tenants/{id}/users", s.mw.Require(platform.PermManageUsers, s.handleCreateUser))
	s.mux.HandleFunc("POST /api/users/{id}/apikeys", s.mw.Require(platform.PermManageUsers, s.handleCreateAPIKey))
}

type loginRequest struct {
	TenantSlug string `json:"tenant_slug"`
	Provider   string `json:"provider,omitempty"`
	Email      string `json:"email,omitempty"`
	Password   string `json:"password,omitempty"`
	APIKey     string `json:"api_key,omitempty"`
}

type loginResponse struct {
	Token    string   `json:"token"`
	UserID   string   `json:"user_id"`
	TenantID string   `json:"tenant_id"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	creds := platform.Credentials{
		Email:    req.Email,
		Password: req.Password,
		APIKey:   req.APIKey,
	}

	// Brute-force protection: throttle repeated failures per identity.
	guardKey := req.TenantSlug + ":" + req.Email
	if req.APIKey != "" {
		guardKey = "apikey"
	}
	if s.loginGuard != nil && !s.loginGuard.Allowed(guardKey) {
		w.Header().Set("Retry-After", "900")
		s.recordAdminAudit("auth:lockout", audit.SeverityHigh, req.Email, "", map[string]any{"tenant": req.TenantSlug})
		writeError(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}

	// Resolve tenant slug -> id for password logins (API keys are global).
	if req.APIKey == "" && req.TenantSlug != "" {
		ten, err := s.tenants.GetBySlug(req.TenantSlug)
		if err != nil {
			if s.loginGuard != nil {
				s.loginGuard.RecordFailure(guardKey)
			}
			// Uniform error to avoid tenant enumeration.
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		creds.TenantID = ten.ID
	}

	token, principal, err := s.auth.Login(r.Context(), req.Provider, creds)
	if err != nil {
		if s.loginGuard != nil {
			s.loginGuard.RecordFailure(guardKey)
		}
		s.recordAdminAudit("auth:login_failed", audit.SeverityMedium, req.Email, "", map[string]any{"tenant": req.TenantSlug})
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if s.loginGuard != nil {
		s.loginGuard.RecordSuccess(guardKey)
	}
	s.recordAdminAudit("auth:login", audit.SeverityInfo, principal.Email, principal.UserID, map[string]any{"tenant": req.TenantSlug})

	roles := make([]string, len(principal.Roles))
	for i, ro := range principal.Roles {
		roles[i] = string(ro)
	}
	writeJSON(w, loginResponse{
		Token:    token,
		UserID:   principal.UserID,
		TenantID: principal.TenantID,
		Email:    principal.Email,
		Roles:    roles,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFromContext(r.Context())
	roles := make([]string, len(p.Roles))
	for i, ro := range p.Roles {
		roles[i] = string(ro)
	}
	writeJSON(w, map[string]any{
		"user_id":   p.UserID,
		"tenant_id": p.TenantID,
		"email":     p.Email,
		"roles":     roles,
	})
}

func (s *Server) handleListTenants(w http.ResponseWriter, _ *http.Request) {
	tenants, err := s.tenants.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"tenants": tenants})
}

type createTenantRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	Plan string `json:"plan,omitempty"`
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ten := &platform.Tenant{Slug: req.Slug, Name: req.Name, Plan: platform.TenantPlan(req.Plan)}
	if err := s.tenants.Create(ten); err != nil {
		if errors.Is(err, platform.ErrConflict) {
			writeError(w, http.StatusConflict, "tenant already exists")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("iam:tenant_created", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"tenant_slug": ten.Slug, "plan": string(ten.Plan)})
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, ten)
}

func callerEmail(p *platform.Principal) string {
	if p == nil {
		return ""
	}
	return p.Email
}

func callerID(p *platform.Principal) string {
	if p == nil {
		return ""
	}
	return p.UserID
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	if !platform.TenantScoped(tenantID, platform.PrincipalFromContext(r.Context())) {
		writeError(w, http.StatusForbidden, "cross-tenant access denied")
		return
	}
	users, err := s.users.ListByTenant(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Never leak password hashes; User JSON tags already omit them (unexported).
	writeJSON(w, map[string]any{"users": users})
}

type createUserRequest struct {
	Email    string   `json:"email"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	if !platform.TenantScoped(tenantID, platform.PrincipalFromContext(r.Context())) {
		writeError(w, http.StatusForbidden, "cross-tenant access denied")
		return
	}
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	roles := make([]platform.Role, 0, len(req.Roles))
	for _, ro := range req.Roles {
		role := platform.Role(ro)
		if !platform.KnownRole(role) {
			writeError(w, http.StatusBadRequest, "unknown role: "+ro)
			return
		}
		roles = append(roles, role)
	}
	u := &platform.User{TenantID: tenantID, Email: req.Email, Username: req.Username, Roles: roles}
	if err := u.SetPassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.users.Create(u); err != nil {
		if errors.Is(err, platform.ErrConflict) {
			writeError(w, http.StatusConflict, "user already exists")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("iam:user_created", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"new_user_email": u.Email, "roles": req.Roles, "tenant_id": tenantID})
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": u.ID, "email": u.Email, "roles": req.Roles})
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	u, err := s.users.Get(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	if !platform.TenantScoped(u.TenantID, caller) {
		writeError(w, http.StatusForbidden, "cross-tenant access denied")
		return
	}
	raw, err := u.GenerateAPIKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.users.Update(u); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordAdminAudit("iam:apikey_issued", audit.SeverityHigh, callerEmail(caller), callerID(caller), map[string]any{"target_user_id": u.ID, "target_email": u.Email})
	// The raw key is returned exactly once and cannot be recovered later.
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"api_key": raw, "user_id": u.ID})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
