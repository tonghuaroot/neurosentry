// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/platform"
)

// SSO (OIDC) login. A tenant configured for SSO delegates authentication to its
// enterprise IdP: the browser completes the OIDC flow with the IdP and posts
// the resulting ID token here. NeuroSentry verifies it, JIT-provisions or
// updates the user (the IdP is the source of truth for identity and group ->
// role mapping), and issues a normal NeuroSentry session token. Password login
// (handleLogin) remains as a break-glass fallback.

// SetOIDCProvider wires a verified OIDC provider and the tenant its users are
// provisioned into. When set, POST /api/auth/sso/oidc is enabled.
func (s *Server) SetOIDCProvider(p *platform.OIDCProvider, tenantSlug string) {
	s.oidc = p
	s.oidcTenant = tenantSlug
}

type ssoLoginRequest struct {
	IDToken string `json:"id_token"`
}

// SetSAMLProvider enables SAML SSO, provisioning into tenantSlug. When set,
// POST /api/auth/sso/saml/acs (the assertion consumer service) is enabled.
func (s *Server) SetSAMLProvider(p *platform.SAMLProvider, tenantSlug string) {
	s.saml = p
	s.samlTenant = tenantSlug
}

// handleSAMLACS is the SAML assertion consumer service: the IdP posts a signed
// SAMLResponse here; we validate it (via the vetted library), JIT-provision the
// user with IdP-mapped roles, and issue a NeuroSentry session token.
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	if s.saml == nil {
		writeError(w, http.StatusServiceUnavailable, "SAML SSO is not configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return
	}
	samlResp := r.FormValue("SAMLResponse")
	if samlResp == "" {
		writeError(w, http.StatusBadRequest, "SAMLResponse is required")
		return
	}
	claims, err := s.saml.ParseAssertion(samlResp)
	if err != nil {
		s.recordAdminAudit("auth:sso_failed", audit.SeverityMedium, "", "", map[string]any{"protocol": "saml", "error": err.Error()})
		writeError(w, http.StatusUnauthorized, "invalid SAML assertion")
		return
	}
	if claims.Email == "" {
		writeError(w, http.StatusUnauthorized, "SAML assertion has no email/nameid")
		return
	}
	_, resp, serr := s.ssoIssue(r, s.samlTenant, claims.Email, s.saml.MapRoles(claims.Groups), "saml")
	if serr != nil {
		writeError(w, serr.code, serr.msg)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusServiceUnavailable, "SSO is not configured")
		return
	}
	var req ssoLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.IDToken) == "" {
		writeError(w, http.StatusBadRequest, "id_token is required")
		return
	}

	claims, err := s.oidc.Verify(r.Context(), req.IDToken)
	if err != nil {
		s.recordAdminAudit("auth:sso_failed", audit.SeverityMedium, "", "", map[string]any{"error": err.Error()})
		writeError(w, http.StatusUnauthorized, "invalid SSO token")
		return
	}
	if claims.Email == "" {
		writeError(w, http.StatusUnauthorized, "SSO token has no email claim")
		return
	}

	_, resp, serr := s.ssoIssue(r, s.oidcTenant, claims.Email, s.oidc.MapRoles(claims.Groups), "oidc")
	if serr != nil {
		writeError(w, serr.code, serr.msg)
		return
	}
	writeJSON(w, resp)
}

type ssoError struct {
	code int
	msg  string
}

// ssoIssue is the shared SSO tail used by every protocol: JIT-provision or
// reconcile the user (the IdP owns identity + roles), then mint a NeuroSentry
// session token. Returns the token and the login response, or a typed error.
func (s *Server) ssoIssue(r *http.Request, tenantSlug, email string, roles []platform.Role, protocol string) (string, loginResponse, *ssoError) {
	ten, err := s.tenants.GetBySlug(tenantSlug)
	if err != nil {
		return "", loginResponse{}, &ssoError{http.StatusInternalServerError, "SSO tenant not found"}
	}
	user, err := s.users.GetByEmail(ten.ID, email)
	if err != nil {
		user = &platform.User{
			TenantID: ten.ID, Email: email, Username: email,
			Roles: roles, Status: platform.UserActive,
		}
		if cerr := s.users.Create(user); cerr != nil {
			return "", loginResponse{}, &ssoError{http.StatusInternalServerError, "could not provision SSO user"}
		}
		s.recordAdminAudit("auth:sso_provision", audit.SeverityInfo, email, user.ID, map[string]any{"tenant": tenantSlug, "protocol": protocol})
	} else {
		user.Roles = roles
		user.Status = platform.UserActive
		_ = s.users.Update(user)
	}

	principal := platform.NewPrincipal(user.ID, user.TenantID, user.Email, user.Roles)
	token, err := s.auth.Issuer().Issue(principal)
	if err != nil {
		return "", loginResponse{}, &ssoError{http.StatusInternalServerError, "could not issue session"}
	}
	s.recordAdminAudit("auth:sso_login", audit.SeverityInfo, user.Email, user.ID, map[string]any{"tenant": tenantSlug, "protocol": protocol})

	roleStrs := make([]string, len(principal.Roles))
	for i, ro := range principal.Roles {
		roleStrs[i] = string(ro)
	}
	return token, loginResponse{
		Token: token, UserID: principal.UserID, TenantID: principal.TenantID,
		Email: principal.Email, Roles: roleStrs,
	}, nil
}
