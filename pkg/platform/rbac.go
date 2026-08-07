// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

// Permission is a fine-grained capability. Handlers check permissions, never
// roles directly, so the role->permission mapping can evolve without touching
// authorization sites.
type Permission string

const (
	PermViewEvents    Permission = "events:view"
	PermViewAudit     Permission = "audit:view"
	PermVerifyAudit   Permission = "audit:verify"
	PermExportAudit   Permission = "audit:export"
	PermViewInventory Permission = "inventory:view"
	PermManagePolicy  Permission = "policy:manage"
	PermManageAlerts  Permission = "alerts:manage"
	PermManageUsers   Permission = "users:manage"
	PermManageTenant  Permission = "tenant:manage"
	PermManageSystem  Permission = "system:manage"

	// PermAll is a wildcard granting every permission. Reserved for owners.
	PermAll Permission = "*"
)

// Role is a named bundle of permissions assigned to users.
type Role string

const (
	RoleOwner   Role = "owner"
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

// rolePermissions maps each built-in role to the permissions it grants.
// Owner holds the wildcard; the rest are least-privilege bundles.
var rolePermissions = map[Role][]Permission{
	RoleOwner: {PermAll},
	RoleAdmin: {
		PermViewEvents, PermViewAudit, PermVerifyAudit, PermExportAudit,
		PermViewInventory, PermManagePolicy, PermManageAlerts, PermManageUsers,
	},
	RoleAnalyst: {
		PermViewEvents, PermViewAudit, PermVerifyAudit, PermExportAudit,
		PermViewInventory, PermManageAlerts,
	},
	RoleViewer: {
		PermViewEvents, PermViewAudit, PermViewInventory,
	},
}

// KnownRole reports whether r is a recognized built-in role.
func KnownRole(r Role) bool {
	_, ok := rolePermissions[r]
	return ok
}

// PermissionsForRoles returns the union of permissions granted by the given
// roles. If any role grants PermAll, the result is {PermAll}.
func PermissionsForRoles(roles []Role) map[Permission]struct{} {
	perms := make(map[Permission]struct{})
	for _, r := range roles {
		for _, p := range rolePermissions[r] {
			if p == PermAll {
				return map[Permission]struct{}{PermAll: {}}
			}
			perms[p] = struct{}{}
		}
	}
	return perms
}

// Principal is the authenticated subject attached to a request context. It is
// the single source of truth for "who is calling and what may they do".
type Principal struct {
	UserID   string
	TenantID string
	Email    string
	Roles    []Role
	perms    map[Permission]struct{}
}

// NewPrincipal builds a Principal and precomputes its effective permissions.
func NewPrincipal(userID, tenantID, email string, roles []Role) *Principal {
	return &Principal{
		UserID:   userID,
		TenantID: tenantID,
		Email:    email,
		Roles:    roles,
		perms:    PermissionsForRoles(roles),
	}
}

// Can reports whether the principal holds the given permission (directly or
// via the PermAll wildcard).
func (p *Principal) Can(perm Permission) bool {
	if p == nil {
		return false
	}
	if _, ok := p.perms[PermAll]; ok {
		return true
	}
	_, ok := p.perms[perm]
	return ok
}

// HasRole reports whether the principal carries the given role.
func (p *Principal) HasRole(role Role) bool {
	if p == nil {
		return false
	}
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}
