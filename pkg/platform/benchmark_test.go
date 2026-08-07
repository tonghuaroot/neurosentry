// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// BenchmarkJWTIssue measures token minting cost — incurred once per login.
func BenchmarkJWTIssue(b *testing.B) {
	iss := NewTokenIssuer([]byte("benchmark-signing-key"), "neurosentry", time.Hour)
	p := NewPrincipal("usr_1", "ten_1", "a@x.com", []Role{RoleAdmin})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := iss.Issue(p); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJWTVerify measures per-request token verification cost — this runs on
// every authenticated API call, so it must stay sub-microsecond.
func BenchmarkJWTVerify(b *testing.B) {
	iss := NewTokenIssuer([]byte("benchmark-signing-key"), "neurosentry", time.Hour)
	token, _ := iss.Issue(NewPrincipal("usr_1", "ten_1", "a@x.com", []Role{RoleAdmin}))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := iss.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPasswordHash measures PBKDF2 cost. This is DELIBERATELY slow (work
// factor tuned per OWASP) to resist offline cracking; the benchmark documents
// the per-login CPU budget.
func BenchmarkPasswordHash(b *testing.B) {
	u := &User{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = u.SetPassword("a-reasonably-long-password")
	}
}

// BenchmarkPasswordCheck measures verification cost (same PBKDF2 work factor).
func BenchmarkPasswordCheck(b *testing.B) {
	u := &User{}
	_ = u.SetPassword("a-reasonably-long-password")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = u.CheckPassword("a-reasonably-long-password")
	}
}

// BenchmarkRBACPermissionCheck measures the authorization decision on the hot
// path — every guarded request calls Principal.Can.
func BenchmarkRBACPermissionCheck(b *testing.B) {
	p := NewPrincipal("u", "t", "a@x.com", []Role{RoleAnalyst, RoleViewer})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Can(PermManageAlerts)
	}
}

// BenchmarkTenantLookup measures store read latency at 1k tenants.
func BenchmarkTenantLookup(b *testing.B) {
	s := NewMemTenantStore()
	var ids []string
	for i := 0; i < 1000; i++ {
		t := &Tenant{Slug: fmt.Sprintf("tenant-%d", i), Name: "T"}
		_ = s.Create(t)
		ids = append(ids, t.ID)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Get(ids[i%len(ids)]); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoginGuardAllowed measures brute-force-guard overhead per attempt.
func BenchmarkLoginGuardAllowed(b *testing.B) {
	g := NewLoginGuard(5, 15*time.Minute, 15*time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Allowed("user@example.com")
	}
}

// BenchmarkFullLogin measures an end-to-end password login (store lookup +
// PBKDF2 verify + JWT issue) — the full cost of one authentication.
func BenchmarkFullLogin(b *testing.B) {
	users := NewMemUserStore()
	u := &User{TenantID: "t1", Email: "a@x.com", Roles: []Role{RoleAdmin}}
	_ = u.SetPassword("a-reasonably-long-password")
	_ = users.Create(u)
	auth := NewAuthenticator(NewTokenIssuer([]byte("k"), "ns", time.Hour), NewLocalProvider(users))
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := auth.Login(ctx, "", Credentials{TenantID: "t1", Email: "a@x.com", Password: "a-reasonably-long-password"})
		if err != nil {
			b.Fatal(err)
		}
	}
}
