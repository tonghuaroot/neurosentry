// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aigateway

import (
	"sync"
	"time"
)

// Quota bounds a tenant's consumption. Zero fields mean "unlimited".
type Quota struct {
	MaxRequestsPerMin int   `json:"max_requests_per_min"`
	MaxTokensPerDay   int64 `json:"max_tokens_per_day"`
}

// QuotaManager enforces per-tenant request-rate and daily-token limits. It is
// the relay's abuse / denial-of-wallet guard. The clock is injectable for
// deterministic tests.
type QuotaManager struct {
	mu     sync.Mutex
	quotas map[string]Quota
	reqWin map[string]*window // per-minute request counter
	tokWin map[string]*window // per-day token counter
	now    func() time.Time
}

type window struct {
	start time.Time
	count int64
}

// NewQuotaManager returns a manager with no quotas set (all tenants unlimited
// until SetQuota is called).
func NewQuotaManager() *QuotaManager {
	return &QuotaManager{
		quotas: make(map[string]Quota),
		reqWin: make(map[string]*window),
		tokWin: make(map[string]*window),
		now:    time.Now,
	}
}

// SetQuota configures limits for a tenant.
func (q *QuotaManager) SetQuota(tenant string, quota Quota) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.quotas[tenant] = quota
}

// Allow reports whether a request from tenant carrying estTokens estimated
// tokens may proceed, and reserves the budget if so. Returns a reason when
// denied. Tenants without a configured quota are always allowed.
func (q *QuotaManager) Allow(tenant string, estTokens int64) (bool, string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	quota, ok := q.quotas[tenant]
	if !ok {
		return true, ""
	}
	now := q.now()

	// Request-rate window (1 minute).
	if quota.MaxRequestsPerMin > 0 {
		rw := q.reqWin[tenant]
		if rw == nil || now.Sub(rw.start) >= time.Minute {
			rw = &window{start: now}
			q.reqWin[tenant] = rw
		}
		if rw.count >= int64(quota.MaxRequestsPerMin) {
			return false, "request rate limit exceeded"
		}
	}

	// Daily-token window (24 hours).
	if quota.MaxTokensPerDay > 0 {
		tw := q.tokWin[tenant]
		if tw == nil || now.Sub(tw.start) >= 24*time.Hour {
			tw = &window{start: now}
			q.tokWin[tenant] = tw
		}
		if tw.count+estTokens > quota.MaxTokensPerDay {
			return false, "daily token quota exceeded"
		}
	}

	// Reserve budget now that both checks passed.
	if quota.MaxRequestsPerMin > 0 {
		q.reqWin[tenant].count++
	}
	if quota.MaxTokensPerDay > 0 {
		q.tokWin[tenant].count += estTokens
	}
	return true, ""
}

// SettleTokens reconciles a reservation with the actual token count once the
// upstream response is known (estimate vs actual delta).
func (q *QuotaManager) SettleTokens(tenant string, estimated, actual int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	tw := q.tokWin[tenant]
	if tw == nil {
		return
	}
	tw.count += actual - estimated
	if tw.count < 0 {
		tw.count = 0
	}
}
