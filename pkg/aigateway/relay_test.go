// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neurosentry/neurosentry/pkg/aiguard"
)

// --- Vault ---

func TestVaultSetGetDelete(t *testing.T) {
	v := NewMemKeyVault()
	if err := v.SetKey("ten1", "OpenAI", "sk-secret"); err != nil {
		t.Fatal(err)
	}
	k, ok := v.GetKey("ten1", "OpenAI")
	if !ok || k != "sk-secret" {
		t.Errorf("expected key, got %q %v", k, ok)
	}
	// Tenant isolation: ten2 has no key for OpenAI.
	if _, ok := v.GetKey("ten2", "OpenAI"); ok {
		t.Error("cross-tenant key leak")
	}
	_ = v.DeleteKey("ten1", "OpenAI")
	if _, ok := v.GetKey("ten1", "OpenAI"); ok {
		t.Error("key should be deleted")
	}
}

func TestVaultRejectsEmpty(t *testing.T) {
	v := NewMemKeyVault()
	if err := v.SetKey("", "OpenAI", "k"); err == nil {
		t.Error("empty tenant should error")
	}
}

func TestVaultProviders(t *testing.T) {
	v := NewMemKeyVault()
	_ = v.SetKey("ten1", "OpenAI", "k1")
	_ = v.SetKey("ten1", "Anthropic", "k2")
	_ = v.SetKey("ten2", "OpenAI", "k3")
	provs := v.Providers("ten1")
	if len(provs) != 2 {
		t.Errorf("expected 2 providers for ten1, got %d", len(provs))
	}
}

// --- Usage / cost ---

func TestUsageTrackingAndCost(t *testing.T) {
	tr := NewUsageTracker()
	// 1M input + 1M output tokens on gpt-4o = $2.50 + $10.00 = $12.50.
	tr.Record("ten1", "gpt-4o", 1_000_000, 1_000_000)
	u := tr.Usage("ten1")
	if u.Requests != 1 || u.PromptTokens != 1_000_000 {
		t.Errorf("unexpected usage: %+v", u)
	}
	if u.CostUSD != 12.50 {
		t.Errorf("expected cost 12.50, got %.4f", u.CostUSD)
	}
}

func TestUsagePricingPrefixMatch(t *testing.T) {
	tr := NewUsageTracker()
	// Versioned id should inherit the base model's price.
	tr.Record("ten1", "gpt-4o-2024-11-20", 1_000_000, 0)
	if tr.Usage("ten1").CostUSD != 2.50 {
		t.Errorf("prefix pricing failed: %.4f", tr.Usage("ten1").CostUSD)
	}
}

func TestUsageUnknownModelFallback(t *testing.T) {
	tr := NewUsageTracker()
	tr.Record("ten1", "some-obscure-model", 1_000_000, 0)
	if tr.Usage("ten1").CostUSD != 1.00 {
		t.Errorf("expected fallback cost 1.00, got %.4f", tr.Usage("ten1").CostUSD)
	}
}

func TestParseResponseUsage(t *testing.T) {
	body := []byte(`{"choices":[],"usage":{"prompt_tokens":42,"completion_tokens":13,"total_tokens":55}}`)
	p, c, ok := parseResponseUsage(body)
	if !ok || p != 42 || c != 13 {
		t.Errorf("parse usage failed: %d %d %v", p, c, ok)
	}
	if _, _, ok := parseResponseUsage([]byte(`{"choices":[]}`)); ok {
		t.Error("no usage object should return ok=false")
	}
}

// --- Quota ---

func TestQuotaRequestRateLimit(t *testing.T) {
	clock := &fakeClk{t: time.Unix(1000, 0)}
	q := NewQuotaManager()
	q.now = clock.now
	q.SetQuota("ten1", Quota{MaxRequestsPerMin: 2})

	if ok, _ := q.Allow("ten1", 0); !ok {
		t.Error("1st request should pass")
	}
	if ok, _ := q.Allow("ten1", 0); !ok {
		t.Error("2nd request should pass")
	}
	if ok, reason := q.Allow("ten1", 0); ok || reason == "" {
		t.Error("3rd request should be rate limited")
	}
	// After the window rolls, requests are allowed again.
	clock.advance(61 * time.Second)
	if ok, _ := q.Allow("ten1", 0); !ok {
		t.Error("request after window reset should pass")
	}
}

func TestQuotaTokenLimit(t *testing.T) {
	clock := &fakeClk{t: time.Unix(1000, 0)}
	q := NewQuotaManager()
	q.now = clock.now
	q.SetQuota("ten1", Quota{MaxTokensPerDay: 1000})

	if ok, _ := q.Allow("ten1", 600); !ok {
		t.Error("600 tokens should pass")
	}
	if ok, reason := q.Allow("ten1", 600); ok || reason == "" {
		t.Error("exceeding daily tokens should be denied")
	}
}

func TestQuotaUnlimitedByDefault(t *testing.T) {
	q := NewQuotaManager()
	for i := 0; i < 1000; i++ {
		if ok, _ := q.Allow("no-quota-tenant", 100000); !ok {
			t.Fatal("tenant without quota should be unlimited")
		}
	}
}

func TestQuotaSettleTokens(t *testing.T) {
	clock := &fakeClk{t: time.Unix(1000, 0)}
	q := NewQuotaManager()
	q.now = clock.now
	q.SetQuota("ten1", Quota{MaxTokensPerDay: 1000})

	q.Allow("ten1", 100)             // reserve 100
	q.SettleTokens("ten1", 100, 900) // actual was 900
	// Now only 100 left; a 200-token request should be denied.
	if ok, _ := q.Allow("ten1", 200); ok {
		t.Error("settle should have consumed the higher actual token count")
	}
}

// --- HTTP upstream against a mock provider server ---

func TestHTTPUpstreamForwardsWithKey(t *testing.T) {
	var gotAuth string
	var gotBody []byte
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}`))
	}))
	defer provider.Close()

	vault := NewMemKeyVault()
	_ = vault.SetKey("ten1", "OpenAI", "sk-tenant-key")
	up := NewHTTPUpstream(vault)
	up.SetEndpoint("OpenAI", ProviderEndpoint{URL: provider.URL, AuthStyle: AuthBearer})

	hdr := http.Header{}
	hdr.Set("X-NeuroSentry-Tenant", "ten1")
	status, body, _, err := up.Forward(context.Background(), "OpenAI", []byte(`{"model":"gpt-4o"}`), hdr)
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Errorf("expected 200, got %d", status)
	}
	if gotAuth != "Bearer sk-tenant-key" {
		t.Errorf("upstream did not receive injected key, got %q", gotAuth)
	}
	if len(gotBody) == 0 {
		t.Error("upstream received empty body")
	}
	if _, c, _ := parseResponseUsage(body); c != 7 {
		t.Error("response usage not passed through")
	}
}

func TestHTTPUpstreamMissingKey(t *testing.T) {
	up := NewHTTPUpstream(NewMemKeyVault())
	hdr := http.Header{}
	hdr.Set("X-NeuroSentry-Tenant", "ten-without-key")
	if _, _, _, err := up.Forward(context.Background(), "OpenAI", []byte(`{}`), hdr); err == nil {
		t.Error("missing key should error")
	}
}

// --- Full metered relay end-to-end ---

func TestMeteredRelayEndToEnd(t *testing.T) {
	// Mock provider returns a usage object.
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Paris"}}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`))
	}))
	defer provider.Close()

	vault := NewMemKeyVault()
	_ = vault.SetKey("ten1", "OpenAI", "sk-key")
	up := NewHTTPUpstream(vault)
	up.SetEndpoint("OpenAI", ProviderEndpoint{URL: provider.URL, AuthStyle: AuthBearer})

	tracker := NewUsageTracker()
	quota := NewQuotaManager()
	quota.SetQuota("ten1", Quota{MaxRequestsPerMin: 10})

	guards := []Guard{
		NewInjectionGuard(aiguard.NewInjectionDetector(), aiguard.VerdictMalicious),
		NewDLPGuard(aiguard.NewSecretScanner()),
	}
	g := New(Config{BlockOnDetect: true}, up, guards, nil).WithMetering(quota, tracker)

	body, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "What is the capital of France?"}},
	})
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("X-NeuroSentry-Tenant", "ten1")
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("metered relay should succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	// Usage recorded from the provider's usage object.
	u := tracker.Usage("ten1")
	if u.Requests != 1 || u.PromptTokens != 10 || u.CompletionTokens != 2 {
		t.Errorf("usage not recorded correctly: %+v", u)
	}
	if u.CostUSD <= 0 {
		t.Error("cost should be computed")
	}
}

func TestMeteredRelayEnforcesQuota(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"usage":{"total_tokens":1}}`))
	}))
	defer provider.Close()

	vault := NewMemKeyVault()
	_ = vault.SetKey("ten1", "OpenAI", "sk-key")
	up := NewHTTPUpstream(vault)
	up.SetEndpoint("OpenAI", ProviderEndpoint{URL: provider.URL})

	quota := NewQuotaManager()
	quota.SetQuota("ten1", Quota{MaxRequestsPerMin: 1})
	g := New(Config{BlockOnDetect: true}, up, nil, nil).WithMetering(quota, NewUsageTracker())

	mk := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []map[string]string{{"role": "user", "content": "hi"}}})
		req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("X-NeuroSentry-Tenant", "ten1")
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)
		return rec
	}

	if mk().Code != http.StatusOK {
		t.Fatal("first request should pass quota")
	}
	if code := mk().Code; code != http.StatusTooManyRequests {
		t.Errorf("second request should be rate-limited (429), got %d", code)
	}
}

// fakeClk is a deterministic clock for quota tests.
type fakeClk struct{ t time.Time }

func (c *fakeClk) now() time.Time          { return c.t }
func (c *fakeClk) advance(d time.Duration) { c.t = c.t.Add(d) }
