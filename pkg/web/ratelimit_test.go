// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterBurstThenRefill(t *testing.T) {
	clk := &rlClock{t: time.Unix(1000, 0)}
	rl := newRateLimiter(10, 3) // 10/s, burst 3
	rl.now = clk.now

	// First 3 allowed (burst), 4th denied.
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Error("4th request should be denied (burst exhausted)")
	}

	// After 0.2s at 10/s, 2 tokens refill.
	clk.advance(200 * time.Millisecond)
	a1 := rl.allow("1.2.3.4")
	a2 := rl.allow("1.2.3.4")
	if !a1 || !a2 {
		t.Error("two refilled tokens should be allowed")
	}
	if rl.allow("1.2.3.4") {
		t.Error("third after partial refill should be denied")
	}
}

func TestRateLimiterPerClientIsolation(t *testing.T) {
	clk := &rlClock{t: time.Unix(1000, 0)}
	rl := newRateLimiter(1, 1)
	rl.now = clk.now
	rl.allow("a") // exhaust a
	if rl.allow("a") {
		t.Error("a should be limited")
	}
	if !rl.allow("b") {
		t.Error("b must be independent of a")
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	clk := &rlClock{t: time.Unix(1000, 0)}
	rl := newRateLimiter(1, 2)
	rl.now = clk.now
	h := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	call := func(path, ip string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = ip + ":5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// API path: burst 2 ok, 3rd is 429.
	c1 := call("/api/status", "9.9.9.9")
	c2 := call("/api/status", "9.9.9.9")
	if c1 != 200 || c2 != 200 {
		t.Fatal("first two API calls should pass")
	}
	if code := call("/api/status", "9.9.9.9"); code != http.StatusTooManyRequests {
		t.Errorf("third API call should be 429, got %d", code)
	}
	// Non-API path is never limited.
	for i := 0; i < 5; i++ {
		if call("/", "9.9.9.9") != 200 {
			t.Error("dashboard path must not be rate-limited")
		}
	}
	// A different client is unaffected.
	if call("/api/status", "8.8.8.8") != 200 {
		t.Error("different client should not be limited")
	}
}

func TestClientIPForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if ip := clientIP(req); ip != "203.0.113.7" {
		t.Errorf("expected leftmost XFF ip, got %s", ip)
	}
}

type rlClock struct{ t time.Time }

func (c *rlClock) now() time.Time          { return c.t }
func (c *rlClock) advance(d time.Duration) { c.t = c.t.Add(d) }
