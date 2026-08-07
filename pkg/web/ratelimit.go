// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimiter is a per-client token-bucket limiter protecting the API from
// abuse and accidental floods — a baseline control every production API needs.
// Keyed by client IP; refills at `rate` tokens/sec up to `burst`.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64
	burst   float64
	now     func() time.Time
	lastGC  time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(ratePerSec, burst float64) *rateLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 50
	}
	if burst <= 0 {
		burst = 100
	}
	return &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    ratePerSec,
		burst:   burst,
		now:     time.Now,
	}
}

// allow consumes a token for key, returning false when the bucket is empty.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()

	// Opportunistic GC of idle buckets to bound memory.
	if now.Sub(rl.lastGC) > time.Minute {
		for k, b := range rl.buckets {
			if now.Sub(b.last) > 5*time.Minute {
				delete(rl.buckets, k)
			}
		}
		rl.lastGC = now
	}

	b := rl.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}
	// Refill based on elapsed time.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// middleware applies the limiter to matching requests. Long-lived SSE streams
// are exempt (they are a single connection, not a request flood).
func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/events/stream" {
			if !rl.allow(clientIP(r)) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the caller IP, honoring X-Forwarded-For when present (the
// leftmost entry) so per-client limits work behind a reverse proxy.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
