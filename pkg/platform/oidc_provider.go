// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OIDCProvider is the live side of OIDC SSO: it discovers the IdP's JWKS
// endpoint, fetches and caches the signing keys, and refreshes them on key
// rotation (an unknown kid triggers at most one rate-limited refetch). It wraps
// the pure OIDCVerifier with current keys.
type OIDCProvider struct {
	cfg        OIDCConfig
	jwksURI    string
	httpClient *http.Client
	now        func() time.Time
	minRefresh time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

type discoveryDoc struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// NewOIDCProvider discovers the IdP configuration from the issuer's
// well-known endpoint, fetches its JWKS, and returns a ready provider.
func NewOIDCProvider(ctx context.Context, cfg OIDCConfig, client *http.Client) (*OIDCProvider, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	p := &OIDCProvider{
		cfg:        cfg,
		httpClient: client,
		now:        time.Now,
		minRefresh: time.Minute,
	}

	disco, err := p.fetchDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	if disco.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("oidc: discovery issuer %q != configured %q", disco.Issuer, cfg.Issuer)
	}
	p.jwksURI = disco.JWKSURI
	if err := p.refreshKeys(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *OIDCProvider) fetchDiscovery(ctx context.Context) (*discoveryDoc, error) {
	url := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	body, err := p.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery fetch: %w", err)
	}
	var d discoveryDoc
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("oidc: discovery parse: %w", err)
	}
	if d.JWKSURI == "" {
		return nil, fmt.Errorf("oidc: discovery missing jwks_uri")
	}
	return &d, nil
}

func (p *OIDCProvider) refreshKeys(ctx context.Context) error {
	body, err := p.get(ctx, p.jwksURI)
	if err != nil {
		return fmt.Errorf("oidc: jwks fetch: %w", err)
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.keys = keys
	p.fetchedAt = p.now()
	p.mu.Unlock()
	return nil
}

func (p *OIDCProvider) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// Verify validates an ID token against the current keys. If the token's key id
// is unknown (likely a rotation), it refetches the JWKS once — rate-limited by
// minRefresh — before failing.
func (p *OIDCProvider) Verify(ctx context.Context, idToken string) (*OIDCClaims, error) {
	claims, err := p.verifyWithCurrentKeys(idToken)
	if err == nil || !strings.Contains(err.Error(), "unknown signing key") {
		return claims, err
	}
	p.mu.RLock()
	stale := p.now().Sub(p.fetchedAt) > p.minRefresh
	p.mu.RUnlock()
	if !stale {
		return nil, err
	}
	if rerr := p.refreshKeys(ctx); rerr != nil {
		return nil, err // return the original verification error
	}
	return p.verifyWithCurrentKeys(idToken)
}

func (p *OIDCProvider) verifyWithCurrentKeys(idToken string) (*OIDCClaims, error) {
	p.mu.RLock()
	keys := p.keys
	p.mu.RUnlock()
	return NewOIDCVerifier(p.cfg, keys).Verify(idToken)
}

// MapRoles resolves IdP groups to NeuroSentry roles per the provider config.
func (p *OIDCProvider) MapRoles(groups []string) []Role { return p.cfg.MapRoles(groups) }
