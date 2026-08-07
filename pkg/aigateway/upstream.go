// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aigateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AuthStyle is how a provider expects its API key presented.
type AuthStyle int

const (
	AuthBearer    AuthStyle = iota // Authorization: Bearer <key>  (OpenAI-compatible)
	AuthAnthropic                  // x-api-key: <key> + anthropic-version
)

// ProviderEndpoint describes where and how to reach an upstream provider's
// OpenAI-compatible chat endpoint.
type ProviderEndpoint struct {
	URL       string
	AuthStyle AuthStyle
	// ExtraHeaders are static headers required by the provider (e.g. Anthropic's
	// version pin).
	ExtraHeaders map[string]string
}

// defaultEndpoints covers the providers that expose an OpenAI-compatible chat
// API. Most modern providers do; Anthropic uses a distinct schema and is
// included with its native auth (payload translation is a separate concern).
var defaultEndpoints = map[string]ProviderEndpoint{
	"OpenAI":        {URL: "https://api.openai.com/v1/chat/completions", AuthStyle: AuthBearer},
	"Mistral":       {URL: "https://api.mistral.ai/v1/chat/completions", AuthStyle: AuthBearer},
	"DeepSeek":      {URL: "https://api.deepseek.com/v1/chat/completions", AuthStyle: AuthBearer},
	"Groq":          {URL: "https://api.groq.com/openai/v1/chat/completions", AuthStyle: AuthBearer},
	"xAI":           {URL: "https://api.x.ai/v1/chat/completions", AuthStyle: AuthBearer},
	"Together AI":   {URL: "https://api.together.xyz/v1/chat/completions", AuthStyle: AuthBearer},
	"Fireworks AI":  {URL: "https://api.fireworks.ai/inference/v1/chat/completions", AuthStyle: AuthBearer},
	"OpenRouter":    {URL: "https://openrouter.ai/api/v1/chat/completions", AuthStyle: AuthBearer},
	"Google Gemini": {URL: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", AuthStyle: AuthBearer},
	"Anthropic": {URL: "https://api.anthropic.com/v1/messages", AuthStyle: AuthAnthropic,
		ExtraHeaders: map[string]string{"anthropic-version": "2023-06-01"}},
}

// HTTPUpstream forwards vetted requests to real providers, injecting each
// tenant's provider key from the vault. It satisfies the Upstream interface.
// Providers whose native schema differs from OpenAI (e.g. Anthropic) are wired
// with a Translator so the gateway stays OpenAI-uniform end to end.
type HTTPUpstream struct {
	client      *http.Client
	vault       KeyVault
	endpoints   map[string]ProviderEndpoint
	translators map[string]Translator
}

// NewHTTPUpstream builds an upstream over a key vault with the default provider
// endpoint table. Anthropic is pre-wired with its request/response translator.
func NewHTTPUpstream(vault KeyVault) *HTTPUpstream {
	eps := make(map[string]ProviderEndpoint, len(defaultEndpoints))
	for k, v := range defaultEndpoints {
		eps[k] = v
	}
	return &HTTPUpstream{
		client:      &http.Client{Timeout: 120 * time.Second},
		vault:       vault,
		endpoints:   eps,
		translators: map[string]Translator{"Anthropic": NewAnthropicTranslator()},
	}
}

// SetEndpoint overrides or adds a provider endpoint (e.g. to point at a private
// deployment or a test server).
func (u *HTTPUpstream) SetEndpoint(provider string, ep ProviderEndpoint) {
	u.endpoints[provider] = ep
}

// SetTranslator registers (or clears, with nil) a schema translator for a
// provider.
func (u *HTTPUpstream) SetTranslator(provider string, t Translator) {
	if t == nil {
		delete(u.translators, provider)
		return
	}
	u.translators[provider] = t
}

// Forward sends the request to the provider for the tenant named in the
// X-NeuroSentry-Tenant header, injecting that tenant's key.
func (u *HTTPUpstream) Forward(ctx context.Context, provider string, body []byte, header http.Header) (int, []byte, http.Header, error) {
	ep, ok := u.endpoints[provider]
	if !ok {
		return 0, nil, nil, fmt.Errorf("no endpoint configured for provider %q", provider)
	}
	tenant := header.Get("X-NeuroSentry-Tenant")
	key, ok := u.vault.GetKey(tenant, provider)
	if !ok {
		return 0, nil, nil, fmt.Errorf("no API key for tenant %q provider %q", tenant, provider)
	}

	// Translate the OpenAI-format request into the provider's native schema.
	translator := u.translators[provider]
	sendBody := body
	if translator != nil {
		tb, err := translator.TranslateRequest(body)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("request translation for %q: %w", provider, err)
		}
		sendBody = tb
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(sendBody))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	switch ep.AuthStyle {
	case AuthAnthropic:
		req.Header.Set("x-api-key", key)
	default:
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range ep.ExtraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := u.client.Do(req) //nolint:gosec // G704: upstream URL comes from the provider allowlist/config, not user input
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, nil, nil, err
	}

	// Translate the provider's native response back to OpenAI format so the
	// gateway's metering and the client both see a uniform schema. Only
	// translate successful bodies; pass error responses through untouched.
	if translator != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		ob, err := translator.TranslateResponse(respBody)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("response translation for %q: %w", provider, err)
		}
		respBody = ob
	}
	return resp.StatusCode, respBody, resp.Header, nil
}
