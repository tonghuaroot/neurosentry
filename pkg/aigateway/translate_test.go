// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aigateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/aiguard"
)

func TestAnthropicRequestTranslation(t *testing.T) {
	tr := NewAnthropicTranslator()
	openAI := []byte(`{
		"model":"claude-sonnet-4",
		"messages":[
			{"role":"system","content":"You are helpful."},
			{"role":"user","content":"Hello"}
		],
		"max_tokens":256
	}`)
	out, err := tr.TranslateRequest(openAI)
	if err != nil {
		t.Fatal(err)
	}
	var req anthropicRequest
	if err := json.Unmarshal(out, &req); err != nil {
		t.Fatal(err)
	}
	if req.System != "You are helpful." {
		t.Errorf("system prompt not lifted: %q", req.System)
	}
	if len(req.Messages) != 1 || req.Messages[0].Role != "user" {
		t.Errorf("system message should be removed from messages: %+v", req.Messages)
	}
	if req.MaxTokens != 256 {
		t.Errorf("max_tokens not carried: %d", req.MaxTokens)
	}
}

func TestAnthropicRequestDefaultMaxTokens(t *testing.T) {
	tr := NewAnthropicTranslator()
	out, _ := tr.TranslateRequest([]byte(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
	var req anthropicRequest
	_ = json.Unmarshal(out, &req)
	if req.MaxTokens != 4096 {
		t.Errorf("expected default max_tokens 4096, got %d", req.MaxTokens)
	}
}

func TestAnthropicResponseTranslation(t *testing.T) {
	tr := NewAnthropicTranslator()
	anthropic := []byte(`{
		"id":"msg_123","model":"claude-sonnet-4",
		"content":[{"type":"text","text":"The capital is Paris."}],
		"stop_reason":"end_turn",
		"usage":{"input_tokens":15,"output_tokens":6}
	}`)
	out, err := tr.TranslateResponse(anthropic)
	if err != nil {
		t.Fatal(err)
	}
	var resp oaiResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Object != "chat.completion" {
		t.Errorf("wrong object type: %s", resp.Object)
	}
	if len(resp.Choices) != 1 || resp.Choices[0].Message.Content != "The capital is Paris." {
		t.Errorf("content not mapped: %+v", resp.Choices)
	}
	if resp.Choices[0].FinishReason != "stop" {
		t.Errorf("stop reason not mapped: %s", resp.Choices[0].FinishReason)
	}
	if resp.Usage.PromptTokens != 15 || resp.Usage.CompletionTokens != 6 || resp.Usage.TotalTokens != 21 {
		t.Errorf("usage not mapped: %+v", resp.Usage)
	}
}

func TestStopReasonMapping(t *testing.T) {
	cases := map[string]string{
		"end_turn":      "stop",
		"max_tokens":    "length",
		"tool_use":      "tool_calls",
		"stop_sequence": "stop",
		"":              "stop",
	}
	for in, want := range cases {
		if got := mapAnthropicStop(in); got != want {
			t.Errorf("mapAnthropicStop(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAnthropicRelayEndToEnd drives an OpenAI-format request through the gateway
// to a mock Anthropic-native server and asserts the client gets OpenAI format
// back — proving the universal-relay translation works inline.
func TestAnthropicRelayEndToEnd(t *testing.T) {
	var receivedNative anthropicRequest
	var receivedKey string
	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("x-api-key")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedNative)
		// Respond in Anthropic-native format.
		_, _ = w.Write([]byte(`{"id":"msg_1","model":"claude-sonnet-4","content":[{"type":"text","text":"Bonjour"}],"stop_reason":"end_turn","usage":{"input_tokens":8,"output_tokens":3}}`))
	}))
	defer anthropicServer.Close()

	vault := NewMemKeyVault()
	_ = vault.SetKey("ten1", "Anthropic", "sk-ant-tenant-key")
	up := NewHTTPUpstream(vault)
	up.SetEndpoint("Anthropic", ProviderEndpoint{URL: anthropicServer.URL, AuthStyle: AuthAnthropic})

	tracker := NewUsageTracker()
	guards := []Guard{
		NewInjectionGuard(aiguard.NewInjectionDetector(), aiguard.VerdictMalicious),
		NewDLPGuard(aiguard.NewSecretScanner()),
	}
	g := New(Config{BlockOnDetect: true}, up, guards, nil).WithMetering(nil, tracker)

	// Client sends OpenAI format with a system message.
	openAIBody, _ := json.Marshal(map[string]any{
		"model": "claude-sonnet-4",
		"messages": []map[string]string{
			{"role": "system", "content": "Answer in French."},
			{"role": "user", "content": "Hello"},
		},
	})
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(openAIBody))
	req.Header.Set("X-NeuroSentry-Tenant", "ten1")
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("anthropic relay failed: %d %s", rec.Code, rec.Body.String())
	}

	// The Anthropic server must have received NATIVE format (system lifted).
	if receivedNative.System != "Answer in French." {
		t.Errorf("system not translated to native: %q", receivedNative.System)
	}
	if receivedKey != "sk-ant-tenant-key" {
		t.Errorf("anthropic key not injected: %q", receivedKey)
	}

	// The client must have received OpenAI format back.
	var clientResp oaiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &clientResp); err != nil {
		t.Fatal(err)
	}
	if len(clientResp.Choices) != 1 || clientResp.Choices[0].Message.Content != "Bonjour" {
		t.Errorf("client did not get OpenAI-format content: %s", rec.Body.String())
	}
	// Usage was parsed from the translated (OpenAI-shaped) body.
	if u := tracker.Usage("ten1"); u.PromptTokens != 8 || u.CompletionTokens != 3 {
		t.Errorf("usage not metered through translation: %+v", u)
	}
}

func TestUpstreamSetTranslatorNilClears(t *testing.T) {
	up := NewHTTPUpstream(NewMemKeyVault())
	up.SetTranslator("Anthropic", nil)
	if up.translators["Anthropic"] != nil {
		t.Error("nil translator should clear the entry")
	}
}
