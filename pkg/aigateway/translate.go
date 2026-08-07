// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aigateway

import (
	"encoding/json"
	"strings"
)

// Translator adapts between the gateway's canonical wire format (OpenAI
// chat-completions) and a provider that speaks a different schema. This is what
// lets a single OpenAI-compatible client reach any provider through the relay —
// the universal-gateway capability (cf. LiteLLM / OpenRouter). Providers that
// are already OpenAI-compatible need no translator.
type Translator interface {
	// TranslateRequest converts an OpenAI chat request into the provider's
	// native request body.
	TranslateRequest(openAIBody []byte) ([]byte, error)
	// TranslateResponse converts the provider's native response back into an
	// OpenAI chat-completion body, so all downstream metering/parsing stays
	// uniform.
	TranslateResponse(providerBody []byte) ([]byte, error)
}

// --- Anthropic ---

// AnthropicTranslator maps OpenAI chat-completions <-> Anthropic Messages API.
// The salient differences it reconciles: Anthropic lifts the system prompt to a
// top-level field, requires max_tokens, and returns content blocks with a
// different usage shape.
type AnthropicTranslator struct {
	// DefaultMaxTokens is used when the client omits max_tokens (Anthropic
	// requires it).
	DefaultMaxTokens int
}

// NewAnthropicTranslator returns a translator with a sane max_tokens default.
func NewAnthropicTranslator() *AnthropicTranslator {
	return &AnthropicTranslator{DefaultMaxTokens: 4096}
}

type oaiRequest struct {
	Model       string       `json:"model"`
	Messages    []oaiMessage `json:"messages"`
	MaxTokens   *int         `json:"max_tokens,omitempty"`
	Temperature *float64     `json:"temperature,omitempty"`
	Stream      *bool        `json:"stream,omitempty"`
}

type oaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature *float64           `json:"temperature,omitempty"`
	Stream      *bool              `json:"stream,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// TranslateRequest converts an OpenAI request to Anthropic's Messages format.
func (t *AnthropicTranslator) TranslateRequest(openAIBody []byte) ([]byte, error) {
	var in oaiRequest
	if err := json.Unmarshal(openAIBody, &in); err != nil {
		return nil, err
	}

	var systemParts []string
	msgs := make([]anthropicMessage, 0, len(in.Messages))
	for _, m := range in.Messages {
		if m.Role == "system" {
			systemParts = append(systemParts, m.Content)
			continue
		}
		msgs = append(msgs, anthropicMessage(m))
	}

	maxTok := t.DefaultMaxTokens
	if in.MaxTokens != nil && *in.MaxTokens > 0 {
		maxTok = *in.MaxTokens
	}

	out := anthropicRequest{
		Model:       in.Model,
		System:      strings.Join(systemParts, "\n"),
		Messages:    msgs,
		MaxTokens:   maxTok,
		Temperature: in.Temperature,
		Stream:      in.Stream,
	}
	return json.Marshal(out)
}

type anthropicResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
}

type oaiResponse struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Model   string      `json:"model"`
	Choices []oaiChoice `json:"choices"`
	Usage   oaiUsage    `json:"usage"`
}

type oaiChoice struct {
	Index        int        `json:"index"`
	Message      oaiMessage `json:"message"`
	FinishReason string     `json:"finish_reason"`
}

type oaiUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// TranslateResponse converts an Anthropic Messages response into an OpenAI
// chat-completion response.
func (t *AnthropicTranslator) TranslateResponse(providerBody []byte) ([]byte, error) {
	var in anthropicResponse
	if err := json.Unmarshal(providerBody, &in); err != nil {
		return nil, err
	}

	var text strings.Builder
	for _, c := range in.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}

	out := oaiResponse{
		ID:     in.ID,
		Object: "chat.completion",
		Model:  in.Model,
		Choices: []oaiChoice{{
			Index:        0,
			Message:      oaiMessage{Role: "assistant", Content: text.String()},
			FinishReason: mapAnthropicStop(in.StopReason),
		}},
		Usage: oaiUsage{
			PromptTokens:     in.Usage.InputTokens,
			CompletionTokens: in.Usage.OutputTokens,
			TotalTokens:      in.Usage.InputTokens + in.Usage.OutputTokens,
		},
	}
	return json.Marshal(out)
}

// mapAnthropicStop normalizes Anthropic stop reasons to OpenAI finish reasons.
func mapAnthropicStop(reason string) string {
	switch reason {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	default:
		if reason == "" {
			return "stop"
		}
		return reason
	}
}
