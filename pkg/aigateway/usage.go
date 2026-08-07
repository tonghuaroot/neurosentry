// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aigateway

import (
	"encoding/json"
	"strings"
	"sync"
)

// ModelPricing is the per-million-token price for a model (USD). Used to turn
// token counts into a billable cost — the foundation of a relay's metering.
type ModelPricing struct {
	InputPer1M  float64 `json:"input_per_1m"`
	OutputPer1M float64 `json:"output_per_1m"`
}

// UsageRecord is the accumulated consumption for one tenant.
type UsageRecord struct {
	Requests         int64   `json:"requests"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	CostUSD          float64 `json:"cost_usd"`
}

// defaultPricing is an indicative price table (mid-2026, USD per 1M tokens).
// Operators override it; unknown models fall back to a conservative default.
var defaultPricing = map[string]ModelPricing{
	"gpt-4o":            {2.50, 10.00},
	"gpt-4o-mini":       {0.15, 0.60},
	"o1":                {15.00, 60.00},
	"claude-3-5-sonnet": {3.00, 15.00},
	"claude-opus-4":     {15.00, 75.00},
	"claude-sonnet-4":   {3.00, 15.00},
	"gemini-2.0-flash":  {0.10, 0.40},
	"mistral-large":     {2.00, 6.00},
	"deepseek-chat":     {0.27, 1.10},
}

var fallbackPricing = ModelPricing{InputPer1M: 1.00, OutputPer1M: 3.00}

// UsageTracker accumulates per-tenant token usage and cost. Safe for concurrent
// use.
type UsageTracker struct {
	mu       sync.Mutex
	byTenant map[string]*UsageRecord
	pricing  map[string]ModelPricing
}

// NewUsageTracker returns a tracker seeded with the default price table.
func NewUsageTracker() *UsageTracker {
	pricing := make(map[string]ModelPricing, len(defaultPricing))
	for k, v := range defaultPricing {
		pricing[k] = v
	}
	return &UsageTracker{byTenant: make(map[string]*UsageRecord), pricing: pricing}
}

// SetPricing overrides the price for a model.
func (t *UsageTracker) SetPricing(model string, p ModelPricing) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pricing[model] = p
}

// Record adds one request's token usage for a tenant and updates its cost.
func (t *UsageTracker) Record(tenant, model string, promptTokens, completionTokens int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byTenant[tenant]
	if rec == nil {
		rec = &UsageRecord{}
		t.byTenant[tenant] = rec
	}
	rec.Requests++
	rec.PromptTokens += promptTokens
	rec.CompletionTokens += completionTokens

	price := t.priceFor(model)
	cost := float64(promptTokens)/1e6*price.InputPer1M +
		float64(completionTokens)/1e6*price.OutputPer1M
	rec.CostUSD = roundCost(rec.CostUSD + cost)
}

// Usage returns a snapshot of a tenant's consumption.
func (t *UsageTracker) Usage(tenant string) UsageRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	if rec, ok := t.byTenant[tenant]; ok {
		return *rec
	}
	return UsageRecord{}
}

// priceFor resolves a model to a price, matching by prefix so versioned model
// ids (e.g. "gpt-4o-2024-11") inherit the base model's price. Falls back to a
// conservative default. Caller holds the lock.
func (t *UsageTracker) priceFor(model string) ModelPricing {
	if p, ok := t.pricing[model]; ok {
		return p
	}
	for base, p := range t.pricing {
		if strings.HasPrefix(model, base) {
			return p
		}
	}
	return fallbackPricing
}

// usageEnvelope matches the `usage` object OpenAI-compatible providers return.
type usageEnvelope struct {
	Usage struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
		TotalTokens      int64 `json:"total_tokens"`
	} `json:"usage"`
}

// parseResponseUsage extracts token counts from a provider response body.
// Returns ok=false when the response carries no usage object.
func parseResponseUsage(body []byte) (prompt, completion int64, ok bool) {
	var env usageEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return 0, 0, false
	}
	if env.Usage.TotalTokens == 0 && env.Usage.PromptTokens == 0 && env.Usage.CompletionTokens == 0 {
		return 0, 0, false
	}
	return env.Usage.PromptTokens, env.Usage.CompletionTokens, true
}

// estimateTokens is a coarse token estimate (~4 chars/token) used for
// pre-flight quota checks before the real usage is known.
func estimateTokens(text string) int64 {
	if text == "" {
		return 0
	}
	return int64(len(text)/4) + 1
}

// roundCost keeps 6 decimal places so sub-cent per-request costs are preserved
// for accurate billing accumulation.
func roundCost(f float64) float64 {
	return float64(int(f*1e6+0.5)) / 1e6
}
