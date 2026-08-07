// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package aiguard implements NeuroSentry's AI-native security layer: it
// understands the semantics of AI/LLM traffic that generic syscall monitors
// cannot. It classifies outbound AI API destinations (shadow-AI detection),
// detects prompt-injection / jailbreak attempts, and maps findings to the
// OWASP LLM Top 10 and MITRE ATLAS taxonomies.
//
// The detectors are deterministic heuristics — the first, cheap line of
// defense that handles the bulk of known-shape threats. They are designed to
// front an optional ML/LLM classifier (pluggable via the Detector interface)
// for the residual novel cases.
package aiguard

import "strings"

// ProviderCategory groups AI endpoints by what they expose.
type ProviderCategory string

const (
	CategoryLLM       ProviderCategory = "llm"       // chat/completion APIs
	CategoryModelHub  ProviderCategory = "model_hub" // model download/hosting
	CategoryVectorDB  ProviderCategory = "vector_db" // embeddings / RAG stores
	CategoryInference ProviderCategory = "inference" // hosted inference platforms
)

// AIProvider describes a known AI service and the hostnames it serves from.
type AIProvider struct {
	Name     string           `json:"name"`
	Category ProviderCategory `json:"category"`
	Domains  []string         `json:"domains"`
}

// catalog is a curated set of well-known AI providers (mid-2026). It is
// intentionally data-driven so operators can extend it via config without code
// changes. Matching is by domain suffix.
var catalog = []AIProvider{
	{"OpenAI", CategoryLLM, []string{"api.openai.com", "openai.azure.com"}},
	{"Anthropic", CategoryLLM, []string{"api.anthropic.com"}},
	{"Google Gemini", CategoryLLM, []string{"generativelanguage.googleapis.com", "aiplatform.googleapis.com"}},
	{"Azure OpenAI", CategoryLLM, []string{"openai.azure.com", "cognitiveservices.azure.com"}},
	{"AWS Bedrock", CategoryLLM, []string{"bedrock-runtime.amazonaws.com", "bedrock.amazonaws.com"}},
	{"Cohere", CategoryLLM, []string{"api.cohere.ai", "api.cohere.com"}},
	{"Mistral", CategoryLLM, []string{"api.mistral.ai"}},
	{"Groq", CategoryLLM, []string{"api.groq.com"}},
	{"Perplexity", CategoryLLM, []string{"api.perplexity.ai"}},
	{"xAI", CategoryLLM, []string{"api.x.ai"}},
	{"DeepSeek", CategoryLLM, []string{"api.deepseek.com"}},
	{"Together AI", CategoryInference, []string{"api.together.xyz", "api.together.ai"}},
	{"Replicate", CategoryInference, []string{"api.replicate.com"}},
	{"Fireworks AI", CategoryInference, []string{"api.fireworks.ai"}},
	{"OpenRouter", CategoryLLM, []string{"openrouter.ai"}},
	{"Hugging Face", CategoryModelHub, []string{"huggingface.co", "hf.co"}},
	{"Pinecone", CategoryVectorDB, []string{"pinecone.io"}},
	{"Weaviate", CategoryVectorDB, []string{"weaviate.io", "weaviate.network"}},
	{"Qdrant", CategoryVectorDB, []string{"qdrant.io", "cloud.qdrant.io"}},
}

// Catalog is a domain-indexed classifier for AI endpoints.
type Catalog struct {
	byDomain  map[string]*AIProvider
	providers []AIProvider
}

// NewCatalog builds the classifier from the built-in provider set.
func NewCatalog() *Catalog {
	c := &Catalog{byDomain: make(map[string]*AIProvider)}
	c.providers = append(c.providers, catalog...)
	c.reindex()
	return c
}

func (c *Catalog) reindex() {
	c.byDomain = make(map[string]*AIProvider)
	for i := range c.providers {
		p := &c.providers[i]
		for _, d := range p.Domains {
			c.byDomain[strings.ToLower(d)] = p
		}
	}
}

// AddProvider registers a custom AI provider (e.g. an internal gateway or a
// niche vendor) at runtime.
func (c *Catalog) AddProvider(p AIProvider) {
	c.providers = append(c.providers, p)
	c.reindex()
}

// Classify identifies the AI provider serving a hostname, matching by exact
// host or any parent-domain suffix (so "eu.api.openai.com" matches
// "api.openai.com"). Returns nil if the host is not a known AI endpoint.
func (c *Catalog) Classify(host string) *AIProvider {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	// Strip any :port.
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if p, ok := c.byDomain[host]; ok {
		return p
	}
	// Suffix match against every known domain.
	for domain, p := range c.byDomain {
		if strings.HasSuffix(host, "."+domain) || host == domain {
			return p
		}
	}
	return nil
}

// IsAIEndpoint reports whether a host is any known AI provider.
func (c *Catalog) IsAIEndpoint(host string) bool {
	return c.Classify(host) != nil
}

// EgressPolicy enforces which AI providers an environment may reach. Any AI
// endpoint not on the allowlist is "shadow AI" — an unsanctioned service that
// may be exfiltrating data or incurring untracked cost/risk.
type EgressPolicy struct {
	catalog    *Catalog
	allowed    map[string]struct{} // provider names
	allowNonAI bool                // permit non-AI destinations (default true)
}

// NewEgressPolicy builds a policy over a catalog. allowedProviders is the set
// of sanctioned AI provider names; an empty set means no AI egress is allowed.
func NewEgressPolicy(cat *Catalog, allowedProviders []string) *EgressPolicy {
	allowed := make(map[string]struct{})
	for _, name := range allowedProviders {
		allowed[name] = struct{}{}
	}
	return &EgressPolicy{catalog: cat, allowed: allowed, allowNonAI: true}
}

// EgressVerdict is the decision for one outbound destination.
type EgressVerdict struct {
	Host     string      `json:"host"`
	Provider *AIProvider `json:"provider,omitempty"`
	IsAI     bool        `json:"is_ai"`
	Allowed  bool        `json:"allowed"`
	ShadowAI bool        `json:"shadow_ai"`
	Reason   string      `json:"reason,omitempty"`
}

// Evaluate classifies a destination host and decides whether it is permitted.
func (p *EgressPolicy) Evaluate(host string) EgressVerdict {
	prov := p.catalog.Classify(host)
	v := EgressVerdict{Host: host, Provider: prov, IsAI: prov != nil}

	if prov == nil {
		v.Allowed = p.allowNonAI
		if !v.Allowed {
			v.Reason = "non-AI egress blocked by policy"
		}
		return v
	}
	if _, ok := p.allowed[prov.Name]; ok {
		v.Allowed = true
		return v
	}
	v.Allowed = false
	v.ShadowAI = true
	v.Reason = "unsanctioned AI provider: " + prov.Name
	return v
}
