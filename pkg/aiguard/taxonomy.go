// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package aiguard

// Threat taxonomy: findings are mapped to industry-standard frameworks so they
// slot into existing SOC workflows and compliance reporting. Two frameworks are
// referenced: the OWASP Top 10 for LLM Applications and MITRE ATLAS.

// OWASPCategory is an OWASP LLM Top 10 (2025) identifier.
type OWASPCategory struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

var owaspLLM = map[string]OWASPCategory{
	"LLM01": {"LLM01", "Prompt Injection"},
	"LLM02": {"LLM02", "Sensitive Information Disclosure"},
	"LLM03": {"LLM03", "Supply Chain"},
	"LLM04": {"LLM04", "Data and Model Poisoning"},
	"LLM05": {"LLM05", "Improper Output Handling"},
	"LLM06": {"LLM06", "Excessive Agency"},
	"LLM07": {"LLM07", "System Prompt Leakage"},
	"LLM08": {"LLM08", "Vector and Embedding Weaknesses"},
	"LLM09": {"LLM09", "Misinformation"},
	"LLM10": {"LLM10", "Unbounded Consumption"},
}

// LookupOWASP returns the OWASP category for an id, or false if unknown.
func LookupOWASP(id string) (OWASPCategory, bool) {
	c, ok := owaspLLM[id]
	return c, ok
}

// ATLASTechnique is a MITRE ATLAS technique reference relevant to runtime AI
// defense.
type ATLASTechnique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// atlasForOWASP maps an OWASP LLM category to the closest MITRE ATLAS technique,
// so a single detection carries both a developer-facing (OWASP) and a
// SOC/threat-intel-facing (ATLAS) label.
var atlasForOWASP = map[string]ATLASTechnique{
	"LLM01": {"AML.T0051", "LLM Prompt Injection"},
	"LLM02": {"AML.T0057", "LLM Data Leakage"},
	"LLM03": {"AML.T0010", "ML Supply Chain Compromise"},
	"LLM04": {"AML.T0020", "Poison Training Data"},
	"LLM06": {"AML.T0053", "LLM Plugin Compromise"},
	"LLM07": {"AML.T0056", "LLM Meta Prompt Extraction"},
	"LLM10": {"AML.T0034", "Cost Harvesting"},
}

// MapTechnique resolves a taxonomy id (e.g. "LLM01") to its OWASP category and
// associated ATLAS technique, if known.
func MapTechnique(id string) (OWASPCategory, *ATLASTechnique) {
	owasp, ok := LookupOWASP(id)
	if !ok {
		return OWASPCategory{}, nil
	}
	if atlas, ok := atlasForOWASP[id]; ok {
		return owasp, &atlas
	}
	return owasp, nil
}

// Finding is a taxonomy-enriched security finding suitable for emitting to the
// audit chain, SIEM, or dashboard.
type Finding struct {
	Source  string          `json:"source"` // "injection", "egress", "dlp"
	Verdict string          `json:"verdict"`
	Score   float64         `json:"score,omitempty"`
	OWASP   *OWASPCategory  `json:"owasp,omitempty"`
	ATLAS   *ATLASTechnique `json:"atlas,omitempty"`
	Detail  string          `json:"detail,omitempty"`
}

// EnrichInjection converts an InjectionResult into taxonomy-tagged findings
// (one per distinct technique), ready for downstream reporting.
func EnrichInjection(r InjectionResult) []Finding {
	var findings []Finding
	for _, tech := range r.Techniques {
		owasp, atlas := MapTechnique(tech)
		var owaspPtr *OWASPCategory
		if owasp.ID != "" {
			owaspPtr = &owasp
		}
		findings = append(findings, Finding{
			Source:  "injection",
			Verdict: string(r.Verdict),
			Score:   r.Score,
			OWASP:   owaspPtr,
			ATLAS:   atlas,
		})
	}
	return findings
}
