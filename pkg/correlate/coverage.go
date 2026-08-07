// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package correlate

import "sort"

// Framework-coverage mapping. Buyers and auditors ask "which MITRE ATT&CK and
// OWASP-LLM / ATLAS techniques does this actually detect?" This turns the live
// detection catalog into that answer: distinct techniques covered, how many
// rules back each, and whether the coverage is currently enabled — so gaps are
// visible rather than assumed.

// TechniqueCoverage is one framework technique and the rules that cover it.
type TechniqueCoverage struct {
	Framework   string   `json:"framework"` // "MITRE ATT&CK" | "OWASP LLM"
	ID          string   `json:"id"`        // e.g. "T1041" | "LLM01"
	Name        string   `json:"name"`      // human-readable technique name
	RuleCount   int      `json:"rule_count"`
	EnabledInID int      `json:"enabled_rules"`
	Rules       []string `json:"rules"` // rule IDs covering it
}

// CoverageReport is the framework-coverage view of the detection library.
type CoverageReport struct {
	Techniques    []TechniqueCoverage `json:"techniques"`
	TotalTechs    int                 `json:"total_techniques"`
	CoveredTechs  int                 `json:"covered_techniques"` // techniques with >=1 enabled rule
	TotalRules    int                 `json:"total_rules"`
	EnabledRules  int                 `json:"enabled_rules"`
	ATTACKCovered int                 `json:"attack_techniques"`
	LLMCovered    int                 `json:"llm_techniques"`
}

// attackNames maps the ATT&CK technique IDs used by the built-in rules to names.
var attackNames = map[string]string{
	"T1041":     "Exfiltration Over C2 Channel",
	"T1567":     "Exfiltration Over Web Service",
	"T1059":     "Command and Scripting Interpreter",
	"T1059.004": "Unix Shell",
	"T1195":     "Supply Chain Compromise",
	"T1030":     "Data Transfer Size Limits",
	"T1611":     "Escape to Host",
	"T1552":     "Unsecured Credentials",
}

// llmNames maps OWASP-LLM / ATLAS technique IDs to names.
var llmNames = map[string]string{
	"LLM01": "Prompt Injection",
	"LLM02": "Sensitive Information Disclosure",
	"LLM03": "Supply Chain Vulnerabilities",
	"LLM06": "Excessive Agency",
	"LLM10": "Model Theft",
}

// ComputeCoverage aggregates a detection catalog into framework coverage.
func ComputeCoverage(dets []DetectionInfo) CoverageReport {
	type acc struct {
		framework, name string
		rules           []string
		enabled         int
	}
	byKey := map[string]*acc{}

	add := func(framework, id, name, ruleID string, enabled bool) {
		if id == "" {
			return
		}
		key := framework + "|" + id
		a := byKey[key]
		if a == nil {
			a = &acc{framework: framework, name: name}
			byKey[key] = a
		}
		a.rules = append(a.rules, ruleID)
		if enabled {
			a.enabled++
		}
	}

	rep := CoverageReport{}
	for _, d := range dets {
		rep.TotalRules++
		if d.Enabled {
			rep.EnabledRules++
		}
		add("MITRE ATT&CK", d.MitreAttack, attackNames[d.MitreAttack], d.ID, d.Enabled)
		add("OWASP LLM", d.Technique, llmNames[d.Technique], d.ID, d.Enabled)
	}

	for key, a := range byKey {
		id := key[len(a.framework)+1:]
		name := a.name
		if name == "" {
			name = id
		}
		tc := TechniqueCoverage{
			Framework: a.framework, ID: id, Name: name,
			RuleCount: len(a.rules), EnabledInID: a.enabled, Rules: a.rules,
		}
		rep.Techniques = append(rep.Techniques, tc)
		rep.TotalTechs++
		if a.enabled > 0 {
			rep.CoveredTechs++
		}
		if a.framework == "MITRE ATT&CK" {
			rep.ATTACKCovered++
		} else {
			rep.LLMCovered++
		}
	}

	sort.Slice(rep.Techniques, func(i, j int) bool {
		if rep.Techniques[i].Framework != rep.Techniques[j].Framework {
			return rep.Techniques[i].Framework < rep.Techniques[j].Framework
		}
		return rep.Techniques[i].ID < rep.Techniques[j].ID
	})
	return rep
}
