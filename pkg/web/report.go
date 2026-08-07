// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/neurosentry/neurosentry/pkg/incident"
)

// The executive report is the artifact a CISO forwards upward: a single
// point-in-time security-posture summary — coverage, activity, top risks, and
// evidence integrity — rendered as JSON (for automation) or a printable HTML
// page (for the board deck). It is composed entirely from live in-process state
// so it never drifts from what the console shows.

// PostureReport is the machine-readable executive summary.
type PostureReport struct {
	GeneratedAt   time.Time         `json:"generated_at"`
	Product       string            `json:"product"`
	PostureScore  int               `json:"posture_score"` // 0-100, higher is better
	PostureGrade  string            `json:"posture_grade"`
	Detections    detectionCoverage `json:"detections"`
	MitreCoverage []mitreTechnique  `json:"mitre_coverage"`
	Cases         incident.Stats    `json:"cases"`
	SeverityMix   map[string]int    `json:"severity_mix"`
	TopCases      []reportCase      `json:"top_cases"`
	Integrity     integrityStatus   `json:"integrity"`
	Protection    map[string]any    `json:"protection,omitempty"`
}

type detectionCoverage struct {
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
	Custom  int `json:"custom"`
}

type mitreTechnique struct {
	Technique string `json:"technique"`
	Name      string `json:"name"`
	Cases     int    `json:"cases"`
}

type reportCase struct {
	ID        string `json:"id"`
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Technique string `json:"technique,omitempty"`
	PID       int    `json:"pid"`
	Count     int    `json:"count"`
	Status    string `json:"status"`
}

type integrityStatus struct {
	Entries  int    `json:"entries"`
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

// handleReport serves GET /api/report?format=json|html.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	rep := s.buildReport()
	if strings.ToLower(r.URL.Query().Get("format")) == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderReportHTML(rep)))
		return
	}
	writeJSON(w, rep)
}

func (s *Server) buildReport() PostureReport {
	rep := PostureReport{
		GeneratedAt: time.Now().UTC(),
		Product:     "NeuroSentry",
		SeverityMix: map[string]int{},
	}

	// Detection catalog coverage + MITRE technique inventory (what we *can* catch).
	techNames := map[string]string{}
	if s.detectionsList != nil {
		for _, d := range s.detectionsList() {
			rep.Detections.Total++
			if d.Enabled {
				rep.Detections.Enabled++
			}
			if d.Custom {
				rep.Detections.Custom++
			}
			if d.MitreAttack != "" {
				techNames[d.MitreAttack] = d.Name
			}
		}
	}

	// Case activity: severity mix, top cases, MITRE techniques actually observed.
	techCases := map[string]int{}
	if s.cases != nil {
		rep.Cases = s.cases.Stats()
		all := s.cases.List(incident.Filter{})
		for _, c := range all {
			rep.SeverityMix[strings.ToLower(c.Severity)]++
			if c.MitreAttack != "" {
				techCases[c.MitreAttack]++
				if _, ok := techNames[c.MitreAttack]; !ok {
					techNames[c.MitreAttack] = c.Rule
				}
			} else if c.Technique != "" {
				techCases[c.Technique]++
				if _, ok := techNames[c.Technique]; !ok {
					techNames[c.Technique] = c.Rule
				}
			}
		}
		rep.TopCases = topCases(all)
	}

	for tech, name := range techNames {
		rep.MitreCoverage = append(rep.MitreCoverage, mitreTechnique{
			Technique: tech, Name: name, Cases: techCases[tech],
		})
	}
	sort.Slice(rep.MitreCoverage, func(i, j int) bool {
		if rep.MitreCoverage[i].Cases != rep.MitreCoverage[j].Cases {
			return rep.MitreCoverage[i].Cases > rep.MitreCoverage[j].Cases
		}
		return rep.MitreCoverage[i].Technique < rep.MitreCoverage[j].Technique
	})

	// Evidence integrity.
	rep.Integrity.Entries = len(s.auditChain.Entries())
	if err := s.auditChain.Verify(); err != nil {
		rep.Integrity.Verified = false
		rep.Integrity.Error = err.Error()
	} else {
		rep.Integrity.Verified = true
	}

	if s.configProvider != nil {
		rep.Protection = s.configProvider()
	}

	rep.PostureScore, rep.PostureGrade = scorePosture(rep)
	return rep
}

// topCases ranks by severity weight, then recurrence count, capped at 10.
func topCases(all []*incident.Case) []reportCase {
	sorted := make([]*incident.Case, len(all))
	copy(sorted, all)
	sort.Slice(sorted, func(i, j int) bool {
		wi, wj := sevWeight(sorted[i].Severity), sevWeight(sorted[j].Severity)
		if wi != wj {
			return wi > wj
		}
		return sorted[i].Count > sorted[j].Count
	})
	out := make([]reportCase, 0, 10)
	for _, c := range sorted {
		if len(out) >= 10 {
			break
		}
		out = append(out, reportCase{
			ID: c.ID, Rule: c.Rule, Severity: c.Severity, Technique: c.Technique,
			PID: c.PID, Count: c.Count, Status: string(c.Status),
		})
	}
	return out
}

func sevWeight(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// scorePosture derives a 0-100 posture score. It starts at 100 and deducts for
// unresolved risk (open critical/high cases) and evidence-integrity failure.
func scorePosture(rep PostureReport) (int, string) {
	score := 100
	openCrit := rep.SeverityMix["critical"]
	openHigh := rep.SeverityMix["high"]
	// Only unresolved cases weigh on posture.
	unresolved := rep.Cases.Open + rep.Cases.Acknowledged
	if unresolved > 0 {
		score -= min(40, openCrit*15+openHigh*7)
	}
	if !rep.Integrity.Verified {
		score -= 25
	}
	if rep.Detections.Enabled == 0 {
		score -= 20
	}
	if score < 0 {
		score = 0
	}
	grade := "A"
	switch {
	case score < 50:
		grade = "D"
	case score < 70:
		grade = "C"
	case score < 85:
		grade = "B"
	}
	return score, grade
}

func renderReportHTML(rep PostureReport) string {
	var b strings.Builder
	esc := html.EscapeString
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>NeuroSentry — Security Posture Report</title>`)
	b.WriteString(`<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:40px;color:#1a1f2b;background:#fff;max-width:900px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:#5b6472;margin:28px 0 10px;border-bottom:1px solid #e5e8ee;padding-bottom:6px}
.sub{color:#7a828f;font-size:13px;margin-bottom:20px}
.score{display:flex;align-items:center;gap:18px;margin:18px 0}
.badge{width:84px;height:84px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:34px;font-weight:700;color:#fff}
table{border-collapse:collapse;width:100%;font-size:13px;margin-top:6px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #eef0f4}th{color:#5b6472;font-weight:600}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.crit{background:#fde8e8;color:#c0392b}.high{background:#fdf0e3;color:#c47f17}.med{background:#fef8e0;color:#9a7d0a}.low{background:#e8f0fe;color:#2c5aa0}
.ok{color:#1e8e4f;font-weight:600}.bad{color:#c0392b;font-weight:600}
.kpis{display:flex;gap:24px;flex-wrap:wrap}.kpi{min-width:120px}.kpi .n{font-size:24px;font-weight:700}.kpi .l{font-size:12px;color:#7a828f}
@media print{body{margin:0}}
</style></head><body>`)

	b.WriteString(`<h1>Security Posture Report</h1>`)
	b.WriteString(`<div class="sub">NeuroSentry runtime protection for AI inference &middot; generated ` + esc(rep.GeneratedAt.Format("2006-01-02 15:04 UTC")) + `</div>`)

	color := "#1e8e4f"
	if rep.PostureScore < 85 {
		color = "#c47f17"
	}
	if rep.PostureScore < 70 {
		color = "#c0392b"
	}
	b.WriteString(`<div class="score"><div class="badge" style="background:` + color + `">` + esc(rep.PostureGrade) + `</div>`)
	fmt.Fprintf(&b, `<div><div style="font-size:30px;font-weight:700">%d<span style="font-size:16px;color:#7a828f">/100</span></div><div class="sub" style="margin:0">Overall posture score</div></div></div>`, rep.PostureScore)

	b.WriteString(`<h2>Coverage &amp; Activity</h2><div class="kpis">`)
	b.WriteString(kpi(rep.Detections.Enabled, "Detections enabled"))
	b.WriteString(kpi(rep.Detections.Custom, "Custom rules"))
	b.WriteString(kpi(len(rep.MitreCoverage), "MITRE techniques"))
	b.WriteString(kpi(rep.Cases.Total, "Total cases"))
	b.WriteString(kpi(rep.Cases.Open, "Open cases"))
	b.WriteString(kpi(rep.Integrity.Entries, "Audit records"))
	b.WriteString(`</div>`)

	b.WriteString(`<h2>Evidence Integrity</h2><p>`)
	if rep.Integrity.Verified {
		b.WriteString(`<span class="ok">&#10004; Verified</span> — the SHA-256 hash chain of ` + fmt.Sprint(rep.Integrity.Entries) + ` audit records is intact and tamper-evident.`)
	} else {
		b.WriteString(`<span class="bad">&#10008; Integrity check failed</span> — ` + esc(rep.Integrity.Error))
	}
	b.WriteString(`</p>`)

	if len(rep.MitreCoverage) > 0 {
		b.WriteString(`<h2>MITRE Technique Coverage</h2><table><tr><th>Technique</th><th>Detection</th><th>Observed cases</th></tr>`)
		for _, m := range rep.MitreCoverage {
			b.WriteString(`<tr><td><code>` + esc(m.Technique) + `</code></td><td>` + esc(m.Name) + `</td><td>` + fmt.Sprint(m.Cases) + `</td></tr>`)
		}
		b.WriteString(`</table>`)
	}

	if len(rep.TopCases) > 0 {
		b.WriteString(`<h2>Top Risks</h2><table><tr><th>Case</th><th>Detection</th><th>Severity</th><th>Technique</th><th>PID</th><th>Hits</th><th>Status</th></tr>`)
		for _, c := range rep.TopCases {
			b.WriteString(`<tr><td><code>` + esc(c.ID) + `</code></td><td>` + esc(c.Rule) + `</td><td>` + sevPill(c.Severity) + `</td><td>` + esc(c.Technique) + `</td><td>` + fmt.Sprint(c.PID) + `</td><td>` + fmt.Sprint(c.Count) + `</td><td>` + esc(c.Status) + `</td></tr>`)
		}
		b.WriteString(`</table>`)
	}

	b.WriteString(`</body></html>`)
	return b.String()
}

func kpi(n int, label string) string {
	return fmt.Sprintf(`<div class="kpi"><div class="n">%d</div><div class="l">%s</div></div>`, n, html.EscapeString(label))
}

func sevPill(sev string) string {
	cls := map[string]string{"critical": "crit", "high": "high", "medium": "med", "low": "low"}[strings.ToLower(sev)]
	if cls == "" {
		cls = "low"
	}
	return `<span class="pill ` + cls + `">` + html.EscapeString(sev) + `</span>`
}
