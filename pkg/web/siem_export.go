// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/correlate"
)

// lineWriter streams newline-delimited records (NDJSON or CEF) to a response.
type lineWriter struct {
	w   *bufio.Writer
	enc *json.Encoder // json.Encoder writes a trailing newline per Encode -> NDJSON
}

func newLineWriter(w io.Writer) *lineWriter {
	bw := bufio.NewWriter(w)
	return &lineWriter{w: bw, enc: json.NewEncoder(bw)}
}

func (l *lineWriter) json(v any) { _ = l.enc.Encode(v) }

func (l *lineWriter) line(s string) {
	_, _ = l.w.WriteString(s)
	_ = l.w.WriteByte('\n')
}

func (l *lineWriter) flush() { _ = l.w.Flush() }

// SIEM export streams NeuroSentry's tamper-evident audit trail and cross-layer
// correlation findings in the formats a SOC's existing pipeline already speaks —
// OCSF (JSON, the Splunk/Amazon Security Lake schema) or ArcSight CEF (text).
// This is the "no rip-and-replace" integration story: point Splunk, Panther, or
// Sentinel at GET /api/export/siem and the events land in their native schema.

// handleSIEMExport serves GET /api/export/siem?format=ocsf|cef&type=audit|findings|all.
func (s *Server) handleSIEMExport(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "ocsf"
	}
	kind := strings.ToLower(r.URL.Query().Get("type"))
	if kind == "" {
		kind = "all"
	}
	limit := 1000
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	var since time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		since, _ = time.Parse(time.RFC3339, v)
	}

	switch format {
	case "cef":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	case "ocsf", "ndjson", "json":
		format = "ocsf"
		// NDJSON: one JSON object per line (application/x-ndjson).
		w.Header().Set("Content-Type", "application/x-ndjson")
	default:
		writeError(w, http.StatusBadRequest, "format must be ocsf or cef")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=neurosentry-%s.%s",
		kind, map[string]string{"cef": "cef", "ocsf": "ndjson"}[format]))

	enc := newLineWriter(w)

	if kind == "audit" || kind == "all" {
		entries := s.auditChain.Entries()
		start := 0
		if len(entries) > limit {
			start = len(entries) - limit
		}
		for _, e := range entries[start:] {
			if !since.IsZero() && e.Timestamp.Before(since) {
				continue
			}
			if format == "cef" {
				enc.line(auditToCEF(e))
			} else {
				enc.json(auditToOCSF(e))
			}
		}
	}

	if (kind == "findings" || kind == "all") && s.correlationSource != nil {
		for _, f := range s.correlationSource(limit) {
			if !since.IsZero() && f.Timestamp.Before(since) {
				continue
			}
			if format == "cef" {
				enc.line(findingToCEF(f))
			} else {
				enc.json(findingToOCSF(f))
			}
		}
	}
	enc.flush()
}

// ---- OCSF (Open Cybersecurity Schema Framework) ----

// auditToOCSF maps an audit entry onto an OCSF Detection/Security Finding
// (category 2, class 2001) object with NeuroSentry-native fields preserved
// under unmapped/enrichments so no fidelity is lost.
func auditToOCSF(e *audit.Entry) map[string]any {
	catUID := e.CategoryUID
	if catUID == 0 {
		catUID = audit.CategorySecurity
	}
	classUID := e.ClassUID
	if classUID == 0 {
		classUID = audit.ClassFinding
	}
	o := map[string]any{
		"category_uid": catUID,
		"class_uid":    classUID,
		"activity_id":  1,
		"type_uid":     classUID*100 + 1,
		"severity_id":  e.SeverityID,
		"severity":     titleCase(string(e.Severity)),
		"time":         e.Timestamp.UnixMilli(),
		"time_dt":      e.Timestamp.UTC().Format(time.RFC3339Nano),
		"message":      e.EventType,
		"status":       "New",
		"metadata": map[string]any{
			"uid":      e.ID,
			"sequence": e.SequenceNum,
			"version":  "1.1.0",
			"product": map[string]any{
				"name":        "NeuroSentry",
				"vendor_name": "NeuroSentry",
			},
			"log_provider": "neurosentry",
		},
		"unmapped": map[string]any{
			"event_type": e.EventType,
			"details":    e.Details,
			"prev_hash":  e.PrevHash,
			"hash":       e.Hash,
		},
	}
	if e.Actor != nil {
		o["actor"] = map[string]any{
			"process": map[string]any{
				"pid":  e.Actor.PID,
				"name": e.Actor.Comm,
				"user": map[string]any{"uid": strconv.Itoa(e.Actor.UID)},
			},
		}
	}
	return o
}

// findingToOCSF maps a correlation finding onto an OCSF Detection Finding with
// its MITRE technique and the full causal chain preserved.
func findingToOCSF(f correlate.Finding) map[string]any {
	chain := make([]map[string]any, 0, len(f.Chain))
	for _, sig := range f.Chain {
		chain = append(chain, map[string]any{
			"layer":      string(sig.Layer),
			"kind":       sig.Kind,
			"time_dt":    sig.Timestamp.UTC().Format(time.RFC3339Nano),
			"attributes": sig.Attributes,
		})
	}
	finding := map[string]any{
		"title": f.Rule,
		"desc":  f.Description,
		"uid":   f.RuleID,
		"types": []string{"cross-layer-correlation"},
	}
	if f.Technique != "" {
		finding["attacks"] = []map[string]any{{
			"technique": map[string]any{"uid": f.Technique},
		}}
	}
	return map[string]any{
		"category_uid": audit.CategorySecurity,
		"class_uid":    audit.ClassFinding,
		"activity_id":  1,
		"type_uid":     audit.ClassFinding*100 + 1,
		"severity_id":  severityToID(f.Severity),
		"severity":     titleCase(f.Severity),
		"time":         f.Timestamp.UnixMilli(),
		"time_dt":      f.Timestamp.UTC().Format(time.RFC3339Nano),
		"message":      f.Description,
		"status":       "New",
		"finding_info": finding,
		"metadata": map[string]any{
			"version":      "1.1.0",
			"log_provider": "neurosentry",
			"product":      map[string]any{"name": "NeuroSentry", "vendor_name": "NeuroSentry"},
		},
		"actor":    map[string]any{"process": map[string]any{"pid": f.PID}},
		"unmapped": map[string]any{"tenant_id": f.TenantID, "chain": chain},
	}
}

// ---- CEF (ArcSight Common Event Format) ----
//
// CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

func auditToCEF(e *audit.Entry) string {
	ext := map[string]string{
		"rt":         strconv.FormatInt(e.Timestamp.UnixMilli(), 10),
		"externalId": e.ID,
		"cs1Label":   "hashChain",
		"cs1":        e.Hash,
	}
	if e.Actor != nil {
		ext["dpid"] = strconv.Itoa(e.Actor.PID)
		ext["dproc"] = e.Actor.Comm
		ext["duid"] = strconv.Itoa(e.Actor.UID)
	}
	for k, v := range e.Details {
		ext["cs_"+cefSanitize(k)] = cefEscapeVal(fmt.Sprintf("%v", v))
	}
	return cefHeader(e.EventType, e.EventType, cefSeverity(string(e.Severity))) + cefExtension(ext)
}

func findingToCEF(f correlate.Finding) string {
	ext := map[string]string{
		"rt":       strconv.FormatInt(f.Timestamp.UnixMilli(), 10),
		"dpid":     strconv.Itoa(f.PID),
		"msg":      cefEscapeVal(f.Description),
		"cs2Label": "mitre",
		"cs2":      f.Technique,
	}
	if f.TenantID != "" {
		ext["cs3Label"] = "tenant"
		ext["cs3"] = f.TenantID
	}
	sig := f.RuleID
	if sig == "" {
		sig = f.Rule
	}
	return cefHeader(sig, f.Rule, cefSeverity(f.Severity)) + cefExtension(ext)
}

func cefHeader(sigID, name string, sev int) string {
	return fmt.Sprintf("CEF:0|NeuroSentry|NeuroSentry|0.2.0|%s|%s|%d|",
		cefEscapeHeader(sigID), cefEscapeHeader(name), sev)
}

func cefExtension(ext map[string]string) string {
	var b strings.Builder
	first := true
	for k, v := range ext {
		if v == "" {
			continue
		}
		if !first {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		first = false
	}
	return b.String()
}

// cefSeverity maps a NeuroSentry severity string onto CEF's 0-10 scale.
func cefSeverity(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 1
	}
}

func severityToID(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func cefEscapeVal(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func cefSanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "field"
	}
	return b.String()
}

func titleCase(s string) string {
	if s == "" {
		return "Unknown"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
