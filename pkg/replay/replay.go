// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package replay imports external security datasets — real attack telemetry —
// and replays them through NeuroSentry's correlation engine, so the platform can
// be demonstrated and validated against realistic data instead of a handful of
// synthetic chains. It deliberately does NOT vendor any dataset (licensing +
// size); it provides tolerant adapters that normalize third-party records into
// NeuroSentry signals, and a replayer that feeds them to the engine.
//
// Two source families map onto NeuroSentry's two observation layers:
//   - host/kernel attack telemetry (e.g. OTRF Security-Datasets / Mordor auditd
//     JSON, MITRE ATT&CK-mapped) -> kernel_file/kernel_net/kernel_proc signals
//   - prompt-injection / jailbreak corpora -> ai-layer signals
//
// so a replayed dataset can exercise the cross-layer correlation that is
// NeuroSentry's differentiator.
package replay

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/neurosentry/neurosentry/pkg/correlate"
)

// Event is a normalized, source-agnostic security event.
type Event struct {
	TS       time.Time
	PID      int
	Layer    correlate.Layer
	Kind     string
	Attrs    map[string]string
	Severity string
}

// ToSignal converts a normalized event into a correlation signal.
func (e Event) ToSignal() correlate.Signal {
	return correlate.Signal{
		Timestamp:  e.TS,
		PID:        e.PID,
		Layer:      e.Layer,
		Kind:       e.Kind,
		Attributes: e.Attrs,
		Severity:   e.Severity,
	}
}

// Adapter maps one raw dataset record into a normalized Event. It returns
// ok=false for records that don't map to a signal (they are skipped).
type Adapter func(rec map[string]any) (Event, bool)

// ReadNDJSON parses newline-delimited JSON records through an adapter. Malformed
// lines are skipped so a partial/dirty dataset still imports what it can.
func ReadNDJSON(r io.Reader, adapt Adapter) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tolerate large records
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if ev, ok := adapt(rec); ok {
			out = append(out, ev)
		}
	}
	return out, sc.Err()
}

// HostTelemetryAdapter normalizes a host/kernel attack-telemetry record (OTRF
// Security-Datasets / Mordor / OSSEM / auditd-shaped) into a kernel signal. It
// is intentionally tolerant of field-name variance across those sources.
func HostTelemetryAdapter(rec map[string]any) (Event, bool) {
	ev := Event{Attrs: map[string]string{}, TS: firstTime(rec, "@timestamp", "timestamp", "TimeGenerated", "utc_time")}
	ev.PID = firstInt(rec, "process_pid", "pid", "ProcessId", "process_id")

	dst := firstStr(rec, "network_dest_ip", "dest_ip", "DestinationIp", "dst", "dst_ip", "remote_ip")
	path := firstStr(rec, "file_path", "TargetFilename", "path", "file_name", "name")
	comm := firstStr(rec, "process_name", "Image", "exe", "comm", "process_path")
	action := strings.ToLower(firstStr(rec, "event_type", "action", "Channel", "category", "type") + " " +
		firstStr(rec, "EventID", "auditd_type", "syscall"))

	switch {
	case dst != "":
		ev.Layer = correlate.LayerKernelNet
		ev.Kind = "net_connect"
		ev.Attrs["dst"] = dst
		if ip := net.ParseIP(dst); ip != nil && isPublicIP(ip) {
			ev.Attrs["external"] = "true"
		}
		if comm != "" {
			ev.Attrs["comm"] = baseName(comm)
		}
	case isExec(action, rec):
		ev.Layer = correlate.LayerKernelProc
		ev.Kind = "exec"
		if comm != "" {
			ev.Attrs["comm"] = baseName(comm)
		}
		if path != "" {
			ev.Attrs["path"] = path
		}
	case path != "":
		ev.Layer = correlate.LayerKernelFile
		ev.Kind = "file_read"
		ev.Attrs["path"] = path
		if comm != "" {
			ev.Attrs["comm"] = baseName(comm)
		}
	default:
		return Event{}, false
	}
	return ev, true
}

// PromptInjectionAdapter normalizes a labeled prompt-injection / jailbreak record
// ({text|prompt, label}) into an AI-layer signal. Malicious/jailbreak rows carry
// injection="malicious" so they can complete an injection-then-action chain.
func PromptInjectionAdapter(rec map[string]any) (Event, bool) {
	text := firstStr(rec, "text", "prompt", "input", "content")
	if text == "" {
		return Event{}, false
	}
	label := strings.ToLower(strings.TrimSpace(firstStr(rec, "label", "class", "category", "type")))
	verdict := "clean"
	switch label {
	case "jailbreak", "injection", "prompt_injection", "malicious", "1", "true", "attack", "unsafe":
		verdict = "malicious"
	}
	// Some datasets encode the label as a boolean/number field.
	if verdict == "clean" {
		if b, ok := rec["jailbreak"].(bool); ok && b {
			verdict = "malicious"
		}
		if n, ok := rec["label"].(float64); ok && n >= 1 {
			verdict = "malicious"
		}
	}
	ev := Event{
		TS:    firstTime(rec, "@timestamp", "timestamp", "TimeGenerated", "utc_time"),
		Layer: correlate.LayerAI,
		Kind:  "prompt",
		PID:   firstInt(rec, "pid", "process_pid"),
		Attrs: map[string]string{"injection": verdict, "text": truncate(text, 240)},
	}
	if verdict == "malicious" {
		ev.Severity = "high"
	}
	return ev, true
}

// MCPToolAdapter normalizes an MCP tool-call record ({tool|mcp_tool|tool_name,
// args/query, injection?}) into an mcp-layer signal. This is what lets a dataset
// exercise the MCP gateway and the tool-based correlation rules (NS-CORR-002/
// 003/011), which no kernel/AI record can produce on its own.
func MCPToolAdapter(rec map[string]any) (Event, bool) {
	tool := firstStr(rec, "tool", "mcp_tool", "tool_name")
	if tool == "" {
		return Event{}, false
	}
	ev := Event{
		TS:    firstTime(rec, "@timestamp", "timestamp", "TimeGenerated", "utc_time"),
		Layer: correlate.LayerMCP,
		Kind:  "tool_call",
		PID:   firstInt(rec, "pid", "process_pid"),
		Attrs: map[string]string{"tool": tool},
	}
	switch strings.ToLower(firstStr(rec, "injection", "verdict", "label")) {
	case "malicious", "injection", "prompt_injection", "jailbreak", "attack":
		ev.Attrs["injection"] = "malicious"
		ev.Severity = "high"
	}
	if a := firstStr(rec, "args", "arguments", "query", "path", "dst"); a != "" {
		ev.Attrs["args"] = truncate(a, 120)
	}
	return ev, true
}

// CombinedAdapter tries the MCP tool shape, then host telemetry, then the
// prompt-injection shape, so a single mixed dataset can drive mcp, kernel, and
// AI-layer signals — and therefore the cross-layer chains that are NeuroSentry's
// differentiator.
func CombinedAdapter(rec map[string]any) (Event, bool) {
	if ev, ok := MCPToolAdapter(rec); ok {
		return ev, true
	}
	if ev, ok := HostTelemetryAdapter(rec); ok {
		return ev, true
	}
	return PromptInjectionAdapter(rec)
}

// AdapterFor returns the adapter for a --replay-format value.
func AdapterFor(format string) Adapter {
	switch format {
	case "host":
		return HostTelemetryAdapter
	case "injection":
		return PromptInjectionAdapter
	case "mcp":
		return MCPToolAdapter
	default:
		return CombinedAdapter
	}
}

// Replay feeds events into ingest in timestamp order. If ingest is nil it is a
// no-op. Returns the number of signals ingested.
func Replay(events []Event, ingest func(correlate.Signal)) int {
	if ingest == nil {
		return 0
	}
	n := 0
	for _, e := range events {
		ingest(e.ToSignal())
		n++
	}
	return n
}

// ---- field helpers (tolerant to schema variance) ----

func firstStr(rec map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := rec[k]; ok {
			switch s := v.(type) {
			case string:
				if s != "" {
					return s
				}
			case float64:
				return strconv.FormatFloat(s, 'f', -1, 64)
			}
		}
	}
	return ""
}

func firstInt(rec map[string]any, keys ...string) int {
	for _, k := range keys {
		switch v := rec[k].(type) {
		case float64:
			return int(v)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return 0
}

func firstTime(rec map[string]any, keys ...string) time.Time {
	for _, k := range keys {
		if s, ok := rec[k].(string); ok && s != "" {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999", "2006-01-02T15:04:05"} {
				if t, err := time.Parse(layout, s); err == nil {
					return t
				}
			}
		}
	}
	return time.Time{}
}

func isExec(action string, rec map[string]any) bool {
	if strings.Contains(action, "exec") || strings.Contains(action, "process_creat") || strings.Contains(action, "1") && strings.Contains(action, "sysmon") {
		return true
	}
	if _, ok := rec["argv"]; ok {
		return true
	}
	if _, ok := rec["CommandLine"]; ok {
		return true
	}
	return false
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	return true
}
