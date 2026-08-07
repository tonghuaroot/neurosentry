// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/neurosentry/neurosentry/pkg/correlate"
)

// ReadAuditd parses the raw Linux auditd log text format (as produced by auditd
// and shipped by OTRF/Security-Datasets) into NeuroSentry signals. This lets the
// engine consume REAL kernel audit telemetry, not just JSON-normalized datasets.
//
// auditd emits multiple lines per event, correlated by the audit(TS:SERIAL) key:
// a SYSCALL line (pid/comm/exe/syscall), optional EXECVE (argv), PATH (files),
// CWD, PROCTITLE. Lines are grouped by SERIAL and folded into one Event:
//   - execve syscalls (59/322) -> kernel_proc "exec" {comm, path=exe}
//   - open/openat syscalls (2/257/...) with a PATH -> kernel_file "file_read"
//   - connect syscall (42) with a saddr -> kernel_net "net_connect"
func ReadAuditd(r io.Reader) ([]Event, error) {
	type group struct {
		ts      time.Time
		fields  map[string]string // from the SYSCALL line
		paths   []string          // PATH name= entries
		hasConn bool
	}
	groups := map[string]*group{}
	var order []string

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		typ, serial, ts, kv := parseAuditLine(line)
		if serial == "" {
			continue
		}
		g := groups[serial]
		if g == nil {
			g = &group{ts: ts, fields: map[string]string{}}
			groups[serial] = g
			order = append(order, serial)
		}
		switch typ {
		case "SYSCALL":
			for k, v := range kv {
				g.fields[k] = v
			}
			if !ts.IsZero() {
				g.ts = ts
			}
		case "PATH":
			if n := kv["name"]; n != "" {
				g.paths = append(g.paths, n)
			}
		case "SOCKADDR", "NETFILTER_PKT":
			g.hasConn = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	var out []Event
	for _, serial := range order {
		g := groups[serial]
		syscall := g.fields["syscall"]
		pid, _ := strconv.Atoi(g.fields["pid"])
		comm := unquote(g.fields["comm"])
		exe := unquote(g.fields["exe"])

		switch {
		case isExecSyscall(syscall):
			ev := Event{TS: g.ts, PID: pid, Layer: correlate.LayerKernelProc, Kind: "exec", Attrs: map[string]string{}}
			if comm != "" {
				ev.Attrs["comm"] = comm
			}
			if exe != "" {
				ev.Attrs["path"] = exe
			}
			out = append(out, ev)
		case isConnectSyscall(syscall) || g.hasConn:
			ev := Event{TS: g.ts, PID: pid, Layer: correlate.LayerKernelNet, Kind: "net_connect", Attrs: map[string]string{}}
			if comm != "" {
				ev.Attrs["comm"] = comm
			}
			out = append(out, ev)
		case isOpenSyscall(syscall) && len(g.paths) > 0:
			ev := Event{TS: g.ts, PID: pid, Layer: correlate.LayerKernelFile, Kind: "file_read",
				Attrs: map[string]string{"path": g.paths[0]}}
			if comm != "" {
				ev.Attrs["comm"] = comm
			}
			out = append(out, ev)
		}
	}
	return out, nil
}

// parseAuditLine extracts type, the audit serial, the timestamp, and the key=val
// fields from one auditd line. Returns serial="" for unparseable lines.
func parseAuditLine(line string) (typ, serial string, ts time.Time, kv map[string]string) {
	kv = map[string]string{}
	if !strings.HasPrefix(line, "type=") {
		return "", "", ts, kv
	}
	// type=NAME msg=audit(TS:SERIAL): field=val field="val" ...
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		return "", "", ts, kv
	}
	typ = strings.TrimPrefix(line[:sp], "type=")

	mi := strings.Index(line, "msg=audit(")
	if mi < 0 {
		return "", "", ts, kv
	}
	rest := line[mi+len("msg=audit("):]
	end := strings.Index(rest, ")")
	if end < 0 {
		return "", "", ts, kv
	}
	stamp := rest[:end]  // TS:SERIAL
	body := rest[end+2:] // after "): "
	if c := strings.IndexByte(stamp, ':'); c >= 0 {
		serial = stamp[c+1:]
		if secs, err := strconv.ParseFloat(stamp[:c], 64); err == nil {
			ts = time.Unix(int64(secs), int64((secs-float64(int64(secs)))*1e9))
		}
	}
	for k, v := range parseKV(body) {
		kv[k] = v
	}
	return typ, serial, ts, kv
}

// parseKV splits space-separated key=value pairs, honoring "quoted" values.
func parseKV(s string) map[string]string {
	kv := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		key := s[i : i+eq]
		i += eq + 1
		var val string
		if i < len(s) && s[i] == '"' {
			i++
			j := strings.IndexByte(s[i:], '"')
			if j < 0 {
				break
			}
			val = s[i : i+j]
			i += j + 1
		} else {
			j := strings.IndexByte(s[i:], ' ')
			if j < 0 {
				val = s[i:]
				i = len(s)
			} else {
				val = s[i : i+j]
				i += j
			}
		}
		kv[key] = val
	}
	return kv
}

func unquote(s string) string { return strings.Trim(s, "\"") }

func isExecSyscall(s string) bool    { return s == "59" || s == "322" }               // execve, execveat
func isOpenSyscall(s string) bool    { return s == "2" || s == "257" || s == "0" }    // open, openat, read
func isConnectSyscall(s string) bool { return s == "42" || s == "288" || s == "290" } // connect, accept4, sendto
