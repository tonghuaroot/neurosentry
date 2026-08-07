// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"strings"
	"testing"

	"github.com/neurosentry/neurosentry/pkg/correlate"
)

// Real OTRF/Security-Datasets Linux auditd records (arp discovery + a dd write).
const auditdReal = `type=SYSCALL msg=audit(1604994496.155:92733): arch=c000003e syscall=59 success=yes exit=0 a0=558e251634a0 a1=558e25162a50 a2=558e25160800 a3=8 items=2 ppid=29002 pid=1631 auid=1000 uid=1000 comm="arp" exe="/usr/sbin/arp" key=(null)
type=EXECVE msg=audit(1604994496.155:92733): argc=2 a0="arp" a1="-a"
type=CWD msg=audit(1604994496.155:92733): cwd="/home/wardog"
type=PATH msg=audit(1604994496.155:92733): item=0 name="/usr/sbin/arp" inode=13181
type=PROCTITLE msg=audit(1604994496.155:92733): proctitle=617270002D61
type=SYSCALL msg=audit(1604994500.000:92800): arch=c000003e syscall=257 success=yes exit=3 ppid=100 pid=2048 comm="cat" exe="/usr/bin/cat" key=(null)
type=PATH msg=audit(1604994500.000:92800): item=0 name="/etc/shadow" inode=99`

func TestReadAuditdParsesRealFormat(t *testing.T) {
	events, err := ReadAuditd(strings.NewReader(auditdReal))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events (1 exec + 1 file), got %d: %+v", len(events), events)
	}
	// First: the execve of arp -> kernel_proc with comm+exe.
	e0 := events[0]
	if e0.Layer != correlate.LayerKernelProc || e0.Attrs["comm"] != "arp" || e0.Attrs["path"] != "/usr/sbin/arp" {
		t.Errorf("exec event wrong: %+v", e0)
	}
	if e0.TS.Unix() != 1604994496 {
		t.Errorf("timestamp not parsed: %v", e0.TS)
	}
	// Second: openat of /etc/shadow -> kernel_file file_read (this WOULD feed a
	// secret-read rule if paired with egress).
	e1 := events[1]
	if e1.Layer != correlate.LayerKernelFile || e1.Attrs["path"] != "/etc/shadow" || e1.Attrs["comm"] != "cat" {
		t.Errorf("file event wrong: %+v", e1)
	}
}
