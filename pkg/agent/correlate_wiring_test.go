// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/neurosentry/neurosentry/pkg/correlate"
)

func TestEventToSignalMapping(t *testing.T) {
	cases := []struct {
		name      string
		event     Event
		wantOK    bool
		wantLayer correlate.Layer
		wantKind  string
		wantAttr  string // key to check present/non-empty
	}{
		{
			name: "file blocked -> kernel_file",
			event: Event{
				Type:   EventTypeFileBlocked,
				Source: EventSource{PID: 42},
				Data:   EventData{FilePath: "/etc/shadow"},
			},
			wantOK: true, wantLayer: correlate.LayerKernelFile, wantKind: "file_read", wantAttr: "path",
		},
		{
			name: "network blocked -> kernel_net",
			event: Event{
				Type:   EventTypeNetworkBlocked,
				Source: EventSource{PID: 43},
				Data:   EventData{DstAddr: "203.0.113.5"},
			},
			wantOK: true, wantLayer: correlate.LayerKernelNet, wantKind: "net_connect", wantAttr: "dst",
		},
		{
			name: "model load -> model",
			event: Event{
				Type:   EventTypeModelLoad,
				Source: EventSource{PID: 44},
				Data:   EventData{FilePath: "/models/x.safetensors"},
			},
			wantOK: true, wantLayer: correlate.LayerModel, wantKind: "load", wantAttr: "path",
		},
		{
			name:   "pickle event -> not correlated",
			event:  Event{Type: EventTypePickleDangerous, Source: EventSource{PID: 45}},
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, ok := eventToSignal(tc.event)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if s.Layer != tc.wantLayer {
				t.Errorf("layer = %s, want %s", s.Layer, tc.wantLayer)
			}
			if s.Kind != tc.wantKind {
				t.Errorf("kind = %s, want %s", s.Kind, tc.wantKind)
			}
			if s.PID != tc.event.Source.PID {
				t.Errorf("pid = %d, want %d", s.PID, tc.event.Source.PID)
			}
			if tc.wantAttr != "" && s.Attr(tc.wantAttr) == "" {
				t.Errorf("expected attribute %q to be set, got empty", tc.wantAttr)
			}
			// Timestamp must be left zero so the engine stamps ingest time
			// (BPF ktime is boot-relative, not wall-clock).
			if !s.Timestamp.IsZero() {
				t.Error("timestamp should be zero for engine to stamp")
			}
		})
	}
}
