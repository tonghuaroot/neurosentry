// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

// EventType represents the type of security event
type EventType string

const (
	EventTypeFileAccess      EventType = "file_access"
	EventTypeFileBlocked     EventType = "file_blocked"
	EventTypeNetworkAllowed  EventType = "network_allowed"
	EventTypeNetworkBlocked  EventType = "network_blocked"
	EventTypeModelLoad       EventType = "model_load"
	EventTypePickleLoad      EventType = "pickle_load"
	EventTypePickleDangerous EventType = "pickle_dangerous"
)

// Event represents a security event from the eBPF layer
type Event struct {
	Type      EventType   `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Severity  string      `json:"severity"`
	Source    EventSource `json:"source"`
	Data      EventData   `json:"data"`
}

// EventSource identifies where the event originated
type EventSource struct {
	PID     int    `json:"pid"`
	UID     int    `json:"uid"`
	Comm    string `json:"comm"`
	CGroup  string `json:"cgroup,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
}

// EventData contains event-specific data
type EventData struct {
	// File access events
	FilePath    string `json:"file_path,omitempty"`
	FileAction  string `json:"file_action,omitempty"`
	Extension   string `json:"extension,omitempty"`

	// Network events
	SrcAddr     string `json:"src_addr,omitempty"`
	DstAddr     string `json:"dst_addr,omitempty"`
	SrcPort     int    `json:"src_port,omitempty"`
	DstPort     int    `json:"dst_port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	BlockReason string `json:"block_reason,omitempty"`

	// Model load events
	Framework   string `json:"framework,omitempty"`
	ModelSize   int64  `json:"model_size,omitempty"`
	ModelHash   string `json:"model_hash,omitempty"`

	// Pickle events
	StackDepth  int    `json:"stack_depth,omitempty"`
	Symbols     []string `json:"symbols,omitempty"`
}

// ModelAccessEvent represents a model file access event from BPF
type ModelAccessEvent struct {
	PID       uint32
	UID       uint32
	Timestamp uint64
	EventType uint32
	Comm      [16]byte
	Filename  [256]byte
	CGroup    [64]byte
}

// NetworkEvent represents a network event from BPF
type NetworkEvent struct {
	PID       uint32
	Timestamp uint64
	Action    uint32
	SAddr     uint32
	DAddr     uint32
	Sport     uint16
	Dport     uint16
	Protocol  uint8
	Reason    [32]byte
}

// ModelLoadEvent represents a model load event from uprobe
type ModelLoadEvent struct {
	PID       uint32
	Timestamp uint64
	ModelSize uint64
	ModelPath [256]byte
	Comm      [16]byte
	Framework uint8
	ModelHash [32]byte
}

// PickleEvent represents a pickle deserialization event
type PickleEvent struct {
	PID       uint32
	Timestamp uint64
	PicklePath [256]byte
	Comm      [16]byte
	Dangerous uint8
	StackTrace [256]byte
}

// ParseEvent parses a raw ringbuf record into an Event
func ParseEvent(record ringbuf.Record) (Event, error) {
	if len(record.RawSample) < 4 {
		return Event{}, fmt.Errorf("record too short")
	}

	// The first 4 bytes should indicate event type
	// In a real implementation, we'd have a proper header
	eventType := binary.LittleEndian.Uint32(record.RawSample[:4])

	switch eventType {
	case 1, 2: // Model access events
		return parseModelAccessEvent(record.RawSample)
	case 3, 4: // Network events
		return parseNetworkEvent(record.RawSample)
	case 5: // Model load event
		return parseModelLoadEvent(record.RawSample)
	case 6, 7: // Pickle events
		return parsePickleEvent(record.RawSample)
	default:
		return Event{}, fmt.Errorf("unknown event type: %d", eventType)
	}
}

func parseModelAccessEvent(data []byte) (Event, error) {
	if len(data) < int(unsafe.Sizeof(ModelAccessEvent{})) {
		return Event{}, fmt.Errorf("invalid model access event size")
	}

	bpfEvent := (*ModelAccessEvent)(unsafe.Pointer(&data[0])) //nolint:gosec // G103: unsafe.Pointer needed for BPF event parsing

	event := Event{
		Timestamp: time.Unix(0, int64(bpfEvent.Timestamp)), //nolint:gosec // G115: timestamp conversion is safe
		Source: EventSource{
			PID:    int(bpfEvent.PID),
			UID:    int(bpfEvent.UID),
			Comm:   cGoString(bpfEvent.Comm[:]),
			CGroup: cGoString(bpfEvent.CGroup[:]),
		},
		Data: EventData{
			FilePath: cGoString(bpfEvent.Filename[:]),
		},
	}

	if bpfEvent.EventType == 2 {
		event.Type = EventTypeFileBlocked
		event.Severity = "high"
		event.Data.FileAction = "blocked"
	} else {
		event.Type = EventTypeFileAccess
		event.Severity = "info"
		event.Data.FileAction = "allowed"
	}

	return event, nil
}

func parseNetworkEvent(data []byte) (Event, error) {
	if len(data) < int(unsafe.Sizeof(NetworkEvent{})) {
		return Event{}, fmt.Errorf("invalid network event size")
	}

	bpfEvent := (*NetworkEvent)(unsafe.Pointer(&data[0])) //nolint:gosec // G103: unsafe.Pointer needed for BPF event parsing

	event := Event{
		Timestamp: time.Unix(0, int64(bpfEvent.Timestamp)), //nolint:gosec // G115: timestamp conversion is safe
		Source: EventSource{
			PID: int(bpfEvent.PID),
		},
		Data: EventData{
			SrcAddr: uint32ToIP(bpfEvent.SAddr),
			DstAddr: uint32ToIP(bpfEvent.DAddr),
			SrcPort: int(bpfEvent.Sport),
			DstPort: int(bpfEvent.Dport),
			Protocol: protocolToString(bpfEvent.Protocol),
		},
	}

	if bpfEvent.Action == 2 { // XDP_DROP
		event.Type = EventTypeNetworkBlocked
		event.Severity = "high"
		event.Data.BlockReason = cGoString(bpfEvent.Reason[:])
	} else {
		event.Type = EventTypeNetworkAllowed
		event.Severity = "info"
	}

	return event, nil
}

func parseModelLoadEvent(data []byte) (Event, error) {
	if len(data) < int(unsafe.Sizeof(ModelLoadEvent{})) {
		return Event{}, fmt.Errorf("invalid model load event size")
	}

	bpfEvent := (*ModelLoadEvent)(unsafe.Pointer(&data[0])) //nolint:gosec // G103: unsafe.Pointer needed for BPF event parsing

	frameworkMap := map[uint8]string{
		1: "pytorch",
		2: "tensorflow",
		3: "onnx",
	}

	event := Event{
		Type:      EventTypeModelLoad,
		Timestamp: time.Unix(0, int64(bpfEvent.Timestamp)), //nolint:gosec // G115: timestamp conversion is safe
		Severity:  "info",
		Source: EventSource{
			PID:  int(bpfEvent.PID),
			Comm: cGoString(bpfEvent.Comm[:]),
		},
		Data: EventData{
			FilePath:  cGoString(bpfEvent.ModelPath[:]),
			Framework: frameworkMap[bpfEvent.Framework],
			ModelSize: int64(bpfEvent.ModelSize), //nolint:gosec // G115: model size conversion is safe
			ModelHash: fmt.Sprintf("%x", bpfEvent.ModelHash[:]),
		},
	}

	return event, nil
}

func parsePickleEvent(data []byte) (Event, error) {
	if len(data) < int(unsafe.Sizeof(PickleEvent{})) {
		return Event{}, fmt.Errorf("invalid pickle event size")
	}

	bpfEvent := (*PickleEvent)(unsafe.Pointer(&data[0])) //nolint:gosec // G103: unsafe.Pointer needed for BPF event parsing

	event := Event{
		Timestamp: time.Unix(0, int64(bpfEvent.Timestamp)), //nolint:gosec // G115: timestamp conversion is safe
		Source: EventSource{
			PID:  int(bpfEvent.PID),
			Comm: cGoString(bpfEvent.Comm[:]),
		},
		Data: EventData{
			FilePath: cGoString(bpfEvent.PicklePath[:]),
		},
	}

	if bpfEvent.Dangerous == 1 {
		event.Type = EventTypePickleDangerous
		event.Severity = "critical"
	} else {
		event.Type = EventTypePickleLoad
		event.Severity = "info"
	}

	return event, nil
}

// Helper functions
func cGoString(b []byte) string {
	end := 0
	for i, c := range b {
		if c == 0 {
			end = i
			break
		}
	}
	return string(b[:end])
}

func uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF)
}

func protocolToString(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("proto(%d)", p)
	}
}
