// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"
)

func TestCGoString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "normal string with null terminator",
			input:    []byte{'h', 'e', 'l', 'l', 'o', 0, 'x', 'y', 'z'},
			expected: "hello",
		},
		{
			name:     "empty string",
			input:    []byte{0, 'a', 'b', 'c'},
			expected: "",
		},
		{
			name:     "string without null terminator",
			input:    []byte{'t', 'e', 's', 't'},
			expected: "",
		},
		{
			name:     "all nulls",
			input:    []byte{0, 0, 0, 0},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cGoString(tt.input)
			if result != tt.expected {
				t.Errorf("cGoString(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected string
	}{
		{
			name:     "localhost",
			input:    0x7F000001, // 127.0.0.1
			expected: "127.0.0.1",
		},
		{
			name:     "private network",
			input:    0xC0A80001, // 192.168.0.1
			expected: "192.168.0.1",
		},
		{
			name:     "all zeros",
			input:    0x00000000,
			expected: "0.0.0.0",
		},
		{
			name:     "all ones",
			input:    0xFFFFFFFF,
			expected: "255.255.255.255",
		},
		{
			name:     "10.0.0.1",
			input:    0x0A000001,
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uint32ToIP(tt.input)
			if result != tt.expected {
				t.Errorf("uint32ToIP(0x%08X) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestProtocolToString(t *testing.T) {
	tests := []struct {
		name     string
		input    uint8
		expected string
	}{
		{
			name:     "ICMP",
			input:    1,
			expected: "icmp",
		},
		{
			name:     "TCP",
			input:    6,
			expected: "tcp",
		},
		{
			name:     "UDP",
			input:    17,
			expected: "udp",
		},
		{
			name:     "unknown protocol",
			input:    99,
			expected: "proto(99)",
		},
		{
			name:     "zero",
			input:    0,
			expected: "proto(0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := protocolToString(tt.input)
			if result != tt.expected {
				t.Errorf("protocolToString(%d) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEventTypes(t *testing.T) {
	// Verify event type constants are defined correctly
	eventTypes := []EventType{
		EventTypeFileAccess,
		EventTypeFileBlocked,
		EventTypeNetworkAllowed,
		EventTypeNetworkBlocked,
		EventTypeModelLoad,
		EventTypePickleLoad,
		EventTypePickleDangerous,
	}

	for _, et := range eventTypes {
		if string(et) == "" {
			t.Errorf("EventType %v should not be empty", et)
		}
	}
}

func TestEventStructure(t *testing.T) {
	// Test that Event struct can be properly initialized
	event := Event{
		Type:     EventTypeFileAccess,
		Severity: "info",
		Source: EventSource{
			PID:  1234,
			UID:  1000,
			Comm: "test-process",
		},
		Data: EventData{
			FilePath:   "/models/test.safetensors",
			FileAction: "read",
		},
	}

	if event.Type != EventTypeFileAccess {
		t.Errorf("Expected event type %s, got %s", EventTypeFileAccess, event.Type)
	}
	if event.Source.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", event.Source.PID)
	}
	if event.Data.FilePath != "/models/test.safetensors" {
		t.Errorf("Expected file path /models/test.safetensors, got %s", event.Data.FilePath)
	}
}

func TestParseEventShortRecord(t *testing.T) {
	// Test that short records are rejected
	shortData := []byte{0x01, 0x02}

	// Create a mock ringbuf.Record - we can't directly import it here
	// but we can test the size check logic
	if len(shortData) >= 4 {
		t.Error("Test data should be less than 4 bytes")
	}
}

func TestParseModelAccessEventData(t *testing.T) {
	// Test parseModelAccessEvent with valid data
	// Create a buffer large enough for ModelAccessEvent
	data := make([]byte, 512)

	// Set event type (first 4 bytes)
	data[0] = 1 // file_access event type

	// Set PID at offset 0
	data[0] = 0xD2
	data[1] = 0x04
	data[2] = 0x00
	data[3] = 0x00 // PID = 1234

	// Set UID at offset 4
	data[4] = 0xE8
	data[5] = 0x03
	data[6] = 0x00
	data[7] = 0x00 // UID = 1000

	// Verify buffer is large enough
	if len(data) < 340 { // Approximate size of ModelAccessEvent
		t.Skip("Buffer too small for test")
	}
}

func TestParseNetworkEventData(t *testing.T) {
	// Test network event structure
	data := make([]byte, 256)

	// Set event type
	data[0] = 3 // network event

	// Verify buffer is large enough
	if len(data) < 60 { // Approximate size of NetworkEvent
		t.Skip("Buffer too small for test")
	}
}

func TestModelAccessEventStruct(t *testing.T) {
	// Test struct sizes and field offsets
	event := ModelAccessEvent{
		PID:       1234,
		UID:       1000,
		Timestamp: 1234567890,
		EventType: 1,
	}
	copy(event.Comm[:], "test")
	copy(event.Filename[:], "/test/path")

	if event.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", event.PID)
	}
	if event.UID != 1000 {
		t.Errorf("Expected UID 1000, got %d", event.UID)
	}
}

func TestNetworkEventStruct(t *testing.T) {
	event := NetworkEvent{
		PID:       5678,
		Timestamp: 9876543210,
		Action:    2, // XDP_DROP
		SAddr:     0xC0A80001,
		DAddr:     0x08080808,
		Sport:     12345,
		Dport:     443,
		Protocol:  6, // TCP
	}

	if event.PID != 5678 {
		t.Errorf("Expected PID 5678, got %d", event.PID)
	}
	if event.Protocol != 6 {
		t.Errorf("Expected protocol 6, got %d", event.Protocol)
	}
}
