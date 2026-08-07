// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSplunkHECSendsEnvelope(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	ch := NewSplunkHECChannel(srv.URL, "my-hec-token", "neurosentry", "")
	err := ch.Send(context.Background(), Alert{
		Timestamp: time.Unix(1_700_000_000, 0),
		Title:     "secret-read-then-llm",
		Severity:  "critical",
		Source:    "correlation",
		Message:   "credential read then LLM egress",
		Fields:    map[string]string{"pid": "4242"},
	})
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if gotAuth != "Splunk my-hec-token" {
		t.Errorf("HEC auth header wrong: %q", gotAuth)
	}
	var env hecEnvelope
	if err := json.Unmarshal([]byte(gotBody), &env); err != nil {
		t.Fatalf("body is not a HEC envelope: %v — %s", err, gotBody)
	}
	if env.SourceType != "neurosentry:alert" || env.Index != "neurosentry" {
		t.Errorf("envelope metadata wrong: %+v", env)
	}
	if env.Event.Title != "secret-read-then-llm" || env.Event.Severity != "critical" {
		t.Errorf("event payload wrong: %+v", env.Event)
	}
	if env.Time != 1_700_000_000 {
		t.Errorf("event time wrong: %d", env.Time)
	}
}

func TestSplunkHECErrorsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // bad token
	}))
	defer srv.Close()

	ch := NewSplunkHECChannel(srv.URL, "bad", "", "")
	if err := ch.Send(context.Background(), Alert{Title: "x", Severity: "high"}); err == nil {
		t.Error("expected an error on non-200 HEC response")
	}
}

// The HEC channel must satisfy the Channel interface so the Router can fan out
// to it like any other sink.
func TestSplunkHECIsAChannel(t *testing.T) {
	var _ Channel = NewSplunkHECChannel("http://x", "t", "", "")
}
