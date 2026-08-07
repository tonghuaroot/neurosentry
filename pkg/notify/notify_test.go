// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// mockChannel records what it receives and can be made to fail.
type mockChannel struct {
	mu   sync.Mutex
	name string
	got  []Alert
	fail bool
}

func (m *mockChannel) Name() string { return m.name }
func (m *mockChannel) Send(_ context.Context, a Alert) error {
	if m.fail {
		return io.EOF
	}
	m.mu.Lock()
	m.got = append(m.got, a)
	m.mu.Unlock()
	return nil
}
func (m *mockChannel) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.got) }

type nclock struct{ t time.Time }

func (c *nclock) now() time.Time { return c.t }

func TestSeverityThreshold(t *testing.T) {
	r := NewRouter(time.Minute)
	high := &mockChannel{name: "high"}
	crit := &mockChannel{name: "crit"}
	r.AddChannel(high, "high")
	r.AddChannel(crit, "critical")

	r.Route(context.Background(), Alert{Title: "a", Severity: "high"})
	if high.count() != 1 {
		t.Error("high-threshold channel should receive a high alert")
	}
	if crit.count() != 0 {
		t.Error("critical-threshold channel must NOT receive a high alert")
	}

	r.Route(context.Background(), Alert{Title: "b", Severity: "critical"})
	if high.count() != 2 || crit.count() != 1 {
		t.Errorf("critical alert should reach both, got high=%d crit=%d", high.count(), crit.count())
	}

	// Below-threshold alert reaches neither.
	r.Route(context.Background(), Alert{Title: "c", Severity: "medium"})
	if high.count() != 2 {
		t.Error("medium alert should not reach the high channel")
	}
}

func TestDedup(t *testing.T) {
	clk := &nclock{t: time.Unix(1000, 0)}
	r := NewRouter(30 * time.Second)
	r.now = clk.now
	ch := &mockChannel{name: "x"}
	r.AddChannel(ch, "info")

	a := Alert{Title: "same", Severity: "high", Timestamp: clk.t}
	r.Route(context.Background(), a)
	r.Route(context.Background(), a) // within window -> suppressed
	if ch.count() != 1 {
		t.Errorf("duplicate within window should be suppressed, got %d", ch.count())
	}
	if r.Stats().Suppressed != 1 {
		t.Errorf("expected 1 suppressed, got %d", r.Stats().Suppressed)
	}

	// After the window, it delivers again.
	clk.t = clk.t.Add(31 * time.Second)
	r.Route(context.Background(), Alert{Title: "same", Severity: "high", Timestamp: clk.t})
	if ch.count() != 2 {
		t.Error("alert after dedup window should deliver")
	}
}

func TestOneChannelFailingDoesNotBlockOthers(t *testing.T) {
	r := NewRouter(time.Minute)
	bad := &mockChannel{name: "bad", fail: true}
	good := &mockChannel{name: "good"}
	r.AddChannel(bad, "info")
	r.AddChannel(good, "info")
	sent := r.Route(context.Background(), Alert{Title: "a", Severity: "high"})
	if sent != 1 {
		t.Errorf("expected 1 successful delivery, got %d", sent)
	}
	if good.count() != 1 {
		t.Error("good channel should still receive despite bad channel failure")
	}
}

func TestWebhookChannel(t *testing.T) {
	var got Alert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ch := NewWebhookChannel(srv.URL)
	if err := ch.Send(context.Background(), Alert{Title: "test", Severity: "critical", Message: "boom"}); err != nil {
		t.Fatal(err)
	}
	if got.Title != "test" || got.Severity != "critical" {
		t.Errorf("webhook did not receive the alert: %+v", got)
	}
}

func TestSlackChannelFormatsAttachment(t *testing.T) {
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &payload)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ch := NewSlackChannel(srv.URL)
	err := ch.Send(context.Background(), Alert{
		Title: "secret exfil", Severity: "critical", Message: "chain detected",
		Source: "correlation", Fields: map[string]string{"pid": "42", "rule": "NS-CORR-001"},
	})
	if err != nil {
		t.Fatal(err)
	}
	atts, ok := payload["attachments"].([]any)
	if !ok || len(atts) != 1 {
		t.Fatalf("expected one attachment, got %v", payload["attachments"])
	}
	att := atts[0].(map[string]any)
	if att["color"] != "#ef4444" {
		t.Errorf("critical should be red, got %v", att["color"])
	}
	if att["title"] != "[critical] secret exfil" {
		t.Errorf("unexpected title: %v", att["title"])
	}
}

func TestWebhookErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	if err := NewWebhookChannel(srv.URL).Send(context.Background(), Alert{Title: "x", Severity: "high"}); err == nil {
		t.Error("5xx should be reported as an error")
	}
}
