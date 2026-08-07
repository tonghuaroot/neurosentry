// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSentinelSignsAndSends(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("super-secret-workspace-key"))
	var gotAuth, gotLogType, gotDate, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotLogType = r.Header.Get("Log-Type")
		gotDate = r.Header.Get("x-ms-date")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch, err := NewSentinelChannel("ws-123", key, "NeuroSentryAlerts")
	if err != nil {
		t.Fatal(err)
	}
	ch.endpoint = srv.URL // redirect to the test server
	ch.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	alert := Alert{Timestamp: time.Unix(1_700_000_000, 0), Title: "reverse-shell-indicator", Severity: "critical", Source: "correlation", Message: "shell opened external connection"}
	if err := ch.Send(context.Background(), alert); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	if gotLogType != "NeuroSentryAlerts" {
		t.Errorf("Log-Type header wrong: %q", gotLogType)
	}
	if !strings.HasSuffix(gotDate, "GMT") {
		t.Errorf("x-ms-date must end in GMT, got %q", gotDate)
	}
	if !strings.HasPrefix(gotAuth, "SharedKey ws-123:") {
		t.Fatalf("Authorization must be SharedKey scheme, got %q", gotAuth)
	}

	// Independently recompute the HMAC and confirm the signature matches — this
	// proves the signing is correct, not just present.
	rawKey, _ := base64.StdEncoding.DecodeString(key)
	stringToSign := "POST\n" + strconv.Itoa(len(gotBody)) + "\napplication/json\nx-ms-date:" + gotDate + "\n/api/logs"
	mac := hmac.New(sha256.New, rawKey)
	mac.Write([]byte(stringToSign))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if gotAuth != "SharedKey ws-123:"+want {
		t.Errorf("signature mismatch:\n got %s\nwant SharedKey ws-123:%s", gotAuth, want)
	}

	// Body must be a JSON array of alerts.
	var arr []Alert
	if err := json.Unmarshal([]byte(gotBody), &arr); err != nil || len(arr) != 1 {
		t.Errorf("body should be a JSON array of 1 alert: %v", err)
	}
}

func TestSentinelRejectsBadKey(t *testing.T) {
	if _, err := NewSentinelChannel("ws", "not-base64!!!", ""); err == nil {
		t.Error("non-base64 shared key should error")
	}
}

func TestSentinelIsAChannel(t *testing.T) {
	ch, _ := NewSentinelChannel("ws", base64.StdEncoding.EncodeToString([]byte("k")), "")
	var _ Channel = ch
}
