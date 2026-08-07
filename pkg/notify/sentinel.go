// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// SentinelChannel streams alerts to Microsoft Sentinel via the Log Analytics
// HTTP Data Collector API. Auth is an HMAC-SHA256 signature over the request
// using the workspace shared key (the scheme Azure defines), so no bearer token
// travels on the wire. This gives Azure-shop SOCs the same real-time push that
// SplunkHECChannel gives Splunk shops.
type SentinelChannel struct {
	workspaceID string
	sharedKey   []byte // base64-decoded workspace primary/secondary key
	logType     string
	endpoint    string
	client      *http.Client
	now         func() time.Time
}

// NewSentinelChannel builds a Sentinel channel. sharedKeyB64 is the workspace
// key as shown in the Azure portal (base64). logType is the custom log table
// name (Sentinel appends "_CL").
func NewSentinelChannel(workspaceID, sharedKeyB64, logType string) (*SentinelChannel, error) {
	key, err := base64.StdEncoding.DecodeString(sharedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("sentinel: shared key is not valid base64: %w", err)
	}
	if logType == "" {
		logType = "NeuroSentry"
	}
	return &SentinelChannel{
		workspaceID: workspaceID,
		sharedKey:   key,
		logType:     logType,
		endpoint: fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
			workspaceID),
		client: &http.Client{Timeout: 10 * time.Second},
		now:    time.Now,
	}, nil
}

func (c *SentinelChannel) Name() string { return "sentinel" }

func (c *SentinelChannel) Send(ctx context.Context, a Alert) error {
	body, err := json.Marshal([]Alert{a}) // Data Collector API takes a JSON array
	if err != nil {
		return err
	}
	date := c.now().UTC().Format(time.RFC1123)
	// RFC1123 uses "UTC"; the API requires "GMT".
	date = replaceSuffix(date, "UTC", "GMT")

	sig, err := c.buildSignature(len(body), date)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", c.logType)
	req.Header.Set("x-ms-date", date)
	req.Header.Set("time-generated-field", "timestamp")
	req.Header.Set("Authorization", "SharedKey "+c.workspaceID+":"+sig)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("sentinel: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sentinel: status %d", resp.StatusCode)
	}
	return nil
}

// buildSignature computes the Log Analytics HMAC-SHA256 authorization signature.
func (c *SentinelChannel) buildSignature(contentLen int, date string) (string, error) {
	stringToSign := "POST\n" + strconv.Itoa(contentLen) + "\napplication/json\n" +
		"x-ms-date:" + date + "\n/api/logs"
	mac := hmac.New(sha256.New, c.sharedKey)
	if _, err := mac.Write([]byte(stringToSign)); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func replaceSuffix(s, from, to string) string {
	if len(s) >= len(from) && s[len(s)-len(from):] == from {
		return s[:len(s)-len(from)] + to
	}
	return s
}
