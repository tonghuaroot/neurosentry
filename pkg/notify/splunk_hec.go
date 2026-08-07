// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SplunkHECChannel streams alerts to a Splunk HTTP Event Collector in real time.
// This is the push counterpart to the pull-based OCSF/CEF export: findings land
// in the SOC's Splunk index as they happen, in HEC's native envelope, so
// NeuroSentry plugs into an existing pipeline without a scheduled pull job.
type SplunkHECChannel struct {
	url        string
	token      string
	sourceType string
	index      string
	client     *http.Client
}

// NewSplunkHECChannel builds a HEC channel. url is the collector endpoint
// (e.g. https://splunk:8088/services/collector/event); token is the HEC token.
func NewSplunkHECChannel(url, token, index, sourceType string) *SplunkHECChannel {
	if sourceType == "" {
		sourceType = "neurosentry:alert"
	}
	return &SplunkHECChannel{
		url: url, token: token, index: index, sourceType: sourceType,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *SplunkHECChannel) Name() string { return "splunk-hec" }

// hecEnvelope is Splunk's HEC event wrapper.
type hecEnvelope struct {
	Time       int64  `json:"time"`
	Host       string `json:"host,omitempty"`
	Source     string `json:"source"`
	SourceType string `json:"sourcetype"`
	Index      string `json:"index,omitempty"`
	Event      Alert  `json:"event"`
}

func (c *SplunkHECChannel) Send(ctx context.Context, a Alert) error {
	env := hecEnvelope{
		Time:       a.Timestamp.Unix(),
		Source:     "neurosentry",
		SourceType: c.sourceType,
		Index:      c.index,
		Event:      a,
	}
	if env.Time == 0 {
		env.Time = time.Now().Unix()
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// HEC authenticates with "Authorization: Splunk <token>".
	req.Header.Set("Authorization", "Splunk "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk hec: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("splunk hec: status %d", resp.StatusCode)
	}
	return nil
}
