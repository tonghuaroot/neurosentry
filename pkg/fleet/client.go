// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client is the agent side of the fleet control plane: it enrolls this node
// with a control-plane registry and heartbeats its health on a schedule. Nodes
// running their own embedded control plane update the registry in-process
// instead; this HTTP client is for agents reporting to a remote control plane.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
	id      string
}

// NewClient builds a fleet client for the given control-plane base URL and
// enrollment token.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

// WithTLS returns the client configured to use the given (typically mutual) TLS
// config for all control-plane requests.
func (c *Client) WithTLS(cfg *tls.Config) *Client {
	c.http = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}
	return c
}

// Enroll registers this node and stores the assigned agent ID for heartbeats.
func (c *Client) Enroll(ctx context.Context, info AgentInfo) (string, error) {
	body, _ := json.Marshal(map[string]any{"info": info})
	var out struct {
		ID string `json:"id"`
	}
	if err := c.post(ctx, "/api/fleet/enroll", body, &out); err != nil {
		return "", err
	}
	c.id = out.ID
	return out.ID, nil
}

// Heartbeat reports current health and returns the control plane's desired
// state for the agent to converge to. Enroll must have succeeded first.
func (c *Client) Heartbeat(ctx context.Context, info AgentInfo) (DesiredState, error) {
	if c.id == "" {
		return DesiredState{}, fmt.Errorf("fleet client: not enrolled")
	}
	body, _ := json.Marshal(info)
	var out struct {
		Desired DesiredState `json:"desired"`
	}
	if err := c.post(ctx, "/api/fleet/"+c.id+"/heartbeat", body, &out); err != nil {
		return DesiredState{}, err
	}
	return out.Desired, nil
}

// ID returns the assigned agent ID (empty until enrolled).
func (c *Client) ID() string { return c.id }

func (c *Client) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fleet client: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("fleet client: %s -> status %d", path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
