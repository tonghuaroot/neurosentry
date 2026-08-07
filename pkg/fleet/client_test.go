// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fleetTestServer stands up a minimal control plane (the real Registry behind
// HTTP handlers mirroring the web API) so the client can be tested end-to-end.
func fleetTestServer(reg *Registry, token string) *httptest.Server {
	auth := func(r *http.Request) bool {
		return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == token
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/fleet/enroll", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req struct {
			ID   string    `json:"id"`
			Info AgentInfo `json:"info"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		id, _ := reg.Enroll(req.ID, req.Info)
		json.NewEncoder(w).Encode(map[string]string{"id": id})
	})
	mux.HandleFunc("POST /api/fleet/{id}/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var info AgentInfo
		json.NewDecoder(r.Body).Decode(&info)
		if err := reg.Heartbeat(r.PathValue("id"), info); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "desired": reg.Desired()})
	})
	return httptest.NewServer(mux)
}

func TestClientEnrollAndHeartbeat(t *testing.T) {
	reg := NewRegistry(90_000_000_000)
	srv := fleetTestServer(reg, "fleet-secret")
	defer srv.Close()

	c := NewClient(srv.URL, "fleet-secret")
	id, err := c.Enroll(context.Background(), AgentInfo{Hostname: "node-7", Version: "0.2.0", Support: "supported"})
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}
	if id == "" || c.ID() != id {
		t.Fatalf("client should store assigned id, got %q", id)
	}
	if _, err := c.Heartbeat(context.Background(), AgentInfo{Hostname: "node-7", Version: "0.2.0", Ready: true}); err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}

	list := reg.List()
	if len(list) != 1 || list[0].Hostname != "node-7" || list[0].Beats != 1 {
		t.Errorf("registry should reflect the client's enroll+heartbeat: %+v", list)
	}
}

func TestDesiredStateConvergence(t *testing.T) {
	reg := NewRegistry(0)
	on := true
	d := reg.SetDesired(DesiredState{LearningMode: &on, MinSeverity: "high"})
	if d.Version != 1 {
		t.Fatalf("first SetDesired should be version 1, got %d", d.Version)
	}
	// A second update bumps the version so agents re-converge.
	if d2 := reg.SetDesired(DesiredState{MinSeverity: "critical"}); d2.Version != 2 {
		t.Errorf("second SetDesired should be version 2, got %d", d2.Version)
	}

	srv := fleetTestServer(reg, "t")
	defer srv.Close()
	c := NewClient(srv.URL, "t")
	c.Enroll(context.Background(), AgentInfo{Hostname: "n"})
	got, err := c.Heartbeat(context.Background(), AgentInfo{Hostname: "n"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.MinSeverity != "critical" {
		t.Errorf("agent should receive latest desired state via heartbeat, got %+v", got)
	}
}

func TestClientRejectedWithBadToken(t *testing.T) {
	reg := NewRegistry(0)
	srv := fleetTestServer(reg, "right")
	defer srv.Close()

	c := NewClient(srv.URL, "wrong")
	if _, err := c.Enroll(context.Background(), AgentInfo{}); err == nil {
		t.Error("enroll with a bad token should fail")
	}
}

func TestClientHeartbeatRequiresEnroll(t *testing.T) {
	c := NewClient("http://localhost:0", "t")
	if _, err := c.Heartbeat(context.Background(), AgentInfo{}); err == nil {
		t.Error("heartbeat before enroll should error")
	}
}
