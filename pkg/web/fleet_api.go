// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/neurosentry/neurosentry/pkg/audit"
	"github.com/neurosentry/neurosentry/pkg/fleet"
	"github.com/neurosentry/neurosentry/pkg/platform"
)

// Fleet control-plane API. Per-node agents enroll and heartbeat here (bearer
// token shared with the fleet), and operators view the whole fleet from the
// console (RBAC). This is the first slice of at-scale management: one pane of
// glass for every agent's health, version, and kernel support.

// SetFleetRegistry enables the fleet API. enrollToken authenticates agent
// enroll/heartbeat calls; console reads are RBAC-gated.
func (s *Server) SetFleetRegistry(reg *fleet.Registry, enrollToken string) {
	s.fleet = reg
	s.fleetToken = enrollToken
}

func (s *Server) registerFleetRoutes() {
	s.mux.HandleFunc("GET /api/fleet", s.dataGuard(platform.PermViewEvents, s.handleFleetList))
	s.mux.HandleFunc("POST /api/fleet/enroll", s.fleetAuth(s.handleFleetEnroll))
	s.mux.HandleFunc("POST /api/fleet/{id}/heartbeat", s.fleetAuth(s.handleFleetHeartbeat))
	s.mux.HandleFunc("POST /api/fleet/{id}/remove", s.mutationGuard(platform.PermManageSystem, s.handleFleetRemove))
	s.mux.HandleFunc("POST /api/fleet/desired", s.mutationGuard(platform.PermManagePolicy, s.handleFleetDesired))
	s.mux.HandleFunc("POST /api/fleet/rollout", s.mutationGuard(platform.PermManagePolicy, s.handleFleetRollout))
	s.mux.HandleFunc("POST /api/fleet/rollout/promote", s.mutationGuard(platform.PermManagePolicy, s.handleFleetRolloutPromote))
	s.mux.HandleFunc("POST /api/fleet/rollout/abort", s.mutationGuard(platform.PermManagePolicy, s.handleFleetRolloutAbort))
}

// FleetAgentHandler returns an http.Handler exposing only the agent-facing fleet
// endpoints (enroll/heartbeat), for serving on a dedicated mutual-TLS listener.
// The shared token still applies; mTLS adds certificate-based peer authentication
// at the transport layer.
func (s *Server) FleetAgentHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /api/fleet/enroll", s.fleetAuth(s.handleFleetEnroll))
	m.HandleFunc("POST /api/fleet/{id}/heartbeat", s.fleetAuth(s.handleFleetHeartbeat))
	return m
}

// fleetAuth gates agent-facing endpoints on the shared enrollment token.
func (s *Server) fleetAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.fleet == nil || s.fleetToken == "" {
			writeError(w, http.StatusServiceUnavailable, "fleet control plane not configured")
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.fleetToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid fleet token")
			return
		}
		h(w, r)
	}
}

func (s *Server) handleFleetList(w http.ResponseWriter, _ *http.Request) {
	if s.fleet == nil {
		writeJSON(w, map[string]any{"agents": []any{}, "stats": fleet.Stats{}})
		return
	}
	writeJSON(w, map[string]any{"agents": s.fleet.List(), "stats": s.fleet.Stats()})
}

type fleetEnrollRequest struct {
	ID   string          `json:"id,omitempty"`
	Info fleet.AgentInfo `json:"info"`
}

func (s *Server) handleFleetEnroll(w http.ResponseWriter, r *http.Request) {
	var req fleetEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid enroll body")
		return
	}
	id, err := s.fleet.Enroll(req.ID, req.Info)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.recordAdminAudit("fleet:agent_enrolled", audit.SeverityInfo, req.Info.Hostname, id, map[string]any{"version": req.Info.Version, "kernel": req.Info.Kernel})
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": id})
}

func (s *Server) handleFleetHeartbeat(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var info fleet.AgentInfo
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		writeError(w, http.StatusBadRequest, "invalid heartbeat body")
		return
	}
	if err := s.fleet.Heartbeat(id, info); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The heartbeat response carries this agent's desired state (honoring any
	// in-progress canary rollout) so agents converge.
	writeJSON(w, map[string]any{"ok": true, "desired": s.fleet.DesiredForAgent(id)})
}

func (s *Server) handleFleetRollout(w http.ResponseWriter, r *http.Request) {
	if s.fleet == nil {
		writeError(w, http.StatusServiceUnavailable, "fleet control plane not configured")
		return
	}
	var req struct {
		Desired fleet.DesiredState `json:"desired"`
		Percent int                `json:"percent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rollout body")
		return
	}
	ro := s.fleet.StartRollout(req.Desired, req.Percent)
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("fleet:rollout_started", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"version": ro.Desired.Version, "percent": ro.Percent})
	writeJSON(w, ro)
}

func (s *Server) handleFleetRolloutPromote(w http.ResponseWriter, r *http.Request) {
	if s.fleet == nil {
		writeError(w, http.StatusServiceUnavailable, "fleet control plane not configured")
		return
	}
	var req struct {
		Percent int `json:"percent"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ro, ok := s.fleet.PromoteRollout(req.Percent)
	if !ok {
		writeError(w, http.StatusBadRequest, "no rollout in progress")
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("fleet:rollout_promoted", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"percent": ro.Percent})
	writeJSON(w, ro)
}

func (s *Server) handleFleetRolloutAbort(w http.ResponseWriter, r *http.Request) {
	if s.fleet == nil {
		writeError(w, http.StatusServiceUnavailable, "fleet control plane not configured")
		return
	}
	if !s.fleet.AbortRollout() {
		writeError(w, http.StatusBadRequest, "no rollout in progress")
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("fleet:rollout_aborted", audit.SeverityMedium, callerEmail(caller), callerID(caller), nil)
	writeJSON(w, map[string]any{"aborted": true})
}

func (s *Server) handleFleetDesired(w http.ResponseWriter, r *http.Request) {
	if s.fleet == nil {
		writeError(w, http.StatusServiceUnavailable, "fleet control plane not configured")
		return
	}
	var d fleet.DesiredState
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		writeError(w, http.StatusBadRequest, "invalid desired-state body")
		return
	}
	applied := s.fleet.SetDesired(d)
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("fleet:desired_set", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"version": applied.Version})
	writeJSON(w, applied)
}

func (s *Server) handleFleetRemove(w http.ResponseWriter, r *http.Request) {
	if s.fleet == nil {
		writeError(w, http.StatusServiceUnavailable, "fleet control plane not configured")
		return
	}
	id := r.PathValue("id")
	if !s.fleet.Remove(id) {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	caller := platform.PrincipalFromContext(r.Context())
	s.recordAdminAudit("fleet:agent_removed", audit.SeverityMedium, callerEmail(caller), callerID(caller), map[string]any{"agent_id": id})
	writeJSON(w, map[string]any{"id": id, "removed": true})
}
