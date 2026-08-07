// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package fleet is NeuroSentry's control-plane side of at-scale operations: many
// per-node agents enroll with a central registry and heartbeat their health,
// version, and kernel-support level, so an operator can see and manage the whole
// fleet from one place instead of node-by-node. This is the foundation the rest
// of the control plane (config distribution, staged rollout) builds on.
package fleet

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// AgentStatus is the derived liveness of an enrolled agent.
type AgentStatus string

const (
	StatusHealthy AgentStatus = "healthy" // heartbeat within the stale window
	StatusStale   AgentStatus = "stale"   // missed heartbeats (possible outage)
)

// AgentInfo is the self-reported state an agent sends at enroll/heartbeat.
type AgentInfo struct {
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	Kernel   string `json:"kernel"`
	Support  string `json:"support"` // supported | degraded | unsupported
	Ready    bool   `json:"ready"`
}

// AgentRecord is the registry's view of one agent.
type AgentRecord struct {
	ID string `json:"id"`
	AgentInfo
	FirstSeen time.Time   `json:"first_seen"`
	LastSeen  time.Time   `json:"last_seen"`
	Beats     int64       `json:"beats"`
	Status    AgentStatus `json:"status"`
}

// DesiredState is the configuration the control plane wants every agent to
// converge to. It is versioned: an agent applies it only when the version is
// newer than what it last applied, so distribution is idempotent. Pointer
// fields mean "unset — don't change" so partial updates are possible.
type DesiredState struct {
	Version      int64  `json:"version"`
	LearningMode *bool  `json:"learning_mode,omitempty"`
	MinSeverity  string `json:"min_severity,omitempty"`
}

// Rollout is a staged (canary) desired-state change: the target state is served
// only to agents whose stable bucket falls under Percent, so a config change can
// be validated on a slice of the fleet before promotion to 100%.
type Rollout struct {
	Desired DesiredState `json:"desired"`
	Percent int          `json:"percent"` // 0-100
}

// Registry tracks the enrolled agent fleet. Safe for concurrent use.
type Registry struct {
	mu         sync.Mutex
	agents     map[string]*AgentRecord
	desired    DesiredState // stable state served to agents outside a rollout
	pending    *Rollout     // in-progress canary, if any
	staleAfter time.Duration
	maxAgents  int
	now        func() time.Time
}

// StartRollout begins a staged change to percent% of the fleet. The new state's
// version is assigned by the registry. percent is clamped to [0,100].
func (r *Registry) StartRollout(d DesiredState, percent int) Rollout {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	d.Version = r.desired.Version + 1
	r.pending = &Rollout{Desired: d, Percent: percent}
	return *r.pending
}

// PromoteRollout advances the canary. At 100% the pending state becomes the new
// stable state and the rollout completes. Returns the resulting rollout status.
func (r *Registry) PromoteRollout(percent int) (Rollout, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		return Rollout{}, false
	}
	if percent > 100 {
		percent = 100
	}
	if percent <= r.pending.Percent {
		percent = 100 // promote fully if no larger step given
	}
	r.pending.Percent = percent
	if percent >= 100 {
		r.desired = r.pending.Desired
		r.pending = nil
		return Rollout{Desired: r.desired, Percent: 100}, true
	}
	return *r.pending, true
}

// AbortRollout discards the pending canary; agents revert to stable state.
func (r *Registry) AbortRollout() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		return false
	}
	r.pending = nil
	return true
}

// RolloutStatus reports the active rollout (if any) and how many agents it
// currently targets.
func (r *Registry) RolloutStatus() (rollout Rollout, active bool, targeted int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		return Rollout{}, false, 0
	}
	for id := range r.agents {
		if bucket(id) < r.pending.Percent {
			targeted++
		}
	}
	return *r.pending, true, targeted
}

// DesiredForAgent returns the desired state a specific agent should converge to,
// honoring an in-progress canary rollout.
func (r *Registry) DesiredForAgent(id string) DesiredState {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil && bucket(id) < r.pending.Percent {
		return r.pending.Desired
	}
	return r.desired
}

// bucket maps an agent ID to a stable 0-99 slot (FNV-1a), so an agent stays in
// or out of a canary consistently across heartbeats.
func bucket(id string) int {
	const (
		offset = 2166136261
		prime  = 16777619
	)
	h := uint32(offset)
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= prime
	}
	return int(h % 100)
}

// SetDesired updates the fleet-wide desired state, bumping its version so agents
// re-converge. The supplied version is ignored; the registry assigns it.
func (r *Registry) SetDesired(d DesiredState) DesiredState {
	r.mu.Lock()
	defer r.mu.Unlock()
	d.Version = r.desired.Version + 1
	r.desired = d
	return d
}

// Desired returns the current desired state (with its version).
func (r *Registry) Desired() DesiredState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.desired
}

// NewRegistry builds a fleet registry. staleAfter marks an agent stale when no
// heartbeat has arrived within that window (default 90s if <= 0).
func NewRegistry(staleAfter time.Duration) *Registry {
	if staleAfter <= 0 {
		staleAfter = 90 * time.Second
	}
	return &Registry{
		agents:     make(map[string]*AgentRecord),
		staleAfter: staleAfter,
		maxAgents:  100000,
		now:        time.Now,
	}
}

// registrySnapshot is the serialized registry state (enrolled agents + the
// stable and in-progress desired state) so the control plane survives restart
// without orphaning the fleet or losing a canary rollout.
type registrySnapshot struct {
	Agents  []*AgentRecord `json:"agents"`
	Desired DesiredState   `json:"desired"`
	Pending *Rollout       `json:"pending,omitempty"`
}

// Snapshot serializes the registry for durable persistence.
func (r *Registry) Snapshot() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := registrySnapshot{Desired: r.desired, Pending: r.pending}
	snap.Agents = make([]*AgentRecord, 0, len(r.agents))
	for _, rec := range r.agents {
		snap.Agents = append(snap.Agents, rec)
	}
	return json.Marshal(snap)
}

// Restore loads a snapshot produced by Snapshot. Empty input is a no-op. Existing
// agents with the same ID are overwritten by the snapshot.
func (r *Registry) Restore(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var snap registrySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.desired = snap.Desired
	r.pending = snap.Pending
	for _, rec := range snap.Agents {
		if rec == nil || rec.ID == "" {
			continue
		}
		cp := *rec
		r.agents[cp.ID] = &cp
	}
	return nil
}

// Enroll registers an agent (or re-attaches an existing ID) and returns its ID.
// An empty id mints a new one, so a fresh agent need not supply one.
func (r *Registry) Enroll(id string, info AgentInfo) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if id == "" {
		id = newAgentID()
	}
	now := r.now()
	rec, ok := r.agents[id]
	if !ok {
		if len(r.agents) >= r.maxAgents {
			return "", fmt.Errorf("fleet registry full (%d agents)", r.maxAgents)
		}
		rec = &AgentRecord{ID: id, FirstSeen: now}
		r.agents[id] = rec
	}
	rec.AgentInfo = info
	rec.LastSeen = now
	return id, nil
}

// Heartbeat records a liveness beat and refreshed state for an enrolled agent.
// An unknown ID is treated as an implicit enroll so a control-plane restart
// doesn't orphan live agents.
func (r *Registry) Heartbeat(id string, info AgentInfo) error {
	if id == "" {
		return fmt.Errorf("heartbeat requires an agent id")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	rec, ok := r.agents[id]
	if !ok {
		if len(r.agents) >= r.maxAgents {
			return fmt.Errorf("fleet registry full")
		}
		rec = &AgentRecord{ID: id, FirstSeen: now}
		r.agents[id] = rec
	}
	rec.AgentInfo = info
	rec.LastSeen = now
	rec.Beats++
	return nil
}

// EvictStale removes agents whose last heartbeat is older than olderThan,
// bounding the persisted registry so genuinely-dead nodes don't accumulate
// forever. Returns the number evicted. A non-positive olderThan is a no-op.
func (r *Registry) EvictStale(olderThan time.Duration) int {
	if olderThan <= 0 {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-olderThan)
	n := 0
	for id, rec := range r.agents {
		if rec.LastSeen.Before(cutoff) {
			delete(r.agents, id)
			n++
		}
	}
	return n
}

// Remove drops an agent (decommission).
func (r *Registry) Remove(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agents[id]; !ok {
		return false
	}
	delete(r.agents, id)
	return true
}

// List returns all agents with derived status, newest-heartbeat first.
func (r *Registry) List() []AgentRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]AgentRecord, 0, len(r.agents))
	for _, rec := range r.agents {
		cp := *rec
		cp.Status = r.statusLocked(rec, now)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Stats summarizes fleet health.
type Stats struct {
	Total   int `json:"total"`
	Healthy int `json:"healthy"`
	Stale   int `json:"stale"`
}

// Stats returns fleet-wide counts.
func (r *Registry) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	s := Stats{Total: len(r.agents)}
	for _, rec := range r.agents {
		if r.statusLocked(rec, now) == StatusHealthy {
			s.Healthy++
		} else {
			s.Stale++
		}
	}
	return s
}

func (r *Registry) statusLocked(rec *AgentRecord, now time.Time) AgentStatus {
	if now.Sub(rec.LastSeen) <= r.staleAfter {
		return StatusHealthy
	}
	return StatusStale
}

func newAgentID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "agt-" + hex.EncodeToString(b)
}
