// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"testing"
	"time"
)

func TestSnapshotRestore(t *testing.T) {
	r := NewRegistry(90 * time.Second)
	id, _ := r.Enroll("", AgentInfo{Hostname: "node-1", Version: "0.2.0", Kernel: "6.1", Support: "supported", Ready: true})
	_ = r.Heartbeat(id, AgentInfo{Hostname: "node-1", Version: "0.2.0"})
	r.SetDesired(DesiredState{LearningMode: boolPtr(true), MinSeverity: "high"})
	r.StartRollout(DesiredState{MinSeverity: "critical"}, 25)

	data, err := r.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	// A fresh registry restores agents, desired state, and the pending rollout.
	r2 := NewRegistry(90 * time.Second)
	if err := r2.Restore(data); err != nil {
		t.Fatal(err)
	}
	list := r2.List()
	if len(list) != 1 || list[0].ID != id || list[0].Hostname != "node-1" {
		t.Fatalf("agents not restored: %+v", list)
	}
	if d := r2.Desired(); d.MinSeverity != "high" || d.LearningMode == nil || !*d.LearningMode {
		t.Errorf("desired not restored: %+v", d)
	}
	// The pending canary restores (targeted count depends on agent hash buckets,
	// so assert the rollout itself, not how many agents fall in the slice).
	if ro, active, _ := r2.RolloutStatus(); !active || ro.Percent != 25 || ro.Desired.MinSeverity != "critical" {
		t.Errorf("pending rollout not restored: active=%v %+v", active, ro)
	}
	// Restoring empty data is a no-op, not an error.
	if err := r2.Restore(nil); err != nil {
		t.Errorf("empty restore should be a no-op: %v", err)
	}
}

func boolPtr(b bool) *bool { return &b }

func TestEvictStale(t *testing.T) {
	now := time.Now()
	r := NewRegistry(90 * time.Second)
	r.now = func() time.Time { return now }
	fresh, _ := r.Enroll("fresh", AgentInfo{Hostname: "a"})
	dead, _ := r.Enroll("dead", AgentInfo{Hostname: "b"})
	// Age "dead" past the eviction window; "fresh" stays recent.
	r.now = func() time.Time { return now.Add(2 * time.Hour) }
	_ = r.Heartbeat(fresh, AgentInfo{Hostname: "a"})

	if n := r.EvictStale(time.Hour); n != 1 {
		t.Fatalf("expected 1 eviction, got %d", n)
	}
	ids := map[string]bool{}
	for _, a := range r.List() {
		ids[a.ID] = true
	}
	if ids[dead] || !ids[fresh] {
		t.Errorf("wrong agent evicted: %+v", ids)
	}
	if r.EvictStale(0) != 0 {
		t.Error("non-positive window should be a no-op")
	}
}

func TestEnrollAndList(t *testing.T) {
	r := NewRegistry(90 * time.Second)
	id, err := r.Enroll("", AgentInfo{Hostname: "node-1", Version: "0.2.0", Kernel: "6.1", Support: "supported", Ready: true})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("enroll should mint an id")
	}
	list := r.List()
	if len(list) != 1 || list[0].Hostname != "node-1" {
		t.Fatalf("unexpected list: %+v", list)
	}
	if list[0].Status != StatusHealthy {
		t.Errorf("fresh agent should be healthy, got %s", list[0].Status)
	}
}

func TestHeartbeatUpdatesState(t *testing.T) {
	r := NewRegistry(90 * time.Second)
	id, _ := r.Enroll("node-fixed", AgentInfo{Version: "0.2.0"})
	if err := r.Heartbeat(id, AgentInfo{Version: "0.3.0", Ready: true}); err != nil {
		t.Fatal(err)
	}
	list := r.List()
	if list[0].Version != "0.3.0" || list[0].Beats != 1 {
		t.Errorf("heartbeat should update version + beat count: %+v", list[0])
	}
}

func TestStaleDetection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := NewRegistry(60 * time.Second)
	r.now = func() time.Time { return now }
	r.Enroll("a", AgentInfo{Hostname: "a"})

	// Advance past the stale window.
	now = now.Add(2 * time.Minute)
	st := r.Stats()
	if st.Total != 1 || st.Stale != 1 || st.Healthy != 0 {
		t.Errorf("agent should be stale after window: %+v", st)
	}
	if r.List()[0].Status != StatusStale {
		t.Error("list should mark the agent stale")
	}

	// A heartbeat revives it.
	r.Heartbeat("a", AgentInfo{Hostname: "a"})
	if r.Stats().Healthy != 1 {
		t.Error("heartbeat should revive the agent to healthy")
	}
}

func TestRemove(t *testing.T) {
	r := NewRegistry(0)
	id, _ := r.Enroll("", AgentInfo{})
	if !r.Remove(id) {
		t.Error("remove should succeed for known agent")
	}
	if r.Remove(id) {
		t.Error("remove should fail for unknown agent")
	}
	if r.Stats().Total != 0 {
		t.Error("registry should be empty after remove")
	}
}

func TestHeartbeatImplicitEnroll(t *testing.T) {
	r := NewRegistry(0)
	// Unknown ID (e.g. after a control-plane restart) is implicitly enrolled.
	if err := r.Heartbeat("agt-orphan", AgentInfo{Hostname: "x"}); err != nil {
		t.Fatal(err)
	}
	if r.Stats().Total != 1 {
		t.Error("heartbeat from unknown id should implicitly enroll")
	}
}
