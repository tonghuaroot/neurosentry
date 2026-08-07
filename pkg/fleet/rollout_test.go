// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package fleet

import "testing"

func TestCanaryRolloutTargetsSubset(t *testing.T) {
	r := NewRegistry(0)
	// Enroll a spread of agents with stable IDs.
	ids := []string{}
	for i := 0; i < 200; i++ {
		id, _ := r.Enroll("agt-"+string(rune('a'+i%26))+itoa(i), AgentInfo{})
		ids = append(ids, id)
	}

	on := true
	r.StartRollout(DesiredState{LearningMode: &on}, 25) // ~25% canary

	targeted := 0
	for _, id := range ids {
		d := r.DesiredForAgent(id)
		if d.LearningMode != nil && *d.LearningMode {
			targeted++
		}
	}
	// Roughly a quarter should get the new state — allow a generous band since
	// bucketing is a hash, not exact.
	if targeted == 0 || targeted >= len(ids) {
		t.Fatalf("canary should target a strict subset, got %d/%d", targeted, len(ids))
	}
	frac := float64(targeted) / float64(len(ids))
	if frac < 0.10 || frac > 0.45 {
		t.Errorf("canary fraction %.2f far from the 25%% target", frac)
	}
}

func TestRolloutBucketIsStable(t *testing.T) {
	// The same agent must stay in or out of the canary across heartbeats.
	a, b := bucket("agt-stable"), bucket("agt-stable")
	if a != b {
		t.Error("bucket must be deterministic for an id")
	}
	if a < 0 || a >= 100 {
		t.Errorf("bucket out of range: %d", a)
	}
}

func TestPromoteAndAbort(t *testing.T) {
	r := NewRegistry(0)
	r.Enroll("agt-x", AgentInfo{})
	on := true

	r.StartRollout(DesiredState{LearningMode: &on}, 10)
	if _, active, _ := r.RolloutStatus(); !active {
		t.Fatal("rollout should be active after start")
	}

	// Promote to 100% -> pending becomes stable, rollout clears.
	ro, ok := r.PromoteRollout(100)
	if !ok || ro.Percent != 100 {
		t.Fatalf("promote to 100 should complete: %+v ok=%v", ro, ok)
	}
	if _, active, _ := r.RolloutStatus(); active {
		t.Error("rollout should be cleared after full promotion")
	}
	// Every agent now gets the promoted state.
	if d := r.DesiredForAgent("agt-x"); d.LearningMode == nil || !*d.LearningMode {
		t.Error("promoted state should apply to all agents")
	}

	// Abort of a fresh rollout reverts to stable (which is now learning=on).
	off := false
	r.StartRollout(DesiredState{LearningMode: &off}, 50)
	if !r.AbortRollout() {
		t.Error("abort should succeed for active rollout")
	}
	if r.AbortRollout() {
		t.Error("abort should fail when nothing is pending")
	}
}

// itoa avoids importing strconv in the test.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
