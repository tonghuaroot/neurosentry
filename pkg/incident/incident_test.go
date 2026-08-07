// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package incident

import (
	"testing"
	"time"

	"github.com/neurosentry/neurosentry/pkg/correlate"
)

type clk struct{ t time.Time }

func (c *clk) now() time.Time          { return c.t }
func (c *clk) advance(d time.Duration) { c.t = c.t.Add(d) }

func find(rule string, pid int) correlate.Finding {
	return correlate.Finding{RuleID: rule, Rule: rule, PID: pid, Severity: "high", Description: "d"}
}

func TestAddCreatesCase(t *testing.T) {
	s := NewStore()
	c := s.Add(find("R1", 100))
	if c.ID == "" || c.Status != StatusOpen || c.Count != 1 {
		t.Fatalf("unexpected case: %+v", c)
	}
	if s.Stats().Open != 1 {
		t.Error("stats should show 1 open")
	}
}

func TestGroupingSameRulePID(t *testing.T) {
	cl := &clk{t: time.Unix(1000, 0)}
	s := NewStore()
	s.now = cl.now
	c1 := s.Add(find("R1", 100))
	cl.advance(30 * time.Second)
	c2 := s.Add(find("R1", 100)) // same rule+pid, within window -> grouped
	if c1.ID != c2.ID {
		t.Error("recurrence should group into the same case")
	}
	if c2.Count != 2 {
		t.Errorf("expected count 2, got %d", c2.Count)
	}
	if s.Stats().Total != 1 {
		t.Errorf("expected 1 total case, got %d", s.Stats().Total)
	}
}

func TestNoGroupDifferentPID(t *testing.T) {
	s := NewStore()
	s.Add(find("R1", 100))
	s.Add(find("R1", 200))
	if s.Stats().Total != 2 {
		t.Error("different PIDs should be separate cases")
	}
}

func TestResolvedCaseDoesNotGroup(t *testing.T) {
	cl := &clk{t: time.Unix(1000, 0)}
	s := NewStore()
	s.now = cl.now
	c := s.Add(find("R1", 100))
	s.SetStatus(c.ID, StatusResolved)
	cl.advance(10 * time.Second)
	s.Add(find("R1", 100)) // resolved -> new case opens
	if s.Stats().Total != 2 {
		t.Error("a recurrence after resolution should open a new case")
	}
}

func TestLifecycleTransitions(t *testing.T) {
	s := NewStore()
	c := s.Add(find("R1", 100))
	if !s.SetStatus(c.ID, StatusAcknowledged) {
		t.Fatal("ack should succeed")
	}
	if !s.SetStatus(c.ID, StatusResolved) {
		t.Fatal("resolve should succeed")
	}
	if s.SetStatus(c.ID, "bogus") {
		t.Error("invalid status must be rejected")
	}
	if s.SetStatus("nope", StatusResolved) {
		t.Error("unknown id must be rejected")
	}
	st := s.Stats()
	if st.Resolved != 1 || st.Open != 0 {
		t.Errorf("stats wrong after resolve: %+v", st)
	}
}

func TestAssignAndNote(t *testing.T) {
	s := NewStore()
	c := s.Add(find("R1", 100))
	if !s.Assign(c.ID, "analyst@corp") {
		t.Fatal("assign should succeed")
	}
	n, ok := s.AddNote(c.ID, "analyst@corp", "investigating")
	if !ok || n == nil || n.ID == "" {
		t.Fatal("note should succeed and return an id")
	}
	got, _ := s.Get(c.ID)
	if got.Assignee != "analyst@corp" || len(got.Notes) != 1 || got.Notes[0].Text != "investigating" {
		t.Errorf("assign/note not persisted: %+v", got)
	}

	// Edit records a revision and updates the text.
	if _, ok := s.EditNote(c.ID, n.ID, "lead@corp", "investigating — confirmed malicious"); !ok {
		t.Fatal("edit should succeed")
	}
	got, _ = s.Get(c.ID)
	if got.Notes[0].Text != "investigating — confirmed malicious" || len(got.Notes[0].Revisions) != 1 || got.Notes[0].Revisions[0].Text != "investigating" {
		t.Errorf("edit did not record revision: %+v", got.Notes[0])
	}
	// Editing to the same text records no new revision.
	if _, ok := s.EditNote(c.ID, n.ID, "lead@corp", got.Notes[0].Text); !ok {
		t.Fatal("no-op edit should still succeed")
	}
	got, _ = s.Get(c.ID)
	if len(got.Notes[0].Revisions) != 1 {
		t.Errorf("no-op edit should not add a revision: %d", len(got.Notes[0].Revisions))
	}
	// Soft-delete keeps the note as a tombstone (text retained, flagged).
	if _, ok := s.DeleteNote(c.ID, n.ID, "lead@corp"); !ok {
		t.Fatal("delete should succeed")
	}
	got, _ = s.Get(c.ID)
	if len(got.Notes) != 1 || !got.Notes[0].Deleted || got.Notes[0].DeletedBy != "lead@corp" || got.Notes[0].Text == "" {
		t.Errorf("soft-delete not applied: %+v", got.Notes)
	}
	// Restore clears the tombstone.
	if _, ok := s.RestoreNote(c.ID, n.ID); !ok {
		t.Fatal("restore should succeed")
	}
	got, _ = s.Get(c.ID)
	if got.Notes[0].Deleted || !got.Notes[0].DeletedAt.IsZero() {
		t.Errorf("restore did not clear tombstone: %+v", got.Notes[0])
	}
	if _, ok := s.DeleteNote(c.ID, "note_missing", "x"); ok {
		t.Error("deleting a missing note should fail")
	}
}

func TestListFilters(t *testing.T) {
	s := NewStore()
	a := s.Add(correlate.Finding{RuleID: "R1", PID: 1, Severity: "critical"})
	s.Add(correlate.Finding{RuleID: "R2", PID: 2, Severity: "high"})
	s.SetStatus(a.ID, StatusResolved)

	if len(s.List(Filter{Status: StatusResolved})) != 1 {
		t.Error("status filter failed")
	}
	if len(s.List(Filter{Severity: "critical"})) != 1 {
		t.Error("severity filter failed")
	}
	if len(s.List(Filter{Limit: 1})) != 1 {
		t.Error("limit failed")
	}
	if len(s.List(Filter{})) != 2 {
		t.Error("unfiltered should return all")
	}
}

func TestGetReturnsCopy(t *testing.T) {
	s := NewStore()
	c := s.Add(find("R1", 100))
	got, _ := s.Get(c.ID)
	got.Status = StatusResolved
	again, _ := s.Get(c.ID)
	if again.Status == StatusResolved {
		t.Error("Get must return a copy, not a live pointer")
	}
}
