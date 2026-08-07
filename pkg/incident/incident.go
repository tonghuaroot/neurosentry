// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Package incident turns raw detections into managed cases with a lifecycle
// (open -> acknowledged -> resolved / false-positive), assignment, and notes.
// It is what makes the console a SOC workbench rather than a read-only viewer:
// recurring detections of the same rule for the same process are grouped into
// one case with a hit count, the way an alerting product deduplicates.
package incident

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/neurosentry/neurosentry/pkg/correlate"
)

// Snapshot serializes all cases so the store can be persisted to a durable
// backend and survive restarts.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(s.cases)
}

// Restore replaces the store's contents from a Snapshot blob (called on startup
// before any new detections arrive).
func (s *Store) Restore(data []byte) error {
	var cases []*Case
	if err := json.Unmarshal(data, &cases); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cases = cases
	s.byID = make(map[string]*Case, len(cases))
	for _, c := range cases {
		s.byID[c.ID] = c
	}
	if len(s.cases) > s.maxCases {
		s.cases = s.cases[len(s.cases)-s.maxCases:]
	}
	return nil
}

// Status is a case lifecycle state.
type Status string

const (
	StatusOpen         Status = "open"
	StatusAcknowledged Status = "acknowledged"
	StatusResolved     Status = "resolved"
	StatusFalse        Status = "false_positive"
)

func validStatus(s Status) bool {
	switch s {
	case StatusOpen, StatusAcknowledged, StatusResolved, StatusFalse:
		return true
	}
	return false
}

// NoteRevision is a superseded version of a note's text, retained so an edit
// can be audited and diffed (chain of custody on analyst commentary).
type NoteRevision struct {
	Text string    `json:"text"`
	At   time.Time `json:"at"` // when this text was replaced
}

// Note is a timestamped analyst comment on a case. Edits keep the prior text in
// Revisions (append-only) so the change is diffable and never silently lost.
type Note struct {
	ID        string         `json:"id"`
	Author    string         `json:"author"`
	Text      string         `json:"text"`
	At        time.Time      `json:"at"`
	EditedAt  time.Time      `json:"edited_at,omitzero"`
	EditedBy  string         `json:"edited_by,omitempty"`
	Revisions []NoteRevision `json:"revisions,omitempty"`
	// Deletion is a soft tombstone: the note text is retained so the removal is
	// auditable and shown as a deletion diff, and can be restored.
	Deleted   bool      `json:"deleted,omitempty"`
	DeletedAt time.Time `json:"deleted_at,omitzero"`
	DeletedBy string    `json:"deleted_by,omitempty"`
}

// Case is a managed detection with investigation/response state.
type Case struct {
	ID          string             `json:"id"`
	RuleID      string             `json:"rule_id"`
	Rule        string             `json:"rule"`
	Severity    string             `json:"severity"`
	Technique   string             `json:"technique,omitempty"`
	MitreAttack string             `json:"mitre_attack,omitempty"`
	Description string             `json:"description"`
	PID         int                `json:"pid"`
	TenantID    string             `json:"tenant_id,omitempty"`
	Chain       []correlate.Signal `json:"chain,omitempty"`
	Count       int                `json:"count"`
	Status      Status             `json:"status"`
	Assignee    string             `json:"assignee,omitempty"`
	Notes       []Note             `json:"notes,omitempty"`
	FirstSeen   time.Time          `json:"first_seen"`
	LastSeen    time.Time          `json:"last_seen"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// Store holds cases in memory (bounded). Safe for concurrent use.
type Store struct {
	mu          sync.Mutex
	cases       []*Case
	byID        map[string]*Case
	maxCases    int
	groupWindow time.Duration
	now         func() time.Time
}

// NewStore returns a case store. Recurrences of the same rule+PID within
// groupWindow (while the case is still open/acknowledged) are grouped.
func NewStore() *Store {
	return &Store{
		byID:        make(map[string]*Case),
		maxCases:    2000,
		groupWindow: 10 * time.Minute,
		now:         time.Now,
	}
}

// Add records a detection. It returns the (possibly existing) case.
func (s *Store) Add(f correlate.Finding) *Case {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	// Group into an existing active case for the same rule+process.
	for _, c := range s.cases {
		if c.RuleID == f.RuleID && c.PID == f.PID &&
			(c.Status == StatusOpen || c.Status == StatusAcknowledged) &&
			now.Sub(c.LastSeen) <= s.groupWindow {
			c.Count++
			c.LastSeen = now
			c.UpdatedAt = now
			return c
		}
	}

	c := &Case{
		ID: newID(), RuleID: f.RuleID, Rule: f.Rule, Severity: f.Severity,
		Technique: f.Technique, Description: f.Description, PID: f.PID,
		TenantID: f.TenantID, Chain: f.Chain, Count: 1, Status: StatusOpen,
		FirstSeen: now, LastSeen: now, UpdatedAt: now,
	}
	s.cases = append(s.cases, c)
	s.byID[c.ID] = c
	if len(s.cases) > s.maxCases {
		drop := s.cases[0]
		delete(s.byID, drop.ID)
		s.cases = s.cases[1:]
	}
	return c
}

// Filter narrows a List query. Empty fields match all.
type Filter struct {
	Status   Status
	Severity string
	Limit    int
}

// List returns cases newest-first, applying the filter.
func (s *Store) List(f Filter) []*Case {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Case, 0, len(s.cases))
	for _, c := range s.cases {
		if f.Status != "" && c.Status != f.Status {
			continue
		}
		if f.Severity != "" && c.Severity != f.Severity {
			continue
		}
		cp := *c
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}

// Get returns a copy of a case by ID.
func (s *Store) Get(id string) (*Case, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	cp := *c
	return &cp, true
}

// SetStatus transitions a case. Returns false if the id or status is invalid.
func (s *Store) SetStatus(id string, status Status) bool {
	if !validStatus(status) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return false
	}
	c.Status = status
	c.UpdatedAt = s.now()
	return true
}

// Assign sets the case owner.
func (s *Store) Assign(id, assignee string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return false
	}
	c.Assignee = assignee
	c.UpdatedAt = s.now()
	return true
}

// AddNote appends an analyst note and returns a copy of it (with its new ID).
func (s *Store) AddNote(id, author, text string) (*Note, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	n := Note{ID: newNoteID(), Author: author, Text: text, At: s.now()}
	c.Notes = append(c.Notes, n)
	c.UpdatedAt = s.now()
	return &n, true
}

// EditNote replaces a note's text, retaining the prior text as a revision so the
// edit is diffable. Returns a copy of the updated note. No-op text (unchanged)
// is accepted but records no new revision.
func (s *Store) EditNote(caseID, noteID, editor, text string) (*Note, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[caseID]
	if !ok {
		return nil, false
	}
	for i := range c.Notes {
		if c.Notes[i].ID != noteID {
			continue
		}
		n := &c.Notes[i]
		if n.Text != text {
			n.Revisions = append(n.Revisions, NoteRevision{Text: n.Text, At: s.now()})
			n.Text = text
			n.EditedAt = s.now()
			n.EditedBy = editor
			c.UpdatedAt = s.now()
		}
		cp := *n
		return &cp, true
	}
	return nil, false
}

// DeleteNote soft-deletes a note: it is flagged as a tombstone (text retained
// for the deletion diff / audit) rather than dropped, so the removal is
// reversible and never silently erases the record. Returns a copy of the
// tombstoned note.
func (s *Store) DeleteNote(caseID, noteID, actor string) (*Note, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[caseID]
	if !ok {
		return nil, false
	}
	for i := range c.Notes {
		if c.Notes[i].ID == noteID {
			n := &c.Notes[i]
			n.Deleted = true
			n.DeletedAt = s.now()
			n.DeletedBy = actor
			c.UpdatedAt = s.now()
			cp := *n
			return &cp, true
		}
	}
	return nil, false
}

// RestoreNote clears a note's deletion tombstone. Returns a copy of the note.
func (s *Store) RestoreNote(caseID, noteID string) (*Note, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[caseID]
	if !ok {
		return nil, false
	}
	for i := range c.Notes {
		if c.Notes[i].ID == noteID {
			n := &c.Notes[i]
			n.Deleted = false
			n.DeletedAt = time.Time{}
			n.DeletedBy = ""
			c.UpdatedAt = s.now()
			cp := *n
			return &cp, true
		}
	}
	return nil, false
}

// Stats is a case-count summary by status for the dashboard.
type Stats struct {
	Total        int `json:"total"`
	Open         int `json:"open"`
	Acknowledged int `json:"acknowledged"`
	Resolved     int `json:"resolved"`
	False        int `json:"false_positive"`
}

// Stats returns the case counts by status.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{Total: len(s.cases)}
	for _, c := range s.cases {
		switch c.Status {
		case StatusOpen:
			st.Open++
		case StatusAcknowledged:
			st.Acknowledged++
		case StatusResolved:
			st.Resolved++
		case StatusFalse:
			st.False++
		}
	}
	return st
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "case_" + hex.EncodeToString(b)
}

func newNoteID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "note_" + hex.EncodeToString(b)
}
