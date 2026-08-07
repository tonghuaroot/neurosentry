// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"crypto/rand"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Entry struct {
	ID          string         `json:"id"`
	SequenceNum uint64         `json:"sequence_num"`
	Timestamp   time.Time      `json:"timestamp"`
	EventType   string         `json:"event_type"`
	Severity    Severity       `json:"severity"`
	SeverityID  int            `json:"severity_id"`
	CategoryUID int            `json:"category_uid,omitempty"`
	ClassUID    int            `json:"class_uid,omitempty"`
	Actor       *Actor         `json:"actor,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
	Metadata    *EntryMetadata `json:"metadata,omitempty"`
	PrevHash    string         `json:"prev_hash"`
	Hash        string         `json:"hash"`
}

type Actor struct {
	PID  int    `json:"pid,omitempty"`
	UID  int    `json:"uid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

type EntryMetadata struct {
	Product string `json:"product"`
	Version string `json:"version"`
}

const (
	CategorySecurity = 2
	CategoryNetwork  = 4
	ClassFileSys     = 1001
	ClassNetwork     = 4001
	ClassFinding     = 2001
)

var severityIDMap = map[Severity]int{
	SeverityInfo: 1, SeverityLow: 2, SeverityMedium: 3,
	SeverityHigh: 4, SeverityCritical: 5,
}

func NewEntry(eventType string, severity Severity, details map[string]any) *Entry {
	return &Entry{
		ID:         generateID(),
		Timestamp:  time.Now(),
		EventType:  eventType,
		Severity:   severity,
		SeverityID: severityIDMap[severity],
		Details:    details,
		Metadata:   &EntryMetadata{Product: "neurosentry", Version: "0.2.0"},
	}
}

func (e *Entry) SetActor(pid, uid int, comm string) {
	e.Actor = &Actor{PID: pid, UID: uid, Comm: comm}
}

func (e *Entry) SetCategory(category, class int) {
	e.CategoryUID = category
	e.ClassUID = class
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func computeHash(e *Entry) string {
	h := sha256.New()
	h.Write([]byte(e.ID))
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, e.SequenceNum)
	h.Write(seq)
	h.Write([]byte(e.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(e.EventType))
	h.Write([]byte(e.Severity))
	if e.Details != nil {
		data, _ := json.Marshal(e.Details)
		h.Write(data)
	}
	h.Write([]byte(e.PrevHash))
	return hex.EncodeToString(h.Sum(nil))
}

const DefaultMaxEntries = 10000

// EntrySink receives every appended entry for durable persistence (e.g. the
// SQLite store). It is written through synchronously so an entry is durable
// before Append returns.
type EntrySink interface {
	Write(*Entry) error
}

type Chain struct {
	mu          sync.Mutex
	entries     []*Entry
	nextSeq     uint64
	maxEntries  int
	totalCount  int64
	sink        EntrySink
	resumedHash string // prev-hash seed after resuming from a durable store
}

// Resumable is an optional capability of a durable sink: it reports the last
// persisted (seq, hash) so a fresh Chain can continue the sequence and hash
// chain across restarts instead of restarting at genesis.
type Resumable interface {
	LastSeqHash() (seq uint64, hash string, ok bool, err error)
}

// AttachSink wires a durable backend. Existing entries already in memory are
// replayed into the sink so it starts consistent with the chain.
func (c *Chain) AttachSink(sink EntrySink) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sink = sink
	// If the chain is fresh (a restart) and the sink already holds persisted
	// entries, resume the sequence + prev-hash from the store's last entry so
	// new entries continue the chain instead of colliding at seq 0.
	if len(c.entries) == 0 && c.nextSeq == 0 {
		if r, ok := sink.(Resumable); ok {
			if seq, hash, has, err := r.LastSeqHash(); err == nil && has {
				c.nextSeq = seq + 1
				c.resumedHash = hash
				c.totalCount = int64(seq + 1) //nolint:gosec // G115: audit sequence numbers never approach int64 max
			}
		}
	}
	for _, e := range c.entries {
		_ = sink.Write(e)
	}
}

func NewChain() *Chain {
	return &Chain{maxEntries: DefaultMaxEntries}
}

func NewChainWithCapacity(max int) *Chain {
	if max <= 0 {
		max = DefaultMaxEntries
	}
	return &Chain{maxEntries: max}
}

func (c *Chain) Append(e *Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	e.SequenceNum = c.nextSeq
	c.nextSeq++

	if len(c.entries) == 0 {
		if c.resumedHash != "" {
			e.PrevHash = c.resumedHash // continue the chain across a restart
		} else {
			e.PrevHash = GenesisHash
		}
	} else {
		e.PrevHash = c.entries[len(c.entries)-1].Hash
	}

	e.Hash = computeHash(e)
	c.entries = append(c.entries, e)
	c.totalCount++

	if len(c.entries) > c.maxEntries {
		c.entries = c.entries[len(c.entries)-c.maxEntries:]
	}

	// Persist durably before returning so the entry survives restart and the
	// in-memory ring can drop it without losing the evidence.
	if c.sink != nil {
		if err := c.sink.Write(e); err != nil {
			return fmt.Errorf("audit: durable write: %w", err)
		}
	}
	return nil
}

func (c *Chain) TotalCount() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalCount
}

func (c *Chain) Verify() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, e := range c.entries {
		expected := computeHash(e)
		if e.Hash != expected {
			return fmt.Errorf("entry %d (%s): hash mismatch (stored=%s, computed=%s)", i, e.ID, e.Hash, expected)
		}

		if i == 0 {
			// entries is a bounded, resumable window: only the genuine first
			// entry of the whole chain (sequence 0) must carry the genesis
			// prev-hash. When the ring has evicted earlier entries (or the chain
			// resumed after restart), entries[0] legitimately links to an entry
			// we no longer hold — so we can't check its prev-hash here, but that
			// is not tampering. The durable store verifies the full chain.
			if e.SequenceNum == 0 && e.PrevHash != GenesisHash {
				return fmt.Errorf("entry 0: prev_hash should be genesis hash")
			}
		} else {
			if e.PrevHash != c.entries[i-1].Hash {
				return fmt.Errorf("entry %d: prev_hash does not match previous entry hash", i)
			}
		}
	}
	return nil
}

func (c *Chain) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Chain) Entries() []*Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]*Entry, len(c.entries))
	for i, e := range c.entries {
		eCopy := *e
		cp[i] = &eCopy
	}
	return cp
}
