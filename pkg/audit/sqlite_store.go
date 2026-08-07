// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pure-Go Postgres driver (database/sql name "pgx", CGO-free)
	_ "modernc.org/sqlite"             // pure-Go SQLite driver (CGO-free, cross-compiles)
)

// Store is the durable, indexed backend contract for the audit trail. The
// in-memory Chain keeps only a bounded recent window (and is lost on restart);
// a Store retains every entry across restarts and makes the trail queryable at
// volume — the retention + evidentiary requirements a real deployment (and
// compliance) demands. The hash chain is preserved per row, so integrity can be
// re-verified straight from the database.
//
// Implementations are pluggable: SQLite (embedded, CGO-free) for single-node
// and Postgres for production/HA. Both share identical hash-chain semantics.
type Store interface {
	// Write persists one entry. Implements the Chain EntrySink contract.
	Write(*Entry) error
	// Query returns matching entries newest-first.
	Query(QueryFilter) ([]*Entry, error)
	// Count returns the total number of persisted entries.
	Count() (int64, error)
	// VerifyChain re-verifies the tamper-evident hash chain at rest, in
	// sequence order, returning the number of entries checked.
	VerifyChain() (int, error)
	// SaveSnapshot persists an opaque blob under key (upsert).
	SaveSnapshot(key string, data []byte, at time.Time) error
	// LoadSnapshot returns the blob stored under key, or ok=false if none.
	LoadSnapshot(key string) ([]byte, bool, error)
	// Close releases the database.
	Close() error
}

// dbStore is a driver-aware durable audit backend over database/sql. A single
// implementation backs both SQLite and Postgres; the pg flag selects the
// dialect (placeholder style, schema types, and upsert syntax). All hash-chain
// logic is driver-independent and identical across backends.
type dbStore struct {
	db *sql.DB
	pg bool
}

// SQLiteStore is retained as the historical name of the durable store type. It
// is an alias for the driver-aware dbStore so existing references keep
// compiling; OpenSQLiteStore still returns a SQLite-backed instance.
type SQLiteStore = dbStore

// Compile-time proof the concrete store satisfies the pluggable Store contract.
var _ Store = (*SQLiteStore)(nil)

// OpenStore opens (creating schema if needed) a durable audit store using the
// named driver. Supported drivers: "sqlite" (dsn is a file path; use ":memory:"
// for tests) and "postgres" (dsn is a libpq/pgx connection string). "pg" and
// "postgresql" are accepted as aliases; an empty driver defaults to sqlite.
func OpenStore(driver, dsn string) (Store, error) {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "", "sqlite", "sqlite3":
		return openSQLite(dsn)
	case "postgres", "postgresql", "pg", "pgx":
		return openPostgres(dsn)
	default:
		return nil, fmt.Errorf("audit: unknown store driver %q (want sqlite|postgres)", driver)
	}
}

// OpenSQLiteStore opens (creating if needed) a SQLite-backed audit store at
// path. Use ":memory:" for tests. Retained for backward compatibility; it
// delegates to OpenStore.
func OpenSQLiteStore(path string) (Store, error) {
	return OpenStore("sqlite", path)
}

func openSQLite(path string) (*dbStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("audit sqlite: open: %w", err)
	}
	// Durability + concurrency: WAL keeps writers from blocking readers. These
	// pragmas are SQLite-only and must never run against Postgres.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("audit sqlite: %q: %w", pragma, err)
		}
	}
	if _, err := db.Exec(sqliteSchemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit sqlite: schema: %w", err)
	}
	return &dbStore{db: db, pg: false}, nil
}

func openPostgres(dsn string) (*dbStore, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("audit postgres: empty dsn (set audit.db_dsn)")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit postgres: open: %w", err)
	}
	// Fail fast on an unreachable/misconfigured database rather than at first
	// write, so a bad DSN surfaces at boot.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit postgres: ping: %w", err)
	}
	if _, err := db.Exec(pgSchemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit postgres: schema: %w", err)
	}
	return &dbStore{db: db, pg: true}, nil
}

// rebind converts '?' placeholders to $1..$N for Postgres; SQLite keeps '?'.
// The audit queries never embed a literal '?', so positional rewriting is safe.
func (s *dbStore) rebind(query string) string {
	if !s.pg {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

// SQLite schema: INTEGER primary key, BLOB snapshot payload, integer timestamps.
const sqliteSchemaSQL = `
CREATE TABLE IF NOT EXISTS audit_entries (
  seq         INTEGER PRIMARY KEY,
  id          TEXT NOT NULL,
  ts          INTEGER NOT NULL,   -- unix nanoseconds
  event_type  TEXT NOT NULL,
  severity    TEXT NOT NULL,
  severity_id INTEGER,
  actor_pid   INTEGER,
  actor_comm  TEXT,
  details     TEXT,               -- JSON
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_entries(ts);
CREATE INDEX IF NOT EXISTS idx_audit_sev  ON audit_entries(severity);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_entries(event_type);
CREATE TABLE IF NOT EXISTS kv_snapshots (
  key        TEXT PRIMARY KEY,
  data       BLOB NOT NULL,
  updated_at INTEGER NOT NULL
);
`

// Postgres schema: BIGINT primary key (seq/ts fit int64), BYTEA snapshot blob.
const pgSchemaSQL = `
CREATE TABLE IF NOT EXISTS audit_entries (
  seq         BIGINT PRIMARY KEY,
  id          TEXT NOT NULL,
  ts          BIGINT NOT NULL,    -- unix nanoseconds
  event_type  TEXT NOT NULL,
  severity    TEXT NOT NULL,
  severity_id INTEGER,
  actor_pid   INTEGER,
  actor_comm  TEXT,
  details     TEXT,               -- JSON
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_entries(ts);
CREATE INDEX IF NOT EXISTS idx_audit_sev  ON audit_entries(severity);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_entries(event_type);
CREATE TABLE IF NOT EXISTS kv_snapshots (
  key        TEXT PRIMARY KEY,
  data       BYTEA NOT NULL,
  updated_at BIGINT NOT NULL
);
`

// SaveSnapshot persists an opaque blob under key (upsert). Used to make
// otherwise in-memory stores (cases, etc.) durable in the same database.
func (s *dbStore) SaveSnapshot(key string, data []byte, at time.Time) error {
	// ON CONFLICT (key) DO UPDATE with the excluded pseudo-row is valid in both
	// SQLite and Postgres, so a single statement serves both dialects.
	q := `INSERT INTO kv_snapshots (key,data,updated_at) VALUES (?,?,?)
	      ON CONFLICT (key) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`
	if _, err := s.db.Exec(s.rebind(q), key, data, at.UnixNano()); err != nil {
		return fmt.Errorf("audit store: save snapshot %q: %w", key, err)
	}
	return nil
}

// LoadSnapshot returns the blob stored under key, or ok=false if none.
func (s *dbStore) LoadSnapshot(key string) ([]byte, bool, error) {
	var data []byte
	err := s.db.QueryRow(s.rebind(`SELECT data FROM kv_snapshots WHERE key = ?`), key).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

// Write persists one entry. It implements the Chain sink contract, so attaching
// it makes every appended entry durable. Duplicate seq values (replays) are
// idempotently ignored: SQLite via INSERT OR IGNORE, Postgres via ON CONFLICT
// (seq) DO NOTHING.
func (s *dbStore) Write(e *Entry) error {
	var detailsJSON string
	if e.Details != nil {
		b, _ := json.Marshal(e.Details)
		detailsJSON = string(b)
	}
	var pid int
	var comm string
	if e.Actor != nil {
		pid = e.Actor.PID
		comm = e.Actor.Comm
	}
	const cols = `(seq,id,ts,event_type,severity,severity_id,actor_pid,actor_comm,details,prev_hash,hash)`
	const vals = `VALUES (?,?,?,?,?,?,?,?,?,?,?)`
	var q string
	if s.pg {
		q = `INSERT INTO audit_entries ` + cols + ` ` + vals + ` ON CONFLICT (seq) DO NOTHING`
	} else {
		q = `INSERT OR IGNORE INTO audit_entries ` + cols + ` ` + vals
	}
	// seq stored as int64 (BIGINT/INTEGER) — driver-agnostic and safe for the
	// monotonically increasing sequence numbers we emit.
	_, err := s.db.Exec(s.rebind(q),
		int64(e.SequenceNum), e.ID, e.Timestamp.UnixNano(), e.EventType, string(e.Severity),
		e.SeverityID, pid, comm, detailsJSON, e.PrevHash, e.Hash,
	)
	if err != nil {
		return fmt.Errorf("audit store: write: %w", err)
	}
	return nil
}

// LastSeqHash returns the sequence number and hash of the highest-seq persisted
// entry (ok=false if the store is empty). It lets a fresh Chain resume its
// sequence + hash chain across restarts instead of restarting at seq 0 (which
// would collide with existing rows and fork the chain).
func (s *dbStore) LastSeqHash() (uint64, string, bool, error) {
	var seq int64
	var hash string
	err := s.db.QueryRow(`SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, "", false, nil
		}
		return 0, "", false, err
	}
	return uint64(seq), hash, true, nil
}

// QueryFilter narrows a durable query. Zero fields match all.
type QueryFilter struct {
	Since      time.Time
	Until      time.Time
	Severity   string
	TypePrefix string
	Limit      int
	Offset     int
}

// Query returns matching entries newest-first, reconstructed from the store.
func (s *dbStore) Query(f QueryFilter) ([]*Entry, error) {
	var where []string
	var args []any
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.Since.UnixNano())
	}
	if !f.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, f.Until.UnixNano())
	}
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, f.Severity)
	}
	if f.TypePrefix != "" {
		where = append(where, "event_type LIKE ?")
		args = append(args, f.TypePrefix+"%")
	}
	q := "SELECT seq,id,ts,event_type,severity,severity_id,actor_pid,actor_comm,details,prev_hash,hash FROM audit_entries"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY seq DESC"
	limit := f.Limit
	if limit <= 0 || limit > 10000 {
		limit = 500
	}
	q += " LIMIT ? OFFSET ?"
	args = append(args, limit, f.Offset)

	rows, err := s.db.Query(s.rebind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("audit store: query: %w", err)
	}
	defer rows.Close()

	var out []*Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Count returns the total number of persisted entries.
func (s *dbStore) Count() (int64, error) {
	var n int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM audit_entries").Scan(&n)
	return n, err
}

// VerifyChain re-verifies the tamper-evident hash chain directly from the
// database, in sequence order — proving the persisted evidence was not altered
// at rest. Returns the number of entries checked. The hash/chain logic is
// identical across SQLite and Postgres.
func (s *dbStore) VerifyChain() (int, error) {
	rows, err := s.db.Query(`SELECT seq,id,ts,event_type,severity,severity_id,actor_pid,actor_comm,details,prev_hash,hash
	                         FROM audit_entries ORDER BY seq ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	prevHash := GenesisHash
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return n, err
		}
		if got := computeHash(e); got != e.Hash {
			return n, fmt.Errorf("entry %d (%s): hash mismatch at rest (stored=%s computed=%s)", e.SequenceNum, e.ID, e.Hash, got)
		}
		if e.PrevHash != prevHash {
			return n, fmt.Errorf("entry %d (%s): broken chain (prev=%s expected=%s)", e.SequenceNum, e.ID, e.PrevHash, prevHash)
		}
		prevHash = e.Hash
		n++
	}
	return n, rows.Err()
}

// Close releases the database.
func (s *dbStore) Close() error { return s.db.Close() }

func scanEntry(rows *sql.Rows) (*Entry, error) {
	var (
		e           Entry
		seq         int64
		tsNano      int64
		detailsJSON string
		pid         int
		comm        string
	)
	if err := rows.Scan(&seq, &e.ID, &tsNano, &e.EventType, &e.Severity,
		&e.SeverityID, &pid, &comm, &detailsJSON, &e.PrevHash, &e.Hash); err != nil {
		return nil, err
	}
	e.SequenceNum = uint64(seq)
	e.Timestamp = time.Unix(0, tsNano)
	if detailsJSON != "" {
		_ = json.Unmarshal([]byte(detailsJSON), &e.Details)
	}
	if pid != 0 || comm != "" {
		e.Actor = &Actor{PID: pid, Comm: comm}
	}
	return &e, nil
}
