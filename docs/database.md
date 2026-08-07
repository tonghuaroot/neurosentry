# Audit Database Backends

NeuroSentry persists its durable, queryable audit trail (and a few small
key/value snapshots) to a pluggable SQL backend. Two backends are supported and
share the same schema, query surface, and tamper-evident hash-chain integrity
checks:

| Backend | Use for | Driver | CGO |
|---|---|---|---|
| **SQLite** (default) | single-node, demo, edge, dev | `modernc.org/sqlite` (pure Go) | none |
| **PostgreSQL** | production, HA, multi-node control plane | `github.com/jackc/pgx/v5/stdlib` (pure Go) | none |

Both drivers are pure Go, so the agent still builds and ships as a single static,
CGO-free binary:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/neurosentry
```

The durable store is optional. When it is not configured the agent keeps a
bounded in-memory audit ring (the last ~10,000 entries, lost on restart). Enable
a backend to retain **every** entry across restarts and query the trail at
volume for retention and compliance.

## Choosing a backend

Configuration lives under the `audit` section. Prefer a config **file** over
environment variables — the loader uses viper with `AutomaticEnv`, but nested
env-key mapping (e.g. `audit.db_dsn`) is not reliably wired, so nested keys
should come from the YAML file.

### SQLite (default)

```yaml
audit:
  enabled: true
  db_driver: sqlite                       # optional; sqlite is the default
  db_path: /var/lib/neurosentry/audit.db  # ":memory:" for ephemeral/tests
```

`db_path` is the on-disk database file. The store opens in **WAL** mode
(`journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`) so readers do not
block the single writer. SQLite is single-node and single-writer by design — use
it for one host, not for HA.

### PostgreSQL (production / HA)

```yaml
audit:
  enabled: true
  db_driver: postgres
  db_dsn: "postgres://neurosentry:CHANGEME@db:5432/neurosentry?sslmode=require"
```

Point every node at the same PostgreSQL instance for a shared, highly-available
audit store. Standard Postgres HA (streaming replication, managed failover,
connection pooler) applies unchanged.

### DSN format

The Postgres backend uses the `pgx` stdlib driver (registered driver name
`pgx`), which accepts either DSN form:

```text
# URL form
postgres://USER:PASSWORD@HOST:5432/DBNAME?sslmode=require

# keyword/value form
host=db port=5432 user=neurosentry password=CHANGEME dbname=neurosentry sslmode=require
```

Common `sslmode` values: `disable` (local/dev only), `require`, `verify-full`
(recommended in production). Any libpq keyword pgx supports (e.g.
`connect_timeout`, `pool_max_conns`) may be appended.

For SQLite, the "DSN" is simply the file path in `db_path` (or `:memory:`).

## What is stored

The backend maintains two tables.

### `audit_entries` — the tamper-evident chain

Every audit entry is appended as a row. Each row carries the hash-chain fields so
integrity can be re-verified straight from the database, independent of the
running process.

| Column | Meaning |
|---|---|
| `seq` | monotonic sequence number (primary key) |
| `id` | random 128-bit entry id |
| `ts` | event time, unix nanoseconds (indexed) |
| `event_type` | e.g. `model.access.blocked`, `correlation.finding` (indexed) |
| `severity` / `severity_id` | `info…critical` / 1–5 (severity indexed) |
| `actor_pid` / `actor_comm` | acting process, when known |
| `details` | event payload (JSON) |
| `prev_hash` / `hash` | SHA-256 chain link (`prev_hash` of row *n* = `hash` of row *n-1*; the first row links to the genesis hash) |

Because each entry's `hash` covers its id, sequence, timestamp, type, severity,
details, and `prev_hash`, any insertion, deletion, or edit of a persisted row is
detectable. The store can re-walk the whole chain in sequence order and prove the
evidence was not altered at rest.

### `kv_snapshots` — durable key/value blobs

An upsert table (`key` primary key, `data` blob, `updated_at`) for otherwise
in-memory state that must survive restarts. Today it holds the **`cases`**
snapshot — the SOC incident/case workbench — so analyst-owned cases persist. It
is written with `INSERT … ON CONFLICT(key) DO UPDATE` (last write wins per key).

## Operational notes

### Integrity verification

The chain can be re-verified end-to-end directly from the database (in `seq`
order, starting from the genesis hash). A mismatch pinpoints the first altered or
missing entry. Run this as part of periodic compliance/evidence checks.

### Backup

- **SQLite** — the database is a single file. Because it runs in WAL mode, take a
  *consistent* hot copy rather than `cp`-ing the live file:
  ```bash
  sqlite3 /var/lib/neurosentry/audit.db ".backup '/backup/audit-$(date +%F).db'"
  ```
  If you must copy raw files, copy `audit.db`, `audit.db-wal`, and `audit.db-shm`
  together while the agent is quiesced. On the compose stack the file lives on the
  `ns-data` volume.
- **PostgreSQL** — use your standard tooling: `pg_dump`/`pg_restore`, managed
  snapshots, or continuous archiving (WAL / PITR) for point-in-time recovery.

### Retention

The durable store keeps **every** entry (there is no automatic pruning); only the
in-memory ring is bounded. Size disk accordingly, or archive/prune cold rows by
`ts` on a schedule.

> Pruning caveat: full-chain verification starts from the genesis hash, so
> deleting the earliest rows breaks re-verification of the *entire* chain from
> the start (contiguous ranges you retain still verify internally). If you must
> prune, snapshot/export the removed range first for evidentiary continuity.

### Querying

Entries are queryable newest-first with filters for time range (`since`/`until`),
`severity`, an `event_type` prefix, plus `limit`/`offset` (default limit 500, max
10,000). The web console's audit API is backed by the same store when a durable
backend is attached.

### Backend parity

Both backends implement the identical write / query / count / verify / snapshot
contract, so switching from SQLite to PostgreSQL is a config change — no schema
migration on the NeuroSentry side and no code changes. Existing history is not
copied automatically; export/import if you need to carry it across a switch.

## See also

- [deployment.md](deployment.md) — one-command Docker Compose stack (NeuroSentry
  + PostgreSQL + Prometheus + Grafana).
