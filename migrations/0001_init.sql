-- Initial schema for the authoritative DNS zone distribution service.
-- All per-version data is immutable; versions form a linear per-zone chain.

CREATE TABLE IF NOT EXISTS zones (
  name            TEXT PRIMARY KEY,   -- canonical absolute lowercase apex
  current_serial  INTEGER NOT NULL,   -- uint32
  current_version INTEGER NOT NULL,   -- per-zone monotonic version id
  retain_versions INTEGER NOT NULL,   -- history retention policy (>= 1)
  record_count    INTEGER NOT NULL DEFAULT 0,
  rrset_count     INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS versions (
  zone        TEXT NOT NULL,
  version_id  INTEGER NOT NULL,
  serial      INTEGER NOT NULL,       -- uint32, unique within zone
  request_id  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (zone, version_id),
  UNIQUE (zone, serial)
);

-- Full immutable snapshot per version (materialized at publish time).
CREATE TABLE IF NOT EXISTS records (
  zone        TEXT NOT NULL,
  version_id  INTEGER NOT NULL,
  name        TEXT NOT NULL,
  rtype       TEXT NOT NULL,
  ttl         INTEGER NOT NULL,
  rdata       TEXT NOT NULL,          -- canonical JSON
  rdata_wire  BLOB NOT NULL,
  PRIMARY KEY (zone, version_id, name, rtype, rdata)
);
CREATE INDEX IF NOT EXISTS idx_records_version
  ON records (zone, version_id);

-- Per-publish RR delta, organized by publish boundary for IXFR output.
-- old_* set for a deletion, new_* set for an addition.
CREATE TABLE IF NOT EXISTS changes (
  zone        TEXT NOT NULL,
  version_id  INTEGER NOT NULL,
  seq         INTEGER NOT NULL,
  op          TEXT NOT NULL,          -- 'ADD' | 'DEL'
  name        TEXT NOT NULL,
  rtype       TEXT NOT NULL,
  ttl         INTEGER NOT NULL,
  rdata       TEXT NOT NULL,
  rdata_wire  BLOB NOT NULL,
  PRIMARY KEY (zone, version_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_changes_version
  ON changes (zone, version_id);

-- Persistent idempotency ledger.
CREATE TABLE IF NOT EXISTS publish_requests (
  zone            TEXT NOT NULL,
  request_id      TEXT NOT NULL,
  fingerprint     TEXT NOT NULL,
  status          TEXT NOT NULL,      -- COMMITTED | FAILED
  version_id      INTEGER,
  serial          INTEGER,
  error_code      TEXT,
  error_message   TEXT,
  error_status    INTEGER,
  error_details   TEXT,
  base_serial     INTEGER NOT NULL,
  next_serial     INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (zone, request_id)
);

-- TSIG-style transfer keys. Secret material is never exposed by any API and
-- is selected only inside the authentication transaction.
CREATE TABLE IF NOT EXISTS keys (
  zone        TEXT NOT NULL,
  key_id      TEXT NOT NULL,
  gen         INTEGER NOT NULL,       -- authorization generation, per zone
  key_name    TEXT NOT NULL,
  secret      BLOB NOT NULL,
  state       TEXT NOT NULL,          -- ACTIVE | RETIRING | REVOKED
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER,                -- RETIRING hard expiry (server UTC)
  revoked_at  INTEGER,
  PRIMARY KEY (zone, key_id)
);
CREATE INDEX IF NOT EXISTS idx_keys_lookup
  ON keys (zone, key_name, state);

-- In-flight transfer pins. A pinned version/generation is immune to cleanup
-- and the serving thread keeps the authenticated secret in its own memory.
-- min_version covers the oldest version an IXFR delta chain may read.
CREATE TABLE IF NOT EXISTS transfer_refs (
  ref_id      TEXT PRIMARY KEY,
  zone        TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  version_id  INTEGER NOT NULL,
  min_version INTEGER NOT NULL,
  key_gen     INTEGER NOT NULL,
  started_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  state       TEXT NOT NULL           -- OPEN | DONE
);
CREATE INDEX IF NOT EXISTS idx_transfer_refs_open
  ON transfer_refs (zone, state, version_id);

-- Durable cleanup task queue (lease/claim protocol).
CREATE TABLE IF NOT EXISTS cleanup_tasks (
  task_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  zone         TEXT NOT NULL,
  state        TEXT NOT NULL,         -- PENDING | RUNNING | DONE
  token        TEXT,
  leased_at    INTEGER,
  lease_expires INTEGER,
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_error   TEXT,
  created_at   INTEGER NOT NULL,
  finished_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cleanup_pending
  ON cleanup_tasks (state, lease_expires);
