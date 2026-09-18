-- Schema drift v1 foundation (ADR-0002 §7.1 / §4.2.4 / §4.3.1 / §4 D7).
-- Adds three tables that subsequent phases populate, plus a `kind` discriminator
-- on database_connections so credential-use audit policy can differ between
-- collaboration-DB and source-drift-DB credentials (D2.1).
--
-- This migration is schema-only; Phase A does not yet write to these tables.
-- Phase C (snapshot), Phase D (audit), Phase E (run history) populate them.

-- CHANGE: ADR-0002 §4 D7 + §8 v1-C-9 — per-run audit trail. Replaces scalar
-- scheduled_tasks.last_status as the primary observability surface for runs.
-- 'status' values: 'running' | 'succeeded' | 'failed'.
-- 'triggered_by' values: 'scheduler' | 'manual:<user_id>'.
-- 'summary' is JSON (e.g. {"drift_count": N, "webhook_status": "ok|failed", "duration_ms": M}).
CREATE TABLE IF NOT EXISTS task_run_history (
    id           TEXT PRIMARY KEY,
    task_id      TEXT NOT NULL REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL,
    error        TEXT,
    summary      TEXT,
    triggered_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_run_history_task_time
    ON task_run_history(task_id, started_at DESC);

-- CHANGE: ADR-0002 §4.3.1 + §8 v1-C-10 — append-only schema snapshot chain.
-- 'schema_hash'  = sha256 of canonical 'schema_json'.
-- 'prior_hash'   = previous snapshot's schema_hash (NULL for the first snap);
--                  threading hashes gives a tamper-evident history.
-- 'change_count' = diff vs prior snapshot (0 on first snap).
-- 'schema_json'  = canonical JSON of tables/columns/pk/indexes/fk.
--                  NO row data ever enters this column (D5 boundary).
-- 'task_id'      = which scheduled task produced this snap (NULL = manual).
CREATE TABLE IF NOT EXISTS schema_snapshots (
    id            TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL REFERENCES database_connections(id) ON DELETE CASCADE,
    captured_at   TEXT NOT NULL,
    schema_hash   TEXT NOT NULL,
    schema_json   TEXT NOT NULL,
    prior_hash    TEXT,
    task_id       TEXT,
    change_count  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_snapshots_conn_time
    ON schema_snapshots(connection_id, captured_at DESC);

-- CHANGE: ADR-0002 §4.2.4 + §8 v1-C-5 — credential-use audit log.
-- One row per decryption/use of a stored credential.
-- 'action' values: 'schema_snapshot' | 'drift_compare' | 'canary_check' | 'webhook_deliver'.
-- 'status' values: 'ok' | 'error'.
-- 'error' holds a redacted summary (NO credential, NO SQL text, NO returned data, NO PII).
-- 'triggered_by' values: 'scheduler' | 'manual:<user_id>'.
CREATE TABLE IF NOT EXISTS credential_access_audit (
    id            TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL REFERENCES database_connections(id) ON DELETE CASCADE,
    action        TEXT NOT NULL,
    status        TEXT NOT NULL,
    error         TEXT,
    at            TEXT NOT NULL,
    triggered_by  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credential_audit_conn_time
    ON credential_access_audit(connection_id, at DESC);

-- CHANGE: ADR-0002 §4.2.1 (D2.1) — discriminator for collab vs source_drift
-- credentials. Existing rows default to 'collab' (their original purpose); new
-- source-drift connections set 'source_drift' and get distinct audit handling.
-- NOTE: SQLite's ALTER TABLE ADD COLUMN does NOT support IF NOT EXISTS; sqlx
-- tracks applied migrations in _sqlx_migrations so this runs exactly once per
-- database file. Re-deploying to a fresh DB is safe; re-running on an already-
-- migrated DB skips this file entirely.
ALTER TABLE database_connections ADD COLUMN kind TEXT NOT NULL DEFAULT 'collab';
