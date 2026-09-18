-- Automation engine schema: connections, scheduled tasks, approvals, saved queries, reports, telemetry
-- Applied automatically at server startup via sqlx::migrate!().

-- Database connections (shared or personal)
CREATE TABLE IF NOT EXISTS database_connections (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    db_type             TEXT NOT NULL DEFAULT 'mysql',
    host                TEXT NOT NULL,
    port                INTEGER NOT NULL DEFAULT 3306,
    username            TEXT NOT NULL,
    password_encrypted  TEXT NOT NULL,
    default_database    TEXT,
    ssh_enabled         INTEGER NOT NULL DEFAULT 0,
    ssh_host            TEXT,
    ssh_port            INTEGER,
    team_id             TEXT,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_connections_team ON database_connections(team_id);

-- Scheduled tasks (cron-driven automation)
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    task_type       TEXT NOT NULL DEFAULT 'data_sync',
    cron_expr       TEXT NOT NULL,
    config          TEXT NOT NULL DEFAULT '{}',
    source_db_id    TEXT NOT NULL REFERENCES database_connections(id) ON DELETE CASCADE,
    target_db_id    TEXT REFERENCES database_connections(id) ON DELETE SET NULL,
    notify_channels TEXT NOT NULL DEFAULT '[]',
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_run_at     TEXT,
    last_status     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_tasks_enabled ON scheduled_tasks(enabled);

-- DDL approvals
CREATE TABLE IF NOT EXISTS ddl_approvals (
    id           TEXT PRIMARY KEY,
    submitter_id TEXT NOT NULL,
    ddl_sql      TEXT NOT NULL,
    target_db_id TEXT NOT NULL REFERENCES database_connections(id),
    reviewer_id  TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at  TEXT
);

-- Team query library
CREATE TABLE IF NOT EXISTS saved_queries (
    id           TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    sql_text     TEXT NOT NULL,
    tags         TEXT NOT NULL DEFAULT '[]',
    workspace_id TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Generated reports
CREATE TABLE IF NOT EXISTS reports (
    id          TEXT PRIMARY KEY,
    task_id     TEXT NOT NULL REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
    report_type TEXT NOT NULL,
    title       TEXT NOT NULL,
    content     TEXT NOT NULL DEFAULT '{}',
    generated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_reports_task ON reports(task_id, generated_at DESC);

-- Telemetry events
CREATE TABLE IF NOT EXISTS telemetry_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    install_uuid        TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    event_payload       TEXT NOT NULL DEFAULT '{}',
    db_type             TEXT,
    client_ip_redacted  TEXT,
    received_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_telemetry_uuid ON telemetry_events(install_uuid, event_type, received_at);
