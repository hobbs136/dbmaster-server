-- Health check engine v1 foundation (ADR-0004 §2.4).
--
-- Two tables:
--   health_check_results — one row per inspection run (append-only, rotated
--     by the runner per config.retention_days).
--   health_alert_state   — per (task, metric) alert state machine row,
--     carrying the Ok → Failing(count) → Alerting → Resolved transition
--     state plus the last-seen detail used for incremental structural
--     alerting (e.g. missing-PK table set).
--
-- Reuses scheduled_tasks (task_type='health_check') + task_run_history from
-- earlier migrations; no new task or run-history table is introduced.

-- CHANGE: ADR-0004 §2.4 — per-inspection results.
-- 'status': 'success' | 'failed' | 'partial' (a metric failing to collect
--   without aborting the whole run → 'partial').
-- 'metrics_summary': canonical JSON of the MetricsSnapshot collected this
--   run (connectivity / row_count / missing_pk / connection_count).
-- 'alert_changes': JSON array of the AlertChange events produced this run
--   (Alert + Resolved), empty if none.
-- 'triggered_by': 'scheduler' | 'manual:<user_id>' (ADR-0002 §4.2.4 convention).
CREATE TABLE IF NOT EXISTS health_check_results (
    id              TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL,
    metrics_summary TEXT NOT NULL,
    alert_changes   TEXT NOT NULL DEFAULT '[]',
    triggered_by    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_health_results_task_time
    ON health_check_results(task_id, started_at DESC);

-- CHANGE: ADR-0004 §2.3 / §2.4 — per (task, metric) alert state machine.
-- 'metric': 'connectivity' | 'row_count' | 'missing_pk' | 'connection_count'.
-- 'state': 'ok' | 'failing' | 'alerting'.
-- 'fail_count': consecutive failure/over-threshold count while state='failing';
--   reaching config.fail_threshold flips state to 'alerting' (Alert webhook).
-- 'detail': metric-specific JSON carrying the last-seen context; for
--   missing_pk it holds {"last_missing": [...]} so incremental alerting can
--   diff the new set against the prior one (newly-missing → Alert,
--   newly-restored → Resolved).
CREATE TABLE IF NOT EXISTS health_alert_state (
    task_id     TEXT NOT NULL REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
    metric      TEXT NOT NULL,
    state       TEXT NOT NULL,
    fail_count  INTEGER NOT NULL DEFAULT 0,
    detail      TEXT,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (task_id, metric)
);
