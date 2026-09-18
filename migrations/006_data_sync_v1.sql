-- data_sync v1 — dedicated run-history table for the data-sync ETL engine.
--
-- Separate from task_run_history (drift's table) because data-sync needs
-- progress / cursor / cancel_requested — concepts drift never uses. Keeping
-- them apart keeps drift's observable surface clean and lets data-sync add
-- its own columns without touching drift's FromRow model column order.
--
-- A row is opened per invocation of data_sync::runner::run_task; the runner
-- updates progress/cursor/processed_rows/failed_rows per batch and writes
-- the terminal status (succeeded/failed/canceled) on completion.

CREATE TABLE IF NOT EXISTS data_sync_runs (
    id                TEXT PRIMARY KEY,
    task_id           TEXT NOT NULL REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    status            TEXT NOT NULL,              -- running|succeeded|failed|canceled
    progress          INTEGER NOT NULL DEFAULT 0, -- 0..100 (approximate; UI feedback)
    cursor            TEXT,                       -- ISO8601 anchor of the next batch
    processed_rows    INTEGER NOT NULL DEFAULT 0,
    failed_rows       INTEGER NOT NULL DEFAULT 0,
    error             TEXT,                       -- redacted (no SQL / credential / PII)
    summary           TEXT,                       -- JSON: {duration_ms, processed_rows, failed_rows, canceled}
    triggered_by      TEXT NOT NULL,              -- 'scheduler' | 'manual:<user_id>'
    cancel_requested  INTEGER NOT NULL DEFAULT 0  -- set to 1 by POST /api/tasks/:id/cancel
);

CREATE INDEX IF NOT EXISTS idx_data_sync_runs_task_time
    ON data_sync_runs(task_id, started_at DESC);
