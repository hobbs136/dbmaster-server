-- U06 (task_usage_loop) — health check failure visibility.
--
-- A failed run (db unreachable, credential decrypt failure, collector error)
-- previously left NO health_check_results row: the desktop list inferred
-- status from results only, so "database down" rendered as unknown and the
-- 'failed' badge branch was unreachable. From migration 014 on, the runner
-- writes a results row for failed runs too, carrying the redacted error here.
--
-- 'error': short first-line redacted summary (mirrors task_run_history.error;
--   no credentials / SQL / PII). NULL for success/partial rows and for legacy
--   rows written before this migration.

ALTER TABLE health_check_results ADD COLUMN error TEXT;
