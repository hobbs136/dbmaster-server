//! dbmaster-data-sync — v1 data-sync ETL engine.
//!
//! Domain: read a main (anchor) table from a customer source DB, optionally
//! LEFT JOIN related tables to build a wide row, and bulk-insert the result
//! into a target table. Runs are time-batched (anchor column), resumable
//! (cursor persisted to `data_sync_runs`), and cancellable (per-batch poll
//! of `cancel_requested`).
//!
//! Module layout:
//! - [`config`] — strongly-typed task config model + identifier validation.
//! - [`runner`] — end-to-end ETL orchestration (decrypt → batch JOIN → insert).
//! - [`scheduler`] — `tokio::time::interval` scanner for due cron tasks.
//! - [`sql`] — identifier-quoting helper.
//!
//! Trust boundary: the runner decrypts source/target credentials (reusing
//! `dbmaster_automation::credential`), opens short-lived pools, runs
//! parameterised SELECTs/INSERTs only, and redacts any error before
//! persistence. Identifiers are validated before any SQL is assembled.

pub mod clickhouse;
pub mod config;
pub mod doris_stream_load;
pub mod notify;
pub mod runner;
pub mod scheduler;
pub mod sql;

pub use config::DataSyncTaskConfig;
pub use runner::{run_task, RunOutcome};
pub use scheduler::{scan_and_dispatch, spawn as spawn_scheduler, InFlightTasks, SchedulerHandle};

// CHANGE: data-sync 一期 — DataSyncRunner impl bridging the manual-run HTTP
// handler (in automation) to data_sync::runner::run_task, without automation
// depending on data_sync. The binary crate constructs
// `Arc<DataSyncRunnerHandle>` and injects it into AppState. Mirrors the
// DriftRunner bridge (crates/drift/src/lib.rs).
#[async_trait::async_trait]
impl dbmaster_core::server::DataSyncRunner for DataSyncRunnerHandle {
    async fn run(
        &self,
        pool: &sqlx::SqlitePool,
        state: &dbmaster_core::server::AppState,
        task_id: &str,
        triggered_by: &str,
    ) -> Result<(), String> {
        let outcome = runner::run_task(pool, state, task_id, triggered_by)
            .await
            .map_err(|e| {
                // run_task has already persisted a redacted error to
                // data_sync_runs.error; surface the same redacted string to
                // the caller for structured logging.
                let s = e.to_string();
                s.chars().take(500).collect::<String>()
            })?;
        tracing::info!(
            task_id,
            processed = outcome.processed_rows,
            failed = outcome.failed_rows,
            canceled = outcome.canceled,
            triggered_by,
            "data_sync run completed via DataSyncRunner bridge"
        );
        Ok(())
    }
}

/// Empty implementation carrier; [`dbmaster_core::server::DataSyncRunner`] is
/// implemented for it above. The unit struct exists only to name the impl —
/// the runner is stateless (all state lives in [`runner::run_task`]).
#[derive(Debug, Clone, Copy)]
pub struct DataSyncRunnerHandle;
