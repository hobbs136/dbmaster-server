//! dbmaster-drift — v1 schema-drift engine (ADR-0002).
//!
//! Domain: scan a customer's source DB schema on a schedule, snapshot it,
//! compare against the previous snapshot, and webhook-notify on drift.
//!
//! Module layout (one responsibility each, per ADR §7.1); phases add modules:
//! - [`snapshot`] — canonical JSON + sha256 hash of a collected schema (Phase B).
//! - [`collector`] — parameterized information_schema/pg_catalog introspection
//!   (MySQL + PostgreSQL). Read-only; never touches business rows (Phase B).
//! - `diff` — 11-kind structural drift detection (Phase C).
//! - `notify` — `dbmaster.drift-event.v1` webhook delivery (Phase D).
//! - `audit` — `credential_access_audit` writer (Phase D).
//! - `canary` — read-only enforcement at create_connection (Phase E).
//! - `scheduler` — `tokio::time::interval` scanner for due drift tasks (Phase E).
//! - `runner` — end-to-end orchestration (Phase E).
//!
//! Trust boundary (ADR §4 D2 / §6): the runner decrypts a stored source-DB
//! credential, opens a short-lived pool to the customer DB, introspects
//! `information_schema` / `pg_catalog` ONLY, and tears the pool down. The
//! webhook payload is hard-excluded from carrying host/port/user/password or
//! any row data.

// CHANGE: ADR-0002 §7.1 — crate scaffold (Phase B-E complete).
pub mod audit;
pub mod canary;
pub mod collector;
pub mod diff;
pub mod notify;
pub mod runner;
pub mod scheduler;
pub mod snapshot;

pub use audit::{log_access as log_credential_access, AuditAction, AuditStatus};
pub use diff::{compute_drifts, summarize, Drift, DriftKind, DriftKindCounts, DriftObject};
pub use notify::{
    deliver, deliver_with_backoff, validate_webhook_url, ConnectionRef, DeliveryReceipt,
    DeliveryStatus, DriftSummary, NotifyError, PAYLOAD_SCHEMA, SourceRef, TaskRef, WebhookPayload,
};
pub use runner::{run_task, RunOutcome, RunSummary};
pub use scheduler::{spawn as spawn_scheduler, InFlightTasks, SchedulerHandle};
pub use snapshot::{
    ColumnSchema, DbType, ForeignKey, IndexSchema, PrimaryKey, SchemaSnapshot, TableSchema,
};

// CHANGE: ADR-0002 v1-C-9 — DriftRunner impl bridging the manual-run HTTP
// handler (in automation) to drift::runner::run_task, without automation
// depending on drift. The binary crate constructs Arc<DriftRunnerHandle>
// and injects it into AppState.
#[async_trait::async_trait]
impl dbmaster_core::server::DriftRunner for DriftRunnerHandle {
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
                // task_run_history.error; surface the same redacted string
                // to the caller for structured logging.
                let s = e.to_string();
                s.chars().take(500).collect::<String>()
            })?;
        tracing::info!(
            task_id,
            drift_count = outcome.drift_count,
            webhook_status = %outcome.webhook_status,
            triggered_by,
            "drift run completed via DriftRunner bridge"
        );
        Ok(())
    }
}

/// Empty implementation carrier; [`dbmaster_core::server::DriftRunner`] is
/// implemented for it above. The unit struct exists only to name the impl —
/// the runner is stateless (all state lives in [`runner::run_task`]).
#[derive(Debug, Clone, Copy)]
pub struct DriftRunnerHandle;

