//! dbmaster-health-check — scheduled DB health monitoring engine (ADR-0004).
//!
//! Domain: periodically inspect registered database connections for health
//! (connectivity + key metrics), evaluate threshold-based alerting rules
//! (with flap-suppression + resolved notification), and webhook-notify on
//! state transitions.
//!
//! Module layout (one responsibility each, mirrors drift/data_sync):
//! - [`config`] — strongly-typed `HealthCheckTaskConfig` (cron / metric flags /
//!   thresholds / retention) stored as JSON in `scheduled_tasks.config`.
//! - `collector` — 4 core metrics (connectivity+latency / table-row estimate /
//!   missing-PK detection / connection count) for MySQL + PostgreSQL, with
//!   graceful degradation to connectivity-only for other DB types.
//! - `alert` — threshold state machine (Ok → Failing(count) → Alerting →
//!   Resolved) with flap-suppression + incremental structural alerting.
//! - `runner` — end-to-end orchestration (canary → collect → alert → notify →
//!   persist → retain).
//! - `scheduler` — `tokio::time::interval` cron scanner for due health_check
//!   tasks (mirrors data_sync scheduler shape).
//! - `notify` — `dbmaster.health-event.v1` webhook delivery.
//!
//! Trust boundary (ADR-0004 §5): the runner decrypts a stored source-DB
//! credential, opens a short-lived pool to the customer DB, runs SELECT-only
//! health probes, and tears the pool down. The webhook payload excludes
//! host/port/user/password and any business-row data.
//!
//! Phase: M1 scaffold (ADR-0004 §6) — only the bridge trait impl + module
//! stubs exist; collector/alert/runner/scheduler/notify are populated in
//! M2-M5.

// Module stubs — populated in later milestones.
pub mod alert;
pub mod collector;
pub mod config;
pub mod notify;
pub mod runner;
pub mod scheduler;

// CHANGE: ADR-0004 §3.6 / M5 T28 — re-export the scheduler entry so main.rs can
// spawn it the same way it spawns drift / data_sync schedulers.
pub use scheduler::{spawn as spawn_scheduler, InFlightTasks, SchedulerHandle};

use dbmaster_core::server::AppState;

// CHANGE: ADR-0004 §2.2 — HealthCheckRunner impl bridging the manual-run HTTP
// handler (in automation) to health_check::runner::run_task, without automation
// depending on health_check. The binary crate constructs
// Arc<HealthCheckRunnerHandle> and injects it into AppState.
#[async_trait::async_trait]
impl dbmaster_core::server::HealthCheckRunner for HealthCheckRunnerHandle {
    async fn run(
        &self,
        pool: &sqlx::SqlitePool,
        state: &AppState,
        task_id: &str,
        triggered_by: &str,
    ) -> Result<(), String> {
        let outcome = runner::run_task(pool, state, task_id, triggered_by)
            .await
            .map_err(|e| {
                // run_task has already persisted a redacted error to
                // task_run_history.error; surface the same redacted string to
                // the caller for structured logging.
                let s = e.to_string();
                s.chars().take(500).collect::<String>()
            })?;
        tracing::info!(
            task_id,
            status = %outcome.status,
            metrics_collected = outcome.metrics_collected,
            alert_changes = outcome.alert_changes,
            webhook_status = %outcome.webhook_status,
            triggered_by,
            "health_check run completed via HealthCheckRunner bridge"
        );
        Ok(())
    }
}

/// Empty implementation carrier; [`dbmaster_core::server::HealthCheckRunner`]
/// is implemented for it above. The unit struct exists only to name the impl —
/// the runner is stateless (all state lives in [`runner::run_task`]).
#[derive(Debug, Clone, Copy)]
pub struct HealthCheckRunnerHandle;
