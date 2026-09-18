//! `tokio::time::interval` scheduler for due drift tasks (ADR-0002 §4 D7 /
//! v1-C-14).
//!
//! Constraints (locked at v1):
//! - **Single process.** Multi-replica deployment is documented as
//!   unsupported (ADR §4 D7 / §6); we rely on in-memory mutual exclusion.
//! - **No missed-run catch-up.** On restart, we read `last_run_at` and decide
//!   due-ness from there; we do NOT compute "how many intervals were missed"
//!   and run them. The next snapshot will surface any drift that happened
//!   during the outage, slightly later than it would have. (ADR §4 D7.)
//! - **Self-skipping on overlap.** If task X is still running when its next
//!   tick comes due, the scheduler skips that tick. Tracked via
//!   [`InFlightTasks`].
//!
//! The scheduler is the only place the system proactively opens drift runs;
//! `runner::run_task` is also reachable from the manual API (`POST
//! /api/tasks/:id/run`) which is gated separately by Phase A's entitlement
//! gate.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use dbmaster_core::server::AppState;

/// Decide whether a task is due based on its `last_run_at` and the task's
/// interval (minutes). Exposed so unit tests cover the decision without a
/// running scheduler.
///
/// `last_run_at = None` ⇒ due (never run yet). Otherwise due when
/// `last_run_at + interval_minutes ≤ now`.
pub fn is_due(last_run_at: Option<&str>, interval_minutes: u32, now: DateTime<Utc>) -> bool {
    let Some(ts) = last_run_at else {
        return true;
    };
    let Ok(parsed) = DateTime::parse_from_rfc3339(ts) else {
        // Unparseable timestamp ⇒ treat as never run (safer: re-run + write a
        // fresh last_run_at).
        return true;
    };
    let due_at = parsed.with_timezone(&Utc) + chrono::Duration::minutes(interval_minutes.max(1) as i64);
    now >= due_at
}

/// In-memory set of task ids currently being executed. Mutex-guarded so the
/// scan loop and the runner can coordinate (single process; ADR §4 D7).
#[derive(Default)]
pub struct InFlightTasks {
    inner: Arc<Mutex<HashSet<String>>>,
}

impl InFlightTasks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to mark `task_id` as running. Returns `true` if newly acquired
    /// (caller proceeds), `false` if already in flight (caller skips).
    pub async fn try_acquire(&self, task_id: &str) -> bool {
        let mut guard = self.inner.lock().await;
        guard.insert(task_id.to_string())
    }

    /// Release the task id. No-op if not held.
    pub async fn release(&self, task_id: &str) {
        let mut guard = self.inner.lock().await;
        guard.remove(task_id);
    }

    #[cfg(test)]
    pub async fn contains(&self, task_id: &str) -> bool {
        self.inner.lock().await.contains(task_id)
    }
}

/// A minimal projection of a `scheduled_tasks` row used by the scheduler.
/// Kept narrow so the scan SELECT stays narrow (the row count grows with the
/// customer's task set, not the snapshot history).
#[derive(sqlx::FromRow)]
pub struct DueTaskRow {
    pub id: String,
    pub name: String,
    pub config: String,
    pub last_run_at: Option<String>,
}

/// SQL for the per-tick scan. Bound to `enabled = 1 AND task_type =
/// 'schema_drift'` (the literal is static — not user input).
// CHANGE: ADR-0002 §4 D7 — scan only schema_drift tasks; per-task due-ness
// decided in Rust.
pub const SCAN_SQL: &str =
    "SELECT id, name, config, last_run_at FROM scheduled_tasks \
     WHERE task_type = 'schema_drift' AND enabled = 1";

/// Cadence at which the scheduler wakes up and scans. Decoupled from the
/// per-task `interval_minutes`: a task configured for "every 5 min" should
/// fire within ~SCAN_CADENCE_SECS of being due. 60s gives minute-level
/// precision without hammering SQLite.
const SCAN_CADENCE_SECS: u64 = 60;

/// One-line helper to parse `interval_minutes` out of a task's config JSON
/// with the global default as fallback.
fn task_interval_minutes(config_json: &str, default: u32) -> u32 {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return default;
    };
    v.get("interval_minutes")
        .and_then(|x| x.as_u64())
        .and_then(|x| u32::try_from(x).ok())
        .filter(|x| (1..=1440).contains(x))
        .unwrap_or(default)
}

/// Top-level scheduler entry point. Spawns a single tokio task that ticks
/// every [`SCAN_CADENCE_SECS`], scans for due tasks, and dispatches each to
/// [`crate::runner::run_task`] on its own tokio task (so one slow customer
/// DB doesn't block the others).
///
/// Returns immediately; the work happens in the spawned task. Cancellation
/// is via the returned [`SchedulerHandle`] — dropping or aborting it stops
/// scheduling new dispatches (in-flight runs may complete; ADR §4 D7 / §4.7).
// CHANGE: ADR-0002 §4 D7 / Phase E — single-process scheduler spawn.
pub fn spawn(pool: SqlitePool, state: AppState) -> SchedulerHandle {
    let in_flight = Arc::new(InFlightTasks::new());
    let handle = tokio::spawn(run_loop(pool, state, in_flight));
    SchedulerHandle { handle }
}

/// Owned join handle for the scheduler loop. Aborting it cancels future
/// ticks; in-flight runs finish on their own (per ADR §4.7 — v1 accepts
/// "未发出的丢失" on shutdown).
pub struct SchedulerHandle {
    pub handle: tokio::task::JoinHandle<()>,
}

impl SchedulerHandle {
    /// Abort the scheduler loop. Idempotent.
    pub fn abort(&self) {
        self.handle.abort();
    }
}

async fn run_loop(pool: SqlitePool, state: AppState, in_flight: Arc<InFlightTasks>) {
    let cadence = Duration::from_secs(SCAN_CADENCE_SECS);
    let mut ticker = tokio::time::interval(cadence);
    tracing::info!(
        scan_cadence_secs = SCAN_CADENCE_SECS,
        "drift scheduler started"
    );

    loop {
        ticker.tick().await;
        if let Err(e) = scan_and_dispatch(&pool, &state, &in_flight).await {
            tracing::warn!(error = %e, "drift scheduler scan failed; will retry next tick");
        }
    }
}

async fn scan_and_dispatch(
    pool: &SqlitePool,
    state: &AppState,
    in_flight: &InFlightTasks,
) -> anyhow::Result<()> {
    let rows = sqlx::query_as::<_, DueTaskRow>(SCAN_SQL).fetch_all(pool).await?;
    let total_scanned = rows.len();

    let now = Utc::now();
    let default_interval = state.config.drift_default_interval_mins;
    let mut dispatched = 0u32;

    for task in rows {
        let interval = task_interval_minutes(&task.config, default_interval);
        if !is_due(task.last_run_at.as_deref(), interval, now) {
            continue;
        }
        if !in_flight.try_acquire(&task.id).await {
            // Previous run still going — skip this tick (v1-C-14).
            tracing::info!(task_id = %task.id, "drift task still in flight; skipping tick");
            continue;
        }

        // Dispatch on its own task so the next tick's scan is not blocked by
        // a slow customer DB.
        let pool_clone = pool.clone();
        let state_clone = state.clone();
        let task_id = task.id.clone();
        let in_flight_clone = in_flight.inner.clone();
        tokio::spawn(async move {
            let inflight = InFlightTasks { inner: in_flight_clone };
            let started = std::time::Instant::now();
            let result = crate::runner::run_task(&pool_clone, &state_clone, &task_id, "scheduler").await;
            match &result {
                Ok(summary) => tracing::info!(
                    task_id = %task_id,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    drift_count = summary.drift_count,
                    "drift task completed"
                ),
                Err(e) => tracing::warn!(task_id = %task_id, error = %e, "drift task failed"),
            }
            inflight.release(&task_id).await;
        });
        dispatched += 1;
    }

    if dispatched > 0 {
        tracing::info!(dispatched, total_scanned, "drift dispatch pass");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_due_when_never_run() {
        let now = Utc::now();
        assert!(is_due(None, 5, now));
    }

    #[test]
    fn is_due_when_unparseable_timestamp() {
        let now = Utc::now();
        assert!(is_due(Some("not-a-date"), 5, now));
    }

    #[test]
    fn not_due_within_interval() {
        let now = Utc::now();
        let last = (now - chrono::Duration::minutes(2)).to_rfc3339();
        assert!(!is_due(Some(&last), 5, now));
    }

    #[test]
    fn due_at_interval_boundary() {
        let now = Utc::now();
        let last = (now - chrono::Duration::minutes(5)).to_rfc3339();
        assert!(is_due(Some(&last), 5, now));
    }

    #[test]
    fn due_after_interval() {
        let now = Utc::now();
        let last = (now - chrono::Duration::minutes(60)).to_rfc3339();
        assert!(is_due(Some(&last), 5, now));
    }

    #[test]
    fn task_interval_minutes_uses_default_for_garbage() {
        assert_eq!(task_interval_minutes("{not json", 30), 30);
        assert_eq!(task_interval_minutes("{}", 30), 30);
    }

    #[test]
    fn task_interval_minutes_reads_override() {
        let cfg = r#"{"interval_minutes": 7}"#;
        assert_eq!(task_interval_minutes(cfg, 30), 7);
    }

    #[test]
    fn task_interval_minutes_clamps_out_of_range() {
        // 0 / 1441 / negative-as-i64 — all fall back to default per ADR §6.
        assert_eq!(task_interval_minutes(r#"{"interval_minutes": 0}"#, 30), 30);
        assert_eq!(task_interval_minutes(r#"{"interval_minutes": 1441}"#, 30), 30);
    }

    #[tokio::test]
    async fn inflight_acquire_then_release_cycle() {
        let t = InFlightTasks::new();
        assert!(t.try_acquire("t1").await); // newly inserted
        assert!(!t.try_acquire("t1").await); // already held
        assert!(t.contains("t1").await);
        t.release("t1").await;
        assert!(!t.contains("t1").await);
        assert!(t.try_acquire("t1").await); // re-acquire after release
        t.release("t1").await;
    }
}
