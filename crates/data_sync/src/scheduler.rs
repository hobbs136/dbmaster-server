//! `tokio::time::interval` cron scheduler for due `data_sync` tasks.
//!
//! Mirrors the drift scheduler's shape (`spawn` → `run_loop` →
//! `scan_and_dispatch` with `InFlightTasks` overlap protection) but:
//!
//! - Scans `task_type = 'data_sync'` rows.
//! - Per-task due-ness is decided by parsing the row's `cron_expr` (5-field)
//!   via the `cron` crate, not by `interval_minutes`.
//! - Tasks with an empty `cron_expr` are skipped by the scheduler (they're
//!   one-shot tasks triggered via `POST /api/tasks/:id/run`).
//!
//! v1 constraints (same as drift):
//! - Single-process. Multi-replica is documented as unsupported.
//! - No missed-run catch-up. On restart, due-ness is recomputed from
//!   `last_run_at`; missed cron ticks during the outage are not replayed.
//! - Self-skipping on overlap via [`InFlightTasks`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use cron::Schedule;
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use dbmaster_core::server::AppState;

/// In-memory set of task ids currently being executed.
#[derive(Default)]
pub struct InFlightTasks {
    inner: Arc<Mutex<HashSet<String>>>,
}

impl InFlightTasks {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn try_acquire(&self, task_id: &str) -> bool {
        self.inner.lock().await.insert(task_id.to_string())
    }

    pub async fn release(&self, task_id: &str) {
        self.inner.lock().await.remove(task_id);
    }
}

#[derive(sqlx::FromRow)]
struct DueTaskRow {
    id: String,
    cron_expr: String,
    last_run_at: Option<String>,
}

/// Scan only data_sync tasks that have a non-empty cron expression. The
/// `task_type` literal is static — not user input.
const SCAN_SQL: &str = "SELECT id, cron_expr, last_run_at FROM scheduled_tasks \
     WHERE task_type = 'data_sync' AND enabled = 1 AND COALESCE(cron_expr, '') != ''";

const SCAN_CADENCE_SECS: u64 = 60;

/// Decide whether a task is due based on its `cron_expr` and `last_run_at`.
/// 一期 uses UTC for all cron evaluation; the optional `timezone` field on
/// [`crate::config::ScheduleConfig`] is accepted on the wire but ignored
/// (forward-compat: swap in `chrono-tz` when needed).
///
/// `last_run_at = None` ⇒ due (never run). Unparseable cron ⇒ not due (the
/// task is skipped; operators notice via WARN logs).
fn is_due(cron_expr: &str, last_run_at: Option<&str>, now: DateTime<Utc>) -> bool {
    let Some(schedule) = parse_schedule(cron_expr) else {
        tracing::warn!(cron_expr, "unparseable cron expression; task skipped");
        return false;
    };
    let last = match last_run_at {
        Some(ts) => match DateTime::parse_from_rfc3339(ts) {
            Ok(parsed) => parsed.with_timezone(&Utc),
            Err(_) => return true, // unparseable ⇒ treat as never run
        },
        None => return true,
    };
    // Due if there is any scheduled tick in (last, now].
    schedule.after(&last).take(1).next().is_some_and(|t| t <= now)
}

/// Build a UTC `cron::Schedule` from a 5-field expression
/// (`min hour dom month dow`, e.g. `0 3 * * *`).
///
/// The `cron` crate expects 6-7 fields (sec min hour dom month dow [year]).
/// We accept the user-friendly 5-field form by prepending a `0 ` seconds
/// field. 6-7 field inputs pass through unchanged.
fn parse_schedule(expr: &str) -> Option<Schedule> {
    use std::str::FromStr;
    let trimmed = expr.trim();
    let full = match trimmed.split_whitespace().count() {
        5 => format!("0 {trimmed}"),
        _ => trimmed.to_string(),
    };
    Schedule::from_str(&full).ok()
}

/// Top-level scheduler entry point. Returns immediately.
pub fn spawn(pool: SqlitePool, state: AppState) -> SchedulerHandle {
    let in_flight = Arc::new(InFlightTasks::new());
    let handle = tokio::spawn(run_loop(pool, state, in_flight));
    SchedulerHandle { handle }
}

pub struct SchedulerHandle {
    pub handle: tokio::task::JoinHandle<()>,
}

impl SchedulerHandle {
    pub fn abort(&self) {
        self.handle.abort();
    }
}

async fn run_loop(pool: SqlitePool, state: AppState, in_flight: Arc<InFlightTasks>) {
    let cadence = Duration::from_secs(SCAN_CADENCE_SECS);
    let mut ticker = tokio::time::interval(cadence);
    tracing::info!(scan_cadence_secs = SCAN_CADENCE_SECS, "data_sync scheduler started");
    loop {
        ticker.tick().await;
        if let Err(e) = scan_and_dispatch(&pool, &state, &in_flight).await {
            tracing::warn!(error = %e, "data_sync scheduler scan failed; will retry next tick");
        }
    }
}

/// P1-2: 暴露为 pub 供集成测试直接调用（跳过 60s tick 等待）。
pub async fn scan_and_dispatch(pool: &SqlitePool, state: &AppState, in_flight: &InFlightTasks) -> anyhow::Result<()> {
    let rows = sqlx::query_as::<_, DueTaskRow>(SCAN_SQL).fetch_all(pool).await?;
    let total_scanned = rows.len();
    let now = Utc::now();
    let mut dispatched = 0u32;

    for task in rows {
        if !is_due(&task.cron_expr, task.last_run_at.as_deref(), now) {
            continue;
        }
        if !in_flight.try_acquire(&task.id).await {
            tracing::info!(task_id = %task.id, "data_sync task still in flight; skipping tick");
            continue;
        }
        let pool_clone = pool.clone();
        let state_clone = state.clone();
        let task_id = task.id.clone();
        let in_flight_clone = in_flight.inner.clone();
        tokio::spawn(async move {
            let inflight = InFlightTasks { inner: in_flight_clone };
            let started = std::time::Instant::now();
            let result = crate::runner::run_task(&pool_clone, &state_clone, &task_id, "scheduler").await;
            match &result {
                Ok(o) => tracing::info!(
                    task_id = %task_id,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    processed = o.processed_rows,
                    canceled = o.canceled,
                    "data_sync task completed"
                ),
                Err(e) => tracing::warn!(task_id = %task_id, error = %e, "data_sync task failed"),
            }
            inflight.release(&task_id).await;
        });
        dispatched += 1;
    }

    if dispatched > 0 {
        tracing::info!(dispatched, total_scanned, "data_sync dispatch pass");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_when_never_run() {
        let now = Utc::now();
        assert!(is_due("0 3 * * *", None, now));
    }

    #[test]
    fn due_when_unparseable_last_run() {
        let now = Utc::now();
        assert!(is_due("0 3 * * *", Some("not-a-date"), now));
    }

    #[test]
    fn not_due_within_interval() {
        // Daily at 03:00. last_run = 1 minute ago → next tick is tomorrow 03:00.
        let now = chrono::NaiveDate::from_ymd_opt(2026, 8, 7).unwrap()
            .and_hms_opt(10, 0, 0).unwrap()
            .and_local_timezone(chrono::Utc).unwrap();
        let last = (now - chrono::Duration::minutes(1)).to_rfc3339();
        assert!(!is_due("0 3 * * *", Some(&last), now));
    }

    #[test]
    fn due_after_cron_tick() {
        // Daily at 03:00. last_run yesterday 02:00, now today 10:00 → tick at 03:00 passed.
        let now = chrono::NaiveDate::from_ymd_opt(2026, 8, 7).unwrap()
            .and_hms_opt(10, 0, 0).unwrap()
            .and_local_timezone(chrono::Utc).unwrap();
        let last = chrono::NaiveDate::from_ymd_opt(2026, 8, 6).unwrap()
            .and_hms_opt(2, 0, 0).unwrap()
            .and_local_timezone(chrono::Utc).unwrap()
            .to_rfc3339();
        assert!(is_due("0 3 * * *", Some(&last), now));
    }

    #[test]
    fn not_due_for_garbage_cron() {
        let now = Utc::now();
        assert!(!is_due("not a cron", None, now));
    }

    #[tokio::test]
    async fn inflight_acquire_then_release_cycle() {
        let t = InFlightTasks::new();
        assert!(t.try_acquire("t1").await);
        assert!(!t.try_acquire("t1").await);
        t.release("t1").await;
        assert!(t.try_acquire("t1").await);
        t.release("t1").await;
    }
}
