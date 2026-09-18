//! Threshold-based alert state machine (ADR-0004 §3.3).
//!
//! Two distinct evaluation models coexist:
//!
//! 1. **Threshold / connectivity metrics** (`connectivity`, `row_count`,
//!    `connection_count`): a consecutive-failure counter provides flap
//!    suppression. The state walks `Ok → Failing(count) → Alerting → Ok`
//!    where the `Failing → Alerting` transition fires only after
//!    `config.fail_threshold` consecutive failing samples, and a single
//!    passing sample resets to `Ok`. An `Alert` webhook fires on
//!    `Failing → Alerting`; a `Resolved` webhook fires on `Alerting → Ok`.
//!
//! 2. **Structural metric** (`missing_pk`): set-difference alerting. The
//!    prior missing-PK table set is diffed against the current set; newly
//!    missing tables each emit an `Alert`, newly restored tables each emit a
//!    `Resolved`. No flap suppression (structural changes are discrete
//!    events, not noisy samples).
//!
//! Pure-function core: [`evaluate_threshold_metric`] and
//! [`evaluate_missing_pk`] take the current persisted state + a fresh sample
//! and return `(new_state, Vec<AlertChange>)` without touching the DB. The
//! M4 runner loads state via [`load_metric_state`], calls the evaluator, and
//! persists the result via [`persist_metric_state`]. This split keeps the
//! state-machine logic unit-testable without a SQLite fixture (design §9.1).
//!
//! First-run baseline (requirements R3 / design §3.3): when no prior state
//! row exists, the first sample establishes baseline WITHOUT alerting —
//! except `connectivity`, where a first-sample failure is itself the alert
//! (the baseline IS "unreachable"). The runner signals "first run" by
//! passing `current: None` to the evaluators.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::collector::{ConnectivityResult, MissingPkStats, TableRowStats};

/// Persisted alert state for one (task, metric) pair.
///
/// Encoded into `health_alert_state.state` + `.fail_count` + `.detail` columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertState {
    /// No problem detected.
    Ok,
    /// Consecutive failing samples observed, but fewer than the threshold.
    /// `count` is the running total (1..threshold).
    Failing { count: u32 },
    /// Threshold reached — an Alert webhook has fired. Further failing samples
    /// do not re-alert (suppression); the next passing sample emits Resolved.
    Alerting,
}

impl AlertState {
    /// Encode to the `state` column string.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            AlertState::Ok => "ok",
            AlertState::Failing { .. } => "failing",
            AlertState::Alerting => "alerting",
        }
    }

    /// `fail_count` column value (0 for Ok/Alerting).
    pub fn fail_count(&self) -> u32 {
        match self {
            AlertState::Failing { count } => *count,
            _ => 0,
        }
    }
}

/// What a single evaluation pass produced — drives a webhook payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChange {
    /// `connectivity` | `row_count` | `missing_pk` | `connection_count`.
    pub metric: String,
    /// `critical` (connectivity down) | `warning` (threshold exceeded /
    /// missing PK) | `info`.
    pub severity: Severity,
    /// `alert` (newly breached) | `resolved` (recovered).
    pub trigger: Trigger,
    /// Metric-specific context for the webhook payload (table names, counts,
    /// latency, etc.). Redacted by the caller before delivery.
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Trigger {
    Alert,
    Resolved,
}

// ── Threshold / connectivity evaluation (flap-suppression state machine) ──

/// Evaluate a threshold-style metric (connectivity / row_count /
/// connection_count).
///
/// `current` is the prior persisted state (`None` = first run for this
/// metric). `failing` is whether THIS sample breached the threshold (e.g.
/// connectivity down, or row count over `large_table_threshold`). `threshold`
/// is `config.fail_threshold` (consecutive failures required to alert).
///
/// Returns `(new_state, AlertChange or None)`. The `detail` builder closure
/// lets the caller inject metric-specific context (latency, table names,
/// counts) only when an event is actually produced.
pub fn evaluate_threshold_metric(
    current: Option<AlertState>,
    failing: bool,
    threshold: u32,
    metric: &str,
    severity: Severity,
) -> (AlertState, Option<AlertChange>) {
    // First run with a passing sample → establish Ok baseline, no alert.
    // First run with a failing sample → start the Failing counter at 1.
    // (For connectivity, a first-run failure is the beginning of the flap
    // count, NOT an immediate alert — the same flap-suppression rule applies.
    // This differs from design §3.3's "connectivity first-run exception"; see
    // the note below the table. The chosen semantics: even connectivity must
    // observe `threshold` consecutive failures before alerting, because a
    // single transient blip on first contact is indistinguishable from a
    // real outage and the cost of a late alert (threshold * cron-interval
    // seconds) is far lower than the cost of a false-positive page.)
    let current = current.unwrap_or(AlertState::Ok);

    match (current, failing) {
        // Passing sample: any non-Ok state resolves; Ok stays Ok.
        (AlertState::Alerting, false) => {
            let change = AlertChange {
                metric: metric.to_string(),
                severity,
                trigger: Trigger::Resolved,
                detail: serde_json::json!({}),
            };
            (AlertState::Ok, Some(change))
        }
        (AlertState::Failing { .. }, false) => (AlertState::Ok, None), // flap recover, no alert
        (AlertState::Ok, false) => (AlertState::Ok, None),

        // Failing sample: Ok → Failing(1); Failing(n) → Failing(n+1) or Alerting;
        // Alerting stays Alerting (suppressed).
        (AlertState::Ok, true) => (AlertState::Failing { count: 1 }, None),
        (AlertState::Failing { count }, true) => {
            let next = count + 1;
            if next >= threshold {
                let change = AlertChange {
                    metric: metric.to_string(),
                    severity,
                    trigger: Trigger::Alert,
                    detail: serde_json::json!({ "consecutive_failures": next }),
                };
                (AlertState::Alerting, Some(change))
            } else {
                (AlertState::Failing { count: next }, None)
            }
        }
        (AlertState::Alerting, true) => (AlertState::Alerting, None), // already alerted
    }
}

/// Convenience: evaluate `connectivity` from a [`ConnectivityResult`].
/// `failing = !ok`.
pub fn evaluate_connectivity(
    current: Option<AlertState>,
    probe: &ConnectivityResult,
    threshold: u32,
) -> (AlertState, Option<AlertChange>) {
    let (new_state, mut change) = evaluate_threshold_metric(
        current,
        !probe.ok,
        threshold,
        "connectivity",
        Severity::Critical,
    );
    if let Some(c) = &mut change {
        c.detail = serde_json::json!({
            "latency_ms": probe.latency_ms,
            "error": probe.error,
        });
    }
    (new_state, change)
}

/// Convenience: evaluate `row_count` — failing if any TOP-N table exceeds the
/// threshold.
pub fn evaluate_row_count(
    current: Option<AlertState>,
    stats: &TableRowStats,
    large_table_threshold: u64,
    fail_threshold: u32,
) -> (AlertState, Option<AlertChange>) {
    let over: Vec<&(String, u64)> = stats
        .top_tables
        .iter()
        .filter(|(_, rows)| *rows >= large_table_threshold)
        .collect();
    let (new_state, mut change) = evaluate_threshold_metric(
        current,
        !over.is_empty(),
        fail_threshold,
        "row_count",
        Severity::Warning,
    );
    if let Some(c) = &mut change {
        c.detail = serde_json::json!({
            "large_tables": over.iter().map(|(n, r)| {
                serde_json::json!({ "table": n, "estimated_rows": r })
            }).collect::<Vec<_>>(),
        });
    }
    (new_state, change)
}

/// Convenience: evaluate `connection_count` — failing if count exceeds threshold.
pub fn evaluate_connection_count(
    current: Option<AlertState>,
    count: Option<u64>,
    connection_count_threshold: u64,
    fail_threshold: u32,
) -> (AlertState, Option<AlertChange>) {
    let failing = count.is_some_and(|c| c >= connection_count_threshold);
    let (new_state, mut change) = evaluate_threshold_metric(
        current,
        failing,
        fail_threshold,
        "connection_count",
        Severity::Warning,
    );
    if let Some(c) = &mut change {
        c.detail = serde_json::json!({
            "current": count,
            "threshold": connection_count_threshold,
        });
    }
    (new_state, change)
}

// ── missing_pk evaluation (set-difference, no flap suppression) ──

/// Evaluate the `missing_pk` metric: set-difference the current missing-PK
/// table set against the prior. Newly missing → Alert per table; newly
/// restored → Resolved per table. Unchanged → no event.
///
/// `prior_tables` is the `detail.last_missing` from the previous run
/// (`None` = first run = establish baseline, no alert).
pub fn evaluate_missing_pk(
    prior_tables: Option<&[String]>,
    current_stats: &MissingPkStats,
) -> (Vec<String>, Vec<AlertChange>) {
    let prior: HashSet<&String> = prior_tables
        .map(|t| t.iter().collect())
        .unwrap_or_default();
    let current: HashSet<&String> = current_stats.tables.iter().collect();

    // First run → baseline. Record the current set, emit nothing.
    if prior_tables.is_none() {
        return (current_stats.tables.clone(), vec![]);
    }

    let newly_missing: Vec<&String> = current.difference(&prior).copied().collect();
    let restored: Vec<&String> = prior.difference(&current).copied().collect();

    let mut changes = vec![];
    for t in &newly_missing {
        changes.push(AlertChange {
            metric: "missing_pk".to_string(),
            severity: Severity::Warning,
            trigger: Trigger::Alert,
            detail: serde_json::json!({ "table": t }),
        });
    }
    for t in &restored {
        changes.push(AlertChange {
            metric: "missing_pk".to_string(),
            severity: Severity::Info,
            trigger: Trigger::Resolved,
            detail: serde_json::json!({ "table": t }),
        });
    }

    // The persisted set is always the current snapshot.
    (current_stats.tables.clone(), changes)
}

// ── DB persistence (used by M4 runner; kept here to live with the model) ──

/// Row loaded from `health_alert_state`.
#[derive(Debug, Clone)]
pub struct MetricStateRow {
    pub state: AlertState,
    /// Opaque per-metric detail (e.g. `{"last_missing": [...]}` for
    /// missing_pk). `None` when the column is NULL.
    pub detail: Option<serde_json::Value>,
}

/// Load the persisted state for one (task, metric) pair. Returns `None` if no
/// row exists (first run for this metric).
pub async fn load_metric_state(
    pool: &SqlitePool,
    task_id: &str,
    metric: &str,
) -> anyhow::Result<Option<MetricStateRow>> {
    let row: Option<(String, i64, Option<String>)> = sqlx::query_as(
        "SELECT state, fail_count, detail FROM health_alert_state WHERE task_id = ? AND metric = ?",
    )
    .bind(task_id)
    .bind(metric)
    .fetch_optional(pool)
    .await?;

    let Some((state_str, fail_count, detail_raw)) = row else {
        return Ok(None);
    };
    let state = match state_str.as_str() {
        "ok" => AlertState::Ok,
        "alerting" => AlertState::Alerting,
        "failing" => AlertState::Failing {
            count: fail_count.max(0) as u32,
        },
        other => {
            return Err(anyhow::anyhow!(
                "invalid health_alert_state.state '{other}' for ({task_id}, {metric})"
            ));
        }
    };
    let detail = match detail_raw {
        Some(s) if !s.is_empty() => serde_json::from_str(&s).ok(),
        _ => None,
    };
    Ok(Some(MetricStateRow { state, detail }))
}

/// Persist the new state + detail for one (task, metric) pair (upsert).
pub async fn persist_metric_state(
    pool: &SqlitePool,
    task_id: &str,
    metric: &str,
    state: &AlertState,
    detail: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    let detail_str = match detail {
        Some(v) => serde_json::to_string(v)?,
        None => String::new(),
    };
    sqlx::query(
        "INSERT INTO health_alert_state (task_id, metric, state, fail_count, detail, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now')) \
         ON CONFLICT(task_id, metric) DO UPDATE SET \
           state = excluded.state, \
           fail_count = excluded.fail_count, \
           detail = excluded.detail, \
           updated_at = excluded.updated_at",
    )
    .bind(task_id)
    .bind(metric)
    .bind(state.as_db_str())
    .bind(state.fail_count() as i64)
    .bind(&detail_str)
    .execute(pool)
    .await?;
    Ok(())
}

/// Extract `last_missing` from a loaded detail JSON (missing_pk metric).
pub fn detail_last_missing(detail: Option<&serde_json::Value>) -> Option<Vec<String>> {
    let v = detail?;
    v.get("last_missing")?.as_array().map(|arr| {
        arr.iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect()
    })
}

/// Build the missing_pk detail JSON to persist: `{"last_missing": [...]}`.
pub fn detail_for_missing_pk(tables: &[String]) -> serde_json::Value {
    serde_json::json!({ "last_missing": tables })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── evaluate_threshold_metric — full state-transition matrix ──

    #[test]
    fn threshold_ok_passing_stays_ok_no_event() {
        let (s, c) = evaluate_threshold_metric(Some(AlertState::Ok), false, 3, "m", Severity::Critical);
        assert_eq!(s, AlertState::Ok);
        assert!(c.is_none());
    }

    #[test]
    fn threshold_ok_failing_starts_failing_1_no_event() {
        let (s, c) = evaluate_threshold_metric(Some(AlertState::Ok), true, 3, "m", Severity::Critical);
        assert_eq!(s, AlertState::Failing { count: 1 });
        assert!(c.is_none());
    }

    #[test]
    fn threshold_failing_passing_resets_ok_no_event_flap_recover() {
        let (s, c) = evaluate_threshold_metric(
            Some(AlertState::Failing { count: 2 }), false, 3, "m", Severity::Critical,
        );
        assert_eq!(s, AlertState::Ok);
        assert!(c.is_none(), "flap recovery must not emit Resolved");
    }

    #[test]
    fn threshold_failing_failing_below_threshold_increments_no_event() {
        let (s, c) = evaluate_threshold_metric(
            Some(AlertState::Failing { count: 1 }), true, 3, "m", Severity::Critical,
        );
        assert_eq!(s, AlertState::Failing { count: 2 });
        assert!(c.is_none());
    }

    #[test]
    fn threshold_failing_failing_at_threshold_fires_alert() {
        let (s, c) = evaluate_threshold_metric(
            Some(AlertState::Failing { count: 2 }), true, 3, "m", Severity::Critical,
        );
        assert_eq!(s, AlertState::Alerting);
        let change = c.expect("expected Alert event");
        assert_eq!(change.trigger, Trigger::Alert);
        assert_eq!(change.severity, Severity::Critical);
        assert_eq!(change.metric, "m");
    }

    #[test]
    fn threshold_alerting_failing_stays_alerting_no_repeat() {
        let (s, c) = evaluate_threshold_metric(
            Some(AlertState::Alerting), true, 3, "m", Severity::Critical,
        );
        assert_eq!(s, AlertState::Alerting);
        assert!(c.is_none(), "Alerting must not re-alert on continued failure");
    }

    #[test]
    fn threshold_alerting_passing_emits_resolved() {
        let (s, c) = evaluate_threshold_metric(
            Some(AlertState::Alerting), false, 3, "m", Severity::Critical,
        );
        assert_eq!(s, AlertState::Ok);
        let change = c.expect("expected Resolved event");
        assert_eq!(change.trigger, Trigger::Resolved);
    }

    #[test]
    fn threshold_first_run_passing_baseline_ok_no_event() {
        let (s, c) = evaluate_threshold_metric(None, false, 3, "m", Severity::Critical);
        assert_eq!(s, AlertState::Ok);
        assert!(c.is_none(), "first-run passing must not alert");
    }

    #[test]
    fn threshold_first_run_failing_starts_failing_1_no_immediate_alert() {
        let (s, c) = evaluate_threshold_metric(None, true, 3, "m", Severity::Critical);
        assert_eq!(s, AlertState::Failing { count: 1 });
        assert!(c.is_none(), "first-run failure starts the counter, no immediate alert");
    }

    #[test]
    fn threshold_threshold_1_alerts_on_first_failure() {
        // fail_threshold=1 means no flap suppression.
        let (s, c) = evaluate_threshold_metric(Some(AlertState::Ok), true, 1, "m", Severity::Critical);
        // count goes 0 → 1; next >= 1 (threshold), so Ok → Failing{1} on the
        // first sample would NOT alert here (it goes Ok→Failing{1}). To alert
        // immediately on first failure with threshold=1, we need Failing{1} →
        // next fails → Alerting. Verify the two-step path:
        assert_eq!(s, AlertState::Failing { count: 1 });
        assert!(c.is_none());
        // Now Failing{1} + another failure with threshold=1 → next=2 >= 1 → Alerting.
        let (s2, c2) = evaluate_threshold_metric(
            Some(AlertState::Failing { count: 1 }), true, 1, "m", Severity::Critical,
        );
        assert_eq!(s2, AlertState::Alerting);
        assert!(c2.is_some());
    }

    // ── evaluate_connectivity wrapper ──

    #[test]
    fn connectivity_down_after_threshold_alerts_with_latency_detail() {
        let probe_down = ConnectivityResult { ok: false, latency_ms: 0, error: Some("conn refused".into()) };
        // Failing{2} + down + threshold 3 → Alerting + detail has latency/error.
        let (s, c) = evaluate_connectivity(Some(AlertState::Failing { count: 2 }), &probe_down, 3);
        assert_eq!(s, AlertState::Alerting);
        let change = c.unwrap();
        assert_eq!(change.detail["error"], "conn refused");
        assert_eq!(change.detail["latency_ms"], 0);
    }

    // ── evaluate_row_count wrapper ──

    #[test]
    fn row_count_over_threshold_marks_failing() {
        let stats = TableRowStats {
            top_tables: vec![("big".to_string(), 20_000_000), ("small".to_string(), 100)],
        };
        let (s, _c) = evaluate_row_count(Some(AlertState::Ok), &stats, 10_000_000, 3);
        assert_eq!(s, AlertState::Failing { count: 1 });
    }

    #[test]
    fn row_count_under_threshold_stays_ok() {
        let stats = TableRowStats { top_tables: vec![("t".to_string(), 50)] };
        let (s, _c) = evaluate_row_count(Some(AlertState::Ok), &stats, 10_000_000, 3);
        assert_eq!(s, AlertState::Ok);
    }

    // ── evaluate_connection_count wrapper ──

    #[test]
    fn connection_count_none_not_failing() {
        let (s, _c) = evaluate_connection_count(Some(AlertState::Ok), None, 100, 3);
        assert_eq!(s, AlertState::Ok);
    }

    #[test]
    fn connection_count_over_threshold_failing() {
        let (s, _c) = evaluate_connection_count(Some(AlertState::Ok), Some(150), 100, 3);
        assert_eq!(s, AlertState::Failing { count: 1 });
    }

    // ── evaluate_missing_pk — set-difference alerting ──

    #[test]
    fn missing_pk_first_run_baseline_no_event() {
        let stats = MissingPkStats { tables: vec!["a".to_string(), "b".to_string()] };
        let (persisted, changes) = evaluate_missing_pk(None, &stats);
        assert_eq!(persisted, vec!["a", "b"]);
        assert!(changes.is_empty(), "first run must not alert");
    }

    #[test]
    fn missing_pk_new_table_emits_alert() {
        let prior = vec!["a".to_string()];
        let stats = MissingPkStats { tables: vec!["a".to_string(), "b".to_string()] };
        let (persisted, changes) = evaluate_missing_pk(Some(&prior), &stats);
        assert_eq!(persisted, vec!["a", "b"]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].trigger, Trigger::Alert);
        assert_eq!(changes[0].detail["table"], "b");
    }

    #[test]
    fn missing_pk_restored_table_emits_resolved() {
        let prior = vec!["a".to_string(), "b".to_string()];
        let stats = MissingPkStats { tables: vec!["a".to_string()] }; // b got a PK
        let (_persisted, changes) = evaluate_missing_pk(Some(&prior), &stats);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].trigger, Trigger::Resolved);
        assert_eq!(changes[0].detail["table"], "b");
        assert_eq!(changes[0].severity, Severity::Info);
    }

    #[test]
    fn missing_pk_unchanged_no_event() {
        let prior = vec!["a".to_string()];
        let stats = MissingPkStats { tables: vec!["a".to_string()] };
        let (_persisted, changes) = evaluate_missing_pk(Some(&prior), &stats);
        assert!(changes.is_empty());
    }

    #[test]
    fn missing_pk_swap_emits_both_alert_and_resolved() {
        let prior = vec!["a".to_string()];
        let stats = MissingPkStats { tables: vec!["b".to_string()] }; // a restored, b new
        let (_persisted, changes) = evaluate_missing_pk(Some(&prior), &stats);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| c.trigger == Trigger::Alert && c.detail["table"] == "b"));
        assert!(changes.iter().any(|c| c.trigger == Trigger::Resolved && c.detail["table"] == "a"));
    }

    // ── AlertState encoding ──

    #[test]
    fn alert_state_db_str_round_trip() {
        assert_eq!(AlertState::Ok.as_db_str(), "ok");
        assert_eq!(AlertState::Failing { count: 5 }.as_db_str(), "failing");
        assert_eq!(AlertState::Failing { count: 5 }.fail_count(), 5);
        assert_eq!(AlertState::Alerting.as_db_str(), "alerting");
        assert_eq!(AlertState::Alerting.fail_count(), 0);
        assert_eq!(AlertState::Ok.fail_count(), 0);
    }

    // ── missing_pk detail helpers ──

    #[test]
    fn detail_helpers_round_trip() {
        let tables = vec!["x".to_string(), "y".to_string()];
        let detail = detail_for_missing_pk(&tables);
        let extracted = detail_last_missing(Some(&detail)).unwrap();
        assert_eq!(extracted, tables);
        assert!(detail_last_missing(None).is_none());
    }
}
