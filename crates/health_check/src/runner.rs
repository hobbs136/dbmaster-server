//! End-to-end orchestration of a single health_check task run (ADR-0004 §2).
//!
//! Pipeline (10 steps):
//! 1. Open a `task_run_history` row (status=running).
//! 2. Load task + connection rows; parse config.
//! 3. Decrypt credential; audit access.
//! 4. Open a short-lived source pool (MySQL/PG only); run canary for
//!    `source_drift`-kind connections.
//! 5. Collect metrics (4 core for MySQL/PG; connectivity-only degradation
//!    for other db types).
//! 6. Evaluate alerts per metric (threshold state machine + missing_pk set
//!    diff); persist state; collect AlertChanges.
//! 7. For each AlertChange: build webhook payload + deliver (with backoff).
//! 8. Insert `health_check_results` row (metrics_summary + alert_changes).
//! 9. Rotate: DELETE expired `health_check_results` per retention_days.
//! 10. Close `task_run_history` (status + summary + webhook outcome).
//!
//! On any step failure the run is marked failed in `task_run_history` with a
//! redacted error, and a failed `health_check_results` row (error column,
//! migration 014) is written so the failure is visible in the read endpoint /
//! desktop history. Partial metric-collection failures (step 5-6) do NOT
//! abort the run — they are recorded in `unsupported_metrics` and the run
//! status is `partial`.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dbmaster_core::server::AppState;
use sqlx::SqlitePool;

use crate::alert::{
    self, detail_for_missing_pk, detail_last_missing, evaluate_connection_count,
    evaluate_connectivity, evaluate_missing_pk, evaluate_row_count, load_metric_state,
    persist_metric_state, AlertChange, AlertState,
};
use crate::collector::{
    self, connectivity_only_snapshot, ConnectivityResult, MetricsSnapshot,
};
use crate::config::HealthCheckTaskConfig;
use crate::notify::{self, WebhookPayload, DEFAULT_TIMEOUT_SECS};

/// Outcome of a single health_check run (returned to the bridge trait impl).
pub struct RunOutcome {
    /// `success` | `failed` | `partial`.
    pub status: String,
    pub metrics_collected: u32,
    pub alert_changes: u32,
    /// `ok` | `failed` | `skipped`.
    pub webhook_status: String,
}

/// Top-level entry. `triggered_by` is `"scheduler"` or `"manual:<user_id>"`.
pub async fn run_task(
    pool: &SqlitePool,
    state: &AppState,
    task_id: &str,
    triggered_by: &str,
) -> Result<RunOutcome> {
    let started = Instant::now();
    let run_id = uuid::Uuid::new_v4().to_string();
    let now_rfc = chrono::Utc::now().to_rfc3339();

    // Step 1: open run_history row (status=running).
    sqlx::query(
        "INSERT INTO task_run_history (id, task_id, started_at, status, triggered_by) \
         VALUES (?1, ?2, ?3, 'running', ?4)",
    )
    .bind(&run_id)
    .bind(task_id)
    .bind(&now_rfc)
    .bind(triggered_by)
    .execute(pool)
    .await
    .context("insert task_run_history running row")?;

    let outcome = run_task_inner(pool, state, task_id, triggered_by).await;

    let elapsed_ms = started.elapsed().as_millis() as u64;
    let now_end = chrono::Utc::now().to_rfc3339();

    match &outcome {
        Ok(o) => {
            let summary = serde_json::json!({
                "status": o.status,
                "metrics_collected": o.metrics_collected,
                "alert_changes": o.alert_changes,
                "webhook_status": o.webhook_status,
                "duration_ms": elapsed_ms,
            })
            .to_string();
            let _ = sqlx::query(
                "UPDATE task_run_history \
                 SET finished_at = ?1, status = 'succeeded', summary = ?2 WHERE id = ?3",
            )
            .bind(&now_end)
            .bind(&summary)
            .bind(&run_id)
            .execute(pool)
            .await;
            let _ = update_task_status(pool, task_id, &now_end, "succeeded").await;
        }
        Err(e) => {
            tracing::warn!(task_id, error = %e, "health_check run failed");
            let redacted = redact_error(e);
            let _ = sqlx::query(
                "UPDATE task_run_history \
                 SET finished_at = ?1, status = 'failed', error = ?2 WHERE id = ?3",
            )
            .bind(&now_end)
            .bind(&redacted)
            .bind(&run_id)
            .execute(pool)
            .await;
            // U06 — a failed run must still be visible in health history:
            // write a results row so /api/health-results + the desktop list
            // show WHY it failed (db down / decrypt failure), not silence.
            // Best-effort: the FK on task_id makes this a no-op for a task
            // deleted mid-run, which must not mask the Err return below.
            let _ = insert_failed_result(
                pool,
                task_id,
                &now_rfc,
                &redacted,
                triggered_by,
            )
            .await;
            let _ = update_task_status(pool, task_id, &now_end, "failed").await;
        }
    }

    outcome
}

async fn run_task_inner(
    pool: &SqlitePool,
    state: &AppState,
    task_id: &str,
    triggered_by: &str,
) -> Result<RunOutcome> {
    // Step 2: load task + connection.
    let task: TaskRow = sqlx::query_as::<_, TaskRow>(
        "SELECT id, name, config, source_db_id, notify_channels \
         FROM scheduled_tasks WHERE id = ?1",
    )
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .context("fetch scheduled_task")?
    .ok_or_else(|| anyhow::anyhow!("task {task_id} not found"))?;

    let conn: ConnectionRow = sqlx::query_as::<_, ConnectionRow>(
        "SELECT id, name, db_type, host, port, username, password_encrypted, \
                default_database, kind \
         FROM database_connections WHERE id = ?1",
    )
    .bind(&task.source_db_id)
    .fetch_optional(pool)
    .await
    .context("fetch source connection")?
    .ok_or_else(|| anyhow::anyhow!("source connection {} not found", task.source_db_id))?;

    let config = HealthCheckTaskConfig::from_json_or_default(&task.config);

    // Step 3: decrypt password; audit access.
    let password = match dbmaster_automation::credential::decrypt_password(
        &conn.password_encrypted,
        &state.credential_key,
    ) {
        Ok(p) => {
            record_credential_access(pool, &conn.id, "ok", None, triggered_by).await;
            p
        }
        Err(e) => {
            // Decrypt errors may echo key/credential material — store only a
            // fixed redacted summary (never the raw error) in the audit row,
            // then fail the run. task_run_history records the run-level error.
            record_credential_access(
                pool,
                &conn.id,
                "error",
                Some("credential decrypt failed"),
                triggered_by,
            )
            .await;
            return Err(anyhow::anyhow!("credential decrypt failed: {e}"));
        }
    };

    // Steps 4-5: open source pool + collect (MySQL/PG), or degrade.
    let (snapshot, all_changes): (MetricsSnapshot, Vec<AlertChange>) = match conn
        .db_type
        .as_str()
    {
        "mysql" => {
            let src_pool = open_mysql_pool(&conn, &password).await?;
            if conn.kind == "source_drift" {
                run_canary_mysql(&src_pool, pool, &conn.id, triggered_by).await?;
            }
            let snap = collector::collect_mysql(
                &src_pool,
                conn.default_database.as_deref().unwrap_or(""),
                &config.metrics,
                10,
            )
            .await;
            drop(src_pool);
            let changes = evaluate_all(pool, task_id, &snap, &config).await?;
            (snap, changes)
        }
        "postgres" => {
            let src_pool = open_pg_pool(&conn, &password).await?;
            if conn.kind == "source_drift" {
                run_canary_pg(&src_pool, pool, &conn.id, triggered_by).await?;
            }
            let snap = collector::collect_postgres(&src_pool, &config.metrics, 10).await;
            drop(src_pool);
            let changes = evaluate_all(pool, task_id, &snap, &config).await?;
            (snap, changes)
        }
        other => {
            // Degradation path: non-MySQL/PG db types get connectivity-only
            // with connectivity marked unsupported (no driver compiled in).
            tracing::info!(
                task_id, db_type = other,
                "health_check degradation: db_type not supported by collector, connectivity-only"
            );
            let snap = connectivity_only_snapshot(
                other,
                ConnectivityResult {
                    ok: false,
                    latency_ms: 0,
                    error: Some(format!("unsupported db_type: {other}")),
                },
                &config.metrics,
            );
            let changes = vec![];
            (snap, changes)
        }
    };

    // Step 6 note: evaluate_all already persisted alert state during step 5.

    // Step 7: deliver webhooks for each AlertChange.
    let webhook_status = if all_changes.is_empty() {
        "skipped".to_string()
    } else {
        let url_opt = notify::first_webhook_url(&task.notify_channels);
        match url_opt {
            None => "skipped".to_string(), // no webhook configured
            Some(url) => {
                let dev_mode = is_dev_mode();
                let mut any_fail = false;
                for change in &all_changes {
                    let payload = WebhookPayload::from_alert_change(
                        uuid::Uuid::new_v4().to_string(),
                        chrono::Utc::now().to_rfc3339(),
                        state.install_uuid.as_ref().clone(),
                        notify::TaskRef {
                            id: task.id.clone(),
                            name: task.name.clone(),
                        },
                        notify::ConnectionRef {
                            id: conn.id.clone(),
                            name: conn.name.clone(),
                        },
                        notify::SourceRef {
                            db_type: conn.db_type.clone(),
                            database: conn.default_database.clone().unwrap_or_default(),
                        },
                        change,
                    );
                    match notify::deliver(
                        &payload,
                        &url,
                        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
                        dev_mode,
                    )
                    .await
                    {
                        Ok(_) => tracing::info!(
                            task_id, metric = %change.metric,
                            "health_check webhook delivered"
                        ),
                        Err(e) => {
                            any_fail = true;
                            tracing::warn!(
                                task_id, metric = %change.metric, error = %e,
                                "health_check webhook delivery failed"
                            );
                        }
                    }
                }
                if any_fail {
                    "failed".to_string()
                } else {
                    "ok".to_string()
                }
            }
        }
    };

    // Step 8: insert health_check_results row.
    let result_id = uuid::Uuid::new_v4().to_string();
    let started_at = now_rfc_for_results();
    let metrics_summary = serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".to_string());
    let alert_changes_json = serde_json::to_string(&all_changes).unwrap_or_else(|_| "[]".to_string());
    let run_status = if snapshot.unsupported_metrics.is_empty() {
        "success"
    } else {
        "partial"
    };
    sqlx::query(
        "INSERT INTO health_check_results \
         (id, task_id, started_at, finished_at, status, metrics_summary, alert_changes, triggered_by) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&result_id)
    .bind(task_id)
    .bind(&started_at)
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(run_status)
    .bind(&metrics_summary)
    .bind(&alert_changes_json)
    .bind(triggered_by)
    .execute(pool)
    .await
    .context("insert health_check_results row")?;

    // Step 9: rotate expired results.
    let _ = rotate_results(pool, task_id, config.retention_days).await;

    // Step 10: task_run_history close handled by run_task() wrapper.

    Ok(RunOutcome {
        status: run_status.to_string(),
        metrics_collected: count_collected(&snapshot),
        alert_changes: all_changes.len() as u32,
        webhook_status,
    })
}

/// Evaluate all metrics for a snapshot, persist alert state, return changes.
/// Each metric is independent — a failure to load/persist one doesn't abort
/// the rest (the snapshot already captured what it could).
async fn evaluate_all(
    pool: &SqlitePool,
    task_id: &str,
    snapshot: &MetricsSnapshot,
    config: &HealthCheckTaskConfig,
) -> Result<Vec<AlertChange>> {
    let mut changes = vec![];

    // connectivity (always evaluated).
    let prior = load_metric_state(pool, task_id, "connectivity")
        .await
        .ok()
        .flatten();
    let (new_state, change) =
        evaluate_connectivity(prior.map(|r| r.state), &snapshot.connectivity, config.fail_threshold);
    if let Err(e) = persist_metric_state(pool, task_id, "connectivity", &new_state, None).await {
        tracing::warn!(task_id, error = %e, "persist connectivity alert state failed");
    }
    if let Some(c) = change {
        changes.push(c);
    }

    // row_count (only if collected).
    if let Some(stats) = &snapshot.row_count {
        let prior = load_metric_state(pool, task_id, "row_count")
            .await
            .ok()
            .flatten();
        let (new_state, change) = evaluate_row_count(
            prior.map(|r| r.state),
            stats,
            config.large_table_threshold,
            config.fail_threshold,
        );
        let _ = persist_metric_state(pool, task_id, "row_count", &new_state, None).await;
        if let Some(c) = change {
            changes.push(c);
        }
    }

    // connection_count (only if collected).
    if let Some(count) = snapshot.connection_count {
        let prior = load_metric_state(pool, task_id, "connection_count")
            .await
            .ok()
            .flatten();
        let (new_state, change) = evaluate_connection_count(
            prior.map(|r| r.state),
            Some(count),
            config.connection_count_threshold,
            config.fail_threshold,
        );
        let _ = persist_metric_state(pool, task_id, "connection_count", &new_state, None).await;
        if let Some(c) = change {
            changes.push(c);
        }
    }

    // missing_pk (set-difference; only if collected).
    if let Some(stats) = &snapshot.missing_pk {
        let prior = load_metric_state(pool, task_id, "missing_pk")
            .await
            .ok()
            .flatten();
        let prior_tables = prior.as_ref().and_then(|r| detail_last_missing(r.detail.as_ref()));
        let (persisted_set, pk_changes) = evaluate_missing_pk(prior_tables.as_deref(), stats);
        let detail = detail_for_missing_pk(&persisted_set);
        let _ = persist_metric_state(
            pool,
            task_id,
            "missing_pk",
            // missing_pk doesn't use the Ok/Failing/Alerting state machine;
            // persist Ok as a marker that the row exists (baseline established).
            &AlertState::Ok,
            Some(&detail),
        )
        .await;
        changes.extend(pk_changes);
    }

    Ok(changes)
}

// ── Pool helpers (mirror drift::runner) ──

async fn open_mysql_pool(
    conn: &ConnectionRow,
    password: &str,
) -> Result<sqlx::Pool<sqlx::MySql>> {
    use sqlx::mysql::MySqlConnectOptions;
    let opts = MySqlConnectOptions::new()
        .host(&conn.host)
        .port(conn.port as u16)
        .username(&conn.username)
        .password(password)
        .database(conn.default_database.as_deref().unwrap_or(""));
    sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .map_err(|e| anyhow::anyhow!("mysql connect failed: {e}"))
}

async fn open_pg_pool(
    conn: &ConnectionRow,
    password: &str,
) -> Result<sqlx::Pool<sqlx::Postgres>> {
    use sqlx::postgres::PgConnectOptions;
    let opts = PgConnectOptions::new()
        .host(&conn.host)
        .port(conn.port as u16)
        .username(&conn.username)
        .password(password)
        .database(conn.default_database.as_deref().unwrap_or(""));
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .map_err(|e| anyhow::anyhow!("postgres connect failed: {e}"))
}

// ── Canary (lightweight inline copy of drift's logic) ──
//
// health_check depends on automation + core but NOT on drift (design §2.1:
// independent crate). The canary is a 2-statement probe (CREATE TEMP TABLE +
// DROP); inlining it avoids a cross-crate dependency for ~20 lines.

async fn run_canary_mysql(
    src_pool: &sqlx::Pool<sqlx::MySql>,
    _audit_pool: &SqlitePool,
    _conn_id: &str,
    _triggered_by: &str,
) -> Result<()> {
    let create = sqlx::query("CREATE TEMPORARY TABLE dbmaster_hc_canary (id INT)")
        .execute(src_pool)
        .await;
    match create {
        Ok(_) => {
            let _ = sqlx::query("DROP TEMPORARY TABLE dbmaster_hc_canary")
                .execute(src_pool)
                .await;
            Err(anyhow::anyhow!(
                "source account is writable; refusing to run health_check"
            ))
        }
        Err(e) => {
            // Permission denied = read-only = good. Connection-level error = bad.
            let s = e.to_string().to_lowercase();
            if s.contains("access denied")
                || s.contains("permission")
                || s.contains("create")
                || s.contains("privilege")
            {
                Ok(())
            } else {
                // Likely connection-level — surface as failure.
                Err(anyhow::anyhow!("canary probe failed: {}", redact_sqlx_err(&s)))
            }
        }
    }
}

async fn run_canary_pg(
    src_pool: &sqlx::Pool<sqlx::Postgres>,
    _audit_pool: &SqlitePool,
    _conn_id: &str,
    _triggered_by: &str,
) -> Result<()> {
    let create = sqlx::query("CREATE TEMP TABLE dbmaster_hc_canary (id INT)")
        .execute(src_pool)
        .await;
    match create {
        Ok(_) => {
            // TEMP dies with session; still, a writable account is a config error.
            Err(anyhow::anyhow!(
                "source account is writable; refusing to run health_check"
            ))
        }
        Err(e) => {
            let s = e.to_string().to_lowercase();
            if s.contains("permission") || s.contains("privilege") {
                Ok(())
            } else {
                Err(anyhow::anyhow!("canary probe failed: {}", redact_sqlx_err(&s)))
            }
        }
    }
}

// ── Result rotation ──

/// U06 — persist a `health_check_results` row for a failed run so the read
/// endpoint / desktop history surface the failure. Empty metrics/alerts JSON
/// (nothing was collected); the redacted error goes to the `error` column
/// (migration 014). Rotation on the next successful run cleans these rows by
/// `started_at` like any other.
async fn insert_failed_result(
    pool: &SqlitePool,
    task_id: &str,
    started_at: &str,
    redacted_error: &str,
    triggered_by: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO health_check_results \
         (id, task_id, started_at, finished_at, status, metrics_summary, \
          alert_changes, triggered_by, error) \
         VALUES (?1, ?2, ?3, ?4, 'failed', '{}', '[]', ?5, ?6)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(task_id)
    .bind(started_at)
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(triggered_by)
    .bind(redacted_error)
    .execute(pool)
    .await
    .context("insert failed-run health_check_results row")?;
    Ok(())
}

async fn rotate_results(pool: &SqlitePool, task_id: &str, retention_days: u32) -> Result<()> {
    sqlx::query(
        "DELETE FROM health_check_results \
         WHERE task_id = ?1 \
         AND started_at < datetime('now', ?2)",
    )
    .bind(task_id)
    .bind(format!("-{retention_days} days"))
    .execute(pool)
    .await
    .context("rotate health_check_results")?;
    Ok(())
}

// ── Helpers ──

async fn update_task_status(
    pool: &SqlitePool,
    task_id: &str,
    when: &str,
    status: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE scheduled_tasks SET last_run_at = ?1, last_status = ?2 WHERE id = ?3",
    )
    .bind(when)
    .bind(status)
    .bind(task_id)
    .execute(pool)
    .await
    .context("update scheduled_tasks last_run_at/last_status")?;
    Ok(())
}

/// Record a `credential_access_audit` row when health_check decrypts and uses a
/// stored source-DB credential (ADR-0002 §4.2.4 / v1-C-5 — uniform audit trail).
///
/// Kept local to health_check instead of depending on `drift::audit`:
/// drift and health_check are sibling domain crates, and the drift
/// `AuditAction` enum is drift-scoped (it carries no `health_check` variant).
/// This mirrors what automation's DDL executor already does (inline INSERT
/// with an open-string action), so the three credential-decrypt sites each
/// own a thin local writer into the same shared table.
///
/// Best-effort: a failed audit write MUST NOT abort the run (the decrypt/use
/// is the trusted boundary; audit logging is defence-in-depth), so errors are
/// swallowed. `status` is `"ok"` | `"error"`; `error` is a short redacted
/// summary (NO credential / SQL text / PII) — pass `None` for success rows.
/// `triggered_by` is `"scheduler"` or `"manual:<user_id>"`.
async fn record_credential_access(
    pool: &SqlitePool,
    connection_id: &str,
    status: &str,
    error: Option<&str>,
    triggered_by: &str,
) {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let err = error.map(truncate_audit_error);
    // DEFENSIVE-NOTE: every value is bound — never interpolated into SQL.
    // connection_id / error are caller-supplied and parameterized, so SQL
    // injection is structurally impossible here. The fixed `action` literal
    // is the only string baked into the statement.
    let res = sqlx::query(
        "INSERT INTO credential_access_audit \
         (id, connection_id, action, status, error, at, triggered_by) \
         VALUES (?1, ?2, 'health_check', ?3, ?4, ?5, ?6)",
    )
    .bind(&id)
    .bind(connection_id)
    .bind(status)
    .bind(&err)
    .bind(&now)
    .bind(triggered_by)
    .execute(pool)
    .await;
    if let Err(e) = res {
        // Defence-in-depth: never escalate an audit-write failure. Log it and
        // continue — task_run_history already captures the run outcome.
        tracing::warn!(error = %e, connection_id, "credential_access_audit write failed");
    }
}

/// Truncate a redacted error summary to a bounded length so a misbehaving
/// caller cannot bloat the audit table. Mirrors drift::audit::truncate_redacted
/// (500 chars) so audit rows are uniformly sized across the three writers.
fn truncate_audit_error(s: &str) -> String {
    const MAX: usize = 500;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(MAX).collect();
        format!("{truncated}…[truncated]")
    }
}

fn count_collected(snapshot: &MetricsSnapshot) -> u32 {
    let mut n = 1; // connectivity always
    if snapshot.row_count.is_some() {
        n += 1;
    }
    if snapshot.missing_pk.is_some() {
        n += 1;
    }
    if snapshot.connection_count.is_some() {
        n += 1;
    }
    n
}

fn now_rfc_for_results() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Render an error safe for storage in task_run_history.error: short, no
/// credential / SQL / PII. Mirrors drift::runner::redact_error.
fn redact_error(e: &anyhow::Error) -> String {
    let s = e.to_string();
    s.lines()
        .next()
        .unwrap_or("health_check run error")
        .chars()
        .take(300)
        .collect()
}

fn redact_sqlx_err(s: &str) -> String {
    s.lines()
        .next()
        .unwrap_or("driver error")
        .chars()
        .take(200)
        .collect()
}

/// Mirrors drift::runner / data_sync::runner — `DBMASTER_DEV=1` enables
/// http://localhost webhook URLs for local testing.
fn is_dev_mode() -> bool {
    matches!(std::env::var("DBMASTER_DEV").as_deref(), Ok("1"))
}

// ── Row projections ──

#[derive(sqlx::FromRow)]
struct TaskRow {
    id: String,
    name: String,
    config: String,
    source_db_id: String,
    notify_channels: String,
}

#[derive(sqlx::FromRow)]
struct ConnectionRow {
    id: String,
    name: String,
    db_type: String,
    host: String,
    port: i64,
    username: String,
    password_encrypted: String,
    default_database: Option<String>,
    kind: String,
}

// `alert` and `collector` are referenced via the use block above; keep the
// imports tidy for future milestones.
#[allow(unused_imports)]
use alert as _alert_module;
#[allow(unused_imports)]
use collector as _collector_module;

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE credential_access_audit (
                id            TEXT PRIMARY KEY,
                connection_id TEXT NOT NULL,
                action        TEXT NOT NULL,
                status        TEXT NOT NULL,
                error         TEXT,
                at            TEXT NOT NULL,
                triggered_by  TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn writes_ok_row_on_successful_access() {
        let pool = setup_pool().await;
        record_credential_access(&pool, "conn-1", "ok", None, "scheduler").await;

        let row: (String, String, String, Option<String>, String, String) = sqlx::query_as(
            "SELECT connection_id, action, status, error, at, triggered_by \
             FROM credential_access_audit WHERE connection_id = ?1",
        )
        .bind("conn-1")
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(row.0, "conn-1");
        assert_eq!(row.1, "health_check");
        assert_eq!(row.2, "ok");
        assert!(row.3.is_none());
        assert!(row.4.contains('T')); // RFC3339
        assert_eq!(row.5, "scheduler");
    }

    #[tokio::test]
    async fn writes_error_row_on_failed_access() {
        let pool = setup_pool().await;
        record_credential_access(
            &pool,
            "conn-2",
            "error",
            Some("credential decrypt failed"),
            "manual:user-7",
        )
        .await;

        let row: (String, Option<String>) = sqlx::query_as(
            "SELECT action, error FROM credential_access_audit WHERE connection_id = ?1",
        )
        .bind("conn-2")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "health_check");
        assert_eq!(row.1.as_deref(), Some("credential decrypt failed"));
    }

    // ── v1-C-5: grep assertion that NO sensitive material is stored ──
    #[tokio::test]
    async fn audit_row_contains_no_credentials_sql_or_pii() {
        let pool = setup_pool().await;
        // DEFENSIVE-NOTE: connection_id deliberately avoids every forbidden
        // substring so the test data cannot trip its own grep. Even so, the
        // writer must not pull in any extra DB/SQL/credential text beyond the
        // caller-provided values.
        record_credential_access(&pool, "conn-uuid-1234", "ok", None, "scheduler").await;

        let rows: Vec<(String, String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT connection_id, action, status, error, triggered_by \
             FROM credential_access_audit",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        let forbidden = ["password", "secret", "credential", "mysql://", "postgres://"];
        for (conn_id, action, status, err, triggered_by) in &rows {
            for needle in forbidden {
                assert!(
                    !conn_id.to_lowercase().contains(needle),
                    "connection_id leaked '{needle}': {conn_id}"
                );
                assert!(
                    !action.to_lowercase().contains(needle),
                    "action leaked '{needle}': {action}"
                );
                assert!(
                    !status.to_lowercase().contains(needle),
                    "status leaked '{needle}': {status}"
                );
                if let Some(e) = err {
                    assert!(!e.to_lowercase().contains(needle), "error leaked '{needle}': {e}");
                }
                assert!(
                    !triggered_by.to_lowercase().contains(needle),
                    "triggered_by leaked '{needle}': {triggered_by}"
                );
            }
        }
    }

    #[test]
    fn truncate_caps_long_error() {
        let long: String = "a".repeat(1000);
        let t = truncate_audit_error(&long);
        assert!(t.chars().count() < 1000);
        assert!(t.ends_with("…[truncated]"));
    }

    #[test]
    fn truncate_keeps_short_error_intact() {
        assert_eq!(truncate_audit_error("short"), "short");
    }
}
