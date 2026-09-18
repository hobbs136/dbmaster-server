//! End-to-end drift run orchestration (ADR-0002 §4.3.1 / §4.4.2 / §7.1 /
//! v1-C-9).
//!
//! Pipeline per run (every step audited; any failure surfaces in
//! [`RunSummary`] and `task_run_history`):
//!
//! 1. Open a `task_run_history` row (status=running, started_at=now).
//! 2. Load `scheduled_tasks` + `database_connections` rows.
//! 3. Decrypt source-DB password; audit `schema_snapshot`.
//! 4. Open a short-lived source-DB pool (`mysql://` or `postgres://`).
//! 5. If `connection.kind == "source_drift"`: run canary (refuse to run if
//!    the account is writable — defence in depth, complementing the
//!    create-time canary).
//! 6. Collect schema → snapshot → sha256 hash.
//! 7. Look up the prior snapshot for this connection.
//! 8. If hash differs and prior exists: compute drifts. Else drifts = [].
//! 9. Insert new `schema_snapshots` row (prior_hash chain, change_count).
//! 10. If drifts non-empty: build payload, deliver webhook (bounded retry).
//!     Audit `webhook_deliver` outcome.
//! 11. Close `task_run_history` (status=succeeded, summary) and update
//!     `scheduled_tasks.last_run_at` / `last_status`.
//!
//! On any failure, the run is marked failed in `task_run_history` with a
//! redacted error message (no credential / SQL / PII).

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use sqlx::SqlitePool;

use dbmaster_core::server::AppState;

use crate::audit::{log_access, AuditAction, AuditStatus};
use crate::canary::{check_mysql, check_postgres, CanaryOutcome};
use crate::collector::{collect_mysql, collect_postgres};
use crate::diff::compute_drifts;
use crate::notify::{deliver, DeliveryStatus, NotifyError, WebhookPayload};
use crate::snapshot::DbType;

/// `DBMASTER_DEV=1` toggles whether http://localhost webhook URLs are allowed
/// (passed into `notify::deliver`).
const DEV_MODE_ENV: &str = "DBMASTER_DEV";

/// Per-run summary written into `task_run_history.summary` (JSON).
/// Fields locked per ADR §7.1 schema comment.
///
/// U09: `snapshot_id`/`baseline_snapshot_id` identify the exact snapshot pair
/// this run compared, so the desktop's "View Diff" on a history row can open
/// that pair instead of guessing "latest two". `baseline_snapshot_id` is
/// `None` on the very first run for a connection (nothing to compare).
/// Old rows written before U09 simply lack the keys — the desktop treats
/// missing keys as "fall back to latest two".
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunSummary {
    pub drift_count: u32,
    pub webhook_status: String, // "ok" | "failed" | "skipped"
    pub duration_ms: u64,
    pub snapshot_id: String,
    pub baseline_snapshot_id: Option<String>,
}

/// What [`run_task`] returns on the success path (used by the scheduler's
/// log line and available to manual callers).
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub drift_count: u32,
    pub webhook_status: String,
    pub snapshot_id: String,
    pub baseline_snapshot_id: Option<String>,
}

/// Narrow row projections used by the runner. Kept private; the public API
/// is [`run_task`].
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

#[derive(sqlx::FromRow)]
struct PriorSnapshotRow {
    id: String,
    captured_at: String,
    schema_hash: String,
    schema_json: String,
}

/// Parse the `notify_channels` JSON array; v1 reads only the first URL (ADR
/// §4.4.2). Returns `None` if empty / malformed → webhook skipped.
fn first_webhook_url(notify_channels_json: &str) -> Option<String> {
    let v = serde_json::from_str::<serde_json::Value>(notify_channels_json).ok()?;
    let arr = v.as_array()?;
    let first = arr.first()?;
    first.as_str().map(|s| s.to_string())
}

/// Top-level entry. `triggered_by` is `"scheduler"` or `"manual:<user_id>"`
/// per ADR §4.2.4.
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
        "INSERT INTO task_run_history (id, task_id, started_at, status, triggered_by)
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
            let summary = serde_json::to_string(&RunSummary {
                drift_count: o.drift_count,
                webhook_status: o.webhook_status.clone(),
                duration_ms: elapsed_ms,
                snapshot_id: o.snapshot_id.clone(),
                baseline_snapshot_id: o.baseline_snapshot_id.clone(),
            })
            .unwrap_or_else(|_| "{}".to_string());
            let _ = sqlx::query(
                "UPDATE task_run_history
                 SET finished_at = ?1, status = 'succeeded', summary = ?2
                 WHERE id = ?3",
            )
            .bind(&now_end)
            .bind(&summary)
            .bind(&run_id)
            .execute(pool)
            .await;
            let _ = update_task_status(pool, task_id, &now_end, "succeeded").await;
        }
        Err(e) => {
            tracing::warn!(task_id, error = %e, "drift run failed");
            let _ = sqlx::query(
                "UPDATE task_run_history
                 SET finished_at = ?1, status = 'failed', error = ?2
                 WHERE id = ?3",
            )
            .bind(&now_end)
            .bind(redact_error(e))
            .bind(&run_id)
            .execute(pool)
            .await;
            let _ = update_task_status(pool, task_id, &now_end, "failed").await;
        }
    }

    outcome
}

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

async fn run_task_inner(
    pool: &SqlitePool,
    state: &AppState,
    task_id: &str,
    triggered_by: &str,
) -> Result<RunOutcome> {
    // Step 2: load task + connection.
    let task: TaskRow = sqlx::query_as::<_, TaskRow>(
        "SELECT id, name, config, source_db_id, notify_channels
         FROM scheduled_tasks WHERE id = ?1",
    )
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .context("fetch scheduled_task")?
    .ok_or_else(|| anyhow!("task {task_id} not found"))?;

    let conn: ConnectionRow = sqlx::query_as::<_, ConnectionRow>(
        "SELECT id, name, db_type, host, port, username, password_encrypted,
                default_database, kind
         FROM database_connections WHERE id = ?1",
    )
    .bind(&task.source_db_id)
    .fetch_optional(pool)
    .await
    .context("fetch source connection")?
    .ok_or_else(|| anyhow!("source connection {} not found", task.source_db_id))?;

    // Step 3: decrypt password; audit schema_snapshot start.
    let password = dbmaster_automation::credential::decrypt_password(
        &conn.password_encrypted,
        &state.credential_key,
    )
    .map_err(|e| anyhow!("credential decrypt failed: {e}"))?;
    log_access(
        pool,
        &conn.id,
        AuditAction::SchemaSnapshot,
        AuditStatus::Ok,
        None,
        triggered_by,
    )
    .await
    .context("audit schema_snapshot start")?;

    // Step 4-6: open source pool, canary, collect.
    let db_type = DbType::from_db_type_str(&conn.db_type)
        .ok_or_else(|| anyhow!("unsupported db_type: {}", conn.db_type))?;
    let snapshot = match db_type {
        DbType::MySql => {
            let src_pool = open_mysql_pool(&conn, &password).await?;
            // Step 5: canary if source_drift.
            if conn.kind == "source_drift" {
                run_canary_mysql(&src_pool, pool, &conn.id, triggered_by).await?;
            }
            // Step 6: collect.
            let db_name = conn.default_database.as_deref().unwrap_or("");
            let snap = collect_mysql(&src_pool, db_name).await?;
            drop(src_pool);
            snap
        }
        DbType::Postgres => {
            let src_pool = open_pg_pool(&conn, &password).await?;
            if conn.kind == "source_drift" {
                run_canary_pg(&src_pool, pool, &conn.id, triggered_by).await?;
            }
            let db_name = conn.default_database.as_deref().unwrap_or("");
            // PG default schema is "public" unless config overrides.
            let schemas = pg_schemas_from_task_config(&task.config);
            let snap = collect_postgres(&src_pool, db_name, &schemas).await?;
            drop(src_pool);
            snap
        }
    };

    let new_hash = snapshot
        .canonical_hash()
        .map_err(|e| anyhow!("hash compute failed: {e}"))?;
    let new_schema_json = String::from_utf8(
        snapshot
            .canonical_json()
            .map_err(|e| anyhow!("canonical json failed: {e}"))?,
    )
    .map_err(|e| anyhow!("canonical json utf8: {e}"))?;

    // Step 7-8: prior snapshot + drifts.
    let prior: Option<PriorSnapshotRow> = sqlx::query_as::<_, PriorSnapshotRow>(
        "SELECT id, captured_at, schema_hash, schema_json
         FROM schema_snapshots WHERE connection_id = ?1
         ORDER BY captured_at DESC LIMIT 1",
    )
    .bind(&conn.id)
    .fetch_optional(pool)
    .await
    .context("fetch prior snapshot")?;

    let (drifts, prior_snapshot_at, change_count): (Vec<_>, Option<String>, u32) = match &prior {
        Some(p) if p.schema_hash != new_hash => {
            // Hash differs → run the structural diff.
            let prior_snap: crate::snapshot::SchemaSnapshot =
                serde_json::from_str(&p.schema_json)
                    .map_err(|e| anyhow!("parse prior snapshot json: {e}"))?;
            let d = compute_drifts(&prior_snap, &snapshot);
            let count = d.len() as u32;
            (d, Some(p.captured_at.clone()), count)
        }
        Some(p) => (Vec::new(), Some(p.captured_at.clone()), 0), // hash equal
        None => (Vec::new(), None, 0),                           // first snapshot
    };

    // Step 9: insert new schema_snapshots row.
    let snap_id = uuid::Uuid::new_v4().to_string();
    let now_snap = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO schema_snapshots
            (id, connection_id, captured_at, schema_hash, schema_json, prior_hash, task_id, change_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&snap_id)
    .bind(&conn.id)
    .bind(&now_snap)
    .bind(&new_hash)
    .bind(&new_schema_json)
    .bind(prior.as_ref().map(|p| p.schema_hash.as_str()))
    .bind(task_id)
    .bind(change_count as i64)
    .execute(pool)
    .await
    .context("insert schema_snapshots row")?;

    // Step 10: webhook if drifts non-empty (v1-C-13).
    let webhook_status = if drifts.is_empty() {
        "skipped".to_string()
    } else {
        let url = first_webhook_url(&task.notify_channels);
        match url {
            None => "skipped".to_string(),
            Some(url) => {
                let payload = build_payload(
                    &snapshot,
                    &drifts,
                    &prior_snapshot_at,
                    &now_snap,
                    &task,
                    &conn,
                    db_type,
                    state,
                );
                let timeout = Duration::from_secs(state.config.drift_webhook_timeout_secs);
                let dev_mode = is_dev_mode();
                let delivery = deliver(&payload, &url, timeout, dev_mode).await;
                let audit_status = match &delivery {
                    Ok(_) => AuditStatus::Ok,
                    Err(_) => AuditStatus::Error,
                };
                let audit_err = delivery.as_ref().err().map(|e| e.to_string());
                log_access(
                    pool,
                    &conn.id,
                    AuditAction::WebhookDeliver,
                    audit_status,
                    audit_err.as_deref(),
                    triggered_by,
                )
                .await
                .ok(); // best-effort; do not let audit failure mask delivery result
                match delivery {
                    Ok(r) if r.final_status == DeliveryStatus::Delivered => "ok".to_string(),
                    Err(NotifyError::InsecureUrl) | Err(NotifyError::MalformedUrl(_)) => {
                        "failed".to_string()
                    }
                    Err(_) => "failed".to_string(),
                    _ => "failed".to_string(),
                }
            }
        }
    };

    Ok(RunOutcome {
        drift_count: change_count,
        webhook_status,
        snapshot_id: snap_id,
        baseline_snapshot_id: prior.as_ref().map(|p| p.id.clone()),
    })
}

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
    // Small pool: a snapshot run is fast and single-purpose.
    sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .map_err(|e| anyhow!("mysql connect failed: {e}"))
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
        .map_err(|e| anyhow!("postgres connect failed: {e}"))
}

async fn run_canary_mysql(
    src_pool: &sqlx::Pool<sqlx::MySql>,
    audit_pool: &SqlitePool,
    conn_id: &str,
    triggered_by: &str,
) -> Result<()> {
    let outcome = check_mysql(src_pool).await;
    let (status, err) = match &outcome {
        CanaryOutcome::ReadOnly => (AuditStatus::Ok, None),
        CanaryOutcome::Writable => (AuditStatus::Error, Some("account is writable; expected read-only")),
        CanaryOutcome::Unreachable(m) => (AuditStatus::Error, Some(m.as_str())),
    };
    log_access(audit_pool, conn_id, AuditAction::CanaryCheck, status, err, triggered_by)
        .await
        .ok();
    match outcome {
        CanaryOutcome::ReadOnly => Ok(()),
        CanaryOutcome::Writable => Err(anyhow!("source account is writable; refusing to run")),
        CanaryOutcome::Unreachable(_) => Err(anyhow!("source DB unreachable during canary")),
    }
}

async fn run_canary_pg(
    src_pool: &sqlx::Pool<sqlx::Postgres>,
    audit_pool: &SqlitePool,
    conn_id: &str,
    triggered_by: &str,
) -> Result<()> {
    let outcome = check_postgres(src_pool).await;
    let (status, err) = match &outcome {
        CanaryOutcome::ReadOnly => (AuditStatus::Ok, None),
        CanaryOutcome::Writable => (AuditStatus::Error, Some("account is writable; expected read-only")),
        CanaryOutcome::Unreachable(m) => (AuditStatus::Error, Some(m.as_str())),
    };
    log_access(audit_pool, conn_id, AuditAction::CanaryCheck, status, err, triggered_by)
        .await
        .ok();
    match outcome {
        CanaryOutcome::ReadOnly => Ok(()),
        CanaryOutcome::Writable => Err(anyhow!("source account is writable; refusing to run")),
        CanaryOutcome::Unreachable(_) => Err(anyhow!("source DB unreachable during canary")),
    }
}

/// Read PG schema list from task.config (`{"pg_schemas": ["public", ...]}`),
/// defaulting to `["public"]`.
fn pg_schemas_from_task_config(config_json: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return vec!["public".to_string()];
    };
    let Some(arr) = v.get("pg_schemas").and_then(|x| x.as_array()) else {
        return vec!["public".to_string()];
    };
    let out: Vec<String> = arr
        .iter()
        .filter_map(|x| x.as_str().map(String::from))
        .filter(|s| !s.is_empty())
        .collect();
    if out.is_empty() {
        vec!["public".to_string()]
    } else {
        out
    }
}

// DEFENSIVE-NOTE: clippy too_many_arguments threshold is 7; this builder
// needs all 8 (every arg maps to an ADR-locked payload field). Consolidating
// into a context struct would add boilerplate without clarifying intent —
// ruled out as 无关重构 per the workspace change rules. Local allow instead.
#[allow(clippy::too_many_arguments)]
fn build_payload(
    snapshot: &crate::snapshot::SchemaSnapshot,
    drifts: &[crate::diff::Drift],
    prior_snapshot_at: &Option<String>,
    new_snapshot_at: &str,
    task: &TaskRow,
    conn: &ConnectionRow,
    db_type: DbType,
    state: &AppState,
) -> WebhookPayload {
    let event_id = uuid::Uuid::new_v4().to_string();
    let event_at = chrono::Utc::now().to_rfc3339();
    // CHANGE: ADR-0002 §4.4.2 — populate instance_uuid from AppState (resolved
    // once at boot from instance_meta). DEFENSIVE-NOTE: install_uuid is NOT
    // PII per ADR §4.4.2; safe to ship in the payload.
    let instance_uuid = state.install_uuid.as_str().to_string();
    let mut payload = WebhookPayload::new(
        event_id,
        event_at,
        instance_uuid,
        drifts.to_vec(),
        prior_snapshot_at.clone(),
        new_snapshot_at.to_string(),
    );
    payload.task = crate::notify::TaskRef {
        id: task.id.clone(),
        name: task.name.clone(),
    };
    payload.connection = crate::notify::ConnectionRef {
        id: conn.id.clone(),
        name: conn.name.clone(),
    };
    payload.source = crate::notify::SourceRef {
        db_type: db_type.as_wire_str().to_string(),
        database: snapshot.database.clone(),
    };
    payload
}

fn is_dev_mode() -> bool {
    matches!(std::env::var(DEV_MODE_ENV).as_deref(), Ok("1"))
}

/// Render an error safe for storage in `task_run_history.error`: short, no
/// credential / SQL / PII. The runner's errors are already constructed with
/// `anyhow!("...")` and redaction happens at construction; we just truncate.
fn redact_error(e: &anyhow::Error) -> String {
    let s = e.to_string();
    let cut: String = s.chars().take(500).collect();
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_webhook_url_reads_first_array_element() {
        let s = r#"["https://a.example/hook", "https://b.example/hook"]"#;
        assert_eq!(
            first_webhook_url(s).as_deref(),
            Some("https://a.example/hook")
        );
    }

    #[test]
    fn first_webhook_url_returns_none_for_empty_array() {
        assert!(first_webhook_url("[]").is_none());
    }

    #[test]
    fn first_webhook_url_returns_none_for_garbage() {
        assert!(first_webhook_url("not json").is_none());
        assert!(first_webhook_url("{}").is_none());
        // Array of non-string values → none.
        assert!(first_webhook_url(r#"[42]"#).is_none());
    }

    #[test]
    fn first_webhook_url_accepts_single_string_array() {
        assert_eq!(
            first_webhook_url(r#"["https://x.example/h"]"#).as_deref(),
            Some("https://x.example/h")
        );
    }

    #[test]
    fn pg_schemas_default_to_public() {
        assert_eq!(pg_schemas_from_task_config("{}"), vec!["public".to_string()]);
        assert_eq!(pg_schemas_from_task_config("garbage"), vec!["public".to_string()]);
    }

    #[test]
    fn pg_schemas_read_from_config() {
        let cfg = r#"{"pg_schemas": ["public", "audit"]}"#;
        assert_eq!(
            pg_schemas_from_task_config(cfg),
            vec!["public".to_string(), "audit".to_string()]
        );
    }

    #[test]
    fn pg_schemas_falls_back_when_empty_array() {
        assert_eq!(pg_schemas_from_task_config(r#"{"pg_schemas": []}"#), vec!["public".to_string()]);
    }

    #[test]
    fn redact_error_truncates_long_messages() {
        let long = anyhow!("{}", "x".repeat(1000));
        let r = redact_error(&long);
        assert!(r.chars().count() <= 500);
    }

    // U09: the desktop's "View Diff" on a run-history row parses
    // `snapshot_id` / `baseline_snapshot_id` out of `summary`. Lock the JSON
    // shape so a rename fails here instead of silently on the desktop.
    #[test]
    fn run_summary_serializes_snapshot_pair() {
        let s = RunSummary {
            drift_count: 2,
            webhook_status: "ok".to_string(),
            duration_ms: 321,
            snapshot_id: "snap-1".to_string(),
            baseline_snapshot_id: Some("snap-0".to_string()),
        };
        let v: serde_json::Value =
            serde_json::to_value(&s).expect("RunSummary is plain data; serialize cannot fail");
        assert_eq!(v["snapshot_id"], "snap-1");
        assert_eq!(v["baseline_snapshot_id"], "snap-0");
    }

    #[test]
    fn run_summary_first_run_has_null_baseline() {
        let s = RunSummary {
            drift_count: 0,
            webhook_status: "skipped".to_string(),
            duration_ms: 5,
            snapshot_id: "snap-first".to_string(),
            baseline_snapshot_id: None,
        };
        let v: serde_json::Value =
            serde_json::to_value(&s).expect("RunSummary is plain data; serialize cannot fail");
        assert!(v["baseline_snapshot_id"].is_null());
        assert_eq!(v["snapshot_id"], "snap-first");
    }
}
