//! End-to-end ETL runner for a single `data_sync` task run.
//!
//! Flow (一期):
//! 1. Open a `data_sync_runs` row (status=running, cursor=start or MIN).
//! 2. Load task config + source/target connection rows; decrypt passwords.
//! 3. Open short-lived source + target pools (max_connections=2, like drift).
//! 4. Probe MIN/MAX of the batching anchor on the main table (aggregate only).
//! 5. Loop while cursor < MAX:
//!    a. Poll `cancel_requested` → break with status=canceled.
//!    b. Execute the time-batched JOIN SELECT on the source pool.
//!    c. Bulk-insert the batch into the target (parameterised, multi-row).
//!    d. Advance cursor; persist progress / processed_rows / cursor.
//! 6. Finalise: status=succeeded (or canceled/failed), summary persisted.
//!
//! Trust boundary: identifiers are validated by [`crate::config`] before any
//! SQL is assembled; JOIN/ON fragments are built only from validated
//! identifiers via [`sql::quote_ident`]. Row values and constants are bound
//! as parameters — never interpolated. Errors are redacted before persistence.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};

use dbmaster_core::server::AppState;

use crate::config::{ColumnSelect, DataSyncTaskConfig, JoinTable, SourceConfig, TargetStrategy};
use crate::notify;

// Identifier-quoting helper (crate-local). The qualified `sql::` path below
// refers to this module; the alias avoids shadowing sqlx's own `sql` items.
use crate::sql;

/// Run outcome recorded in the run summary.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub processed_rows: u64,
    pub failed_rows: u64,
    pub canceled: bool,
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

    // Resume support: if the latest run for this task left a cursor without
    // succeeding, seed the new run from it.
    let resume_cursor = match find_resumable_cursor(pool, task_id).await {
        Ok(Some(c)) => Some(c),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(task_id, error = %e, "could not read resume cursor; starting fresh");
            None
        }
    };

    // Step 1: open run row.
    sqlx::query(
        "INSERT INTO data_sync_runs
           (id, task_id, started_at, status, triggered_by, progress, processed_rows, failed_rows, cancel_requested)
         VALUES (?1, ?2, ?3, 'running', ?4, 0, 0, 0, 0)",
    )
    .bind(&run_id)
    .bind(task_id)
    .bind(&now_rfc)
    .bind(triggered_by)
    .execute(pool)
    .await
    .context("insert data_sync_runs running row")?;

    let outcome = run_task_inner(pool, state, task_id, resume_cursor).await;

    let elapsed_ms = started.elapsed().as_millis() as u64;
    let now_end = chrono::Utc::now().to_rfc3339();
    let status_label = match &outcome {
        Ok(o) if o.canceled => "canceled",
        Ok(_) => "succeeded",
        Err(_) => "failed",
    };

    match &outcome {
        Ok(o) => {
            let summary = serde_json::json!({
                "duration_ms": elapsed_ms,
                "processed_rows": o.processed_rows,
                "failed_rows": o.failed_rows,
                "canceled": o.canceled,
            })
            .to_string();
            let _ = sqlx::query(
                "UPDATE data_sync_runs
                 SET finished_at = ?1, status = ?2, summary = ?3,
                     processed_rows = ?4, failed_rows = ?5
                 WHERE id = ?6",
            )
            .bind(&now_end)
            .bind(status_label)
            .bind(&summary)
            .bind(o.processed_rows as i64)
            .bind(o.failed_rows as i64)
            .bind(&run_id)
            .execute(pool)
            .await;
            let _ = update_task_status(pool, task_id, &now_end, status_label).await;
        }
        Err(e) => {
            tracing::warn!(task_id, error = %e, "data_sync run failed");
            let _ = sqlx::query(
                "UPDATE data_sync_runs
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

    // M1.2: best-effort failure / partial-failure webhook notification.
    // Send on: (a) fatal error (Err), or (b) partial failure (failed_rows > 0).
    // Never blocks outcome — notification errors are logged and swallowed.
    let should_notify = match &outcome {
        Ok(o) => o.failed_rows > 0,
        Err(_) => true,
    };
    if should_notify {
        if let Err(e) = maybe_notify(pool, &state.install_uuid, task_id, &outcome, elapsed_ms).await {
            tracing::warn!(task_id, error = %e, "data_sync webhook notification failed (best-effort)");
        }
    }

    outcome
}

/// Best-effort webhook notification on data-sync failure or partial failure.
/// Loads task name + notify_channels + connection names from the DB, builds a
/// WebhookPayload, and delivers it. All errors are logged and returned (caller
/// swallows them — notifications must never block the outcome).
async fn maybe_notify(
    pool: &SqlitePool,
    install_uuid: &str,
    task_id: &str,
    outcome: &Result<RunOutcome>,
    elapsed_ms: u64,
) -> Result<()> {
    // Load task row for name + notify_channels + source/target connection IDs.
    let task: TaskRow = sqlx::query_as::<_, TaskRow>(
        "SELECT id, name, config, source_db_id, target_db_id, notify_channels
         FROM scheduled_tasks WHERE id = ?1",
    )
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .context("fetch task for notify")?
    .ok_or_else(|| anyhow!("task {task_id} not found for notify"))?;

    let webhook_url = match notify::first_webhook_url(&task.notify_channels) {
        Some(url) => url,
        None => return Ok(()), // no webhook configured, nothing to do
    };

    // Load connection names for the payload (name only, no host/port — 定律 5).
    let source_conn = load_connection(pool, &task.source_db_id).await.ok();
    let target_conn = match &task.target_db_id {
        Some(id) => load_connection(pool, id).await.ok(),
        None => None,
    };

    let (summary, error) = match outcome {
        Ok(o) => (
            notify::SyncSummary {
                processed_rows: o.processed_rows,
                failed_rows: o.failed_rows,
                duration_ms: elapsed_ms,
                canceled: o.canceled,
            },
            None,
        ),
        Err(e) => (
            notify::SyncSummary {
                processed_rows: 0,
                failed_rows: 0,
                duration_ms: elapsed_ms,
                canceled: false,
            },
            Some(redact_error(e)),
        ),
    };

    let payload = notify::WebhookPayload::new(
        uuid::Uuid::new_v4().to_string(),
        chrono::Utc::now().to_rfc3339(),
        install_uuid.to_string(),
        notify::TaskRef { id: task_id.to_string(), name: task.name.clone() },
        notify::ConnectionRef {
            id: task.source_db_id.clone(),
            name: source_conn.map(|c| c.name).unwrap_or_default(),
        },
        notify::ConnectionRef {
            id: task.target_db_id.clone().unwrap_or_default(),
            name: target_conn.map(|c| c.name).unwrap_or_default(),
        },
        summary,
        error,
    );

    let timeout = Duration::from_secs(notify::DEFAULT_TIMEOUT_SECS);
    let dev_mode = is_dev_mode();
    // Best-effort: deliver retries internally; permanent failure returns Err
    // which we surface to the caller (who logs and swallows).
    notify::deliver(&payload, &webhook_url, timeout, dev_mode).await?;
    Ok(())
}

/// Check if dev mode is enabled (allows http://localhost webhooks).
/// Mirrors drift::runner::is_dev_mode.
fn is_dev_mode() -> bool {
    matches!(std::env::var("DBMASTER_DEV").as_deref(), Ok("1"))
}

async fn update_task_status(pool: &SqlitePool, task_id: &str, when: &str, status: &str) -> Result<()> {
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

/// If the most recent run for this task left a cursor and didn't succeed,
/// return that cursor so the new run resumes from there.
async fn find_resumable_cursor(pool: &SqlitePool, task_id: &str) -> Result<Option<String>> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT cursor, status FROM data_sync_runs
         WHERE task_id = ?1
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .context("fetch latest data_sync_runs row for resume")?;
    match row {
        Some((Some(cursor), status)) if status.as_deref() != Some("succeeded") => Ok(Some(cursor)),
        _ => Ok(None),
    }
}

async fn run_task_inner(
    pool: &SqlitePool,
    state: &AppState,
    task_id: &str,
    resume_cursor: Option<String>,
) -> Result<RunOutcome> {
    let task: TaskRow = sqlx::query_as::<_, TaskRow>(
        "SELECT id, name, config, source_db_id, target_db_id, notify_channels
         FROM scheduled_tasks WHERE id = ?1",
    )
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .context("fetch scheduled_task")?
    .ok_or_else(|| anyhow!("task {task_id} not found"))?;

    let config: DataSyncTaskConfig = serde_json::from_str(&task.config)
        .map_err(|e| anyhow!("parse data_sync config: {e}"))?;
    config.validate().map_err(|e| anyhow!("invalid config: {e}"))?;

    let target_db_id = task
        .target_db_id
        .ok_or_else(|| anyhow!("data_sync task {task_id} has no target_db_id"))?;

    let src_conn = load_connection(pool, &task.source_db_id).await?;
    let tgt_conn = load_connection(pool, &target_db_id).await?;

    let src_password = dbmaster_automation::credential::decrypt_password(
        &src_conn.password_encrypted,
        &state.credential_key,
    )
    .map_err(|e| anyhow!("source credential decrypt failed: {e}"))?;
    let tgt_password = dbmaster_automation::credential::decrypt_password(
        &tgt_conn.password_encrypted,
        &state.credential_key,
    )
    .map_err(|e| anyhow!("target credential decrypt failed: {e}"))?;

    let default_batch = state.config.data_sync_default_batch_size.max(1);
    let batch_size = config.batching.batch_size.unwrap_or(default_batch).max(1);

    let src_db = DbType::from_db_type_str(&src_conn.db_type)
        .ok_or_else(|| anyhow!("unsupported source db_type: {}", src_conn.db_type))?;
    let tgt_db = DbType::from_db_type_str(&tgt_conn.db_type)
        .ok_or_else(|| anyhow!("unsupported target db_type: {}", tgt_conn.db_type))?;

    let ctx = LoopCtx {
        ctrl: pool,
        task_id,
        config: &config,
        src_conn: &src_conn,
        batch_size,
        resume_cursor,
        batch_retries: config.batching.batch_retries.unwrap_or(3),
    };

    // Dispatch by (source, target) driver pair.
    match (src_db, tgt_db) {
        (DbType::MySql, DbType::MySql) => {
            let src = open_mysql_pool(&src_conn, &src_password).await?;
            let tgt = open_mysql_pool(&tgt_conn, &tgt_password).await?;
            etl_mysql_to_mysql(&src, &tgt, ctx).await
        }
        (DbType::Postgres, DbType::Postgres) => {
            let src = open_pg_pool(&src_conn, &src_password).await?;
            let tgt = open_pg_pool(&tgt_conn, &tgt_password).await?;
            etl_pg_to_pg(&src, &tgt, ctx).await
        }
        (DbType::MySql, DbType::Postgres) => {
            let src = open_mysql_pool(&src_conn, &src_password).await?;
            let tgt = open_pg_pool(&tgt_conn, &tgt_password).await?;
            etl_cross(
                SourceKind::MySql(&src),
                TargetKind::Postgres(&tgt),
                ctx,
            )
            .await
        }
        (DbType::Postgres, DbType::MySql) => {
            let src = open_pg_pool(&src_conn, &src_password).await?;
            let tgt = open_mysql_pool(&tgt_conn, &tgt_password).await?;
            etl_cross(
                SourceKind::Postgres(&src),
                TargetKind::MySql(&tgt),
                ctx,
            )
            .await
        }
        // CHANGE: 三期 — ClickHouse 作为目标（HTTP JSONEachRow 写入）。
        // CH 只能是目标，不能是源（sqlx 无 CH 驱动）。
        (DbType::MySql, DbType::ClickHouse) => {
            let src = open_mysql_pool(&src_conn, &src_password).await?;
            let ch = open_clickhouse(&tgt_conn, &tgt_password);
            etl_to_clickhouse(SourceKind::MySql(&src), &ch, ctx).await
        }
        (DbType::Postgres, DbType::ClickHouse) => {
            let src = open_pg_pool(&src_conn, &src_password).await?;
            let ch = open_clickhouse(&tgt_conn, &tgt_password);
            etl_to_clickhouse(SourceKind::Postgres(&src), &ch, ctx).await
        }
        // ClickHouse 作源（不支持，sqlx 无 CH 驱动）。
        (DbType::ClickHouse, _) => {
            Err(anyhow!("clickhouse can only be used as data_sync target, not source"))
        }
        // CHANGE: Doris Stream Load 作为目标（HTTP PUT /api/{db}/{table}/_load）。
        // Doris 只能是目标。
        (DbType::MySql, DbType::Doris) => {
            let src = open_mysql_pool(&src_conn, &src_password).await?;
            let dsl = open_doris_stream_load(&tgt_conn, &tgt_password);
            etl_to_doris_stream_load(SourceKind::MySql(&src), &dsl, ctx).await
        }
        (DbType::Postgres, DbType::Doris) => {
            let src = open_pg_pool(&src_conn, &src_password).await?;
            let dsl = open_doris_stream_load(&tgt_conn, &tgt_password);
            etl_to_doris_stream_load(SourceKind::Postgres(&src), &dsl, ctx).await
        }
        (DbType::Doris, _) => {
            Err(anyhow!("doris can only be used as data_sync target, not source"))
        }
    }
}

/// Everything the batch loop needs that doesn't depend on the source/target
/// driver pair. Bundled so we pass one reference instead of six.
struct LoopCtx<'a> {
    ctrl: &'a SqlitePool,
    task_id: &'a str,
    config: &'a DataSyncTaskConfig,
    src_conn: &'a ConnectionRow,
    batch_size: u64,
    resume_cursor: Option<String>,
    /// Per-batch insert retry count (from `config.batching.batch_retries`, default 3).
    batch_retries: u32,
}

#[derive(sqlx::FromRow)]
struct TaskRow {
    #[allow(dead_code)]
    id: String,
    name: String,
    config: String,
    source_db_id: String,
    target_db_id: Option<String>,
    /// JSON array of notify channels (shared column with drift tasks).
    /// Empty array `[]` = no webhook configured.
    notify_channels: String,
}

#[derive(sqlx::FromRow)]
struct ConnectionRow {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    name: String,
    db_type: String,
    host: String,
    port: i64,
    username: String,
    password_encrypted: String,
    default_database: Option<String>,
}

/// Fixed exponential backoff schedule for batch-insert retries (1s / 4s / 16s).
/// Matches drift::notify's retry cadence for consistency.
const RETRY_BACKOFF_MS: &[u64] = &[1000, 4000, 16000];

/// Retry a batch insert operation up to `max_retries` times with fixed backoff.
///
/// On success returns `Ok(())`; the caller adds the processed count.
/// On exhaustion returns `Err(())`; the caller adds the failed count and the
/// cursor advances (no fatal abort — partial progress is preserved).
///
/// `label` is used for tracing (e.g. "mysql batch insert"). The closure `f`
/// is re-invoked on each retry; inserters are idempotent-safe because the
/// cursor window is unchanged within retries (same rows re-attempted).
async fn retry_batch_insert<F, Fut, T>(
    max_retries: u32,
    label: &str,
    mut f: F,
) -> Result<T, ()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let attempts = max_retries.max(1) as usize;
    for attempt in 1..=attempts {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt == attempts {
                    tracing::warn!(%e, attempt, label, "batch insert exhausted retries");
                    return Err(());
                }
                let backoff = RETRY_BACKOFF_MS
                    .get(attempt - 1)
                    .copied()
                    .unwrap_or(16000);
                tracing::warn!(%e, attempt, backoff_ms = backoff, label, "batch insert failed, retrying");
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            }
        }
    }
    unreachable!()
}

async fn load_connection(pool: &SqlitePool, id: &str) -> Result<ConnectionRow> {
    sqlx::query_as::<_, ConnectionRow>(
        "SELECT id, name, db_type, host, port, username, password_encrypted, default_database
         FROM database_connections WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .context("fetch connection")?
    .ok_or_else(|| anyhow!("connection {id} not found"))
}

/// Supported source/target DB kinds.
/// CHANGE: 三期 — ClickHouse/Doris 仅能作为目标。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DbType {
    MySql,
    Postgres,
    ClickHouse,
    Doris,
}

impl DbType {
    fn from_db_type_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "mysql" => Some(Self::MySql),
            "postgres" | "postgresql" | "pg" => Some(Self::Postgres),
            "clickhouse" => Some(Self::ClickHouse),
            "doris" => Some(Self::Doris),
            _ => None,
        }
    }
}

async fn open_mysql_pool(conn: &ConnectionRow, password: &str) -> Result<sqlx::Pool<sqlx::MySql>> {
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
        .map_err(|e| anyhow!("mysql connect failed: {e}"))
}

async fn open_pg_pool(conn: &ConnectionRow, password: &str) -> Result<sqlx::Pool<sqlx::Postgres>> {
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

/// CHANGE: 三期 — 构造 ClickHouse HTTP 客户端（不开 sqlx pool，CH 走 HTTP）。
/// 连接参数来自 ConnectionRow（host/port/username/password/default_database）。
fn open_clickhouse(conn: &ConnectionRow, password: &str) -> crate::clickhouse::ClickHouseClient {
    crate::clickhouse::ClickHouseClient::new(
        &conn.host,
        conn.port as u16,
        &conn.username,
        password,
        conn.default_database.as_deref().unwrap_or("default"),
    )
}

/// CHANGE: Doris Stream Load — 构造 Doris 客户端。
/// port 应填 BE 的 8040（Stream Load 端口），不是 FE 的 9030。
fn open_doris_stream_load(conn: &ConnectionRow, password: &str) -> crate::doris_stream_load::DorisStreamLoadClient {
    crate::doris_stream_load::DorisStreamLoadClient::new(
        &conn.host,
        conn.port as u16,
        &conn.username,
        password,
        conn.default_database.as_deref().unwrap_or("default"),
    )
}

// ---- batch fetch SQL construction ----

/// Build the time-batched JOIN SELECT. Identifiers are pre-validated.
/// Placeholders are `__P0__` / `__P1__` sentinels rewritten per driver.
fn build_select_sql(cfg: &DataSyncTaskConfig, src_conn: &ConnectionRow, dialect: sql::Dialect) -> String {
    let main_alias = "main";
    let main_table = qualified_main_table(&cfg.source, src_conn, dialect);
    let mut from = format!("FROM {main_table} AS {main_alias}");

    for jt in &cfg.join_tables {
        let alias = jt.effective_alias();
        let jt_table = qualified_join_table(jt, src_conn, dialect);
        // jt.on was validated to the `alias.col = alias.col` shape.
        from.push_str(&format!(" LEFT JOIN {jt_table} AS {alias} ON {}", jt.on));
    }

    let select_list = if cfg.column_mapping.columns.is_empty() {
        "*".to_string()
    } else {
        // CAST every selected column to text + alias it to the target name.
        // This guarantees sqlx can decode every column as String regardless
        // of the source type (INT/DECIMAL/DATETIME/...), which is what the
        // inserters expect. MySQL: CAST(x AS CHAR); PG: x::text.
        cfg.column_mapping
            .columns
            .iter()
            .map(|c| match dialect {
                sql::Dialect::MySql => format!("CAST({} AS CHAR) AS {}", c.source, sql::quote(&c.target, dialect)),
                sql::Dialect::Postgres => format!("{}::text AS {}", c.source, sql::quote(&c.target, dialect)),
                // CH/Doris 不会作为源（sqlx 无其驱动），给回退保证穷尽。
                sql::Dialect::ClickHouse | sql::Dialect::Doris => format!("CAST({} AS CHAR) AS {}", c.source, sql::quote(&c.target, dialect)),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    let time_col = format!("{main_alias}.{}", cfg.batching.time_field);
    format!(
        "SELECT {select_list} {from} WHERE {time_col} >= __P0__ AND {time_col} < __P1__ \
         ORDER BY {time_col} LIMIT {}",
        cfg.batching.batch_size.unwrap_or(10000).max(1)
    )
}

/// `<db>.<table>` for the main table (db optional).
fn qualified_main_table(src: &SourceConfig, conn: &ConnectionRow, dialect: sql::Dialect) -> String {
    let db = src.database.as_deref().or(conn.default_database.as_deref());
    let table = sql::quote(&src.table, dialect);
    match db {
        Some(d) if !d.is_empty() => format!("{}.{}", sql::quote(d, dialect), table),
        _ => table,
    }
}

fn qualified_join_table(jt: &JoinTable, conn: &ConnectionRow, dialect: sql::Dialect) -> String {
    let db = jt.database.as_deref().or(conn.default_database.as_deref());
    let table = sql::quote(&jt.table, dialect);
    match db {
        Some(d) if !d.is_empty() => format!("{}.{}", sql::quote(d, dialect), table),
        _ => table,
    }
}

fn mysql_select(sql: &str) -> String {
    sql.replace("__P0__", "?").replace("__P1__", "?")
}

fn pg_select(sql: &str) -> String {
    sql.replace("__P0__", "$1").replace("__P1__", "$2")
}

// ---- MySQL → MySQL ----

async fn etl_mysql_to_mysql(
    src: &sqlx::Pool<sqlx::MySql>,
    tgt: &sqlx::Pool<sqlx::MySql>,
    ctx: LoopCtx<'_>,
) -> Result<RunOutcome> {
    let cols = ctx.config.column_mapping.columns.clone();
    let raw_sql = build_select_sql(ctx.config, ctx.src_conn, sql::Dialect::MySql);
    let fetch_sql = mysql_select(&raw_sql);
    let (mut cursor, max) = resolve_window_mysql(src, ctx.config, ctx.resume_cursor.clone()).await?;
    maybe_truncate_mysql(tgt, ctx.config, ctx.resume_cursor.is_some()).await;

    let mut processed = 0u64;
    let mut failed = 0u64;
    loop {
        if check_cancel(ctx.ctrl, ctx.task_id).await? {
            return Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: true });
        }
        let next = advance_cursor(&cursor, ctx.batch_size);
        let rows: Vec<sqlx::mysql::MySqlRow> = sqlx::query(&fetch_sql)
            .bind(cursor.clone())
            .bind(next.clone())
            .fetch_all(src)
            .await
            .context("fetch batch (mysql)")?;
        let n = rows.len() as u64;
        if n == 0 {
            if cursor_gt(&next, &max) { break; }
            cursor = next;
            continue;
        }
        match retry_batch_insert(ctx.batch_retries, "mysql batch insert", || {
            insert_batch_mysql(tgt, ctx.config, &rows, &cols)
        }).await {
            Ok(_) => processed += n,
            Err(()) => { failed += n; }
        }
        update_progress(ctx.ctrl, ctx.task_id, &cursor, &max, processed, failed).await?;
        cursor = next;
        if cursor_gt(&cursor, &max) { break; }
    }
    Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: false })
}

// ---- PG → PG ----

async fn etl_pg_to_pg(
    src: &sqlx::Pool<sqlx::Postgres>,
    tgt: &sqlx::Pool<sqlx::Postgres>,
    ctx: LoopCtx<'_>,
) -> Result<RunOutcome> {
    let cols = ctx.config.column_mapping.columns.clone();
    let raw_sql = build_select_sql(ctx.config, ctx.src_conn, sql::Dialect::Postgres);
    let fetch_sql = pg_select(&raw_sql);
    let (mut cursor, max) = resolve_window_pg(src, ctx.config, ctx.resume_cursor.clone()).await?;
    maybe_truncate_pg(tgt, ctx.config, ctx.resume_cursor.is_none()).await;

    let mut processed = 0u64;
    let mut failed = 0u64;
    loop {
        if check_cancel(ctx.ctrl, ctx.task_id).await? {
            return Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: true });
        }
        let next = advance_cursor(&cursor, ctx.batch_size);
        let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(&fetch_sql)
            .bind(cursor.clone())
            .bind(next.clone())
            .fetch_all(src)
            .await
            .context("fetch batch (pg)")?;
        let n = rows.len() as u64;
        if n == 0 {
            if cursor_gt(&next, &max) { break; }
            cursor = next;
            continue;
        }
        match retry_batch_insert(ctx.batch_retries, "pg batch insert", || {
            insert_batch_pg(tgt, ctx.config, &rows, &cols)
        }).await {
            Ok(_) => processed += n,
            Err(()) => { failed += n; }
        }
        update_progress(ctx.ctrl, ctx.task_id, &cursor, &max, processed, failed).await?;
        cursor = next;
        if cursor_gt(&cursor, &max) { break; }
    }
    Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: false })
}

// ---- Cross-driver (via JSON materialisation) ----

enum SourceKind<'a> {
    MySql(&'a sqlx::Pool<sqlx::MySql>),
    Postgres(&'a sqlx::Pool<sqlx::Postgres>),
}

enum TargetKind<'a> {
    MySql(&'a sqlx::Pool<sqlx::MySql>),
    Postgres(&'a sqlx::Pool<sqlx::Postgres>),
}

async fn etl_cross(src: SourceKind<'_>, tgt: TargetKind<'_>, ctx: LoopCtx<'_>) -> Result<RunOutcome> {
    let cols = ctx.config.column_mapping.columns.clone();
    match (src, tgt) {
        (SourceKind::MySql(src), TargetKind::Postgres(tgt)) => {
            let fetch_sql = mysql_select(&build_select_sql(ctx.config, ctx.src_conn, sql::Dialect::MySql));
            let (mut cursor, max) = resolve_window_mysql(src, ctx.config, ctx.resume_cursor.clone()).await?;
            maybe_truncate_pg(tgt, ctx.config, ctx.resume_cursor.is_none()).await;
            let mut processed = 0u64;
            let mut failed = 0u64;
            loop {
                if check_cancel(ctx.ctrl, ctx.task_id).await? {
                    return Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: true });
                }
                let next = advance_cursor(&cursor, ctx.batch_size);
                let rows: Vec<sqlx::mysql::MySqlRow> = sqlx::query(&fetch_sql)
                    .bind(cursor.clone()).bind(next.clone()).fetch_all(src).await?;
                let n = rows.len() as u64;
                if n == 0 { if cursor_gt(&next, &max) { break; } cursor = next; continue; }
                let maps = rows_to_json_mysql(&rows, &cols);
                match retry_batch_insert(ctx.batch_retries, "cross mysql→pg insert", || {
                    insert_json_batch_pg(tgt, ctx.config, &maps, &cols)
                }).await {
                    Ok(_) => processed += n,
                    Err(()) => { failed += n; }
                }
                update_progress(ctx.ctrl, ctx.task_id, &cursor, &max, processed, failed).await?;
                cursor = next;
                if cursor_gt(&cursor, &max) { break; }
            }
            Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: false })
        }
        (SourceKind::Postgres(src), TargetKind::MySql(tgt)) => {
            let fetch_sql = pg_select(&build_select_sql(ctx.config, ctx.src_conn, sql::Dialect::Postgres));
            let (mut cursor, max) = resolve_window_pg(src, ctx.config, ctx.resume_cursor.clone()).await?;
            maybe_truncate_mysql(tgt, ctx.config, ctx.resume_cursor.is_none()).await;
            let mut processed = 0u64;
            let mut failed = 0u64;
            loop {
                if check_cancel(ctx.ctrl, ctx.task_id).await? {
                    return Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: true });
                }
                let next = advance_cursor(&cursor, ctx.batch_size);
                let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(&fetch_sql)
                    .bind(cursor.clone()).bind(next.clone()).fetch_all(src).await?;
                let n = rows.len() as u64;
                if n == 0 { if cursor_gt(&next, &max) { break; } cursor = next; continue; }
                let maps = rows_to_json_pg(&rows, &cols);
                match retry_batch_insert(ctx.batch_retries, "cross pg→mysql insert", || {
                    insert_json_batch_mysql(tgt, ctx.config, &maps, &cols)
                }).await {
                    Ok(_) => processed += n,
                    Err(()) => { failed += n; }
                }
                update_progress(ctx.ctrl, ctx.task_id, &cursor, &max, processed, failed).await?;
                cursor = next;
                if cursor_gt(&cursor, &max) { break; }
            }
            Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: false })
        }
        _ => Err(anyhow!("unsupported source/target combination for cross-driver ETL")),
    }
}

/// CHANGE: 三期 — ETL 到 ClickHouse 目标（HTTP JSONEachRow 写入）。
/// 镜像 etl_cross 的循环结构（cancel + advance_cursor + insert + update_progress），
/// 区别：目标不是 sqlx pool，而是 ClickHouseClient（HTTP）。源仍是 sqlx pool（mysql/pg）。
async fn etl_to_clickhouse(
    src: SourceKind<'_>,
    ch: &crate::clickhouse::ClickHouseClient,
    ctx: LoopCtx<'_>,
) -> Result<RunOutcome> {
    let cols = ctx.config.column_mapping.columns.clone();
    // 按 src 拿 fetch SQL + window
    let (mut cursor, max, fetch_sql) = match src {
        SourceKind::MySql(p) => {
            let sql = mysql_select(&build_select_sql(ctx.config, ctx.src_conn, sql::Dialect::MySql));
            let (c, m) = resolve_window_mysql(p, ctx.config, ctx.resume_cursor.clone()).await?;
            (c, m, sql)
        }
        SourceKind::Postgres(p) => {
            let sql = pg_select(&build_select_sql(ctx.config, ctx.src_conn, sql::Dialect::Postgres));
            let (c, m) = resolve_window_pg(p, ctx.config, ctx.resume_cursor.clone()).await?;
            (c, m, sql)
        }
    };

    maybe_truncate_ch(ch, ctx.config, ctx.resume_cursor.is_some()).await;

    let mut processed = 0u64;
    let mut failed = 0u64;
    loop {
        if check_cancel(ctx.ctrl, ctx.task_id).await? {
            return Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: true });
        }
        let next = advance_cursor(&cursor, ctx.batch_size);
        // 按 src 拉 batch → 转 json::Map
        let maps = match src {
            SourceKind::MySql(p) => {
                let rows: Vec<sqlx::mysql::MySqlRow> = sqlx::query(&fetch_sql)
                    .bind(cursor.clone()).bind(next.clone()).fetch_all(p).await?;
                rows_to_json_mysql(&rows, &cols)
            }
            SourceKind::Postgres(p) => {
                let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(&fetch_sql)
                    .bind(cursor.clone()).bind(next.clone()).fetch_all(p).await?;
                rows_to_json_pg(&rows, &cols)
            }
        };
        let n = maps.len() as u64;
        if n == 0 {
            if cursor_gt(&next, &max) { break; }
            cursor = next;
            continue;
        }
        // 写 ClickHouse（HTTP JSONEachRow）
        match retry_batch_insert(ctx.batch_retries, "clickhouse insert", || {
            ch.insert_batch(&ctx.config.target.table, &maps)
        }).await {
            Ok(written) => processed += written as u64,
            Err(()) => { failed += n; }
        }
        update_progress(ctx.ctrl, ctx.task_id, &cursor, &max, processed, failed).await?;
        cursor = next;
        if cursor_gt(&cursor, &max) { break; }
    }
    Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: false })
}

/// CH 目标的 truncate（HTTP TRUNCATE TABLE）。
async fn maybe_truncate_ch(
    ch: &crate::clickhouse::ClickHouseClient,
    cfg: &DataSyncTaskConfig,
    is_resume: bool,
) {
    if is_resume { return; }
    if matches!(cfg.target_strategy, TargetStrategy::Truncate) {
        let _ = ch.truncate(&cfg.target.table).await;
    }
}

/// CHANGE: Doris Stream Load ETL。镜像 etl_to_clickhouse 的循环结构，
/// 区别：目标用 DorisStreamLoadClient（PUT /api/{db}/{table}/_load）。
async fn etl_to_doris_stream_load(
    src: SourceKind<'_>,
    dsl: &crate::doris_stream_load::DorisStreamLoadClient,
    ctx: LoopCtx<'_>,
) -> Result<RunOutcome> {
    let cols = ctx.config.column_mapping.columns.clone();
    let (mut cursor, max, fetch_sql) = match src {
        SourceKind::MySql(p) => {
            let sql = mysql_select(&build_select_sql(ctx.config, ctx.src_conn, sql::Dialect::MySql));
            let (c, m) = resolve_window_mysql(p, ctx.config, ctx.resume_cursor.clone()).await?;
            (c, m, sql)
        }
        SourceKind::Postgres(p) => {
            let sql = pg_select(&build_select_sql(ctx.config, ctx.src_conn, sql::Dialect::Postgres));
            let (c, m) = resolve_window_pg(p, ctx.config, ctx.resume_cursor.clone()).await?;
            (c, m, sql)
        }
    };

    let mut processed = 0u64;
    let mut failed = 0u64;
    loop {
        if check_cancel(ctx.ctrl, ctx.task_id).await? {
            return Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: true });
        }
        let next = advance_cursor(&cursor, ctx.batch_size);
        let maps = match src {
            SourceKind::MySql(p) => {
                let rows: Vec<sqlx::mysql::MySqlRow> = sqlx::query(&fetch_sql)
                    .bind(cursor.clone()).bind(next.clone()).fetch_all(p).await?;
                rows_to_json_mysql(&rows, &cols)
            }
            SourceKind::Postgres(p) => {
                let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(&fetch_sql)
                    .bind(cursor.clone()).bind(next.clone()).fetch_all(p).await?;
                rows_to_json_pg(&rows, &cols)
            }
        };
        let n = maps.len() as u64;
        if n == 0 {
            if cursor_gt(&next, &max) { break; }
            cursor = next;
            continue;
        }
        match retry_batch_insert(ctx.batch_retries, "doris stream load", || {
            dsl.insert_batch(&ctx.config.target.table, &maps)
        }).await {
            Ok(written) => processed += written as u64,
            Err(()) => { failed += n; }
        }
        update_progress(ctx.ctrl, ctx.task_id, &cursor, &max, processed, failed).await?;
        cursor = next;
        if cursor_gt(&cursor, &max) { break; }
    }
    Ok(RunOutcome { processed_rows: processed, failed_rows: failed, canceled: false })
}

// ---- window probing ----

async fn resolve_window_mysql(
    src: &sqlx::Pool<sqlx::MySql>,
    cfg: &DataSyncTaskConfig,
    resume_cursor: Option<String>,
) -> Result<(String, String)> {
    let q = format!(
        "SELECT CAST(MIN({}) AS CHAR), CAST(MAX({}) AS CHAR) FROM {}",
        sql::quote(&cfg.batching.time_field, sql::Dialect::MySql),
        sql::quote(&cfg.batching.time_field, sql::Dialect::MySql),
        sql::quote(&cfg.source.table, sql::Dialect::MySql)
    );
    let row: (Option<String>, Option<String>) = sqlx::query_as(&q)
        .fetch_one(src)
        .await
        .context("probe MIN/MAX (mysql)")?;
    let min = row.0.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let max = row.1.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let start = resume_cursor.or_else(|| cfg.batching.start.clone()).unwrap_or(min);
    Ok((start, max))
}

async fn resolve_window_pg(
    src: &sqlx::Pool<sqlx::Postgres>,
    cfg: &DataSyncTaskConfig,
    resume_cursor: Option<String>,
) -> Result<(String, String)> {
    let q = format!(
        "SELECT MIN({})::text, MAX({})::text FROM {}",
        sql::quote(&cfg.batching.time_field, sql::Dialect::Postgres),
        sql::quote(&cfg.batching.time_field, sql::Dialect::Postgres),
        sql::quote(&cfg.source.table, sql::Dialect::Postgres)
    );
    let row: (Option<String>, Option<String>) = sqlx::query_as(&q)
        .fetch_one(src)
        .await
        .context("probe MIN/MAX (pg)")?;
    let min = row.0.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let max = row.1.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let start = resume_cursor.or_else(|| cfg.batching.start.clone()).unwrap_or(min);
    Ok((start, max))
}

// ---- cursor / progress helpers ----

/// Compare two cursor strings: strict greater-than. Used for loop-exit:
/// we keep looping while cursor <= max so the batch covering the MAX row
/// is still processed. Needed because cursor (RFC3339 after advance) and
/// max (source-native "YYYY-MM-DD HH:MM:SS") have different string orderings.
fn cursor_gt(a: &str, b: &str) -> bool {
    match (parse_cursor(a), parse_cursor(b)) {
        (Some(x), Some(y)) => x > y,
        _ => a > b,
    }
}

/// Parse a cursor timestamp flexibly. Sources return time in different
/// string formats: MySQL CAST AS CHAR → "2026-08-01 10:00:00"; PG ::text →
/// "2026-08-01 10:00:00.123456"; persisted cursors are RFC3339. Try each.
fn parse_cursor(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // MySQL/PG naive formats: "YYYY-MM-DD HH:MM:SS" or with fractional secs.
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(ndt.and_utc());
    }
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(ndt.and_utc());
    }
    None
}

/// Time-batched cursor advance. We treat `batch_size` as seconds of coverage;
/// the actual row count is bounded by LIMIT, so dense tables simply do more
/// (smaller-window) batches. This keeps source-DB pressure constant.
fn advance_cursor(cursor: &str, batch_size: u64) -> String {
    let Some(parsed) = parse_cursor(cursor) else {
        return cursor.to_string();
    };
    let secs = batch_size.max(1) as i64;
    let next = parsed + chrono::Duration::seconds(secs);
    next.to_rfc3339()
}

async fn check_cancel(ctrl: &SqlitePool, task_id: &str) -> Result<bool> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT cancel_requested FROM data_sync_runs
         WHERE task_id = ?1 AND status = 'running'
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(task_id)
    .fetch_optional(ctrl)
    .await
    .context("poll cancel_requested")?;
    Ok(row.map(|(c,)| c != 0).unwrap_or(false))
}

async fn update_progress(
    ctrl: &SqlitePool,
    task_id: &str,
    cursor: &str,
    max: &str,
    processed: u64,
    failed: u64,
) -> Result<()> {
    let progress = compute_pct(cursor, max);
    sqlx::query(
        "UPDATE data_sync_runs
         SET cursor = ?1, progress = ?2, processed_rows = ?3, failed_rows = ?4
         WHERE task_id = ?5 AND status = 'running'",
    )
    .bind(cursor)
    .bind(progress)
    .bind(processed as i64)
    .bind(failed as i64)
    .bind(task_id)
    .execute(ctrl)
    .await
    .context("update data_sync_runs progress")?;
    Ok(())
}

/// Approximate progress from cursor/max. Accepts RFC3339 or naive
/// "YYYY-MM-DD HH:MM:SS" (source-DB native format). UI feedback only.
fn compute_pct(cursor: &str, max: &str) -> i64 {
    let (Some(c), Some(m)) = (parse_cursor(cursor), parse_cursor(max))
    else { return 0; };
    if m <= c { return 100; }
    let pct = (c.timestamp_millis() as f64 / m.timestamp_millis().max(1) as f64) * 100.0;
    pct.clamp(0.0, 100.0) as i64
}

// ---- truncate guards ----

async fn maybe_truncate_mysql(tgt: &sqlx::Pool<sqlx::MySql>, cfg: &DataSyncTaskConfig, is_resume: bool) {
    if is_resume { return; }
    if matches!(cfg.target_strategy, TargetStrategy::Truncate) {
        let _ = sqlx::query(&format!("TRUNCATE TABLE {}", sql::quote(&cfg.target.table, sql::Dialect::MySql)))
            .execute(tgt)
            .await;
    }
}

async fn maybe_truncate_pg(tgt: &sqlx::Pool<sqlx::Postgres>, cfg: &DataSyncTaskConfig, is_resume: bool) {
    if is_resume { return; }
    if matches!(cfg.target_strategy, TargetStrategy::Truncate) {
        let _ = sqlx::query(&format!("TRUNCATE TABLE {}", sql::quote(&cfg.target.table, sql::Dialect::Postgres)))
            .execute(tgt)
            .await;
    }
}

// ---- batch inserters ----
//
// We use `sqlx::QueryBuilder` to assemble the multi-row INSERT + bind every
// value. QueryBuilder sidesteps the hand-rolled placeholder arithmetic and
// the `Query<DB, Args>` type-parameter trap (the Arguments type isn't the
// database type, and getting it wrong is the E0599 we'd otherwise hit). The
// builder handles MySQL `?` vs PG `$N` automatically via the database's
// `Arguments` impl.

/// All target column names (selected columns + constants), each quoted.
fn target_columns(cfg: &DataSyncTaskConfig, cols: &[ColumnSelect], dialect: sql::Dialect) -> Vec<String> {
    let mut out: Vec<String> = cols.iter().map(|c| sql::quote(&c.target, dialect)).collect();
    for cst in &cfg.column_mapping.constants {
        out.push(sql::quote(&cst.target, dialect));
    }
    out
}

/// Append the ON CONFLICT / ON DUPLICATE KEY tail honouring [`TargetStrategy`].
/// `col_names` are the already-quoted target columns (selected + constants).
fn upsert_tail(cfg: &DataSyncTaskConfig, col_names: &[String], dialect: sql::Dialect) -> Option<String> {
    match &cfg.target_strategy {
        TargetStrategy::Upsert(key) => {
            let qk = sql::quote(key, dialect);
            // MySQL-syntax ON DUPLICATE KEY UPDATE works on MySQL; PG uses
            // ON CONFLICT … DO UPDATE. The caller picks the dialect-specific
            // variant — here we just compute the update list.
            let updates: Vec<String> = col_names.iter()
                .filter(|c| *c != &qk)
                .map(|c| format!("{c}=VALUES({c})"))
                .collect();
            if updates.is_empty() {
                Some(format!("ON DUPLICATE KEY UPDATE {qk}={qk}"))
            } else {
                Some(format!("ON DUPLICATE KEY UPDATE {}", updates.join(", ")))
            }
        }
        _ => None,
    }
}

/// Append a PG ON CONFLICT clause honouring [`TargetStrategy`].
fn upsert_tail_pg(cfg: &DataSyncTaskConfig, col_names: &[String], dialect: sql::Dialect) -> Option<String> {
    match &cfg.target_strategy {
        TargetStrategy::Upsert(key) => {
            let qk = sql::quote(key, dialect);
            let updates: Vec<String> = col_names.iter()
                .filter(|c| *c != &qk)
                .map(|c| format!("{c}=EXCLUDED.{c}"))
                .collect();
            if updates.is_empty() {
                Some(format!("ON CONFLICT ({qk}) DO NOTHING"))
            } else {
                Some(format!("ON CONFLICT ({qk}) DO UPDATE SET {}", updates.join(", ")))
            }
        }
        _ => None,
    }
}

async fn insert_batch_mysql(
    tgt: &sqlx::Pool<sqlx::MySql>,
    cfg: &DataSyncTaskConfig,
    rows: &[sqlx::mysql::MySqlRow],
    cols: &[ColumnSelect],
) -> Result<()> {
    if rows.is_empty() { return Ok(()); }
    let col_names = target_columns(cfg, cols, sql::Dialect::MySql);
    let table = sql::quote(&cfg.target.table, sql::Dialect::MySql);
    let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!("INSERT INTO {table} ("));
    qb.push(col_names.join(", "));
    qb.push(") VALUES ");
    for (ri, r) in rows.iter().enumerate() {
        if ri > 0 { qb.push(", "); }
        qb.push("(");
        for (ci, c) in cols.iter().enumerate() {
            if ci > 0 { qb.push(", "); }
            let v: Option<String> = r.try_get(c.target.as_str()).ok();
            qb.push_bind(v);
        }
        // constants repeat per row
        for (k, cst) in cfg.column_mapping.constants.iter().enumerate() {
            if !cols.is_empty() || k > 0 { qb.push(", "); }
            qb.push_bind(json_value_to_string(&cst.value));
        }
        qb.push(")");
    }
    if let Some(tail) = upsert_tail(cfg, &col_names, sql::Dialect::MySql) { qb.push(" ").push(tail); }
    qb.build().execute(tgt).await.context("mysql batch insert")?;
    Ok(())
}

async fn insert_batch_pg(
    tgt: &sqlx::Pool<sqlx::Postgres>,
    cfg: &DataSyncTaskConfig,
    rows: &[sqlx::postgres::PgRow],
    cols: &[ColumnSelect],
) -> Result<()> {
    if rows.is_empty() { return Ok(()); }
    let col_names = target_columns(cfg, cols, sql::Dialect::Postgres);
    let table = sql::quote(&cfg.target.table, sql::Dialect::Postgres);
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!("INSERT INTO {table} ("));
    qb.push(col_names.join(", "));
    qb.push(") VALUES ");
    for (ri, r) in rows.iter().enumerate() {
        if ri > 0 { qb.push(", "); }
        qb.push("(");
        for (ci, c) in cols.iter().enumerate() {
            if ci > 0 { qb.push(", "); }
            let v: Option<String> = r.try_get(c.target.as_str()).ok();
            qb.push_bind(v);
        }
        for (k, cst) in cfg.column_mapping.constants.iter().enumerate() {
            if !cols.is_empty() || k > 0 { qb.push(", "); }
            qb.push_bind(json_value_to_string(&cst.value));
        }
        qb.push(")");
    }
    if let Some(tail) = upsert_tail_pg(cfg, &col_names, sql::Dialect::Postgres) { qb.push(" ").push(tail); }
    qb.build().execute(tgt).await.context("pg batch insert")?;
    Ok(())
}

// ---- batch inserters (cross-driver via JSON) ----

fn rows_to_json_mysql(rows: &[sqlx::mysql::MySqlRow], cols: &[ColumnSelect]) -> Vec<serde_json::Map<String, serde_json::Value>> {
    rows.iter().map(|r| {
        let mut m = serde_json::Map::new();
        for c in cols {
            let v: Option<String> = r.try_get(c.target.as_str()).ok();
            m.insert(c.target.clone(), serde_json::Value::String(v.unwrap_or_default()));
        }
        m
    }).collect()
}

fn rows_to_json_pg(rows: &[sqlx::postgres::PgRow], cols: &[ColumnSelect]) -> Vec<serde_json::Map<String, serde_json::Value>> {
    rows.iter().map(|r| {
        let mut m = serde_json::Map::new();
        for c in cols {
            let v: Option<String> = r.try_get(c.target.as_str()).ok();
            m.insert(c.target.clone(), serde_json::Value::String(v.unwrap_or_default()));
        }
        m
    }).collect()
}

async fn insert_json_batch_mysql(
    tgt: &sqlx::Pool<sqlx::MySql>,
    cfg: &DataSyncTaskConfig,
    rows: &[serde_json::Map<String, serde_json::Value>],
    cols: &[ColumnSelect],
) -> Result<()> {
    if rows.is_empty() { return Ok(()); }
    let col_names = target_columns(cfg, cols, sql::Dialect::MySql);
    let table = sql::quote(&cfg.target.table, sql::Dialect::MySql);
    let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!("INSERT INTO {table} ("));
    qb.push(col_names.join(", "));
    qb.push(") VALUES ");
    for (ri, r) in rows.iter().enumerate() {
        if ri > 0 { qb.push(", "); }
        qb.push("(");
        for (ci, c) in cols.iter().enumerate() {
            if ci > 0 { qb.push(", "); }
            let v = r.get(&c.target).and_then(|v| v.as_str()).map(String::from);
            qb.push_bind(v);
        }
        for (k, cst) in cfg.column_mapping.constants.iter().enumerate() {
            if !cols.is_empty() || k > 0 { qb.push(", "); }
            qb.push_bind(json_value_to_string(&cst.value));
        }
        qb.push(")");
    }
    if let Some(tail) = upsert_tail(cfg, &col_names, sql::Dialect::MySql) { qb.push(" ").push(tail); }
    qb.build().execute(tgt).await.context("mysql json batch insert")?;
    Ok(())
}

async fn insert_json_batch_pg(
    tgt: &sqlx::Pool<sqlx::Postgres>,
    cfg: &DataSyncTaskConfig,
    rows: &[serde_json::Map<String, serde_json::Value>],
    cols: &[ColumnSelect],
) -> Result<()> {
    if rows.is_empty() { return Ok(()); }
    let col_names = target_columns(cfg, cols, sql::Dialect::Postgres);
    let table = sql::quote(&cfg.target.table, sql::Dialect::Postgres);
    // PG cross-driver fix: source values arrive as strings (MySQL DATETIME/
    // DECIMAL → text). PG prepared-statement params are typed, so binding
    // text for an integer column fails. We embed each value as a quoted
    // string literal followed by `::unknown`, which lets PG infer the target
    // column type per assignment. Values are escaped (doubled single quotes);
    // NULLs become the untyped NULL literal.
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!("INSERT INTO {table} ("));
    qb.push(col_names.join(", "));
    qb.push(") VALUES ");
    for (ri, r) in rows.iter().enumerate() {
        if ri > 0 { qb.push(", "); }
        qb.push("(");
        for (ci, c) in cols.iter().enumerate() {
            if ci > 0 { qb.push(", "); }
            let raw = r.get(&c.target).and_then(|v| v.as_str());
            push_pg_literal(&mut qb, raw);
        }
        for (k, cst) in cfg.column_mapping.constants.iter().enumerate() {
            if !cols.is_empty() || k > 0 { qb.push(", "); }
            push_pg_literal(&mut qb, Some(&json_value_to_string(&cst.value)));
        }
        qb.push(")");
    }
    if let Some(tail) = upsert_tail_pg(cfg, &col_names, sql::Dialect::Postgres) { qb.push(" ").push(tail); }
    qb.build().execute(tgt).await.context("pg json batch insert")?;
    Ok(())
}

/// Push a PG string literal that coerces to the target column type.
/// `Some(v)` → `'v'::unknown` (PG infers type from assignment context);
/// `None` → `NULL`.
fn push_pg_literal(qb: &mut sqlx::QueryBuilder<'_, sqlx::Postgres>, v: Option<&str>) {
    match v {
        Some(s) => {
            let escaped = s.replace('\'', "''");
            qb.push("'").push(escaped).push("'::unknown");
        }
        None => {
            qb.push("NULL");
        }
    }
}

fn json_value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Redact an error before persistence. Surface the category; drop SQL/PII.
fn redact_error(e: &anyhow::Error) -> String {
    let s = e.to_string();
    if s.contains("connect") {
        return "source/target database connection failed".to_string();
    }
    if s.contains("config") || s.contains("identifier") || s.contains("ON clause") {
        return s.chars().take(300).collect();
    }
    if s.contains("not found") {
        return s.chars().take(200).collect();
    }
    "data_sync ETL run failed".to_string()
}
