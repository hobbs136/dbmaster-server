//! ADR-0003 S10 — transaction session store (cross-request, session-pinned).
//!
//! The query gateway (`db_handler::db_query`) is stateless: it opens a fresh
//! `max_connections(1)` pool per request and drops it on return. That cannot
//! hold a transaction open across requests, because the transaction lives on
//! the physical DB connection, which goes away when the pool is dropped.
//!
//! S10 pins one `max_connections(1)` pool *per transaction session* and drives
//! the transaction with SQL text (`START TRANSACTION` / `COMMIT` / `ROLLBACK`).
//! Because the pool has exactly one connection, every `acquire()` on it returns
//! that same physical connection — so the transaction state survives across
//! HTTP requests, as long as the session entry (and its pool) stays in the
//! map. `sqlx::Transaction` is deliberately NOT used: its borrow of a single
//! connection cannot be stored across `await` points in `State`.
//!
//! Sessions are keyed by an unguessable UUID v4. They expire after a TTL of
//! inactivity (see [`DbTxnSessionStore::cleanup_expired`]); on expiry the pool
//! is dropped, which closes the physical connection and the DB rolls back the
//! open transaction as its default behavior. Each session is serialized by a
//! `tokio::Mutex` so concurrent requests on the same session queue instead of
//! dead-locking on the single-connection pool.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use sqlx::Row;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::db_handler::redact;

/// Connection parameters handed to [`DbTxnSessionStore::begin`]. The store does
/// not depend on `DbConnectionRow` (private to `db_handler`) — handlers extract
/// the raw fields so this module stays decoupled from the connection-row shape.
pub struct ConnParams<'a> {
    pub db_type: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub username: &'a str,
    pub password: &'a str,
    pub database: Option<&'a str>,
    /// MySQL charset (e.g. "utf8mb4"). Applied via SET NAMES on the pinned pool.
    pub charset: Option<&'a str>,
    /// MySQL session timezone (e.g. "Asia/Shanghai"). Applied via SET time_zone;
    /// T21 — whether to issue it is decided by the family profile (Doris skips it, unsupported).
    pub timezone: Option<&'a str>,
    /// SQLite only — file path. Ignored by MySQL/PG.
    pub file_path: Option<&'a str>,
}

/// A pinned pool for one DB family. The pool is `max_connections(1)`, so every
/// acquire returns the same physical connection (transaction state persists).
/// T21 — MySQL 族变体携带薄适配 profile（执行模式随成员差异，如 Doris
/// 的 raw_sql 文本协议）。
enum PinnedPool {
    MySql(
        sqlx::Pool<sqlx::MySql>,
        &'static dyn crate::mysql_family::MysqlFamilyHooks,
    ),
    Pg(sqlx::Pool<sqlx::Postgres>),
    Sqlite(sqlx::SqlitePool),
}

impl PinnedPool {
    /// The DB-family tag, for logging / error messages.
    fn db_type(&self) -> &'static str {
        match self {
            PinnedPool::MySql(_, profile) => profile.name(),
            PinnedPool::Pg(_) => "postgres",
            PinnedPool::Sqlite(_) => "sqlite",
        }
    }
}

/// One live transaction session: a pinned pool + a serialization lock + the
/// bookkeeping the TTL sweeper needs.
struct TxnSession {
    pool: PinnedPool,
    /// Serializes acquires on this session's single-connection pool. Held only
    /// for the duration of one statement; never across I/O from the caller.
    lock: Mutex<()>,
    /// When the session was opened. Not yet surfaced over HTTP but kept for
    /// diagnostics / future TTL tuning; silences the dead-code lint.
    #[allow(dead_code)]
    created_at: Instant,
    last_used: Mutex<Instant>,
}

/// Concurrent map of `session_id → TxnSession`. Shared via `Arc` and injected
/// into the transaction handlers through axum's `Extension` layer (keeps
/// `AppState` in the `core` crate free of sqlx business types).
#[derive(Clone)]
pub struct DbTxnSessionStore {
    sessions: Arc<DashMap<String, TxnSession>>,
}

impl DbTxnSessionStore {
    pub fn new() -> Self {
        Self { sessions: Arc::new(DashMap::new()) }
    }

    /// Open a pinned pool, emit the DB-family BEGIN statement, register the
    /// session, and return its id. The caller's plaintext password is dropped
    /// at the end of this function (the pool has already completed its
    /// handshake) — it is never cached in the session.
    pub async fn begin(&self, params: ConnParams<'_>) -> Result<String, String> {
        let pool = open_pinned_pool(params).await?;
        // Emit the BEGIN statement on the freshly-opened connection.
        let begin_sql = begin_sql_for(pool.db_type());
        execute_control(&pool, &begin_sql).await.map_err(|e| {
            // pool drops here on failure, closing the connection.
            redact(&format!("begin failed: {e}"))
        })?;
        let session_id = Uuid::new_v4().to_string();
        let now = Instant::now();
        self.sessions.insert(
            session_id.clone(),
            TxnSession {
                pool,
                lock: Mutex::new(()),
                created_at: now,
                last_used: Mutex::new(now),
            },
        );
        Ok(session_id)
    }

    /// Run a SQL statement inside an existing transaction session. SELECT-like
    /// statements return `{columns, rows}`; otherwise `{affectedRows}`. Mirrors
    /// the shape of the stateless `db_query` result so the client needs no
    /// special-casing.
    pub async fn execute_in_txn(
        &self,
        session_id: &str,
        sql: &str,
        limit: usize,
        is_select: bool,
    ) -> Result<serde_json::Value, String> {
        let entry = self
            .sessions
            .get(session_id)
            .ok_or_else(|| "transaction session not found (expired or rolled back)".to_string())?;
        // Hold the session lock for the whole statement so a concurrent request
        // on the same session waits rather than dead-locking on the 1-conn pool.
        let _guard = entry.lock.lock().await;
        let pool = &entry.pool;
        let mut result = match pool {
            PinnedPool::MySql(p, profile) => {
                crate::db_handler::execute_sql_mysql(
                    p,
                    sql,
                    limit,
                    is_select,
                    profile.catalog_mode(),
                )
                .await
                .map_err(axum_err_to_string)?
            }
            PinnedPool::Pg(p) => {
                crate::db_handler::execute_sql_pg(p, sql, limit, is_select)
                    .await
                    .map_err(axum_err_to_string)?
            }
            PinnedPool::Sqlite(p) => {
                crate::db_handler::execute_sql_sqlite(p, sql, limit, is_select)
                    .await
                    .map_err(axum_err_to_string)?
            }
        };
        // S8 收尾: for MySQL/Doris, expose the pinned connection's thread id so
        // the client can KILL a long-running statement inside the transaction
        // (the local client connection's CONNECTION_ID() is a different session).
        // The pool is max_connections(1), so this hits the same physical connection
        // that just ran the user SQL — the id is valid until the session closes.
        if let PinnedPool::MySql(p, profile) = pool {
            // T21 — 探测语句同按族执行模式（Doris raw_sql）。
            if let Ok(rows) = crate::mysql_family::fetch_all_by_mode(
                p,
                profile.catalog_mode(),
                "SELECT CONNECTION_ID()",
                None,
            )
            .await
            {
                if let Some(row) = rows.first() {
                    if let Ok(tid) = row.try_get::<i64, _>(0) {
                        if let Some(obj) = result.as_object_mut() {
                            obj.insert("threadId".to_string(), serde_json::json!(tid));
                        }
                    }
                }
            }
            // best-effort: CONNECTION_ID failure is non-fatal (KILL falls back)
        }
        // Refresh last_used after a successful statement.
        *entry.last_used.lock().await = Instant::now();
        Ok(result)
    }

    /// COMMIT the transaction and drop the session (closing the connection).
    pub async fn commit(&self, session_id: &str) -> Result<(), String> {
        self.finish(session_id, "COMMIT").await
    }

    /// ROLLBACK the transaction and drop the session. Used by both the explicit
    /// rollback endpoint and the TTL sweeper.
    pub async fn rollback(&self, session_id: &str) -> Result<(), String> {
        self.finish(session_id, "ROLLBACK").await
    }

    async fn finish(&self, session_id: &str, sql: &str) -> Result<(), String> {
        // Remove first so the session lock is the only one guarding the pool —
        // a concurrent request that already holds the lock will complete, but
        // no new request can grab the entry once it's removed. If the control
        // statement fails the connection is still dropped (pool falls out of
        // scope), and the DB rolls back on its own.
        let (_id, session) = match self.sessions.remove(session_id) {
            Some(removed) => removed,
            None => return Err("transaction session not found".to_string()),
        };
        let _guard = session.lock.lock().await;
        // Best-effort: a failure here still drops the pool (rollback-by-close).
        let _ = execute_control(&session.pool, sql).await;
        Ok(())
    }

    /// Sweep sessions idle longer than `ttl`, rolling each back. Returns the
    /// number of sessions reclaimed. Intended to be called on a timer by the
    /// TTL task set up in `lib.rs`.
    pub async fn cleanup_expired(&self, ttl: Duration) -> usize {
        // Collect candidates under short-lived borrows; remove & rollback
        // without holding a dashmap read guard across an await.
        let now = Instant::now();
        let mut victims: Vec<(String, Instant)> = Vec::new();
        for entry in self.sessions.iter() {
            let last = *entry.last_used.lock().await;
            if now.duration_since(last) > ttl {
                victims.push((entry.key().clone(), last));
            }
        }
        let mut reclaimed = 0;
        for (id, _last) in victims {
            // remove_if ensures we only reclaim sessions still idle past ttl
            // (a session touched between the scan and here is left alone).
            let removed = self
                .sessions
                .remove_if(&id, |_, session| {
                    // Synchronous check on last_used — try_lock avoids blocking
                    // the sweeper if a statement is mid-flight; if locked, the
                    // session is active, skip it.
                    session.last_used.try_lock().map_or(false, |l| {
                        now.duration_since(*l) > ttl
                    })
                });
            if let Some((_id, session)) = removed {
                reclaimed += 1;
                let _ = execute_control(&session.pool, "ROLLBACK").await;
                // pool drops here, closing the connection.
            }
        }
        reclaimed
    }

    /// Snapshot of live session ids + their last-used instant, for diagnostics
    /// and tests. Not exposed over HTTP.
    pub async fn snapshot(&self) -> HashMap<String, Instant> {
        let mut out = HashMap::new();
        for entry in self.sessions.iter() {
            out.insert(entry.key().clone(), *entry.last_used.lock().await);
        }
        out
    }

    /// Number of live sessions (for tests / metrics).
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl Default for DbTxnSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── pool opening (mirrors db_handler::open_*, kept here so this module owns
//     the pinned-pool lifecycle without reaching into db_handler privates) ──

async fn open_pinned_pool(params: ConnParams<'_>) -> Result<PinnedPool, String> {
    // T21 — MySQL 协议族经薄适配注册表分发（mysql/doris 及后续成员一处
    // 注册即支持 txn；能力位 supports_transactions 留给不适配事务的成员）。
    if let Some(profile) = crate::mysql_family::mysql_family_for(params.db_type) {
        if !profile.supports_transactions() {
            return Err(format!("transactions unsupported for db_type '{}'", params.db_type));
        }
        return open_mysql_pinned(params, profile)
            .await
            .map(|p| PinnedPool::MySql(p, profile));
    }
    match params.db_type {
        "postgres" | "postgresql" => open_pg_pinned(params)
            .await
            .map(PinnedPool::Pg),
        "sqlite" => open_sqlite_pinned(params)
            .await
            .map(PinnedPool::Sqlite),
        other => Err(format!("transactions unsupported for db_type '{other}'")),
    }
}

async fn open_mysql_pinned(
    p: ConnParams<'_>,
    profile: &'static dyn crate::mysql_family::MysqlFamilyHooks,
) -> Result<sqlx::Pool<sqlx::MySql>, String> {
    use sqlx::mysql::MySqlConnectOptions;
    let mut opts = MySqlConnectOptions::new()
        .host(p.host)
        .port(p.port)
        .username(p.username)
        .password(p.password);
    if let Some(db) = p.database {
        if !db.is_empty() {
            opts = opts.database(db);
        }
    }
    // T21 — 握手经族 profile（Doris 的 sql_mode workaround 与 open_mysql_db
    // 同源，pinned 池不再绕过）。T23 — 空密码不下发（sqlx 对空串仍产生
    // 非空 scramble，无密码用户会被拒；同 db_handler::mysql_connect_options）。
    let opts = if p.password.is_empty() { opts } else { opts.password(p.password) };
    let opts = profile.handshake(opts);
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(|e| redact(&format!("mysql connect: {e}")))?;
    crate::db_handler::apply_mysql_session(&pool, p.charset, p.timezone, p.db_type).await;
    Ok(pool)
}

async fn open_pg_pinned(p: ConnParams<'_>) -> Result<sqlx::Pool<sqlx::Postgres>, String> {
    use sqlx::postgres::PgConnectOptions;
    let mut opts = PgConnectOptions::new()
        .host(p.host)
        .port(p.port)
        .username(p.username)
        .password(p.password);
    let db = p.database.unwrap_or("postgres");
    opts = opts.database(db);
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(|e| redact(&format!("pg connect: {e}")))
}

async fn open_sqlite_pinned(p: ConnParams<'_>) -> Result<sqlx::SqlitePool, String> {
    let path = p.file_path.ok_or_else(|| {
        "sqlite transaction missing file_path".to_string()
    })?;
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .read_only(false)
        .create_if_missing(false);
    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(|e| redact(&format!("sqlite connect: {e}")))
}

/// The BEGIN statement for each DB family.
fn begin_sql_for(db_type: &str) -> String {
    // T21 — MySQL 协议族（含 Doris 及后续薄适配成员）统一 START TRANSACTION。
    if crate::mysql_family::mysql_family_for(db_type).is_some() {
        return "START TRANSACTION".to_string();
    }
    match db_type {
        "postgres" | "postgresql" => "BEGIN".to_string(),
        "sqlite" => "BEGIN TRANSACTION".to_string(),
        other => format!("/* unsupported: {other} */ START TRANSACTION"),
    }
}

/// Execute a transaction-control statement (BEGIN/COMMIT/ROLLBACK) on the
/// pinned pool. No result set is expected.
async fn execute_control(pool: &PinnedPool, sql: &str) -> Result<(), String> {
    match pool {
        // T21 — 控制语句同按族执行模式（Doris raw_sql 文本协议）。
        PinnedPool::MySql(p, profile) => {
            crate::mysql_family::execute_by_mode(p, profile.catalog_mode(), sql)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())?;
        }
        PinnedPool::Pg(p) => {
            sqlx::query(sql).execute(p).await.map_err(|e| e.to_string())?;
        }
        PinnedPool::Sqlite(p) => {
            sqlx::query(sql).execute(p).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Extract a human-readable message from the `(StatusCode, Json<Value>)` error
/// tuple returned by the `execute_sql_*` helpers. The JSON envelope is
/// `{"ok":false,"error":{"code","message"}}`; we pull `message` (already
/// redacted at the source) and re-redact defensively.
fn axum_err_to_string(
    err: (axum::http::StatusCode, axum::Json<serde_json::Value>),
) -> String {
    let (_status, body) = err;
    let msg = body
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("query execution failed");
    redact(msg)
}
