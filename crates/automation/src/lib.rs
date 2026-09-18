//! dbmaster-automation — Scheduled data sync, health checks, slow query reports.
//!
//! Models and handlers for the automation engine: cron-scheduled tasks,
//! database connections, DDL approvals, and team query library.

// CHANGE: ADR-0001 §4.8 D8 — credential encryption module.
pub mod credential;
pub mod model;
pub mod handler;
pub mod db_handler;
// T21 — MySQL 协议族薄适配层（hook 面 + db_type 注册表；Doris 首个子类，
// T22-T25 的 OceanBase/TiDB/StarRocks/MariaDB 按同模板接入）。
pub(crate) mod mysql_family;
// T06 — 富元数据 API（MCP 元数据工具与网关 API v1 的同源后端）。
pub mod metadata;
// T07 — MCP read_query 执行后端（复用 DbBackend 路径 + 墙钟超时）。
pub mod read_query;
// T27 — 网关 API v1 流式查询执行后端（SSE 位置数组行 + 取消/超时/行限）。
pub mod stream_query;
// T28 — SQL Server（TDS/tiberius）后端基建：连接/解码/类型格式化，
// 由 db_handler / metadata / stream_query 三处消费（同源纪律）。
pub mod sqlserver;
// T29 非 SQL 批次（B1，ADR-0006）— MongoDB 网关腿基建：集群 extra 解析 +
// ClientOptions 组装（凭据分离注入）+ runCommand/游标展平 + BSON↔JSON，
// 由 db_handler / metadata / stream_query 三处消费（同源纪律）。
pub mod mongo;
// T29 非 SQL 批次（B3，ADR-0006）— Redis 网关腿基建：凭据分离连接/db 路由 +
// 命令分类（ACL CAT 缓存 + 静态表兜底）+ RESP→JSON/语义列展平 + PubSub
// 订阅连接，由 metadata / stream_query / gateway 订阅端点消费。模块名避用
// `redis`（防与 redis crate 路径互遮）。
pub mod redis_leg;
// T29 TDengine 批次 — taosAdapter REST 通道腿基建：执行器（URL 组装 +
// Basic auth + 超时）+ 写语句静态分类 + 响应解析（查询/写/错误三形状），
// 由 db_handler / metadata / stream_query 三处消费（同源纪律）。
pub mod tdengine_leg;
// S10 — transaction session store (cross-request, session-pinned pools).
pub mod txn;
// 网关网络层批次（2026-08-29）— extra 网络开关（useTls/tlsInsecure/
// tunneled）的统一解析（crate 内消费）。
pub(crate) mod net_flags;
// 网络层批次 — server 侧 SSH 隧道：wire 配置 / 秘密存储形态 / 进程级隧道
// 管理器，由 metadata load_connection 收口 + 网关注册/测试 handler 消费。
pub mod ssh;
// 网络层批次 — SSH 隧道 + TLS 透传的真网络集成验证（进程内 SSH/TLS 桩
// + 真实 Redis；目标不可达时 SKIP，离线 cargo test 恒绿）。
#[cfg(test)]
mod gw_net_e2e;
// S8b prep — MySQL script splitter for the admin/script endpoint.
pub mod sql_split;
// reports-M1（#29）— 慢查询采样：digest 归一化 + 进程级 Recorder（旁路写入）
// + retention 轮转。捕获点全集与显式排除清单见模块文档。
pub mod query_stats;
// reports-M2（#29）— 周报 writer：聚合 query_stats 生成 slow_query_weekly
// 报告行（content_version 1）+ 手动触发生成端点 + 周期 ticker。
pub mod report_writer;
// reports-M3（#29）— 原生慢查源采集器（Redis SLOWLOG / MySQL slow_log 表）
// → query_stats（source='db_native:*'）+ 游标持久化 + 每小时 ticker。
pub mod native_collector;

// CHANGE: ADR-0002 v1-C-1 — Claims auth + Arc<Config> plumbing for the
// automation router. Config must reach request extensions so the Claims
// extractor (dbmaster_core::auth::middleware) can verify access tokens.
use std::sync::Arc;
use std::time::Duration;

use axum::{middleware, routing::{delete, get, patch, post, put}, Extension, Router};
use dbmaster_core::config::Config;
use dbmaster_core::server::AppState;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// ── Scheduled Task ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScheduledTask {
    pub id: String,
    pub name: String,
    pub task_type: String,
    pub cron_expr: String,
    pub config: String, // JSON
    pub source_db_id: String,
    pub target_db_id: Option<String>,
    pub notify_channels: String, // JSON array
    pub enabled: bool,
    pub last_run_at: Option<String>,
    pub last_status: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTaskRequest {
    pub name: String,
    pub task_type: String,
    pub cron_expr: String,
    pub config: serde_json::Value,
    pub source_db_id: String,
    pub target_db_id: Option<String>,
    pub notify_channels: Option<Vec<String>>,
}

// ── Database Connection ──

// CHANGE: ADR-0002 §4.2.1 / Phase E — `kind` discriminator on
// database_connections. Defaults to "collab" for back-compat with existing
// clients that don't send the field; new source-drift connections set
// "source_drift" and get canary-checked at create time (see handler.rs).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DatabaseConnection {
    pub id: String,
    pub name: String,
    pub db_type: String,
    pub host: String,
    pub port: i64,
    pub username: String,
    pub password_encrypted: String,
    pub default_database: Option<String>,
    pub ssh_enabled: bool,
    pub ssh_host: Option<String>,
    pub ssh_port: Option<i64>,
    pub team_id: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub kind: String,
    /// ADR-0003 第一阶段 — SQLite 源库文件路径。其他 db_type 为 None。
    pub file_path: Option<String>,
    // extended client-connection fields (migration 008).
    // These mirror the Flutter DbServer so migrated connections round-trip
    // without losing SSL/timeout/charset/environment/group/extra config.
    pub use_ssl: bool,
    pub timeout_seconds: i64,
    pub auto_reconnect: bool,
    pub charset: Option<String>,
    pub timezone: Option<String>,
    pub environment: Option<String>,
    pub read_only: bool,
    pub group_id: Option<String>,
    /// Vendor-specific options (MongoDB cluster config, Redis auth mode) as a
    /// JSON blob. Consumers decode on read.
    pub extra: Option<String>,
    // full SSH credentials (002 only carried enabled/
    // host/port). Encrypted with the same AES-256-GCM key as password.
    pub ssh_username: Option<String>,
    pub ssh_auth_mode: Option<String>,
    pub ssh_password_encrypted: Option<String>,
    pub ssh_private_key_encrypted: Option<String>,
    pub ssh_passphrase_encrypted: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateConnectionRequest {
    pub name: String,
    pub db_type: String,
    pub host: String,
    pub port: i64,
    pub username: String,
    pub password: String,
    pub default_database: Option<String>,
    #[serde(default)]
    pub ssh_enabled: bool,
    pub ssh_host: Option<String>,
    pub ssh_port: Option<i64>,
    /// ADR-0002 §4.2.1 — "collab" | "source_drift". None ⇒ "collab"
    #[serde(default)]
    pub kind: Option<String>,
    /// ADR-0003 第一阶段 — SQLite 源库的文件路径。其他 db_type 为 None。
    #[serde(default)]
    pub file_path: Option<String>,
    // extended client-connection fields. All optional /
    // defaulted so existing callers (drift source-drift creates) keep working.
    #[serde(default)]
    pub use_ssl: bool,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: i64,
    #[serde(default)]
    pub auto_reconnect: bool,
    pub charset: Option<String>,
    pub timezone: Option<String>,
    pub environment: Option<String>,
    #[serde(default)]
    pub read_only: bool,
    pub group_id: Option<String>,
    /// JSON-encoded vendor-specific options. Stored verbatim.
    pub extra: Option<String>,
    // SSH credentials (plaintext in the request body; encrypted server-side).
    pub ssh_username: Option<String>,
    /// "password" | "privateKey".
    pub ssh_auth_mode: Option<String>,
    pub ssh_password: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_passphrase: Option<String>,
}

/// Default for the serde-derived `timeout_seconds` field. Mirrors migration
/// 008's column default (30s) so a create without the field matches the
/// DB-level default exactly.
// serde can't read the SQL default; spell it out.
fn default_timeout_seconds() -> i64 {
    30
}

/// U05 (#32) — partial update for `PUT /api/connections/:id`.
///
/// All fields optional; omitted fields keep their stored values. `password` is
/// only re-encrypted when a non-empty value is supplied (None/empty = keep the
/// stored ciphertext) so the edit form can omit it. In-place update by design:
/// delete+recreate would mint a new id and CASCADE-delete every task whose
/// `source_db_id` points at the old row (SQLite FK, migration 002).
#[derive(Debug, Deserialize)]
pub struct UpdateConnectionRequest {
    pub name: Option<String>,
    pub db_type: Option<String>,
    pub host: Option<String>,
    pub port: Option<i64>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub default_database: Option<String>,
    pub file_path: Option<String>,
    pub use_ssl: Option<bool>,
    pub read_only: Option<bool>,
    pub timeout_seconds: Option<i64>,
    pub charset: Option<String>,
    pub timezone: Option<String>,
    pub environment: Option<String>,
}

// ── DDL Approval ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DdlApproval {
    pub id: String,
    pub submitter_id: String,
    pub ddl_sql: String,
    pub target_db_id: String,
    pub reviewer_id: Option<String>,
    pub status: String,
    pub created_at: String,
    pub resolved_at: Option<String>,
    /// Migration 009 — execution tracking for the approve-and-execute flow.
    /// `exec_status` mirrors `status` once approve is claimed ('pending' →
    /// 'executing' → 'approved'/'failed'); `exec_error` carries the redacted
    /// target-side error when the DDL execution failed (U10: surfaced to the
    /// client via GET /api/approvals so failures are more than the word
    /// "failed"). Option + serde default keeps old wire payloads decodable.
    #[serde(default)]
    pub exec_status: Option<String>,
    #[serde(default)]
    pub executed_at: Option<String>,
    #[serde(default)]
    pub exec_error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitApprovalRequest {
    pub ddl_sql: String,
    pub target_db_id: String,
}

// ── Saved Query ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SavedQuery {
    pub id: String,
    pub title: String,
    pub sql_text: String,
    pub tags: String, // JSON array
    pub workspace_id: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SaveQueryRequest {
    pub title: String,
    pub sql_text: String,
    pub tags: Vec<String>,
}

/// Query string for `GET /api/queries`. All fields optional:
/// - `tag` — exact-match a tag (tags column is a JSON array string like
///   `["foo","bar"]`; we filter with SQL `LIKE '%"tag"%'`).
/// - `q` — case-insensitive substring search on title + sql_text.
/// - `limit` — server-clamped (default 100, max 500).
// CHANGE: #4 Saved Queries 只写不读 — adds the read side (list/get/delete)
// alongside the existing INSERT (save_query). README promised "save, search,
// tag"; this delivers search+tag+list.
#[derive(Debug, Deserialize)]
pub struct SavedQueryListQuery {
    pub tag: Option<String>,
    pub q: Option<String>,
    pub limit: Option<i64>,
}

// ── Report ──

/// reports 表行（migration 017 起 task_id 可空——系统级周报不隶属任务）。
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Report {
    pub id: String,
    pub task_id: Option<String>,
    pub report_type: String,
    pub title: String,
    pub content: String, // JSON（本体携带 content_version）
    pub generated_at: String,
}

// ── Drift: run history + schema snapshots (read views over Phase E tables) ──
// CHANGE: Phase F desktop UI — expose the per-run trail + snapshot chain the
// drift runner started writing in Phase E (migration 005). Read-only by design;
// no gate, mirroring list_reports / list_approvals (Phase A "visible-but-locked"
// policy). Column types/names mirror migrations/005_drift_v1.sql exactly.

/// One row of `task_run_history`. The drift runner appends one row per
/// scheduler tick or manual run (Phase E). `summary` / `error` are JSON or
/// TEXT; passed through verbatim — the desktop formats them.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TaskRunHistory {
    pub id: String,
    pub task_id: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub summary: Option<String>,
    pub triggered_by: String,
}

/// Full schema snapshot row, including the (potentially large) `schema_json`.
/// Returned only by the single-snapshot GET; list responses use
/// [`SchemaSnapshotMeta`] to keep payload sizes bounded.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SchemaSnapshot {
    pub id: String,
    pub connection_id: String,
    pub captured_at: String,
    pub schema_hash: String,
    pub schema_json: String,
    pub prior_hash: Option<String>,
    pub task_id: Option<String>,
    pub change_count: i64,
}

/// Metadata-only projection of [`SchemaSnapshot`]: omits `schema_json`, which
/// can be tens of KB to MB for wide schemas. List endpoints return this; the
/// desktop fetches the full payload lazily via `GET /api/snapshots/:id` when
/// the user actually opens a diff.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SchemaSnapshotMeta {
    pub id: String,
    pub connection_id: String,
    pub captured_at: String,
    pub schema_hash: String,
    pub prior_hash: Option<String>,
    pub task_id: Option<String>,
    pub change_count: i64,
}

/// Query string for `GET /api/run-history`. `task_id` is required (list-by-task
/// semantic); `limit` is optional with a server-side default + cap.
#[derive(Debug, Deserialize)]
pub struct RunHistoryQuery {
    pub task_id: String,
    pub limit: Option<i64>,
}

/// Query string for `GET /api/snapshots`. `connection_id` is required;
/// `limit` is optional with a server-side default + cap.
#[derive(Debug, Deserialize)]
pub struct SnapshotListQuery {
    pub connection_id: String,
    pub limit: Option<i64>,
}

/// A `health_check_results` row (ADR-0004 §2.4). Exposed for the read-only
/// `GET /api/health-results` endpoint; the health_check runner is the only
/// writer. `metrics_summary` + `alert_changes` are opaque JSON strings
/// (clients parse them as JSON; the server does not interpret them here).
/// `error` carries the redacted failure reason on `status='failed'` rows
/// (migration 014); NULL on success/partial/legacy rows.
// CHANGE: ADR-0004 §5 / M5 T29 — read model for health-check history.
#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct HealthCheckResult {
    pub id: String,
    pub task_id: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub metrics_summary: String,
    pub alert_changes: String,
    pub triggered_by: String,
    pub error: Option<String>,
}

/// Query string for `GET /api/health-results`. `task_id` is required;
/// `limit` is optional with a server-side default + cap.
#[derive(Debug, Deserialize)]
pub struct HealthResultsQuery {
    pub task_id: String,
    pub limit: Option<i64>,
}

// ── Task execution trait ──

/// Implemented by each automation service.
#[async_trait::async_trait]
pub trait TaskExecutor: Send + Sync {
    async fn execute(&self, task: &ScheduledTask) -> Result<String, String>;
}

// CHANGE: ADR-0001 §7.1 — automation owns its routes to break the core↔automation
// dependency cycle. The binary crate merges this Router with core's.
/// All automation-engine HTTP routes, bound to the given [`AppState`].
///
/// Returns a stateless `Router` (state already bound); safe to `.merge()` into
/// the final app Router.
// CHANGE: ADR-0002 v1-C-1 — every automation route is now behind Claims auth.
/// `Arc<Config>` is injected into request extensions via a layer so the
/// `Claims` extractor (`dbmaster_core::auth::middleware`) can verify access
/// tokens. Mirrors the core router's pattern in `core/src/server/router.rs`.
pub fn routes(state: AppState) -> Router {
    let config_for_extensions: Arc<Config> = state.config.clone();
    // S10 — transaction session store, shared across the 4 txn routes via
    // Extension. Spawn a TTL sweeper that rolls back idle sessions (default
    // 5 min inactivity), so a client that never COMMITs can't leak a pinned
    // connection. The task is best-effort and self-terminates with the runtime.
    let txn_store: Arc<txn::DbTxnSessionStore> = Arc::new(txn::DbTxnSessionStore::new());
    {
        let sweeper_store = txn_store.clone();
        tokio::spawn(async move {
            let ttl = Duration::from_secs(5 * 60);
            let interval = Duration::from_secs(60);
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip the immediate first tick
            loop {
                ticker.tick().await;
                let reclaimed = sweeper_store.cleanup_expired(ttl).await;
                if reclaimed > 0 {
                    tracing::info!(
                        reclaimed,
                        "txn session TTL sweeper rolled back idle sessions"
                    );
                }
            }
        });
    }
    Router::new()
        // ── Connections ──
        .route("/api/connections", get(handler::list_connections))
        .route("/api/connections", post(handler::create_connection))
        .route("/api/connections/:id", put(handler::update_connection))
        .route("/api/connections/:id", delete(handler::delete_connection))
        // plaintext credential retrieval (embedded only;
        // the handler enforces state.embedded_mode). Lets the desktop client
        // open local DB connections from server-stored credentials while it
        // still uses its own adapters (pre-S4).
        .route("/api/connections/:id/credential", get(handler::get_connection_credential))
        // ── Tasks ──
        .route("/api/tasks", get(handler::list_tasks))
        .route("/api/tasks", post(handler::create_task))
        .route("/api/tasks/:id/run", post(handler::run_task_now))
        .route("/api/tasks/:id", delete(handler::delete_task))
        // CHANGE: data-sync 一期 — task enable/disable (pause cron) and
        // cancel an in-flight data_sync run. Reads stay un-gated (visible-
        // but-locked); mutations call gate_blocked like other writes.
        .route("/api/tasks/:id", patch(handler::update_task))
        .route("/api/tasks/:id/cancel", post(handler::cancel_task))
        .route("/api/tasks/:id/data-sync-runs", get(handler::list_data_sync_runs))
        // ── DDL Approvals ──
        .route("/api/approvals", get(handler::list_approvals))
        .route("/api/approvals", post(handler::submit_approval))
        .route("/api/approvals/:id/approve", post(handler::approve_approval))
        .route("/api/approvals/:id/reject", post(handler::reject_approval))
        // ── Saved Queries ──
        // CHANGE: #4 — adds list (with tag/q filter) / get / delete alongside
        // the existing POST. README promised "save, search, tag"; the read side
        // is now wired (writes have always worked).
        .route("/api/queries", get(handler::list_saved_queries))
        .route("/api/queries", post(handler::save_query))
        .route("/api/queries/:id", get(handler::get_saved_query))
        .route("/api/queries/:id", delete(handler::delete_saved_query))
// ── Reports ──
.route("/api/reports", get(handler::list_reports))
.route("/api/reports/:id", get(handler::get_report))
// reports-M2（#29）— 手动生成本期周报（mutation → Gated 门；幂等）。
.route("/api/reports/generate", post(handler::generate_report))
// reports-M1（#29）— 慢查询采样读面（migration 016）。读端点不做
// entitlement gate（对齐 reports/run-history 的 visible-but-locked 策略）。
.route("/api/query-stats/summary", get(handler::query_stats_summary))
.route("/api/query-stats", get(handler::query_stats_list))
        // CHANGE: Phase F — drift read endpoints. Read-only: no gate, mirrors
        // list_reports policy. Auth still enforced by the Claims layer above
        // (every route in this router sits behind the middleware::from_fn that
        // injects Arc<Config> for token verification).
        .route("/api/run-history", get(handler::list_run_history))
        .route("/api/snapshots", get(handler::list_snapshots))
        .route("/api/snapshots/:id", get(handler::get_snapshot))
        // CHANGE: ADR-0004 §5 — health_check read endpoint (read-only, no gate,
        // mirrors run-history/snapshots policy).
        .route("/api/health-results", get(handler::list_health_results))
        // ADR-0003 第一阶段 — 通用 DB 操作端点（客户端经 server API 操作数据库）。
        .route("/api/db/:conn_id/databases", get(db_handler::db_list_databases))
        .route("/api/db/:conn_id/tables", get(db_handler::db_list_tables))
        .route("/api/db/:conn_id/columns", get(db_handler::db_list_columns))
        // extended browse endpoints (schema objects +
        // indexes/foreign keys) so the client sidebar tree can route through
        // the gateway. Names only; full metadata is a later refinement.
        .route("/api/db/:conn_id/views", get(db_handler::db_list_views))
        .route("/api/db/:conn_id/procedures", get(db_handler::db_list_procedures))
        .route("/api/db/:conn_id/functions", get(db_handler::db_list_functions))
        .route("/api/db/:conn_id/triggers", get(db_handler::db_list_triggers))
        .route("/api/db/:conn_id/indexes", get(db_handler::db_list_indexes))
        .route("/api/db/:conn_id/foreign_keys", get(db_handler::db_list_foreign_keys))
        .route("/api/db/:conn_id/query", post(db_handler::db_query))
        .route("/api/db/:conn_id/test", post(db_handler::db_test))
        // ADR-0003 S10 — transaction session endpoints. `begin` opens a
        // pinned single-connection pool; `query/commit/rollback` address it
        // by session_id. Transaction-control statements bypass the mutation
        // gate (handled inside the handlers).
        .route("/api/db/:conn_id/txn/begin", post(db_handler::txn_begin))
        .route("/api/db/:conn_id/txn/:session_id/query", post(db_handler::txn_query))
        .route("/api/db/:conn_id/txn/:session_id/commit", post(db_handler::txn_commit))
        .route("/api/db/:conn_id/txn/:session_id/rollback", post(db_handler::txn_rollback))
        // ADR-0003 S8b prep — admin endpoints. KILL needs an independent
        // privileged connection; script runs a real SQL-aware splitter then
        // executes each statement. Both go through the mutation gate (like
        // db_query) — embedded Licensed passes, remote Gated blocks.
        .route("/api/db/:conn_id/admin/kill", post(db_handler::admin_kill))
        .route("/api/db/:conn_id/admin/script", post(db_handler::admin_script))
        // Inject the txn session store so the 4 txn handlers above (and only
        // them, though harmless elsewhere) can reach it via Extension.
        .layer(Extension(txn_store))
        // Inject Arc<Config> so the Claims extractor can verify access tokens.
        // Layer is applied before .with_state so it wraps every route above.
        .layer(middleware::from_fn(move |mut req: axum::http::Request<axum::body::Body>, next: middleware::Next| {
            let cfg = config_for_extensions.clone();
            async move {
                req.extensions_mut().insert(cfg);
                next.run(req).await
            }
        }))
        .with_state(state)
}
