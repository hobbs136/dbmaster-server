//! 网关集成测试共享基建（同 mcp tests 手法：内存 server 库 + 真实 SQLite
//! 目标库文件 + tower oneshot 直驱 router）。

#![allow(dead_code)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use dbmaster_core::auth::jwt::issue_access_token;
use dbmaster_core::config::Config;
use sqlx::SqlitePool;

pub const GW_AUDIT_DDL: &str = include_str!("../../../../migrations/015_gateway_audit.sql");

/// database_connections 最小可用投影（覆盖网关注册 INSERT 的列集 +
/// metadata 读取列；真实列序由 migration 文件保证，此处只保证列存在）。
pub const CONNECTIONS_DDL: &str = "CREATE TABLE database_connections (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    db_type TEXT NOT NULL DEFAULT 'mysql',
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 3306,
    username TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    default_database TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    kind TEXT NOT NULL DEFAULT 'collab',
    file_path TEXT,
    charset TEXT,
    timezone TEXT,
    read_only INTEGER NOT NULL DEFAULT 0,
    extra TEXT,
    ssh_secret_encrypted TEXT
);";

/// gw knobs 可覆盖的测试 Config（其余字段与生产默认一致）。
pub struct GwKnobs {
    pub rate_limit_per_minute: u32,
    pub query_max_rows: u32,
}

impl Default for GwKnobs {
    fn default() -> Self {
        Self { rate_limit_per_minute: 600, query_max_rows: 10000 }
    }
}

pub fn test_config(knobs: GwKnobs) -> Arc<Config> {
    Arc::new(Config {
        host: "127.0.0.1".into(),
        port: 0,
        jwt_secret: "test-gw-jwt-secret".into(),
        jwt_refresh_secret: "test-gw-refresh-secret".into(),
        database_url: "sqlite::memory:".into(),
        funnel_lite_enabled: false,
        drift_default_interval_mins: 30,
        drift_webhook_timeout_secs: 10,
        data_sync_default_batch_size: 10000,
        data_sync_max_concurrency: 1,
        mcp_rate_limit_per_minute: 120,
        mcp_read_query_max_rows: 10000,
        mcp_read_query_timeout_secs: 30,
        mcp_allowed_hosts: Vec::new(),
        mcp_allowed_connections: Vec::new(),
        gw_rate_limit_per_minute: knobs.rate_limit_per_minute,
        gw_query_default_rows: 500,
        gw_query_max_rows: knobs.query_max_rows,
        gw_query_timeout_secs: 30,
        // reports-M1 — 与生产默认一致（M1 加 Config 字段时本文件漏更，
        // --workspace 全量才暴露）。
        slow_query_enabled: true,
        slow_query_threshold_ms: 1000,
        slow_query_store_sql: true,
        slow_query_retention_days: 14,
        slow_query_cap_per_digest_per_hour: 20,
    })
}

/// server 侧库：gw_audit（015）+ database_connections。
pub async fn server_pool() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.expect("server pool");
    sqlx::raw_sql(GW_AUDIT_DDL).execute(&pool).await.expect("015");
    sqlx::raw_sql(CONNECTIONS_DDL).execute(&pool).await.expect("connections");
    pool
}

/// 目标库：真实 SQLite 文件（artist/album + 100 行 big 表），返回路径。
/// tag 用于并行测试隔离（各自独立文件）。
pub async fn target_sqlite_db(tag: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "dbmaster-gw-{tag}-{}-{}.db",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let url = format!("sqlite:{}?mode=rwc", path.display());
    let pool = SqlitePool::connect(&url).await.expect("target pool");
    sqlx::raw_sql(
        "CREATE TABLE artist (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        CREATE TABLE big (n INTEGER);
        WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 100)
        INSERT INTO big SELECT x FROM c;
        INSERT INTO artist (id, name) VALUES (1, 'a'), (2, 'b');",
    )
    .execute(&pool)
    .await
    .expect("seed target");
    pool.close().await;
    path.display().to_string()
}

/// 注册一条已存在的 sqlite 连接（网关侧不走注册端点时的直插基线）。
pub async fn register_connection(pool: &SqlitePool, conn_id: &str, file_path: &str, db_type: &str) {
    sqlx::query(
        "INSERT INTO database_connections
         (id, name, db_type, host, port, username, password_encrypted,
          default_database, file_path, read_only)
         VALUES (?1, ?2, ?3, 'unused', 0, 'unused', '',
                 NULL, ?4, 0)",
    )
    .bind(conn_id)
    .bind(format!("gw-test-{conn_id}"))
    .bind(db_type)
    .bind(file_path)
    .execute(pool)
    .await
    .expect("insert connection");
}

pub fn token_for(config: &Config, user_id: &str) -> String {
    issue_access_token(config, user_id).expect("mint access token")
}

/// 带 Bearer 的 JSON GET。
pub fn authed_get(token: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// 带 Bearer 的 JSON POST。
pub fn authed_post_json(token: &str, path: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

pub fn authed_delete(token: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

pub async fn body_string(body: Body) -> String {
    let bytes = http_body_util::BodyExt::collect(body)
        .await
        .expect("collect body")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 解析 SSE 文本为 (event, data-json) 序列（忽略 keep-alive 注释）。
pub fn parse_sse(text: &str) -> Vec<(String, serde_json::Value)> {
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        let mut event = None;
        let mut data = String::new();
        for line in block.lines() {
            if let Some(e) = line.strip_prefix("event: ") {
                event = Some(e.to_string());
            } else if let Some(d) = line.strip_prefix("data: ") {
                data.push_str(d);
            }
        }
        if let Some(event) = event {
            let json = serde_json::from_str(&data)
                .unwrap_or_else(|e| panic!("SSE data 不是合法 JSON（{event}）: {e}\n{data}"));
            out.push((event, json));
        }
    }
    out
}

pub fn status_of(resp: &axum::http::Response<Body>) -> StatusCode {
    resp.status()
}
