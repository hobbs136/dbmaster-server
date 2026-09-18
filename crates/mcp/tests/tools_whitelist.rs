//! T08 集成测试：连接白名单（`mcp.allowed_connections`）对整个工具面的约束。
//!
//! 真连 SQLite 目标库 + 内存 server 库（真实 migration DDL + 连接表），
//! JSON-RPC over HTTP（与 tools_metadata.rs 同一手法）。空白名单 = 不过滤
//! 的默认行为由 tools_metadata.rs 既有用例回归（其 list_connections 全量
//! 可见即证明）；本文件只测**非空白名单**的收紧语义：
//!
//! 1. list_connections 只回白名单内连接（按 name 放行 + 按 id 放行都覆盖）；
//! 2. 白名单外连接的连接级工具（list_databases / read_query）在触达目标库
//!    前被拒（CONNECTION_NOT_ALLOWED），read_query 连风险门都不进；
//! 3. 未知 id 仍由底层报 NOT_FOUND（白名单不吞掉原错误文案）；
//! 4. 拒绝调用落 tool_call 审计行（status=error）。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use dbmaster_core::auth::jwt::issue_access_token;
use dbmaster_core::config::Config;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::SqlitePool;
use tower::ServiceExt;

/// D1 测试默认 entitlement：Trial 未到期（未门控——既有测试语义不变）。
fn test_entitlement() -> dbmaster_mcp::EntitlementArc {
    std::sync::Arc::new(arc_swap::ArcSwap::from(std::sync::Arc::new(
        dbmaster_license::EntitlementState::Trial {
            expires_at: chrono::Utc::now() + chrono::Duration::days(30),
        },
    )))
}

const MCP_AUDIT_DDL: &str = include_str!("../../../migrations/011_mcp_audit.sql");
const MCP_AUDIT_TOOL_DDL: &str = include_str!("../../../migrations/013_mcp_audit_tool.sql");

const CONNECTIONS_DDL: &str = "CREATE TABLE database_connections (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    db_type TEXT NOT NULL DEFAULT 'mysql',
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 3306,
    username TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    default_database TEXT,
    file_path TEXT,
    charset TEXT,
    timezone TEXT,
    extra TEXT,
    ssh_secret_encrypted TEXT,
    read_only INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);";

/// 白名单：alpha 按名字放行，conn-c 按 id 放行，beta/conn-b 两键都不命中。
fn test_config() -> Arc<Config> {
    Arc::new(Config {
        host: "127.0.0.1".into(),
        port: 0,
        jwt_secret: "test-mcp-jwt-secret".into(),
        jwt_refresh_secret: "test-mcp-refresh-secret".into(),
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
        mcp_allowed_connections: vec!["alpha".into(), "conn-c".into()],
        gw_rate_limit_per_minute: 600,
        gw_query_default_rows: 500,
        gw_query_max_rows: 10000,
        gw_query_timeout_secs: 30,
        // reports-M1 — 测试默认值与生产一致。
        slow_query_enabled: true,
        slow_query_threshold_ms: 1000,
        slow_query_store_sql: true,
        slow_query_retention_days: 14,
        slow_query_cap_per_digest_per_hour: 20,
    })
}

async fn server_pool() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.expect("server pool");
    sqlx::raw_sql(MCP_AUDIT_DDL).execute(&pool).await.expect("011");
    sqlx::raw_sql(MCP_AUDIT_TOOL_DDL).execute(&pool).await.expect("013");
    sqlx::raw_sql(CONNECTIONS_DDL).execute(&pool).await.expect("connections");
    pool
}

/// 临时目标库序号：Windows 时钟粒度粗，并行测试同 pid 下 timestamp_nanos
/// 可能同值 → 同名文件「table already exists」。追加进程内单调序号消歧。
static TARGET_DB_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn target_sqlite_db() -> String {
    let path = std::env::temp_dir().join(format!(
        "dbmaster-mcp-t08-{}-{}-{}.db",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        TARGET_DB_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let url = format!("sqlite:{}?mode=rwc", path.display());
    let pool = SqlitePool::connect(&url).await.expect("target pool");
    sqlx::raw_sql(
        "CREATE TABLE t (id INTEGER PRIMARY KEY);
         INSERT INTO t (id) VALUES (1), (2);",
    )
    .execute(&pool)
    .await
    .expect("seed target");
    pool.close().await;
    path.display().to_string()
}

/// 注册一条 sqlite 连接（file_path 即凭据；密码列存空串，sqlite 路径不解密）。
async fn register_connection(pool: &SqlitePool, id: &str, name: &str, file_path: &str) {
    sqlx::query(
        "INSERT INTO database_connections
         (id, name, db_type, host, port, username, password_encrypted,
          default_database, file_path, read_only)
         VALUES (?1, ?2, 'sqlite', 'unused', 0, 'unused', '',
                 NULL, ?3, 0)",
    )
    .bind(id)
    .bind(name)
    .bind(file_path)
    .execute(pool)
    .await
    .expect("insert connection");
}

fn token_for(config: &Config, user_id: &str) -> String {
    issue_access_token(config, user_id).expect("mint access token")
}

fn json_rpc(id: u64, method: &str, params: Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string()
}

fn init_body() -> String {
    json_rpc(
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "t08-whitelist-test", "version": "0.0.0" }
        }),
    )
}

async fn post(
    app: &axum::Router,
    body: String,
    session: Option<&str>,
    token: &str,
) -> (StatusCode, Option<String>, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(sid) = session {
        builder = builder.header("mcp-session-id", sid);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .expect("oneshot request failed");
    let status = resp.status();
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = resp.into_body().collect().await.expect("body read").to_bytes();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let json: Value = if text.trim().is_empty() {
        Value::Null
    } else if text.trim_start().starts_with('{') {
        serde_json::from_str(&text).expect("JSON response body")
    } else {
        let data = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .find(|d| !d.is_empty())
            .expect("non-empty SSE data frame");
        serde_json::from_str(data).expect("SSE data JSON")
    };
    (status, sid, json)
}

/// 调一个工具并解出其结果 JSON（content[0].text）。
async fn call_tool(
    app: &axum::Router,
    session: &Option<String>,
    token: &str,
    id: u64,
    name: &str,
    args: Value,
) -> Value {
    let body = json_rpc(
        id,
        "tools/call",
        serde_json::json!({ "name": name, "arguments": args }),
    );
    let (status, _, json) = post(app, body, session.as_deref(), token).await;
    assert_eq!(status, StatusCode::OK, "tools/call {name}, body: {json}");
    let result = &json["result"];
    assert!(
        result.get("isError").and_then(Value::as_bool) != Some(true),
        "tool {name} unexpected isError: {json}"
    );
    let text = result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool {name} content text missing: {json}"));
    serde_json::from_str(text)
        .unwrap_or_else(|_| panic!("tool {name} content is not JSON: {text}"))
}

/// 调一个工具，断言**工具级错误**并返回错误文案。
async fn call_tool_error(
    app: &axum::Router,
    session: &Option<String>,
    token: &str,
    id: u64,
    name: &str,
    args: Value,
) -> String {
    let body = json_rpc(
        id,
        "tools/call",
        serde_json::json!({ "name": name, "arguments": args }),
    );
    let (status, _, json) = post(app, body, session.as_deref(), token).await;
    assert_eq!(status, StatusCode::OK, "tools/call {name}, body: {json}");
    assert_eq!(
        json["result"]["isError"], true,
        "tool {name} expected isError: {json}"
    );
    json["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool {name} error text missing: {json}"))
        .to_string()
}

async fn audit_rows(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT action, status, tool FROM mcp_audit ORDER BY rowid",
    )
    .fetch_all(pool)
    .await
    .expect("read mcp_audit")
}

// ── 主用例：非空白名单收紧整个工具面 ──────────────────────────────────

#[tokio::test]
async fn whitelist_hides_and_blocks_non_listed_connections() {
    let config = test_config();
    let pool = server_pool().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, "conn-a", "alpha", &target).await;
    register_connection(&pool, "conn-b", "beta", &target).await;
    register_connection(&pool, "conn-c", "gamma", &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [9u8; 32], test_entitlement());
    let token = token_for(&config, "user-t08");

    let (status, session, json) = post(&app, init_body(), None, &token).await;
    assert_eq!(status, StatusCode::OK, "initialize, body: {json}");
    assert!(session.is_some(), "initialize must return session id");

    // ① list_connections：只回白名单内的 conn-a（name 命中）与
    //    conn-c（id 命中）；conn-b 两键都不命中 → 不可见。
    let conns = call_tool(&app, &session, &token, 2, "list_connections", serde_json::json!({})).await;
    let list = conns["connections"].as_array().expect("connections array");
    let mut ids: Vec<&str> = list.iter().map(|c| c["id"].as_str().expect("id")).collect();
    ids.sort_unstable();
    assert_eq!(ids, vec!["conn-a", "conn-c"], "hidden conn-b must not appear");
    let raw = serde_json::to_string(&conns).unwrap();
    assert!(!raw.contains("beta"), "hidden connection name leaked: {raw}");
    assert!(!raw.contains("conn-b"), "hidden connection id leaked: {raw}");

    // ② 白名单外连接的元数据工具：触达目标库之前被拒。
    let err = call_tool_error(
        &app, &session, &token, 3, "list_databases",
        serde_json::json!({ "connection_id": "conn-b" }),
    ).await;
    assert!(err.contains("CONNECTION_NOT_ALLOWED"), "error text: {err}");

    // ③ 白名单外连接的 read_query：SELECT 本身无害也拒（授权先于内容分析）。
    let err = call_tool_error(
        &app, &session, &token, 4, "read_query",
        serde_json::json!({ "connection_id": "conn-b", "sql": "SELECT id FROM t" }),
    ).await;
    assert!(err.contains("CONNECTION_NOT_ALLOWED"), "error text: {err}");

    // ④ 白名单内（按 id 放行）连接：钻取与查询全链路可用。
    let dbs = call_tool(
        &app, &session, &token, 5, "list_databases",
        serde_json::json!({ "connection_id": "conn-c" }),
    ).await;
    assert_eq!(dbs["databases"], serde_json::json!(["main"]));
    let r = call_tool(
        &app, &session, &token, 6, "read_query",
        serde_json::json!({ "connection_id": "conn-c", "sql": "SELECT count(*) AS n FROM t" }),
    ).await;
    assert_eq!(r["rowCount"], 1);
    assert_eq!(r["rows"][0]["n"], 2);

    // ⑤ 未知 id：白名单不吞掉底层 NOT_FOUND 文案（便于排障区分配错 vs 不存在）。
    let err = call_tool_error(
        &app, &session, &token, 7, "list_databases",
        serde_json::json!({ "connection_id": "no-such-conn" }),
    ).await;
    assert!(err.contains("NOT_FOUND"), "error text: {err}");

    // ⑥ 审计：6 次调用各一行，3 次拒绝落 error（含工具名，无 SQL 明文）。
    let rows = audit_rows(&pool).await;
    assert_eq!(rows.len(), 6, "6 次调用各一行: {rows:?}");
    let errors: Vec<&(String, String, Option<String>)> =
        rows.iter().filter(|(_, status, _)| status == "error").collect();
    assert_eq!(errors.len(), 3, "{rows:?}");
    assert!(errors.iter().all(|(_, _, tool)| tool.is_some()));

    let _ = std::fs::remove_file(&target);
}
