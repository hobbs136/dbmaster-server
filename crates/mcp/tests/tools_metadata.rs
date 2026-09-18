//! T06 集成测试：4 个元数据工具对真实 SQLite 目标库的三级钻取。
//!
//! 真连目标库（临时 .db 文件，含表/视图/索引/外键），不 mock 数据库服务；
//! server 侧库用内存 SQLite + 真实 migration DDL（011/013）。走原始
//! JSON-RPC over HTTP（tower oneshot），与 handshake.rs 同一套手法；
//! Claude Code 实配验证在 T09。

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

/// database_connections 最小可用投影（002 基线 + 007 file_path + 008 扩展列
/// 中本模块用到的子集——真实列序由 migration 文件保证，这里只保证列存在）。
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
        // T07 — read_query 行限上限 / 超时（测试默认值与生产默认一致）。
        mcp_read_query_max_rows: 10000,
        mcp_read_query_timeout_secs: 30,
        mcp_allowed_hosts: Vec::new(),
        mcp_allowed_connections: Vec::new(),
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

/// server 侧库：mcp_audit（011+013）+ database_connections。
async fn server_pool() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.expect("server pool");
    sqlx::raw_sql(MCP_AUDIT_DDL).execute(&pool).await.expect("011");
    sqlx::raw_sql(MCP_AUDIT_TOOL_DDL).execute(&pool).await.expect("013");
    sqlx::raw_sql(CONNECTIONS_DDL).execute(&pool).await.expect("connections");
    pool
}

/// 目标库：真实 SQLite 文件（Artist/Album 外键 + 索引 + 视图），返回路径。
/// 临时目标库序号：Windows 时钟粒度粗，并行测试同 pid 下 timestamp_nanos
/// 可能同值 → 同名文件「table already exists」。追加进程内单调序号消歧。
static TARGET_DB_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn target_sqlite_db() -> String {
    let path = std::env::temp_dir().join(format!(
        "dbmaster-mcp-t06-{}-{}-{}.db",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        TARGET_DB_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let url = format!("sqlite:{}?mode=rwc", path.display());
    let pool = SqlitePool::connect(&url).await.expect("target pool");
    sqlx::raw_sql(
        "CREATE TABLE artist (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        CREATE TABLE album (
            id INTEGER PRIMARY KEY,
            artist_id INTEGER NOT NULL REFERENCES artist(id),
            title TEXT NOT NULL
        );
        CREATE INDEX idx_album_title ON album(title);
        CREATE VIEW v_album AS SELECT id, title FROM album;
        INSERT INTO artist (id, name) VALUES (1, 'a'), (2, 'b');
        INSERT INTO album (id, artist_id, title) VALUES (1, 1, 't1'), (2, 1, 't2');",
    )
    .execute(&pool)
    .await
    .expect("seed target");
    pool.close().await;
    path.display().to_string()
}

/// 注册一条 sqlite 连接（file_path 即凭据；密码列存空串，sqlite 路径不解密）。
async fn register_connection(pool: &SqlitePool, file_path: &str) {
    sqlx::query(
        "INSERT INTO database_connections
         (id, name, db_type, host, port, username, password_encrypted,
          default_database, file_path, read_only)
         VALUES ('conn-t06', 't06-sqlite', 'sqlite', 'unused', 0, 'unused', '',
                 NULL, ?1, 0)",
    )
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
            "clientInfo": { "name": "t06-metadata-test", "version": "0.0.0" }
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

/// 调一个工具并解出其结果 JSON（content[0].text；结构化字段同值）。
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
    serde_json::from_str(text).unwrap_or_else(|_| {
        panic!("tool {name} content is not JSON: {text}")
    })
}

async fn audit_rows(pool: &SqlitePool) -> Vec<(Option<String>, String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT user_id, action, status, tool FROM mcp_audit ORDER BY rowid",
    )
    .fetch_all(pool)
    .await
    .expect("read mcp_audit")
}

// ── 主流程：三级钻取 ──────────────────────────────────────────────────

#[tokio::test]
async fn tier1_drill_down_against_sqlite_target() {
    let config = test_config();
    let pool = server_pool().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [9u8; 32], test_entitlement());
    let token = token_for(&config, "user-t06");

    // initialize → 会话
    let (status, session, json) = post(&app, init_body(), None, &token).await;
    assert_eq!(status, StatusCode::OK, "initialize, body: {json}");
    assert!(session.is_some(), "initialize must return session id");

    // ① list_connections：安全投影（绝不回 host/username/凭据）。
    let conns = call_tool(&app, &session, &token, 2, "list_connections", serde_json::json!({})).await;
    let list = conns["connections"].as_array().expect("connections array");
    assert_eq!(list.len(), 1);
    let conn = &list[0];
    assert_eq!(conn["id"], "conn-t06");
    assert_eq!(conn["name"], "t06-sqlite");
    assert_eq!(conn["dbType"], "sqlite");
    assert_eq!(conn["readOnly"], false);
    assert_eq!(conn["defaultDatabase"], Value::Null);
    // 契约：连接对象只有这 5 个键——出现 host/username/password 即违约。
    let mut keys: Vec<&str> = conn
        .as_object()
        .expect("connection object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["dbType", "defaultDatabase", "id", "name", "readOnly"]);
    let raw = serde_json::to_string(&conns).unwrap();
    for banned in ["host", "username", "password", "credential", "ssh"] {
        assert!(!raw.contains(banned), "list_connections leaked '{banned}': {raw}");
    }

    // ② list_databases：SQLite 无库概念，返回 ["main"]。
    let dbs = call_tool(
        &app, &session, &token, 3, "list_databases",
        serde_json::json!({ "connection_id": "conn-t06" }),
    ).await;
    assert_eq!(dbs["databases"], serde_json::json!(["main"]));

    // ③ list_tables：表 + 视图（SQLite 无注释/行数估计 → 键省略）。
    let tables = call_tool(
        &app, &session, &token, 4, "list_tables",
        serde_json::json!({ "connection_id": "conn-t06" }),
    ).await;
    let tlist = tables["tables"].as_array().expect("tables array");
    let by_name: std::collections::HashMap<&str, &Value> = tlist
        .iter()
        .map(|t| (t["name"].as_str().expect("name"), t))
        .collect();
    let album = *by_name.get("album").expect("album table listed");
    assert_eq!(album["type"], "table");
    assert!(album.get("comment").is_none(), "sqlite 无注释应省略键");
    assert!(album.get("row_estimate").is_none(), "sqlite 无统计应省略键");
    let view = *by_name.get("v_album").expect("view listed");
    assert_eq!(view["type"], "view");

    // ④ describe_table：列 + PK + FK + 索引。
    let album_desc = call_tool(
        &app, &session, &token, 5, "describe_table",
        serde_json::json!({ "connection_id": "conn-t06", "table": "album" }),
    ).await;
    assert_eq!(album_desc["table"], "album");
    let cols = album_desc["columns"].as_array().expect("columns");
    let col_names: Vec<&str> = cols.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(col_names, vec!["id", "artist_id", "title"]);
    let artist_id_col = &cols[1];
    assert_eq!(artist_id_col["type"], "INTEGER");
    assert_eq!(artist_id_col["nullable"], false);
    assert_eq!(album_desc["primaryKey"], serde_json::json!(["id"]));
    let fks = album_desc["foreignKeys"].as_array().expect("foreignKeys");
    assert_eq!(fks.len(), 1);
    assert_eq!(fks[0]["columns"], serde_json::json!(["artist_id"]));
    assert_eq!(fks[0]["refTable"], "artist");
    assert_eq!(fks[0]["refColumns"], serde_json::json!(["id"]));
    let indexes = album_desc["indexes"].as_array().expect("indexes");
    let idx_names: Vec<&str> =
        indexes.iter().map(|i| i["name"].as_str().unwrap()).collect();
    assert!(idx_names.contains(&"idx_album_title"), "indexes: {idx_names:?}");

    // ⑤ 审计：每次 tool_call 一行（无 SQL/数据明文；tool 列记录工具名）。
    let rows = audit_rows(&pool).await;
    assert_eq!(rows.len(), 4, "4 次调用各一行: {rows:?}");
    for (user, action, status, tool) in &rows {
        assert_eq!(user.as_deref(), Some("user-t06"));
        assert_eq!(action, "tool_call");
        assert_eq!(status, "ok");
        assert!(tool.is_some(), "tool name must be recorded");
    }
    assert_eq!(rows[0].3.as_deref(), Some("list_connections"));
    assert_eq!(rows[3].3.as_deref(), Some("describe_table"));

    // 清理目标库临时文件（Windows 上池已关，可删）。
    let _ = std::fs::remove_file(&target);
}

// ── 错误路径：NOT_FOUND 工具级错误 + 审计 error 行 ────────────────────

#[tokio::test]
async fn unknown_table_is_tool_error_and_audited() {
    let config = test_config();
    let pool = server_pool().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [9u8; 32], test_entitlement());
    let token = token_for(&config, "user-t06-err");

    let (status, session, json) = post(&app, init_body(), None, &token).await;
    assert_eq!(status, StatusCode::OK, "initialize, body: {json}");

    // 不存在的连接：工具级错误（isError=true），agent 可见原因。
    let (status, _, json) = post(
        &app,
        json_rpc(
            2,
            "tools/call",
            serde_json::json!({ "name": "list_databases", "arguments": { "connection_id": "nope" } }),
        ),
        session.as_deref(),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["isError"], true, "body: {json}");
    let text = json["result"]["content"][0]["text"].as_str().expect("error text");
    assert!(text.contains("NOT_FOUND"), "error text: {text}");

    // 不存在的表：同样工具级错误。
    let (status, _, json) = post(
        &app,
        json_rpc(
            3,
            "tools/call",
            serde_json::json!({
                "name": "describe_table",
                "arguments": { "connection_id": "conn-t06", "table": "missing_table" }
            }),
        ),
        session.as_deref(),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["isError"], true, "body: {json}");

    // 未知工具名：工具级错误（不是协议 500）。
    let (status, _, json) = post(
        &app,
        json_rpc(
            4,
            "tools/call",
            serde_json::json!({ "name": "drop_everything", "arguments": {} }),
        ),
        session.as_deref(),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["isError"], true, "body: {json}");

    // 审计：3 行 tool_call 且全为 error（含 tool 名）。
    let rows = audit_rows(&pool).await;
    assert_eq!(rows.len(), 3, "{rows:?}");
    for (user, action, status, tool) in &rows {
        assert_eq!(user.as_deref(), Some("user-t06-err"));
        assert_eq!(action, "tool_call");
        assert_eq!(status, "error");
        assert!(tool.is_some());
    }

    let _ = std::fs::remove_file(&target);
}

// ── 参数校验：缺必填参数 → INVALID_ARGUMENT 工具级错误 ────────────────

#[tokio::test]
async fn missing_required_argument_is_rejected() {
    let config = test_config();
    let pool = server_pool().await;
    let app = dbmaster_mcp::router(config.clone(), pool, [9u8; 32], test_entitlement());
    let token = token_for(&config, "user-t06-args");

    let (_, session, json) = post(&app, init_body(), None, &token).await;
    assert_eq!(json["jsonrpc"], "2.0");

    let (status, _, json) = post(
        &app,
        json_rpc(
            2,
            "tools/call",
            serde_json::json!({ "name": "describe_table", "arguments": { "connection_id": "x" } }),
        ),
        session.as_deref(),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["isError"], true);
    let text = json["result"]["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("table"), "missing-arg message: {text}");
}

// ── T07 read_query：SELECT-only 门 + 行限 + 超时 + 审计 ────────────────

/// 501 行样本（验证默认 500 截断边界）。
async fn target_sqlite_db_501() -> String {
    let path = std::env::temp_dir().join(format!(
        "dbmaster-mcp-t07-{}-{}-{}.db",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        TARGET_DB_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let url = format!("sqlite:{}?mode=rwc", path.display());
    let pool = SqlitePool::connect(&url).await.expect("target pool");
    sqlx::raw_sql(
        "CREATE TABLE big (n INTEGER PRIMARY KEY);
         WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 501)
         INSERT INTO big (n) SELECT x FROM c;",
    )
    .execute(&pool)
    .await
    .expect("seed 501 rows");
    pool.close().await;
    path.display().to_string()
}

#[tokio::test]
async fn read_query_returns_rows_and_enforces_row_limit() {
    let config = Arc::new(Config {
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
        mcp_allowed_connections: Vec::new(),
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
    });
    let pool = server_pool().await;
    let target = target_sqlite_db_501().await;
    register_connection(&pool, &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [9u8; 32], test_entitlement());
    let token = token_for(&config, "user-t07");

    let (status, session, json) = post(&app, init_body(), None, &token).await;
    assert_eq!(status, StatusCode::OK, "initialize, body: {json}");

    // ① SELECT：默认行限 500 生效（501 行 → 500 + truncated）。
    let r = call_tool(
        &app, &session, &token, 2, "read_query",
        serde_json::json!({ "connection_id": "conn-t06", "sql": "SELECT n FROM big ORDER BY n" }),
    ).await;
    assert_eq!(r["rowCount"], 500);
    assert_eq!(r["truncated"], true);
    assert_eq!(r["rows"][0]["n"], 1);
    assert_eq!(r["columns"], serde_json::json!(["n"]));

    // ② max_rows 抬到 1000：全量 501 行，无截断。
    let r = call_tool(
        &app, &session, &token, 3, "read_query",
        serde_json::json!({
            "connection_id": "conn-t06",
            "sql": "SELECT n FROM big ORDER BY n",
            "max_rows": 1000
        }),
    ).await;
    assert_eq!(r["rowCount"], 501);
    assert_eq!(r["truncated"], false);

    // ③ 收紧 max_rows=10。
    let r = call_tool(
        &app, &session, &token, 4, "read_query",
        serde_json::json!({
            "connection_id": "conn-t06",
            "sql": "SELECT n FROM big",
            "max_rows": 10
        }),
    ).await;
    assert_eq!(r["rowCount"], 10);
    assert_eq!(r["truncated"], true);

    // ④ 审计：3 次 read_query 全 ok。
    let rows = audit_rows(&pool).await;
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(rows.iter().all(|(_, action, status, tool)| {
        action == "tool_call" && status == "ok" && tool.as_deref() == Some("read_query")
    }));

    let _ = std::fs::remove_file(&target);
}

#[tokio::test]
async fn read_query_rejects_non_read_only_and_multi_statement() {
    let config = test_config();
    let pool = server_pool().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [9u8; 32], test_entitlement());
    let token = token_for(&config, "user-t07-rj");

    let (status, session, json) = post(&app, init_body(), None, &token).await;
    assert_eq!(status, StatusCode::OK, "initialize, body: {json}");

    // 拒绝矩阵：写 / DDL / USE / 事务 / 多语句 / 解析失败（fail-closed）。
    // 期望：isError=true + NOT_READ_ONLY 或 MULTI_STATEMENT + 原因文案。
    let cases = [
        ("UPDATE artist SET name = 'x' WHERE id = 1", "NOT_READ_ONLY", "data-modifying statement"),
        ("DELETE FROM artist", "NOT_READ_ONLY", "data-modifying statement"),
        ("DROP TABLE artist", "NOT_READ_ONLY", "schema/privilege change"),
        ("USE other_db", "NOT_READ_ONLY", "USE statement forbidden"),
        ("BEGIN", "NOT_READ_ONLY", "transaction control statement"),
        ("SELECT 1; SELECT 2", "MULTI_STATEMENT", "one SQL statement"),
        ("TOTALLY NOT SQL @@@", "NOT_READ_ONLY", "parse failure"),
        // 副作用函数（T05 覆盖面在真实门上的回归）。
        ("SELECT nextval('s')", "NOT_READ_ONLY", "side-effect"),
    ];
    let mut rpc_id = 2u64;
    for (sql, code, reason_frag) in cases {
        let body = json_rpc(
            rpc_id,
            "tools/call",
            serde_json::json!({ "name": "read_query", "arguments": { "connection_id": "conn-t06", "sql": sql } }),
        );
        let (status, _, json) = post(&app, body, session.as_deref(), &token).await;
        assert_eq!(status, StatusCode::OK, "case {sql}");
        assert_eq!(json["result"]["isError"], true, "case {sql}: {json}");
        let text = json["result"]["content"][0]["text"].as_str().expect("error text");
        assert!(text.contains(code), "case {sql}: expected {code} in {text}");
        assert!(text.contains(reason_frag), "case {sql}: expected '{reason_frag}' in {text}");
        rpc_id += 1;
    }

    // 审计：8 行全 error（含 read_query 工具名）。
    let rows = audit_rows(&pool).await;
    assert_eq!(rows.len(), cases.len(), "{rows:?}");
    assert!(rows.iter().all(|(_, action, status, tool)| {
        action == "tool_call" && status == "error" && tool.as_deref() == Some("read_query")
    }));

    let _ = std::fs::remove_file(&target);
}

#[tokio::test]
async fn read_query_times_out_long_running_statement() {
    // 1 秒超时 + 大递归 CTE（CPU 密集，远超 1s）→ TIMEOUT 工具级错误。
    let config = Arc::new(Config {
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
        mcp_read_query_timeout_secs: 1,
        mcp_allowed_hosts: Vec::new(),
        mcp_allowed_connections: Vec::new(),
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
    });
    let pool = server_pool().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [9u8; 32], test_entitlement());
    let token = token_for(&config, "user-t07-to");

    let (status, session, json) = post(&app, init_body(), None, &token).await;
    assert_eq!(status, StatusCode::OK, "initialize, body: {json}");

    let body = json_rpc(
        2,
        "tools/call",
        serde_json::json!({
            "name": "read_query",
            "arguments": {
                "connection_id": "conn-t06",
                "sql": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 100000000) SELECT count(*) FROM c"
            }
        }),
    );
    let started = std::time::Instant::now();
    let (status, _, json) = post(&app, body, session.as_deref(), &token).await;
    let elapsed = started.elapsed();
    assert_eq!(status, StatusCode::OK, "body: {json}");
    assert_eq!(json["result"]["isError"], true, "body: {json}");
    let text = json["result"]["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("TIMEOUT"), "text: {text}");
    // 超时在 ~1s 触发（而非跑完 1 亿次递归）。
    assert!(elapsed.as_secs_f64() < 10.0, "timeout took {elapsed:?}");

    let _ = std::fs::remove_file(&target);
}
