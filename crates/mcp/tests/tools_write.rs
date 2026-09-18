//! T19 集成测试：MCP 写路径三工具（审批制：提交 → 人批 → 幂等执行）。
//!
//! 真连 SQLite 目标库 + 内存 server 库（真实 migration DDL：mcp_audit 011+013、
//! database_connections、ddl_approvals 002+009 形状），JSON-RPC over HTTP（与
//! tools_whitelist.rs 同一手法）。核心验收（task_dbx_response T19）：
//!
//! 1. submit → get 本人可见；他人/无 token 不可见（防探测统一 NOT_FOUND）；
//! 2. 未审批 execute → 拒（APPROVAL_NOT_APPROVED）；
//! 3. 程序置 approved → execute 成功（真建表）→ **重复 execute 幂等**——
//!    SQLite 的 CREATE TABLE 不带 IF NOT EXISTS，若重复执行会报
//!    "table already exists" 落 failed；断言二次调用仍回 approved 即证明
//!    执行副作用只发生一次；
//! 4. 多语句 / 纯读 / 未知连接 / 白名单外连接的 submit → 拒；
//! 5. 执行失败（DML 过执行器 DDL 白名单）→ exec_status=failed + execError，
//!    行状态流转 failed，重试被 APPROVAL_NOT_APPROVED 拒（重新提交才是路径）；
//! 6. 审计：tool_call 有行、error 列静态文案、无 SQL 明文。
//!
//! 「程序置 approved」用 SQL 直改行（等价于人批准后的终态，剥掉 REST
//! approve 的 spawn 执行——那会立刻异步执行，测不出 MCP 幂等语义；真 REST
//! 路径回归归 automation crate 既有测试）。

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
    kind TEXT NOT NULL DEFAULT 'collab',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);";

/// ddl_approvals：002 形状 + 009 的 exec_* 列（ALTER 合并进 CREATE）。
const APPROVALS_DDL: &str = "CREATE TABLE ddl_approvals (
    id           TEXT PRIMARY KEY,
    submitter_id TEXT NOT NULL,
    ddl_sql      TEXT NOT NULL,
    target_db_id TEXT NOT NULL REFERENCES database_connections(id),
    reviewer_id  TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at  TEXT,
    exec_status  TEXT NOT NULL DEFAULT 'pending',
    executed_at  TEXT,
    exec_error   TEXT
);";

/// 与 router 的 credential_key 一致（测试进程内自定）。
const KEY: [u8; 32] = [9u8; 32];

fn test_config(allowed_connections: Vec<String>) -> Arc<Config> {
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
        mcp_allowed_connections: allowed_connections,
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
    sqlx::raw_sql(APPROVALS_DDL).execute(&pool).await.expect("approvals");
    pool
}

/// 临时目标库序号：Windows 时钟粒度粗，并行测试同 pid 下 timestamp_nanos
/// 可能同值 → 同名文件「table already exists」（全 workspace 并行时实测）。
/// 追加进程内单调序号消歧（跨进程仍由 pid + 时间戳区分）。
static TARGET_DB_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn target_sqlite_db() -> String {
    let path = std::env::temp_dir().join(format!(
        "dbmaster-mcp-t19-{}-{}-{}.db",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        TARGET_DB_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let url = format!("sqlite:{}?mode=rwc", path.display());
    let pool = SqlitePool::connect(&url).await.expect("target pool");
    sqlx::raw_sql("CREATE TABLE t (id INTEGER PRIMARY KEY);")
        .execute(&pool)
        .await
        .expect("seed target");
    pool.close().await;
    path.display().to_string()
}

/// 注册一条 sqlite 连接。密码列存 v1 加密的空串——执行路径
/// （execute_ddl_on_target_with_key → load_and_decrypt_key）会真解密，
/// 空明文也走 encrypt_v1 与生产客户端的 sqlite 连接一致。
async fn register_connection(pool: &SqlitePool, id: &str, name: &str, file_path: &str) {
    let password_encrypted =
        dbmaster_automation::credential::encrypt_v1("", &KEY).expect("encrypt empty password");
    sqlx::query(
        "INSERT INTO database_connections
         (id, name, db_type, host, port, username, password_encrypted,
          default_database, file_path, read_only)
         VALUES (?1, ?2, 'sqlite', 'unused', 0, 'unused', ?4,
                 NULL, ?3, 0)",
    )
    .bind(id)
    .bind(name)
    .bind(file_path)
    .bind(password_encrypted)
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
            "clientInfo": { "name": "t19-write-test", "version": "0.0.0" }
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

/// 无 Bearer 的裸 POST——auth guard 应 401（写面同样先过认证）。
async fn post_noauth(app: &axum::Router, body: String) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("oneshot request failed");
    resp.status()
}

async fn init_session(app: &axum::Router, token: &str) -> Option<String> {
    let (status, session, json) = post(app, init_body(), None, token).await;
    assert_eq!(status, StatusCode::OK, "initialize, body: {json}");
    session
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

/// 「人批准」：置 status=approved（exec_status 保持 pending，等 agent 执行）。
async fn human_approves(pool: &SqlitePool, approval_id: &str) {
    sqlx::query("UPDATE ddl_approvals SET status = 'approved' WHERE id = ?1")
        .bind(approval_id)
        .execute(pool)
        .await
        .expect("programmatically approve");
}

/// 审批行直读：(status, exec_status, exec_error, executed_at)。
async fn approval_row(
    pool: &SqlitePool,
    approval_id: &str,
) -> (String, String, Option<String>, Option<String>) {
    sqlx::query_as(
        "SELECT status, exec_status, exec_error, executed_at FROM ddl_approvals WHERE id = ?1",
    )
    .bind(approval_id)
    .fetch_one(pool)
    .await
    .expect("approval row")
}

/// 目标 SQLite 里表是否已建（执行副作用探针）。
async fn table_exists_in_target(path: &str, table: &str) -> bool {
    let url = format!("sqlite:{path}");
    let pool = SqlitePool::connect(&url).await.expect("reopen target");
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
    )
    .bind(table)
    .fetch_one(&pool)
    .await
    .expect("sqlite_master probe");
    pool.close().await;
    n > 0
}

async fn audit_rows(pool: &SqlitePool) -> Vec<(String, String, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT action, status, tool, error FROM mcp_audit ORDER BY rowid",
    )
    .fetch_all(pool)
    .await
    .expect("read mcp_audit")
}

// ── 主用例 ①：submit → get 可见性 → 未批拒 → 批后执行 → 幂等 ──────────

#[tokio::test]
async fn approval_lifecycle_submit_get_execute_idempotent() {
    let config = test_config(Vec::new());
    let pool = server_pool().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, "conn-a", "alpha", &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), KEY, test_entitlement());
    let token_a = token_for(&config, "user-a");
    let token_b = token_for(&config, "user-b");

    let session_a = init_session(&app, &token_a).await;
    let session_b = init_session(&app, &token_b).await;

    // 无 token：认证层 401，写面不可达（先于一切工具语义）。
    let status = post_noauth(&app, init_body()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // ① submit：落 pending 行，risk 记录（DDL 等级 + 静态原因）。
    let submit = call_tool(
        &app, &session_a, &token_a, 2, "submit_write",
        serde_json::json!({
            "connection_id": "conn-a",
            "sql": "CREATE TABLE mcp_t19_lifecycle (id INTEGER PRIMARY KEY)"
        }),
    ).await;
    let approval_id = submit["approvalId"].as_str().expect("approvalId").to_string();
    assert_eq!(submit["status"], "pending");
    assert_eq!(submit["risk"]["level"], "ddl");
    assert!(
        submit["risk"]["reasons"].as_array().is_some_and(|r| !r.is_empty()),
        "risk reasons 记录拒因: {submit}"
    );

    // ② get：本人可见全字段。
    let got = call_tool(
        &app, &session_a, &token_a, 3, "get_approval",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert_eq!(got["approvalId"], approval_id.as_str());
    assert_eq!(got["status"], "pending");
    assert_eq!(got["execStatus"], "pending");
    assert!(got["createdAt"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(got.get("execError").is_none(), "未执行无 execError: {got}");
    assert!(got.get("resolvedAt").is_none(), "未裁决无 resolvedAt: {got}");

    // ③ 他人不可见——与未知 id 同文案（防探测）。
    let err_b = call_tool_error(
        &app, &session_b, &token_b, 4, "get_approval",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert!(err_b.contains("NOT_FOUND"), "error text: {err_b}");
    let err_unknown = call_tool_error(
        &app, &session_a, &token_a, 5, "get_approval",
        serde_json::json!({ "approval_id": "no-such-approval" }),
    ).await;
    assert!(err_unknown.contains("NOT_FOUND"), "error text: {err_unknown}");

    // ④ 未审批 execute → 拒（T19 验收原文）。
    let err = call_tool_error(
        &app, &session_a, &token_a, 6, "execute_write",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert!(err.contains("APPROVAL_NOT_APPROVED"), "error text: {err}");
    assert!(!table_exists_in_target(&target, "mcp_t19_lifecycle").await);

    // ⑤ 他人 execute 也拒（NOT_FOUND 防探测，而非权限差异文案）。
    let err = call_tool_error(
        &app, &session_b, &token_b, 7, "execute_write",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert!(err.contains("NOT_FOUND"), "error text: {err}");

    // ⑥ 人批准（直改行——REST approve 会立刻 spawn 执行，测不出 MCP 幂等）。
    human_approves(&pool, &approval_id).await;

    // ⑦ execute：成功执行（真建表）。
    let executed = call_tool(
        &app, &session_a, &token_a, 8, "execute_write",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert_eq!(executed["approvalId"], approval_id.as_str());
    assert_eq!(executed["execStatus"], "approved", "执行成功终态: {executed}");
    assert!(table_exists_in_target(&target, "mcp_t19_lifecycle").await);

    // ⑧ 重复 execute：幂等——同一状态返回，不重复执行。SQLite 的 CREATE
    //    TABLE 不带 IF NOT EXISTS，若二次执行必报 already exists 落 failed；
    //    仍回 approved 即证明副作用只发生一次（T19 验收原文）。
    let again = call_tool(
        &app, &session_a, &token_a, 9, "execute_write",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert_eq!(again["execStatus"], "approved", "幂等返回同状态: {again}");
    assert!(table_exists_in_target(&target, "mcp_t19_lifecycle").await);

    // ⑨ get 反映终态；行内 status/exec_status 双 approved + executed_at 落库。
    let got = call_tool(
        &app, &session_a, &token_a, 10, "get_approval",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert_eq!(got["status"], "approved");
    assert_eq!(got["execStatus"], "approved");
    let (status, exec_status, exec_error, executed_at) = approval_row(&pool, &approval_id).await;
    assert_eq!((status.as_str(), exec_status.as_str()), ("approved", "approved"));
    assert!(exec_error.is_none());
    assert!(executed_at.is_some(), "executed_at 落库");

    // ⑩ 审计：每次 tools/call 一行 tool_call；错误行文案静态（无 SQL 明文）。
    let rows = audit_rows(&pool).await;
    let tool_rows: Vec<&(String, String, Option<String>, Option<String>)> =
        rows.iter().filter(|(action, _, _, _)| action == "tool_call").collect();
    assert_eq!(tool_rows.len(), 9, "9 次 tools/call 各一行: {rows:?}");
    assert!(tool_rows.iter().all(|(_, _, tool, _)| tool.is_some()));
    let error_rows: Vec<_> = tool_rows.iter().filter(|(_, s, _, _)| s == "error").collect();
    assert_eq!(error_rows.len(), 4, "4 次拒绝（NOT_FOUND×3 / NOT_APPROVED×1）: {rows:?}");
    for (_, _, tool, err) in &error_rows {
        let err = err.as_deref().unwrap_or("");
        assert!(!err.contains("CREATE TABLE"), "审计泄露 SQL 明文: {err}");
        assert!(!err.contains("mcp_t19_lifecycle"), "审计泄露表名: {err}");
        let _ = tool;
    }

    let _ = std::fs::remove_file(&target);
}

// ── 主用例 ②：submit 的输入约束（多语句/纯读/未知连接/白名单外）───────

#[tokio::test]
async fn submit_rejects_bad_input_and_non_whitelisted_connection() {
    let config = test_config(vec!["alpha".into()]); // 只放行 conn-a（按 name）
    let pool = server_pool().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, "conn-a", "alpha", &target).await;
    register_connection(&pool, "conn-b", "beta", &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), KEY, test_entitlement());
    let token = token_for(&config, "user-a");
    let session = init_session(&app, &token).await;

    // 多语句：拒（单语句约束与 read_query 同款）。
    let err = call_tool_error(
        &app, &session, &token, 2, "submit_write",
        serde_json::json!({
            "connection_id": "conn-a",
            "sql": "CREATE TABLE m1 (a INT); CREATE TABLE m2 (a INT)"
        }),
    ).await;
    assert!(err.contains("MULTI_STATEMENT"), "error text: {err}");

    // 纯读语句：不该走审批路径——引导回 read_query。
    let err = call_tool_error(
        &app, &session, &token, 3, "submit_write",
        serde_json::json!({ "connection_id": "conn-a", "sql": "SELECT 1" }),
    ).await;
    assert!(err.contains("READ_ONLY_SQL"), "error text: {err}");

    // 未知连接：统一 NOT_FOUND（不触达 FK 裸错误）。
    let err = call_tool_error(
        &app, &session, &token, 4, "submit_write",
        serde_json::json!({ "connection_id": "no-such-conn", "sql": "CREATE TABLE x (a INT)" }),
    ).await;
    assert!(err.contains("NOT_FOUND"), "error text: {err}");

    // 白名单外连接：授权先于内容分析，触达目标库前被拒。
    let err = call_tool_error(
        &app, &session, &token, 5, "submit_write",
        serde_json::json!({ "connection_id": "conn-b", "sql": "CREATE TABLE x (a INT)" }),
    ).await;
    assert!(err.contains("CONNECTION_NOT_ALLOWED"), "error text: {err}");

    // 解析失败的非语句：statement_count=0 ≠ 1 → MULTI_STATEMENT（fail-closed）。
    let err = call_tool_error(
        &app, &session, &token, 6, "submit_write",
        serde_json::json!({ "connection_id": "conn-a", "sql": "TOTALLY NOT SQL @@@" }),
    ).await;
    assert!(err.contains("MULTI_STATEMENT"), "error text: {err}");

    // 拒绝的提交不落审批行。
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM ddl_approvals")
        .fetch_one(&pool)
        .await
        .expect("count approvals");
    assert_eq!(n, 0, "全部拒绝，无审批行");

    // 审计错误行无 SQL 明文。
    let rows = audit_rows(&pool).await;
    for (_, status, tool, err) in &rows {
        if status == "error" {
            let err = err.as_deref().unwrap_or("");
            assert!(!err.contains("CREATE TABLE"), "审计泄露 SQL 明文: {err}");
            assert!(!err.contains("m1"), "审计泄露表名: {err}");
        }
        let _ = tool;
    }

    let _ = std::fs::remove_file(&target);
}

// ── 主用例 ③：执行失败流转（DML 过执行器 DDL 白名单）+ 重试语义 ─────────

#[tokio::test]
async fn execution_failure_marks_failed_and_retry_is_refused() {
    let config = test_config(Vec::new());
    let pool = server_pool().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, "conn-a", "alpha", &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), KEY, test_entitlement());
    let token = token_for(&config, "user-a");
    let session = init_session(&app, &token).await;

    // DML 在 submit 侧合法（写类只记录不拦），执行器的 DDL 白名单拒。
    let submit = call_tool(
        &app, &session, &token, 2, "submit_write",
        serde_json::json!({
            "connection_id": "conn-a",
            "sql": "INSERT INTO t (id) VALUES (99)"
        }),
    ).await;
    assert_eq!(submit["risk"]["level"], "write");
    let approval_id = submit["approvalId"].as_str().expect("approvalId").to_string();

    human_approves(&pool, &approval_id).await;
    let executed = call_tool(
        &app, &session, &token, 3, "execute_write",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert_eq!(executed["execStatus"], "failed", "DML 被执行器拒: {executed}");
    assert!(
        executed["execError"].as_str().is_some_and(|e| !e.is_empty()),
        "失败带 execError: {executed}"
    );

    // 行内双列流转 failed（对齐 REST 状态机）；exec_error 落库。
    let (status, exec_status, exec_error, _) = approval_row(&pool, &approval_id).await;
    assert_eq!((status.as_str(), exec_status.as_str()), ("failed", "failed"));
    assert!(exec_error.is_some());

    // 重试：status 已 failed → APPROVAL_NOT_APPROVED（重新提交才是路径）。
    let err = call_tool_error(
        &app, &session, &token, 4, "execute_write",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert!(err.contains("APPROVAL_NOT_APPROVED"), "error text: {err}");

    // get_approval 透出 execError。
    let got = call_tool(
        &app, &session, &token, 5, "get_approval",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert_eq!(got["execStatus"], "failed");
    assert!(got["execError"].as_str().is_some());

    let _ = std::fs::remove_file(&target);
}

// =============================================================================
// T20 · 审批闭环 e2e：MCP 提交 → 真人经 REST approve（批准即执行）→ MCP 观察
// =============================================================================

use axum::extract::{Path, State};
use dbmaster_automation::handler::approve_approval;
use dbmaster_core::server::{AppState, DataSyncRunner, DriftRunner, HealthCheckRunner};

/// 测试用 Noop runner（main.rs 的 embedded 同款语义：本测试不触发调度器）。
macro_rules! noop_runner {
    ($name:ident, $trait:ident) => {
        struct $name;
        #[async_trait::async_trait]
        impl $trait for $name {
            async fn run(
                &self,
                _pool: &SqlitePool,
                _state: &AppState,
                _task_id: &str,
                _triggered_by: &str,
            ) -> Result<(), String> {
                Ok(())
            }
        }
    };
}
noop_runner!(NoopDrift, DriftRunner);
noop_runner!(NoopDataSync, DataSyncRunner);
noop_runner!(NoopHealthCheck, HealthCheckRunner);

/// 单连接内存库：approve 的 spawn 执行与主测试任务经同一连接串行，
/// 避免 :memory: 多连接各持独立库的隔离陷阱。
async fn server_pool_single_conn() -> SqlitePool {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("server pool");
    for ddl in [MCP_AUDIT_DDL, MCP_AUDIT_TOOL_DDL, CONNECTIONS_DDL, APPROVALS_DDL] {
        sqlx::raw_sql(ddl).execute(&pool).await.expect("ddl");
    }
    pool
}

fn core_state(config: &dbmaster_core::config::Config, pool: SqlitePool) -> AppState {
    AppState::new(
        pool,
        config.clone(),
        KEY,
        dbmaster_license::EntitlementState::Trial {
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        },
        "test-install".into(),
        std::sync::Arc::new(NoopDrift),
        std::sync::Arc::new(NoopDataSync),
        std::sync::Arc::new(NoopHealthCheck),
    )
}

/// T20 e2e：agent（user-a，MCP 面）提交 → 审批人（user-b，真 approve handler，
/// 批准即 spawn 执行）→ MCP get_approval 轮询到终态 → execute_write 幂等观察。
/// 审计断言：mcp_audit 有 submit/get/execute 的 tool_call 行。
#[tokio::test]
async fn t20_e2e_submit_rest_approve_observe() {
    let config = test_config(Vec::new());
    let pool = server_pool_single_conn().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, "conn-e2e", "e2e", &target).await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), KEY, test_entitlement());
    let token_agent = token_for(&config, "user-agent");
    let session = init_session(&app, &token_agent).await;

    // ① agent 提交一条真 DDL。
    let submit = call_tool(
        &app, &session, &token_agent, 1, "submit_write",
        serde_json::json!({
            "connection_id": "conn-e2e",
            "sql": "CREATE TABLE t20_e2e (id INTEGER PRIMARY KEY, name TEXT)"
        }),
    ).await;
    let approval_id = submit["approvalId"].as_str().expect("approvalId").to_string();

    // ② 审批人（user-b）走真 REST handler：原子认领 + spawn 执行。
    let reviewer_claims = dbmaster_core::auth::jwt::Claims {
        sub: "user-reviewer".into(),
        iat: 0,
        exp: usize::MAX,
        jti: "test-jti".into(),
    };
    let state = core_state(&config, pool.clone());
    let resp = approve_approval(reviewer_claims, State(state), Path(approval_id.clone())).await;
    assert!(resp.is_ok(), "rest approve should succeed: {resp:?}");

    // 重复批准：已非 pending → ALREADY_RESOLVED（REST 幂等守卫）。
    let reviewer_claims2 = dbmaster_core::auth::jwt::Claims {
        sub: "user-reviewer".into(),
        iat: 0,
        exp: usize::MAX,
        jti: "test-jti-2".into(),
    };
    let state2 = core_state(&config, pool.clone());
    let dup = approve_approval(reviewer_claims2, State(state2), Path(approval_id.clone())).await;
    assert!(dup.is_err(), "double approve must fail");

    // ③ agent 轮询 get_approval 至终态（spawn 执行 sqlite DDL，毫秒级）。
    let mut got = Value::Null;
    for _ in 0..100 {
        got = call_tool(
            &app, &session, &token_agent, 2, "get_approval",
            serde_json::json!({ "approval_id": approval_id }),
        ).await;
        let terminal = matches!(
            got["execStatus"].as_str(),
            Some("approved") | Some("failed")
        );
        if terminal {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(got["execStatus"], "approved", "terminal state: {got}");
    assert_eq!(got["status"], "approved", "row status: {got}");

    // ④ execute_write 幂等观察者：REST 已执行 → 返回现态不重复执行。
    let executed = call_tool(
        &app, &session, &token_agent, 3, "execute_write",
        serde_json::json!({ "approval_id": approval_id }),
    ).await;
    assert_eq!(executed["execStatus"], "approved", "idempotent observe: {executed}");

    // ⑤ 行级断言：审批人落库 + resolved_at；副作用只发生一次（表存在）。
    let row: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT reviewer_id, resolved_at FROM ddl_approvals WHERE id = ?1",
    )
    .bind(&approval_id)
    .fetch_one(&pool)
    .await
    .expect("approval row");
    assert_eq!(row.0.as_deref(), Some("user-reviewer"));
    assert!(row.1.is_some(), "resolved_at set by approve");

    let target_check = SqlitePool::connect(&format!("sqlite:{}", target)).await.unwrap();
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='t20_e2e'",
    )
    .fetch_one(&target_check)
    .await
    .expect("target master");
    target_check.close().await;
    assert_eq!(count.0, 1, "DDL executed exactly once (table exists)");

    // ⑥ 审计：MCP 面 tool_call 行（submit/get/execute），无 SQL 明文。
    let tools: Vec<(String,)> = sqlx::query_as(
        "SELECT tool FROM mcp_audit WHERE action='tool_call' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("mcp_audit rows");
    let names: Vec<&str> = tools.iter().map(|t| t.0.as_str()).collect();
    assert!(names.contains(&"submit_write"), "audit tools: {names:?}");
    assert!(names.contains(&"get_approval"), "audit tools: {names:?}");
    assert!(names.contains(&"execute_write"), "audit tools: {names:?}");

    let _ = std::fs::remove_file(&target);
}

// ── D1（2026-08-27 拍板：写门读放）——Gated 实例的门控行为 ──────────

/// Gated（Trial 到期）实例：会话可建立、读工具可用、`get_approval` 走正常
/// NOT_FOUND（visible-but-locked）；`submit_write`/`execute_write` 返回静态
/// ENTITLEMENT_GATED 文案且不落审批行。随后热换 entitlement 到 Trial——
/// **同一会话**的写工具立即放行（ArcSwap 运行时语义，`POST /api/license`
/// 激活后无需重连）。
#[tokio::test]
async fn d1_gated_blocks_write_tools_reads_pass() {
    let config = test_config(Vec::new());
    let pool = server_pool().await;
    let target = target_sqlite_db().await;
    register_connection(&pool, "conn-gated", "gated-target", &target).await;

    let entitlement = std::sync::Arc::new(arc_swap::ArcSwap::from(std::sync::Arc::new(
        dbmaster_license::EntitlementState::Gated {
            reason: dbmaster_license::GatedReason::TrialExpired,
        },
    )));
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), KEY, entitlement.clone());
    let token = token_for(&config, "user-gated");

    // 会话级不设门：initialize 正常（AI agent 可发现工具面）。
    let session = init_session(&app, &token).await;

    // 读面放行：list_connections 可见目标连接。
    let conns = call_tool(&app, &session, &token, 2, "list_connections", serde_json::json!({})).await;
    let list = conns["connections"].as_array().expect("connections array");
    assert_eq!(list.len(), 1, "read tool under Gated: {conns}");
    assert_eq!(list[0]["id"], "conn-gated");

    // 读面放行：read_query SELECT 走通目标库。
    call_tool(
        &app, &session, &token, 3, "read_query",
        serde_json::json!({
            "connection_id": "conn-gated",
            "sql": "SELECT count(*) AS n FROM t"
        }),
    ).await;

    // 写门：submit_write 拒——静态文案（无连接 id / SQL 明文插值）。
    let err = call_tool_error(
        &app, &session, &token, 4, "submit_write",
        serde_json::json!({
            "connection_id": "conn-gated",
            "sql": "CREATE TABLE gated_should_not_land (id INTEGER)"
        }),
    ).await;
    assert!(err.contains("ENTITLEMENT_GATED"), "error text: {err}");
    assert!(!err.contains("conn-gated") && !err.contains("CREATE TABLE"), "static text: {err}");

    // 写门：execute_write 拒——先于审批行存在性检查（不回显 NOT_FOUND）。
    let err2 = call_tool_error(
        &app, &session, &token, 5, "execute_write",
        serde_json::json!({ "approval_id": "any-id" }),
    ).await;
    assert!(err2.contains("ENTITLEMENT_GATED"), "error text: {err2}");

    // get_approval 放行（visible-but-locked）：未知 id 走正常 NOT_FOUND
    // 而非门控错误——证明读面未被门住。
    let err3 = call_tool_error(
        &app, &session, &token, 6, "get_approval",
        serde_json::json!({ "approval_id": "no-such" }),
    ).await;
    assert!(err3.contains("NOT_FOUND"), "error text: {err3}");

    // submit 被门拦在落库之前：审批表零行。
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM ddl_approvals")
        .fetch_one(&pool)
        .await
        .expect("count approvals");
    assert_eq!(n, 0, "no approval row should land under Gated");

    // 热换（等价 POST /api/license 激活）：Trial 态入库后同一会话写工具
    // 立即放行——门读的是 ArcSwap 当前值，不是会话建立时的快照。
    entitlement.store(std::sync::Arc::new(dbmaster_license::EntitlementState::Trial {
        expires_at: chrono::Utc::now() + chrono::Duration::days(14),
    }));
    let submit = call_tool(
        &app, &session, &token, 7, "submit_write",
        serde_json::json!({
            "connection_id": "conn-gated",
            "sql": "CREATE TABLE gated_after_swap (id INTEGER)"
        }),
    ).await;
    assert_eq!(submit["status"], "pending", "write passes after entitlement swap: {submit}");
    assert!(submit["approvalId"].as_str().is_some(), "approvalId returned: {submit}");

    // 清理目标库临时文件（Windows 上可删）。
    let _ = std::fs::remove_file(&target);
}
