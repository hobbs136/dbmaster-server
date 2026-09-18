//! MCP 端点集成测试（T03 握手 + T04 认证/限流/审计）。
//!
//! 走原始 JSON-RPC over HTTP（tower oneshot），不依赖 rmcp 客户端传输——
//! 骨架阶段验证协议层与传输层安全本身，客户端实配（Claude Code/Cursor）在 T09。

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

// 真实 migration 文件建表——顺带验证 011/013 的 DDL 可执行（schema 漂移会让测试挂）。
const MCP_AUDIT_DDL: &str = include_str!("../../../migrations/011_mcp_audit.sql");
const MCP_AUDIT_TOOL_DDL: &str = include_str!("../../../migrations/013_mcp_audit_tool.sql");

fn test_config(rate_limit: u32) -> Arc<Config> {
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
        mcp_rate_limit_per_minute: rate_limit,
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

async fn test_pool() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.expect("test pool");
    sqlx::raw_sql(MCP_AUDIT_DDL).execute(&pool).await.expect("apply 011 migration");
    sqlx::raw_sql(MCP_AUDIT_TOOL_DDL).execute(&pool).await.expect("apply 013 migration");
    pool
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
            "clientInfo": { "name": "t04-auth-test", "version": "0.0.0" }
        }),
    )
}

async fn post(
    app: &axum::Router,
    body: String,
    session: Option<&str>,
    auth: Option<&str>,
) -> (StatusCode, Option<String>, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        // rmcp 的 StreamableHttpService 依赖 Host/authority 解析会话与来源校验；
        // oneshot 测试不会自动带 Host（真实 HTTP 客户端总会带），需显式补。
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        // Streamable HTTP 规范：Accept 必须同时允许 JSON 与 SSE。
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(sid) = session {
        builder = builder.header("mcp-session-id", sid);
    }
    if let Some(token) = auth {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
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
    let bytes = resp.into_body().collect().await.expect("body read failed").to_bytes();
    // 响应可能是 application/json（单结果）、text/event-stream（SSE 帧）或
    // 空体（notifications/initialized 等通知类请求 → 202，无响应体）。
    let text = String::from_utf8_lossy(&bytes).to_string();
    let json: Value = if text.trim().is_empty() {
        Value::Null
    } else if text.trim_start().starts_with('{') {
        serde_json::from_str(&text).expect("JSON response body")
    } else {
        // SSE 首帧可能是空的 keep-alive（`data: \nid: 0\nretry: 3000`），
        // 真正的 JSON-RPC 消息在第一个非空 data 帧。
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

async fn audit_rows(pool: &SqlitePool) -> Vec<(Option<String>, String)> {
    // rowid 序 = 插入序（同一毫秒内 rfc3339 时间戳可能并列）。
    sqlx::query_as("SELECT user_id, action FROM mcp_audit ORDER BY rowid")
        .fetch_all(pool)
        .await
        .expect("read mcp_audit")
}

// ── T03 回归：带 token 的协议握手 ──────────────────────────────────────

#[tokio::test]
async fn initialize_then_ping_roundtrip() {
    let config = test_config(120);
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config.clone(), pool, [7u8; 32], test_entitlement());
    let token = token_for(&config, "user-t03");

    // ── initialize ──
    let (status, session_id, json) = post(&app, init_body(), None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "initialize should be 200, body: {json}");
    assert!(session_id.is_some(), "initialize must return Mcp-Session-Id");
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 1, "response id must echo request id");
    assert_eq!(json["result"]["serverInfo"]["name"], "dbmaster-server");
    assert!(
        !json["result"]["protocolVersion"].as_str().unwrap_or("").is_empty(),
        "negotiated protocolVersion must be present"
    );

    // ── notifications/initialized（无响应体；流式模式下服务端可返回 202/200）──
    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
    .to_string();
    let _ = post(&app, initialized, session_id.as_deref(), Some(&token)).await;

    // ── ping（带会话）──
    let ping_body = json_rpc(2, "ping", serde_json::json!({}));
    let (status, _, json) = post(&app, ping_body, session_id.as_deref(), Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "ping should be 200, body: {json}");
    // session id 只在 initialize 签发；后续请求携带即被接受（非 404）。
    assert_eq!(json["id"], 2);
    assert!(
        json["result"].is_object(),
        "ping result is an empty object per MCP spec"
    );
    assert!(json.get("error").is_none(), "ping must not error");
}

#[tokio::test]
async fn tools_list_exposes_tier1_metadata_surface() {
    let config = test_config(120);
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config.clone(), pool, [7u8; 32], test_entitlement());
    let token = token_for(&config, "user-t03");

    let (_, session_id, _) = post(&app, init_body(), None, Some(&token)).await;
    let list_body = json_rpc(
        2,
        "tools/list",
        serde_json::json!({ "cursor": null }),
    );
    let (status, _, json) = post(&app, list_body, session_id.as_deref(), Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    // T06+T07：4 个元数据工具 + read_query；T19：审批制写路径三工具。
    let tools = json["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "list_connections",
            "list_databases",
            "list_tables",
            "describe_table",
            "read_query",
            "submit_write",
            "get_approval",
            "execute_write",
        ]
    );
    for t in tools {
        assert!(t["description"].as_str().is_some_and(|d| !d.is_empty()));
        assert!(t["inputSchema"].is_object(), "input schema required");
    }
    // SEP-2549：ZCode 等严格客户端要求 ttlMs（数字）/ cacheScope 必填
    // （2026-08-16 实配发现——rmcp 默认构造会省略这两个字段）。
    assert!(
        json["result"]["ttlMs"].is_u64(),
        "ttlMs must be a number: {json}"
    );
    assert_eq!(json["result"]["cacheScope"], "public");
}

// ── T04：认证（401）───────────────────────────────────────────────────

#[tokio::test]
async fn missing_token_is_401_with_bearer_challenge_and_audited() {
    let config = test_config(120);
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config, pool.clone(), [7u8; 32], test_entitlement());

    let (status, _, json) = post(&app, init_body(), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {json}");
    assert_eq!(json["error"], "UNAUTHORIZED");

    // RFC 6750 §3：401 应带 WWW-Authenticate: Bearer 质询。
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(init_body()))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(
        resp.headers().get(header::WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()),
        Some("Bearer")
    );

    let rows = audit_rows(&pool).await;
    // 两次无 token 请求（断言用 + 质询头检查用）各落一行，均无 user_id。
    assert_eq!(
        rows,
        vec![
            (None, "auth_rejected".to_string()),
            (None, "auth_rejected".to_string()),
        ]
    );
}

#[tokio::test]
async fn invalid_token_is_401_and_audited() {
    let config = test_config(120);
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [7u8; 32], test_entitlement());

    // 用同一 secret 签发后篡改 → 验签失败。
    let token = token_for(&config, "user-a");
    let tampered = format!("{}x", token);
    let (status, _, json) = post(&app, init_body(), None, Some(&tampered)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {json}");

    let rows = audit_rows(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], (None, "auth_rejected".to_string()));
}

#[tokio::test]
async fn token_signed_with_other_secret_is_401() {
    let config = test_config(120);
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config, pool, [7u8; 32], test_entitlement());

    // 另一把密钥签的 token（模拟跨实例/伪造）。
    let mut other = (*test_config(120)).clone();
    other.jwt_secret = "a-completely-different-secret".into();
    let foreign = token_for(&other, "user-a");
    let (status, _, _) = post(&app, init_body(), None, Some(&foreign)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ── T04：限流（429）───────────────────────────────────────────────────

#[tokio::test]
async fn rate_limit_returns_429_and_audited_per_user() {
    let config = test_config(2); // 每用户每分钟 2 次
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [7u8; 32], test_entitlement());
    let token_a = token_for(&config, "user-a");
    let token_b = token_for(&config, "user-b");

    // user-a：前 2 次过 guard（协议层 200），第 3 次 429。
    let (s1, _, _) = post(&app, init_body(), None, Some(&token_a)).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _, _) = post(&app, init_body(), None, Some(&token_a)).await;
    assert_eq!(s2, StatusCode::OK);
    let (s3, _, json) = post(&app, init_body(), None, Some(&token_a)).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS, "body: {json}");
    assert_eq!(json["error"], "RATE_LIMITED");

    // user-b 不受 user-a 窗口影响（per-user 隔离）。
    let (sb, _, _) = post(&app, init_body(), None, Some(&token_b)).await;
    assert_eq!(sb, StatusCode::OK);

    let rows = audit_rows(&pool).await;
    assert_eq!(
        rows,
        vec![(Some("user-a".to_string()), "rate_limited".to_string())],
        "only the 429 rejection is audited (accepted requests are not): {rows:?}"
    );
}

// ── T04：审计（会话关闭）──────────────────────────────────────────────

#[tokio::test]
async fn session_close_is_audited_with_user() {
    let config = test_config(120);
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [7u8; 32], test_entitlement());
    let token = token_for(&config, "user-close");

    let (_, session_id, _) = post(&app, init_body(), None, Some(&token)).await;
    let sid = session_id.expect("initialize returns session id");

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/mcp")
                .header(header::HOST, "localhost")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header("mcp-session-id", &sid)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("DELETE session");
    // rmcp 对 DELETE 的具体状态码（200/404 视会话状态）不是 T04 的关注点；
    // 这里只保证中间件先于服务执行完毕。
    let _ = resp.status();

    let rows = audit_rows(&pool).await;
    assert_eq!(
        rows,
        vec![(Some("user-close".to_string()), "session_close".to_string())]
    );
}
