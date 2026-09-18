//! 长效 MCP 专用 token 生命周期集成测试（用户拍板 2026-08-15：长效、可删除）。
//!
//! 覆盖：创建（明文只返一次）→ 持有者鉴权打通 `/mcp` → 列表不泄密 →
//! 吊销后 401 → 跨用户删除 404 → 审计行（token_created / token_revoked）。

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

const USERS_DDL: &str = include_str!("../../../migrations/001_initial.sql");
const MCP_AUDIT_DDL: &str = include_str!("../../../migrations/011_mcp_audit.sql");
// 013 — tool 列（T06 tool_call 审计行使用；audit INSERT 显式列名，缺失会失败）。
const MCP_AUDIT_TOOL_DDL: &str = include_str!("../../../migrations/013_mcp_audit_tool.sql");
const MCP_TOKENS_DDL: &str = include_str!("../../../migrations/012_mcp_tokens.sql");

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

async fn test_pool() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.expect("test pool");
    sqlx::raw_sql(USERS_DDL).execute(&pool).await.expect("apply 001");
    sqlx::raw_sql(MCP_AUDIT_DDL).execute(&pool).await.expect("apply 011");
    sqlx::raw_sql(MCP_AUDIT_TOOL_DDL).execute(&pool).await.expect("apply 013");
    sqlx::raw_sql(MCP_TOKENS_DDL).execute(&pool).await.expect("apply 012");
    // mcp_tokens.user_id has an FK to users; seed one row per test user.
    for (id, email) in [("user-a", "a@test.local"), ("user-b", "b@test.local")] {
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, display_name)
             VALUES (?1, ?2, 'x', ?3)",
        )
        .bind(id)
        .bind(email)
        .bind(id)
        .execute(&pool)
        .await
        .expect("seed user");
    }
    pool
}

fn jwt_for(config: &Config, user_id: &str) -> String {
    issue_access_token(config, user_id).expect("mint jwt")
}

async fn req(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Option<String>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "localhost");
    if let Some(token) = auth {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(json)
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

async fn create_mcp_token(app: &axum::Router, config: &Config, user: &str) -> (String, Value) {
    let jwt = jwt_for(config, user);
    let (status, json) = req(
        app,
        "POST",
        "/api/mcp/tokens",
        Some(&jwt),
        Some(r#"{"name":"claude-code"}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create token: {json}");
    let plaintext = json["data"]["token"].as_str().expect("token in response").to_string();
    assert!(plaintext.starts_with("dbm_mcp_"), "prefix: {plaintext}");
    (plaintext, json["data"].clone())
}

async fn audit_actions(pool: &SqlitePool) -> Vec<(Option<String>, String)> {
    sqlx::query_as("SELECT user_id, action FROM mcp_audit ORDER BY rowid")
        .fetch_all(pool)
        .await
        .expect("read mcp_audit")
}

fn init_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "token-lifecycle-test", "version": "0.0.0" }
        }
    })
    .to_string()
}

#[tokio::test]
async fn token_lifecycle_create_use_revoke() {
    let config = test_config();
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config.clone(), pool.clone(), [7u8; 32], test_entitlement());
    let jwt = jwt_for(&config, "user-a");

    // ── 创建：明文只出现一次，name 回显（envelope data 内）──
    let (plaintext, created) = create_mcp_token(&app, &config, "user-a").await;
    assert_eq!(created["name"], "claude-code");
    let id = created["id"].as_str().expect("id").to_string();

    // ── 用长效 token 打 /mcp：guard 接受，initialize 200 ──
    let (status, _, json) = mcp_post(&app, &plaintext).await;
    assert_eq!(status, StatusCode::OK, "initialize with mcp token: {json}");

    // ── last_used_at 已更新 ──
    let last_used: Option<String> =
        sqlx::query_scalar("SELECT last_used_at FROM mcp_tokens WHERE id = ?1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("row exists");
    assert!(last_used.is_some(), "last_used_at stamped on use");

    // ── 列表：只有 prefix，无明文/hash（envelope data 内）──
    let (status, list) = req(&app, "GET", "/api/mcp/tokens", Some(&jwt), None).await;
    assert_eq!(status, StatusCode::OK);
    let arr = list["data"].as_array().expect("data array");
    assert_eq!(arr.len(), 1);
    let entry = &arr[0];
    assert_eq!(entry["id"], id.as_str());
    assert!(entry["token_prefix"].as_str().unwrap_or("").starts_with("dbm_mcp_"));
    assert!(
        entry.get("token").is_none() && entry.get("token_hash").is_none(),
        "list must not leak token material: {entry}"
    );

    // ── 吊销 → 200 envelope；再用 → 401（吊销立即生效）──
    let (status, body) = req(&app, "DELETE", &format!("/api/mcp/tokens/{id}"), Some(&jwt), None).await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");
    assert_eq!(body["data"]["revoked"], true);
    let (status, _, _) = mcp_post(&app, &plaintext).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked token must 401");

    // ── 吊销后列表为空 ──
    let (_, list) = req(&app, "GET", "/api/mcp/tokens", Some(&jwt), None).await;
    assert_eq!(list["data"].as_array().map(Vec::len), Some(0));

    // ── 审计：created + revoked（管理事件），加上吊销后那次 401 使用尝试 ──
    let actions = audit_actions(&pool).await;
    assert_eq!(
        actions,
        vec![
            (Some("user-a".to_string()), "token_created".to_string()),
            (Some("user-a".to_string()), "token_revoked".to_string()),
            (None, "auth_rejected".to_string()),
        ]
    );
}

#[tokio::test]
async fn other_user_cannot_revoke_and_gets_404() {
    let config = test_config();
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config.clone(), pool, [7u8; 32], test_entitlement());

    let (_, created) = create_mcp_token(&app, &config, "user-a").await;
    let id = created["id"].as_str().expect("id");

    // user-b 删 user-a 的 token → 404（不泄露存在性）。
    let jwt_b = jwt_for(&config, "user-b");
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/mcp/tokens/{id}"),
        Some(&jwt_b),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // token 仍然可用（未被他人吊销）。
    let plaintext = created["token"].as_str().expect("token").to_string();
    let (status, _, _) = mcp_post(&app, &plaintext).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn management_requires_jwt_and_rejects_mcp_token() {
    let config = test_config();
    let pool = test_pool().await;
    let app = dbmaster_mcp::router(config.clone(), pool, [7u8; 32], test_entitlement());

    // 无凭证 → 401。
    let (status, _) = req(&app, "GET", "/api/mcp/tokens", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 用 MCP token 反向调管理接口 → 401（管理面只认 access JWT；
    // MCP token 仅用于 /mcp，权限最小化）。
    let (plaintext, _) = create_mcp_token(&app, &config, "user-a").await;
    let (status, _) = req(&app, "GET", "/api/mcp/tokens", Some(&plaintext), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

async fn mcp_post(app: &axum::Router, token: &str) -> (StatusCode, Option<String>, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(init_body()))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = resp.status();
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let text = String::from_utf8_lossy(&resp.into_body().collect().await.expect("body").to_bytes())
        .to_string();
    let json: Value = if text.trim().is_empty() {
        Value::Null
    } else if text.trim_start().starts_with('{') {
        serde_json::from_str(&text).expect("json body")
    } else {
        let data = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .find(|d| !d.is_empty())
            .unwrap_or("");
        serde_json::from_str(data).unwrap_or(Value::Null)
    };
    (status, sid, json)
}
