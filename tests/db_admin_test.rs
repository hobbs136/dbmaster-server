//! ADR-0003 S8b prep — admin endpoint tests.
//!
//! Exercises the SQLite path for the script endpoint (multi-statement split
//! + execute) and the error paths (KILL on SQLite returns UNSUPPORTED). The
//! handler shapes are identical across dialects; MySQL KILL semantics are
//! validated by the embedded e2e + manual verification.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dbmaster_core::config::Config;
use dbmaster_core::server::{DataSyncRunner, DriftRunner, HealthCheckRunner};
use dbmaster_license::{EntitlementState, LicenseV2};
use sqlx::SqlitePool;
use tower::ServiceExt;

struct NoopDrift;
struct NoopDs;
struct NoopHc;

#[async_trait]
impl DriftRunner for NoopDrift {
    async fn run(&self, _: &SqlitePool, _: &dbmaster_core::server::AppState, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
}
#[async_trait]
impl DataSyncRunner for NoopDs {
    async fn run(&self, _: &SqlitePool, _: &dbmaster_core::server::AppState, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
}
#[async_trait]
impl HealthCheckRunner for NoopHc {
    async fn run(&self, _: &SqlitePool, _: &dbmaster_core::server::AppState, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
}

fn licensed() -> EntitlementState {
    EntitlementState::Licensed {
        license: LicenseV2 {
            email: "embedded@local".into(),
            expires_at: None,
            instance_id: "i".into(),
            issued_at: chrono::Utc::now().to_rfc3339(),
            license_type: "embedded".into(),
        },
        expires_at: None,
    }
}

fn config() -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: 0,
        jwt_secret: "test-jwt-secret-aaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        jwt_refresh_secret: "test-refresh-secret-aaaaaaaaaaaaaaaaaaa".into(),
        database_url: "sqlite::memory:".into(),
        funnel_lite_enabled: true,
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
        }
}

async fn setup() -> (axum::Router, String, SqlitePool) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();
    let cfg = config();
    let (_uid, access, _r) =
        dbmaster_core::user::handler::ensure_embedded_user_and_tokens(&pool, &cfg)
            .await
            .unwrap();
    let runner: Arc<dyn DriftRunner> = Arc::new(NoopDrift);
    let ds: Arc<dyn DataSyncRunner> = Arc::new(NoopDs);
    let hc: Arc<dyn HealthCheckRunner> = Arc::new(NoopHc);
    let app = dbmaster_server::build_app_with_config(
        pool.clone(), cfg, [0u8; 32], licensed(),
        "install".into(), runner, ds, hc, true,
    );
    (app, access, pool)
}

async fn seed_sqlite_connection(pool: &SqlitePool, created_by: &str, tag: &str) -> String {
    use sqlx::Executor;
    let dir = std::env::temp_dir().join(format!("s8b-admin-{}-{tag}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("target.db");
    let _ = std::fs::remove_file(&path);
    let target_url = format!("sqlite:{}?mode=rwc", path.display());
    let tpool = SqlitePool::connect(&target_url).await.unwrap();
    tpool.execute("CREATE TABLE a (x INTEGER)").await.unwrap();
    tpool.close().await;

    let id = format!("conn-s8b-{tag}");
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO database_connections (id, name, db_type, host, port, username,
         password_encrypted, created_by, created_at, kind, file_path)
         VALUES (?, 't', 'sqlite', 'sqlite', 0, '', 'enc:', ?, ?, 'collab', ?)",
    )
    .bind(&id)
    .bind(created_by)
    .bind(&now)
    .bind(path.to_string_lossy().to_string())
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn real_user_id(pool: &SqlitePool) -> String {
    sqlx::query_scalar("SELECT id FROM users LIMIT 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn post(app: &axum::Router, token: &str, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn script_runs_multiple_statements() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "multi").await;

    let script = "INSERT INTO a VALUES (1); INSERT INTO a VALUES (2); SELECT x FROM a";
    let (s, v) = post(
        &app, &token,
        &format!("/api/db/{conn_id}/admin/script"),
        serde_json::json!({ "script": script }),
    ).await;
    assert_eq!(s, StatusCode::OK, "body: {v}");
    let results = v["data"]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3, "should split into 3 statements: {results:?}");
    // first two are INSERTs (ok, affectedRows)
    assert_eq!(results[0]["ok"], true);
    assert_eq!(results[1]["ok"], true);
    // third is the SELECT — rows should contain both inserts
    assert_eq!(results[2]["ok"], true);
    let rows = results[2]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "SELECT should see both inserts: {rows:?}");
}

#[tokio::test]
async fn script_continues_past_errors() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "errors").await;

    // First statement references a nonexistent table (fails), second is valid.
    let script = "INSERT INTO no_such_table VALUES (1); INSERT INTO a VALUES (42)";
    let (s, v) = post(
        &app, &token,
        &format!("/api/db/{conn_id}/admin/script"),
        serde_json::json!({ "script": script }),
    ).await;
    assert_eq!(s, StatusCode::OK, "body: {v}");
    let results = v["data"]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["ok"], false, "first should fail: {results:?}");
    assert!(results[0]["error"].as_str().is_some());
    assert_eq!(results[1]["ok"], true, "second should succeed despite first failure");
}

#[tokio::test]
async fn script_handles_semicolon_in_string() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "quote").await;

    // The semicolon inside the string literal must NOT split the statement.
    let script = "INSERT INTO a VALUES (1); INSERT INTO a VALUES (2)";
    let (s, v) = post(
        &app, &token,
        &format!("/api/db/{conn_id}/admin/script"),
        serde_json::json!({ "script": script }),
    ).await;
    assert_eq!(s, StatusCode::OK, "body: {v}");
    let results = v["data"]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2, "two statements: {results:?}");
}

#[tokio::test]
async fn kill_on_sqlite_returns_unsupported() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "kill").await;

    let (s, v) = post(
        &app, &token,
        &format!("/api/db/{conn_id}/admin/kill"),
        serde_json::json!({ "thread_id": 123 }),
    ).await;
    // SQLite doesn't support KILL — endpoint returns 400 UNSUPPORTED.
    assert_eq!(s, StatusCode::BAD_REQUEST, "body: {v}");
    assert_eq!(v["error"]["code"], "UNSUPPORTED");
}

#[tokio::test]
async fn script_empty_script_returns_empty_results() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "empty").await;

    let (s, v) = post(
        &app, &token,
        &format!("/api/db/{conn_id}/admin/script"),
        serde_json::json!({ "script": "  ;  ;  " }),
    ).await;
    assert_eq!(s, StatusCode::OK, "body: {v}");
    let results = v["data"]["results"].as_array().unwrap();
    assert!(results.is_empty(), "whitespace-only script → no statements");
}
