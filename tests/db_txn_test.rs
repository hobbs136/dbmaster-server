//! ADR-0003 S10 — transaction endpoint tests.
//!
//! Exercises the SQLite path (the only one runnable without a live
//! mysql/postgres in CI): begin → query → commit / rollback, plus the error
//! paths (unsupported db_type, unknown session, double-commit). The handler
//! shapes are identical across dialects; dialect-specific BEGIN syntax is
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

/// Seed a SQLite connection row pointing at a temp file with a `counter`
/// table. Returns the connection id.
async fn seed_sqlite_connection(pool: &SqlitePool, created_by: &str, tag: &str) -> String {
    use sqlx::Executor;
    let dir = std::env::temp_dir().join(format!("s10-txn-{}-{tag}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("target.db");
    let _ = std::fs::remove_file(&path);
    let target_url = format!("sqlite:{}?mode=rwc", path.display());
    let tpool = SqlitePool::connect(&target_url).await.unwrap();
    tpool.execute("CREATE TABLE counter (n INTEGER)").await.unwrap();
    tpool.close().await;

    let id = format!("conn-s10-{tag}");
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
async fn begin_query_commit_persists() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "commit").await;

    // BEGIN
    let (s, v) = post(&app, &token, &format!("/api/db/{conn_id}/txn/begin"), serde_json::json!({})).await;
    assert_eq!(s, StatusCode::OK, "begin body: {v}");
    let session_id = v["data"]["sessionId"].as_str().expect("sessionId present").to_string();

    // INSERT inside the transaction
    let (s, v) = post(
        &app, &token,
        &format!("/api/db/{conn_id}/txn/{session_id}/query"),
        serde_json::json!({ "sql": "INSERT INTO counter VALUES (1)" }),
    ).await;
    assert_eq!(s, StatusCode::OK, "insert body: {v}");

    // COMMIT
    let (s, v) = post(&app, &token, &format!("/api/db/{conn_id}/txn/{session_id}/commit"), serde_json::json!({})).await;
    assert_eq!(s, StatusCode::OK, "commit body: {v}");
    assert_eq!(v["data"]["committed"], true);

    // Verify the row persisted by reading via the stateless query endpoint
    // (opens a fresh connection; the txn session is gone).
    let (s, v) = post(
        &app, &token,
        &format!("/api/db/{conn_id}/query"),
        serde_json::json!({ "sql": "SELECT n FROM counter" }),
    ).await;
    assert_eq!(s, StatusCode::OK, "verify body: {v}");
    let rows = v["data"]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "committed row should be visible");
}

#[tokio::test]
async fn begin_query_rollback_discards() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "rollback").await;

    let (_, v) = post(&app, &token, &format!("/api/db/{conn_id}/txn/begin"), serde_json::json!({})).await;
    let session_id = v["data"]["sessionId"].as_str().unwrap().to_string();

    // INSERT inside the txn
    post(
        &app, &token,
        &format!("/api/db/{conn_id}/txn/{session_id}/query"),
        serde_json::json!({ "sql": "INSERT INTO counter VALUES (42)" }),
    ).await;

    // ROLLBACK
    let (s, v) = post(&app, &token, &format!("/api/db/{conn_id}/txn/{session_id}/rollback"), serde_json::json!({})).await;
    assert_eq!(s, StatusCode::OK, "rollback body: {v}");
    assert_eq!(v["data"]["rolledBack"], true);

    // The row should NOT be visible — rollback discarded it.
    let (s, v) = post(
        &app, &token,
        &format!("/api/db/{conn_id}/query"),
        serde_json::json!({ "sql": "SELECT n FROM counter" }),
    ).await;
    assert_eq!(s, StatusCode::OK, "verify body: {v}");
    let rows = v["data"]["rows"].as_array().unwrap();
    assert!(rows.is_empty(), "rolled-back row must not be visible");
}

#[tokio::test]
async fn unknown_session_query_fails() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "unknown").await;

    let (s, v) = post(
        &app, &token,
        &format!("/api/db/{conn_id}/txn/no-such-session/query"),
        serde_json::json!({ "sql": "SELECT 1" }),
    ).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "body: {v}");
    assert_eq!(v["ok"], false);
}

#[tokio::test]
async fn double_commit_second_fails() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "double").await;

    let (_, v) = post(&app, &token, &format!("/api/db/{conn_id}/txn/begin"), serde_json::json!({})).await;
    let session_id = v["data"]["sessionId"].as_str().unwrap().to_string();

    // First commit succeeds and removes the session.
    let (s, _) = post(&app, &token, &format!("/api/db/{conn_id}/txn/{session_id}/commit"), serde_json::json!({})).await;
    assert_eq!(s, StatusCode::OK);

    // Second commit on the now-removed session must fail.
    let (s, v) = post(&app, &token, &format!("/api/db/{conn_id}/txn/{session_id}/commit"), serde_json::json!({})).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "body: {v}");
}

#[tokio::test]
async fn begin_unsupported_db_type_rejected() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;

    // Seed a ClickHouse connection row (no live server needed — begin rejects
    // on db_type before opening any pool).
    let id = "conn-s10-clickhouse";
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO database_connections (id, name, db_type, host, port, username,
         password_encrypted, created_by, created_at, kind)
         VALUES (?, 'ch', 'clickhouse', 'ch', 9000, 'default', 'enc:', ?, ?, 'collab')",
    )
    .bind(id)
    .bind(&uid)
    .bind(&now)
    .execute(&pool)
    .await
    .unwrap();

    let (s, v) = post(&app, &token, &format!("/api/db/{id}/txn/begin"), serde_json::json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "body: {v}");
    assert_eq!(v["error"]["code"], "UNSUPPORTED_TXN");
}
