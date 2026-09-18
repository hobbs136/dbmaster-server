//! ADR-0003 S5 — browse endpoint tests (views/procedures/functions/triggers/
//! indexes/foreign_keys).
//!
//! These exercise the SQLite path (the only one runnable without a live
//! mysql/postgres server in CI) plus the error paths (unsupported db_type,
//! missing connection). The handler shapes are identical across dialects, so
//! the SQLite cases validate the wiring; dialect-specific SQL is covered by
//! the embedded e2e + manual verification.

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

/// Build an embedded-mode app + token. Returns (app, token, pool) where the
/// pool is the server's own in-memory DB (so tests can seed a connection row
/// pointing at a file-backed sqlite the gateway will open).
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

/// Create a connection row whose file_path points at a temp sqlite file we
/// seed with schema (a base table + index + view + self-FK). Returns the
/// connection id. [tag] makes each test's file unique so parallel runs don't
/// collide on "table already exists".
async fn seed_sqlite_connection(pool: &SqlitePool, created_by: &str, tag: &str) -> String {
    use sqlx::Executor;
    let dir = std::env::temp_dir().join(format!("s5-browse-{}-{tag}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("target.db");
    let _ = std::fs::remove_file(&path);
    let target_url = format!("sqlite:{}?mode=rwc", path.display());
    let tpool = SqlitePool::connect(&target_url).await.unwrap();
    tpool.execute("CREATE TABLE base (id INTEGER PRIMARY KEY, ref_id INTEGER REFERENCES base(id))").await.unwrap();
    tpool.execute("CREATE INDEX idx_base_ref ON base(ref_id)").await.unwrap();
    tpool.execute("CREATE VIEW v_base AS SELECT id FROM base").await.unwrap();
    tpool.close().await;

    let id = format!("conn-s5-{tag}");
    let now = chrono::Utc::now().to_rfc3339();
    // password_encrypted uses the legacy `enc:` format so load_and_decrypt's
    // decrypt_password returns it without touching AES (SQLite ignores the
    // password anyway, but load_and_decrypt always decrypts before dispatch).
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

async fn get(app: &axum::Router, token: &str, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn list_views_returns_seeded_view() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "views").await;

    let (status, v) = get(&app, &token, &format!("/api/db/{conn_id}/views")).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(v["ok"], true);
    let names = v["data"].as_array().unwrap();
    assert!(names.iter().any(|n| n == "v_base"), "expected v_base in {names:?}");
}

#[tokio::test]
async fn list_indexes_returns_seeded_index() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "indexes").await;

    let (status, v) = get(&app, &token, &format!("/api/db/{conn_id}/indexes?table=base")).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    let names = v["data"].as_array().unwrap();
    assert!(names.iter().any(|n| n == "idx_base_ref"), "expected idx_base_ref in {names:?}");
}

#[tokio::test]
async fn list_foreign_keys_returns_synthesized_name() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "fks").await;

    let (status, v) = get(&app, &token, &format!("/api/db/{conn_id}/foreign_keys?table=base")).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    let names = v["data"].as_array().unwrap();
    assert!(names.iter().any(|n| n.as_str().unwrap_or("").starts_with("fk_base_")),
        "expected a fk_base_* name in {names:?}");
}

#[tokio::test]
async fn procedures_functions_triggers_empty_for_sqlite() {
    let (app, token, pool) = setup().await;
    let uid = real_user_id(&pool).await;
    let conn_id = seed_sqlite_connection(&pool, &uid, "empty").await;

    for kind in ["procedures", "functions", "triggers"] {
        let (status, v) = get(&app, &token, &format!("/api/db/{conn_id}/{kind}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["data"].as_array().unwrap().len(), 0, "{kind} should be empty for sqlite");
    }
}

#[tokio::test]
async fn browse_endpoint_missing_connection_returns_404_envelope() {
    let (app, token, _pool) = setup().await;
    let (status, v) = get(&app, &token, "/api/db/nonexistent-id/views").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error"]["code"], "CONNECTION_NOT_FOUND");
}
