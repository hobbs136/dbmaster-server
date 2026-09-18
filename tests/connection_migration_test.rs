//! ADR-0003 S3 — connection migration (keychain → server) contract tests.
//!
//! Verifies the server-side half of S3:
//! - `POST /api/connections` accepts the extended client fields (migration 008)
//!   and round-trips them through `GET /api/connections`.
//! - SSH credentials are encrypted at rest and returned decrypted via the
//!   embedded-only `GET /api/connections/:id/credential` endpoint.
//! - The credential endpoint refuses with `NOT_EMBEDDED` when the app is built
//!   in normal (remote) mode — the plaintext-credential policy gate.
//! - Credential-key persistence (S3 design A): the embedded server loads a
//!   stable key so connections survive restarts. Tested at the key-helper level.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dbmaster_core::config::Config;
use dbmaster_core::server::{DataSyncRunner, DriftRunner, HealthCheckRunner};
use dbmaster_license::EntitlementState;
use sqlx::SqlitePool;
use tower::ServiceExt;

// ── Local no-op runners (the shared `common::Noop*` are private). ──
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

fn licensed_entitlement() -> EntitlementState {
    use dbmaster_license::LicenseV2;
    EntitlementState::Licensed {
        license: LicenseV2 {
            email: "embedded@local".into(),
            expires_at: None,
            instance_id: "test-install".into(),
            issued_at: chrono::Utc::now().to_rfc3339(),
            license_type: "embedded".into(),
        },
        expires_at: None,
    }
}

fn test_config() -> Config {
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

/// Build an app in the given mode and a token for the embedded single user.
async fn build_app_and_token(embedded: bool) -> (axum::Router, String, SqlitePool) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();
    let config = test_config();
    let install_uuid = "test-install-uuid".to_string();
    let entitlement = licensed_entitlement();

    // Issue a token for the embedded user (same path main.rs uses).
    let (_uid, access, _refresh) =
        dbmaster_core::user::handler::ensure_embedded_user_and_tokens(&pool, &config)
            .await
            .unwrap();

    let runner: Arc<dyn DriftRunner> = Arc::new(NoopDrift);
    let ds: Arc<dyn DataSyncRunner> = Arc::new(NoopDs);
    let hc: Arc<dyn HealthCheckRunner> = Arc::new(NoopHc);
    let app = dbmaster_server::build_app_with_config(
        pool.clone(), config, [0u8; 32], entitlement, install_uuid, runner, ds, hc, embedded,
    );
    (app, access, pool)
}

/// Create a connection with the full extended-field set; return the created id.
async fn create_full_connection(app: &axum::Router, token: &str) -> String {
    let body = serde_json::json!({
        "name": "mysql-prod",
        "db_type": "mysql",
        "host": "10.0.0.5",
        "port": 3306,
        "username": "dba",
        "password": "s3cret-pw",
        "default_database": "shop",
        "use_ssl": true,
        "timeout_seconds": 45,
        "auto_reconnect": true,
        "charset": "utf8mb4",
        "timezone": "UTC",
        "environment": "production",
        "read_only": false,
        "group_id": "g1",
        "extra": "{\"poolSize\":10}",
        "ssh_enabled": true,
        "ssh_host": "bastion",
        "ssh_port": 22,
        "ssh_username": "tunnel",
        "ssh_auth_mode": "password",
        "ssh_password": "ssh-pw",
        "kind": "collab"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/connections")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ok"], true, "create failed: {v}");
    v["data"]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn extended_fields_round_trip_through_list() {
    let (app, token, _pool) = build_app_and_token(true).await;
    let id = create_full_connection(&app, &token).await;

    // GET /api/connections — all extended fields must be present.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/connections")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let row = v["data"].as_array().unwrap().iter().find(|r| r["id"] == id).unwrap();
    assert_eq!(row["use_ssl"], true);
    assert_eq!(row["timeout_seconds"], 45);
    assert_eq!(row["auto_reconnect"], true);
    assert_eq!(row["charset"], "utf8mb4");
    assert_eq!(row["timezone"], "UTC");
    assert_eq!(row["environment"], "production");
    assert_eq!(row["read_only"], false);
    assert_eq!(row["group_id"], "g1");
    assert_eq!(row["extra"], "{\"poolSize\":10}");
    assert_eq!(row["ssh_username"], "tunnel");
    assert_eq!(row["ssh_auth_mode"], "password");
    // password_encrypted must be the ciphertext blob, not plaintext.
    assert!(row["password_encrypted"].as_str().unwrap().starts_with("v1:"));
    assert!(row["ssh_password_encrypted"].as_str().unwrap().starts_with("v1:"));
}

#[tokio::test]
async fn credential_endpoint_returns_plaintext_in_embedded_mode() {
    let (app, token, _pool) = build_app_and_token(true).await;
    let id = create_full_connection(&app, &token).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/connections/{id}/credential"))
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ok"], true, "credential fetch failed: {v}");
    assert_eq!(v["data"]["password"], "s3cret-pw");
    assert_eq!(v["data"]["ssh_username"], "tunnel");
    assert_eq!(v["data"]["ssh_password"], "ssh-pw");
    assert_eq!(v["data"]["ssh_auth_mode"], "password");
    // privateKey/passphrase were never sent → null.
    assert!(v["data"]["ssh_private_key"].is_null());
    assert!(v["data"]["ssh_passphrase"].is_null());
}

#[tokio::test]
async fn credential_endpoint_refuses_in_remote_mode() {
    // Build the app in NORMAL (remote) mode — embedded_mode = false.
    let (app, token, _pool) = build_app_and_token(false).await;
    let id = create_full_connection(&app, &token).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/connections/{id}/credential"))
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // The policy gate must refuse even though auth succeeded.
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "NOT_EMBEDDED");
}

#[tokio::test]
async fn credential_endpoint_404_for_unknown_id() {
    let (app, token, _pool) = build_app_and_token(true).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/connections/does-not-exist/credential")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"]["code"], "NOT_FOUND");
}
