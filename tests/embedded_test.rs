//! In-process tests for the ADR-0003 S2 embedded mode.
//!
//! These tests exercise the embedded-mode building blocks WITHOUT spawning a
//! real OS process (that's covered by `embedded_process_test.rs`):
//! - The synthesized lifetime-`Licensed` entitlement is not gated
//!   (`is_gated() == false`), so `db_query` write paths pass the gate.
//! - `ensure_embedded_user_and_tokens` is idempotent: first call creates the
//!   user row, second call reuses it; both return a valid token pair.
//! - An app built with `build_app_with_config` + the synthesized entitlement
//!   serves `/api/health` and accepts a token-issued write without returning
//!   `ENTITLEMENT_GATED`.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dbmaster_core::config::Config;
use dbmaster_core::server::{DataSyncRunner, DriftRunner, HealthCheckRunner};
use dbmaster_license::{EntitlementState, LicenseV2};
use sqlx::SqlitePool;
use tower::ServiceExt;

// Local no-op runners (the shared `common::Noop*` types are private). Keeping
// these local to this test file keeps `common` unchanged.
struct LocalNoopDriftRunner;
struct LocalNoopDataSyncRunner;
struct LocalNoopHealthCheckRunner;

#[async_trait]
impl DriftRunner for LocalNoopDriftRunner {
    async fn run(
        &self,
        _pool: &SqlitePool,
        _state: &dbmaster_core::server::AppState,
        _task_id: &str,
        _triggered_by: &str,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[async_trait]
impl DataSyncRunner for LocalNoopDataSyncRunner {
    async fn run(
        &self,
        _pool: &SqlitePool,
        _state: &dbmaster_core::server::AppState,
        _task_id: &str,
        _triggered_by: &str,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[async_trait]
impl HealthCheckRunner for LocalNoopHealthCheckRunner {
    async fn run(
        &self,
        _pool: &SqlitePool,
        _state: &dbmaster_core::server::AppState,
        _task_id: &str,
        _triggered_by: &str,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Construct the same synthesized entitlement `run_embedded` builds in main.rs.
// centralize the construction so tests + main.rs can't
/// drift apart.
fn embedded_entitlement(install_uuid: &str) -> EntitlementState {
    EntitlementState::Licensed {
        license: LicenseV2 {
            email: "embedded@local".to_string(),
            expires_at: None,
            instance_id: install_uuid.to_string(),
            issued_at: chrono::Utc::now().to_rfc3339(),
            license_type: "embedded".to_string(),
        },
        expires_at: None,
    }
}

/// The embedded entitlement must report as NOT gated — this is the whole point
/// of the synthesis: the free desktop tier must allow DBA write operations,
/// which the production ¥399/yr gate would block after the 14-day trial.
#[tokio::test]
async fn embedded_entitlement_is_not_gated() {
    let ent = embedded_entitlement("install-xyz");
    assert!(!ent.is_gated(), "embedded Licensed must not be gated");
    // lifetime license → no expiry banner, days_until_expiry None
    assert_eq!(ent.days_until_expiry(), None);
    assert!(ent.renewal_banner().is_none());
}

/// `ensure_embedded_user_and_tokens` creates the user on first call and reuses
/// it on subsequent calls (idempotent across restarts). Both calls must return
/// a usable token pair.
#[tokio::test]
async fn ensure_embedded_user_is_idempotent_across_restarts() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();

    let config = test_config();

    // First boot: creates the user.
    let (user_id_a, access_a, refresh_a) =
        dbmaster_core::user::handler::ensure_embedded_user_and_tokens(&pool, &config)
            .await
            .expect("first bootstrap");
    assert!(!user_id_a.is_empty());
    assert!(!access_a.is_empty());
    assert!(!refresh_a.is_empty());

    // Exactly one user row after first boot.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "exactly one embedded user after first boot");

    // Second boot (simulated restart, same DB): reuses the user, issues a fresh
    // token pair. The user_id must match; the new tokens differ (fresh JTI/exp).
    let (user_id_b, access_b, _refresh_b) =
        dbmaster_core::user::handler::ensure_embedded_user_and_tokens(&pool, &config)
            .await
            .expect("second bootstrap");
    assert_eq!(user_id_a, user_id_b, "second boot must reuse the same user");
    assert_ne!(access_a, access_b, "a fresh access token is issued each boot");

    // Still exactly one user row — second boot did NOT create another.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "no duplicate user on second boot");

    // The embedded user must have the canonical email.
    let email: String =
        sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
            .bind(&user_id_a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(email, "embedded@local");
}

/// The embedded token pair must use far-future TTLs (30d access / 31d refresh)
/// instead of the normal 15m / 7d. With per-boot random JWT secrets the real
/// lifetime is the child process's, and the long TTL keeps a long-running
/// desktop session from 401-ing 15 minutes after boot (the 2026-08-22
/// gray-screen incident's root cause: every authenticated call 401'd once the
/// handshake access token expired, and older clients never refresh it).
#[tokio::test]
async fn embedded_token_pair_uses_far_future_ttls() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();

    let config = test_config();

    let (_user_id, access_token, refresh_token) =
        dbmaster_core::user::handler::ensure_embedded_user_and_tokens(&pool, &config)
            .await
            .unwrap();

    let access_claims =
        dbmaster_core::auth::jwt::verify_access_token(&config, &access_token).unwrap();
    assert!(
        access_claims.exp - access_claims.iat
            >= dbmaster_core::auth::jwt::EMBEDDED_ACCESS_TOKEN_TTL_SECS - 5,
        "embedded access TTL must be far-future, got {}s",
        access_claims.exp - access_claims.iat
    );

    let refresh_claims =
        dbmaster_core::auth::jwt::verify_refresh_token(&config, &refresh_token).unwrap();
    assert!(
        refresh_claims.exp - refresh_claims.iat
            >= dbmaster_core::auth::jwt::EMBEDDED_REFRESH_TOKEN_TTL_SECS - 5,
        "embedded refresh TTL must outlive the access token, got {}s",
        refresh_claims.exp - refresh_claims.iat
    );
}

/// An app built via `build_app_with_config` with the synthesized entitlement
/// must serve `/api/health` (no auth) and accept an embedded-issued token on an
/// authenticated route. This proves the env-decoupled composition path works
/// end-to-end without touching process env vars.
#[tokio::test]
async fn build_app_with_config_serves_health_and_authenticated_route() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();

    let config = test_config();
    let install_uuid = "test-install-uuid".to_string();
    let entitlement = embedded_entitlement(&install_uuid);

    // Issue a real token for the embedded user.
    let (_user_id, access_token, _refresh) =
        dbmaster_core::user::handler::ensure_embedded_user_and_tokens(&pool, &config)
            .await
            .unwrap();

    let runner: Arc<dyn DriftRunner> = Arc::new(LocalNoopDriftRunner);
    let ds_runner: Arc<dyn DataSyncRunner> = Arc::new(LocalNoopDataSyncRunner);
    let hc_runner: Arc<dyn HealthCheckRunner> = Arc::new(LocalNoopHealthCheckRunner);

    let app = dbmaster_server::build_app_with_config(
        pool,
        config,
        [0u8; 32],
        entitlement,
        install_uuid,
        runner,
        ds_runner,
        hc_runner,
        // embedded_mode = true (this test simulates the
        // embedded app composition; the credential endpoint gate is exercised
        // separately).
        true,
    );

    // /api/health — no auth required.
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // /api/me — authenticated with the embedded-issued token. A 200 here proves
    // the token validates against the same Config used to issue it, i.e. the
    // env-decoupled build_app_with_config wired the Config into both the issuer
    // (ensure_embedded_user_and_tokens) and the verifier (auth middleware).
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header("Authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Embedded mode must reject drift/health_check tasks with an explicit
/// `UNSUPPORTED_IN_EMBEDDED` error — both at creation and at manual run —
/// because those types run on Noop runners locally (a silent 202 would never
/// produce run history). data_sync tasks must keep working.
#[tokio::test]
async fn embedded_mode_rejects_drift_and_health_tasks() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();

    let config = test_config();
    let install_uuid = "test-install-uuid".to_string();
    let entitlement = embedded_entitlement(&install_uuid);

    let (_user_id, access_token, _refresh) =
        dbmaster_core::user::handler::ensure_embedded_user_and_tokens(&pool, &config)
            .await
            .unwrap();

    let app = dbmaster_server::build_app_with_config(
        pool.clone(),
        config,
        [0u8; 32],
        entitlement,
        install_uuid,
        Arc::new(LocalNoopDriftRunner),
        Arc::new(LocalNoopDataSyncRunner),
        Arc::new(LocalNoopHealthCheckRunner),
        true,
    );

    let auth = format!("Bearer {access_token}");

    // scheduled_tasks.source_db_id has an FK to database_connections — insert
    // one real row so the data_sync create below succeeds.
    sqlx::query(
        "INSERT INTO database_connections (id, name, host, username, password_encrypted, created_by)
         VALUES ('conn_x', 'test conn', 'localhost', 'u', 'x', 'embedded@local')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let post_task = |task_type: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/tasks")
            .header("Authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "name": "t",
                    "task_type": task_type,
                    "cron_expr": "0 0 * * *",
                    "config": {},
                    "source_db_id": "conn_x",
                })
                .to_string(),
            ))
            .unwrap()
    };

    // Creation of drift / health_check tasks → 400 UNSUPPORTED_IN_EMBEDDED.
    for task_type in ["schema_drift", "health_check"] {
        let resp = app
            .clone()
            .oneshot(post_task(task_type))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{task_type} create");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&bytes).contains("UNSUPPORTED_IN_EMBEDDED"),
            "{task_type} create must carry the explicit error code"
        );
    }

    // data_sync creation still succeeds (it has a real runner in embedded).
    let resp = app.clone().oneshot(post_task("data_sync")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let ds_task_id = created["data"]["id"].as_str().unwrap().to_string();

    // Its manual run still returns 202 (Noop runner accepts it).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/tasks/{ds_task_id}/run"))
                .header("Authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // A drift task row that predates the guard (e.g. created via direct API
    // before upgrade) must also be rejected at run time, not silently "queued".
    let legacy_id = "legacy-drift-task-id".to_string();
    sqlx::query(
        "INSERT INTO scheduled_tasks (id, name, task_type, cron_expr, config, source_db_id, notify_channels, created_at)
         VALUES (?1, 'legacy drift', 'schema_drift', '0 0 * * *', '{}', 'conn_x', '[]', ?2)",
    )
    .bind(&legacy_id)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(&pool)
    .await
    .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/tasks/{legacy_id}/run"))
                .header("Authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("UNSUPPORTED_IN_EMBEDDED"));
}

/// A minimal Config with fixed test secrets. Mirrors the structure `run_embedded`
/// builds, but with deterministic values for test stability.
fn test_config() -> Config {
    Config {
        host: "127.0.0.1".to_string(),
        port: 0,
        jwt_secret: "test-jwt-secret-embedded-aaaaaaaaaaaaaaaa".to_string(),
        jwt_refresh_secret: "test-refresh-secret-embedded-aaaaaaaaaaaaaa".to_string(),
        database_url: "sqlite::memory:".to_string(),
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
