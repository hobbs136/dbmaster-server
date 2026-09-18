//! Integration test helpers for dbmaster-server.
//!
//! Provides utilities for building a test server with in-memory SQLite,
//! running migrations, and making HTTP requests.

// CHANGE: ADR-0001 §7.1 — shared HTTP helpers may be unused by individual test
// files; suppress dead_code at the module level (idiomatic for test helpers).
#![allow(dead_code)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use serde::de::DeserializeOwned;
use sqlx::SqlitePool;
use tower::ServiceExt;

/// No-op DriftRunner for tests that don't exercise the run path.
/// Keeping it here (not in main code) avoids polluting the production crates
/// with test scaffolding. Tests that DO want to assert on the run path can
/// construct their own impl and call [`build_app`] with it.
// CHANGE: ADR-0002 v1-C-9 — provides a DriftRunner for the AppState assembled
// inside build_test_app, so the new AppState::new signature compiles in tests.
struct NoopDriftRunner;

#[async_trait]
impl dbmaster_core::server::DriftRunner for NoopDriftRunner {
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

// CHANGE: data-sync 一期 — mirror NoopDriftRunner so the AppState assembled
// inside build_test_app compiles with the new 7-arg signature. Tests that
// exercise the real ETL path construct their own impl and pass it in.
struct NoopDataSyncRunner;

#[async_trait]
impl dbmaster_core::server::DataSyncRunner for NoopDataSyncRunner {
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

// CHANGE: ADR-0004 §2.2 — mirror NoopDriftRunner/NoopDataSyncRunner so the
// AppState assembled inside build_test_app compiles with the 8-arg signature.
struct NoopHealthCheckRunner;

#[async_trait]
impl dbmaster_core::server::HealthCheckRunner for NoopHealthCheckRunner {
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

/// Build a test router with in-memory SQLite and migrations applied.
// CHANGE: ADR-0001 §7.1 — compose via the binary lib (merges core + automation).
pub async fn build_test_app() -> Router {
    // Default to a Trial entitlement far in the future so gated paths don't fire
    // in tests that exercise auth/workspace flows.
    let far_future = chrono::Utc::now() + chrono::Duration::days(365);
    let entitlement = dbmaster_license::EntitlementState::Trial { expires_at: far_future };
    build_test_app_with_entitlement(entitlement).await
}

/// Build a test router with an explicit [`EntitlementState`].
///
/// Tests that need to exercise the gated path (e.g. automation mutations under
/// `EntitlementState::Gated`) pass the desired state here; everything else uses
/// the trial default above.
// CHANGE: ADR-0002 v1-C-2 — expose entitlement so gate tests can drive Gated.
// CHANGE: supply a fixed install_uuid + NoopDriftRunner so AppState::new
/// compiles in tests without forcing every test to know about drift.
pub async fn build_test_app_with_entitlement(
    entitlement: dbmaster_license::EntitlementState,
) -> Router {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();
    // Tests don't rely on real encryption — use a deterministic zero key.
    let credential_key = [0u8; 32];
    // Deterministic install_uuid for any test that asserts on webhook payloads.
    let install_uuid = "test-install-uuid-fixed-000000000000000000000000000".to_string();
    let runner: Arc<dyn dbmaster_core::server::DriftRunner> = Arc::new(NoopDriftRunner);
    let ds_runner: Arc<dyn dbmaster_core::server::DataSyncRunner> = Arc::new(NoopDataSyncRunner);
    let hc_runner: Arc<dyn dbmaster_core::server::HealthCheckRunner> = Arc::new(NoopHealthCheckRunner);
    dbmaster_server::build_app(pool, credential_key, entitlement, install_uuid, runner, ds_runner, hc_runner)
}

/// Build a test router along with a clone of the underlying pool, for tests
/// that need to seed tables directly via SQL (e.g. `task_run_history` and
/// `schema_snapshots`, which have no write endpoint — only the drift runner
/// writes them, and the NoopDriftRunner writes nothing).
// CHANGE: Phase F — drift read-endpoint tests INSERT fixture rows directly
/// because the read API under test is the only HTTP surface for those tables.
/// SqlitePool is internally Arced, so the clone shares the same in-memory DB
/// as the one bound into the router; writes via this handle are visible to
/// HTTP requests served from the same pool (this same sharing is what makes
/// existing create→list round-trip tests pass).
pub async fn build_test_app_with_pool() -> (Router, SqlitePool) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();
    let credential_key = [0u8; 32];
    let far_future = chrono::Utc::now() + chrono::Duration::days(365);
    let entitlement = dbmaster_license::EntitlementState::Trial { expires_at: far_future };
    let install_uuid = "test-install-uuid-fixed-000000000000000000000000000".to_string();
    let runner: Arc<dyn dbmaster_core::server::DriftRunner> = Arc::new(NoopDriftRunner);
    let ds_runner: Arc<dyn dbmaster_core::server::DataSyncRunner> = Arc::new(NoopDataSyncRunner);
    let hc_runner: Arc<dyn dbmaster_core::server::HealthCheckRunner> = Arc::new(NoopHealthCheckRunner);
    let app = dbmaster_server::build_app(
        pool.clone(),
        credential_key,
        entitlement,
        install_uuid,
        runner,
        ds_runner,
        hc_runner,
    );
    (app, pool)
}

/// Make a GET request to the test app and return the response.
pub async fn get(app: &mut Router, uri: &str) -> ResponseAssert {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a POST request with a JSON body.
pub async fn post(app: &mut Router, uri: &str, body: impl serde::Serialize) -> ResponseAssert {
    let json = serde_json::to_string(&body).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a POST request with a JSON body and an `X-Forwarded-For` header,
/// so rate-limit tests can drive distinct client IPs (oneshot requests have no
/// socket peer address and would all fall into the limiter's "unknown" bucket).
pub async fn post_with_ip(
    app: &mut Router,
    uri: &str,
    body: impl serde::Serialize,
    client_ip: &str,
) -> ResponseAssert {
    let json = serde_json::to_string(&body).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("POST")
                .header("Content-Type", "application/json")
                .header("X-Forwarded-For", client_ip)
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a PATCH request with a JSON body.
pub async fn patch(app: &mut Router, uri: &str, body: impl serde::Serialize) -> ResponseAssert {
    let json = serde_json::to_string(&body).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("PATCH")
                .header("Content-Type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a PUT request with a JSON body (no auth header).
// U05 — PUT /api/connections/:id auth-rejection coverage.
pub async fn put(app: &mut Router, uri: &str, body: impl serde::Serialize) -> ResponseAssert {
    let json = serde_json::to_string(&body).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("PUT")
                .header("Content-Type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a DELETE request.
pub async fn delete(app: &mut Router, uri: &str) -> ResponseAssert {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a POST request with an optional JSON body and an Authorization header.
pub async fn post_with_auth(
    app: &mut Router,
    uri: &str,
    body: impl serde::Serialize,
    token: &str,
) -> ResponseAssert {
    let json = serde_json::to_string(&body).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("POST")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a GET request with an Authorization header.
pub async fn get_with_auth(app: &mut Router, uri: &str, token: &str) -> ResponseAssert {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("GET")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a PATCH request with an Authorization header.
pub async fn patch_with_auth(
    app: &mut Router,
    uri: &str,
    body: impl serde::Serialize,
    token: &str,
) -> ResponseAssert {
    let json = serde_json::to_string(&body).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("PATCH")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a DELETE request with an Authorization header.
pub async fn delete_with_auth(app: &mut Router, uri: &str, token: &str) -> ResponseAssert {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("DELETE")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Make a PUT request with a JSON body and an Authorization header.
// U05 — PUT /api/connections/:id (in-place connection update).
pub async fn put_with_auth(
    app: &mut Router,
    uri: &str,
    body: impl serde::Serialize,
    token: &str,
) -> ResponseAssert {
    let json = serde_json::to_string(&body).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("PUT")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    ResponseAssert { response }
}

/// Wrapper around Axum HTTP response for fluent assertions.
pub struct ResponseAssert {
    response: axum::http::Response<axum::body::Body>,
}

impl ResponseAssert {
    /// #3 — public constructor for tests that build a custom request (e.g.
    /// `POST /api/license` with `X-Admin-Token` header, which the standard
    /// `post_with_auth` helper doesn't cover).
    pub fn from_response(response: axum::http::Response<axum::body::Body>) -> Self {
        Self { response }
    }
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    /// Assert the response status code.
    pub fn assert_status(&self, expected: StatusCode) -> &Self {
        assert_eq!(
            self.response.status(),
            expected,
            "Expected status {}, got {}",
            expected.as_u16(),
            self.response.status().as_u16()
        );
        self
    }

    /// Assert the response has a 2xx status.
    pub fn assert_ok(&self) -> &Self {
        assert!(
            self.response.status().is_success(),
            "Expected 2xx, got {}",
            self.response.status().as_u16()
        );
        self
    }

    /// Extract the JSON body.
    pub async fn json<T: DeserializeOwned>(self) -> T {
        let body_bytes = axum::body::to_bytes(self.response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    /// Extract the JSON body as a raw `serde_json::Value`.
    pub async fn json_value(self) -> serde_json::Value {
        let body_bytes = axum::body::to_bytes(self.response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    /// Extract the body as a string.
    #[allow(dead_code)]
    pub async fn text(self) -> String {
        let body_bytes = axum::body::to_bytes(self.response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        String::from_utf8(body_bytes.to_vec()).unwrap()
    }
}
