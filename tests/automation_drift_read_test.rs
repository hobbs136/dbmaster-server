//! Integration tests for drift read endpoints (Phase F desktop UI dependency).
//!
//! Verifies the three read-only views over Phase E tables:
//! - `GET /api/run-history?task_id=…`           → rows from task_run_history.
//! - `GET /api/snapshots?connection_id=…`        → metadata list (no schema_json).
//! - `GET /api/snapshots/:id`                    → full row (with schema_json).
//!
//! Plus the cross-cutting concern: every route requires a valid access token
//! (Claims layer), consistent with the rest of the automation router.
//!
//! Fixture strategy: these tables have no HTTP write endpoint — only the drift
//! runner writes them, and the test app uses NoopDriftRunner. So we INSERT
//! fixture rows directly via the SqlitePool returned by `build_test_app_with_pool`.
//! That pool is the same Arc-shared in-memory DB the router serves reads from,
//! so HTTP GETs observe the seeded rows.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};

use axum::http::StatusCode;
use serde_json::{json, Value};

/// Per-process counter for unique fixture ids. Avoids pulling `uuid` into the
/// root package's dev-deps for a handful of INSERTs (uuid stays a per-crate dep
/// in automation/drift where it's load-bearing). Sequential + deterministic,
/// which makes failing fixtures easy to inspect.
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);
fn fresh_id(prefix: &str) -> String {
    let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

/// Register a user and return the access token. Mirrors the helper in
/// automation_gate_test so the assertion style stays uniform across files.
async fn register_and_get_token(app: &mut axum::Router, email: &str) -> String {
    let body: Value = common::post(
        app,
        "/api/auth/register",
        json!({
            "email": email,
            "password": "secure12345",
            "display_name": "Test User"
        }),
    )
    .await
    .json_value()
    .await;
    body["access_token"].as_str().unwrap().to_string()
}

/// Create a `collab` connection and return its id. Default `kind = collab`
/// skips the source-drift canary (which would need a real DB), so this works
/// against the in-memory test app.
async fn create_connection(app: &mut axum::Router, token: &str) -> String {
    let body: Value = common::post_with_auth(
        app,
        "/api/connections",
        json!({
            "name": "src",
            "db_type": "mysql",
            "host": "127.0.0.1",
            "port": 3306,
            "username": "u",
            "password": "p",
            "default_database": null,
            "ssh_enabled": false,
            "ssh_host": null,
            "ssh_port": null,
        }),
        token,
    )
    .await
    .json_value()
    .await;
    body["data"]["id"].as_str().unwrap().to_string()
}

/// Create a task referencing the given source connection and return its id.
async fn create_task(app: &mut axum::Router, token: &str, source_db_id: &str) -> String {
    let body: Value = common::post_with_auth(
        app,
        "/api/tasks",
        json!({
            "name": "drift-watch",
            "task_type": "schema_drift",
            "cron_expr": "*/5 * * * *",
            "config": {},
            "source_db_id": source_db_id,
            "target_db_id": null,
            "notify_channels": [],
        }),
        token,
    )
    .await
    .json_value()
    .await;
    body["data"]["id"].as_str().unwrap().to_string()
}

/// INSERT one row into task_run_history and return its id.
async fn seed_run_history(
    pool: &sqlx::SqlitePool,
    task_id: &str,
    status: &str,
) -> String {
    let id = fresh_id(&format!("run-{status}"));
    let started = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO task_run_history (id, task_id, started_at, finished_at, status, error, summary, triggered_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&id)
    .bind(task_id)
    .bind(&started)
    .bind(Some(&started))
    .bind(status)
    .bind(Option::<String>::None) // error NULL on success path
    .bind(json!({"drift_count": 0, "duration_ms": 12}).to_string())
    .bind("manual:test-user")
    .execute(pool)
    .await
    .unwrap();
    id
}

/// INSERT one row into schema_snapshots and return its id.
async fn seed_snapshot(
    pool: &sqlx::SqlitePool,
    connection_id: &str,
    prior_hash: Option<&str>,
    change_count: i64,
) -> String {
    let id = fresh_id("snap");
    let captured = chrono::Utc::now().to_rfc3339();
    // DEFENSIVE-NOTE: fixture-only — schema_json contents here are arbitrary;
    // the real collector writes canonical JSON (migration 005 D5: no row data).
    let schema_json = json!({"tables": [{"name": "users", "columns": []}]}).to_string();
    let schema_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(schema_json.as_bytes());
        hex::encode(h.finalize())
    };
    sqlx::query(
        "INSERT INTO schema_snapshots
            (id, connection_id, captured_at, schema_hash, schema_json, prior_hash, task_id, change_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&id)
    .bind(connection_id)
    .bind(&captured)
    .bind(&schema_hash)
    .bind(&schema_json)
    .bind(prior_hash)
    .bind(Option::<String>::None) // task_id NULL = manual snapshot
    .bind(change_count)
    .execute(pool)
    .await
    .unwrap();
    id
}

// ── /api/run-history ──

#[tokio::test]
async fn run_history_returns_seeded_rows_for_task() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "rh@example.com").await;
    let conn_id = create_connection(&mut app, &token).await;
    let task_id = create_task(&mut app, &token, &conn_id).await;
    let run_id = seed_run_history(&pool, &task_id, "succeeded").await;
    // Distractor row on a different task — must NOT appear.
    let other_task = create_task(&mut app, &token, &conn_id).await;
    seed_run_history(&pool, &other_task, "failed").await;

    let body: Value = common::get_with_auth(
        &mut app,
        &format!("/api/run-history?task_id={task_id}"),
        &token,
    )
    .await
    .json_value()
    .await;

    assert_eq!(body["ok"], true);
    let rows = body["data"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "only the seeded task's rows should appear");
    assert_eq!(rows[0]["id"].as_str().unwrap(), run_id);
    assert_eq!(rows[0]["task_id"].as_str().unwrap(), task_id);
    assert_eq!(rows[0]["status"].as_str().unwrap(), "succeeded");
    assert_eq!(rows[0]["triggered_by"].as_str().unwrap(), "manual:test-user");
    // summary/error/finished_at are present (NULL or string), schema enforced
    // by FromRow — we just confirm the JSON key exists so a future column drop
    // doesn't silently break the desktop's parser.
    assert!(rows[0].get("summary").is_some());
    assert!(rows[0].get("error").is_some());
    assert!(rows[0].get("finished_at").is_some());
}

#[tokio::test]
async fn run_history_unknown_task_returns_empty_not_404() {
    let (mut app, _pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "rh-404@example.com").await;

    let resp = common::get_with_auth(
        &mut app,
        "/api/run-history?task_id=does-not-exist",
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json_value().await;
    assert_eq!(body["ok"], true);
    assert!(body["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn run_history_missing_task_id_is_400() {
    let (mut app, _pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "rh-bad@example.com").await;

    let resp = common::get_with_auth(&mut app, "/api/run-history", &token).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json_value().await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], "BAD_QUERY");
}

#[tokio::test]
async fn run_history_non_numeric_limit_is_400() {
    let (mut app, _pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "rh-limit@example.com").await;

    let resp = common::get_with_auth(
        &mut app,
        "/api/run-history?task_id=x&limit=abc",
        &token,
    )
    .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

// ── /api/snapshots ──

#[tokio::test]
async fn snapshots_list_omits_schema_json() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "snap-list@example.com").await;
    let conn_id = create_connection(&mut app, &token).await;
    let snap_id = seed_snapshot(&pool, &conn_id, None, 0).await;
    // Distractor on a different connection — must NOT appear.
    let other_conn = create_connection(&mut app, &token).await;
    seed_snapshot(&pool, &other_conn, None, 0).await;

    let body: Value = common::get_with_auth(
        &mut app,
        &format!("/api/snapshots?connection_id={conn_id}"),
        &token,
    )
    .await
    .json_value()
    .await;

    assert_eq!(body["ok"], true);
    let rows = body["data"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "only the seeded connection's snapshots");
    assert_eq!(rows[0]["id"].as_str().unwrap(), snap_id);
    assert_eq!(rows[0]["connection_id"].as_str().unwrap(), conn_id);
    assert_eq!(rows[0]["change_count"].as_i64().unwrap(), 0);
    // DEFENSIVE-NOTE: the entire point of the list endpoint — schema_json must
    // NOT be present so a list of wide schemas doesn't blow up the payload.
    assert!(
        rows[0].get("schema_json").is_none() || rows[0]["schema_json"].is_null(),
        "list response must not include schema_json; got: {}",
        rows[0]
    );
}

#[tokio::test]
async fn snapshots_unknown_connection_returns_empty_not_404() {
    let (mut app, _pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "snap-404@example.com").await;

    let resp = common::get_with_auth(
        &mut app,
        "/api/snapshots?connection_id=does-not-exist",
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json_value().await;
    assert_eq!(body["ok"], true);
    assert!(body["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn snapshots_missing_connection_id_is_400() {
    let (mut app, _pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "snap-bad@example.com").await;

    let resp = common::get_with_auth(&mut app, "/api/snapshots", &token).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "BAD_QUERY");
}

// ── /api/snapshots/:id ──

#[tokio::test]
async fn snapshot_by_id_includes_schema_json() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "snap-id@example.com").await;
    let conn_id = create_connection(&mut app, &token).await;
    let snap_id = seed_snapshot(&pool, &conn_id, None, 0).await;

    let body: Value = common::get_with_auth(
        &mut app,
        &format!("/api/snapshots/{snap_id}"),
        &token,
    )
    .await
    .json_value()
    .await;

    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["id"].as_str().unwrap(), snap_id);
    // The complement of the list test: by-id MUST carry schema_json so the
    // desktop can run its client-side Schema Diff.
    let schema_json = body["data"]["schema_json"].as_str().unwrap();
    assert!(schema_json.contains("users"), "schema_json body lost");
    assert_eq!(body["data"]["schema_hash"].as_str().unwrap().len(), 64);
    assert!(body["data"]["prior_hash"].is_null());
    assert!(body["data"]["task_id"].is_null());
}

#[tokio::test]
async fn snapshot_by_id_unknown_returns_not_found_envelope() {
    let (mut app, _pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "snap-nf@example.com").await;

    let resp = common::get_with_auth(&mut app, "/api/snapshots/nope", &token).await;
    resp.assert_status(StatusCode::OK); // envelope stays 200; ok:false signals the miss
    let body: Value = resp.json_value().await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], "NOT_FOUND");
}

// ── Auth: every drift read route requires Claims ──

#[tokio::test]
async fn drift_read_routes_require_auth() {
    let (mut app, _pool) = common::build_test_app_with_pool().await;

    // No Authorization header on any drift read route → 401 (Claims layer).
    for uri in [
        "/api/run-history?task_id=anything",
        "/api/snapshots?connection_id=anything",
        "/api/snapshots/any-id",
    ] {
        common::get(&mut app, uri)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
}
