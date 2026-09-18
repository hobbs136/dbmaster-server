//! U06 (task_usage_loop) — health check failure visibility.
//!
//! Before U06, a failed run (db unreachable / credential decrypt failure)
//! wrote no `health_check_results` row: the desktop list inferred status from
//! results only, so "database down" rendered as unknown and the 'failed'
//! badge branch was unreachable. These tests pin the new contract:
//!
//! - migration 014 adds the `error` column to `health_check_results`;
//! - the runner's failure path writes a results row (status='failed',
//!   redacted error, empty metrics/alerts JSON) in addition to the
//!   task_run_history row + scheduled_tasks.last_status update;
//! - `GET /api/health-results` exposes `error` (non-null on failed rows,
//!   null on legacy rows).

mod common;

use std::sync::Arc;

use sqlx::SqlitePool;

use dbmaster_core::config::Config;
use dbmaster_core::server::AppState;
use dbmaster_license::EntitlementState;

/// Register a user and return their access token (mirrors health_results_test).
async fn register_and_get_token(app: &mut axum::Router, email: &str) -> String {
    let body: serde_json::Value = common::post(
        app,
        "/api/auth/register",
        serde_json::json!({
            "email": email,
            "password": "secure12345",
            "display_name": "Test User",
        }),
    )
    .await
    .json_value()
    .await;
    body["access_token"].as_str().unwrap().to_string()
}

/// Build an AppState over the given pool with a far-future Trial entitlement
/// and zero credential key (mirrors e2e_data_sync_test's assembly).
fn test_state(pool: SqlitePool) -> AppState {
    let config = Config::from_env().expect("config (all fields have defaults)");
    AppState::new(
        pool,
        config,
        [0u8; 32],
        EntitlementState::Trial {
            expires_at: chrono::Utc::now() + chrono::Duration::days(365),
        },
        "u06-test-install-uuid".to_string(),
        Arc::new(dbmaster_drift::DriftRunnerHandle),
        Arc::new(dbmaster_data_sync::DataSyncRunnerHandle),
        Arc::new(dbmaster_health_check::HealthCheckRunnerHandle),
    )
}

/// Seed one mysql `database_connections` row + one health_check
/// `scheduled_tasks` row pointing at it. `port` picks the failure flavor
/// (1 = connection refused; the password ciphertext picks decrypt ok/fail).
async fn seed_task_and_connection(pool: &SqlitePool, task_id: &str, password_encrypted: &str) {
    sqlx::query(
        "INSERT INTO database_connections \
           (id, name, db_type, host, port, username, password_encrypted, \
            default_database, ssh_enabled, kind, created_by, created_at) \
         VALUES ('u06-conn-1', 'u06 source', 'mysql', '127.0.0.1', 1, 'u', ?1, \
            NULL, 0, 'collab', 'test', '2026-01-01')",
    )
    .bind(password_encrypted)
    .execute(pool)
    .await
    .expect("seed connection");

    sqlx::query(
        "INSERT INTO scheduled_tasks \
           (id, name, task_type, cron_expr, config, source_db_id, target_db_id, \
            notify_channels, enabled, created_at) \
         VALUES (?1, 'u06 health', 'health_check', '*/5 * * * *', '{}', \
            'u06-conn-1', NULL, '[]', 1, '2026-01-01')",
    )
    .bind(task_id)
    .execute(pool)
    .await
    .expect("seed task");
}

#[tokio::test]
async fn migration_014_adds_error_column() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();

    let col: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('health_check_results') \
         WHERE name = 'error'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(col, 1, "health_check_results.error column missing");
}

#[tokio::test]
async fn decrypt_failure_writes_failed_results_row() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();
    seed_task_and_connection(&pool, "u06-task-decrypt", "not-a-valid-ciphertext").await;

    let state = test_state(pool.clone());
    let outcome =
        dbmaster_health_check::runner::run_task(&pool, &state, "u06-task-decrypt", "manual:u1").await;
    assert!(outcome.is_err(), "run should fail on undecryptable credential");

    let row: (String, String, String, Option<String>) = sqlx::query_as(
        "SELECT status, metrics_summary, alert_changes, error \
         FROM health_check_results WHERE task_id = ?1",
    )
    .bind("u06-task-decrypt")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "failed");
    assert_eq!(row.1, "{}");
    assert_eq!(row.2, "[]");
    let err = row.3.expect("failed row must carry an error");
    assert!(
        err.to_lowercase().contains("decrypt"),
        "error should name the failure, got: {err}"
    );
    // No credential material may leak into the stored error.
    assert!(!err.to_lowercase().contains("not-a-valid-ciphertext"));

    // The task-level status flip is pinned too (drives the desktop fallback).
    let last: Option<String> = sqlx::query_scalar(
        "SELECT last_status FROM scheduled_tasks WHERE id = 'u06-task-decrypt'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(last.as_deref(), Some("failed"));
}

#[tokio::test]
async fn unreachable_db_writes_failed_results_row() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();
    // Valid ciphertext for the zero key so decrypt succeeds; the connection
    // then fails against 127.0.0.1:1 (refused).
    let password = dbmaster_automation::credential::encrypt_v1("secret-pw", &[0u8; 32]).unwrap();
    seed_task_and_connection(&pool, "u06-task-connrefused", &password).await;

    let state = test_state(pool.clone());
    let outcome = dbmaster_health_check::runner::run_task(
        &pool,
        &state,
        "u06-task-connrefused",
        "scheduler",
    )
    .await;
    assert!(outcome.is_err(), "run should fail on unreachable db");

    let row: (String, Option<String>) = sqlx::query_as(
        "SELECT status, error FROM health_check_results WHERE task_id = ?1",
    )
    .bind("u06-task-connrefused")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "failed");
    let err = row.1.unwrap_or_default();
    assert!(!err.is_empty(), "error should be populated");
    assert!(!err.to_lowercase().contains("secret-pw"), "no credential leak");

    // task_run_history keeps its own failed row with the redacted error.
    let history: (String, Option<String>) = sqlx::query_as(
        "SELECT status, error FROM task_run_history WHERE task_id = ?1",
    )
    .bind("u06-task-connrefused")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(history.0, "failed");
    assert!(history.1.is_some());
}

#[tokio::test]
async fn health_results_endpoint_exposes_error_field() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "u06-api@example.com").await;

    // scheduled_tasks.source_db_id has an FK to database_connections — seed a
    // (never-connected-to) connection row first.
    sqlx::query(
        "INSERT INTO database_connections \
           (id, name, db_type, host, port, username, password_encrypted, \
            default_database, ssh_enabled, kind, created_by, created_at) \
         VALUES ('u06-conn-api', 'u06 api conn', 'mysql', '127.0.0.1', 3306, 'u', \
            'ct', NULL, 0, 'collab', 'test', '2026-01-01')",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO scheduled_tasks \
           (id, name, task_type, cron_expr, config, source_db_id, target_db_id, \
            notify_channels, enabled, created_at) \
         VALUES ('u06-task-api', 'u06 api', 'health_check', '*/5 * * * *', '{}', \
            'u06-conn-api', NULL, '[]', 1, '2026-01-01')",
    )
    .execute(&pool)
    .await
    .unwrap();

    // One failed row written by the runner (error set) + one legacy success
    // row written before migration 014 (error NULL).
    sqlx::query(
        "INSERT INTO health_check_results \
           (id, task_id, started_at, finished_at, status, metrics_summary, \
            alert_changes, triggered_by, error) \
         VALUES ('r-failed', 'u06-task-api', '2026-08-17T10:00:00+00:00', \
            '2026-08-17T10:00:01+00:00', 'failed', '{}', '[]', 'scheduler', \
            'mysql connect failed: refused')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO health_check_results \
           (id, task_id, started_at, finished_at, status, metrics_summary, \
            alert_changes, triggered_by) \
         VALUES ('r-legacy', 'u06-task-api', '2026-08-16T10:00:00+00:00', \
            '2026-08-16T10:00:01+00:00', 'success', '{}', '[]', 'scheduler')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let resp = common::get_with_auth(&mut app, "/api/health-results?task_id=u06-task-api", &token)
        .await;
    resp.assert_ok();
    let body: serde_json::Value = resp.json_value().await;
    let rows = body["data"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    // Newest first: the failed row leads and carries the error verbatim.
    assert_eq!(rows[0]["id"], "r-failed");
    assert_eq!(rows[0]["status"], "failed");
    assert_eq!(rows[0]["error"], "mysql connect failed: refused");
    assert_eq!(rows[1]["id"], "r-legacy");
    assert_eq!(rows[1]["error"], serde_json::Value::Null);
}
