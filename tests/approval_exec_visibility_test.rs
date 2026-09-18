//! U10 (task_usage_loop) — DDL approval execution-failure visibility.
//!
//! The approve handler has written `exec_status` / `executed_at` / `exec_error`
//! since migration 009, but the `DdlApproval` read model (and therefore
//! GET /api/approvals) omitted them — the desktop list rendered a failed
//! approval as the bare word "failed" with no reason. These tests pin the
//! contract: the list endpoint exposes the exec columns for failed rows (and
//! null/pending for rows that never executed).

mod common;

use serde_json::Value;

async fn register_and_get_token(app: &mut axum::Router, email: &str) -> String {
    let body: Value = common::post(
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

/// Find the approval row by id inside GET /api/approvals' data array.
async fn fetch_approval(app: &mut axum::Router, token: &str, id: &str) -> Value {
    let body: Value = common::get_with_auth(app, "/api/approvals", token)
        .await
        .json_value()
        .await;
    body["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == Value::String(id.to_string()))
        .cloned()
        .expect("approval row present in list")
}

#[tokio::test]
async fn list_approvals_exposes_exec_columns() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "u10-seed@example.com").await;

    // Seed one connection (FK target) + two approvals: a failed one carrying
    // the exec columns, and a pending one that never executed.
    sqlx::query(
        "INSERT INTO database_connections \
           (id, name, db_type, host, port, username, password_encrypted, \
            default_database, ssh_enabled, kind, created_by, created_at) \
         VALUES ('u10-conn', 'u10 target', 'mysql', '127.0.0.1', 3306, 'u', 'ct', \
            NULL, 0, 'collab', 'test', '2026-01-01')",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO ddl_approvals \
           (id, ddl_sql, target_db_id, submitter_id, reviewer_id, status, created_at, \
            resolved_at, exec_status, executed_at, exec_error) \
         VALUES ('u10-ap-failed', 'ALTER TABLE t ADD c INT', 'u10-conn', 'u1', 'u2', \
            'failed', '2026-01-02', '2026-01-02', 'failed', '2026-01-02', \
            'mysql: syntax error near c')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO ddl_approvals \
           (id, ddl_sql, target_db_id, submitter_id, status, created_at) \
         VALUES ('u10-ap-pending', 'ALTER TABLE t ADD d INT', 'u10-conn', 'u1', \
            'pending', '2026-01-03')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let failed = fetch_approval(&mut app, &token, "u10-ap-failed").await;
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["exec_status"], "failed");
    assert_eq!(
        failed["exec_error"], "mysql: syntax error near c",
        "failed row must expose the execution error"
    );

    let pending = fetch_approval(&mut app, &token, "u10-ap-pending").await;
    assert_eq!(pending["exec_status"], "pending");
    assert_eq!(pending["exec_error"], Value::Null);
}

#[tokio::test]
async fn approve_failure_flow_surfaces_exec_error() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "u10-flow@example.com").await;

    // Valid ciphertext for the test app's zero credential key so decrypt
    // succeeds; the DDL whitelist then rejects "SELECT 1" deterministically
    // without touching the network.
    let password = dbmaster_automation::credential::encrypt_v1("pw", &[0u8; 32]).unwrap();
    sqlx::query(
        "INSERT INTO database_connections \
           (id, name, db_type, host, port, username, password_encrypted, \
            default_database, ssh_enabled, kind, created_by, created_at) \
         VALUES ('u10-conn-flow', 'u10 flow target', 'mysql', '127.0.0.1', 3306, 'u', ?1, \
            NULL, 0, 'collab', 'test', '2026-01-01')",
    )
    .bind(&password)
    .execute(&pool)
    .await
    .unwrap();

    let resp = common::post_with_auth(
        &mut app,
        "/api/approvals",
        serde_json::json!({
            "ddl_sql": "SELECT 1;",
            "target_db_id": "u10-conn-flow",
        }),
        &token,
    )
    .await;
    resp.assert_ok();
    let body: Value = resp.json_value().await;
    let id = body["data"]["id"].as_str().unwrap().to_string();

    let resp = common::post_with_auth(
        &mut app,
        &format!("/api/approvals/{id}/approve"),
        serde_json::json!({}),
        &token,
    )
    .await;
    resp.assert_ok();
    let body: Value = resp.json_value().await;
    assert_eq!(body["data"]["exec_status"], "executing");

    // The DDL runs in a spawned task; poll the list until it lands in the
    // terminal failed state (bounded so a regression can't hang the suite).
    let mut row = fetch_approval(&mut app, &token, &id).await;
    for _ in 0..100 {
        if row["status"] == "failed" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        row = fetch_approval(&mut app, &token, &id).await;
    }
    assert_eq!(
        row["status"], "failed",
        "non-DDL statement must fail execution"
    );
    assert_eq!(row["exec_status"], "failed");
    let err = row["exec_error"].as_str().unwrap_or_default();
    assert!(!err.is_empty(), "exec_error must be populated on failure");
    assert!(
        err.contains("non-DDL"),
        "error should name the rejection, got: {err}"
    );
}
