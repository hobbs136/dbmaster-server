//! Integration tests for the saved-queries read side (#4) and the extended
//! PATCH /api/tasks/:id (#5).
//!
//! #4 — `save_query` (POST /api/queries) has always worked; the read side
//! (list / get / delete) was missing, making the team query library write-only.
//! These tests cover the round trip + tag/text filters.
//!
//! #5 — `update_task` previously accepted only `{ enabled: bool }`. The
//! extended PATCH allows partial updates of name/cron/config/target/notify
//! without DELETE + recreate. These tests cover backward compat (existing
//! `{enabled: bool}` clients) + new multi-field behavior + empty-patch
//! rejection + updated_at bump.

mod common;

use axum::http::StatusCode;
use serde_json::json;

/// Register a user and return the access token. Same helper as in
/// automation_gate_test.rs (duplicated to keep each test file standalone).
async fn register_and_get_token(app: &mut axum::Router, email: &str) -> String {
    let body: serde_json::Value = common::post(
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

// ── #4: Saved Queries read side ──

#[tokio::test]
async fn saved_queries_round_trip() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "sq-round@example.com").await;

    // Empty list to start
    let resp = common::get_with_auth(&mut app, "/api/queries", &token).await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["ok"], true);
    assert!(body["data"].as_array().unwrap().is_empty());

    // Save one
    let resp = common::post_with_auth(
        &mut app,
        "/api/queries",
        json!({
            "title": "Active users",
            "sql_text": "SELECT id, name FROM users WHERE active = 1",
            "tags": ["users", "report"],
        }),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    let id = body["data"]["id"].as_str().unwrap().to_string();

    // List now has one
    let resp = common::get_with_auth(&mut app, "/api/queries", &token).await;
    let body: serde_json::Value = resp.json_value().await;
    let arr = body["data"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["title"], "Active users");

    // Get by id
    let resp =
        common::get_with_auth(&mut app, &format!("/api/queries/{id}"), &token).await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"]["title"], "Active users");
    assert_eq!(body["data"]["sql_text"], "SELECT id, name FROM users WHERE active = 1");

    // Delete
    let resp =
        common::delete_with_auth(&mut app, &format!("/api/queries/{id}"), &token).await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"]["deleted"], true);

    // Get again → NOT_FOUND
    let resp =
        common::get_with_auth(&mut app, &format!("/api/queries/{id}"), &token).await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "NOT_FOUND");

    // Delete again → NOT_FOUND (rows_affected == 0)
    let resp =
        common::delete_with_auth(&mut app, &format!("/api/queries/{id}"), &token).await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "NOT_FOUND");
}

// D2-B (#32)：删除收紧为仅作者——他人删除 403，行保留；作者删除成功。
#[tokio::test]
async fn saved_queries_delete_only_by_author() {
    let mut app = common::build_test_app().await;
    let author = register_and_get_token(&mut app, "sq-author@example.com").await;
    let other = register_and_get_token(&mut app, "sq-other@example.com").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/queries",
        json!({ "title": "Author's query", "sql_text": "SELECT 1", "tags": [] }),
        &author,
    )
    .await;
    let body: serde_json::Value = resp.json_value().await;
    let id = body["data"]["id"].as_str().unwrap().to_string();

    // Non-author → 403 FORBIDDEN, row survives.
    let resp =
        common::delete_with_auth(&mut app, &format!("/api/queries/{id}"), &other).await;
    resp.assert_status(StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "FORBIDDEN");

    let resp =
        common::get_with_auth(&mut app, &format!("/api/queries/{id}"), &author).await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"]["title"], "Author's query");

    // Author → OK.
    let resp =
        common::delete_with_auth(&mut app, &format!("/api/queries/{id}"), &author).await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"]["deleted"], true);
}

#[tokio::test]
async fn saved_queries_tag_filter() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "sq-tag@example.com").await;

    // Save three with overlapping tags
    for (title, tags) in [
        ("q1", vec!["users", "report"]),
        ("q2", vec!["orders", "report"]),
        ("q3", vec!["users", "admin"]),
    ] {
        common::post_with_auth(
            &mut app,
            "/api/queries",
            json!({ "title": title, "sql_text": "SELECT 1", "tags": tags }),
            &token,
        )
        .await;
    }

    // Filter by "users" → q1 + q3 (not q2)
    let resp = common::get_with_auth(
        &mut app,
        "/api/queries?tag=users",
        &token,
    )
    .await;
    let body: serde_json::Value = resp.json_value().await;
    let titles: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles.len(), 2);
    assert!(titles.contains(&"q1"));
    assert!(titles.contains(&"q3"));

    // Filter by exact tag — "user" (substring of "users") must NOT match.
    // The pattern `%"user"%` requires the tag to appear as a quoted JSON
    // element; `users` is the element, not `user`.
    let resp = common::get_with_auth(
        &mut app,
        "/api/queries?tag=user",
        &token,
    )
    .await;
    let body: serde_json::Value = resp.json_value().await;
    assert!(body["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn saved_queries_text_search() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "sq-text@example.com").await;

    common::post_with_auth(
        &mut app,
        "/api/queries",
        json!({ "title": "Find active users", "sql_text": "SELECT * FROM users", "tags": [] }),
        &token,
    )
    .await;
    common::post_with_auth(
        &mut app,
        "/api/queries",
        json!({ "title": "Monthly revenue", "sql_text": "SELECT SUM(amount) FROM orders", "tags": [] }),
        &token,
    )
    .await;

    // q=users matches both title (Find active users) and sql (FROM users) of q1
    let resp = common::get_with_auth(&mut app, "/api/queries?q=users", &token).await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["title"], "Find active users");

    // q=orders matches q2's sql_text only
    let resp = common::get_with_auth(&mut app, "/api/queries?q=orders", &token).await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["title"], "Monthly revenue");

    // No match
    let resp = common::get_with_auth(&mut app, "/api/queries?q=nonexistent", &token).await;
    let body: serde_json::Value = resp.json_value().await;
    assert!(body["data"].as_array().unwrap().is_empty());
}

// ── #5: Extended PATCH /api/tasks/:id ──

/// Create a task via POST /api/tasks and return its id. Tests need a task to
/// PATCH; this helper avoids depending on a separate seed fixture.
async fn create_task_for_patch(app: &mut axum::Router, token: &str, name: &str) -> String {
    // scheduled_tasks.source_db_id REFERENCES database_connections(id), so we
    // must create a connection first.
    let resp = common::post_with_auth(
        app,
        "/api/connections",
        json!({
            "name": "src-for-".to_string() + name,
            "db_type": "mysql",
            "host": "127.0.0.1",
            "port": 3306,
            "username": "u",
            "password": "p",
            "ssh_enabled": false,
        }),
        token,
    )
    .await;
    let body: serde_json::Value = resp.json_value().await;
    let conn_id = body["data"]["id"].as_str().unwrap().to_string();

    let resp = common::post_with_auth(
        app,
        "/api/tasks",
        json!({
            "name": name,
            "task_type": "data_sync",
            "cron_expr": "0 * * * *",
            "config": {},
            "source_db_id": conn_id,
        }),
        token,
    )
    .await;
    let body: serde_json::Value = resp.json_value().await;
    body["data"]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn patch_task_backward_compat_enabled_only() {
    // Existing clients send `{enabled: bool}` — must still work after #5.
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "patch-compat@example.com").await;
    let id = create_task_for_patch(&mut app, &token, "compat-task").await;

    let resp = common::patch_with_auth(
        &mut app,
        &format!("/api/tasks/{id}"),
        json!({ "enabled": false }),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    // Response now returns the full task object (mirrors create_task shape);
    // enabled should reflect the new value.
    assert_eq!(body["data"]["enabled"], false);
    assert_eq!(body["data"]["name"], "compat-task"); // unchanged
    assert_eq!(body["data"]["cron_expr"], "0 * * * *"); // unchanged
}

#[tokio::test]
async fn patch_task_multiple_fields() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "patch-multi@example.com").await;
    let id = create_task_for_patch(&mut app, &token, "multi-task").await;

    let resp = common::patch_with_auth(
        &mut app,
        &format!("/api/tasks/{id}"),
        json!({
            "name": "renamed",
            "cron_expr": "*/30 * * * *",
            "notify_channels": ["https://hook.example.com/x"],
        }),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"]["name"], "renamed");
    assert_eq!(body["data"]["cron_expr"], "*/30 * * * *");
    // enabled untouched (was default true at create)
    assert_eq!(body["data"]["enabled"], true);
    // notify_channels persisted as JSON array string
    let notify: serde_json::Value =
        serde_json::from_str(body["data"]["notify_channels"].as_str().unwrap()).unwrap();
    assert_eq!(notify[0], "https://hook.example.com/x");
}

#[tokio::test]
async fn patch_task_empty_body_rejected() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "patch-empty@example.com").await;
    let id = create_task_for_patch(&mut app, &token, "empty-task").await;

    let resp = common::patch_with_auth(
        &mut app,
        &format!("/api/tasks/{id}"),
        json!({}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "EMPTY_PATCH");
}

#[tokio::test]
async fn patch_task_not_found() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "patch-nf@example.com").await;

    let resp = common::patch_with_auth(
        &mut app,
        "/api/tasks/nonexistent-id",
        json!({ "enabled": false }),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "NOT_FOUND");
}

#[tokio::test]
async fn patch_task_bumps_updated_at() {
    // The `updated_at` column exists in the schema but was never written by
    // any UPDATE before #5. This test pins the fix.
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "patch-ts@example.com").await;
    let id = create_task_for_patch(&mut app, &token, "ts-task").await;

    // Read pre-PATCH updated_at directly from the DB.
    let before: (String,) = sqlx::query_as("SELECT updated_at FROM scheduled_tasks WHERE id = ?")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Sleep briefly so the RFC3339 timestamp differs.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    common::patch_with_auth(
        &mut app,
        &format!("/api/tasks/{id}"),
        json!({ "enabled": false }),
        &token,
    )
    .await;

    let after: (String,) = sqlx::query_as("SELECT updated_at FROM scheduled_tasks WHERE id = ?")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(before.0, after.0, "updated_at must be bumped by PATCH");
}
