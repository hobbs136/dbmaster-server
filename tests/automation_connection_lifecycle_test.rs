//! U05 (#32) — task-connection validation + in-place connection update.
//!
//! Two regression guards for the "local-id submitted to a remote server"
//! breakage class:
//! - `create_task` must 404 `CONNECTION_NOT_FOUND` naming the missing side
//!   (source or target) instead of surfacing a raw FK violation at INSERT or
//!   an opaque run-time failure later.
//! - `PUT /api/connections/:id` updates fields in place (stable id), keeps
//!   the stored password when the request omits it, and preserves task
//!   references — delete+recreate would CASCADE-delete tasks.

mod common;

use axum::http::StatusCode;
use serde_json::{json, Value};

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

/// Create a `collab` connection (kind=collab skips the source-drift canary)
/// and return its server id.
async fn create_connection(app: &mut axum::Router, token: &str, name: &str) -> String {
    let body: Value = common::post_with_auth(
        app,
        "/api/connections",
        json!({
            "name": name,
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

fn data_sync_task(source: &str, target: &str) -> serde_json::Value {
    json!({
        "name": "sync-1",
        "task_type": "data_sync",
        "cron_expr": "*/5 * * * *",
        "config": {},
        "source_db_id": source,
        "target_db_id": target,
        "notify_channels": [],
    })
}

// ── create_task connection validation ──

#[tokio::test]
async fn create_task_rejects_missing_source_connection() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "u05-src@example.com").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/tasks",
        data_sync_task("no-such-conn", "no-such-conn-either"),
        &token,
    )
    .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "CONNECTION_NOT_FOUND");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("source"),
        "error must name the missing side, got: {msg}"
    );
}

#[tokio::test]
async fn create_task_rejects_missing_target_connection() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "u05-tgt@example.com").await;
    let source = create_connection(&mut app, &token, "src").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/tasks",
        data_sync_task(&source, "no-such-target"),
        &token,
    )
    .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "CONNECTION_NOT_FOUND");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("target"),
        "error must name the missing side, got: {msg}"
    );
}

#[tokio::test]
async fn create_task_accepts_existing_connections() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "u05-ok@example.com").await;
    let source = create_connection(&mut app, &token, "src").await;
    let target = create_connection(&mut app, &token, "tgt").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/tasks",
        data_sync_task(&source, &target),
        &token,
    )
    .await;

    resp.assert_ok();
    let body: Value = resp.json_value().await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["source_db_id"], source);
    assert_eq!(body["data"]["target_db_id"], target);
}

#[tokio::test]
async fn create_task_null_target_skips_target_validation() {
    // health_check / drift tasks carry target_db_id = null — the target leg
    // of the validation must not run for them.
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "u05-null@example.com").await;
    let source = create_connection(&mut app, &token, "src").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/tasks",
        json!({
            "name": "health-1",
            "task_type": "health_check",
            "cron_expr": "*/5 * * * *",
            "config": {},
            "source_db_id": source,
            "target_db_id": null,
            "notify_channels": [],
        }),
        &token,
    )
    .await;

    resp.assert_ok();
    let body: Value = resp.json_value().await;
    assert_eq!(body["ok"], true);
}

// ── PUT /api/connections/:id ──

#[tokio::test]
async fn update_connection_renames_in_place_and_keeps_task_references() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "u05-put@example.com").await;
    let source = create_connection(&mut app, &token, "before").await;
    let target = create_connection(&mut app, &token, "tgt").await;

    // A task referencing the connection under its original name/id.
    let task: Value = common::post_with_auth(
        &mut app,
        "/api/tasks",
        data_sync_task(&source, &target),
        &token,
    )
    .await
    .json_value()
    .await;
    let task_id = task["data"]["id"].as_str().unwrap().to_string();

    let resp = common::put_with_auth(
        &mut app,
        &format!("/api/connections/{source}"),
        json!({"name": "after", "host": "10.0.0.5"}),
        &token,
    )
    .await;
    resp.assert_ok();
    let body: Value = resp.json_value().await;
    assert_eq!(body["ok"], true);
    // Stable id + applied fields.
    assert_eq!(body["data"]["id"], source);
    assert_eq!(body["data"]["name"], "after");
    assert_eq!(body["data"]["host"], "10.0.0.5");
    // Unmodified fields keep their values.
    assert_eq!(body["data"]["port"], 3306);

    // The referencing task survives the edit (delete+recreate would have
    // CASCADE-deleted it).
    let tasks: Value = common::get_with_auth(&mut app, "/api/tasks", &token)
        .await
        .json_value()
        .await;
    let ids: Vec<&str> = tasks["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&task_id.as_str()), "task must survive an in-place connection edit");
}

#[tokio::test]
async fn update_connection_keeps_password_when_omitted() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "u05-pw@example.com").await;
    let id = create_connection(&mut app, &token, "src").await;

    let before: Value = common::get_with_auth(&mut app, "/api/connections", &token)
        .await
        .json_value()
        .await;
    let row_before = before["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id.as_str())
        .unwrap()
        .clone();

    let resp = common::put_with_auth(
        &mut app,
        &format!("/api/connections/{id}"),
        json!({"name": "renamed-no-pw"}),
        &token,
    )
    .await;
    resp.assert_ok();

    let after: Value = common::get_with_auth(&mut app, "/api/connections", &token)
        .await
        .json_value()
        .await;
    let row_after = after["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id.as_str())
        .unwrap()
        .clone();

    // Omitted password ⇒ ciphertext unchanged (the edit form omits secrets).
    assert_eq!(
        row_before["password_encrypted"], row_after["password_encrypted"],
        "omitted password must keep the stored ciphertext"
    );
    assert_eq!(row_after["name"], "renamed-no-pw");
}

#[tokio::test]
async fn update_connection_reencrypts_password_when_supplied() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "u05-pw2@example.com").await;
    let id = create_connection(&mut app, &token, "src").await;

    let before: Value = common::get_with_auth(&mut app, "/api/connections", &token)
        .await
        .json_value()
        .await;
    let row_before = before["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id.as_str())
        .unwrap()
        .clone();

    let resp = common::put_with_auth(
        &mut app,
        &format!("/api/connections/{id}"),
        json!({"password": "new-secret"}),
        &token,
    )
    .await;
    resp.assert_ok();

    let after: Value = common::get_with_auth(&mut app, "/api/connections", &token)
        .await
        .json_value()
        .await;
    let row_after = after["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id.as_str())
        .unwrap()
        .clone();

    // AES-256-GCM minted a fresh ciphertext (never plaintext equality).
    assert_ne!(
        row_before["password_encrypted"], row_after["password_encrypted"],
        "supplied password must be re-encrypted"
    );
    assert_ne!(row_after["password_encrypted"], "new-secret");
}

#[tokio::test]
async fn update_connection_missing_returns_404() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "u05-404@example.com").await;

    let resp = common::put_with_auth(
        &mut app,
        "/api/connections/no-such-row",
        json!({"name": "x"}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "NOT_FOUND");
}

#[tokio::test]
async fn update_connection_requires_auth() {
    let mut app = common::build_test_app().await;

    let resp = common::put(
        &mut app,
        "/api/connections/any-id",
        json!({"name": "x"}),
    )
    .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}
