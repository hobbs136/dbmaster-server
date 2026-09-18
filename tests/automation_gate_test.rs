//! Integration tests for automation auth + entitlement gate (ADR-0002 v1-C-1, v1-C-2).
//!
//! Verifies that:
//! - Every automation route requires a valid access token (v1-C-1).
//! - When `EntitlementState::Gated`, all mutations return 403 ENTITLEMENT_GATED
//!   while read routes remain accessible (v1-C-2).
//! - Default Trial state does not gate mutations (sanity / regression guard).

mod common;

use axum::http::StatusCode;
use serde_json::json;

/// Register a user and return the access token. Auth endpoints are independent
/// of entitlement, so this works under any EntitlementState.
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

// ── v1-C-1: every automation route requires Claims ──

#[tokio::test]
async fn automation_get_routes_require_auth() {
    let mut app = common::build_test_app().await;

    // No Authorization header on any GET automation route → 401.
    for uri in ["/api/tasks", "/api/connections", "/api/approvals", "/api/reports"] {
        common::get(&mut app, uri)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn automation_post_routes_require_auth() {
    let mut app = common::build_test_app().await;

    // create_task without auth → 401 (extractor runs before any handler logic,
    // so the missing FK / validation issues never come into play).
    common::post(
        &mut app,
        "/api/tasks",
        json!({
            "name": "x",
            "task_type": "schema_drift",
            "cron_expr": "*",
            "config": {},
            "source_db_id": "x",
            "target_db_id": null,
            "notify_channels": [],
        }),
    )
    .await
    .assert_status(StatusCode::UNAUTHORIZED);

    // create_connection without auth → 401.
    common::post(
        &mut app,
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
    )
    .await
    .assert_status(StatusCode::UNAUTHORIZED);
}

// ── v1-C-2: Gated blocks mutations, reads stay open ──

fn gated_state() -> dbmaster_license::EntitlementState {
    dbmaster_license::EntitlementState::Gated {
        reason: dbmaster_license::GatedReason::TrialExpired,
    }
}

#[tokio::test]
async fn gated_blocks_create_task() {
    let mut app = common::build_test_app_with_entitlement(gated_state()).await;
    let token = register_and_get_token(&mut app, "gate-task@example.com").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/tasks",
        json!({
            "name": "drift-watch",
            "task_type": "schema_drift",
            "cron_expr": "*/5 * * * *",
            "config": {},
            "source_db_id": "any-id",
            "target_db_id": null,
            "notify_channels": [],
        }),
        &token,
    )
    .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "ENTITLEMENT_GATED");
}

#[tokio::test]
async fn gated_blocks_create_connection() {
    let mut app = common::build_test_app_with_entitlement(gated_state()).await;
    let token = register_and_get_token(&mut app, "gate-conn@example.com").await;

    let resp = common::post_with_auth(
        &mut app,
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
        &token,
    )
    .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "ENTITLEMENT_GATED");
}

#[tokio::test]
async fn gated_blocks_submit_approval() {
    let mut app = common::build_test_app_with_entitlement(gated_state()).await;
    let token = register_and_get_token(&mut app, "gate-approval@example.com").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/approvals",
        json!({
            "ddl_sql": "ALTER TABLE t ADD COLUMN c INT;",
            "target_db_id": "any-id",
        }),
        &token,
    )
    .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "ENTITLEMENT_GATED");
}

#[tokio::test]
async fn gated_blocks_save_query() {
    let mut app = common::build_test_app_with_entitlement(gated_state()).await;
    let token = register_and_get_token(&mut app, "gate-query@example.com").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/queries",
        json!({
            "title": "q",
            "sql_text": "SELECT 1",
            "tags": [],
        }),
        &token,
    )
    .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "ENTITLEMENT_GATED");
}

#[tokio::test]
async fn gated_allows_read_routes() {
    let mut app = common::build_test_app_with_entitlement(gated_state()).await;
    let token = register_and_get_token(&mut app, "gate-read@example.com").await;

    // Reads must stay open so gated users can still see their data.
    for uri in [
        "/api/tasks",
        "/api/connections",
        "/api/approvals",
        "/api/reports",
        // #4 — list_saved_queries is a read route; gated users must still see
        // their saved queries (the gate blocks POST/DELETE, not GET).
        "/api/queries",
        // reports-M1（#29）— query-stats 读端点同策略（visible-but-locked）。
        "/api/query-stats",
        "/api/query-stats/summary",
    ] {
        common::get_with_auth(&mut app, uri, &token)
            .await
            .assert_status(StatusCode::OK);
    }
}

// ── Sanity: Trial (default) does not gate mutations ──

#[tokio::test]
async fn trial_does_not_gate_mutations() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "trial-mut@example.com").await;

    let resp = common::post_with_auth(
        &mut app,
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
        &token,
    )
    .await;

    // Specifically NOT 403. (May be 200 with ok:true, or other failure code
    // for unrelated reasons; the gate is what we're proving here.)
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Trial entitlement must not gate automation mutations"
    );
}

// ── v1-C-1 follow-up: created_by / submitter_id captured from claims ──

#[tokio::test]
async fn create_connection_records_authenticated_user_as_created_by() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "audit@example.com").await;

    // Create a connection.
    let resp = common::post_with_auth(
        &mut app,
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
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["ok"], true);

    // created_by must be the authenticated user id (NOT the legacy "system").
    let created_by = body["data"]["created_by"].as_str().unwrap();
    assert!(
        !created_by.is_empty() && created_by != "system",
        "created_by should be the user id, got {created_by}"
    );

    // list_connections should surface the same created_by.
    let listed: serde_json::Value =
        common::get_with_auth(&mut app, "/api/connections", &token)
            .await
            .json_value()
            .await;
    let rows = listed["data"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["created_by"].as_str().unwrap(), created_by);
}
