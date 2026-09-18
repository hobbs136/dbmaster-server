//! M5 T29/T30 — health_check read endpoint + license-gate integration tests.
//!
//! Covers:
//! - `GET /api/health-results?task_id=` returns `{ok:true, data:[]}` for a task
//!   with no history (list-missing-task-returns-[] semantics).
//! - `GET /api/health-results` rejects bad query (missing task_id) with BAD_QUERY.
//! - `GET /api/health-results` is readable under Gated entitlement (read-only,
//!   no gate — same policy as run-history / snapshots).
//! - `POST /api/tasks` with `task_type: "health_check"` under Gated entitlement
//!   returns 403 ENTITLEMENT_GATED (mutation gate, ADR-0004 §5 NF4).

mod common;

use axum::http::StatusCode;
use serde_json::json;

use dbmaster_license::{EntitlementState, GatedReason};

/// Register a user and return their access token. Mirrors automation_gate_test.
async fn register_and_get_token(app: &mut axum::Router, email: &str) -> String {
    let body: serde_json::Value = common::post(
        app,
        "/api/auth/register",
        json!({
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

fn gated_state() -> EntitlementState {
    EntitlementState::Gated {
        reason: GatedReason::TrialExpired,
    }
}

#[tokio::test]
async fn health_results_empty_list_for_unknown_task() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "hr-empty@example.com").await;

    let resp = common::get_with_auth(
        &mut app,
        "/api/health-results?task_id=never-existed",
        &token,
    )
    .await;
    resp.assert_ok();
    let body: serde_json::Value = resp.json_value().await;
    assert!(body["ok"].as_bool().unwrap());
    assert!(body["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn health_results_rejects_missing_task_id() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app, "hr-badq@example.com").await;

    // No task_id at all → BAD_QUERY (400), not 403/500.
    let resp = common::get_with_auth(&mut app, "/api/health-results", &token).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "BAD_QUERY");
}

#[tokio::test]
async fn health_results_readable_under_gated_entitlement() {
    // Read-only endpoint: no gate. A Gated instance can still list history
    // (visible-but-locked policy, mirrors run-history / snapshots).
    let mut app = common::build_test_app_with_entitlement(gated_state()).await;
    let token = register_and_get_token(&mut app, "hr-gated@example.com").await;

    let resp = common::get_with_auth(
        &mut app,
        "/api/health-results?task_id=any",
        &token,
    )
    .await;
    // NOT 403 — reads stay open under Gated.
    resp.assert_ok();
}

#[tokio::test]
async fn gated_blocks_create_health_check_task() {
    // Mutation gate: creating a health_check task under Gated entitlement
    // returns 403 ENTITLEMENT_GATED (ADR-0004 §5 NF4).
    let mut app = common::build_test_app_with_entitlement(gated_state()).await;
    let token = register_and_get_token(&mut app, "hc-gate@example.com").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/tasks",
        json!({
            "name": "prod-health",
            "task_type": "health_check",
            "cron_expr": "*/10 * * * *",
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
