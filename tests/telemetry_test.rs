//! Integration tests for `POST /api/telemetry/event` (telemetry-funnel-plan.md §6).
//!
//! Covers the contract surface end-to-end via the assembled test app:
//!   * all 6 new funnel event types are accepted,
//!   * unknown event types are rejected with a permanent 200+ok=false body
//!     (so the desktop client drops the poison-pill event rather than retrying),
//!   * idempotency dedup returns `deduplicated: true` on a second identical hit,
//!   * events without `idempotency_key` are not deduped (legacy-client compat),
//!   * rate limit returns 429 once the per-install_uuid cap is exceeded,
//!   * rate limit budget is independent per install_uuid,
//!   * `/api/health` surfaces `funnel_lite_enabled: bool` (D5).
//!
//! DEFENSIVE: assertions check status + body only; no direct DB access (the
//! pool is held inside the assembled app). Column-population correctness is
//! guaranteed by the migration running cleanly + the INSERT succeeding + the
//! dedup branch firing (which proves the unique index exists).

mod common;

use axum::http::StatusCode;
use serde_json::{json, Value};

/// Build a minimal valid telemetry body for `event_type` with the given
/// install_uuid + idempotency_key. Mirrors what the desktop client sends.
fn event_body(event_type: &str, install_uuid: &str, idem: &str) -> Value {
    json!({
        "event_type": event_type,
        "event_payload": {
            "install_uuid": install_uuid,
            "app_version": "0.0.1+1",
            "idempotency_key": idem,
            "os": "windows",
            "locale": "en",
        }
    })
}

#[tokio::test]
async fn accepts_all_six_new_funnel_event_types() {
    let new_types = [
        "touchpoint_exposed",
        "touchpoint_clicked",
        "server_download_clicked",
        "server_connected",
        "trial_started",
        "trial_activated",
    ];

    for ty in new_types {
        let mut app = common::build_test_app().await;
        let resp = common::post(
            &mut app,
            "/api/telemetry/event",
            event_body(ty, "11111111-1111-4111-8111-111111111111", "k1"),
        )
        .await;
        resp.assert_status(StatusCode::OK);
        let body: Value = resp.json_value().await;
        assert_eq!(body["ok"], true, "[{ty}] ok should be true");
        assert_eq!(body["data"]["ingested"], true, "[{ty}] ingested should be true");
        assert_eq!(
            body["data"]["deduplicated"],
            false,
            "[{ty}] first insert must not be a dedup"
        );
    }
}

#[tokio::test]
async fn legacy_event_types_still_accepted() {
    // Regression guard: existing whitelist entries must keep working.
    let mut app = common::build_test_app().await;
    let resp = common::post(
        &mut app,
        "/api/telemetry/event",
        event_body("feature_used", "legacy-install", "lk1"),
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json_value().await;
    assert_eq!(body["data"]["ingested"], true);
}

#[tokio::test]
async fn rejects_unknown_event_type_as_permanent_failure() {
    let mut app = common::build_test_app().await;
    let resp = common::post(
        &mut app,
        "/api/telemetry/event",
        event_body("evil_event", "inst-x", "k1"),
    )
    .await;
    // 200 + ok=false (NOT 4xx) — desktop treats 4xx as permanent-drop anyway,
    // but the unified envelope lets it read the structured INVALID_EVENT_TYPE
    // code if it ever wants to.
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json_value().await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["data"], Value::Null);
    assert_eq!(body["error"]["code"], "INVALID_EVENT_TYPE");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("evil_event"));
}

#[tokio::test]
async fn idempotency_dedupes_second_identical_insert() {
    let mut app = common::build_test_app().await;
    let body = event_body(
        "server_connected",
        "22222222-2222-4222-8222-222222222222",
        "same-key",
    );

    let first = common::post(&mut app, "/api/telemetry/event", body.clone()).await;
    first.assert_status(StatusCode::OK);
    let v1: Value = first.json_value().await;
    assert_eq!(v1["data"]["ingested"], true);
    assert_eq!(v1["data"]["deduplicated"], false);

    let second = common::post(&mut app, "/api/telemetry/event", body).await;
    second.assert_status(StatusCode::OK);
    let v2: Value = second.json_value().await;
    assert_eq!(v2["data"]["ingested"], false);
    assert_eq!(v2["data"]["deduplicated"], true);
}

#[tokio::test]
async fn distinct_idempotency_keys_are_not_deduped() {
    let mut app = common::build_test_app().await;
    let install = "33333333-3333-4333-8333-333333333333";

    let first = common::post(
        &mut app,
        "/api/telemetry/event",
        event_body("touchpoint_exposed", install, "key-A"),
    )
    .await;
    first.assert_status(StatusCode::OK);
    let v1: Value = first.json_value().await;
    assert_eq!(v1["data"]["ingested"], true);

    let second = common::post(
        &mut app,
        "/api/telemetry/event",
        event_body("touchpoint_exposed", install, "key-B"),
    )
    .await;
    second.assert_status(StatusCode::OK);
    let v2: Value = second.json_value().await;
    assert_eq!(v2["data"]["ingested"], true);
    assert_eq!(v2["data"]["deduplicated"], false);
}

#[tokio::test]
async fn events_without_idempotency_key_are_inserted_not_deduped() {
    // Legacy clients (or any payload that omits idempotency_key) must not be
    // rejected by the partial unique index — both inserts should land.
    let mut app = common::build_test_app().await;
    let payload = json!({
        "event_type": "feature_used",
        "event_payload": {
            "install_uuid": "44444444-4444-4444-8444-444444444444",
            "feature_id": "schema_diff_compare",
        }
    });

    let first = common::post(&mut app, "/api/telemetry/event", payload.clone()).await;
    first.assert_status(StatusCode::OK);
    let v1: Value = first.json_value().await;
    assert_eq!(v1["data"]["ingested"], true);
    assert_eq!(v1["data"]["deduplicated"], false);

    let second = common::post(&mut app, "/api/telemetry/event", payload).await;
    second.assert_status(StatusCode::OK);
    let v2: Value = second.json_value().await;
    assert_eq!(v2["data"]["ingested"], true);
    assert_eq!(v2["data"]["deduplicated"], false);
}

#[tokio::test]
async fn rate_limit_returns_429_after_per_install_cap() {
    let mut app = common::build_test_app().await;
    let install = "rate-test-install";

    // Saturate the per-install_uuid budget (60 req/min per telemetry.rs).
    for i in 0..60 {
        let resp = common::post(
            &mut app,
            "/api/telemetry/event",
            event_body("feature_used", install, &format!("k{i}")),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request {i} should pass, got {}",
            resp.status()
        );
    }

    // 61st within the same window → 429.
    let resp = common::post(
        &mut app,
        "/api/telemetry/event",
        event_body("feature_used", install, "overflow"),
    )
    .await;
    resp.assert_status(StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn rate_limit_budget_is_independent_per_install_uuid() {
    let mut app = common::build_test_app().await;
    // inst-a burns through its own budget.
    for i in 0..60 {
        let _ = common::post(
            &mut app,
            "/api/telemetry/event",
            event_body("feature_used", "inst-a", &format!("a{i}")),
        )
        .await;
    }
    // inst-b must still be under its own budget.
    let resp = common::post(
        &mut app,
        "/api/telemetry/event",
        event_body("feature_used", "inst-b", "b1"),
    )
    .await;
    resp.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn health_endpoint_surfaces_funnel_lite_enabled_flag() {
    // D5 (telemetry-funnel-plan.md §1.B / §12): the desktop client reads
    // `funnel_lite_enabled: bool` from /api/health. Field presence + type is
    // the contract surface; the default comes from Config::from_env.
    let mut app = common::build_test_app().await;
    let resp = common::get(&mut app, "/api/health").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json_value().await;
    assert_eq!(body["status"], "ok");
    assert!(
        body["funnel_lite_enabled"].is_boolean(),
        "funnel_lite_enabled must be a bool, got: {body}"
    );
}

#[tokio::test]
async fn ingestion_does_not_require_auth() {
    // Funnel first hop: anonymous clients (not yet logged in / not connected
    // to a server) must be able to ingest. Confirms no auth middleware leaked
    // onto the telemetry route.
    let mut app = common::build_test_app().await;
    let resp = common::post(
        &mut app,
        "/api/telemetry/event",
        event_body("app_first_launch", "anon-install", "anon-1"),
    )
    .await;
    resp.assert_status(StatusCode::OK);
}
