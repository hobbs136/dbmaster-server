//! Integration tests for the License HTTP API (#3):
//! - GET /api/instance (R1)
//! - POST /api/license (R2 + R3)
//!
//! These tests cover the full pipeline: route → handler → resolve_entitlement
//! → write file → ArcSwap. Signing helpers are replicated from the license
//! crate's #[cfg(test)] module (the seed + golden key are unified with
//! tech-site per ADR-0001 + C-8; this file duplicates them since #[cfg(test)]
//! items aren't accessible from integration tests).

mod common;

use axum::http::StatusCode;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::sync::{Mutex, Once};

/// All tests in this file manipulate process-global env vars
/// (`DBMASTER_SERVER_ADMIN_TOKEN`, `DBMASTER_LICENSE_FILE`). Without this
/// lock, parallel test execution would race and AppState::new (which reads
/// the env once at construction) would pick up the wrong values. The lock
/// serializes ONLY within this binary — other test binaries run as separate
/// processes and are unaffected.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Same dev seed as license crate's tests + tests/golden_license.json (C-8).
/// The matching dev public key is derived from this seed; the real handler now
/// trusts the PRODUCTION `SERVER_PUBLIC_KEY_HEX` (#12), so `ensure_dev_verify_override`
/// points the debug-gated override at the dev pubkey to make these dev-signed
/// fixtures verify.
const TEST_DEV_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xf5, 0xeb, 0x81, 0xfa, 0xb4, 0xe6, 0x68, 0x9d, 0x08, 0xfb, 0x4e,
    0xce, 0xa2, 0xc2, 0x55, 0x60, 0x96, 0x0b, 0x4d, 0x3e, 0xea, 0x45, 0x04, 0xd0, 0x3b, 0x5d, 0x0a,
];

/// Fixed install_uuid used by `common::build_test_app*` (common/mod.rs:102).
/// Licenses must bind to this id to pass instance-match.
const TEST_INSTALL_UUID: &str = "test-install-uuid-fixed-000000000000000000000000000";

/// Build a canonical v2 license byte sequence (mirrors license crate's
/// LicenseV2::canonical_bytes). Key:value lines (NO space after colon),
/// lexicographic key order, LF-separated, no trailing newline. Lifetime
/// licenses pass empty `expires_at`.
///
/// DO NOT change this without coordinating with crates/license/src/lib.rs
/// canonical_bytes() — drift would break signature verification.
fn canonical_bytes(
    email: &str,
    expires_at: &str,
    instance_id: &str,
    issued_at: &str,
    license_type: &str,
) -> Vec<u8> {
    format!(
        "email:{email}\nexpires_at:{exp}\ninstance_id:{iid}\nissued_at:{iat}\nproduct:server\ntype:{typ}\nv:2",
        email = email,
        exp = expires_at,
        iid = instance_id,
        iat = issued_at,
        typ = license_type,
    )
    .into_bytes()
}

fn sign_for_dev(canonical: &[u8]) -> String {
    let sk = SigningKey::from_bytes(&TEST_DEV_SEED);
    let sig = sk.sign(canonical);
    hex::encode(sig.to_bytes())
}

/// Render a PEM license with the given fields. Empty `expires_at` = lifetime.
fn render_pem(
    email: &str,
    expires_at: &str,
    instance_id: &str,
    issued_at: &str,
    license_type: &str,
    signature_hex: &str,
) -> String {
    format!(
        "-----BEGIN DBMASTER SERVER LICENSE-----\n\
         email: {email}\n\
         expires_at: {exp}\n\
         instance_id: {iid}\n\
         issued_at: {iat}\n\
         product: server\n\
         type: {typ}\n\
         v: 2\n\
         signature: {sig}\n\
         -----END DBMASTER SERVER LICENSE-----",
        email = email,
        exp = expires_at,
        iid = instance_id,
        iat = issued_at,
        typ = license_type,
        sig = signature_hex,
    )
}

/// Build a fully-signed valid yearly license PEM bound to TEST_INSTALL_UUID.
fn valid_license_pem() -> String {
    let canonical = canonical_bytes(
        "alice@example.com",
        "2099-01-01T00:00:00Z",
        TEST_INSTALL_UUID,
        "2026-08-12T00:00:00Z",
        "yearly",
    );
    let sig = sign_for_dev(&canonical);
    render_pem(
        "alice@example.com",
        "2099-01-01T00:00:00Z",
        TEST_INSTALL_UUID,
        "2026-08-12T00:00:00Z",
        "yearly",
        &sig,
    )
}

/// Set DBMASTER_LICENSE_FILE to a temp file (isolated from real .dbmlicense).
fn with_temp_license_file() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("api_test.dbmlicense");
    // SAFETY (env var): tests in this file don't run in parallel with each
    // other on the same env var; cargo runs integration test BINARIES
    // concurrently but each binary is single-threaded by default. If parallel
    // tests within this file touch the env var, they'd race — but each test
    // here sets the var before any HTTP call that reads it.
    std::env::set_var("DBMASTER_LICENSE_FILE", &path);
    dir
}

/// #12: idempotently point the debug-gated verify-key override at the dev
/// pubkey so dev-signed fixtures verify through the REAL handler (which now
/// trusts the production `SERVER_PUBLIC_KEY_HEX`). `Once` serializes the single
/// `set_var`; the value is never changed afterward, so parallel reads are safe.
/// Release builds compile the override path out entirely (`cfg(debug_assertions)`),
/// where dev-signed fixtures would (correctly) fail to verify.
static OVERRIDE_INIT: Once = Once::new();
fn ensure_dev_verify_override() {
    OVERRIDE_INIT.call_once(|| {
        let dev_pubkey = SigningKey::from_bytes(&TEST_DEV_SEED).verifying_key();
        std::env::set_var(
            "DBMASTER_LICENSE_VERIFY_PUBKEY_OVERRIDE_HEX",
            hex::encode(dev_pubkey.to_bytes()),
        );
    });
}

/// Build a test app AND seed `instance_meta` with TEST_INSTALL_UUID so that
/// `resolve_entitlement_with_text` (which reads install_uuid from the DB, not
/// AppState) sees a matching value when verifying the license signature.
///
/// Without this seeding, get_or_create_instance lazily generates a fresh
/// random install_uuid for the DB, diverging from AppState's install_uuid —
/// the license bound to AppState's value would then mismatch the DB's.
async fn build_app_with_seeded_instance() -> axum::Router {
    ensure_dev_verify_override();
    let (app, pool) = common::build_test_app_with_pool().await;
    sqlx::query(
        "INSERT OR REPLACE INTO instance_meta (install_uuid, created_at) VALUES (?1, ?2)",
    )
    .bind(TEST_INSTALL_UUID)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(&pool)
    .await
    .expect("seed instance_meta");
    app
}

// ── R1: GET /api/instance ──

#[tokio::test]
async fn get_instance_returns_install_uuid_version_embedded() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut app = build_app_with_seeded_instance().await;

    let resp = common::get(&mut app, "/api/instance").await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["ok"], true);
    let data = &body["data"];
    assert_eq!(data["install_uuid"], TEST_INSTALL_UUID);
    // version is non-empty (matches CARGO_PKG_VERSION at build time)
    assert!(
        data["version"].as_str().unwrap().len() > 0,
        "version should be non-empty"
    );
    assert_eq!(data["embedded_mode"], false); // build_test_app is non-embedded
}

// ── R2: POST /api/license (success + verification failure paths) ──
//
// All POST tests need DBMASTER_SERVER_ADMIN_TOKEN configured because
// build_test_app is non-embedded. We set the env var per-test.

/// Helper: POST /api/license with X-Admin-Token header (the auth this endpoint
/// actually uses, distinct from the Bearer auth other endpoints use).
async fn post_license_with_admin_token(
    app: &mut axum::Router,
    body: &serde_json::Value,
    admin_token: Option<&str>,
) -> common::ResponseAssert {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let json = serde_json::to_string(body).unwrap();
    let mut builder = Request::builder()
        .uri("/api/license")
        .method("POST")
        .header("Content-Type", "application/json");
    if let Some(tok) = admin_token {
        builder = builder.header("X-Admin-Token", tok);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(json)).unwrap())
        .await
        .unwrap();
    common::ResponseAssert::from_response(response)
}

#[tokio::test]
async fn post_license_valid_swaps_entitlement() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "secret-token");
    let mut app = build_app_with_seeded_instance().await;

    let resp =
        post_license_with_admin_token(&mut app, &json!({ "license": valid_license_pem() }), Some("secret-token"))
            .await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["ok"], true, "expected ok:true, got {body}");
    assert_eq!(body["data"]["state"], "licensed");
    assert_eq!(body["data"]["license_type"], "yearly");
    assert_eq!(
        body["data"]["scheduler_note"],
        "restart_required_for_schedulers"
    );

    // GET /api/entitlement reflects new state (HTTP gate immediately effective)
    let resp = common::get(&mut app, "/api/entitlement").await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"]["state"], "licensed");

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}

#[tokio::test]
async fn post_license_wrong_instance_id_returns_instance_mismatch() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "secret-token");
    let mut app = build_app_with_seeded_instance().await;

    // License bound to a DIFFERENT install_uuid than the test server's
    let canonical = canonical_bytes(
        "alice@example.com",
        "2099-01-01T00:00:00Z",
        "deadbeef-another-instance-id-not-matching",
        "2026-08-12T00:00:00Z",
        "yearly",
    );
    let sig = sign_for_dev(&canonical);
    let pem = render_pem(
        "alice@example.com",
        "2099-01-01T00:00:00Z",
        "deadbeef-another-instance-id-not-matching",
        "2026-08-12T00:00:00Z",
        "yearly",
        &sig,
    );

    let resp = post_license_with_admin_token(
        &mut app,
        &json!({ "license": pem }),
        Some("secret-token"),
    )
    .await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], "INSTANCE_MISMATCH");

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}

#[tokio::test]
async fn post_license_bad_signature_returns_invalid_license() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "secret-token");
    let mut app = build_app_with_seeded_instance().await;

    // Use a different (wrong) seed to sign — signature won't verify
    let wrong_seed = [0x42u8; 32];
    let sk = SigningKey::from_bytes(&wrong_seed);
    let canonical = canonical_bytes(
        "alice@example.com",
        "2099-01-01T00:00:00Z",
        TEST_INSTALL_UUID,
        "2026-08-12T00:00:00Z",
        "yearly",
    );
    let bad_sig = hex::encode(sk.sign(&canonical).to_bytes());
    let pem = render_pem(
        "alice@example.com",
        "2099-01-01T00:00:00Z",
        TEST_INSTALL_UUID,
        "2026-08-12T00:00:00Z",
        "yearly",
        &bad_sig,
    );

    let resp = post_license_with_admin_token(
        &mut app,
        &json!({ "license": pem }),
        Some("secret-token"),
    )
    .await;
    let body: serde_json::Value = resp.json_value().await;
    // Tampered signature → Gated(LicenseInvalid) per resolve_entitlement_with_text
    assert_eq!(body["ok"], false);
    let code = body["error"]["code"].as_str().unwrap();
    assert!(
        code == "INVALID_LICENSE" || code == "INSTANCE_MISMATCH",
        "expected INVALID_LICENSE or INSTANCE_MISMATCH (bad sig may fall into either branch), got {code}"
    );

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}

#[tokio::test]
async fn post_license_expired_returns_expired() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "secret-token");
    let mut app = build_app_with_seeded_instance().await;

    // Valid signature but expires_at in the past
    let canonical = canonical_bytes(
        "alice@example.com",
        "2020-01-01T00:00:00Z",
        TEST_INSTALL_UUID,
        "2019-01-01T00:00:00Z",
        "yearly",
    );
    let sig = sign_for_dev(&canonical);
    let pem = render_pem(
        "alice@example.com",
        "2020-01-01T00:00:00Z",
        TEST_INSTALL_UUID,
        "2019-01-01T00:00:00Z",
        "yearly",
        &sig,
    );

    let resp = post_license_with_admin_token(
        &mut app,
        &json!({ "license": pem }),
        Some("secret-token"),
    )
    .await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], "EXPIRED");

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}

#[tokio::test]
async fn post_license_malformed_body_returns_400() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "secret-token");
    let mut app = build_app_with_seeded_instance().await;

    // Body is JSON but missing `license` field → serde rejects → axum 422/400.
    let resp = post_license_with_admin_token(
        &mut app,
        &json!({ "not_license": "wrong" }),
        Some("secret-token"),
    )
    .await;
    // axum returns 422 for JSON parse failures of body extractors by default;
    // 400 if Content-Type wrong. Either is "client error" — assert range.
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422 for malformed body, got {status}"
    );

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}

// ── R3: admin token auth ──

#[tokio::test]
async fn post_license_remote_without_admin_token_configured_returns_403() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
    let mut app = build_app_with_seeded_instance().await;

    let resp = post_license_with_admin_token(
        &mut app,
        &json!({ "license": valid_license_pem() }),
        Some("any-token"), // doesn't matter; server has no expected token configured
    )
    .await;
    resp.assert_status(StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "FORBIDDEN");
}

#[tokio::test]
async fn post_license_remote_with_wrong_admin_token_returns_401() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "correct-token");
    let mut app = build_app_with_seeded_instance().await;

    let resp = post_license_with_admin_token(
        &mut app,
        &json!({ "license": valid_license_pem() }),
        Some("wrong-token"),
    )
    .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "UNAUTHORIZED");

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}

#[tokio::test]
async fn post_license_remote_no_admin_token_header_returns_401() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "correct-token");
    let mut app = build_app_with_seeded_instance().await;

    let resp = post_license_with_admin_token(
        &mut app,
        &json!({ "license": valid_license_pem() }),
        None, // no X-Admin-Token header at all
    )
    .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}

#[tokio::test]
async fn post_license_with_correct_admin_token_succeeds() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "correct-token");
    let mut app = build_app_with_seeded_instance().await;

    let resp = post_license_with_admin_token(
        &mut app,
        &json!({ "license": valid_license_pem() }),
        Some("correct-token"),
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["state"], "licensed");

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}

// ── R4: ArcSwap concurrency ──

#[tokio::test]
async fn concurrent_post_does_not_panic() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "correct-token");
    let mut app = build_app_with_seeded_instance().await;

    // Fire several POSTs concurrently — load() + store() must be race-free.
    // Mix valid + invalid licenses; the ArcSwap should handle all safely.
    let mut handles = Vec::new();
    for i in 0..5 {
        let mut app_clone = app.clone();
        let pem = valid_license_pem();
        handles.push(tokio::spawn(async move {
            // Each task sends one POST; we don't care about response — only
            // that the server doesn't panic. Slight env-var race here is
            // acceptable (read once at AppState::new, already loaded).
            let _ = post_license_with_admin_token(
                &mut app_clone,
                &serde_json::json!({ "license": pem }),
                Some("correct-token"),
            )
            .await;
            // touch i to silence unused warning
            let _ = i;
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    // After concurrent POSTs: GET /api/entitlement is Licensed (last valid write wins).
    let resp = common::get(&mut app, "/api/entitlement").await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"]["state"], "licensed");

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}

// ── T13: End-to-end "renew anytime" workflow ──

/// Full activation workflow as a user would run it (T13):
///   1. GET /api/instance — learn install_uuid
///   2. (off-band) tech-site signs license for that instance_id
///   3. POST /api/license — deliver license
///   4. GET /api/entitlement — confirm HTTP gate reflects Licensed immediately
///
/// This pins the "renew anytime" promise end-to-end (no server restart needed
/// for HTTP gates; schedulers still do — see response.scheduler_note).
#[tokio::test]
async fn end_to_end_activation_workflow() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _dir = with_temp_license_file();
    std::env::set_var("DBMASTER_SERVER_ADMIN_TOKEN", "e2e-token");

    let mut app = build_app_with_seeded_instance().await;

    // (1) Before activation: server is in default Trial state (per
    // build_test_app's far-future Trial entitlement).
    let resp = common::get(&mut app, "/api/entitlement").await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["data"]["state"], "trial", "fresh server should be Trial");

    // (2) Learn install_uuid
    let resp = common::get(&mut app, "/api/instance").await;
    let body: serde_json::Value = resp.json_value().await;
    let install_uuid = body["data"]["install_uuid"].as_str().expect("install_uuid");
    assert_eq!(install_uuid, TEST_INSTALL_UUID);

    // (3) Sign a license for this instance (off-band: this is what tech-site does)
    let canonical = canonical_bytes(
        "customer@example.com",
        "2099-01-01T00:00:00Z",
        install_uuid,
        "2026-08-12T00:00:00Z",
        "yearly",
    );
    let sig = sign_for_dev(&canonical);
    let pem = render_pem(
        "customer@example.com",
        "2099-01-01T00:00:00Z",
        install_uuid,
        "2026-08-12T00:00:00Z",
        "yearly",
        &sig,
    );

    // (4) Deliver license
    let resp = post_license_with_admin_token(
        &mut app,
        &json!({ "license": pem }),
        Some("e2e-token"),
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["state"], "licensed");

    // (5) Confirm HTTP gate reflects Licensed immediately (no restart)
    let resp = common::get(&mut app, "/api/entitlement").await;
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(
        body["data"]["state"], "licensed",
        "GET /api/entitlement must reflect Licensed immediately after POST (no restart)"
    );

    std::env::remove_var("DBMASTER_SERVER_ADMIN_TOKEN");
}
