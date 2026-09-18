//! Integration tests for authentication endpoints.
//!
//! Tests: register, login, refresh tokens, rate limiting.

mod common;

use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn register_success() {
    let mut app = common::build_test_app().await;

    let resp = common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "alice@example.com",
            "password": "secure12345",
            "display_name": "Alice"
        }),
    )
    .await;

    resp.assert_status(StatusCode::CREATED);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["user"]["email"], "alice@example.com");
    assert_eq!(body["user"]["display_name"], "Alice");
    assert!(body["access_token"].as_str().unwrap().len() > 10);
    assert!(body["refresh_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn register_duplicate_email_returns_conflict() {
    let mut app = common::build_test_app().await;

    // First registration succeeds
    common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "bob@example.com",
            "password": "secure12345",
            "display_name": "Bob"
        }),
    )
    .await
    .assert_status(StatusCode::CREATED);

    // Second with same email fails
    let resp = common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "bob@example.com",
            "password": "different123",
            "display_name": "Bob2"
        }),
    )
    .await;

    resp.assert_status(StatusCode::CONFLICT);
    let body: serde_json::Value = resp.json_value().await;
    assert!(body["error"]["code"].as_str().unwrap().contains("CONFLICT"));
}

#[tokio::test]
async fn register_email_case_insensitive_unique() {
    let mut app = common::build_test_app().await;

    common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "Carol@Example.com",
            "password": "secure12345",
            "display_name": "Carol"
        }),
    )
    .await
    .assert_status(StatusCode::CREATED);

    // Same email different case should be rejected
    common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "carol@example.com",
            "password": "secure12345",
            "display_name": "Carol2"
        }),
    )
    .await
    .assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_validation_errors() {
    let mut app = common::build_test_app().await;

    // Missing @ in email
    let resp = common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "notanemail",
            "password": "secure12345",
            "display_name": "Test"
        }),
    )
    .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Short password
    let resp = common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "test@example.com",
            "password": "123",
            "display_name": "Test"
        }),
    )
    .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Empty display name
    let resp = common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "test@example.com",
            "password": "secure12345",
            "display_name": ""
        }),
    )
    .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_success() {
    let mut app = common::build_test_app().await;

    // Register first
    common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "dave@example.com",
            "password": "secure12345",
            "display_name": "Dave"
        }),
    )
    .await;

    // Login
    let resp = common::post(
        &mut app,
        "/api/auth/login",
        json!({
            "email": "dave@example.com",
            "password": "secure12345"
        }),
    )
    .await;

    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["user"]["email"], "dave@example.com");
    assert!(body["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn login_wrong_password_returns_401() {
    let mut app = common::build_test_app().await;

    common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "eve@example.com",
            "password": "correct-password",
            "display_name": "Eve"
        }),
    )
    .await;

    let resp = common::post(
        &mut app,
        "/api/auth/login",
        json!({
            "email": "eve@example.com",
            "password": "wrong-password"
        }),
    )
    .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json_value().await;
    assert!(body["error"]["code"].as_str().unwrap().contains("INVALID_CREDENTIALS"));
    // Must not reveal whether email or password was wrong
    assert!(body["error"]["message"].as_str().unwrap().contains("Invalid email or password"));
}

#[tokio::test]
async fn login_nonexistent_email_returns_401() {
    let mut app = common::build_test_app().await;

    let resp = common::post(
        &mut app,
        "/api/auth/login",
        json!({
            "email": "nobody@example.com",
            "password": "some-password"
        }),
    )
    .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_token_success() {
    let mut app = common::build_test_app().await;

    // Register to get tokens
    let body: serde_json::Value = common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "frank@example.com",
            "password": "secure12345",
            "display_name": "Frank"
        }),
    )
    .await
    .json_value()
    .await;

    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // Refresh
    let resp = common::post(
        &mut app,
        "/api/auth/refresh",
        json!({ "refresh_token": &refresh_token }),
    )
    .await;

    resp.assert_status(StatusCode::OK);
    let refreshed: serde_json::Value = resp.json_value().await;
    assert!(refreshed["access_token"].as_str().unwrap().len() > 10);
    assert!(refreshed["refresh_token"].as_str().unwrap().len() > 10);
    // New refresh token should be different from old one (rotation)
    assert_ne!(
        refreshed["refresh_token"].as_str().unwrap(),
        &refresh_token
    );
}

#[tokio::test]
async fn refresh_token_reused_returns_401() {
    let mut app = common::build_test_app().await;

    let body: serde_json::Value = common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "grace@example.com",
            "password": "secure12345",
            "display_name": "Grace"
        }),
    )
    .await
    .json_value()
    .await;

    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // First refresh succeeds and revokes the old token
    common::post(
        &mut app,
        "/api/auth/refresh",
        json!({ "refresh_token": &refresh_token }),
    )
    .await
    .assert_status(StatusCode::OK);

    // Second refresh with same (now revoked) token fails
    common::post(
        &mut app,
        "/api/auth/refresh",
        json!({ "refresh_token": &refresh_token }),
    )
    .await
    .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_token_invalid_returns_401() {
    let mut app = common::build_test_app().await;

    let resp = common::post(
        &mut app,
        "/api/auth/refresh",
        json!({ "refresh_token": "not-a-valid-token" }),
    )
    .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

// Rate limiting: 5 requests/min per IP, shared across register/login/refresh.

#[tokio::test]
async fn login_rate_limited_after_5_attempts() {
    let mut app = common::build_test_app().await;
    let ip = "10.0.0.1";

    // Register from a different IP so it doesn't consume the login budget.
    common::post_with_ip(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "henry@example.com",
            "password": "secure12345",
            "display_name": "Henry"
        }),
        "10.0.0.2",
    )
    .await
    .assert_status(StatusCode::CREATED);

    // First 5 login attempts pass the limiter (all 401 wrong-password).
    for _ in 0..5 {
        common::post_with_ip(
            &mut app,
            "/api/auth/login",
            json!({
                "email": "henry@example.com",
                "password": "wrong-password"
            }),
            ip,
        )
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    }

    // 6th attempt from the same IP is rejected before reaching the handler.
    let resp = common::post_with_ip(
        &mut app,
        "/api/auth/login",
        json!({
            "email": "henry@example.com",
            "password": "secure12345"
        }),
        ip,
    )
    .await;

    resp.assert_status(StatusCode::TOO_MANY_REQUESTS);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["error"]["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn rate_limit_is_per_ip() {
    let mut app = common::build_test_app().await;

    // Exhaust IP A's budget on /api/auth/login.
    for _ in 0..5 {
        common::post_with_ip(
            &mut app,
            "/api/auth/login",
            json!({
                "email": "nobody@example.com",
                "password": "some-password"
            }),
            "10.0.1.1",
        )
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    }
    common::post_with_ip(
        &mut app,
        "/api/auth/login",
        json!({
            "email": "nobody@example.com",
            "password": "some-password"
        }),
        "10.0.1.1",
    )
    .await
    .assert_status(StatusCode::TOO_MANY_REQUESTS);

    // IP B is unaffected — reaches the handler (401, not 429).
    common::post_with_ip(
        &mut app,
        "/api/auth/login",
        json!({
            "email": "nobody@example.com",
            "password": "some-password"
        }),
        "10.0.1.2",
    )
    .await
    .assert_status(StatusCode::UNAUTHORIZED);
}
