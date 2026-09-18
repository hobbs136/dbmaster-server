//! Integration tests for user profile endpoints.

mod common;

use axum::http::StatusCode;
use serde_json::json;

/// Helper: register a user and return the access token.
async fn register_and_get_token(app: &mut axum::Router) -> String {
    let body: serde_json::Value = common::post(
        app,
        "/api/auth/register",
        json!({
            "email": "testuser@example.com",
            "password": "secure12345",
            "display_name": "Test User"
        }),
    )
    .await
    .json_value()
    .await;

    body["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn get_me_authenticated() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app).await;

    let resp = common::get_with_auth(&mut app, "/api/me", &token).await;

    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["email"], "testuser@example.com");
    assert_eq!(body["display_name"], "Test User");
    assert!(!body["id"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn get_me_unauthenticated_returns_401() {
    let mut app = common::build_test_app().await;

    let resp = common::get(&mut app, "/api/me").await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn update_display_name() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app).await;

    let resp = common::patch_with_auth(
        &mut app,
        "/api/me",
        json!({ "display_name": "Updated Name" }),
        &token,
    )
    .await;

    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["display_name"], "Updated Name");
}

#[tokio::test]
async fn update_password() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app).await;

    // Change password
    common::patch_with_auth(
        &mut app,
        "/api/me",
        json!({ "password": "new-password-12345" }),
        &token,
    )
    .await
    .assert_status(StatusCode::OK);

    // Old password should no longer work for login
    let resp = common::post(
        &mut app,
        "/api/auth/login",
        json!({ "email": "testuser@example.com", "password": "secure12345" }),
    )
    .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    // New password should work
    common::post(
        &mut app,
        "/api/auth/login",
        json!({ "email": "testuser@example.com", "password": "new-password-12345" }),
    )
    .await
    .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn update_password_revokes_refresh_tokens() {
    let mut app = common::build_test_app().await;

    // Register and get tokens
    let body: serde_json::Value = common::post(
        &mut app,
        "/api/auth/register",
        json!({
            "email": "revoker@example.com",
            "password": "secure12345",
            "display_name": "Revoker"
        }),
    )
    .await
    .json_value()
    .await;

    let access_token = body["access_token"].as_str().unwrap().to_string();
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // Change password
    common::patch_with_auth(
        &mut app,
        "/api/me",
        json!({ "password": "new-password-12345" }),
        &access_token,
    )
    .await
    .assert_status(StatusCode::OK);

    // Old refresh token should be revoked
    common::post(
        &mut app,
        "/api/auth/refresh",
        json!({ "refresh_token": &refresh_token }),
    )
    .await
    .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn update_me_validation_errors() {
    let mut app = common::build_test_app().await;
    let token = register_and_get_token(&mut app).await;

    // Empty display name
    common::patch_with_auth(
        &mut app,
        "/api/me",
        json!({ "display_name": "" }),
        &token,
    )
    .await
    .assert_status(StatusCode::BAD_REQUEST);

    // Short password
    common::patch_with_auth(
        &mut app,
        "/api/me",
        json!({ "password": "123" }),
        &token,
    )
    .await
    .assert_status(StatusCode::BAD_REQUEST);
}
