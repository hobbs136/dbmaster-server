//! Integration tests for workspace endpoints.

mod common;

use axum::http::StatusCode;
use serde_json::json;

/// Helper: register a user and return (access_token, user_id).
async fn register_user(app: &mut axum::Router, email: &str, name: &str) -> (String, String) {
    let body: serde_json::Value = common::post(
        app,
        "/api/auth/register",
        json!({
            "email": email,
            "password": "secure12345",
            "display_name": name
        }),
    )
    .await
    .json_value()
    .await;

    (
        body["access_token"].as_str().unwrap().to_string(),
        body["user"]["id"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn create_workspace_success() {
    let mut app = common::build_test_app().await;
    let (token, _) = register_user(&mut app, "admin@example.com", "Admin").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "Test Workspace" }),
        &token,
    )
    .await;

    resp.assert_status(StatusCode::CREATED);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["name"], "Test Workspace");
    assert_eq!(body["role"], "admin");
    assert_eq!(body["member_count"], 1);
    assert!(body["invite_code"].as_str().unwrap().len() == 6);
}

#[tokio::test]
async fn create_workspace_empty_name_returns_400() {
    let mut app = common::build_test_app().await;
    let (token, _) = register_user(&mut app, "user@example.com", "User").await;

    common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "" }),
        &token,
    )
    .await
    .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_workspaces_empty() {
    let mut app = common::build_test_app().await;
    let (token, _) = register_user(&mut app, "lonely@example.com", "Lonely").await;

    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/workspaces", &token)
        .await
        .json_value()
        .await;

    assert!(body["workspaces"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_workspaces_with_membership() {
    let mut app = common::build_test_app().await;
    let (token, _) = register_user(&mut app, "member@example.com", "Member").await;

    // Create a workspace
    common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "My Team" }),
        &token,
    )
    .await;

    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/workspaces", &token)
        .await
        .json_value()
        .await;

    let workspaces = body["workspaces"].as_array().unwrap();
    assert_eq!(workspaces.len(), 1);
    assert_eq!(workspaces[0]["name"], "My Team");
}

#[tokio::test]
async fn get_workspace_detail_with_members() {
    let mut app = common::build_test_app().await;
    let (token, _) = register_user(&mut app, "owner@example.com", "Owner").await;

    // Create workspace
    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "Detail Test" }),
        &token,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();

    // Join another user
    let invite_code = ws["invite_code"].as_str().unwrap().to_string();
    let (token2, _) = register_user(&mut app, "joiner@example.com", "Joiner").await;

    common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/join", ws_id),
        json!({ "invite_code": &invite_code }),
        &token2,
    )
    .await;

    // Get detail
    let detail: serde_json::Value = common::get_with_auth(
        &mut app,
        &format!("/api/workspaces/{}", ws_id),
        &token,
    )
    .await
    .json_value()
    .await;

    assert_eq!(detail["name"], "Detail Test");
    assert_eq!(detail["members"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn get_workspace_non_member_returns_403() {
    let mut app = common::build_test_app().await;
    let (token1, _) = register_user(&mut app, "creator@example.com", "Creator").await;
    let (token2, _) = register_user(&mut app, "outsider@example.com", "Outsider").await;

    // Create workspace as user 1
    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "Private" }),
        &token1,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();

    // User 2 tries to access without joining
    common::get_with_auth(&mut app, &format!("/api/workspaces/{}", ws_id), &token2)
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn join_workspace_success() {
    let mut app = common::build_test_app().await;
    let (token1, _) = register_user(&mut app, "owner2@example.com", "Owner2").await;
    let (token2, _) = register_user(&mut app, "joiner2@example.com", "Joiner2").await;

    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "Joinable" }),
        &token1,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();
    let invite_code = ws["invite_code"].as_str().unwrap();

    let resp = common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/join", ws_id),
        json!({ "invite_code": invite_code }),
        &token2,
    )
    .await;

    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json_value().await;
    assert_eq!(body["role"], "member");
    assert_eq!(body["workspace_id"], ws_id);
}

#[tokio::test]
async fn join_workspace_bad_invite_code_returns_409() {
    let mut app = common::build_test_app().await;
    let (token1, _) = register_user(&mut app, "owner3@example.com", "Owner3").await;
    let (token2, _) = register_user(&mut app, "joiner3@example.com", "Joiner3").await;

    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "CodeTest" }),
        &token1,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();

    // Try with wrong code
    common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/join", ws_id),
        json!({ "invite_code": "WRONG1" }),
        &token2,
    )
    .await
    .assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn join_workspace_already_member_returns_409() {
    let mut app = common::build_test_app().await;
    let (token, _) = register_user(&mut app, "dup@example.com", "Dup").await;

    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "DupTest" }),
        &token,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();
    let invite_code = ws["invite_code"].as_str().unwrap();

    // Creator is already a member, trying to join again should fail
    common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/join", ws_id),
        json!({ "invite_code": invite_code }),
        &token,
    )
    .await
    .assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn leave_workspace_success() {
    let mut app = common::build_test_app().await;
    let (token1, _) = register_user(&mut app, "owner4@example.com", "Owner4").await;
    let (token2, _) = register_user(&mut app, "leaver@example.com", "Leaver").await;

    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "LeaveTest" }),
        &token1,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();
    let invite_code = ws["invite_code"].as_str().unwrap();

    // Join as user 2
    common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/join", ws_id),
        json!({ "invite_code": invite_code }),
        &token2,
    )
    .await
    .assert_status(StatusCode::OK);

    // Leave
    common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/leave", ws_id),
        json!({}),
        &token2,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn last_admin_cannot_leave_returns_422() {
    let mut app = common::build_test_app().await;
    let (token, _) = register_user(&mut app, "soleadmin@example.com", "SoleAdmin").await;

    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "SoloTeam" }),
        &token,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();

    common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/leave", ws_id),
        json!({}),
        &token,
    )
    .await
    .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn remove_member_success() {
    let mut app = common::build_test_app().await;
    let (token1, _) = register_user(&mut app, "admin5@example.com", "Admin5").await;
    let (token2, _) = register_user(&mut app, "target@example.com", "Target").await;

    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "RemoveTest" }),
        &token1,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();
    let invite_code = ws["invite_code"].as_str().unwrap();

    // Join as user 2
    let join_resp: serde_json::Value = common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/join", ws_id),
        json!({ "invite_code": invite_code }),
        &token2,
    )
    .await
    .json_value()
    .await;

    let target_uid = join_resp["user_id"].as_str().unwrap();

    // Admin removes the member
    common::delete_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/members/{}", ws_id, target_uid),
        &token1,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn non_admin_cannot_remove_member_returns_403() {
    let mut app = common::build_test_app().await;
    let (token1, _) = register_user(&mut app, "admin6@example.com", "Admin6").await;
    let (token2, _) = register_user(&mut app, "member6@example.com", "Member6").await;
    let (token3, uid3) = register_user(&mut app, "extra6@example.com", "Extra6").await;

    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "AuthTest" }),
        &token1,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();
    let invite_code = ws["invite_code"].as_str().unwrap();

    // Join as user 2 and user 3
    common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/join", ws_id),
        json!({ "invite_code": invite_code }),
        &token2,
    )
    .await;

    common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/join", ws_id),
        json!({ "invite_code": invite_code }),
        &token3,
    )
    .await;

    // User 2 (member) tries to remove user 3
    common::delete_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/members/{}", ws_id, uid3),
        &token2,
    )
    .await
    .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_workspace_success() {
    let mut app = common::build_test_app().await;
    let (token, _) = register_user(&mut app, "deleter@example.com", "Deleter").await;

    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "ToDelete" }),
        &token,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();

    common::delete_with_auth(&mut app, &format!("/api/workspaces/{}", ws_id), &token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Verify deleted
    common::get_with_auth(&mut app, &format!("/api/workspaces/{}", ws_id), &token)
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn non_admin_cannot_delete_workspace_returns_403() {
    let mut app = common::build_test_app().await;
    let (token1, _) = register_user(&mut app, "admin7@example.com", "Admin7").await;
    let (token2, _) = register_user(&mut app, "member7@example.com", "Member7").await;

    let ws: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/workspaces",
        json!({ "name": "NonAdminDel" }),
        &token1,
    )
    .await
    .json_value()
    .await;

    let ws_id = ws["id"].as_str().unwrap();
    let invite_code = ws["invite_code"].as_str().unwrap();

    // Join as regular member
    common::post_with_auth(
        &mut app,
        &format!("/api/workspaces/{}/join", ws_id),
        json!({ "invite_code": invite_code }),
        &token2,
    )
    .await;

    // Regular member tries to delete
    common::delete_with_auth(&mut app, &format!("/api/workspaces/{}", ws_id), &token2)
        .await
        .assert_status(StatusCode::FORBIDDEN);
}