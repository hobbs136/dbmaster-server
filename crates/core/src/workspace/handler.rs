//! REST handlers for workspace CRUD, join, leave, and member management.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use uuid::Uuid;

use crate::auth::jwt::Claims;
use crate::error::AppError;
use crate::server::AppState;
use crate::workspace::invite;
use crate::workspace::model::{
    CreateWorkspaceRequest, JoinRequest, MemberInfo, MembershipResponse, WorkspaceListItem,
    WorkspaceListResponse, WorkspaceWithMembers,
};

/// `GET /api/workspaces` — List all workspaces the authenticated user is a member of.
pub async fn list_workspaces(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<WorkspaceListResponse>, AppError> {
    let rows = sqlx::query_as::<_, WorkspaceListRow>(
        r#"SELECT w.id, w.name, w.owner_id, w.invite_code, w.created_at,
                  (SELECT COUNT(*) FROM workspace_members wm2 WHERE wm2.workspace_id = w.id) AS member_count,
                  wm.role
           FROM workspaces w
           JOIN workspace_members wm ON wm.workspace_id = w.id
           WHERE wm.user_id = ?
           ORDER BY w.created_at DESC"#,
    )
    .bind(&claims.sub)
    .fetch_all(&state.pool)
    .await?;

    let workspaces = rows
        .into_iter()
        .map(|r| WorkspaceListItem {
            id: r.id,
            name: r.name,
            owner_id: r.owner_id,
            invite_code: r.invite_code,
            member_count: r.member_count,
            role: r.role,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(WorkspaceListResponse { workspaces }))
}

/// `POST /api/workspaces` — Create a new workspace. The creating user becomes admin.
pub async fn create_workspace(
    claims: Claims,
    State(state): State<AppState>,
    Json(req): Json<CreateWorkspaceRequest>,
) -> Result<(StatusCode, Json<WorkspaceListItem>), AppError> {
    let req = req.normalized();
    req.validate().map_err(AppError::Validation)?;

    let workspace_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let invite_code = invite::generate_unique_invite_code(&state.pool).await?;

    sqlx::query(
        "INSERT INTO workspaces (id, name, owner_id, invite_code, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&workspace_id)
    .bind(&req.name)
    .bind(&claims.sub)
    .bind(&invite_code)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    // Auto-join the creator as admin
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, role, joined_at) VALUES (?, ?, 'admin', ?)",
    )
    .bind(&workspace_id)
    .bind(&claims.sub)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(WorkspaceListItem {
            id: workspace_id,
            name: req.name,
            owner_id: claims.sub,
            invite_code,
            member_count: 1,
            role: "admin".to_string(),
            created_at: now,
        }),
    ))
}

/// `GET /api/workspaces/:id` — Get workspace detail with full member list.
pub async fn get_workspace(
    claims: Claims,
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
) -> Result<Json<WorkspaceWithMembers>, AppError> {
    // Verify membership
    let member = sqlx::query_scalar::<_, String>(
        "SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
    )
    .bind(&workspace_id)
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await?;

    if member.is_none() {
        return Err(AppError::Forbidden(
            "You are not a member of this workspace.".to_string(),
        ));
    }

    // Fetch workspace
    let ws = sqlx::query_as::<_, WorkspaceRow>(
        "SELECT id, name, owner_id, invite_code, created_at FROM workspaces WHERE id = ?",
    )
    .bind(&workspace_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound("Workspace not found.".to_string()))?;

    // Fetch members with user profile info
    let members = sqlx::query_as::<_, MemberInfo>(
        r#"SELECT wm.user_id, u.display_name, u.email, wm.role, wm.joined_at
           FROM workspace_members wm
           JOIN users u ON u.id = wm.user_id
           WHERE wm.workspace_id = ?
           ORDER BY wm.joined_at ASC"#,
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(WorkspaceWithMembers {
        id: ws.id,
        name: ws.name,
        owner_id: ws.owner_id,
        invite_code: ws.invite_code,
        created_at: ws.created_at,
        members,
    }))
}

/// `DELETE /api/workspaces/:id` — Delete a workspace. Only admins can perform this action.
pub async fn delete_workspace(
    claims: Claims,
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
) -> Result<StatusCode, AppError> {
    // Verify admin role
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
    )
    .bind(&workspace_id)
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await?;

    match role.as_deref() {
        Some("admin") => {} // allowed
        Some(_) => {
            return Err(AppError::Forbidden(
                "Only workspace admins can delete the workspace.".to_string(),
            ));
        }
        None => {
            return Err(AppError::NotFound("Workspace not found.".to_string()));
        }
    }

    sqlx::query("DELETE FROM workspaces WHERE id = ?")
        .bind(&workspace_id)
        .execute(&state.pool)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/workspaces/:id/join` — Join a workspace using an invite code.
pub async fn join_workspace(
    claims: Claims,
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
    Json(req): Json<JoinRequest>,
) -> Result<Json<MembershipResponse>, AppError> {
    // Verify workspace exists
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM workspaces WHERE id = ?",
    )
    .bind(&workspace_id)
    .fetch_one(&state.pool)
    .await?;

    if exists == 0 {
        return Err(AppError::NotFound("Workspace not found.".to_string()));
    }

    // Verify invite code
    invite::verify_invite_code(&state.pool, &workspace_id, &req.invite_code).await?;

    // Check not already a member
    let is_member = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
    )
    .bind(&workspace_id)
    .bind(&claims.sub)
    .fetch_one(&state.pool)
    .await?;

    if is_member > 0 {
        return Err(AppError::Conflict(
            "You are already a member of this workspace.".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
    )
    .bind(&workspace_id)
    .bind(&claims.sub)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    Ok(Json(MembershipResponse {
        workspace_id,
        user_id: claims.sub,
        role: "member".to_string(),
        joined_at: now,
    }))
}

/// `POST /api/workspaces/:id/leave` — Leave a workspace.
/// The last admin cannot leave (must delete the workspace instead).
pub async fn leave_workspace(
    claims: Claims,
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
) -> Result<StatusCode, AppError> {
    // Check membership
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
    )
    .bind(&workspace_id)
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await?;

    let role = role.ok_or(AppError::NotFound(
        "You are not a member of this workspace.".to_string(),
    ))?;

    // If the requester is an admin, check they're not the last one
    if role == "admin" {
        let admin_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = ? AND role = 'admin'",
        )
        .bind(&workspace_id)
        .fetch_one(&state.pool)
        .await?;

        if admin_count <= 1 {
            return Err(AppError::BusinessRuleViolation(
                "You are the last admin of this workspace. Delete the workspace or promote another member to admin first.".to_string(),
            ));
        }
    }

    sqlx::query(
        "DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
    )
    .bind(&workspace_id)
    .bind(&claims.sub)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/workspaces/:id/members/:uid` — Remove a member. Only admins can do this.
pub async fn remove_member(
    claims: Claims,
    State(state): State<AppState>,
    Path((workspace_id, target_user_id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    // Verify requester is admin
    let requester_role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
    )
    .bind(&workspace_id)
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await?;

    match requester_role.as_deref() {
        Some("admin") => {} // allowed
        Some(_) => {
            return Err(AppError::Forbidden(
                "Only workspace admins can remove members.".to_string(),
            ));
        }
        None => {
            return Err(AppError::NotFound("Workspace not found.".to_string()));
        }
    }

    // Check target is a member
    let target_role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
    )
    .bind(&workspace_id)
    .bind(&target_user_id)
    .fetch_optional(&state.pool)
    .await?;

    let target_role = target_role.ok_or(AppError::NotFound(
        "Member not found in this workspace.".to_string(),
    ))?;

    // Check not removing the last admin
    if target_role == "admin" {
        let admin_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = ? AND role = 'admin'",
        )
        .bind(&workspace_id)
        .fetch_one(&state.pool)
        .await?;

        if admin_count <= 1 {
            return Err(AppError::BusinessRuleViolation(
                "Cannot remove the last admin of the workspace.".to_string(),
            ));
        }
    }

    sqlx::query(
        "DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
    )
    .bind(&workspace_id)
    .bind(&target_user_id)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Query Row Types ──

#[derive(sqlx::FromRow)]
struct WorkspaceListRow {
    id: String,
    name: String,
    owner_id: String,
    invite_code: String,
    member_count: i64,
    role: String,
    created_at: String,
}

#[derive(sqlx::FromRow)]
struct WorkspaceRow {
    id: String,
    name: String,
    owner_id: String,
    invite_code: String,
    created_at: String,
}
