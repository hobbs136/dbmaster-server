//! Workspace model types — database rows and API request/response DTOs.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Database row for the `workspaces` table.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub invite_code: String,
    pub created_at: String,
}

/// Database row for the `workspace_members` table.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct WorkspaceMember {
    pub workspace_id: String,
    pub user_id: String,
    pub role: String,
    pub joined_at: String,
}

/// Workspace list item with member count and the requester's role.
#[derive(Debug, Serialize)]
pub struct WorkspaceListItem {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub invite_code: String,
    pub member_count: i64,
    pub role: String,
    pub created_at: String,
}

/// Member info joined with user profile for display.
#[derive(Debug, Serialize, FromRow)]
pub struct MemberInfo {
    pub user_id: String,
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub joined_at: String,
}

/// Full workspace detail with member list.
#[derive(Debug, Serialize)]
pub struct WorkspaceWithMembers {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub invite_code: String,
    pub created_at: String,
    pub members: Vec<MemberInfo>,
}

/// Create workspace request body.
#[derive(Debug, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub name: String,
}

impl CreateWorkspaceRequest {
    pub fn validate(&self) -> Result<(), String> {
        let name = self.name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err("Workspace name must be between 1 and 100 characters.".to_string());
        }
        Ok(())
    }

    pub fn normalized(mut self) -> Self {
        self.name = self.name.trim().to_string();
        self
    }
}

/// Workspace list response wrapper.
#[derive(Debug, Serialize)]
pub struct WorkspaceListResponse {
    pub workspaces: Vec<WorkspaceListItem>,
}

/// Join workspace request body.
#[derive(Debug, Deserialize)]
pub struct JoinRequest {
    pub invite_code: String,
}

/// Join workspace response.
#[derive(Debug, Serialize)]
pub struct MembershipResponse {
    pub workspace_id: String,
    pub user_id: String,
    pub role: String,
    pub joined_at: String,
}
