//! User model types — database row, API request/response DTOs.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Database row for the `users` table.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub display_name: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Public-facing user representation (omits `password_hash`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            display_name: u.display_name,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

/// Registration request body.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub display_name: String,
}

impl CreateUserRequest {
    /// Validate all fields. Returns an error message string if invalid.
    pub fn validate(&self) -> Result<(), String> {
        let email = self.email.trim();
        if email.is_empty() {
            return Err("Email is required.".to_string());
        }
        if !email.contains('@') || !email.contains('.') {
            return Err("Invalid email format.".to_string());
        }

        if self.password.len() < 8 {
            return Err("Password must be at least 8 characters.".to_string());
        }

        let name = self.display_name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err("Display name must be between 1 and 100 characters.".to_string());
        }

        Ok(())
    }

    /// Normalize fields (trim whitespace, lowercase email).
    pub fn normalized(mut self) -> Self {
        self.email = self.email.trim().to_lowercase();
        self.display_name = self.display_name.trim().to_string();
        self
    }
}

/// Login request body.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Combined response for register + login: user profile + token pair.
#[derive(Debug, Serialize)]
pub struct UserWithTokens {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
}

/// Profile update request body (all fields optional).
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub password: Option<String>,
}

impl UpdateProfileRequest {
    /// Validate optional fields. Password must be ≥8 chars if provided.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref name) = self.display_name {
            let trimmed = name.trim();
            if trimmed.is_empty() || trimmed.len() > 100 {
                return Err("Display name must be between 1 and 100 characters.".to_string());
            }
        }
        if let Some(ref pw) = self.password {
            if pw.len() < 8 {
                return Err("Password must be at least 8 characters.".to_string());
            }
        }
        Ok(())
    }
}

/// Refresh token request body.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Token pair returned from refresh.
#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}
