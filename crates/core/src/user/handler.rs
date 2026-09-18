//! REST handlers for user registration, login, profile, and token refresh.

use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use uuid::Uuid;

use crate::auth::jwt::{self, Claims};
use crate::auth::password;
use crate::error::AppError;
use crate::server::AppState;
use crate::user::model::{
    CreateUserRequest, LoginRequest, RefreshRequest, TokenPair, UpdateProfileRequest,
    UserResponse, UserWithTokens,
};

/// `POST /api/auth/register` — Create a new user account.
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserWithTokens>), AppError> {
    let req = req.normalized();
    req.validate().map_err(AppError::Validation)?;

    // Check uniqueness of email (case-insensitive)
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER(?)",
    )
    .bind(&req.email)
    .fetch_one(&state.pool)
    .await?;

    if exists > 0 {
        return Err(AppError::Conflict("Email already registered.".to_string()));
    }

    // Hash the password
    let password_hash =
        password::hash_password(&req.password)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Password hashing failed: {}", e)))?;

    let user_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Insert user
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&user_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(&req.display_name)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    // Issue tokens
    let access_token = jwt::issue_access_token(&state.config, &user_id)?;
    let (refresh_token, refresh_claims) = jwt::issue_refresh_token(&state.config, &user_id)?;

    // Store refresh token
    let refresh_id = Uuid::new_v4().to_string();
    let expires_at =
        chrono::DateTime::from_timestamp(refresh_claims.exp as i64, 0)
            .unwrap_or(Utc::now())
            .to_rfc3339();
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, jti, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&refresh_id)
    .bind(&user_id)
    .bind(&refresh_claims.jti)
    .bind(&expires_at)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    let user_response = UserResponse {
        id: user_id,
        email: req.email,
        display_name: req.display_name,
        created_at: now.clone(),
        updated_at: now,
    };

    Ok((
        StatusCode::CREATED,
        Json(UserWithTokens {
            user: user_response,
            access_token,
            refresh_token,
        }),
    ))
}

/// `POST /api/auth/login` — Authenticate with email and password.
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<UserWithTokens>, AppError> {
    let email = req.email.trim().to_lowercase();

    // Find user by email
    let user = sqlx::query_as::<_, crate::user::model::User>(
        "SELECT id, email, password_hash, display_name, created_at, updated_at FROM users WHERE LOWER(email) = LOWER(?)",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;

    let user = user.ok_or(AppError::InvalidCredentials)?;

    // Verify password
    let valid = password::verify_password(&req.password, &user.password_hash)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Password verification failed: {}", e)))?;

    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    // Issue tokens
    let access_token = jwt::issue_access_token(&state.config, &user.id)?;
    let (refresh_token, refresh_claims) = jwt::issue_refresh_token(&state.config, &user.id)?;

    // Store refresh token
    let refresh_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let expires_at =
        chrono::DateTime::from_timestamp(refresh_claims.exp as i64, 0)
            .unwrap_or(Utc::now())
            .to_rfc3339();
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, jti, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&refresh_id)
    .bind(&user.id)
    .bind(&refresh_claims.jti)
    .bind(&expires_at)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    Ok(Json(UserWithTokens {
        user: UserResponse::from(user),
        access_token,
        refresh_token,
    }))
}

/// `GET /api/me` — Get the authenticated user's profile.
pub async fn get_me(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<UserResponse>, AppError> {
    let user = sqlx::query_as::<_, crate::user::model::User>(
        "SELECT id, email, password_hash, display_name, created_at, updated_at FROM users WHERE id = ?",
    )
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await?;

    match user {
        Some(u) => Ok(Json(UserResponse::from(u))),
        None => Err(AppError::NotFound("User not found.".to_string())),
    }
}

/// `PATCH /api/me` — Update the authenticated user's profile.
///
/// If the password is changed, all existing refresh tokens for this user are revoked.
pub async fn update_me(
    claims: Claims,
    State(state): State<AppState>,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<UserResponse>, AppError> {
    req.validate().map_err(AppError::Validation)?;

    let now = Utc::now().to_rfc3339();

    if let Some(ref new_name) = req.display_name {
        let name = new_name.trim();
        sqlx::query("UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?")
            .bind(name)
            .bind(&now)
            .bind(&claims.sub)
            .execute(&state.pool)
            .await?;
    }

    if let Some(ref new_password) = req.password {
        let password_hash = password::hash_password(new_password)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Password hashing failed: {}", e)))?;

        sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(&password_hash)
            .bind(&now)
            .bind(&claims.sub)
            .execute(&state.pool)
            .await?;

        // Revoke ALL refresh tokens for this user (force re-login on other devices)
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        )
        .bind(&now)
        .bind(&claims.sub)
        .execute(&state.pool)
        .await?;
    }

    // Fetch and return updated user
    let user = sqlx::query_as::<_, crate::user::model::User>(
        "SELECT id, email, password_hash, display_name, created_at, updated_at FROM users WHERE id = ?",
    )
    .bind(&claims.sub)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(UserResponse::from(user)))
}

/// `POST /api/auth/refresh` — Exchange a refresh token for a new token pair.
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<TokenPair>, AppError> {
    // Verify the refresh token
    let claims = jwt::verify_refresh_token(&state.config, &req.refresh_token)?;

    // Check if the token exists and is not revoked
    let token_row =
        sqlx::query_as::<_, RefreshTokenRow>(
            "SELECT id, user_id, jti, expires_at, created_at, revoked_at FROM refresh_tokens WHERE jti = ?",
        )
        .bind(&claims.jti)
        .fetch_optional(&state.pool)
        .await?;

    let token_row = token_row.ok_or(AppError::Unauthorized(
        "Invalid refresh token.".to_string(),
    ))?;

    if token_row.revoked_at.is_some() {
        return Err(AppError::Unauthorized(
            "Refresh token has been revoked.".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();

    // Revoke the old token (rotation)
    sqlx::query("UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&token_row.id)
        .execute(&state.pool)
        .await?;

    // Issue new tokens
    let access_token = jwt::issue_access_token(&state.config, &claims.sub)?;
    let (refresh_token_str, new_claims) = jwt::issue_refresh_token(&state.config, &claims.sub)?;

    // Store new refresh token
    let new_id = Uuid::new_v4().to_string();
    let expires_at =
        chrono::DateTime::from_timestamp(new_claims.exp as i64, 0)
            .unwrap_or(Utc::now())
            .to_rfc3339();
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, jti, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&new_id)
    .bind(&claims.sub)
    .bind(&new_claims.jti)
    .bind(&expires_at)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    Ok(Json(TokenPair {
        access_token,
        refresh_token: refresh_token_str,
    }))
}

// ── Helpers ──

/// Row shape for querying refresh tokens.
#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct RefreshTokenRow {
    id: String,
    user_id: String,
    jti: String,
    #[allow(dead_code)]
    expires_at: String,
    #[allow(dead_code)]
    created_at: String,
    revoked_at: Option<String>,
}

/// Ensure the embedded single-user row exists and return fresh tokens for it.
///
/// Used by the ADR-0003 `--embedded` mode: the desktop client never logs into
/// its own local server — instead the server bootstraps one user on first run
/// (or reuses it on subsequent runs) and hands the parent process a token pair.
///
/// Semantics:
/// - If a user with `EMBEDDED_USER_EMAIL` already exists → reuse its id.
/// - Else → INSERT a new row with a random unguessable password hash (login is
///   never used; the password is filler to satisfy the NOT NULL column).
/// - Then issue a fresh token pair with embedded TTLs (30d access / 31d
///   refresh — see `auth::jwt`; per-boot random secrets bound real lifetime to
///   the process) and persist the refresh token row for revocation.
///
/// Returns `(user_id, access_token, refresh_token)`.
// embedded-mode single-user bootstrap, callable from
// main.rs without going through the HTTP layer.
pub async fn ensure_embedded_user_and_tokens(
    pool: &sqlx::SqlitePool,
    config: &crate::config::Config,
) -> Result<(String, String, String), AppError> {
    /// Fixed email for the embedded single-user row. The desktop client is the
    /// only caller; this account exists solely so JWT `sub` has a real user_id.
    pub const EMBEDDED_USER_EMAIL: &str = "embedded@local";
    const EMBEDDED_DISPLAY_NAME: &str = "Embedded User";

    // Idempotent + race-proof: optimistically INSERT OR IGNORE, then SELECT.
    // Two concurrent boots (e.g. a misbehaving parent, or two test processes
    // sharing a DB) won't collide on the UNIQUE(email) constraint — the second
    // INSERT is ignored and both resolve to the same row.
    let new_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    // 32 random bytes formatted as a hex string act as the throwaway "password"
    // input; argon2 hashes it. Unrecoverable, so even if the hash leaked it's
    // useless. Hex formatting avoids a hex/base64 crate dependency for one call.
    let mut rand_bytes = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
    let throwaway_password: String = rand_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let password_hash = password::hash_password(&throwaway_password)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Password hashing failed: {}", e)))?;

    sqlx::query(
        "INSERT OR IGNORE INTO users (id, email, password_hash, display_name, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&new_id)
    .bind(EMBEDDED_USER_EMAIL)
    .bind(&password_hash)
    .bind(EMBEDDED_DISPLAY_NAME)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // Whether we won the INSERT or lost the race, SELECT the canonical row.
    let (user_id,): (String,) = sqlx::query_as(
        "SELECT id FROM users WHERE LOWER(email) = LOWER(?)",
    )
    .bind(EMBEDDED_USER_EMAIL)
    .fetch_one(pool)
    .await?;

    // Issue the embedded pair: far-future TTLs (30d access / 31d refresh).
    // Safe because the embedded server signs with per-boot random secrets —
    // the tokens die with the child process — and the long refresh TTL keeps
    // the client's transparent refresh chain valid when the access token
    // finally nears expiry.
    let access_token = jwt::issue_embedded_access_token(config, &user_id)?;
    let (refresh_token, refresh_claims) =
        jwt::issue_embedded_refresh_token(config, &user_id)?;

    let refresh_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let expires_at = chrono::DateTime::from_timestamp(refresh_claims.exp as i64, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339();
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, jti, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&refresh_id)
    .bind(&user_id)
    .bind(&refresh_claims.jti)
    .bind(&expires_at)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok((user_id, access_token, refresh_token))
}
