//! JWT token issuance and verification (HS256).
//!
//! Access tokens: 15-minute expiry, signed with `SERVER_JWT_SECRET`.
//! Refresh tokens: 7-day expiry, signed with `SERVER_JWT_REFRESH_SECRET`,
//! with unique JTIs for server-side revocation.
//!
//! Embedded mode (ADR-0003 S2) uses far-future variants of both (30d / 31d):
//! the embedded server mints per-boot random secrets, so token lifetime is
//! bounded by the child process regardless of the nominal `exp`.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;

/// Claims embedded in both access and refresh tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user's UUID.
    pub sub: String,
    /// Issued-at timestamp (Unix epoch seconds).
    pub iat: usize,
    /// Expiration timestamp (Unix epoch seconds).
    pub exp: usize,
    /// JWT ID — unique per token, used for refresh token revocation.
    pub jti: String,
}

/// Access-token TTL for normal (remote) sessions: 15 minutes.
pub const ACCESS_TOKEN_TTL_SECS: usize = 900;
/// Refresh-token TTL for normal (remote) sessions: 7 days.
pub const REFRESH_TOKEN_TTL_SECS: usize = 604_800;

/// Embedded-mode access-token TTL: 30 days.
///
/// The embedded server binds to loopback and generates fresh random JWT
/// secrets every boot (`run_embedded`), so a token's real lifetime is the
/// child process's — this TTL only needs to outlive any plausible uptime.
/// Without it, every authenticated client call 401s 15 minutes after boot
/// (older desktop clients never refresh embedded tokens).
pub const EMBEDDED_ACCESS_TOKEN_TTL_SECS: usize = 30 * 24 * 3600;
/// Embedded-mode refresh-token TTL: 31 days — one day beyond the access token
/// so the client's transparent refresh chain always has a valid refresh token
/// when the long-lived access token finally nears expiry.
pub const EMBEDDED_REFRESH_TOKEN_TTL_SECS: usize = 31 * 24 * 3600;

/// Issue a short-lived access token (15 minutes).
pub fn issue_access_token(
    config: &Config,
    user_id: &str,
) -> Result<String, crate::error::AppError> {
    issue_access_token_with_ttl(config, user_id, ACCESS_TOKEN_TTL_SECS)
}

/// Issue the embedded-mode access token (see [EMBEDDED_ACCESS_TOKEN_TTL_SECS]).
pub fn issue_embedded_access_token(
    config: &Config,
    user_id: &str,
) -> Result<String, crate::error::AppError> {
    issue_access_token_with_ttl(config, user_id, EMBEDDED_ACCESS_TOKEN_TTL_SECS)
}

fn issue_access_token_with_ttl(
    config: &Config,
    user_id: &str,
    ttl_secs: usize,
) -> Result<String, crate::error::AppError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| crate::error::AppError::Internal(e.into()))?
        .as_secs() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        iat: now,
        exp: now + ttl_secs,
        jti: Uuid::new_v4().to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| crate::error::AppError::Internal(e.into()))
}

/// Issue a long-lived refresh token (7 days).
///
/// Returns the signed token string and its claims (for storing in DB).
pub fn issue_refresh_token(
    config: &Config,
    user_id: &str,
) -> Result<(String, Claims), crate::error::AppError> {
    issue_refresh_token_with_ttl(config, user_id, REFRESH_TOKEN_TTL_SECS)
}

/// Issue the embedded-mode refresh token (see [EMBEDDED_REFRESH_TOKEN_TTL_SECS]).
pub fn issue_embedded_refresh_token(
    config: &Config,
    user_id: &str,
) -> Result<(String, Claims), crate::error::AppError> {
    issue_refresh_token_with_ttl(config, user_id, EMBEDDED_REFRESH_TOKEN_TTL_SECS)
}

fn issue_refresh_token_with_ttl(
    config: &Config,
    user_id: &str,
    ttl_secs: usize,
) -> Result<(String, Claims), crate::error::AppError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| crate::error::AppError::Internal(e.into()))?
        .as_secs() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        iat: now,
        exp: now + ttl_secs,
        jti: Uuid::new_v4().to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_refresh_secret.as_bytes()),
    )
    .map_err(|e| crate::error::AppError::Internal(e.into()))?;

    Ok((token, claims))
}

/// Verify an access token and return its claims.
pub fn verify_access_token(
    config: &Config,
    token: &str,
) -> Result<Claims, crate::error::AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| e.into())
}

/// Verify a refresh token and return its claims.
pub fn verify_refresh_token(
    config: &Config,
    token: &str,
) -> Result<Claims, crate::error::AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_refresh_secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| e.into())
}
