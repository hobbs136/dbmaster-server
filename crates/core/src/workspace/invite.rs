//! Invite code generation and verification for workspaces.
//!
//! Codes are 6-character alphanumeric (A-Z, 0-9), case-insensitive, unique.

use rand::Rng;
use sqlx::SqlitePool;

/// Characters used for invite codes (ambiguous chars like O/0, I/1, L excluded).
const CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LENGTH: usize = 6;

/// Generate a random 6-character alphanumeric invite code.
fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    (0..CODE_LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Generate a unique invite code (retries if collision in DB).
///
/// Retries up to 10 times before returning an error.
pub async fn generate_unique_invite_code(pool: &SqlitePool) -> Result<String, crate::error::AppError> {
    for _ in 0..10 {
        let code = generate_code();
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM workspaces WHERE invite_code = ?",
        )
        .bind(&code)
        .fetch_one(pool)
        .await?;

        if exists == 0 {
            return Ok(code);
        }
    }

    Err(crate::error::AppError::Internal(anyhow::anyhow!(
        "Failed to generate unique invite code after 10 attempts"
    )))
}

/// Verify an invite code against a workspace (case-insensitive comparison).
///
/// Returns the workspace ID on success, or a `Conflict` error with a generic message
/// (does not reveal whether the code was invalid or the workspace doesn't exist).
pub async fn verify_invite_code(
    pool: &SqlitePool,
    workspace_id: &str,
    code: &str,
) -> Result<(), crate::error::AppError> {
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT invite_code FROM workspaces WHERE id = ?",
    )
    .bind(workspace_id)
    .fetch_optional(pool)
    .await?
    .map(|s: String| s.to_uppercase());

    match stored {
        Some(stored_code) if stored_code == code.trim().to_uppercase() => Ok(()),
        _ => Err(crate::error::AppError::Conflict(
            "Invalid invite code.".to_string(),
        )),
    }
}
