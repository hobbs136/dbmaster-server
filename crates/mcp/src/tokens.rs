//! Long-lived MCP personal tokens (user decision 2026-08-15: 长效专用 token，
//! 可删除). Migration 012.
//!
//! Why: access JWTs expire after 15 minutes — unusable for static client
//! configs (Claude Code / Cursor mcp.json). MCP tokens are opaque
//! high-entropy strings with **no expiry**; revocation is the deletion path.
//!
//! Security shape (GitHub-PAT style):
//! - plaintext `dbm_mcp_<32 hex>` (122 bits randomness) returned **exactly
//!   once** at creation, never stored;
//! - only `sha256(plaintext)` is persisted (lookup key, UNIQUE);
//! - `token_prefix` (first 12 chars) kept for list-view recognition;
//! - revoke = soft delete (`revoked_at`), rows retained for audit trail;
//!   lookups always filter `revoked_at IS NULL`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use dbmaster_core::auth::jwt::Claims;
use dbmaster_core::error::AppError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::audit::{log_mcp_event, McpAuditAction};

/// Plaintext prefix — also the discriminator the auth guard uses to route
/// a Bearer credential to this scheme instead of the JWT verifier.
pub const TOKEN_PREFIX: &str = "dbm_mcp_";
/// How many plaintext chars the list view shows (prefix + trimmed body).
const PREFIX_DISPLAY_LEN: usize = 12;
/// Max label length (names are user-facing metadata only).
const NAME_MAX_CHARS: usize = 100;

/// Axum state for the management routes (see `lib.rs` wiring).
#[derive(Clone)]
pub(crate) struct TokensState {
    pub(crate) pool: SqlitePool,
}

// ── Generation & verification ─────────────────────────────────────────────

/// Mint a fresh token: `(plaintext, sha256-hex)`. One UUIDv4's 122 random
/// bits — brute-forcing the 32-hex body is infeasible; uniqueness is
/// enforced by the UNIQUE index on `token_hash`.
fn mint_token() -> (String, String) {
    let plaintext = format!("{TOKEN_PREFIX}{}", uuid::Uuid::new_v4().simple());
    let hash = hash_token(&plaintext);
    (plaintext, hash)
}

/// sha256 hex digest of the plaintext — the only stored form.
pub(crate) fn hash_token(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Resolve an MCP token to its owner, updating `last_used_at`.
///
/// Returns `None` for unknown **or revoked** tokens (callers treat both as
/// 401 — revealing which one would leak token-existence information).
pub(crate) async fn authenticate(pool: &SqlitePool, plaintext: &str) -> Option<String> {
    let hash = hash_token(plaintext);
    let user_id: Option<String> = sqlx::query_scalar(
        "SELECT user_id FROM mcp_tokens WHERE token_hash = ?1 AND revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    let user_id = user_id?;
    // Best-effort usage stamp; ~≤120 writes/min/user on SQLite is trivial
    // and gives operators a stale-token cleanup signal.
    let now = chrono::Utc::now().to_rfc3339();
    let _ = sqlx::query("UPDATE mcp_tokens SET last_used_at = ?1 WHERE token_hash = ?2")
        .bind(&now)
        .bind(&hash)
        .execute(pool)
        .await;
    Some(user_id)
}

// ── REST handlers (authenticated via core Claims extractor) ───────────────

#[derive(Deserialize)]
pub(crate) struct CreateTokenRequest {
    name: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct TokenCreated {
    id: String,
    name: String,
    /// Full plaintext — shown exactly once; store it in the client config now.
    token: String,
    created_at: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct TokenSummary {
    id: String,
    name: String,
    /// Short prefix for recognition (`dbm_mcp_9f2a…`) — never the secret.
    token_prefix: String,
    created_at: String,
    last_used_at: Option<String>,
}

/// `POST /api/mcp/tokens` — mint a long-lived MCP token for the caller.
/// Success responds with the server-wide `{ok, data, error}` envelope
/// (client services decode it uniformly); errors flow through `AppError`.
pub(crate) async fn create(
    State(state): State<TokensState>,
    claims: Claims,
    body: Option<Json<CreateTokenRequest>>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let name = body
        .and_then(|Json(req)| req.name)
        .map(|n| n.trim().chars().take(NAME_MAX_CHARS).collect::<String>())
        .filter(|n: &String| !n.is_empty())
        .unwrap_or_else(|| "MCP token".to_string());

    let id = uuid::Uuid::new_v4().to_string();
    let (plaintext, hash) = mint_token();
    let display_prefix: String = plaintext.chars().take(PREFIX_DISPLAY_LEN).collect();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO mcp_tokens (id, user_id, name, token_hash, token_prefix, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&name)
    .bind(&hash)
    .bind(&display_prefix)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("insert mcp_token: {e}")))?;

    log_mcp_event(&state.pool, Some(&claims.sub), McpAuditAction::TokenCreated, None, None).await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "ok": true,
            "data": TokenCreated {
                id,
                name,
                token: plaintext,
                created_at: now,
            },
            "error": null,
        })),
    ))
}

/// `GET /api/mcp/tokens` — list the caller's live tokens (no secrets).
pub(crate) async fn list(
    State(state): State<TokensState>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows: Vec<TokenSummary> = sqlx::query_as(
        "SELECT id, name, token_prefix, created_at, last_used_at
         FROM mcp_tokens WHERE user_id = ?1 AND revoked_at IS NULL
         ORDER BY created_at DESC",
    )
    .bind(&claims.sub)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("list mcp_tokens: {e}")))?;
    Ok(Json(serde_json::json!({ "ok": true, "data": rows, "error": null })))
}

/// `DELETE /api/mcp/tokens/:id` — revoke (soft delete). Only the owner's
/// row is addressable: a non-owned id reports 404, not 403, so ids can't be
/// probed across users.
pub(crate) async fn revoke(
    State(state): State<TokensState>,
    claims: Claims,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let now = chrono::Utc::now().to_rfc3339();
    let result = sqlx::query(
        "UPDATE mcp_tokens SET revoked_at = ?1
         WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(&id)
    .bind(&claims.sub)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("revoke mcp_token: {e}")))?;

    if result.rows_affected() == 0 {
        // Unknown, already-revoked, or someone else's — same answer.
        return Err(AppError::NotFound("MCP token not found".to_string()));
    }
    log_mcp_event(&state.pool, Some(&claims.sub), McpAuditAction::TokenRevoked, None, None).await;
    // 200 + envelope (not 204/empty) so client services can decode uniformly.
    Ok(Json(
        serde_json::json!({ "ok": true, "data": { "revoked": true }, "error": null }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_tokens_have_prefix_and_matching_hash() {
        let (plain, hash) = mint_token();
        assert!(plain.starts_with(TOKEN_PREFIX), "plaintext: {plain}");
        assert!(plain.len() > TOKEN_PREFIX.len() + 16);
        assert_eq!(hash.len(), 64, "sha256 hex");
        assert_eq!(hash_token(&plain), hash);
    }

    #[test]
    fn mint_is_unique() {
        let (a, _) = mint_token();
        let (b, _) = mint_token();
        assert_ne!(a, b);
    }
}
