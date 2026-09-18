//! `/mcp` transport-level auth + rate limiting (dbx-response T04).
//!
//! The MCP endpoint is mounted via `route_service` (rmcp tower service), so
//! core's `Claims` extractor does not apply — this middleware runs *before*
//! the rmcp service and enforces, in order:
//!
//! 1. **Auth (401)** — `Authorization: Bearer <access JWT>` verified with
//!    core's `verify_access_token` (same signing key and claims as the REST
//!    API; embedded mode mints the same token kind, so both modes share one
//!    path). Rejections carry `WWW-Authenticate: Bearer` per RFC 6750.
//! 2. **Rate limit (429)** — per-user sliding window (key = JWT `sub`),
//!    ceiling from `Config::mcp_rate_limit_per_minute` (`DBMASTER_MCP_RATE_LIMIT_PER_MIN`,
//!    default 120/min). Auth runs first so unauthenticated traffic is bounded
//!    by the 401 path (one HMAC verify per request), not the counter.
//!
//! Every adverse event (401/429) and every session close (HTTP DELETE) is
//! appended to `mcp_audit` — no token / SQL / PII ever lands there (see
//! `audit.rs`).
//!
//! Successful claims are inserted into request extensions so downstream
//! layers (T06/T07 tool surface: per-user visibility, entitlement) can read
//! the caller identity.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dbmaster_core::auth::jwt::{verify_access_token, Claims};
use dbmaster_core::auth::rate_limiter::SlidingWindowLimiter;
use dbmaster_core::config::Config;
use sqlx::SqlitePool;

use crate::audit::{log_mcp_event, McpAuditAction};

/// Sliding-window duration for the per-user MCP limit (seconds). Fixed at
/// 60s — the config knob is expressed per-minute, so window and ceiling
/// travel together.
const WINDOW_SECS: u64 = 60;

/// Shared guard state: JWT config, per-user counters, audit sink.
#[derive(Clone)]
pub(crate) struct McpAuthGuard {
    config: Arc<Config>,
    limiter: Arc<SlidingWindowLimiter>,
    pool: SqlitePool,
}

impl McpAuthGuard {
    pub(crate) fn new(config: Arc<Config>, pool: SqlitePool) -> Self {
        Self {
            config,
            limiter: Arc::new(SlidingWindowLimiter::new()),
            pool,
        }
    }
}

/// Middleware entry — see module docs for the enforcement order.
pub(crate) async fn guard(
    State(guard): State<McpAuthGuard>,
    req: Request,
    next: Next,
) -> Response {
    // ── 1. Auth: Bearer credential (two schemes) ──
    // `dbm_mcp_*` → long-lived MCP personal token (DB lookup, no expiry,
    // revocable — the static mcp.json credential). Anything else → short
    // lived access JWT (core verifier; embedded mode mints these too).
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let claims = match token {
        None => {
            // No token (or not a Bearer header) — audit without user_id and
            // reject before touching the limiter.
            log_mcp_event(
                &guard.pool,
                None,
                McpAuditAction::AuthRejected,
                None,
                Some("missing or malformed Authorization header"),
            )
            .await;
            return unauthorized("Missing Authorization header. Expected: Bearer <token>");
        }
        Some(t) if t.starts_with(crate::tokens::TOKEN_PREFIX) => {
            match crate::tokens::authenticate(&guard.pool, t).await {
                Some(user_id) => Claims {
                    sub: user_id,
                    // Synthetic timestamps: this credential has no expiry —
                    // the DB lookup above IS the validity check; nothing
                    // downstream re-verifies exp on this path. jti marks the
                    // credential scheme for T06/T07 tool-layer visibility.
                    iat: 0,
                    exp: u64::MAX as usize,
                    jti: "mcp_token".to_string(),
                },
                None => {
                    // Unknown or revoked — indistinguishable by design
                    // (token-existence must not leak).
                    log_mcp_event(
                        &guard.pool,
                        None,
                        McpAuditAction::AuthRejected,
                        None,
                        Some("unknown or revoked MCP token"),
                    )
                    .await;
                    return unauthorized("Invalid or expired token");
                }
            }
        }
        Some(t) => match verify_access_token(&guard.config, t) {
            Ok(claims) => claims,
            Err(e) => {
                // AppError's Debug for token failures is a short reason
                // ("Expired signature" etc.) — no token material inside.
                log_mcp_event(
                    &guard.pool,
                    None,
                    McpAuditAction::AuthRejected,
                    None,
                    Some(&format!("invalid token: {e:?}")),
                )
                .await;
                return unauthorized("Invalid or expired token");
            }
        },
    };

    // ── 2. Per-user rate limit ──
    let max = guard.config.mcp_rate_limit_per_minute as usize;
    if !guard.limiter.check_and_record(&claims.sub, max, WINDOW_SECS) {
        log_mcp_event(
            &guard.pool,
            Some(&claims.sub),
            McpAuditAction::RateLimited,
            None,
            Some(&format!("exceeded {max} req/min sliding window")),
        )
        .await;
        return too_many_requests();
    }

    // ── 3. Identity downstream + session-close audit on DELETE ──
    // Streamable HTTP: POST = message, GET = SSE stream, DELETE = session
    // end. Only DELETE mutates observable session state worth a row at the
    // transport layer; tool-call audit joins in T06/T07 at the ServerHandler
    // layer (where method names are visible without HTTP-body sniffing).
    let is_session_close = req.method() == axum::http::Method::DELETE;
    if is_session_close {
        log_mcp_event(&guard.pool, Some(&claims.sub), McpAuditAction::SessionClose, None, None).await;
    }

    let mut req = req;
    req.extensions_mut().insert(claims);
    next.run(req).await
}

/// 401 with `WWW-Authenticate: Bearer` (RFC 6750 §3) so MCP clients surface
/// a proper auth challenge instead of a bare status code.
fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        axum::Json(serde_json::json!({ "error": "UNAUTHORIZED", "message": msg })),
    )
        .into_response()
}

fn too_many_requests() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "error": "RATE_LIMITED",
            "message": "MCP request rate limit exceeded; retry after the window",
        })),
    )
        .into_response()
}
