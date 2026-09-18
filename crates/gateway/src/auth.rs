//! `/api/gw/*` 认证 + 限流中间件（dbx-response T27，同 `/mcp` guard 模式）。
//!
//! 顺序：
//! 1. **认证（401）** — Bearer access JWT 经 core `verify_access_token`
//!    （与 REST API 同一签发/验签体系；embedded 模式同 token）。**只认
//!    JWT**：`dbm_mcp_*` 长效 token 是 MCP 面给 agent 的凭证，不在网关
//!    消费——两面权限边界刻意分开（网关 v1 无按面差异化权限，但不为
//!    agent 凭证开第二入口）。拒绝带 `WWW-Authenticate: Bearer` 质询。
//! 2. **限流（429）** — per-user 滑动窗口（key = JWT sub），上限
//!    `Config::gw_rate_limit_per_minute`（默认 600/min：GUI 树浏览是请求
//!    密集面）。认证先行，未认证流量由 401 路径兜住。
//!
//! 不利事件（401/429）落 `gw_audit`（无 token/SQL/PII）；正常请求不记
//! （查询执行的成败审计在 handler 层的执行任务里，防灌表纪律同 mcp）。
//! 验证通过的 Claims 进 request extensions，handler 经 `Extension<Claims>`
//! 取用（单次验签）。

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dbmaster_core::auth::jwt::verify_access_token;

use crate::audit::{log_gw_event, GwAuditAction};
use crate::GwState;

/// 滑动窗口时长（秒）——配额按分钟表达，窗口与上限同行。
const WINDOW_SECS: u64 = 60;

pub(crate) async fn guard(State(guard): State<GwState>, req: Request, next: Next) -> Response {
    // ── 1. 认证：JWT-only ──
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let claims = match token {
        None => {
            log_gw_event(
                &guard.pool,
                None,
                GwAuditAction::AuthRejected,
                Some("missing or malformed Authorization header"),
            )
            .await;
            return unauthorized("Missing Authorization header. Expected: Bearer <token>");
        }
        Some(t) => match verify_access_token(&guard.config, t) {
            Ok(claims) => claims,
            Err(e) => {
                // AppError 的 Debug 是短原因（"Expired signature" 等），无 token 材料。
                log_gw_event(
                    &guard.pool,
                    None,
                    GwAuditAction::AuthRejected,
                    Some(&format!("invalid token: {e:?}")),
                )
                .await;
                return unauthorized("Invalid or expired token");
            }
        },
    };

    // ── 2. per-user 限流 ──
    let max = guard.config.gw_rate_limit_per_minute as usize;
    if !guard.limiter.check_and_record(&claims.sub, max, WINDOW_SECS) {
        log_gw_event(
            &guard.pool,
            Some(&claims.sub),
            GwAuditAction::RateLimited,
            Some(&format!("exceeded {max} req/min sliding window")),
        )
        .await;
        return too_many_requests(max);
    }

    let mut req = req;
    req.extensions_mut().insert(claims);
    next.run(req).await
}

/// 401 + `WWW-Authenticate: Bearer`（RFC 6750 §3），错误体走网关 wire 形状。
fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        axum::Json(serde_json::json!({ "error": { "code": "UNAUTHORIZED", "message": msg } })),
    )
        .into_response()
}

fn too_many_requests(max: usize) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "error": {
                "code": "RATE_LIMITED",
                "message": format!("gateway rate limit exceeded ({max} req/min); retry after the window"),
            }
        })),
    )
        .into_response()
}
