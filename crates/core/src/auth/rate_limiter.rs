//! In-memory rate limiting: a reusable sliding-window core plus a per-IP
//! Tower middleware/layer built on it.
//!
//! Tracks request counts per key with a sliding-window expiry. Counters are
//! in-memory only — they do not survive server restarts.
//!
//! The layer is applied to `/api/auth/login`, `/api/auth/register`,
//! `/api/auth/refresh` (5 req/min per IP). The [`SlidingWindowLimiter`] core
//! is shared with other callers that need a different key dimension or
//! limits (e.g. MCP's per-user limit, config-driven — T04).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use axum::{
    extract::Request,
    response::{IntoResponse, Response},
};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::error::AppError;

/// Maximum requests per IP per window (auth-endpoint default).
const MAX_REQUESTS: usize = 5;
/// Sliding window duration in seconds (auth-endpoint default).
const WINDOW_SECS: u64 = 60;

/// Reusable sliding-window counter map. Thread-safe; keys are caller-chosen
/// (IP for auth endpoints, user id for MCP — T04).
// CHANGE: T04 — extracted from RateLimiterState so the MCP endpoint can reuse
// the same windowing semantics with a per-user key and config-driven limits.
#[derive(Default)]
pub struct SlidingWindowLimiter {
    counters: Mutex<HashMap<String, Vec<Instant>>>,
}

impl SlidingWindowLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one request for `key` and return whether it is allowed under
    /// `max` requests per `window_secs` sliding window. Prunes expired
    /// timestamps for the key on every call; stale keys are left to be
    /// overwritten on next use (bounded by distinct-key cardinality).
    pub fn check_and_record(&self, key: &str, max: usize, window_secs: u64) -> bool {
        let mut counters = self.counters.lock().unwrap();
        let now = Instant::now();
        let entries = counters.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t).as_secs() < window_secs);
        if entries.len() >= max {
            false
        } else {
            entries.push(now);
            true
        }
    }
}

/// Shared state for the per-IP auth rate limiter layer.
#[derive(Default)]
struct RateLimiterState {
    /// Per-IP list of request timestamps within the current window.
    limiter: SlidingWindowLimiter,
}

/// Tower Layer that produces `RateLimiter<S>` services.
#[derive(Clone, Default)]
pub struct RateLimiterLayer {
    state: std::sync::Arc<RateLimiterState>,
}

impl RateLimiterLayer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for RateLimiterLayer {
    type Service = RateLimiter<S>;

    fn layer(&self, inner: S) -> RateLimiter<S> {
        RateLimiter {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Tower Service that enforces per-IP rate limits.
#[derive(Clone)]
pub struct RateLimiter<S> {
    inner: S,
    state: std::sync::Arc<RateLimiterState>,
}

impl<S, ReqBody> Service<Request<ReqBody>> for RateLimiter<S>
where
    S: Service<Request<ReqBody>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let client_ip = extract_client_ip(&req);
        let mut inner = self.inner.clone();
        let state = self.state.clone();

        Box::pin(async move {
            // Check and update counters
            let allowed = state
                .limiter
                .check_and_record(&client_ip, MAX_REQUESTS, WINDOW_SECS);

            if !allowed {
                return Ok(AppError::RateLimited.into_response());
            }

            inner.call(req).await
        })
    }
}

/// Extract the client IP from the request.
///
/// Checks `X-Forwarded-For` header first (for reverse proxy), falls back to
/// the socket peer address, and defaults to "unknown".
fn extract_client_ip<B>(req: &Request<B>) -> String {
    // Check X-Forwarded-For header
    if let Some(fwd) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        // Take the first IP in the chain
        let first = fwd.split(',').next().unwrap_or("").trim();
        if !first.is_empty() {
            return first.to_string();
        }
    }

    // Fall back to connection remote address
    // Note: in Axum/Tower, the peer addr may be lost after going through layers.
    // We use a best-effort approach.
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window_allows_up_to_max_then_denies() {
        let limiter = SlidingWindowLimiter::new();

        // First 5 requests for a key should be allowed
        for _ in 0..5 {
            assert!(limiter.check_and_record("192.168.1.1", 5, 60));
        }
        // 6th denied
        assert!(!limiter.check_and_record("192.168.1.1", 5, 60));
        // A different key is unaffected (per-key isolation)
        assert!(limiter.check_and_record("10.0.0.2", 5, 60));
    }

    #[test]
    fn sliding_window_honours_custom_limits() {
        let limiter = SlidingWindowLimiter::new();
        assert!(limiter.check_and_record("u1", 2, 60));
        assert!(limiter.check_and_record("u1", 2, 60));
        assert!(!limiter.check_and_record("u1", 2, 60));
    }

    #[test]
    fn auth_layer_state_tracks_requests_per_ip() {
        let state = RateLimiterState::default();

        // First 5 requests should be allowed
        for _ in 0..MAX_REQUESTS {
            assert!(state.limiter.check_and_record("192.168.1.1", MAX_REQUESTS, WINDOW_SECS));
        }

        // 6th request should be denied
        assert!(!state.limiter.check_and_record("192.168.1.1", MAX_REQUESTS, WINDOW_SECS));
    }
}
