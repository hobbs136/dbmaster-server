//! Axum extractor for JWT authentication.
//!
//! Reads the `Authorization: Bearer <token>` header, verifies the access token,
//! and returns `Claims`. Returns 401 on invalid/missing/expired tokens.
//!
//! `Config` must be injected into request extensions as `Arc<Config>` by the router.

use std::pin::Pin;
use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};

use crate::auth::jwt::{verify_access_token, Claims};
use crate::config::Config;
use crate::error::AppError;

/// Extractor that validates the Bearer token and returns `Claims`.
///
/// Usage in handlers:
/// ```ignore
/// async fn protected_route(claims: Claims, ...) -> ... { }
/// ```
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = Response;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        _state: &'life1 S,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            // Extract the Authorization header
            let header = parts
                .headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    AppError::Unauthorized("Missing Authorization header.".to_string())
                        .into_response()
                })?;

            // Must be "Bearer <token>"
            let token = header
                .strip_prefix("Bearer ")
                .ok_or_else(|| {
                    AppError::Unauthorized(
                        "Invalid Authorization format. Expected: Bearer <token>".to_string(),
                    )
                    .into_response()
                })?;

            // Config is injected into request extensions by the router middleware
            let config = parts
                .extensions
                .get::<Arc<Config>>()
                .ok_or_else(|| {
                    tracing::error!(
                        "Arc<Config> not found in request extensions — router misconfiguration"
                    );
                    AppError::Internal(anyhow::anyhow!("Server configuration error"))
                        .into_response()
                })?;

            verify_access_token(config, token).map_err(|e| e.into_response())
        })
    }
}
