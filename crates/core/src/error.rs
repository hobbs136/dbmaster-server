//! Unified error type for the server.
//!
//! `AppError` maps domain errors to HTTP responses with consistent JSON error bodies
//! per the API contract (`contracts/server-api.md`).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// Standard JSON error response body.
#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

/// All application-level errors, mapped to HTTP status codes and error codes.
#[derive(Debug)]
pub enum AppError {
    // ── Validation ──
    /// Request body fails validation (400).
    Validation(String),

    // ── Authentication ──
    /// Missing or invalid Authorization header (401).
    Unauthorized(String),
    /// Access token has expired (401).
    TokenExpired,
    /// Login with wrong email or password (401).
    InvalidCredentials,

    // ── Authorization ──
    /// Authenticated but lacking permission (403).
    Forbidden(String),

    // ── Resources ──
    /// Requested resource doesn't exist (404).
    NotFound(String),

    // ── Conflict ──
    /// Duplicate or conflicting state (409).
    Conflict(String),

    // ── Business rules ──
    /// Valid request but violates a business rule (422).
    BusinessRuleViolation(String),

    // ── Rate limiting ──
    /// Too many requests (429).
    RateLimited,

    // ── Internal ──
    /// Unexpected server error (500). Message is logged but not exposed to client.
    Internal(anyhow::Error),
}

impl AppError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            Self::TokenExpired => (StatusCode::UNAUTHORIZED, "TOKEN_EXPIRED"),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS"),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            Self::BusinessRuleViolation(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "BUSINESS_RULE_VIOLATION")
            }
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
        }
    }

    fn client_message(&self) -> String {
        match self {
            Self::Validation(msg) => msg.clone(),
            Self::Unauthorized(msg) => msg.clone(),
            Self::TokenExpired => "Access token has expired. Please refresh.".to_string(),
            Self::InvalidCredentials => "Invalid email or password.".to_string(),
            Self::Forbidden(msg) => msg.clone(),
            Self::NotFound(msg) => msg.clone(),
            Self::Conflict(msg) => msg.clone(),
            Self::BusinessRuleViolation(msg) => msg.clone(),
            Self::RateLimited => {
                "Too many requests. Please wait and try again.".to_string()
            }
            // Never leak internal error details to the client.
            Self::Internal(_) => "An unexpected error occurred.".to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let message = self.client_message();

        // Log internal errors with their full cause chain.
        if let Self::Internal(ref err) = self {
            tracing::error!(error = ?err, "Internal server error");
        }

        let body = ErrorBody {
            error: ErrorDetail {
                code,
                message,
            },
        };

        (status, Json(body)).into_response()
    }
}

// Allow `?` on anyhow::Error in handlers.
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err)
    }
}

// Allow `?` on sqlx::Error in handlers.
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        Self::Internal(anyhow::anyhow!(err))
    }
}

// Allow `?` on jsonwebtoken errors.
impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Self::TokenExpired,
            _ => Self::Unauthorized("Invalid or malformed token.".to_string()),
        }
    }
}
