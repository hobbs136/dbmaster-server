//! `mcp_audit` writer (dbx-response T04 / migrations 011+013).
//!
//! Append-only security audit for `/mcp`: auth rejections, rate-limit
//! rejections, session lifecycle events, and tool calls (T06). Deliberately
//! small, mirroring the drift `credential_access_audit` discipline
//! (ADR-0002 §4.2.4):
//!
//! Stored: `user_id` (JWT subject; NULL pre-auth), `action`, `status`,
//! `error`, `at`, `tool` (tool name, tool_call rows only).
//!
//! Excluded (hard rule): the token itself, any SQL text, any returned data,
//! any PII. The caller must pre-redact `error`; this module truncates to a
//! bounded length but performs no other sanitising.

use sqlx::SqlitePool;

/// What is being audited. Serializes as the wire string stored in the
/// `action` column; see migration 011/013 for the enumeration contract.
#[derive(Debug, Clone, Copy)]
pub enum McpAuditAction {
    /// Bearer token missing/malformed/invalid/expired → 401.
    AuthRejected,
    /// Per-user sliding window exhausted → 429.
    RateLimited,
    /// Client ended a session (HTTP DELETE on the endpoint).
    SessionClose,
    /// A long-lived MCP token was minted (management API).
    TokenCreated,
    /// A long-lived MCP token was revoked (management API).
    TokenRevoked,
    /// A tools/call reached the ServerHandler layer (T06). Tool name goes in
    /// the `tool` column; outcome (ok / error + short reason) via `error`.
    ToolCall,
}

/// Outcome of the audited event — adverse rejections are errors, a normal
/// session close is not.
#[derive(Debug, Clone, Copy)]
pub enum McpAuditStatus {
    Ok,
    Error,
}

impl McpAuditAction {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::AuthRejected => "auth_rejected",
            Self::RateLimited => "rate_limited",
            Self::SessionClose => "session_close",
            Self::TokenCreated => "token_created",
            Self::TokenRevoked => "token_revoked",
            Self::ToolCall => "tool_call",
        }
    }

    /// Adverse transport-level events (401/429) record 'error'; session close,
    /// token management and *successful* tool calls are normal lifecycle
    /// events and record 'ok'. Failed tool calls are flagged by the caller
    /// passing a non-empty `error` — see [`log_mcp_event`].
    fn default_status(&self) -> McpAuditStatus {
        match self {
            Self::AuthRejected | Self::RateLimited => McpAuditStatus::Error,
            Self::SessionClose
            | Self::TokenCreated
            | Self::TokenRevoked
            | Self::ToolCall => McpAuditStatus::Ok,
        }
    }
}

/// Append one audit row.
///
/// `error` should be a short, redacted summary (no token / SQL / PII);
/// pass `None` for plain outcomes. `user_id` is the JWT `sub` or `None`
/// when the caller could not be authenticated. `tool` is the static tool
/// name for `tool_call` rows (migration 013), `None` for everything else.
// CHANGE: T04 — every MCP transport-level security event goes through this
// writer so the audit trail is uniform (same pattern as drift audit.rs).
// T06 adds the `tool` column for ServerHandler-layer tool-call audit.
pub async fn log_mcp_event(
    pool: &SqlitePool,
    user_id: Option<&str>,
    action: McpAuditAction,
    tool: Option<&str>,
    error: Option<&str>,
) {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let err = error.map(truncate_redacted);
    let status = match action.default_status() {
        McpAuditStatus::Ok if err.is_none() => "ok",
        _ => "error",
    };
    // DEFENSIVE-NOTE: bind all values — never interpolate into SQL. id/
    // user_id / tool / error are caller-supplied and parameterized; SQL
    // injection is structurally impossible here.
    let result = sqlx::query(
        "INSERT INTO mcp_audit (id, user_id, action, status, error, at, tool)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(action.as_db_str())
    .bind(status)
    .bind(&err)
    .bind(&now)
    .bind(tool)
    .execute(pool)
    .await;
    // Audit is best-effort at the transport layer: a broken audit sink must
    // not turn every MCP request into a 500. The tracing error is the
    // operator's signal to investigate.
    if let Err(e) = result {
        tracing::error!(action = action.as_db_str(), error = %e, "mcp_audit insert failed");
    }
}

/// Truncate to a bounded length so a misbehaving caller cannot bloat the
/// audit table via an over-long error string (same bound as drift audit).
fn truncate_redacted(s: &str) -> String {
    const MAX: usize = 500;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(MAX).collect();
        format!("{truncated}…[truncated]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_wire_strings_stable() {
        // Wire contract with migration 011/013 / future readers — do not rename.
        assert_eq!(McpAuditAction::AuthRejected.as_db_str(), "auth_rejected");
        assert_eq!(McpAuditAction::RateLimited.as_db_str(), "rate_limited");
        assert_eq!(McpAuditAction::SessionClose.as_db_str(), "session_close");
        assert_eq!(McpAuditAction::ToolCall.as_db_str(), "tool_call");
    }

    #[test]
    fn adverse_events_record_error_session_close_records_ok() {
        assert!(matches!(
            McpAuditAction::AuthRejected.default_status(),
            McpAuditStatus::Error
        ));
        assert!(matches!(
            McpAuditAction::RateLimited.default_status(),
            McpAuditStatus::Error
        ));
        // Session close and tool calls are normal lifecycle events, not
        // failures (a failed tool call flips the row to 'error' via the
        // non-empty `error` argument inside log_mcp_event).
        assert!(matches!(
            McpAuditAction::SessionClose.default_status(),
            McpAuditStatus::Ok
        ));
        assert!(matches!(
            McpAuditAction::ToolCall.default_status(),
            McpAuditStatus::Ok
        ));
    }

    #[test]
    fn truncate_bounds_error_length() {
        let long = "x".repeat(600);
        let out = truncate_redacted(&long);
        assert!(out.chars().count() <= 500 + "…[truncated]".chars().count());
        assert!(out.ends_with("[truncated]"));
        assert_eq!(truncate_redacted("short"), "short");
    }
}
