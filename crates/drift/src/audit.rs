//! `credential_access_audit` writer (ADR-0002 §4.2.4 / v1-C-5).
//!
//! Every time the runner decrypts a stored source-DB credential and uses it,
//! one row is appended here. What we log is deliberately small and never
//! includes secrets:
//!
//! Stored: `connection_id`, `action`, `status`, `error`, `at`, `triggered_by`.
//!
//! Excluded (定律 5 / ADR §4.2.4 hard rule): the credential itself, decrypted
//! plaintext, any SQL text, any returned data, any PII. The caller is required
//! to pre-redact `error`; this module never inserts raw error strings beyond
//! what it is handed (no implicit logging of upstream values).

use anyhow::Context;
use sqlx::SqlitePool;

/// What the credential was used for. Serializes as the wire string stored in
/// the `action` column; matches the ADR §4.2.4 enumeration.
#[derive(Debug, Clone, Copy)]
pub enum AuditAction {
    SchemaSnapshot,
    DriftCompare,
    CanaryCheck,
    WebhookDeliver,
}

impl AuditAction {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::SchemaSnapshot => "schema_snapshot",
            Self::DriftCompare => "drift_compare",
            Self::CanaryCheck => "canary_check",
            Self::WebhookDeliver => "webhook_deliver",
        }
    }
}

/// Outcome of the audited action.
#[derive(Debug, Clone, Copy)]
pub enum AuditStatus {
    Ok,
    Error,
}

impl AuditStatus {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// Append one audit row.
///
/// `error` should be a short, redacted summary (no credential / SQL / PII);
/// pass `None` for success rows. `triggered_by` is `"scheduler"` or
/// `"manual:<user_id>"` per ADR §4.2.4.
// CHANGE: ADR-0002 §4.2.4 / v1-C-5 — every credential decryption/use goes
// through this writer so the audit trail is uniform.
pub async fn log_access(
    pool: &SqlitePool,
    connection_id: &str,
    action: AuditAction,
    status: AuditStatus,
    error: Option<&str>,
    triggered_by: &str,
) -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let err = error.map(truncate_redacted);
    // DEFENSIVE-NOTE: bind all values — never interpolate into SQL. id/
    // connection_id / error are caller-supplied and parameterized; SQL
    // injection is structurally impossible here.
    sqlx::query(
        "INSERT INTO credential_access_audit
            (id, connection_id, action, status, error, at, triggered_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(&id)
    .bind(connection_id)
    .bind(action.as_db_str())
    .bind(status.as_db_str())
    .bind(&err)
    .bind(&now)
    .bind(triggered_by)
    .execute(pool)
    .await
    .context("insert credential_access_audit row")?;
    Ok(())
}

/// Truncate to a bounded length so a misbehaving caller cannot bloat the
/// audit table via an over-long error string. 500 chars is enough for a
/// redacted summary and well below any SQLite TEXT concern.
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

    async fn setup_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE credential_access_audit (
                id            TEXT PRIMARY KEY,
                connection_id TEXT NOT NULL,
                action        TEXT NOT NULL,
                status        TEXT NOT NULL,
                error         TEXT,
                at            TEXT NOT NULL,
                triggered_by  TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn writes_ok_row_with_expected_fields() {
        let pool = setup_pool().await;
        log_access(
            &pool,
            "conn-1",
            AuditAction::SchemaSnapshot,
            AuditStatus::Ok,
            None,
            "scheduler",
        )
        .await
        .unwrap();

        let row: (String, String, String, Option<String>, String, String) = sqlx::query_as(
            "SELECT connection_id, action, status, error, at, triggered_by
             FROM credential_access_audit WHERE connection_id = ?1",
        )
        .bind("conn-1")
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(row.0, "conn-1");
        assert_eq!(row.1, "schema_snapshot");
        assert_eq!(row.2, "ok");
        assert!(row.3.is_none());
        assert!(row.4.contains('T')); // RFC3339
        assert_eq!(row.5, "scheduler");
    }

    #[tokio::test]
    async fn writes_error_row_with_redacted_summary() {
        let pool = setup_pool().await;
        log_access(
            &pool,
            "conn-2",
            AuditAction::CanaryCheck,
            AuditStatus::Error,
            Some("account has CREATE privilege; expected read-only"),
            "manual:user-7",
        )
        .await
        .unwrap();

        let row: (String, Option<String>) = sqlx::query_as(
            "SELECT action, error FROM credential_access_audit WHERE connection_id = ?1",
        )
        .bind("conn-2")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "canary_check");
        assert_eq!(
            row.1.as_deref(),
            Some("account has CREATE privilege; expected read-only")
        );
    }

    // ── v1-C-5: grep assertion that NO sensitive material is stored ──

    #[tokio::test]
    async fn audit_row_contains_no_credentials_sql_or_pii() {
        let pool = setup_pool().await;
        // Even if a careless caller passes a sensitive-looking string, the
        // module only stores exactly that caller-provided value — it must not
        // additionally pull in DB row data, SQL text, or the credential.
        // We assert by dumping all stored text columns and grepping.
        // DEFENSIVE-NOTE: connection_id deliberately avoids containing any
        // forbidden substring (the test data must not trip its own grep).
        log_access(
            &pool,
            "conn-uuid-1234",
            AuditAction::DriftCompare,
            AuditStatus::Ok,
            None,
            "scheduler",
        )
        .await
        .unwrap();

        let rows: Vec<(String, String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT connection_id, action, status, error, triggered_by
             FROM credential_access_audit",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        let forbidden = ["password", "secret", "credential", "mysql://", "postgres://"];
        for (conn_id, action, status, err, triggered_by) in &rows {
            for needle in forbidden {
                assert!(
                    !conn_id.to_lowercase().contains(needle),
                    "connection_id leaked '{needle}': {conn_id}"
                );
                assert!(
                    !action.to_lowercase().contains(needle),
                    "action leaked '{needle}': {action}"
                );
                assert!(
                    !status.to_lowercase().contains(needle),
                    "status leaked '{needle}': {status}"
                );
                if let Some(e) = err {
                    assert!(!e.to_lowercase().contains(needle), "error leaked '{needle}': {e}");
                }
                assert!(
                    !triggered_by.to_lowercase().contains(needle),
                    "triggered_by leaked '{needle}': {triggered_by}"
                );
            }
        }
    }

    #[test]
    fn truncate_redacted_keeps_short_strings_intact() {
        assert_eq!(truncate_redacted("short"), "short");
    }

    #[test]
    fn truncate_redacted_caps_long_strings() {
        let long: String = "a".repeat(1000);
        let t = truncate_redacted(&long);
        assert!(t.chars().count() < 1000);
        assert!(t.ends_with("…[truncated]"));
    }

    #[test]
    fn action_and_status_db_strings_match_adr() {
        assert_eq!(AuditAction::SchemaSnapshot.as_db_str(), "schema_snapshot");
        assert_eq!(AuditAction::DriftCompare.as_db_str(), "drift_compare");
        assert_eq!(AuditAction::CanaryCheck.as_db_str(), "canary_check");
        assert_eq!(AuditAction::WebhookDeliver.as_db_str(), "webhook_deliver");
        assert_eq!(AuditStatus::Ok.as_db_str(), "ok");
        assert_eq!(AuditStatus::Error.as_db_str(), "error");
    }
}
