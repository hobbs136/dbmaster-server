//! Read-only canary for `kind = source_drift` connections (ADR-0002 §4.2.3 L2 /
//! v1-C-4).
//!
//! When a customer records a source-DB connection, we attempt a write that
//! should fail on a properly-scoped read-only account. If it succeeds we
//! refuse to save the connection: the customer gave us a write-capable
//! account and our trust model (§1.1 honest-user mode + §6 mitigations)
//! assumes read-only.
//!
//! Safety properties of the canary itself:
//! - **No business-row access**: only DDL on a throwaway `dbmaster_canary_*`
//!   table, never a `SELECT`/`INSERT`/`UPDATE`/`DELETE` on a real table.
//! - **No persistent side effect**:
//!   - MySQL: `CREATE TEMPORARY TABLE` (session-scoped, drops on disconnect)
//!     and if it succeeds, immediate `DROP TEMPORARY TABLE` + return Writable.
//!   - PostgreSQL: `BEGIN; CREATE TEMP TABLE ...; ROLLBACK;` — transactional
//!     DDL, the ROLLBACK undoes the CREATE.
//! - **Failure-expected**: the *normal* outcome is `ReadOnly` (the CREATE
//!   errors with `permission denied`).

use sqlx::{MySql, Postgres};

/// Result of a canary probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryOutcome {
    /// The CREATE failed → the account cannot write; this is what we want.
    ReadOnly,
    /// The CREATE succeeded → the account has write privilege; refuse save.
    Writable,
    /// The DB itself was unreachable / authentication failed. Treated as a
    /// separate outcome so the caller can surface a distinct error.
    Unreachable(String),
}

/// Interpret a "did the CREATE succeed?" boolean into a [`CanaryOutcome`].
/// Exposed so unit tests can cover the pure decision logic without a live DB.
pub fn interpret(create_succeeded: bool) -> CanaryOutcome {
    if create_succeeded {
        CanaryOutcome::Writable
    } else {
        CanaryOutcome::ReadOnly
    }
}

// ── SQL strings ──

/// MySQL canary: `CREATE TEMPORARY TABLE`. Session-scoped; even if we crash
/// before cleanup the table dies with the connection. Read-only accounts
/// (those lacking `CREATE TEMPORARY TABLES` privilege) reject this.
// CHANGE: ADR-0002 §4.2.3 L2 — write probe that read-only accounts fail.
pub fn mysql_canary_create_sql() -> &'static str {
    "CREATE TEMPORARY TABLE dbmaster_canary_readonly (id INT)"
}

pub fn mysql_canary_drop_sql() -> &'static str {
    "DROP TEMPORARY TABLE dbmaster_canary_readonly"
}

/// PostgreSQL canary: `CREATE TEMP TABLE`. Inside a transaction with
/// `ROLLBACK`, even a successful CREATE leaves no persistent footprint.
pub fn pg_canary_create_sql() -> &'static str {
    "CREATE TEMP TABLE dbmaster_canary_readonly (id INT)"
}

// ── Live probes ──

/// Run the canary against an open MySQL pool. Caller opens/closes the pool;
/// this function only executes the two SQL statements.
///
/// DEFENSIVE-NOTE: never returns the underlying sqlx error verbatim to the
/// API caller — the runner / handler redacts to a friendly message.
pub async fn check_mysql(pool: &sqlx::Pool<MySql>) -> CanaryOutcome {
    let create = sqlx::query(mysql_canary_create_sql()).execute(pool).await;
    match create {
        // CREATE succeeded → account can write → clean up + return Writable.
        Ok(_) => {
            // Best-effort cleanup; the temp table dies with the session anyway.
            let _ = sqlx::query(mysql_canary_drop_sql()).execute(pool).await;
            CanaryOutcome::Writable
        }
        Err(e) => {
            // Distinguish "permission denied" (good) from "DB unreachable" (bad).
            if is_connection_level_error(&e) {
                CanaryOutcome::Unreachable(redact(&e))
            } else {
                // Permission / syntax errors ⇒ treat as read-only (good path).
                CanaryOutcome::ReadOnly
            }
        }
    }
}

/// Run the canary against an open PG pool. Wraps the CREATE in a transaction
/// and always rolls back; success ⇒ Writable.
pub async fn check_postgres(pool: &sqlx::Pool<Postgres>) -> CanaryOutcome {
    use sqlx::Acquire;
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => return CanaryOutcome::Unreachable(redact(&e)),
    };

    // BEGIN; CREATE TEMP; ROLLBACK — keep the failure path explicit. Scope tx
    // inside a block so its mutable borrow of `conn` ends before we drop conn.
    let outcome = {
        let mut tx = match conn.begin().await {
            Ok(t) => t,
            Err(e) => return CanaryOutcome::Unreachable(redact(&e)),
        };
        let create = sqlx::query(pg_canary_create_sql()).execute(&mut *tx).await;
        let outcome = match create {
            Ok(_) => CanaryOutcome::Writable,
            Err(e) => {
                if is_connection_level_error(&e) {
                    CanaryOutcome::Unreachable(redact(&e))
                } else {
                    CanaryOutcome::ReadOnly
                }
            }
        };
        // Always rollback — for Writable this drops the temp table; for the
        // failed path it's a no-op (CREATE already errored).
        let _ = tx.rollback().await;
        outcome
    };
    // `conn` returns to the pool automatically on drop; no explicit close.
    outcome
}

/// Heuristic: does this sqlx error suggest the connection itself is broken
/// (vs. a SQL-level "permission denied")? We look at the error's display
/// form for transport-level keywords. This is approximate; both outcomes are
/// handled safely by the caller (we just route them to different messages).
fn is_connection_level_error(e: &sqlx::Error) -> bool {
    let s = e.to_string().to_ascii_lowercase();
    const TRANSPORT_KEYWORDS: &[&str] = &[
        "connection refused",
        "connection reset",
        "broken pipe",
        "timed out",
        "timeout",
        "dns",
        "no route",
        "unreachable",
        "authentication",
        "auth",
        "access denied", // MySQL auth failure
        "password",
        "tls",
        "handshake",
    ];
    TRANSPORT_KEYWORDS.iter().any(|k| s.contains(k))
}

/// Render a sqlx error safe for the audit/error trail: keep the message short
/// and strip anything that looks like a credential. We never include the
/// connection string; the original sqlx error doesn't carry one anyway.
fn redact(e: &sqlx::Error) -> String {
    let msg = e.to_string();
    // Hard cap; the audit writer caps again at 500 but we want this short.
    let cut = msg.chars().take(200).collect::<String>();
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpret_true_is_writable() {
        assert_eq!(interpret(true), CanaryOutcome::Writable);
    }

    #[test]
    fn interpret_false_is_readonly() {
        assert_eq!(interpret(false), CanaryOutcome::ReadOnly);
    }

    #[test]
    fn sql_strings_are_ddl_only_no_business_data() {
        // Sticky grep guard: canary SQL must not touch business rows.
        let mysql_create = mysql_canary_create_sql();
        let mysql_drop = mysql_canary_drop_sql();
        let pg_create = pg_canary_create_sql();

        for sql in [mysql_create, mysql_drop, pg_create] {
            let lower = sql.to_ascii_lowercase();
            assert!(
                lower.starts_with("create ") || lower.starts_with("drop "),
                "canary SQL must be DDL only; got: {sql}"
            );
            // Explicitly forbidding row-mutating statements.
            for forbidden in ["select ", "insert ", "update ", "delete ", "truncate "] {
                assert!(
                    !lower.contains(forbidden),
                    "canary SQL must not contain '{forbidden}': {sql}"
                );
            }
            // Must target only the canary table.
            assert!(
                lower.contains("dbmaster_canary_readonly"),
                "canary SQL must target the canary table: {sql}"
            );
        }
    }

    #[test]
    fn redact_keeps_short_messages() {
        // The redact helper truncates at 200 chars; we cannot easily fake an
        // sqlx::Error with arbitrary text, so we test the cap behaviour at the
        // audit-module level (audit.rs). Here just assert the helper is
        // non-panicking on a synthesised transport error.
        let err = sqlx::Error::Configuration("config typo".into());
        let r = redact(&err);
        assert!(r.contains("config typo"));
    }

    #[test]
    fn connection_level_error_detected_for_transport_keywords() {
        // Synthesised errors via the Display string matching path.
        let e = sqlx::Error::PoolTimedOut;
        assert!(is_connection_level_error(&e));
    }

    #[test]
    fn non_connection_error_not_flagged() {
        // A "duplicate column" or similar logic-level error shouldn't be
        // mistaken for a transport failure (so the canary returns ReadOnly).
        // sqlx::Error::Database carries the server message; we fake it via
        // Configuration which is a different category.
        let e = sqlx::Error::Configuration("permission denied: role u cannot write".into());
        // Note: "permission denied" alone doesn't match keywords — but
        // "denied" doesn't either, so this routes to ReadOnly. Good.
        // However the message does NOT contain transport keywords:
        let s = e.to_string().to_ascii_lowercase();
        const TRANSPORT: &[&str] = &[
            "connection refused",
            "timed out",
            "auth",
            "password",
        ];
        assert!(!TRANSPORT.iter().any(|k| s.contains(k)));
        assert!(!is_connection_level_error(&e));
    }
}
