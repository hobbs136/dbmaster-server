//! SQL-identifier quoting helpers, dialect-aware.
//!
//! Identifiers reaching here are already validated by
//! [`crate::config::is_safe_identifier`] (ASCII `[A-Za-z_][A-Za-z0-9_]*`).
//! MySQL and PostgreSQL quote identifiers differently:
//! - MySQL: backticks `` `name` `` (double quotes are string literals unless
//!   `ANSI_QUOTES` sql_mode is on, which we don't assume).
//! - PostgreSQL / SQLite: double quotes `"name"` (the SQL standard).
//!
//! Callers pass the dialect matching the target pool so the assembled SQL is
//! valid for the driver that executes it.

/// SQL dialect for identifier quoting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    MySql,
    Postgres,
    /// CHANGE: 三期 — ClickHouse 用反引号（与 MySQL 一致，CH 认 backtick）。
    ClickHouse,
    /// CHANGE: Doris 用反引号（与 MySQL 一致）。
    Doris,
}

/// Quote an identifier for the given dialect. Assumes pre-validated input
/// (config validation rejects embedded quote chars / SQL metacharacters).
pub fn quote(name: &str, dialect: Dialect) -> String {
    match dialect {
        Dialect::MySql | Dialect::ClickHouse | Dialect::Doris => {
            let escaped = name.replace('`', "``");
            format!("`{escaped}`")
        }
        Dialect::Postgres => {
            let escaped = name.replace('"', "\"\"");
            format!("\"{escaped}\"")
        }
    }
}
