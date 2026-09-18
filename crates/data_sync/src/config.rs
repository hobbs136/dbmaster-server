//! Strongly-typed config model for `data_sync` tasks.
//!
//! Stored as JSON in `scheduled_tasks.config`. The wire format is shaped by
//! the Flutter `DataSyncDialog` (一期) — main table as anchor, optional
//! LEFT JOIN tables for wide-table construction, column selection/rename +
//! constant marker columns, time-batched pagination, and an optional cron
//! schedule (None = run-once).
//!
//! Trust boundary: table/column/alias identifiers are validated against a
//! strict identifier regex in [`DataSyncTaskConfig::validate`] before they
//! ever reach SQL string assembly (see [`crate::runner::sql`] for the
//! quoting helpers). User-supplied `on` clauses are restricted to the
//! `ident.ident = ident.ident` shape via [`JoinTable::validate_on`].

use serde::{Deserialize, Serialize};

/// A `data_sync` task's full configuration (the JSON stored in
/// `scheduled_tasks.config`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSyncTaskConfig {
    /// Source (anchor) connection + table. The main table drives batching.
    pub source: SourceConfig,
    /// Target connection + table the ETL writes into.
    pub target: TargetConfig,
    /// LEFT JOIN tables (empty = plain single-table copy). Each contributes
    /// zero or more columns to the final SELECT list.
    #[serde(default)]
    pub join_tables: Vec<JoinTable>,
    /// Which columns end up in the target + how they're named.
    pub column_mapping: ColumnMapping,
    /// Time-batched pagination (一期 only supports time anchors).
    pub batching: BatchingConfig,
    /// Target write strategy (append / truncate / upsert).
    pub target_strategy: TargetStrategy,
    /// Schedule. `None` = run-once (manual or API trigger only).
    #[serde(default)]
    pub schedule: Option<ScheduleConfig>,
}

/// Anchor (main) source table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceConfig {
    /// `database_connections.id` for the source server.
    pub connection_id: String,
    /// Optional database/schema override (else the connection's default).
    pub database: Option<String>,
    /// Anchor table name (must pass [`is_safe_identifier`]).
    pub table: String,
}

/// Target table that receives the wide-table rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    /// `database_connections.id` for the target server.
    pub connection_id: String,
    pub database: Option<String>,
    /// Target table name (must already exist; 一期 does not create tables).
    pub table: String,
}

/// A single LEFT JOIN contribution (一期: only LEFT JOIN supported).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinTable {
    pub table: String,
    /// Optional alias used in ON/column refs (defaults to `table`).
    pub alias: Option<String>,
    /// Always `LeftJoin` in v1 (kept as an enum for forward-compat).
    pub join_type: JoinType,
    /// ON condition, e.g. `main.user_id = profiles.id`. Validated by
    /// [`JoinTable::validate_on`] to the `ident.ident = ident.ident` shape.
    pub on: String,
    /// Optional database/schema override (same source connection).
    pub database: Option<String>,
}

/// The set of JOIN kinds v1 understands. Only LEFT JOIN is emitted; the enum
/// exists so adding INNER/RIGHT later doesn't break the wire format.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JoinType {
    #[default]
    LeftJoin,
}

/// Column selection + optional constant marker columns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ColumnMapping {
    /// Selected source columns (table_alias.column_name → target_name).
    #[serde(default)]
    pub columns: Vec<ColumnSelect>,
    /// Constant columns appended to every emitted row (e.g.
    /// `source_table = "users"`).
    #[serde(default)]
    pub constants: Vec<ConstantColumn>,
}

/// A selected source column with an optional rename in the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnSelect {
    /// Fully-qualified source ref: `<alias>.<column>` (e.g. `main.id`,
    /// `profiles.phone`).
    pub source: String,
    /// Target column name (must pass [`is_safe_identifier`]).
    pub target: String,
}

/// A constant column injected into every emitted row of this sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantColumn {
    /// Target column name (must pass [`is_safe_identifier`]).
    pub target: String,
    /// JSON value (string/number/bool/null). Rendered as a SQL literal via
    /// parameter binding — never string-interpolated.
    pub value: serde_json::Value,
}

/// Time-batched pagination config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchingConfig {
    /// Anchor column on the main table (e.g. `created_at`, `updated_at`).
    /// Must be a time-typed column with an index; 一期 does not EXPLAIN-check.
    pub time_field: String,
    /// Rows per batch (default applied from Config::data_sync_default_batch_size
    /// when the runner reads it; the config value wins if present).
    #[serde(default)]
    pub batch_size: Option<u64>,
    /// Incremental start (ISO8601). `None` = full sync from MIN(time_field).
    /// Set this to do incremental runs (the runner persists the cursor and
    /// resumes from it on subsequent runs of the same task).
    #[serde(default)]
    pub start: Option<String>,
    /// Max retry attempts per batch insert on transient failure (default 3).
    /// Backoff is fixed 1s / 4s / 16s (exponential). After exhausting retries
    /// the batch is counted as failed_rows and the cursor advances.
    #[serde(default)]
    pub batch_retries: Option<u32>,
}

/// Target write strategy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TargetStrategy {
    /// Append rows (no pre-clear; may duplicate on re-runs of the same range).
    #[default]
    Append,
    /// TRUNCATE target before writing (full sync only; ignored if cursor resumes).
    Truncate,
    /// UPSERT by the given target column (usually the main table's PK).
    Upsert(String),
}

/// Optional cron schedule. `None` on the task config means run-once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// 5-field cron expression (e.g. `0 3 * * *` = daily at 03:00).
    pub cron: String,
    /// IANA timezone (e.g. `Asia/Shanghai`). `None` = UTC.
    #[serde(default)]
    pub timezone: Option<String>,
}

impl DataSyncTaskConfig {
    /// Validate every identifier before any SQL is assembled. Returns the
    /// first structural error (caller surfaces a redacted message).
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_identifier_opt(&self.source.database, "source.database")?;
        validate_identifier(&self.source.table, "source.table")?;

        validate_identifier_opt(&self.target.database, "target.database")?;
        validate_identifier(&self.target.table, "target.table")?;

        for (i, jt) in self.join_tables.iter().enumerate() {
            validate_identifier(&jt.table, format!("join_tables[{i}].table"))?;
            validate_identifier_opt(&jt.database, format!("join_tables[{i}].database"))?;
            if let Some(alias) = &jt.alias {
                validate_identifier(alias, format!("join_tables[{i}].alias"))?;
            }
            validate_on(&jt.on, format!("join_tables[{i}].on"))?;
        }

        if self.column_mapping.columns.is_empty() && self.column_mapping.constants.is_empty() {
            return Err(ConfigError::NoColumns);
        }
        for (i, c) in self.column_mapping.columns.iter().enumerate() {
            validate_qualified(&c.source, format!("column_mapping.columns[{i}].source"))?;
            validate_identifier(&c.target, format!("column_mapping.columns[{i}].target"))?;
        }
        for (i, c) in self.column_mapping.constants.iter().enumerate() {
            validate_identifier(&c.target, format!("column_mapping.constants[{i}].target"))?;
        }

        validate_identifier(&self.batching.time_field, "batching.time_field")?;
        if self.batching.batch_size == Some(0) {
            return Err(ConfigError::InvalidBatchSize);
        }
        if let Some(start) = &self.batching.start {
            chrono::DateTime::parse_from_rfc3339(start)
                .map_err(|_| ConfigError::InvalidStartDate)?;
        }

        if let Some(sched) = &self.schedule {
            // cron + timezone parsing is exercised in the scheduler; here we
            // only sanity-check non-empty.
            if sched.cron.trim().is_empty() {
                return Err(ConfigError::EmptyCron);
            }
        }

        match &self.target_strategy {
            TargetStrategy::Upsert(key) => validate_identifier(key, "target_strategy.upsert_key")?,
            _ => {}
        }

        Ok(())
    }
}

/// Identifier rules: 1–64 chars of `[A-Za-z_][A-Za-z0-9_]*`. This matches
/// MySQL/PG/SQLite unquoted identifiers and rejects SQL metacharacters,
/// dots, semicolons, comments, etc.
fn is_safe_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    matches!(s.len(), 1..=64)
}

/// A `alias.column` qualified ref. Both halves must be safe identifiers.
fn is_safe_qualified(s: &str) -> bool {
    let (alias, col) = match s.split_once('.') {
        Some(pair) => pair,
        None => return false,
    };
    is_safe_identifier(alias) && is_safe_identifier(col)
}

/// Validate an optional identifier (None is always OK).
fn validate_identifier_opt(value: &Option<String>, field: impl AsRef<str>) -> Result<(), ConfigError> {
    match value {
        None => Ok(()),
        Some(s) if is_safe_identifier(s) => Ok(()),
        Some(_) => Err(ConfigError::UnsafeIdentifier(field.as_ref().to_string())),
    }
}

fn validate_identifier(value: &str, field: impl AsRef<str>) -> Result<(), ConfigError> {
    if is_safe_identifier(value) {
        Ok(())
    } else {
        Err(ConfigError::UnsafeIdentifier(field.as_ref().to_string()))
    }
}

fn validate_qualified(value: &str, field: impl AsRef<str>) -> Result<(), ConfigError> {
    if is_safe_qualified(value) {
        Ok(())
    } else {
        Err(ConfigError::UnsafeIdentifier(field.as_ref().to_string()))
    }
}

/// ON-clause whitelist: must be exactly `<alias>.<col> = <alias>.<col>`.
/// Anything else (extra parens, OR, subqueries, comments) is rejected.
fn validate_on(value: &str, field: impl AsRef<str>) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    let (lhs, rhs) = match trimmed.split_once('=') {
        Some(pair) => pair,
        None => return Err(ConfigError::InvalidOnClause(field.as_ref().to_string())),
    };
    if !is_safe_qualified(lhs.trim()) || !is_safe_qualified(rhs.trim()) {
        return Err(ConfigError::InvalidOnClause(field.as_ref().to_string()));
    }
    Ok(())
}

impl JoinTable {
    /// Effective alias for SQL emission (falls back to the table name).
    pub fn effective_alias(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.table)
    }
}

/// Structural config errors. The message is safe to surface (no secrets);
/// the runner additionally redacts any DB-side error before persistence.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unsafe identifier in field `{0}` (must match [A-Za-z_][A-Za-z0-9_]{{1,64}})")]
    UnsafeIdentifier(String),
    #[error("invalid ON clause in field `{0}` (expected `alias.col = alias.col`)")]
    InvalidOnClause(String),
    #[error("column_mapping must select at least one column or define a constant")]
    NoColumns,
    #[error("batch_size must be > 0")]
    InvalidBatchSize,
    #[error("batching.start must be ISO8601 / RFC3339")]
    InvalidStartDate,
    #[error("schedule.cron must not be empty")]
    EmptyCron,
}
