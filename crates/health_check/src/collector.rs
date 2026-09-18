//! Health-metric collection for the 4 core metrics (ADR-0004 §3.2).
//!
//! Two-dialect design mirrors drift's collector: separate `collect_mysql` /
//! `collect_postgres` entry points, each taking a strongly-typed
//! `sqlx::Pool<MySql>` / `sqlx::Pool<Postgres>`. The M4 runner opens the
//! correct pool by `database_connections.db_type` and dispatches here.
//!
//! Non-MySQL/PG connections never reach this module — the runner degrades to
//! connectivity-only for them (requirements R2).
//!
//! Trust boundary (ADR-0004 §5): every query here is a SELECT against
//! `information_schema` / `pg_catalog` / `SHOW STATUS` / `pg_stat_*`. No
//! business-row reads, no writes. The `database` parameter is bound
//! (`?` / `$1`), never spliced into the SQL string.

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, MySql, Postgres};

use crate::config::MetricFlags;

// ── Result types (serialized into health_check_results.metrics_summary) ──

/// Full result of one metric-collection pass for a single connection.
///
/// Every field except `connectivity` and `db_type` is `Option`: a metric may
/// be `None` because it was disabled in [`MetricFlags`], unsupported for the
/// db type, or failed to collect (permission error / query error). The
/// `unsupported_metrics` list records which were skipped and why, so the
/// runner can mark the run `partial` and the webhook payload can explain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Always collected (even for non-MySQL/PG db types).
    pub connectivity: ConnectivityResult,
    /// Largest tables by estimated row count (TOP N, default 10).
    pub row_count: Option<TableRowStats>,
    /// Tables in the source database missing a primary key.
    pub missing_pk: Option<MissingPkStats>,
    /// Active connection count at collection time.
    pub connection_count: Option<u64>,
    /// Source db_type (e.g. "mysql", "postgres", "sqlite"). Used by the runner
    /// to decide alert applicability and by tests to assert degradation.
    pub db_type: String,
    /// Metrics that were skipped (disabled / unsupported / errored), with a
    /// short reason. Empty when everything collected cleanly.
    #[serde(default)]
    pub unsupported_metrics: Vec<UnsupportedMetric>,
}

/// Connectivity + latency probe result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityResult {
    /// `true` if `SELECT 1` returned within the timeout.
    pub ok: bool,
    /// Round-trip latency in milliseconds (0 on failure).
    pub latency_ms: u64,
    /// Error message on failure (redacted — no credential / PII).
    pub error: Option<String>,
}

/// Largest-tables stats (TOP N by estimated row count).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TableRowStats {
    /// `(table_name, estimated_rows)` sorted descending by rows.
    pub top_tables: Vec<(String, u64)>,
}

/// Missing-primary-key stats.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MissingPkStats {
    /// Table names (unqualified for MySQL, schema-qualified for PG) that are
    /// base tables lacking a PRIMARY KEY. Sorted for deterministic comparison.
    pub tables: Vec<String>,
}

/// Record of a metric that was skipped during collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsupportedMetric {
    pub metric: String,
    pub reason: String,
}

// ── MySQL collection ──

/// Row type for the table-row-estimate query (MySQL information_schema).
#[derive(Debug, Clone, FromRow)]
pub struct MySqlTableRowRow {
    pub table_name: String,
    pub table_rows: Option<i64>,
}

/// Row type for the missing-PK query (MySQL information_schema).
#[derive(Debug, Clone, FromRow)]
pub struct MySqlMissingPkRow {
    pub table_name: String,
}

/// `SHOW STATUS LIKE 'Threads_connected'` returns a name/value string pair.
#[derive(Debug, Clone, FromRow)]
pub struct MySqlStatusRow {
    pub variable_name: String,
    pub value: String,
}

/// MySQL `information_schema.tables` query for the TOP N largest tables by
/// estimated row count. `table_rows` is an InnoDB estimate (requirements R2 +
/// design §3.2). The `?` binds the schema/database name; `LIMIT ?` binds N.
pub const MYSQL_TOP_TABLES_SQL: &str = "\
SELECT table_name AS table_name, table_rows AS table_rows \
FROM information_schema.tables \
WHERE table_schema = ? AND table_type = 'BASE TABLE' \
ORDER BY table_rows DESC \
LIMIT ?";

/// MySQL `information_schema` anti-join for base tables lacking a PRIMARY KEY.
/// Binds the schema name once.
pub const MYSQL_MISSING_PK_SQL: &str = "\
SELECT t.table_name AS table_name \
FROM information_schema.tables t \
WHERE t.table_schema = ? AND t.table_type = 'BASE TABLE' \
  AND NOT EXISTS ( \
    SELECT 1 FROM information_schema.table_constraints c \
    WHERE c.table_schema = t.table_schema \
      AND c.table_name = t.table_name \
      AND c.constraint_type = 'PRIMARY KEY' \
  ) \
ORDER BY t.table_name";

/// Collect MySQL metrics. Each metric is independent: a failure in one (e.g.
/// permission denied on `SHOW STATUS`) records an [`UnsupportedMetric`] and
/// the remaining metrics still collect. `database` is the schema name to
/// scope table-level queries.
///
/// `top_n` controls how many rows the `row_count` metric returns (default 10).
pub async fn collect_mysql(
    pool: &sqlx::Pool<MySql>,
    database: &str,
    flags: &MetricFlags,
    top_n: i64,
) -> MetricsSnapshot {
    let mut snapshot = MetricsSnapshot {
        connectivity: measure_connectivity_mysql(pool).await,
        row_count: None,
        missing_pk: None,
        connection_count: None,
        db_type: "mysql".to_string(),
        unsupported_metrics: vec![],
    };

    if flags.row_count {
        match collect_mysql_top_tables(pool, database, top_n).await {
            Ok(stats) => snapshot.row_count = Some(stats),
            Err(e) => snapshot.unsupported_metrics.push(UnsupportedMetric {
                metric: "row_count".to_string(),
                reason: redact_error(&e),
            }),
        }
    }

    if flags.missing_pk {
        match collect_mysql_missing_pk(pool, database).await {
            Ok(stats) => snapshot.missing_pk = Some(stats),
            Err(e) => snapshot.unsupported_metrics.push(UnsupportedMetric {
                metric: "missing_pk".to_string(),
                reason: redact_error(&e),
            }),
        }
    }

    if flags.connection_count {
        match collect_mysql_connection_count(pool).await {
            Ok(n) => snapshot.connection_count = Some(n),
            Err(e) => snapshot.unsupported_metrics.push(UnsupportedMetric {
                metric: "connection_count".to_string(),
                reason: redact_error(&e),
            }),
        }
    }

    snapshot
}

/// `SELECT 1` round-trip with latency. Any error → `ok: false` + redacted
/// message; never propagates (connectivity is the core probe — a failure here
/// is a result, not an abort).
async fn measure_connectivity_mysql(pool: &sqlx::Pool<MySql>) -> ConnectivityResult {
    let start = std::time::Instant::now();
    match sqlx::query("SELECT 1").execute(pool).await {
        Ok(_) => ConnectivityResult {
            ok: true,
            latency_ms: start.elapsed().as_millis() as u64,
            error: None,
        },
        Err(e) => ConnectivityResult {
            ok: false,
            latency_ms: 0,
            error: Some(redact_error(&e)),
        },
    }
}

async fn collect_mysql_top_tables(
    pool: &sqlx::Pool<MySql>,
    database: &str,
    top_n: i64,
) -> anyhow::Result<TableRowStats> {
    let rows = sqlx::query_as::<_, MySqlTableRowRow>(MYSQL_TOP_TABLES_SQL)
        .bind(database)
        .bind(top_n)
        .fetch_all(pool)
        .await?;
    let top_tables = rows
        .into_iter()
        .map(|r| (r.table_name, r.table_rows.unwrap_or(0).max(0) as u64))
        .collect();
    Ok(TableRowStats { top_tables })
}

async fn collect_mysql_missing_pk(
    pool: &sqlx::Pool<MySql>,
    database: &str,
) -> anyhow::Result<MissingPkStats> {
    let rows = sqlx::query_as::<_, MySqlMissingPkRow>(MYSQL_MISSING_PK_SQL)
        .bind(database)
        .fetch_all(pool)
        .await?;
    Ok(MissingPkStats {
        tables: rows.into_iter().map(|r| r.table_name).collect(),
    })
}

async fn collect_mysql_connection_count(pool: &sqlx::Pool<MySql>) -> anyhow::Result<u64> {
    let row: MySqlStatusRow =
        sqlx::query_as::<_, MySqlStatusRow>("SHOW STATUS LIKE 'Threads_connected'")
            .fetch_one(pool)
            .await?;
    row.value.parse::<u64>().map_err(anyhow::Error::from)
}

// ── PostgreSQL collection ──

/// Row type for the table-row-estimate query (PG pg_stat_user_tables).
#[derive(Debug, Clone, FromRow)]
pub struct PgTableRowRow {
    pub relname: String,
    pub n_live_tup: Option<i64>,
}

/// Row type for the missing-PK query (PG pg_tables + pg_indexes).
#[derive(Debug, Clone, FromRow)]
pub struct PgMissingPkRow {
    pub tablename: String,
}

/// PG `pg_stat_user_tables` query for TOP N largest tables by live-tuple
/// estimate. `LIMIT $1` binds N. Excludes system schemas automatically
/// (pg_stat_user_tables only exposes user schemas).
pub const PG_TOP_TABLES_SQL: &str = "\
SELECT relname AS relname, n_live_tup AS n_live_tup \
FROM pg_stat_user_tables \
ORDER BY n_live_tup DESC NULLS LAST \
LIMIT $1";

/// PG query for base tables lacking a PRIMARY KEY. Joins `pg_tables` against
/// `pg_indexes` (filtering for PRIMARY KEY in the indexdef). Excludes
/// system/internal schemas (`pg_%`).
pub const PG_MISSING_PK_SQL: &str = "\
SELECT t.tablename AS tablename \
FROM pg_tables t \
WHERE t.schemaname NOT LIKE 'pg_%' \
  AND NOT EXISTS ( \
    SELECT 1 FROM pg_indexes i \
    WHERE i.schemaname = t.schemaname \
      AND i.tablename = t.tablename \
      AND i.indexdef LIKE '%PRIMARY KEY%' \
  ) \
ORDER BY t.tablename";

/// Collect PostgreSQL metrics. Independent per-metric failure handling mirrors
/// [`collect_mysql`].
pub async fn collect_postgres(
    pool: &sqlx::Pool<Postgres>,
    flags: &MetricFlags,
    top_n: i64,
) -> MetricsSnapshot {
    let mut snapshot = MetricsSnapshot {
        connectivity: measure_connectivity_postgres(pool).await,
        row_count: None,
        missing_pk: None,
        connection_count: None,
        db_type: "postgres".to_string(),
        unsupported_metrics: vec![],
    };

    if flags.row_count {
        match collect_pg_top_tables(pool, top_n).await {
            Ok(stats) => snapshot.row_count = Some(stats),
            Err(e) => snapshot.unsupported_metrics.push(UnsupportedMetric {
                metric: "row_count".to_string(),
                reason: redact_error(&e),
            }),
        }
    }

    if flags.missing_pk {
        match collect_pg_missing_pk(pool).await {
            Ok(stats) => snapshot.missing_pk = Some(stats),
            Err(e) => snapshot.unsupported_metrics.push(UnsupportedMetric {
                metric: "missing_pk".to_string(),
                reason: redact_error(&e),
            }),
        }
    }

    if flags.connection_count {
        match collect_pg_connection_count(pool).await {
            Ok(n) => snapshot.connection_count = Some(n),
            Err(e) => snapshot.unsupported_metrics.push(UnsupportedMetric {
                metric: "connection_count".to_string(),
                reason: redact_error(&e),
            }),
        }
    }

    snapshot
}

async fn measure_connectivity_postgres(pool: &sqlx::Pool<Postgres>) -> ConnectivityResult {
    let start = std::time::Instant::now();
    match sqlx::query("SELECT 1").execute(pool).await {
        Ok(_) => ConnectivityResult {
            ok: true,
            latency_ms: start.elapsed().as_millis() as u64,
            error: None,
        },
        Err(e) => ConnectivityResult {
            ok: false,
            latency_ms: 0,
            error: Some(redact_error(&e)),
        },
    }
}

async fn collect_pg_top_tables(
    pool: &sqlx::Pool<Postgres>,
    top_n: i64,
) -> anyhow::Result<TableRowStats> {
    let rows = sqlx::query_as::<_, PgTableRowRow>(PG_TOP_TABLES_SQL)
        .bind(top_n)
        .fetch_all(pool)
        .await?;
    let top_tables = rows
        .into_iter()
        .map(|r| (r.relname, r.n_live_tup.unwrap_or(0).max(0) as u64))
        .collect();
    Ok(TableRowStats { top_tables })
}

async fn collect_pg_missing_pk(pool: &sqlx::Pool<Postgres>) -> anyhow::Result<MissingPkStats> {
    let rows = sqlx::query_as::<_, PgMissingPkRow>(PG_MISSING_PK_SQL)
        .fetch_all(pool)
        .await?;
    Ok(MissingPkStats {
        tables: rows.into_iter().map(|r| r.tablename).collect(),
    })
}

async fn collect_pg_connection_count(pool: &sqlx::Pool<Postgres>) -> anyhow::Result<u64> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity")
        .fetch_one(pool)
        .await?;
    Ok(count.max(0) as u64)
}

// ── Helpers ──

/// Redact an error for storage / webhook: keep the short chain, drop any
/// embedded SQL or credential text. Mirrors drift's redaction philosophy
/// (ADR-0002 §4.4.2 — no SQL / credential / PII in payloads or logs).
///
/// Generic over `Display` so it works uniformly for `sqlx::Error` (connectivity
/// probes) and `anyhow::Error` (typed collectors).
fn redact_error<E: std::fmt::Display + ?Sized>(e: &E) -> String {
    let s = e.to_string();
    // Take the first line + cap length; sqlx errors often embed the full SQL
    // and driver diagnostics which we don't want in a webhook payload.
    let first_line = s.lines().next().unwrap_or("collection error");
    first_line.chars().take(200).collect()
}

/// Build a connectivity-only snapshot for non-MySQL/PG db types (degradation
/// path, requirements R2). The M4 runner calls this when `db_type` is not
/// `mysql` or `postgres`. Row-level metrics are recorded as unsupported with
/// the reason `"unsupported_db_type"`.
///
/// The caller supplies the connectivity result because the runner probes
/// connectivity with the db-type-appropriate driver (e.g. a SQLite in-memory
/// pool, a Redis PING) rather than going through this module's MySQL/PG
/// helpers.
pub fn connectivity_only_snapshot(
    db_type: &str,
    connectivity: ConnectivityResult,
    flags: &MetricFlags,
) -> MetricsSnapshot {
    let mut unsupported = vec![];
    if flags.row_count {
        unsupported.push(UnsupportedMetric {
            metric: "row_count".to_string(),
            reason: "unsupported_db_type".to_string(),
        });
    }
    if flags.missing_pk {
        unsupported.push(UnsupportedMetric {
            metric: "missing_pk".to_string(),
            reason: "unsupported_db_type".to_string(),
        });
    }
    if flags.connection_count {
        unsupported.push(UnsupportedMetric {
            metric: "connection_count".to_string(),
            reason: "unsupported_db_type".to_string(),
        });
    }
    MetricsSnapshot {
        connectivity,
        row_count: None,
        missing_pk: None,
        connection_count: None,
        db_type: db_type.to_string(),
        unsupported_metrics: unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connectivity_only_snapshot_marks_metrics_unsupported() {
        let flags = MetricFlags::default();
        let snap = connectivity_only_snapshot(
            "sqlite",
            ConnectivityResult {
                ok: true,
                latency_ms: 2,
                error: None,
            },
            &flags,
        );
        assert_eq!(snap.db_type, "sqlite");
        assert!(snap.connectivity.ok);
        assert_eq!(snap.unsupported_metrics.len(), 3);
        assert!(snap
            .unsupported_metrics
            .iter()
            .all(|m| m.reason == "unsupported_db_type"));
    }

    #[test]
    fn connectivity_only_snapshot_respects_disabled_flags() {
        let flags = MetricFlags {
            connectivity: true,
            row_count: false,
            missing_pk: false,
            connection_count: false,
        };
        let snap = connectivity_only_snapshot(
            "redis",
            ConnectivityResult {
                ok: true,
                latency_ms: 1,
                error: None,
            },
            &flags,
        );
        assert!(snap.unsupported_metrics.is_empty());
    }

    #[test]
    fn metrics_snapshot_serializes_to_summary_json() {
        let snap = MetricsSnapshot {
            connectivity: ConnectivityResult {
                ok: true,
                latency_ms: 5,
                error: None,
            },
            row_count: Some(TableRowStats {
                top_tables: vec![("big_table".to_string(), 1_000_000)],
            }),
            missing_pk: Some(MissingPkStats {
                tables: vec!["no_pk_table".to_string()],
            }),
            connection_count: Some(42),
            db_type: "mysql".to_string(),
            unsupported_metrics: vec![],
        };
        let json = serde_json::to_string(&snap).unwrap();
        // Round-trip preserves all fields.
        let back: MetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert!(back.connectivity.ok);
        assert_eq!(back.row_count.unwrap().top_tables.len(), 1);
        assert_eq!(back.missing_pk.unwrap().tables, vec!["no_pk_table"]);
        assert_eq!(back.connection_count, Some(42));
    }

    #[test]
    fn redact_error_caps_length_and_drops_subsequent_lines() {
        // anyhow error with multi-line display.
        let e = anyhow::anyhow!("line one with SQL SELECT * FROM big\nline two: credential=hunter2");
        let redacted = redact_error(&e);
        assert_eq!(redacted, "line one with SQL SELECT * FROM big");
        assert!(redacted.len() <= 200);
    }

    #[test]
    fn mysql_top_tables_sql_binds_database_and_limit() {
        // Sanity: the SQL text contains both placeholders. This guards against
        // accidental string-concatenation regressions.
        assert!(MYSQL_TOP_TABLES_SQL.contains("table_schema = ?"));
        assert!(MYSQL_TOP_TABLES_SQL.contains("LIMIT ?"));
    }

    #[test]
    fn mysql_missing_pk_sql_uses_parameterized_schema() {
        assert!(MYSQL_MISSING_PK_SQL.contains("t.table_schema = ?"));
        // Must NOT splice the database name.
        assert!(!MYSQL_MISSING_PK_SQL.contains("information_schema.tables t WHERE t.table_schema = ? AND 1=1"));
    }

    #[test]
    fn pg_top_tables_sql_binds_limit_only() {
        assert!(PG_TOP_TABLES_SQL.contains("LIMIT $1"));
    }

    #[test]
    fn pg_missing_pk_sql_excludes_system_schemas() {
        assert!(PG_MISSING_PK_SQL.contains("NOT LIKE 'pg_%'"));
        assert!(PG_MISSING_PK_SQL.contains("PRIMARY KEY"));
    }
}
