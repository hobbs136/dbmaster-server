//! Parameterized source-DB schema introspection (ADR-0002 §4.3.1 / v1-C-8).
//!
//! Two responsibilities live here:
//! 1. SQL strings for MySQL and PostgreSQL that read schema metadata from
//!    `information_schema` / `pg_catalog`. Every query is parameterized
//!    (`?`/`$1` bound via sqlx); no `format!` SQL construction anywhere
//!    (v1-C-8 — grep this file for `format!` to verify only safe uses).
//! 2. Pure row-assembly functions that turn flat `information_schema` rows
//!    into the nested [`SchemaSnapshot`] tree. Unit-testable without a real
//!    DB (real-DB e2e is Phase G per the plan).
//!
//! Trust boundary: every query here is read-only metadata. The runner
//! (Phase E) is the only place a customer-DB pool is opened, and only these
//! SQL strings are run against it. No query in this file touches business
//! data (D5 boundary).

use std::collections::BTreeMap;

use sqlx::{FromRow, MySql, Postgres};

use crate::snapshot::{
    ColumnSchema, DbType, ForeignKey, IndexSchema, PrimaryKey, SchemaSnapshot, TableSchema,
};

// ── SQL strings (parameterized; bound via sqlx::query(...).bind(...)) ──

// CHANGE: ADR-0002 §4.3.1 / v1-C-8 — read-only information_schema queries for
// MySQL. `TABLE_SCHEMA = ?` binds the target database name so we never
// introspect more than the configured DB. Ordinal_position and seq_in_index
// preserve the order the DB reports (PK column order matters; index column
// order matters). DEFENSIVE-NOTE: no row data; pure metadata.

/// MySQL column metadata. Returns one row per (table, column).
// CHANGE: v1-C-12 — CAST every selected column so the row decodes cleanly on
// both MySQL 5.7 and 8.0. String columns of information_schema are VARBINARY
// on 8.0 (utf8mb4 collation shift) → CAST AS CHAR normalizes to connection
// charset. Numeric columns (ORDINAL_POSITION, *_PRECISION, *_SCALE,
// CHARACTER_MAXIMUM_LENGTH) are BIGINT UNSIGNED on 8.0 → CAST AS SIGNED maps
// to BIGINT (i64); values are tiny schema metadata, never overflow. CAST is
// the lowest-risk fix: it leaves the row structs and assemblers untouched and
// behaves identically on 5.7 (where the casts are no-ops on already-SIGNED /
// already-VARCHAR columns).
pub fn mysql_columns_sql() -> &'static str {
    r#"
    SELECT
        CAST(TABLE_NAME AS CHAR)      AS table_name,
        CAST(COLUMN_NAME AS CHAR)     AS column_name,
        CAST(ORDINAL_POSITION AS SIGNED) AS ordinal_position,
        CAST(DATA_TYPE AS CHAR)       AS data_type,
        CAST(IS_NULLABLE AS CHAR)     AS is_nullable,
        CAST(COLUMN_DEFAULT AS CHAR)  AS column_default,
        CAST(CHARACTER_MAXIMUM_LENGTH AS SIGNED) AS char_max_length,
        CAST(NUMERIC_PRECISION AS SIGNED) AS numeric_precision,
        CAST(NUMERIC_SCALE AS SIGNED) AS numeric_scale
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = ?
    ORDER BY table_name, ordinal_position
    "#
}

/// MySQL index metadata (covers both PK and secondary indexes).
/// `non_unique = 0` ⇒ unique index. `index_name = 'PRIMARY'` identifies the PK.
// CHANGE: v1-C-12 — same type-drift fix as mysql_columns_sql: CAST AS CHAR for
// the VARBINARY/VARCHAR name columns, CAST AS SIGNED for SEQ_IN_INDEX and
// NON_UNIQUE (INT on 5.7, BIGINT UNSIGNED on 8.0) → uniform BIGINT (i64).
pub fn mysql_indexes_sql() -> &'static str {
    r#"
    SELECT
        CAST(TABLE_NAME AS CHAR)  AS table_name,
        CAST(INDEX_NAME AS CHAR)  AS index_name,
        CAST(COLUMN_NAME AS CHAR) AS column_name,
        CAST(SEQ_IN_INDEX AS SIGNED) AS seq_in_index,
        CAST(NON_UNIQUE AS SIGNED)   AS non_unique
    FROM information_schema.statistics
    WHERE TABLE_SCHEMA = ?
    ORDER BY table_name, index_name, seq_in_index
    "#
}

/// MySQL foreign key metadata.
// CHANGE: v1-C-12 — same type-drift fix: all six selected kcu.* columns are
// VARBINARY (8.0) / VARCHAR (5.7) for the names and BIGINT UNSIGNED (8.0) for
// ORDINAL_POSITION. CAST AS CHAR / AS SIGNED normalizes both versions without
// touching the JOIN (binary=binary compare of VARBINARY CONSTRAINT_NAME works
// on 8.0; the e2e previously failed only on row *decode*, proving the JOIN
// already returned rows).
pub fn mysql_foreign_keys_sql() -> &'static str {
    r#"
    SELECT
        CAST(kcu.TABLE_NAME AS CHAR)             AS table_name,
        CAST(kcu.CONSTRAINT_NAME AS CHAR)        AS constraint_name,
        CAST(kcu.COLUMN_NAME AS CHAR)            AS column_name,
        CAST(kcu.ORDINAL_POSITION AS SIGNED)     AS ordinal_position,
        CAST(kcu.REFERENCED_TABLE_NAME AS CHAR)  AS ref_table,
        CAST(kcu.REFERENCED_COLUMN_NAME AS CHAR) AS ref_column
    FROM information_schema.key_column_usage kcu
    JOIN information_schema.table_constraints tc
      ON tc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME
     AND tc.TABLE_SCHEMA    = kcu.TABLE_SCHEMA
     AND tc.CONSTRAINT_TYPE = 'FOREIGN KEY'
    WHERE kcu.TABLE_SCHEMA = ?
    ORDER BY table_name, constraint_name, ordinal_position
    "#
}

// CHANGE: ADR-0002 §4.3.1 — PG equivalent. PG exposes PK / unique / FK via
// `pg_catalog`; we co-opt information_schema.columns for the column list
// (stable across PG 12+) and pg_index for index semantics.

/// PostgreSQL column metadata. Binds to the target database name (used only
/// for the snapshot label; PG columns are filtered by schema via the JOIN to
/// the local namespace).
// CHANGE: v1-C-12 — information_schema.columns exposes ordinal_position,
// character_maximum_length, numeric_precision, numeric_scale as INT4 (SQL
// standard `integer`). The row struct holds them as i64/Option<i64>, so CAST
// AS BIGINT (INT8) lets sqlx decode without per-field type changes. Name
// columns (table_name/column_name/nspname/data_type/is_nullable/column_default)
// already arrive as PG `name`/`text` and decode to String cleanly — no cast.
pub fn pg_columns_sql() -> &'static str {
    r#"
    SELECT
        c.table_name   AS table_name,
        n.nspname      AS schema_name,
        c.column_name  AS column_name,
        CAST(c.ordinal_position AS BIGINT) AS ordinal_position,
        c.data_type    AS data_type,
        c.is_nullable  AS is_nullable,
        c.column_default AS column_default,
        CAST(c.character_maximum_length AS BIGINT) AS char_max_length,
        CAST(c.numeric_precision AS BIGINT) AS numeric_precision,
        CAST(c.numeric_scale AS BIGINT) AS numeric_scale
    FROM information_schema.columns c
    JOIN pg_namespace n ON n.nspname = c.table_schema
    WHERE c.table_schema = ANY ($1::text[])
    ORDER BY c.table_name, c.ordinal_position
    "#
}

/// PostgreSQL index metadata (PK + secondary). Uses `pg_index` to detect
/// uniqueness / primary-key-ness.
pub fn pg_indexes_sql() -> &'static str {
    r#"
    SELECT
        t.relname      AS table_name,
        i.relname      AS index_name,
        n.nspname      AS schema_name,
        ix.indisunique AS is_unique,
        ix.indisprimary AS is_primary,
        array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS column_names
    FROM pg_index ix
    JOIN pg_class i  ON i.oid = ix.indexrelid
    JOIN pg_class t  ON t.oid = ix.indrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
    WHERE n.nspname = ANY ($1::text[])
    GROUP BY t.relname, i.relname, n.nspname, ix.indisunique, ix.indisprimary
    ORDER BY t.relname, i.relname
    "#
}

/// PostgreSQL foreign key metadata.
pub fn pg_foreign_keys_sql() -> &'static str {
    r#"
    SELECT
        cl.relname     AS table_name,
        ns.nspname     AS schema_name,
        con.conname    AS constraint_name,
        cl2.relname    AS ref_table,
        ns2.nspname    AS ref_schema,
        array_agg(att.attname ORDER BY u.ord) AS columns,
        array_agg(att2.attname ORDER BY u.ord) AS ref_columns
    FROM pg_constraint con
    JOIN pg_class cl  ON cl.oid  = con.conrelid
    JOIN pg_class cl2 ON cl2.oid = con.confrelid
    JOIN pg_namespace ns  ON ns.oid  = cl.relnamespace
    JOIN pg_namespace ns2 ON ns2.oid = cl2.relnamespace
    JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS u(attnum, ord) ON true
    JOIN LATERAL unnest(con.confkey) WITH ORDINALITY AS u2(attnum, ord) ON u2.ord = u.ord
    JOIN pg_attribute att  ON att.attrelid  = cl.oid  AND att.attnum  = u.attnum
    JOIN pg_attribute att2 ON att2.attrelid = cl2.oid AND att2.attnum = u2.attnum
    WHERE con.contype = 'f' AND ns.nspname = ANY ($1::text[])
    GROUP BY cl.relname, ns.nspname, con.conname, cl2.relname, ns2.nspname
    ORDER BY cl.relname, con.conname
    "#
}

// ── Row types (sqlx::FromRow; column aliases match the SQL above) ──
// CHANGE: ADR-0002 §4.3.1 — flat rows that the assembler folds into TableSchema.
// These are the typed targets of sqlx::query_as, decoupled from the assembler
// logic so unit tests can construct them directly.

#[derive(Debug, Clone, FromRow)]
pub struct MySqlColumnRow {
    pub table_name: String,
    pub column_name: String,
    pub ordinal_position: i64,
    pub data_type: String,
    pub is_nullable: String, // information_schema yields 'YES' / 'NO'
    pub column_default: Option<String>,
    pub char_max_length: Option<i64>,
    pub numeric_precision: Option<i64>,
    pub numeric_scale: Option<i64>,
}

#[derive(Debug, Clone, FromRow)]
pub struct MySqlIndexRow {
    pub table_name: String,
    pub index_name: String,
    pub column_name: String,
    pub seq_in_index: i64,
    pub non_unique: i64, // 0 = unique, 1 = non-unique
}

#[derive(Debug, Clone, FromRow)]
pub struct MySqlFkRow {
    pub table_name: String,
    pub constraint_name: String,
    pub column_name: String,
    pub ordinal_position: i64,
    pub ref_table: String,
    pub ref_column: String,
}

// PG rows. Arrays arrive as Vec<String> (sqlx maps Postgres arrays).
#[derive(Debug, Clone, FromRow)]
pub struct PgColumnRow {
    pub table_name: String,
    pub schema_name: String,
    pub column_name: String,
    pub ordinal_position: i64,
    pub data_type: String,
    pub is_nullable: String,
    pub column_default: Option<String>,
    pub char_max_length: Option<i64>,
    pub numeric_precision: Option<i64>,
    pub numeric_scale: Option<i64>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PgIndexRow {
    pub table_name: String,
    pub index_name: String,
    pub schema_name: String,
    pub is_unique: bool,
    pub is_primary: bool,
    pub column_names: Vec<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PgFkRow {
    pub table_name: String,
    pub schema_name: String,
    pub constraint_name: String,
    pub ref_table: String,
    pub ref_schema: String,
    pub columns: Vec<String>,
    pub ref_columns: Vec<String>,
}

// ── Assemblers (pure; unit-testable without a DB) ──

/// Decode `IS_NULLABLE` ('YES'/'NO') to a boolean. Anything else ⇒ nullable
/// (fail-open on the safe side; the snapshot must not silently mis-classify).
fn is_nullable_decode(s: &str) -> bool {
    !s.eq_ignore_ascii_case("NO")
}

/// Fold flat MySQL column rows into the snapshot tree, keyed by table name.
/// `database_name` becomes the `schema` field on each table (MySQL collapses
/// database ↔ schema).
// CHANGE: ADR-0002 §4.3.1 — pure assembler (Phase B unit-tests cover this).
pub fn assemble_mysql_columns(database_name: &str, rows: Vec<MySqlColumnRow>) -> BTreeMap<String, TableSchema> {
    let mut tables: BTreeMap<String, TableSchema> = BTreeMap::new();
    for r in rows {
        let key = format!("{database_name}.{}", r.table_name);
        let table = tables.entry(key.clone()).or_insert_with(|| TableSchema {
            schema: database_name.to_string(),
            name: r.table_name.clone(),
            columns: BTreeMap::new(),
            primary_key: None,
            indexes: BTreeMap::new(),
            foreign_keys: BTreeMap::new(),
        });
        table.columns.insert(
            r.column_name.clone(),
            ColumnSchema {
                name: r.column_name,
                ordinal: r.ordinal_position as i32,
                data_type: r.data_type,
                is_nullable: is_nullable_decode(&r.is_nullable),
                column_default: r.column_default,
                char_max_length: r.char_max_length,
                numeric_precision: r.numeric_precision,
                numeric_scale: r.numeric_scale,
            },
        );
    }
    tables
}

/// Fold MySQL index rows into PK + secondary indexes. PK is detected by
/// `index_name == 'PRIMARY'` (MySQL convention). Column order within each
/// index is preserved by relying on the SQL `ORDER BY ... seq_in_index`
/// (callers fetch via `mysql_indexes_sql()` which already orders rows).
pub fn assemble_mysql_indexes(
    tables: &mut BTreeMap<String, TableSchema>,
    database_name: &str,
    rows: Vec<MySqlIndexRow>,
) {
    // Buffer PK rows per (table-key) so we can preserve seq_in_index order
    // independent of any pre-sorting the caller did.
    let mut pk_columns: BTreeMap<String, Vec<(i64, String)>> = BTreeMap::new();

    for r in rows {
        let key = format!("{database_name}.{}", r.table_name);
        let _table_ref = tables.entry(key.clone()).or_insert_with(|| TableSchema {
            schema: database_name.to_string(),
            name: r.table_name.clone(),
            columns: BTreeMap::new(),
            primary_key: None,
            indexes: BTreeMap::new(),
            foreign_keys: BTreeMap::new(),
        });

        if r.index_name == "PRIMARY" {
            pk_columns
                .entry(key)
                .or_default()
                .push((r.seq_in_index, r.column_name));
            continue;
        }

        // Secondary index: append columns in row order (SQL guarantees
        // seq_in_index ASC for rows arriving here). is_unique is consistent
        // across rows for the same index; we re-assert on every row.
        let table = tables.get_mut(&key).expect("table was just inserted above");
        let entry = table
            .indexes
            .entry(r.index_name.clone())
            .or_insert_with(|| IndexSchema {
                name: r.index_name.clone(),
                columns: Vec::new(),
                is_unique: r.non_unique == 0,
            });
        entry.is_unique = r.non_unique == 0;
        entry.columns.push(r.column_name);
    }

    // Resolve PK columns ordered by seq_in_index (stable regardless of fetch order).
    for (key, mut cols) in pk_columns {
        cols.sort_by_key(|(seq, _)| *seq);
        let pk_names: Vec<String> = cols.into_iter().map(|(_, n)| n).collect();
        if let Some(table) = tables.get_mut(&key) {
            table.primary_key = Some(PrimaryKey {
                name: Some("PRIMARY".to_string()),
                columns: pk_names,
            });
        }
    }
}

/// Fold MySQL FK rows. `ref_schema` for MySQL is the database name (foreign
/// keys can only reference same-database tables in MySQL). `ref_table` is
/// constant per constraint; we read it from the first row of each group.
pub fn assemble_mysql_fks(
    tables: &mut BTreeMap<String, TableSchema>,
    database_name: &str,
    rows: Vec<MySqlFkRow>,
) {
    // Buffer per (table, constraint) so we preserve ordinal_position ordering.
    let mut buf: BTreeMap<(String, String), Vec<MySqlFkRow>> = BTreeMap::new();
    for r in rows {
        let key = (r.table_name.clone(), r.constraint_name.clone());
        buf.entry(key).or_default().push(r);
    }

    for ((table_name, fk_name), mut group) in buf {
        group.sort_by_key(|r| r.ordinal_position);
        // ref_table is constant within a constraint; take it from the first row.
        let ref_table = group
            .first()
            .map(|r| r.ref_table.clone())
            .unwrap_or_default();
        let (columns, ref_columns): (Vec<String>, Vec<String>) = group
            .into_iter()
            .map(|r| (r.column_name, r.ref_column))
            .unzip();
        let key = format!("{database_name}.{table_name}");
        let table = tables.entry(key).or_insert_with(|| TableSchema {
            schema: database_name.to_string(),
            name: table_name.clone(),
            columns: BTreeMap::new(),
            primary_key: None,
            indexes: BTreeMap::new(),
            foreign_keys: BTreeMap::new(),
        });
        table.foreign_keys.insert(
            fk_name.clone(),
            ForeignKey {
                name: fk_name,
                columns,
                ref_schema: Some(database_name.to_string()),
                ref_table,
                ref_columns,
            },
        );
    }
}

/// Fold PG column rows. Each row carries its own `schema_name` so tables in
/// multiple namespaces don't collide.
pub fn assemble_pg_columns(rows: Vec<PgColumnRow>) -> BTreeMap<String, TableSchema> {
    let mut tables: BTreeMap<String, TableSchema> = BTreeMap::new();
    for r in rows {
        let key = format!("{}.{}", r.schema_name, r.table_name);
        let table = tables.entry(key.clone()).or_insert_with(|| TableSchema {
            schema: r.schema_name.clone(),
            name: r.table_name.clone(),
            columns: BTreeMap::new(),
            primary_key: None,
            indexes: BTreeMap::new(),
            foreign_keys: BTreeMap::new(),
        });
        table.columns.insert(
            r.column_name.clone(),
            ColumnSchema {
                name: r.column_name,
                ordinal: r.ordinal_position as i32,
                data_type: r.data_type,
                is_nullable: is_nullable_decode(&r.is_nullable),
                column_default: r.column_default,
                char_max_length: r.char_max_length,
                numeric_precision: r.numeric_precision,
                numeric_scale: r.numeric_scale,
            },
        );
    }
    tables
}

/// Fold PG index rows. `is_primary = true` populates `primary_key`; otherwise
/// the row is a secondary index.
pub fn assemble_pg_indexes(tables: &mut BTreeMap<String, TableSchema>, rows: Vec<PgIndexRow>) {
    for r in rows {
        let key = format!("{}.{}", r.schema_name, r.table_name);
        let table = tables.entry(key.clone()).or_insert_with(|| TableSchema {
            schema: r.schema_name.clone(),
            name: r.table_name.clone(),
            columns: BTreeMap::new(),
            primary_key: None,
            indexes: BTreeMap::new(),
            foreign_keys: BTreeMap::new(),
        });
        if r.is_primary {
            table.primary_key = Some(PrimaryKey {
                name: Some(r.index_name),
                columns: r.column_names,
            });
        } else {
            table.indexes.insert(
                r.index_name.clone(),
                IndexSchema {
                    name: r.index_name,
                    columns: r.column_names,
                    is_unique: r.is_unique,
                },
            );
        }
    }
}

/// Fold PG FK rows. PG arrays give us the column ordering directly.
pub fn assemble_pg_fks(tables: &mut BTreeMap<String, TableSchema>, rows: Vec<PgFkRow>) {
    for r in rows {
        let key = format!("{}.{}", r.schema_name, r.table_name);
        let table = tables.entry(key.clone()).or_insert_with(|| TableSchema {
            schema: r.schema_name.clone(),
            name: r.table_name.clone(),
            columns: BTreeMap::new(),
            primary_key: None,
            indexes: BTreeMap::new(),
            foreign_keys: BTreeMap::new(),
        });
        let ref_schema = if r.ref_schema.is_empty() {
            None
        } else {
            Some(r.ref_schema)
        };
        table.foreign_keys.insert(
            r.constraint_name.clone(),
            ForeignKey {
                name: r.constraint_name,
                columns: r.columns,
                ref_schema,
                ref_table: r.ref_table,
                ref_columns: r.ref_columns,
            },
        );
    }
}

/// Build a [`SchemaSnapshot`] from already-assembled tables.
pub fn build_snapshot(
    database: String,
    db_type: DbType,
    tables: BTreeMap<String, TableSchema>,
) -> SchemaSnapshot {
    SchemaSnapshot {
        database,
        db_type,
        tables,
    }
}

// ── Live fetchers (used by Phase E runner; kept here to live with their SQL) ──

/// Introspect a MySQL database and assemble a snapshot. The caller supplies
/// an already-connected pool bound to the source DB.
///
/// DEFENSIVE-NOTE: each query string comes from a const in this file; no SQL
/// is built from user input. The `database` parameter is bound, not spliced.
pub async fn collect_mysql(
    pool: &sqlx::Pool<MySql>,
    database: &str,
) -> anyhow::Result<SchemaSnapshot> {
    let column_rows = sqlx::query_as::<_, MySqlColumnRow>(mysql_columns_sql())
        .bind(database)
        .fetch_all(pool)
        .await?;
    let index_rows = sqlx::query_as::<_, MySqlIndexRow>(mysql_indexes_sql())
        .bind(database)
        .fetch_all(pool)
        .await?;
    let fk_rows = sqlx::query_as::<_, MySqlFkRow>(mysql_foreign_keys_sql())
        .bind(database)
        .fetch_all(pool)
        .await?;

    let mut tables = assemble_mysql_columns(database, column_rows);
    assemble_mysql_indexes(&mut tables, database, index_rows);
    assemble_mysql_fks(&mut tables, database, fk_rows);

    Ok(build_snapshot(database.to_string(), DbType::MySql, tables))
}

/// Introspect a PostgreSQL database. `schemas` filters which namespaces are
/// captured (typically `["public"]`; the runner decides).
pub async fn collect_postgres(
    pool: &sqlx::Pool<Postgres>,
    database: &str,
    schemas: &[String],
) -> anyhow::Result<SchemaSnapshot> {
    let schemas_arr = schemas.to_vec();
    let column_rows = sqlx::query_as::<_, PgColumnRow>(pg_columns_sql())
        .bind(&schemas_arr)
        .fetch_all(pool)
        .await?;
    let index_rows = sqlx::query_as::<_, PgIndexRow>(pg_indexes_sql())
        .bind(&schemas_arr)
        .fetch_all(pool)
        .await?;
    let fk_rows = sqlx::query_as::<_, PgFkRow>(pg_foreign_keys_sql())
        .bind(&schemas_arr)
        .fetch_all(pool)
        .await?;

    let mut tables = assemble_pg_columns(column_rows);
    assemble_pg_indexes(&mut tables, index_rows);
    assemble_pg_fks(&mut tables, fk_rows);

    Ok(build_snapshot(database.to_string(), DbType::Postgres, tables))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mysql_col(table: &str, col: &str, ord: i64, dtype: &str, nullable: &str) -> MySqlColumnRow {
        MySqlColumnRow {
            table_name: table.into(),
            column_name: col.into(),
            ordinal_position: ord,
            data_type: dtype.into(),
            is_nullable: nullable.into(),
            column_default: None,
            char_max_length: None,
            numeric_precision: None,
            numeric_scale: None,
        }
    }

    fn mysql_idx(table: &str, idx: &str, col: &str, seq: i64, non_unique: i64) -> MySqlIndexRow {
        MySqlIndexRow {
            table_name: table.into(),
            index_name: idx.into(),
            column_name: col.into(),
            seq_in_index: seq,
            non_unique,
        }
    }

    fn mysql_fk(
        table: &str,
        name: &str,
        col: &str,
        ord: i64,
        ref_table: &str,
        ref_col: &str,
    ) -> MySqlFkRow {
        MySqlFkRow {
            table_name: table.into(),
            constraint_name: name.into(),
            column_name: col.into(),
            ordinal_position: ord,
            ref_table: ref_table.into(),
            ref_column: ref_col.into(),
        }
    }

    // ── MySQL assembler ──

    #[test]
    fn mysql_assembles_columns_grouped_by_table() {
        let rows = vec![
            mysql_col("users", "id", 1, "bigint", "NO"),
            mysql_col("users", "email", 2, "varchar", "NO"),
            mysql_col("orders", "id", 1, "bigint", "NO"),
        ];
        let tables = assemble_mysql_columns("shop", rows);
        assert_eq!(tables.len(), 2);
        let users = tables.get("shop.users").unwrap();
        assert_eq!(users.columns.len(), 2);
        // Column equality for is_nullable flag.
        let id = users.columns.get("id").unwrap();
        assert!(!id.is_nullable);
        assert_eq!(id.ordinal, 1);
        // Hash stability across re-runs (canonical form is deterministic).
        let snap = build_snapshot("shop".into(), DbType::MySql, tables.clone());
        let h1 = snap.canonical_hash().unwrap();
        let h2 = build_snapshot("shop".into(), DbType::MySql, tables).canonical_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn mysql_is_nullable_yes_decodes_to_true() {
        assert!(!is_nullable_decode("NO"));
        assert!(is_nullable_decode("YES"));
        assert!(is_nullable_decode("garbage")); // fail-open
    }

    #[test]
    fn mysql_assembles_pk_and_secondary_indexes_in_order() {
        let col_rows = vec![
            mysql_col("t", "a", 1, "int", "NO"),
            mysql_col("t", "b", 2, "int", "NO"),
            mysql_col("t", "c", 3, "int", "NO"),
        ];
        let mut tables = assemble_mysql_columns("db", col_rows);

        // Composite PK on (b, a) — order matters.
        let idx_rows = vec![
            mysql_idx("t", "PRIMARY", "b", 1, 0),
            mysql_idx("t", "PRIMARY", "a", 2, 0),
            // Secondary unique index on c.
            mysql_idx("t", "uniq_c", "c", 1, 0),
            // Secondary non-unique composite on (a, c).
            mysql_idx("t", "multi", "a", 1, 1),
            mysql_idx("t", "multi", "c", 2, 1),
        ];
        assemble_mysql_indexes(&mut tables, "db", idx_rows);

        let t = tables.get("db.t").unwrap();
        let pk = t.primary_key.as_ref().expect("PK should be set");
        assert_eq!(pk.columns, vec!["b".to_string(), "a".to_string()]);
        assert_eq!(pk.name.as_deref(), Some("PRIMARY"));

        let uniq_c = t.indexes.get("uniq_c").unwrap();
        assert!(uniq_c.is_unique);
        assert_eq!(uniq_c.columns, vec!["c".to_string()]);

        let multi = t.indexes.get("multi").unwrap();
        assert!(!multi.is_unique);
        // ORDER BY in SQL preserves seq_in_index; we appended in row order.
        assert_eq!(multi.columns, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn mysql_assembles_composite_fk_in_order() {
        let mut tables = assemble_mysql_columns(
            "db",
            vec![mysql_col("child", "x", 1, "int", "NO"), mysql_col("child", "y", 2, "int", "NO")],
        );
        let fk_rows = vec![
            mysql_fk("child", "fk_xy", "x", 1, "parent", "px"),
            mysql_fk("child", "fk_xy", "y", 2, "parent", "py"),
        ];
        assemble_mysql_fks(&mut tables, "db", fk_rows);
        let child = tables.get("db.child").unwrap();
        let fk = child.foreign_keys.get("fk_xy").unwrap();
        assert_eq!(fk.columns, vec!["x".to_string(), "y".to_string()]);
        assert_eq!(fk.ref_columns, vec!["px".to_string(), "py".to_string()]);
        assert_eq!(fk.ref_table, "parent");
        assert_eq!(fk.ref_schema.as_deref(), Some("db"));
    }

    // ── PG assembler ──

    fn pg_col(schema: &str, table: &str, col: &str, ord: i64, dtype: &str, nullable: &str) -> PgColumnRow {
        PgColumnRow {
            table_name: table.into(),
            schema_name: schema.into(),
            column_name: col.into(),
            ordinal_position: ord,
            data_type: dtype.into(),
            is_nullable: nullable.into(),
            column_default: None,
            char_max_length: None,
            numeric_precision: None,
            numeric_scale: None,
        }
    }

    #[test]
    fn pg_assembles_columns_across_schemas() {
        let rows = vec![
            pg_col("public", "users", "id", 1, "bigint", "NO"),
            pg_col("public", "users", "email", 2, "character varying", "NO"),
            pg_col("audit", "events", "id", 1, "bigint", "NO"),
        ];
        let tables = assemble_pg_columns(rows);
        assert!(tables.contains_key("public.users"));
        assert!(tables.contains_key("audit.events"));
        let users = tables.get("public.users").unwrap();
        assert_eq!(users.schema, "public");
        assert_eq!(users.name, "users");
        assert_eq!(users.columns.len(), 2);
    }

    #[test]
    fn pg_assembles_pk_and_secondary() {
        let mut tables = assemble_pg_columns(vec![pg_col("public", "t", "id", 1, "int", "NO")]);
        assemble_pg_indexes(
            &mut tables,
            vec![PgIndexRow {
                table_name: "t".into(),
                index_name: "t_pkey".into(),
                schema_name: "public".into(),
                is_unique: true,
                is_primary: true,
                column_names: vec!["id".into()],
            }],
        );
        let t = tables.get("public.t").unwrap();
        assert!(t.primary_key.is_some());
        assert!(t.indexes.is_empty());
        let pk = t.primary_key.as_ref().unwrap();
        assert_eq!(pk.columns, vec!["id".to_string()]);

        // Now a secondary unique index.
        assemble_pg_indexes(
            &mut tables,
            vec![PgIndexRow {
                table_name: "t".into(),
                index_name: "t_id_idx".into(),
                schema_name: "public".into(),
                is_unique: false,
                is_primary: false,
                column_names: vec!["id".into()],
            }],
        );
        let t = tables.get("public.t").unwrap();
        let idx = t.indexes.get("t_id_idx").unwrap();
        assert!(!idx.is_unique);
    }

    #[test]
    fn pg_assembles_fk_with_ref_schema() {
        let mut tables = assemble_pg_columns(vec![pg_col("public", "orders", "user_id", 1, "int", "NO")]);
        assemble_pg_fks(
            &mut tables,
            vec![PgFkRow {
                table_name: "orders".into(),
                schema_name: "public".into(),
                constraint_name: "orders_user_id_fkey".into(),
                ref_table: "users".into(),
                ref_schema: "public".into(),
                columns: vec!["user_id".into()],
                ref_columns: vec!["id".into()],
            }],
        );
        let orders = tables.get("public.orders").unwrap();
        let fk = orders.foreign_keys.get("orders_user_id_fkey").unwrap();
        assert_eq!(fk.ref_schema.as_deref(), Some("public"));
        assert_eq!(fk.ref_table, "users");
    }

    #[test]
    fn sql_strings_are_parameterized_no_format_concat() {
        // v1-C-8 grep guard: every query must bind parameters, never splice.
        // The presence of `?` / `$1` placeholders asserts this structurally.
        assert!(mysql_columns_sql().contains("= ?"));
        assert!(mysql_indexes_sql().contains("= ?"));
        assert!(mysql_foreign_keys_sql().contains("= ?"));
        assert!(pg_columns_sql().contains("$1"));
        assert!(pg_indexes_sql().contains("$1"));
        assert!(pg_foreign_keys_sql().contains("$1"));
    }
}
