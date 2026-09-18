//! 11-kind structural drift detection (ADR-0002 §4.3.1 / §4.4.2 / v1-C-11).
//!
//! Algorithm (ADR §4.3.1):
//! 1. Runner compares the prior snapshot's `schema_hash` to the new one.
//! 2. If equal → no drift (returns `[]`).
//! 3. If different → this module's [`compute_drifts`] walks the two snapshot
//!    trees and emits one [`Drift`] per change, classified into exactly the
//!    11 kinds enumerated in ADR §4.4.2. The kinds enumeration is locked at
//!    v1; new kinds are v2 (only-add-not-delete, ADR §11 Q5).
//!
//! Field-change semantics (a deliberate v1 interpretation; DEFENSIVE-NOTE):
//! - `column_type_changed` fires when `data_type`, `char_max_length`,
//!   `numeric_precision`, OR `numeric_scale` differ (these are the type's
//!   "shape" attributes).
//! - `column_nullability_changed` fires when `is_nullable` differs.
//! - A `column_default`-only change perturbs the hash (snapshot captures it
//!   for desktop diff display, ADR §4.3.1) but fires NO drift kind in v1 —
//!   the 11-kind enumeration has no `column_default_changed`. A future v2
//!   kind can cover it (ADR §11 Q5). Net effect: such a snapshot pair gets
//!   written (hash chain advances) but the webhook does not fire, because
//!   `change_count == 0` (ADR §4.4.2 trigger condition).

use serde::{Deserialize, Serialize};

use crate::snapshot::{ColumnSchema, ForeignKey, IndexSchema, PrimaryKey, SchemaSnapshot, TableSchema};

/// The 11 drift kinds locked at v1 (ADR §4.4.2 `kinds` enumeration).
///
/// Serialization is `snake_case` to match the webhook payload's string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    TableAdded,
    TableDropped,
    ColumnAdded,
    ColumnDropped,
    ColumnTypeChanged,
    ColumnNullabilityChanged,
    IndexAdded,
    IndexDropped,
    PkChanged,
    FkAdded,
    FkDropped,
}

impl DriftKind {
    /// Stable wire string. Equivalent to `serde_json::to_string` but without
    /// the surrounding quotes — used in audit logs (never the payload itself,
    /// which goes through serde).
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            Self::TableAdded => "table_added",
            Self::TableDropped => "table_dropped",
            Self::ColumnAdded => "column_added",
            Self::ColumnDropped => "column_dropped",
            Self::ColumnTypeChanged => "column_type_changed",
            Self::ColumnNullabilityChanged => "column_nullability_changed",
            Self::IndexAdded => "index_added",
            Self::IndexDropped => "index_dropped",
            Self::PkChanged => "pk_changed",
            Self::FkAdded => "fk_added",
            Self::FkDropped => "fk_dropped",
        }
    }
}

/// Object locator for a single drift. All fields optional — populated as the
/// kind's granularity allows (e.g., `column` is `None` for table-level drifts).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
}

/// One drift entry. `before` / `after` are JSON values per ADR §4.4.2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Drift {
    pub kind: DriftKind,
    pub object: DriftObject,
    /// `null` for additions (no prior state).
    pub before: serde_json::Value,
    /// `null` for removals.
    pub after: serde_json::Value,
}

/// Counts per drift kind. Serialised as the `drift_summary.kinds` object in
/// the webhook payload (ADR §4.4.2). All 11 fields always present (locked v1
/// enumeration).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftKindCounts {
    pub table_added: u32,
    pub table_dropped: u32,
    pub column_added: u32,
    pub column_dropped: u32,
    pub column_type_changed: u32,
    pub column_nullability_changed: u32,
    pub index_added: u32,
    pub index_dropped: u32,
    pub pk_changed: u32,
    pub fk_added: u32,
    pub fk_dropped: u32,
}

impl DriftKindCounts {
    /// Total drift count (sum across all kinds).
    pub fn total(&self) -> u32 {
        self.table_added
            + self.table_dropped
            + self.column_added
            + self.column_dropped
            + self.column_type_changed
            + self.column_nullability_changed
            + self.index_added
            + self.index_dropped
            + self.pk_changed
            + self.fk_added
            + self.fk_dropped
    }
}

/// Tally drifts into the per-kind counts structure.
pub fn summarize(drifts: &[Drift]) -> DriftKindCounts {
    let mut c = DriftKindCounts::default();
    for d in drifts {
        match d.kind {
            DriftKind::TableAdded => c.table_added += 1,
            DriftKind::TableDropped => c.table_dropped += 1,
            DriftKind::ColumnAdded => c.column_added += 1,
            DriftKind::ColumnDropped => c.column_dropped += 1,
            DriftKind::ColumnTypeChanged => c.column_type_changed += 1,
            DriftKind::ColumnNullabilityChanged => c.column_nullability_changed += 1,
            DriftKind::IndexAdded => c.index_added += 1,
            DriftKind::IndexDropped => c.index_dropped += 1,
            DriftKind::PkChanged => c.pk_changed += 1,
            DriftKind::FkAdded => c.fk_added += 1,
            DriftKind::FkDropped => c.fk_dropped += 1,
        }
    }
    c
}

// ── Helpers: compact JSON representations for before/after ──

fn column_type_summary(c: &ColumnSchema) -> serde_json::Value {
    serde_json::json!({
        "data_type": c.data_type,
        "char_max_length": c.char_max_length,
        "numeric_precision": c.numeric_precision,
        "numeric_scale": c.numeric_scale,
    })
}

fn column_full(c: &ColumnSchema) -> serde_json::Value {
    serde_json::json!({
        "data_type": c.data_type,
        "is_nullable": c.is_nullable,
        "column_default": c.column_default,
        "char_max_length": c.char_max_length,
        "numeric_precision": c.numeric_precision,
        "numeric_scale": c.numeric_scale,
    })
}

fn pk_summary(pk: &PrimaryKey) -> serde_json::Value {
    serde_json::json!({
        "name": pk.name,
        "columns": pk.columns,
    })
}

fn index_summary(ix: &IndexSchema) -> serde_json::Value {
    serde_json::json!({
        "columns": ix.columns,
        "is_unique": ix.is_unique,
    })
}

fn fk_summary(fk: &ForeignKey) -> serde_json::Value {
    serde_json::json!({
        "columns": fk.columns,
        "ref_schema": fk.ref_schema,
        "ref_table": fk.ref_table,
        "ref_columns": fk.ref_columns,
    })
}

fn table_summary(t: &TableSchema) -> serde_json::Value {
    serde_json::json!({
        "columns": t.columns.len(),
        "indexes": t.indexes.len(),
        "foreign_keys": t.foreign_keys.len(),
    })
}

/// Whether the type-shape attributes of two columns differ (triggers
/// `column_type_changed`). `column_default` is intentionally NOT compared
/// here — see module docs.
fn column_type_differs(a: &ColumnSchema, b: &ColumnSchema) -> bool {
    a.data_type != b.data_type
        || a.char_max_length != b.char_max_length
        || a.numeric_precision != b.numeric_precision
        || a.numeric_scale != b.numeric_scale
}

/// Compute the structural drift between two snapshots. Result is ordered
/// deterministically (tables → columns → pk → indexes → fks), each group
/// walking BTreeMap iteration order (alphabetical).
///
/// Pass the same snapshot as both args to get an empty result.
pub fn compute_drifts(prior: &SchemaSnapshot, current: &SchemaSnapshot) -> Vec<Drift> {
    let mut out = Vec::new();

    // ── table-level add/drop ──
    for (key, cur_table) in &current.tables {
        if !prior.tables.contains_key(key) {
            out.push(Drift {
                kind: DriftKind::TableAdded,
                object: DriftObject {
                    schema: Some(cur_table.schema.clone()),
                    table: Some(cur_table.name.clone()),
                    column: None,
                    index: None,
                },
                before: serde_json::Value::Null,
                after: table_summary(cur_table),
            });
        }
    }
    for (key, pri_table) in &prior.tables {
        if !current.tables.contains_key(key) {
            out.push(Drift {
                kind: DriftKind::TableDropped,
                object: DriftObject {
                    schema: Some(pri_table.schema.clone()),
                    table: Some(pri_table.name.clone()),
                    column: None,
                    index: None,
                },
                before: table_summary(pri_table),
                after: serde_json::Value::Null,
            });
        }
    }

    // ── per-table column / pk / index / fk diffs (only for common tables) ──
    for (key, pri_table) in &prior.tables {
        let Some(cur_table) = current.tables.get(key) else {
            continue;
        };
        diff_table_columns(pri_table, cur_table, &mut out);
        diff_table_pk(pri_table, cur_table, &mut out);
        diff_table_indexes(pri_table, cur_table, &mut out);
        diff_table_fks(pri_table, cur_table, &mut out);
    }

    out
}

fn diff_table_columns(prior: &TableSchema, current: &TableSchema, out: &mut Vec<Drift>) {
    // Added columns.
    for (name, col) in &current.columns {
        if !prior.columns.contains_key(name) {
            out.push(Drift {
                kind: DriftKind::ColumnAdded,
                object: object_for_column(current, name),
                before: serde_json::Value::Null,
                after: column_full(col),
            });
        }
    }
    // Dropped columns.
    for (name, col) in &prior.columns {
        if !current.columns.contains_key(name) {
            out.push(Drift {
                kind: DriftKind::ColumnDropped,
                object: object_for_column(prior, name),
                before: column_full(col),
                after: serde_json::Value::Null,
            });
        }
    }
    // Changed columns (common keys).
    for (name, pri) in &prior.columns {
        let Some(cur) = current.columns.get(name) else {
            continue;
        };
        if column_type_differs(pri, cur) {
            out.push(Drift {
                kind: DriftKind::ColumnTypeChanged,
                object: object_for_column(current, name),
                before: column_type_summary(pri),
                after: column_type_summary(cur),
            });
        }
        if pri.is_nullable != cur.is_nullable {
            out.push(Drift {
                kind: DriftKind::ColumnNullabilityChanged,
                object: object_for_column(current, name),
                before: serde_json::json!(pri.is_nullable),
                after: serde_json::json!(cur.is_nullable),
            });
        }
        // DEFENSIVE-NOTE: column_default / ordinal-only change is not a v1
        // drift kind. Hash moves, snapshot chain advances, but no webhook.
    }
}

fn diff_table_pk(prior: &TableSchema, current: &TableSchema, out: &mut Vec<Drift>) {
    if prior.primary_key != current.primary_key {
        out.push(Drift {
            kind: DriftKind::PkChanged,
            object: DriftObject {
                schema: Some(current.schema.clone()),
                table: Some(current.name.clone()),
                column: None,
                index: None,
            },
            before: prior
                .primary_key
                .as_ref()
                .map(pk_summary)
                .unwrap_or(serde_json::Value::Null),
            after: current
                .primary_key
                .as_ref()
                .map(pk_summary)
                .unwrap_or(serde_json::Value::Null),
        });
    }
}

fn diff_table_indexes(prior: &TableSchema, current: &TableSchema, out: &mut Vec<Drift>) {
    for (name, ix) in &current.indexes {
        if !prior.indexes.contains_key(name) {
            out.push(Drift {
                kind: DriftKind::IndexAdded,
                object: object_for_index(current, name),
                before: serde_json::Value::Null,
                after: index_summary(ix),
            });
        }
    }
    for (name, ix) in &prior.indexes {
        if !current.indexes.contains_key(name) {
            out.push(Drift {
                kind: DriftKind::IndexDropped,
                object: object_for_index(prior, name),
                before: index_summary(ix),
                after: serde_json::Value::Null,
            });
        }
    }
    // DEFENSIVE-NOTE: changes to an existing index (e.g., uniqueness or column
    // set change without rename) are surfaced as PkChanged if it's the PK and
    // otherwise not enumerated in v1. A renamed index surfaces as drop+add.
    // v2 may add `index_changed` per ADR §11 Q5.
}

fn diff_table_fks(prior: &TableSchema, current: &TableSchema, out: &mut Vec<Drift>) {
    for (name, fk) in &current.foreign_keys {
        if !prior.foreign_keys.contains_key(name) {
            out.push(Drift {
                kind: DriftKind::FkAdded,
                object: object_for_fk(current, name),
                before: serde_json::Value::Null,
                after: fk_summary(fk),
            });
        }
    }
    for (name, fk) in &prior.foreign_keys {
        if !current.foreign_keys.contains_key(name) {
            out.push(Drift {
                kind: DriftKind::FkDropped,
                object: object_for_fk(prior, name),
                before: fk_summary(fk),
                after: serde_json::Value::Null,
            });
        }
    }
    // DEFENSIVE-NOTE: FK definition change (e.g., columns re-mapped) without a
    // rename is not enumerated in v1; renamed FK surfaces as drop+add.
}

fn object_for_column(table: &TableSchema, col: &str) -> DriftObject {
    DriftObject {
        schema: Some(table.schema.clone()),
        table: Some(table.name.clone()),
        column: Some(col.to_string()),
        index: None,
    }
}

fn object_for_index(table: &TableSchema, idx: &str) -> DriftObject {
    DriftObject {
        schema: Some(table.schema.clone()),
        table: Some(table.name.clone()),
        column: None,
        index: Some(idx.to_string()),
    }
}

fn object_for_fk(table: &TableSchema, fk: &str) -> DriftObject {
    // FK object uses `index` slot to carry the constraint name (no separate
    // `foreign_key` field in ADR §4.4.2). DEFENSIVE-NOTE: documented choice.
    DriftObject {
        schema: Some(table.schema.clone()),
        table: Some(table.name.clone()),
        column: None,
        index: Some(fk.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::DbType;
    use std::collections::BTreeMap;

    /// Helper: one table, one column, no PK/index/fk.
    fn snapshot_with_table(db: &str, table: &TableSchema) -> SchemaSnapshot {
        let mut tables = BTreeMap::new();
        tables.insert(table.qualified_name(), table.clone());
        SchemaSnapshot {
            database: db.into(),
            db_type: DbType::Postgres,
            tables,
        }
    }

    fn col(name: &str, dtype: &str, nullable: bool) -> ColumnSchema {
        ColumnSchema {
            name: name.into(),
            ordinal: 1,
            data_type: dtype.into(),
            is_nullable: nullable,
            column_default: None,
            char_max_length: None,
            numeric_precision: None,
            numeric_scale: None,
        }
    }

    fn empty_table(schema: &str, name: &str) -> TableSchema {
        TableSchema {
            schema: schema.into(),
            name: name.into(),
            columns: BTreeMap::new(),
            primary_key: None,
            indexes: BTreeMap::new(),
            foreign_keys: BTreeMap::new(),
        }
    }

    // ── v1-C-11: all 11 drift kinds covered ──

    #[test]
    fn table_added() {
        let prior_t = empty_table("public", "old");
        let mut cur_t = empty_table("public", "old");
        cur_t.columns.insert("id".into(), col("id", "int", false));
        let new_t = empty_table("public", "new");
        let mut tables = BTreeMap::new();
        tables.insert(cur_t.qualified_name(), cur_t);
        tables.insert(new_t.qualified_name(), new_t.clone());
        let current = SchemaSnapshot {
            database: "db".into(),
            db_type: DbType::Postgres,
            tables,
        };
        let prior = snapshot_with_table("db", &prior_t);

        let drifts = compute_drifts(&prior, &current);
        let added: Vec<_> = drifts.iter().filter(|d| d.kind == DriftKind::TableAdded).collect();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].object.table.as_deref(), Some("new"));
        assert!(added[0].before.is_null());
        assert!(added[0].after.is_object());
    }

    #[test]
    fn table_dropped() {
        let prior_t = empty_table("public", "going_away");
        let cur_t = empty_table("public", "stays");
        let mut prior_tables = BTreeMap::new();
        prior_tables.insert(prior_t.qualified_name(), prior_t.clone());
        prior_tables.insert(cur_t.qualified_name(), cur_t);
        let prior = SchemaSnapshot {
            database: "db".into(),
            db_type: DbType::Postgres,
            tables: prior_tables,
        };
        let current = snapshot_with_table("db", &empty_table("public", "stays"));

        let drifts = compute_drifts(&prior, &current);
        let dropped: Vec<_> = drifts.iter().filter(|d| d.kind == DriftKind::TableDropped).collect();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].object.table.as_deref(), Some("going_away"));
        assert!(dropped[0].after.is_null());
        assert!(dropped[0].before.is_object());
    }

    #[test]
    fn column_added() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert("a".into(), col("a", "int", false));
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert("a".into(), col("a", "int", false));
        cur_t.columns.insert("b".into(), col("b", "int", false));
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);

        let drifts = compute_drifts(&prior, &current);
        let added: Vec<_> = drifts
            .iter()
            .filter(|d| d.kind == DriftKind::ColumnAdded)
            .collect();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].object.column.as_deref(), Some("b"));
    }

    #[test]
    fn column_dropped() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert("a".into(), col("a", "int", false));
        prior_t.columns.insert("b".into(), col("b", "int", false));
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert("a".into(), col("a", "int", false));
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);

        let drifts = compute_drifts(&prior, &current);
        let dropped: Vec<_> = drifts
            .iter()
            .filter(|d| d.kind == DriftKind::ColumnDropped)
            .collect();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].object.column.as_deref(), Some("b"));
    }

    #[test]
    fn column_type_changed() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert(
            "a".into(),
            ColumnSchema {
                name: "a".into(),
                ordinal: 1,
                data_type: "varchar".into(),
                is_nullable: false,
                column_default: None,
                char_max_length: Some(50),
                numeric_precision: None,
                numeric_scale: None,
            },
        );
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert(
            "a".into(),
            ColumnSchema {
                name: "a".into(),
                ordinal: 1,
                data_type: "varchar".into(),
                is_nullable: false,
                column_default: None,
                char_max_length: Some(100), // widened
                numeric_precision: None,
                numeric_scale: None,
            },
        );
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);

        let drifts = compute_drifts(&prior, &current);
        let kind: Vec<_> = drifts
            .iter()
            .filter(|d| d.kind == DriftKind::ColumnTypeChanged)
            .collect();
        assert_eq!(kind.len(), 1);
        assert_eq!(kind[0].before["char_max_length"], 50);
        assert_eq!(kind[0].after["char_max_length"], 100);
    }

    #[test]
    fn column_nullability_changed() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert("a".into(), col("a", "int", false));
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert("a".into(), col("a", "int", true)); // relaxed
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);

        let drifts = compute_drifts(&prior, &current);
        let kind: Vec<_> = drifts
            .iter()
            .filter(|d| d.kind == DriftKind::ColumnNullabilityChanged)
            .collect();
        assert_eq!(kind.len(), 1);
        assert_eq!(kind[0].before, false);
        assert_eq!(kind[0].after, true);
    }

    #[test]
    fn index_added() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert("a".into(), col("a", "int", false));
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert("a".into(), col("a", "int", false));
        cur_t.indexes.insert(
            "idx_a".into(),
            IndexSchema {
                name: "idx_a".into(),
                columns: vec!["a".into()],
                is_unique: false,
            },
        );
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);

        let drifts = compute_drifts(&prior, &current);
        let kind: Vec<_> = drifts
            .iter()
            .filter(|d| d.kind == DriftKind::IndexAdded)
            .collect();
        assert_eq!(kind.len(), 1);
        assert_eq!(kind[0].object.index.as_deref(), Some("idx_a"));
    }

    #[test]
    fn index_dropped() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert("a".into(), col("a", "int", false));
        prior_t.indexes.insert(
            "idx_a".into(),
            IndexSchema {
                name: "idx_a".into(),
                columns: vec!["a".into()],
                is_unique: false,
            },
        );
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert("a".into(), col("a", "int", false));
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);

        let drifts = compute_drifts(&prior, &current);
        let kind: Vec<_> = drifts
            .iter()
            .filter(|d| d.kind == DriftKind::IndexDropped)
            .collect();
        assert_eq!(kind.len(), 1);
        assert_eq!(kind[0].object.index.as_deref(), Some("idx_a"));
    }

    #[test]
    fn pk_changed() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert("a".into(), col("a", "int", false));
        prior_t.primary_key = Some(PrimaryKey {
            name: Some("t_pkey".into()),
            columns: vec!["a".into()],
        });
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert("a".into(), col("a", "int", false));
        cur_t.columns.insert("b".into(), col("b", "int", false));
        cur_t.primary_key = Some(PrimaryKey {
            name: Some("t_pkey".into()),
            columns: vec!["a".into(), "b".into()], // composite now
        });
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);

        let drifts = compute_drifts(&prior, &current);
        // PK change + column_b added — we focus on PkChanged here.
        let pk: Vec<_> = drifts.iter().filter(|d| d.kind == DriftKind::PkChanged).collect();
        assert_eq!(pk.len(), 1);
        assert_eq!(pk[0].before["columns"].as_array().unwrap().len(), 1);
        assert_eq!(pk[0].after["columns"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn fk_added() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert("user_id".into(), col("user_id", "int", false));
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert("user_id".into(), col("user_id", "int", false));
        cur_t.foreign_keys.insert(
            "fk_user".into(),
            ForeignKey {
                name: "fk_user".into(),
                columns: vec!["user_id".into()],
                ref_schema: Some("public".into()),
                ref_table: "users".into(),
                ref_columns: vec!["id".into()],
            },
        );
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);

        let drifts = compute_drifts(&prior, &current);
        let kind: Vec<_> = drifts.iter().filter(|d| d.kind == DriftKind::FkAdded).collect();
        assert_eq!(kind.len(), 1);
        // FK object reuses the `index` slot per documented choice.
        assert_eq!(kind[0].object.index.as_deref(), Some("fk_user"));
        assert_eq!(kind[0].after["ref_table"], "users");
    }

    #[test]
    fn fk_dropped() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert("user_id".into(), col("user_id", "int", false));
        prior_t.foreign_keys.insert(
            "fk_user".into(),
            ForeignKey {
                name: "fk_user".into(),
                columns: vec!["user_id".into()],
                ref_schema: Some("public".into()),
                ref_table: "users".into(),
                ref_columns: vec!["id".into()],
            },
        );
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert("user_id".into(), col("user_id", "int", false));
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);

        let drifts = compute_drifts(&prior, &current);
        let kind: Vec<_> = drifts.iter().filter(|d| d.kind == DriftKind::FkDropped).collect();
        assert_eq!(kind.len(), 1);
        assert_eq!(kind[0].object.index.as_deref(), Some("fk_user"));
        assert!(kind[0].after.is_null());
    }

    // ── Edge cases ──

    #[test]
    fn identical_snapshots_have_no_drifts() {
        let snap = snapshot_with_table("db", &empty_table("public", "t"));
        assert!(compute_drifts(&snap, &snap).is_empty());
    }

    #[test]
    fn column_default_only_change_emits_no_v1_drift_kind() {
        // DEFENSIVE-NOTE: v1 has no column_default_changed kind. Snapshot
        // chain advances (hash differs at runner level) but no drift fires.
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert(
            "a".into(),
            ColumnSchema {
                name: "a".into(),
                ordinal: 1,
                data_type: "int".into(),
                is_nullable: false,
                column_default: None,
                char_max_length: None,
                numeric_precision: None,
                numeric_scale: None,
            },
        );
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert(
            "a".into(),
            ColumnSchema {
                name: "a".into(),
                ordinal: 1,
                data_type: "int".into(),
                is_nullable: false,
                column_default: Some("0".into()), // changed
                char_max_length: None,
                numeric_precision: None,
                numeric_scale: None,
            },
        );
        let prior = snapshot_with_table("db", &prior_t);
        let current = snapshot_with_table("db", &cur_t);
        let drifts = compute_drifts(&prior, &current);
        assert_eq!(drifts, Vec::<Drift>::new(), "no v1 kind for default-only");
    }

    #[test]
    fn summarize_tallies_each_kind() {
        let mut prior_t = empty_table("public", "t");
        prior_t.columns.insert("a".into(), col("a", "int", false));
        prior_t.columns.insert("b".into(), col("b", "int", false));
        let mut cur_t = empty_table("public", "t");
        cur_t.columns.insert("a".into(), col("a", "int", true)); // nullability change
        cur_t.columns.insert("c".into(), col("c", "int", false)); // added

        let mut prior = snapshot_with_table("db", &prior_t);
        prior.tables.insert(
            "public.old".into(),
            empty_table("public", "old"),
        );
        let mut current = snapshot_with_table("db", &cur_t);
        current.tables.insert(
            "public.new".into(),
            empty_table("public", "new"),
        );

        let drifts = compute_drifts(&prior, &current);
        let counts = summarize(&drifts);
        assert_eq!(counts.table_added, 1);
        assert_eq!(counts.table_dropped, 1);
        assert_eq!(counts.column_added, 1);
        assert_eq!(counts.column_dropped, 1);
        assert_eq!(counts.column_nullability_changed, 1);
        assert_eq!(counts.total() as usize, drifts.len());
    }

    #[test]
    fn drift_kind_serializes_to_adr_wire_strings() {
        // Lock the JSON form so webhook consumers can rely on it (定律 2).
        let pairs: &[(DriftKind, &str)] = &[
            (DriftKind::TableAdded, "\"table_added\""),
            (DriftKind::TableDropped, "\"table_dropped\""),
            (DriftKind::ColumnAdded, "\"column_added\""),
            (DriftKind::ColumnDropped, "\"column_dropped\""),
            (DriftKind::ColumnTypeChanged, "\"column_type_changed\""),
            (
                DriftKind::ColumnNullabilityChanged,
                "\"column_nullability_changed\"",
            ),
            (DriftKind::IndexAdded, "\"index_added\""),
            (DriftKind::IndexDropped, "\"index_dropped\""),
            (DriftKind::PkChanged, "\"pk_changed\""),
            (DriftKind::FkAdded, "\"fk_added\""),
            (DriftKind::FkDropped, "\"fk_dropped\""),
        ];
        for (k, expected) in pairs {
            let s = serde_json::to_string(k).unwrap();
            assert_eq!(&s.as_str(), expected, "wire form mismatch for {:?}", k);
        }
    }

    #[test]
    fn webhook_payload_round_trips_drift() {
        // Drift must round-trip through JSON (it's part of the webhook payload).
        let d = Drift {
            kind: DriftKind::ColumnTypeChanged,
            object: DriftObject {
                schema: Some("public".into()),
                table: Some("t".into()),
                column: Some("a".into()),
                index: None,
            },
            before: serde_json::json!({"data_type": "int"}),
            after: serde_json::json!({"data_type": "bigint"}),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: Drift = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, DriftKind::ColumnTypeChanged);
        assert_eq!(back.object.column.as_deref(), Some("a"));
    }
}
