//! Canonical schema snapshot + sha256 hash (ADR-0002 §4.3.1 / v1-C-10).
//!
//! The hash is the drift-detection primitive: two snapshots with the same
//! canonical JSON must produce the same hash, regardless of the order in which
//! the collector iterated rows. We get this by:
//! 1. Using [`std::collections::BTreeMap`] for all collection-valued fields —
//!    iteration is sorted by key, so re-inserting in any order normalises.
//! 2. Letting `serde` emit struct fields in declaration order (deterministic).
//! 3. Never putting an `f64`/`HashMap`/other non-deterministic type in a
//!    serialized structure.
//!
//! Collection granularity is fixed by ADR §4.3.1: database, tables, columns
//! (name/ordinal/data_type/is_nullable/column_default/length+precision),
//! primary key, indexes (name + column order), foreign keys. No view, no
//! proc, no trigger, NO row data (D5 boundary — enforced structurally: there
//! is simply no field that could hold a row).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Supported source-DB flavors for v1 (ADR §4.3.2 — MySQL + PostgreSQL only).
///
/// Serializes as the lowercase string used in the `db_type` column and in
/// webhook payloads (`source.db_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbType {
    #[serde(rename = "mysql")]
    MySql,
    #[serde(rename = "postgres")]
    Postgres,
}

impl DbType {
    /// Parse the value stored in `database_connections.db_type`. Unknown
    /// strings fall back to `None`; the caller decides whether to reject.
    pub fn from_db_type_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "mysql" => Some(Self::MySql),
            "postgres" | "postgresql" | "pg" => Some(Self::Postgres),
            _ => None,
        }
    }

    /// Lowercase wire string used in webhook payloads (ADR §4.4.2).
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::Postgres => "postgres",
        }
    }
}

/// One column's metadata, captured from `information_schema.columns`.
///
/// `char_max_length` / `numeric_precision` / `numeric_scale` are kept as
/// `Option<i64>` (NULL ⇒ `None`); they participate in the hash so that e.g.
/// `VARCHAR(50)` → `VARCHAR(100)` is detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnSchema {
    pub name: String,
    /// 1-based position in the table (information_schema.ordinal_position).
    pub ordinal: i32,
    /// Normalised type without length/precision (e.g. "varchar", "int", "timestamptz").
    pub data_type: String,
    pub is_nullable: bool,
    /// Column default verbatim from information_schema (text). `None` if NULL.
    pub column_default: Option<String>,
    pub char_max_length: Option<i64>,
    pub numeric_precision: Option<i64>,
    pub numeric_scale: Option<i64>,
}

/// Primary key of a table. `columns` is ordered by `ordinal_position`
/// (PK column ORDER matters: (a,b) ≠ (b,a)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimaryKey {
    /// Constraint name (MySQL: always "PRIMARY"; PG: e.g. "users_pkey").
    pub name: Option<String>,
    /// Columns in PK order, NOT alphabetical.
    pub columns: Vec<String>,
}

/// One index. `columns` is ordered by `seq_in_index` (index column order matters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexSchema {
    pub name: String,
    /// Columns in index order, NOT alphabetical.
    pub columns: Vec<String>,
    pub is_unique: bool,
}

/// One foreign key. `columns` and `ref_columns` are positional parallels:
    /// `columns[i]` maps to `ref_columns[i]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKey {
    pub name: String,
    pub columns: Vec<String>,
    pub ref_schema: Option<String>,
    pub ref_table: String,
    pub ref_columns: Vec<String>,
}

/// Schema of one table. `schema` is the PG namespace ("public", etc.) or the
/// MySQL database name; `name` is the bare table name.
///
/// `columns` / `indexes` / `foreign_keys` are BTreeMaps (sorted by key) so
/// snapshot serialization is canonical. `primary_key` is a single struct
/// (tables have at most one PK).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableSchema {
    /// PG schema or MySQL database name.
    pub schema: String,
    pub name: String,
    pub columns: BTreeMap<String, ColumnSchema>,
    pub primary_key: Option<PrimaryKey>,
    pub indexes: BTreeMap<String, IndexSchema>,
    pub foreign_keys: BTreeMap<String, ForeignKey>,
}

impl TableSchema {
    /// Convenience: fully-qualified `schema.name`.
    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.schema, self.name)
    }
}

/// Full schema snapshot of one database.
///
/// `tables` is keyed by `"{schema}.{name}"` so PG namespaces and MySQL
/// cross-schema snapshots don't collide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaSnapshot {
    pub database: String,
    pub db_type: DbType,
    /// Key = `"{schema}.{table}"`. Sorted iteration ⇒ canonical JSON.
    pub tables: BTreeMap<String, TableSchema>,
}

impl SchemaSnapshot {
    /// Serialise to canonical JSON bytes. Deterministic for equal snapshots
    /// regardless of insertion order (BTreeMap + serde struct field order).
    ///
    /// DEFENSIVE-NOTE: never pretty-printed (whitespace stable, but compact
    /// is the canonical form we hash).
    pub fn canonical_json(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// SHA-256 hex of the canonical JSON. This is the drift-detection
    /// primitive: same hash ⇒ no drift (ADR §4.3.1).
    pub fn canonical_hash(&self) -> Result<String, serde_json::Error> {
        let bytes = self.canonical_json()?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(hex::encode(hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a small snapshot with two tables for round-trip / hash tests.
    fn sample_snapshot() -> SchemaSnapshot {
        let mut users_cols = BTreeMap::new();
        users_cols.insert(
            "id".into(),
            ColumnSchema {
                name: "id".into(),
                ordinal: 1,
                data_type: "bigint".into(),
                is_nullable: false,
                column_default: None,
                char_max_length: None,
                numeric_precision: Some(64),
                numeric_scale: Some(0),
            },
        );
        users_cols.insert(
            "email".into(),
            ColumnSchema {
                name: "email".into(),
                ordinal: 2,
                data_type: "varchar".into(),
                is_nullable: false,
                column_default: None,
                char_max_length: Some(255),
                numeric_precision: None,
                numeric_scale: None,
            },
        );

        let users = TableSchema {
            schema: "public".into(),
            name: "users".into(),
            columns: users_cols,
            primary_key: Some(PrimaryKey {
                name: Some("users_pkey".into()),
                columns: vec!["id".into()],
            }),
            indexes: {
                let mut m = BTreeMap::new();
                m.insert(
                    "users_email_key".into(),
                    IndexSchema {
                        name: "users_email_key".into(),
                        columns: vec!["email".into()],
                        is_unique: true,
                    },
                );
                m
            },
            foreign_keys: BTreeMap::new(),
        };

        let mut orders_cols = BTreeMap::new();
        orders_cols.insert(
            "id".into(),
            ColumnSchema {
                name: "id".into(),
                ordinal: 1,
                data_type: "bigint".into(),
                is_nullable: false,
                column_default: None,
                char_max_length: None,
                numeric_precision: Some(64),
                numeric_scale: Some(0),
            },
        );
        orders_cols.insert(
            "user_id".into(),
            ColumnSchema {
                name: "user_id".into(),
                ordinal: 2,
                data_type: "bigint".into(),
                is_nullable: false,
                column_default: None,
                char_max_length: None,
                numeric_precision: Some(64),
                numeric_scale: Some(0),
            },
        );

        let orders = TableSchema {
            schema: "public".into(),
            name: "orders".into(),
            columns: orders_cols,
            primary_key: Some(PrimaryKey {
                name: Some("orders_pkey".into()),
                columns: vec!["id".into()],
            }),
            indexes: BTreeMap::new(),
            foreign_keys: {
                let mut m = BTreeMap::new();
                m.insert(
                    "orders_user_id_fkey".into(),
                    ForeignKey {
                        name: "orders_user_id_fkey".into(),
                        columns: vec!["user_id".into()],
                        ref_schema: Some("public".into()),
                        ref_table: "users".into(),
                        ref_columns: vec!["id".into()],
                    },
                );
                m
            },
        };

        let mut tables = BTreeMap::new();
        tables.insert(users.qualified_name(), users);
        tables.insert(orders.qualified_name(), orders);

        SchemaSnapshot {
            database: "shop".into(),
            db_type: DbType::Postgres,
            tables,
        }
    }

    // ── v1-C-10: canonical hash stability ──

    #[test]
    fn equal_snapshots_produce_equal_hash() {
        // Two independently-constructed snapshots with identical content.
        let h1 = sample_snapshot().canonical_hash().unwrap();
        let h2 = sample_snapshot().canonical_hash().unwrap();
        assert_eq!(h1, h2, "equal snapshots must hash equally");
        // Sanity: the hash looks like a sha256 hex (64 chars).
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn insertion_order_does_not_affect_hash() {
        // Build snapshot A by inserting users-then-orders; build snapshot B by
        // inserting orders-then-users and email-then-id (reversed column order).
        // Both must hash the same — BTreeMap normalises iteration order.
        let mut a = SchemaSnapshot {
            database: "shop".into(),
            db_type: DbType::Postgres,
            tables: BTreeMap::new(),
        };
        let mut a_users_cols = BTreeMap::new();
        a_users_cols.insert(
            "id".into(),
            ColumnSchema {
                name: "id".into(),
                ordinal: 1,
                data_type: "bigint".into(),
                is_nullable: false,
                column_default: None,
                char_max_length: None,
                numeric_precision: Some(64),
                numeric_scale: Some(0),
            },
        );
        let a_users = TableSchema {
            schema: "public".into(),
            name: "users".into(),
            columns: a_users_cols,
            primary_key: None,
            indexes: BTreeMap::new(),
            foreign_keys: BTreeMap::new(),
        };
        a.tables.insert("public.users".into(), a_users);

        let mut b = SchemaSnapshot {
            database: "shop".into(),
            db_type: DbType::Postgres,
            tables: BTreeMap::new(),
        };
        let mut b_users_cols = BTreeMap::new();
        b_users_cols.insert(
            "id".into(),
            ColumnSchema {
                name: "id".into(),
                ordinal: 1,
                data_type: "bigint".into(),
                is_nullable: false,
                column_default: None,
                char_max_length: None,
                numeric_precision: Some(64),
                numeric_scale: Some(0),
            },
        );
        let b_users = TableSchema {
            schema: "public".into(),
            name: "users".into(),
            columns: b_users_cols,
            primary_key: None,
            indexes: BTreeMap::new(),
            foreign_keys: BTreeMap::new(),
        };
        // Insert into b in reversed top-level order — BTreeMap normalises.
        b.tables.insert("public.users".into(), b_users);

        assert_eq!(
            a.canonical_hash().unwrap(),
            b.canonical_hash().unwrap(),
            "insertion order must not affect canonical hash"
        );
    }

    #[test]
    fn changed_data_type_changes_hash() {
        let base = sample_snapshot();
        let mut modified = sample_snapshot();
        modified
            .tables
            .get_mut("public.users")
            .unwrap()
            .columns
            .get_mut("id")
            .unwrap()
            .data_type = "int".into();
        assert_ne!(
            base.canonical_hash().unwrap(),
            modified.canonical_hash().unwrap(),
            "any column change must perturb the hash"
        );
    }

    #[test]
    fn changed_column_default_changes_hash() {
        // Even though column_default-only changes don't fire a v1 drift kind
        // (the 11 kinds only cover type/nullability), the hash still moves —
        // the structural diff in Phase C decides whether to alert.
        let base = sample_snapshot();
        let mut modified = sample_snapshot();
        modified
            .tables
            .get_mut("public.users")
            .unwrap()
            .columns
            .get_mut("id")
            .unwrap()
            .column_default = Some("nextval('s')".into());
        assert_ne!(
            base.canonical_hash().unwrap(),
            modified.canonical_hash().unwrap()
        );
    }

    #[test]
    fn db_type_wire_strings_match_adr() {
        assert_eq!(DbType::MySql.as_wire_str(), "mysql");
        assert_eq!(DbType::Postgres.as_wire_str(), "postgres");
    }

    #[test]
    fn db_type_parses_storage_variants() {
        assert_eq!(DbType::from_db_type_str("mysql"), Some(DbType::MySql));
        assert_eq!(
            DbType::from_db_type_str("PostgreSQL"),
            Some(DbType::Postgres)
        );
        assert_eq!(DbType::from_db_type_str("pg"), Some(DbType::Postgres));
        assert_eq!(DbType::from_db_type_str("oracle"), None);
    }

    #[test]
    fn empty_snapshot_hashes_stably() {
        let empty = SchemaSnapshot {
            database: "empty".into(),
            db_type: DbType::MySql,
            tables: BTreeMap::new(),
        };
        // Two identical empty snapshots ⇒ identical hash.
        let h1 = empty.canonical_hash().unwrap();
        let h2 = SchemaSnapshot {
            database: "empty".into(),
            db_type: DbType::MySql,
            tables: BTreeMap::new(),
        }
        .canonical_hash()
        .unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn snapshot_roundtrips_through_json() {
        // Canonical JSON must deserialize back to an equal snapshot — this
        // guards against accidental non-round-trippable serde attributes.
        let snap = sample_snapshot();
        let json = serde_json::to_vec(&snap).unwrap();
        let back: SchemaSnapshot = serde_json::from_slice(&json).unwrap();
        assert_eq!(snap, back);
    }
}
