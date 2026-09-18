//! Real-DB e2e for the drift collector + canary (ADR-0002 §9 layer-4 / v1-C-12).
//!
//! Env-gated: bypassed (not failed) when the connection URLs are absent, so the
//! normal `cargo test` suite stays green without a DB. To actually exercise the
//! SQL against real MySQL/PG:
//!
//! ```sh
//! DRIFT_E2E_MYSQL80_URL='mysql://dbmaster:test@127.0.0.1:13306/drifttest' \
//! DRIFT_E2E_MYSQL57_URL='mysql://dbmaster:test@127.0.0.1:13307/drifttest' \
//! DRIFT_E2E_PG_URL='postgres://dbmaster:test@127.0.0.1:15432/drifttest' \
//! cargo test --package dbmaster-drift --test real_db_e2e -- --nocapture
//! ```
//!
//! What this closes (the Phase G risk surface the unit tests could NOT):
//! - MySQL 8.0 + 5.7: information_schema.columns / .statistics / .key_column_usage
//!   actually run + assemble into a correct snapshot (PK / secondary index / FK).
//!   Catches the 5.7↔8.0 column-default format difference if it broke the query.
//! - PostgreSQL 16: pg_catalog introspection (pg_index, pg_constraint with
//!   `LATERAL unnest ... WITH ORDINALITY`) runs + assembles.
//! - Canary: a privileged account is flagged `Writable` (write probe succeeds);
//!   the read-only→ReadOnly path is covered by the canary unit tests + a manual
//!   read-only account exercise documented in README.

use dbmaster_drift::canary::{check_mysql, check_postgres, CanaryOutcome};
use dbmaster_drift::collector::{collect_mysql, collect_postgres};
use dbmaster_drift::{DbType, SchemaSnapshot};

const MYSQL_DB: &str = "drifttest";

fn url(env: &str) -> String {
    std::env::var(env).unwrap_or_default()
}

/// Idempotent MySQL schema: parent + child with PK / unique index / FK.
async fn setup_mysql_schema(pool: &sqlx::MySqlPool) {
    sqlx::query("DROP TABLE IF EXISTS _drift_e2e_child")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE IF EXISTS _drift_e2e_parent")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE _drift_e2e_parent (id BIGINT PRIMARY KEY, name VARCHAR(50) NOT NULL)")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE _drift_e2e_child (
            id BIGINT PRIMARY KEY,
            parent_id BIGINT NOT NULL,
            email VARCHAR(100),
            UNIQUE KEY uniq_email (email),
            CONSTRAINT fk_e2e_parent FOREIGN KEY (parent_id) REFERENCES _drift_e2e_parent(id)
        )",
    )
    .execute(pool)
    .await
    .unwrap();
}

/// Assert the assembled MySQL snapshot has the expected structure.
fn assert_mysql_snapshot(snap: &SchemaSnapshot) {
    let child_key = format!("{}._drift_e2e_child", MYSQL_DB);
    let child = snap
        .tables
        .get(&child_key)
        .unwrap_or_else(|| panic!("missing {child_key}; tables={:?}", snap.tables.keys()));
    assert!(child.columns.contains_key("id"), "missing col id");
    assert!(child.columns.contains_key("parent_id"), "missing col parent_id");
    assert!(child.columns.contains_key("email"), "missing col email");
    let pk = child.primary_key.as_ref().expect("PK on child");
    assert_eq!(pk.columns, vec!["id".to_string()]);
    let idx = child.indexes.get("uniq_email").expect("uniq_email index");
    assert!(idx.is_unique, "uniq_email should be unique");
    assert_eq!(idx.columns, vec!["email".to_string()]);
    let fk = child.foreign_keys.get("fk_e2e_parent").expect("FK fk_e2e_parent");
    assert_eq!(fk.columns, vec!["parent_id".to_string()]);
    assert_eq!(fk.ref_table, "_drift_e2e_parent");
    let parent_key = format!("{}._drift_e2e_parent", MYSQL_DB);
    assert!(snap.tables.contains_key(&parent_key), "parent table present");
}

#[tokio::test]
async fn mysql80_collector_introspects_real_schema() {
    let u = url("DRIFT_E2E_MYSQL80_URL");
    if u.is_empty() {
        eprintln!("[skip] DRIFT_E2E_MYSQL80_URL unset");
        return;
    }
    let pool = sqlx::MySqlPool::connect(&u).await.expect("connect mysql80");
    setup_mysql_schema(&pool).await;
    let snap = collect_mysql(&pool, MYSQL_DB).await.expect("collect_mysql 8.0");
    assert_eq!(snap.db_type, DbType::MySql);
    assert_mysql_snapshot(&snap);
    eprintln!("[ok] mysql 8.0 collector — {} tables", snap.tables.len());
    // dbmaster env user is privileged → canary must flag Writable.
    assert_eq!(
        check_mysql(&pool).await,
        CanaryOutcome::Writable,
        "privileged mysql account should be Writable"
    );
    eprintln!("[ok] mysql 8.0 canary flagged privileged account");
}

#[tokio::test]
async fn mysql57_collector_introspects_real_schema() {
    let u = url("DRIFT_E2E_MYSQL57_URL");
    if u.is_empty() {
        eprintln!("[skip] DRIFT_E2E_MYSQL57_URL unset");
        return;
    }
    let pool = sqlx::MySqlPool::connect(&u).await.expect("connect mysql57");
    setup_mysql_schema(&pool).await;
    let snap = collect_mysql(&pool, MYSQL_DB).await.expect("collect_mysql 5.7");
    assert_mysql_snapshot(&snap);
    eprintln!("[ok] mysql 5.7 collector — {} tables", snap.tables.len());
}

#[tokio::test]
async fn pg16_collector_introspects_real_schema() {
    let u = url("DRIFT_E2E_PG_URL");
    if u.is_empty() {
        eprintln!("[skip] DRIFT_E2E_PG_URL unset");
        return;
    }
    let pool = sqlx::PgPool::connect(&u).await.expect("connect pg16");
    sqlx::query("DROP TABLE IF EXISTS _drift_e2e_child")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE IF EXISTS _drift_e2e_parent")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE _drift_e2e_parent (id BIGINT PRIMARY KEY, name VARCHAR(50) NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE _drift_e2e_child (
            id BIGINT PRIMARY KEY,
            parent_id BIGINT NOT NULL REFERENCES _drift_e2e_parent(id),
            email VARCHAR(100) UNIQUE
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    let snap = collect_postgres(&pool, "drifttest", &["public".into()])
        .await
        .expect("collect_postgres 16");
    assert_eq!(snap.db_type, DbType::Postgres);
    let child = snap
        .tables
        .get("public._drift_e2e_child")
        .expect("public._drift_e2e_child");
    assert!(child.columns.contains_key("id"));
    assert!(child.columns.contains_key("parent_id"));
    assert!(child.columns.contains_key("email"));
    assert!(child.primary_key.is_some(), "PK on child");
    // PG auto-names the FK; assert exactly one FK referencing the parent.
    assert_eq!(child.foreign_keys.len(), 1, "expected 1 FK; got {:?}", child.foreign_keys.keys());
    let fk = child.foreign_keys.values().next().unwrap();
    assert_eq!(fk.ref_table, "_drift_e2e_parent");
    // email UNIQUE → secondary index must appear.
    assert!(
        !child.indexes.is_empty(),
        "expected email unique index; indexes={:?}",
        child.indexes.keys()
    );
    eprintln!("[ok] pg 16 collector — {} tables", snap.tables.len());
    assert_eq!(
        check_postgres(&pool).await,
        CanaryOutcome::Writable,
        "privileged pg account should be Writable"
    );
    eprintln!("[ok] pg 16 canary flagged privileged account");
}
