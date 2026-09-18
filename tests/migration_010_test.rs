//! Smoke test: migration 010 creates health_check tables (ADR-0004 §2.4 M1 DoD).
//!
//! Verifies the two new tables + their columns + the results index exist after
//! `run_migrations`. Cascade-delete behavior is exercised by the M4 runner
//! integration tests (which seed a real `scheduled_tasks` + `database_connections`
//! row first); this M1 test stays schema-only.

use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn migration_010_creates_health_check_tables() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();

    // health_check_results exists with the metrics_summary + alert_changes columns.
    let col_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('health_check_results') \
         WHERE name IN ('metrics_summary', 'alert_changes', 'status', 'triggered_by')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        col_count, 4,
        "health_check_results missing expected columns (got {col_count} of 4)"
    );

    // health_alert_state exists with composite PK (task_id, metric) + fail_count.
    let pk_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('health_alert_state') WHERE pk > 0",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        pk_count, 2,
        "health_alert_state should have composite PK (task_id, metric)"
    );
    let fail_count_col: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('health_alert_state') \
         WHERE name = 'fail_count' AND dflt_value IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        fail_count_col, 1,
        "health_alert_state.fail_count should have a DEFAULT"
    );

    // Results index exists.
    let idx: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='index' \
         AND name='idx_health_results_task_time'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(idx, 1, "idx_health_results_task_time index missing");
}
