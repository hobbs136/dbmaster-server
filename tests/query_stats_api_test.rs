//! Query stats 读端点集成测试（reports-M1 / #29，migration 016）。
//!
//! 覆盖：401 未认证、summary 聚合（digest 分组/排序/最新样本/meta）、
//! 过滤（window/conn_id/digest/status）、明细分页与 total。Gated 态读放行
//! 断言在 automation_gate_test.rs 的 `gated_allows_read_routes`。

mod common;

use axum::http::StatusCode;
use serde_json::json;

async fn register_and_get_token(app: &mut axum::Router, email: &str) -> String {
    let body: serde_json::Value = common::post(
        app,
        "/api/auth/register",
        json!({
            "email": email,
            "password": "secure12345",
            "display_name": "Test User"
        }),
    )
    .await
    .json_value()
    .await;
    body["access_token"].as_str().unwrap().to_string()
}

/// 直插一行采样（绕过捕获链——本文件只测读面）。
#[allow(clippy::too_many_arguments)]
async fn seed(
    pool: &sqlx::SqlitePool,
    id: &str,
    digest: &str,
    conn_id: &str,
    db_kind: &str,
    elapsed_ms: i64,
    captured_at: &str,
    sql_text: Option<&str>,
    status: &str,
) {
    sqlx::query(
        "INSERT INTO query_stats (id, source, conn_id, db_kind, database, digest, sql_text, \
         elapsed_ms, row_count, affected_rows, status, error_code, user_id, entry, captured_at) \
         VALUES (?1, 'gateway', ?2, ?3, 'chinook', ?4, ?5, ?6, 10, NULL, ?7, NULL, NULL, \
         'sync_query', ?8)",
    )
    .bind(id)
    .bind(conn_id)
    .bind(db_kind)
    .bind(digest)
    .bind(sql_text)
    .bind(elapsed_ms)
    .bind(status)
    .bind(captured_at)
    .execute(pool)
    .await
    .unwrap();
}

fn mins_ago(mins: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::minutes(mins)).to_rfc3339()
}

#[tokio::test]
async fn query_stats_routes_require_auth() {
    let mut app = common::build_test_app().await;
    for uri in ["/api/query-stats", "/api/query-stats/summary?window=1h"] {
        common::get(&mut app, uri)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn summary_aggregates_by_digest_with_latest_sample_and_meta() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "qs-sum@example.com").await;

    // digest "t"：两条（1200ms@2min前、800ms@1min前）→ total 2000 / avg 1000，
    // 最新样本 = 1min 前那条的明文。digest "u"：一条 3000ms。
    seed(&pool, "a1", "SELECT * FROM t WHERE id = ?", "c1", "mysql", 1200, &mins_ago(2), Some("SELECT * FROM t WHERE id = 1"), "ok").await;
    seed(&pool, "a2", "SELECT * FROM t WHERE id = ?", "c1", "mysql", 800, &mins_ago(1), Some("SELECT * FROM t WHERE id = 2"), "ok").await;
    seed(&pool, "a3", "SELECT * FROM u", "c1", "mysql", 3000, &mins_ago(1), None, "ok").await;

    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/query-stats/summary", &token)
        .await
        .json_value()
        .await;
    assert_eq!(body["ok"], json!(true), "body: {body}");

    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    // 默认排序 total_ms DESC → u(3000) 在 t(2000) 前。
    assert_eq!(items[0]["digest"], "SELECT * FROM u");
    assert_eq!(items[0]["total_ms"], json!(3000));
    assert_eq!(items[0]["count"], json!(1));
    assert_eq!(items[1]["digest"], "SELECT * FROM t WHERE id = ?");
    assert_eq!(items[1]["count"], json!(2));
    assert_eq!(items[1]["total_ms"], json!(2000));
    assert_eq!(items[1]["avg_ms"], json!(1000.0));
    // 最新明文样本 = 时间戳最新的那条（a2）。
    assert_eq!(items[1]["sample_sql_text"], json!("SELECT * FROM t WHERE id = 2"));
    // NULL 明文行（未存明文的 digest）样本为 null。
    assert_eq!(items[0]["sample_sql_text"], json!(null));

    // meta：默认配置的口径横幅数据。
    let meta = &body["data"]["meta"];
    assert_eq!(meta["threshold_ms"], json!(1000));
    assert_eq!(meta["store_sql"], json!(true));
    assert_eq!(meta["retention_days"], json!(14));
    assert!(meta["window_from"].as_str().is_some());
}

#[tokio::test]
async fn summary_sort_count_and_conn_filter() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "qs-sort@example.com").await;

    seed(&pool, "b1", "d_slow", "c1", "mysql", 5000, &mins_ago(1), None, "ok").await;
    seed(&pool, "b2", "d_fast", "c1", "mysql", 1100, &mins_ago(2), None, "ok").await;
    seed(&pool, "b3", "d_fast", "c1", "mysql", 1200, &mins_ago(3), None, "ok").await;
    seed(&pool, "b4", "d_other_conn", "c2", "postgresql", 9000, &mins_ago(1), None, "ok").await;

    // sort=count → d_fast(2) 在前。
    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/query-stats/summary?sort=count", &token)
        .await
        .json_value()
        .await;
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items[0]["digest"], "d_fast");
    assert_eq!(items[0]["count"], json!(2));

    // conn_id 过滤 → 只剩 c2 的组。
    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/query-stats/summary?conn_id=c2", &token)
        .await
        .json_value()
        .await;
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["conn_id"], "c2");
    assert_eq!(items[0]["db_kind"], "postgresql");
}

#[tokio::test]
async fn window_filter_excludes_old_rows() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "qs-win@example.com").await;

    seed(&pool, "c1", "d_recent", "c1", "mysql", 1500, &mins_ago(30), None, "ok").await;
    // 8 天前：7d 窗排除、默认 24h 也排除。
    seed(&pool, "c2", "d_old", "c1", "mysql", 2000, &mins_ago(8 * 24 * 60), None, "ok").await;

    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/query-stats/summary?window=7d", &token)
        .await
        .json_value()
        .await;
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["digest"], "d_recent");
}

#[tokio::test]
async fn detail_pagination_and_filters() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "qs-list@example.com").await;

    for (i, digest) in ["d1", "d1", "d2"].iter().enumerate() {
        seed(&pool, &format!("e{i}"), digest, "c1", "mysql", 1500 + i as i64, &mins_ago(i as i64 + 1), Some(&format!("SELECT {i}")), "ok").await;
    }
    seed(&pool, "e9", "d_err", "c1", "mysql", 9000, &mins_ago(1), Some("SELECT broken"), "error").await;

    // 分页。
    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/query-stats?limit=2&offset=0", &token)
        .await
        .json_value()
        .await;
    assert_eq!(body["ok"], json!(true), "body: {body}");
    assert_eq!(body["data"]["total"], json!(4));
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 2);
    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/query-stats?limit=2&offset=2", &token)
        .await
        .json_value()
        .await;
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 2);

    // digest 过滤。
    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/query-stats?digest=d2", &token)
        .await
        .json_value()
        .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["digest"], "d2");
    assert_eq!(body["data"]["items"][0]["sql_text"], json!("SELECT 2"));
    assert_eq!(body["data"]["items"][0]["database"], json!("chinook"));
    assert_eq!(body["data"]["items"][0]["entry"], json!("sync_query"));

    // status 过滤。
    let body: serde_json::Value = common::get_with_auth(&mut app, "/api/query-stats?status=error", &token)
        .await
        .json_value()
        .await;
    assert_eq!(body["data"]["total"], json!(1));
    assert_eq!(body["data"]["items"][0]["status"], json!("error"));
}
