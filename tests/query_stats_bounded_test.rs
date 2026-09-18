//! 慢查询增长有界专项（reports-M1 / #29，T6；独立文件 = 独立进程）。
//!
//! env 覆盖阈值/封顶后构建 app：同 digest 高频出现时行数 ≤ 封顶
//! （NF3 / vault 前科不重演的 e2e 锚点）。**独立测试文件**原因：
//! `Config::from_env` 读进程 env，且全局 Recorder 绑定本进程首个 app 的
//! pool——与其它测试同进程会互相污染。
//!
//! 无需真库：MySQL 不在环也成立（SQLite 直查 + 无执行）。但同步查询端点
//! 需要一条能执行的连接——用 SQLite 文件连接（db_type=sqlite，execute_query
//! 支持本地文件）。门控：`QS_E2E_BOUND=1` 显式开启（避免并行测试进程共享
//! env 的意外），默认跳过：
//! ```sh
//! QS_E2E_BOUND=1 cargo test --test query_stats_bounded_test -- --nocapture
//! ```

mod common;

use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn cap_bounds_rows_for_same_digest() {
    if std::env::var("QS_E2E_BOUND").ok().as_deref() != Some("1") {
        eprintln!("QS_E2E_BOUND not set; skipping bounded-growth test");
        return;
    }
    // 阈值 100ms + 封顶 5/h（clamp 下界内）。
    std::env::set_var("DBMASTER_SLOW_QUERY_THRESHOLD_MS", "100");
    std::env::set_var("DBMASTER_SLOW_QUERY_CAP_PER_DIGEST_PER_HOUR", "5");

    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token_body: serde_json::Value = common::post(
        &mut app,
        "/api/auth/register",
        json!({"email": "qs-bound@example.com", "password": "secure12345", "display_name": "T"}),
    )
    .await
    .json_value()
    .await;
    let token = token_body["access_token"].as_str().unwrap().to_string();

    // SQLite 文件连接（真执行、无网络依赖）。open_sqlite 不建文件——
    // 先用 sqlx 初始化一个空库文件（Windows 下显式 close 释放句柄）。
    let db_path = std::env::temp_dir().join(format!("qs-bound-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let init_opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true);
    let init_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(init_opts)
        .await
        .unwrap();
    init_pool.close().await;
    let conn_resp = common::post_with_auth(
        &mut app,
        "/api/connections",
        json!({
            "name": "qs-bound-sqlite",
            "db_type": "sqlite",
            "host": "localhost",
            "port": 0,
            "username": "",
            "password": "",
            "file_path": db_path.display().to_string(),
            "default_database": null,
            "ssh_enabled": false,
        }),
        &token,
    )
    .await;
    conn_resp.assert_ok();
    let conn_id = conn_resp.json_value().await["data"]["id"].as_str().unwrap().to_string();

    // 用 SQLite 的重查询制造慢查询：recursive CTE 计数到 4M（~150-400ms 级）。
    let slow_sql = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 4000000) SELECT COUNT(*) FROM c";
    for _ in 0..12 {
        let resp = common::post_with_auth(
            &mut app,
            &format!("/api/db/{conn_id}/query"),
            json!({"sql": slow_sql, "limit": 10}),
            &token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 等捕获写入沉淀后断言：同 digest 行数 ≤ 封顶 5。
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_stats")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(n <= 5, "封顶应把同 digest 行数限在 5，实际 {n}");
    assert!(n >= 1, "至少应有 1 条采样（若 CTE 太快可调大计数）");

    // 环境还原（本进程后续 from_env 不受影响）。
    std::env::remove_var("DBMASTER_SLOW_QUERY_THRESHOLD_MS");
    std::env::remove_var("DBMASTER_SLOW_QUERY_CAP_PER_DIGEST_PER_HOUR");
    let _ = std::fs::remove_file(&db_path);
}
