//! 慢查询捕获真库 e2e（reports-M1 / #29，T6）。
//!
//! 全链路验证：MySQL 真库上经 dbmaster-server 执行的慢查询（同步 / SSE
//! 网关 / 事务 / admin script / MCP read_query 五入口）旁路落库
//! `query_stats`，快查询不落库。捕获是 fire-and-forget spawn——断言用
//! 轮询等待写入可见。
//!
//! **单测试函数**：全局 Recorder（OnceLock）绑定本进程首个构建 app 的
//! pool，多测试函数并行会互相错位——全部场景串在一个函数里。
//!
//! 门控（对齐 gw_tdengine 模式）：`QS_E2E_MYSQL_HOST` 缺失时跳过。凭据
//! 只经 env，不进代码/日志/断言（激活凭据见仓库外 test_db_server.txt）：
//! ```sh
//! QS_E2E_MYSQL_HOST=<host> QS_E2E_MYSQL_PASSWORD=... \
//! cargo test --test query_stats_e2e_test -- --nocapture
//! ```

mod common;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::SqlitePool;

fn mysql_env() -> Option<(String, i64, String, String)> {
    let host = std::env::var("QS_E2E_MYSQL_HOST").ok().filter(|v| !v.is_empty())?;
    let port = std::env::var("QS_E2E_MYSQL_PORT")
        .ok()
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(3306);
    let user = std::env::var("QS_E2E_MYSQL_USER").unwrap_or_else(|_| "root".to_string());
    let password = std::env::var("QS_E2E_MYSQL_PASSWORD").unwrap_or_default();
    Some((host, port, user, password))
}

/// 轮询等待捕获行写入可见（spawn 异步窗口）。返回该 entry 的行数。
async fn wait_rows(pool: &SqlitePool, entry: &str) -> i64 {
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_stats WHERE entry = ?1")
            .bind(entry)
            .fetch_one(pool)
            .await
            .unwrap();
        if n > 0 {
            return n;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    0
}

async fn count_rows(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM query_stats")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[derive(Debug, sqlx::FromRow)]
struct CapturedRow {
    digest: String,
    db_kind: String,
    database: Option<String>,
    source: String,
    entry: String,
    status: String,
    elapsed_ms: i64,
    user_id: Option<String>,
}

async fn fetch_entry(pool: &SqlitePool, entry: &str) -> CapturedRow {
    sqlx::query_as::<_, CapturedRow>(
        "SELECT digest, db_kind, database, source, entry, status, elapsed_ms, user_id \
         FROM query_stats WHERE entry = ?1 ORDER BY captured_at DESC LIMIT 1",
    )
    .bind(entry)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn slow_query_capture_full_chain_e2e() {
    let Some((host, port, user, password)) = mysql_env() else {
        eprintln!("QS_E2E_MYSQL_HOST not set; skipping real-DB e2e");
        return;
    };

    // ── 场景 1：同步路径（POST /api/db/:id/query）──
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token_body: serde_json::Value = common::post(
        &mut app,
        "/api/auth/register",
        json!({"email": "qs-e2e@example.com", "password": "secure12345", "display_name": "T"}),
    )
    .await
    .json_value()
    .await;
    let token = token_body["access_token"].as_str().unwrap().to_string();

    let conn_resp = common::post_with_auth(
        &mut app,
        "/api/connections",
        json!({
            "name": "qs-e2e-mysql",
            "db_type": "mysql",
            "host": host,
            "port": port,
            "username": user,
            "password": password,
            "default_database": "mysql",
            "ssh_enabled": false,
        }),
        &token,
    )
    .await;
    conn_resp.assert_ok();
    let conn_body = conn_resp.json_value().await;
    let conn_id = conn_body["data"]["id"].as_str().unwrap().to_string();

    // 慢查询（SLEEP 1.5s > 默认阈值 1000ms）。
    let slow = json!({"sql": "SELECT SLEEP(1.5)", "limit": 10});
    let resp = common::post_with_auth(&mut app, &format!("/api/db/{conn_id}/query"), slow, &token)
        .await;
    resp.assert_status(StatusCode::OK);
    let body = resp.json_value().await;
    let elapsed = body["data"]["executionTimeMs"].as_u64().unwrap();
    assert!(elapsed >= 1500, "executionTimeMs should cover SLEEP, got {elapsed}");

    assert!(wait_rows(&pool, "sync_query").await >= 1, "sync_query 捕获超时未出现");
    let row = fetch_entry(&pool, "sync_query").await;
    assert_eq!(row.digest, "SELECT SLEEP(?)");
    assert_eq!(row.db_kind, "mysql");
    assert_eq!(row.database.as_deref(), Some("mysql"));
    assert_eq!(row.source, "gateway");
    assert_eq!(row.status, "ok");
    assert!(row.elapsed_ms >= 1500, "captured elapsed {row:?}");
    assert!(row.user_id.is_some(), "sync path has claims → user_id recorded");

    // 快查询不落库。
    let before = count_rows(&pool).await;
    let resp = common::post_with_auth(
        &mut app,
        &format!("/api/db/{conn_id}/query"),
        json!({"sql": "SELECT 1", "limit": 10}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(count_rows(&pool).await, before, "快查询（<阈值）不应落库");

    // ── 场景 2：SSE 网关路径（POST /api/gw/connections/:id/query）──
    let resp = common::post_with_auth(
        &mut app,
        &format!("/api/gw/connections/{conn_id}/query"),
        json!({"kind": "sql", "sql": "SELECT SLEEP(1.2)", "db": "mysql"}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let sse = resp.text().await;
    assert!(sse.contains("\"type\":\"complete\""), "SSE body 应含 complete 终态: {sse}");

    assert!(wait_rows(&pool, "gw_sse").await >= 1, "gw_sse 捕获超时未出现");
    let row = fetch_entry(&pool, "gw_sse").await;
    assert_eq!(row.digest, "SELECT SLEEP(?)");
    assert_eq!(row.db_kind, "mysql", "db_kind 经懒查解析");
    assert!(row.elapsed_ms >= 1200);

    // ── 场景 3：事务路径（txn begin → query → commit）──
    let resp = common::post_with_auth(
        &mut app,
        &format!("/api/db/{conn_id}/txn/begin"),
        json!({"db": "mysql"}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let session_id = resp.json_value().await["data"]["sessionId"].as_str().unwrap().to_string();

    let resp = common::post_with_auth(
        &mut app,
        &format!("/api/db/{conn_id}/txn/{session_id}/query"),
        json!({"sql": "SELECT SLEEP(1.3)", "limit": 10}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);

    let resp = common::post_with_auth(
        &mut app,
        &format!("/api/db/{conn_id}/txn/{session_id}/commit"),
        json!({}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);

    assert!(wait_rows(&pool, "txn_query").await >= 1, "txn_query 捕获超时未出现");
    let row = fetch_entry(&pool, "txn_query").await;
    assert_eq!(row.digest, "SELECT SLEEP(?)");
    assert_eq!(row.db_kind, "mysql", "txn 无 conn 行 → 懒查解析");
    assert_eq!(row.database, None, "txn session 不保存 db → NULL");
    assert!(row.elapsed_ms >= 1300);

    // ── 场景 4：admin script 路径（逐条计时，本设计唯一新增计时点）──
    let resp = common::post_with_auth(
        &mut app,
        &format!("/api/db/{conn_id}/admin/script"),
        json!({"script": "SELECT SLEEP(1.15)", "limit": 10}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);

    assert!(wait_rows(&pool, "admin_script").await >= 1, "admin_script 捕获超时未出现");
    let row = fetch_entry(&pool, "admin_script").await;
    assert_eq!(row.digest, "SELECT SLEEP(?)");
    assert!(row.elapsed_ms >= 1150);

    // ── 场景 5：MCP read_query 路径（进程内直调；超时臂以单测覆盖）──
    let out = dbmaster_automation::read_query::run_read_query(
        &pool,
        &[0u8; 32],
        &conn_id,
        None,
        "SELECT SLEEP(1.4)",
        100,
        std::time::Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(out["rowCount"], json!(1));

    assert!(wait_rows(&pool, "mcp_read").await >= 1, "mcp_read 捕获超时未出现");
    let row = fetch_entry(&pool, "mcp_read").await;
    assert_eq!(row.digest, "SELECT SLEEP(?)");
    assert!(row.elapsed_ms >= 1400);

    // ── 汇总：读端点聚合五入口样本（真实捕获数据，非直插）──
    let body: serde_json::Value = common::get_with_auth(
        &mut app,
        "/api/query-stats/summary?window=7d&limit=10",
        &token,
    )
    .await
    .json_value()
    .await;
    assert_eq!(body["ok"], json!(true));
    let items = body["data"]["items"].as_array().unwrap();
    assert!(!items.is_empty(), "summary 应看到真实捕获聚合");
    // 五入口同 digest（SELECT SLEEP(?)）在同一连接上聚合为一组；样本 =
    // 时间戳最新一条（mcp_read 场景最后执行 → SLEEP(1.4) 的明文）。
    let top = &items[0];
    assert_eq!(top["digest"], "SELECT SLEEP(?)");
    assert_eq!(top["count"], json!(5));
    assert_eq!(top["sample_sql_text"], json!("SELECT SLEEP(1.4)"));
}
