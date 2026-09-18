//! T27 集成测试：SSE 流式查询全链路（真 SQLite 目标库）。
//!
//! 覆盖：meta/rows/complete 事件序与 seq id、行限截断、空结果、DML
//! affectedRows、坏 SQL 错误事件（engineCode 透传）、TIMEOUT、显式取消
//! （DELETE /executions/{id} → CANCELLED）、前置 4xx（UNSUPPORTED_KIND /
//! MULTI_STATEMENT）、未知执行 id 幂等 204、query_exec 审计行。

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use sqlx::SqlitePool;
use tower::ServiceExt;

use common::*;

fn router(
    config: std::sync::Arc<dbmaster_core::config::Config>,
    pool: SqlitePool,
) -> axum::Router {
    dbmaster_gateway::router(config, pool, [7u8; 32])
}

fn query_body(sql: &str) -> String {
    serde_json::json!({ "sql": sql }).to_string()
}

/// 更直接的辅助：返回 (响应头克隆, SSE 文本)。
async fn query_sse(
    app: &axum::Router,
    token: &str,
    conn_id: &str,
    body: String,
) -> (axum::http::HeaderMap, String) {
    let resp = app
        .clone()
        .oneshot(authed_post_json(token, &format!("/api/gw/connections/{conn_id}/query"), body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers().clone();
    (headers, body_string(resp.into_body()).await)
}

#[tokio::test]
async fn happy_path_streams_meta_rows_complete_in_order() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("happy").await;
    register_connection(&pool, "conn-q", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let (headers, text) = query_sse(
        &app,
        &token,
        "conn-q",
        query_body("SELECT id, name FROM artist ORDER BY id"),
    )
    .await;
    // 响应头回显执行 id（取消句柄）。
    assert!(headers.get("x-execution-id").is_some());
    assert_eq!(headers.get("content-type").unwrap().to_str().unwrap().starts_with("text/event-stream"), true);

    let events = parse_sse(&text);
    let kinds: Vec<&str> = events.iter().map(|(e, _)| e.as_str()).collect();
    assert_eq!(kinds, vec!["meta", "rows", "complete"]);

    // meta：列名数组 + kind/type 判别字段（契约 §4.2）。
    assert_eq!(events[0].1["kind"], "sql");
    assert_eq!(events[0].1["type"], "meta");
    assert_eq!(events[0].1["columns"], serde_json::json!(["id", "name"]));

    // rows：位置数组行（不是列名 map）。
    assert_eq!(events[1].1["rows"], serde_json::json!([[1, "a"], [2, "b"]]));

    // complete：rowCount/truncated/elapsedMs。
    assert_eq!(events[2].1["rowCount"], 2);
    assert_eq!(events[2].1["truncated"], false);
    assert!(events[2].1["elapsedMs"].as_u64().is_some());
    // SELECT 不带 affectedRows（可选键缺省省略）。
    assert!(events[2].1.get("affectedRows").is_none());
}

#[tokio::test]
async fn row_limit_truncates_with_flag() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("limit").await;
    register_connection(&pool, "conn-l", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let (_, text) = query_sse(
        &app,
        &token,
        "conn-l",
        serde_json::json!({ "sql": "SELECT n FROM big", "rowLimit": 10 }).to_string(),
    )
    .await;
    let events = parse_sse(&text);
    let complete = events.last().unwrap();
    assert_eq!(complete.0, "complete");
    assert_eq!(complete.1["rowCount"], 10);
    assert_eq!(complete.1["truncated"], true);
    // rows 事件累计 10 行。
    let rows: usize = events
        .iter()
        .filter(|(e, _)| e == "rows")
        .map(|(_, d)| d["rows"].as_array().unwrap().len())
        .sum();
    assert_eq!(rows, 10);
}

#[tokio::test]
async fn empty_result_still_emits_meta_and_complete() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("empty").await;
    register_connection(&pool, "conn-e", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let (_, text) = query_sse(
        &app,
        &token,
        "conn-e",
        query_body("SELECT id, name FROM artist WHERE 1 = 0"),
    )
    .await;
    let events = parse_sse(&text);
    let kinds: Vec<&str> = events.iter().map(|(e, _)| e.as_str()).collect();
    assert_eq!(kinds, vec!["meta", "complete"]);
    assert_eq!(events[0].1["columns"], serde_json::json!([]));
    assert_eq!(events[1].1["rowCount"], 0);
    assert_eq!(events[1].1["truncated"], false);
}

#[tokio::test]
async fn dml_reports_affected_rows_without_row_events() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("dml").await;
    register_connection(&pool, "conn-w", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let (_, text) = query_sse(
        &app,
        &token,
        "conn-w",
        query_body("INSERT INTO artist (id, name) VALUES (3, 'c')"),
    )
    .await;
    let events = parse_sse(&text);
    let kinds: Vec<&str> = events.iter().map(|(e, _)| e.as_str()).collect();
    assert_eq!(kinds, vec!["complete"]);
    assert_eq!(events[0].1["affectedRows"], 1);
    assert_eq!(events[0].1["rowCount"], 0);
}

#[tokio::test]
async fn bad_sql_is_error_event_with_engine_code() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("bad").await;
    register_connection(&pool, "conn-b", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let (_, text) = query_sse(
        &app,
        &token,
        "conn-b",
        query_body("SELECT no_such_column FROM artist"),
    )
    .await;
    let events = parse_sse(&text);
    let kinds: Vec<&str> = events.iter().map(|(e, _)| e.as_str()).collect();
    assert_eq!(kinds, vec!["error"]);
    assert_eq!(events[0].1["kind"], "sql");
    assert_eq!(events[0].1["type"], "error");
    assert_eq!(events[0].1["code"], "DB_ERROR");
    assert!(!events[0].1["message"].as_str().unwrap().is_empty());
    // 引擎原始码透传（SQLite 扩展码，sqlx 提供）。
    assert!(events[0].1["engineCode"].is_string());
}

#[tokio::test]
async fn statement_timeout_fires_error_event() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("slow").await;
    register_connection(&pool, "conn-t", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    // 30M 行递归求和 ≫ 1s 下限超时（timeoutMs 钳制下限 1000）。
    let (_, text) = query_sse(
        &app,
        &token,
        "conn-t",
        serde_json::json!({
            "sql": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 30000000) SELECT sum(x) FROM c",
            "timeoutMs": 1000
        })
        .to_string(),
    )
    .await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error");
    assert_eq!(events.last().unwrap().1["code"], "TIMEOUT");
}

#[tokio::test]
async fn explicit_cancel_terminates_streaming_execution() {
    let knobs = GwKnobs { query_max_rows: 5_000_000, ..Default::default() };
    let config = test_config(knobs);
    let pool = server_pool().await;
    let target = target_sqlite_db("cancel").await;
    register_connection(&pool, "conn-c", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    // 30M 行持续流 + 大行限：取消时执行必然仍在进行。
    let exec_id = "11111111-1111-1111-1111-111111111111";
    let query_req = query_request_with_exec_id(&token, "conn-c", exec_id);
    let resp = app.clone().oneshot(query_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 并发消费 body（否则通道满会背压执行任务）。
    let consumer = tokio::spawn(async move { body_string(resp.into_body()).await });

    tokio::time::sleep(Duration::from_millis(300)).await;
    let cancel_resp = app
        .clone()
        .oneshot(authed_delete(&token, &format!("/api/gw/executions/{exec_id}")))
        .await
        .unwrap();
    assert_eq!(cancel_resp.status(), StatusCode::NO_CONTENT);

    let text = consumer.await.unwrap();
    let events = parse_sse(&text);
    // 收到 rows 后以 CANCELLED 错误事件终止（而非 complete）。
    assert!(events.iter().any(|(e, _)| e == "rows"));
    assert_eq!(events.last().unwrap().0, "error");
    assert_eq!(events.last().unwrap().1["code"], "CANCELLED");
}

fn query_request_with_exec_id(token: &str, conn_id: &str, exec_id: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(format!("/api/gw/connections/{conn_id}/query"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .header("X-Execution-Id", exec_id)
        .body(axum::body::Body::from(
            serde_json::json!({
                "sql": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 30000000) SELECT x FROM c",
                "rowLimit": 5000000
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn cancel_unknown_execution_id_is_idempotent_204() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let resp = app
        .oneshot(authed_delete(&token, "/api/gw/executions/00000000-0000-0000-0000-000000000000"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn non_sql_kind_rejected_before_stream() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("kind").await;
    register_connection(&pool, "conn-k", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    // TDengine 批次后 sql/mongo/redis/tdengine 均已放开——真不支持的 kind
    // （无此判别值）钉 UNSUPPORTED_KIND 边界。
    let resp = app
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections/conn-k/query",
            serde_json::json!({ "sql": "SELECT 1", "kind": "cassandra" }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["error"]["code"], "UNSUPPORTED_KIND");
}

/// T29 TDengine 批次 — kind:"tdengine" 载荷 = sql：空语句/多语句前置校验
/// （流开始前 4xx，与 "sql" 同口径）。
#[tokio::test]
async fn tdengine_kind_precheck_mirrors_sql() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    for (body, code) in [
        (serde_json::json!({ "kind": "tdengine" }), "CONFIG"), // 缺 sql
        (
            serde_json::json!({ "kind": "tdengine", "sql": "   " }),
            "CONFIG",
        ), // 空白 sql
        (
            serde_json::json!({ "kind": "tdengine", "sql": "SELECT 1; SELECT 2" }),
            "MULTI_STATEMENT",
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(authed_post_json(&token, "/api/gw/connections/any/query", body.to_string()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "tdengine pre-check: {body}");
        let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
        assert_eq!(v["error"]["code"], code, "tdengine pre-check code: {body}");
    }
}

/// T29 非 SQL 批次（B1）— kind:"mongo" 的 command 前置校验（流开始前 4xx；
/// redis kind 仍拒——随 B3 批次放开，上例即钉）。
#[tokio::test]
async fn mongo_kind_requires_nonempty_command_object() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    for body in [
        serde_json::json!({ "kind": "mongo" }),                          // 缺 command
        serde_json::json!({ "kind": "mongo", "command": "find" }),       // 非对象
        serde_json::json!({ "kind": "mongo", "command": {} }),           // 空对象
    ] {
        let resp = app
            .clone()
            .oneshot(authed_post_json(&token, "/api/gw/connections/any/query", body.to_string()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "mongo pre-check: {body}");
        let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
        assert_eq!(v["error"]["code"], "CONFIG", "mongo pre-check: {body}");
    }
}

#[tokio::test]
async fn multi_statement_rejected_before_stream() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("multi").await;
    register_connection(&pool, "conn-m", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let resp = app
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections/conn-m/query",
            query_body("SELECT 1; SELECT 2"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["error"]["code"], "MULTI_STATEMENT");
}

#[tokio::test]
async fn query_exec_audits_outcome_without_sql_text() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("audit").await;
    register_connection(&pool, "conn-a", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config.clone(), pool.clone());

    let (_, _text) = query_sse(
        &app,
        &token,
        "conn-a",
        query_body("SELECT id FROM artist"),
    )
    .await;
    // 审计异步落表——给任务让出调度窗口。
    tokio::time::sleep(Duration::from_millis(100)).await;

    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT action, status, COALESCE(error, '') FROM gw_audit WHERE action = 'query_exec'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "ok");
    // 硬规则：审计不含 SQL 明文。
    let all: String = sqlx::query_scalar("SELECT group_concat(error, '|') FROM gw_audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!all.to_lowercase().contains("select"));
}
