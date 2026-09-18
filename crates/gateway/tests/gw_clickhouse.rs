//! T29 第三批集成测试：ClickHouse 经网关全链路（真库，env 门控）。
//!
//! CH 走 MySQL 兼容口（默认 9004）。执行协议实机钉定：COM_QUERY 文本协议
//! 行解码在 sqlx 下对数值列报 "buffer exhausted"（CH wire 怪癖），
//! COM_STMT_PREPARE 二进制协议正常——stream_query 的 Family::Clickhouse
//! 腿走 `sqlx::query`（Prepare；SQL 无 `?` 绑定，与既有 ClickhouseBackend
//! 同口径）。
//!
//! 门控（对齐 `gw_mysql_family_e2e.rs` 模式）：环境变量 `GW_E2E_CH_HOST`
//! 缺失时**跳过而非失败**（普通 `cargo test` 无库照常绿）。凭据只经 env
//! 读取，不进代码/日志/断言。激活（凭据见仓库外 test_db_server.txt）：
//! ```sh
//! GW_E2E_CH_HOST=<ip> GW_E2E_CH_PORT=9004 GW_E2E_CH_USER=<user> \
//! GW_E2E_CH_PASSWORD=<pwd> \
//! cargo test -p dbmaster-gateway --test gw_clickhouse -- --nocapture
//! ```
//!
//! 覆盖面：test 端点（serverVersion）/ 注册 / 树三级钻取（databases 滤
//! 噪音 / tables / describe）/ SSE（事件序、位置数组行、行限截断、
//! engineCode 透传、超时、取消）/ **类型解码矩阵**（UInt64/Decimal/
//! Nullable/Date/DateTime64/Array/UUID/Bool 经 MySQL 口的到达形态——
//! 实机钉定，防静默落 null 回归）/ DML affectedRows。
//!
//! 账号约束：ch_test 无 DROP 授权——固定库 `ch_test_db` + 固定表名 +
//! TRUNCATE 清理（对齐 tests/e2e_data_sync_test.rs 既有约定）。
//! **并行隔离**：cargo test 默认多线程——每个会写数据的测试独占一张表
//! （sse 用 gw_ch_rows / 类型矩阵用 gw_ch_types），只读测试只做
//! CREATE IF NOT EXISTS，互不踩踏。
//!
//! 已知边界（路线 A，实机钉定于 ch_type_matrix）：
//! - columnTypes 为 MySQL wire 类型名（CHAR/INT UNSIGNED/NEWDECIMAL…），
//!   非 CH 原生名——原生名需 HTTP 8123 路线，后续增强；
//! - Date/DateTime/DateTime64 经 MySQL 口到达为 DATE/DATETIME 类型，由
//!   decode_cell_mysql 的 chrono 臂解码为字符串（SQL 惯例空格分隔；
//!   DateTime64(9) 纳秒截断到微秒 = MySQL 口精度上限）；
//! - Array 到达为文本形态 `['a','b']`（CHAR），UUID 到达为字符串，Bool
//!   到达为 TINYINT UNSIGNED 数字 0/1。

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use sqlx::SqlitePool;
use tower::ServiceExt;

use common::*;

/// 固定测试库（无 DROP 授权，复用 data_sync e2e 的既有约定库）。
const CH_DB: &str = "ch_test_db";
const T_TYPES: &str = "gw_ch_types";
const T_ROWS: &str = "gw_ch_rows";

fn ch_env() -> Option<(String, i64, String, String)> {
    let host = std::env::var("GW_E2E_CH_HOST").ok().filter(|v| !v.is_empty())?;
    let port = std::env::var("GW_E2E_CH_PORT")
        .ok()
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(9004);
    let user = std::env::var("GW_E2E_CH_USER").unwrap_or_else(|_| "ch_test".to_string());
    let password = std::env::var("GW_E2E_CH_PASSWORD").unwrap_or_default();
    Some((host, port, user, password))
}

fn router(config: std::sync::Arc<dbmaster_core::config::Config>, pool: SqlitePool) -> axum::Router {
    dbmaster_gateway::router(config, pool, [7u8; 32])
}

struct ChE2e {
    app: axum::Router,
    token: String,
    conn_id: String,
}

/// setup：注册 CH 连接 + 保证种子表存在（只读测试用；不含 TRUNCATE/INSERT，
/// 写种子的测试各自对自己的专属表做）。
async fn setup() -> Option<ChE2e> {
    let (host, port, user, password) = ch_env()?;
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "ch-e2e-user");
    let app = router(config, pool.clone());

    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "ch-e2e",
                "dbType": "clickhouse",
                "host": host,
                "port": port,
                "username": user,
                "password": password,
                "defaultDatabase": CH_DB,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "ch: register must pass");
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let conn_id = v["serverConnId"].as_str().unwrap().to_string();

    let e2e = ChE2e { app, token, conn_id };
    run_sql(&e2e, &format!(
        "CREATE TABLE IF NOT EXISTS {T_TYPES} (\
         u8 UInt8, u16 UInt16, u32 UInt32, u64 UInt64, \
         i32 Int32, i64 Int64, f32 Float32, f64 Float64, \
         d Decimal(10,2), s String, ns Nullable(String), \
         dt Date, dtm DateTime, dtm64 DateTime64(3), \
         arr Array(String), uu UUID, b Bool\
         ) ENGINE = MergeTree ORDER BY u8"
    )).await;
    run_sql(&e2e, &format!(
        "CREATE TABLE IF NOT EXISTS {T_ROWS} (id UInt32, name String) \
         ENGINE = MergeTree ORDER BY id"
    )).await;
    Some(e2e)
}

/// 单条语句经网关执行端点（断言 complete 终态）。
async fn run_sql(e2e: &ChE2e, sql: &str) -> String {
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({ "sql": sql, "database": CH_DB }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "ch: {sql}");
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    assert_eq!(
        events.last().unwrap().0,
        "complete",
        "ch: statement failed: {sql} → {text}"
    );
    text
}

/// SSE 查询（返回 (SSE 文本, 耗时 ms)）。
async fn query_sse(
    e2e: &ChE2e,
    sql: &str,
    extra: Option<serde_json::Map<String, serde_json::Value>>,
) -> (String, u128) {
    let mut body = serde_json::Map::new();
    body.insert("sql".into(), serde_json::json!(sql));
    body.insert("database".into(), serde_json::json!(CH_DB));
    if let Some(extra) = extra {
        for (k, v) in extra {
            body.insert(k, v);
        }
    }
    let started = std::time::Instant::now();
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::Value::Object(body).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "ch: {sql}");
    let text = body_string(resp.into_body()).await;
    (text, started.elapsed().as_millis())
}

// ── test 端点（T29 第三批补的 clickhouse 臂）──

#[tokio::test]
async fn ch_test_endpoint_returns_server_version() {
    let Some((host, port, user, password)) = ch_env() else { return };
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "ch-test-user");
    let app = router(config, pool.clone());

    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections/test",
            serde_json::json!({
                "dbType": "clickhouse",
                "host": host,
                "port": port,
                "username": user,
                "password": password,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["ok"], true, "ch: {v}");
    let version = v["serverVersion"].as_str().unwrap_or_default();
    assert!(!version.is_empty() && version.contains('.'), "ch: {version}");
}

// ── 树三级钻取（只读，不碰种子数据）──

#[tokio::test]
async fn ch_tree_drill() {
    let Some(e2e) = setup().await else { return };

    // 一级：databases 含固定库，滤 INFORMATION_SCHEMA/system_metadata 噪音。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(&e2e.token, &format!("/api/gw/connections/{}/databases", e2e.conn_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let dbs: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let names: Vec<&str> = dbs.as_array().unwrap().iter().map(|d| d.as_str().unwrap()).collect();
    assert!(names.contains(&CH_DB), "ch: {names:?}");
    for noise in ["INFORMATION_SCHEMA", "information_schema", "system_metadata"] {
        assert!(!names.contains(&noise), "ch: noise {noise} must be filtered: {names:?}");
    }

    // 二级：tables —— 种子表在册（system.tables 方言）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!("/api/gw/connections/{}/tables?db={CH_DB}", e2e.conn_id),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tables: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let names: Vec<&str> = tables.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&T_TYPES), "ch: {names:?}");
    assert!(names.contains(&T_ROWS), "ch: {names:?}");

    // 三级：describe —— 列名/类型（CH 原生类型名来自 system.columns）；
    // CH 无 PK/索引/FK 概念（describe_clickhouse 留空）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!("/api/gw/connections/{}/describe?db={CH_DB}&table={T_ROWS}", e2e.conn_id),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let desc: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let cols: Vec<&str> =
        desc["columns"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(cols, vec!["id", "name"], "ch: {desc}");
    let col_by_name: serde_json::Map<String, serde_json::Value> = desc["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap().to_string(), c.clone()))
        .collect();
    assert_eq!(col_by_name["id"]["type"], "UInt32", "ch: {col_by_name:?}");
    assert_eq!(col_by_name["name"]["type"], "String", "ch: {col_by_name:?}");
}

// ── SSE 基础语义（事件序 / 位置数组行 / 行限 / 错误透传 / DML）──
// 本测试独占 gw_ch_rows（TRUNCATE + INSERT），与其它测试并行安全。

#[tokio::test]
async fn ch_sse_semantics() {
    let Some(e2e) = setup().await else { return };
    run_sql(&e2e, &format!("TRUNCATE TABLE {T_ROWS}")).await;
    run_sql(&e2e, &format!("INSERT INTO {T_ROWS} VALUES (1, 'a'), (2, 'b')")).await;

    // 空结果 = meta（空列数组）+ complete 0 行。
    let (text, _) = query_sse(&e2e, &format!("SELECT id, name FROM {T_ROWS} WHERE 1 = 0"), None).await;
    let events = parse_sse(&text);
    let kinds: Vec<&str> = events.iter().map(|(e, _)| e.as_str()).collect();
    assert_eq!(kinds, vec!["meta", "complete"], "ch: {text}");
    assert_eq!(events[1].1["rowCount"], 0, "ch: {text}");

    // 位置数组行：UInt32 → 数字、String → 字符串。
    let (text, _) = query_sse(&e2e, &format!("SELECT id, name FROM {T_ROWS} ORDER BY id"), None).await;
    let events = parse_sse(&text);
    let rows_ev = events.iter().find(|(e, _)| e == "rows").unwrap();
    let rows = rows_ev.1["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "ch: {text}");
    assert_eq!(rows[0][0], 1, "ch: {text}");
    assert_eq!(rows[0][1], "a", "ch: {text}");
    assert_eq!(rows[1][0], 2, "ch: {text}");
    assert_eq!(rows[1][1], "b", "ch: {text}");
    let complete = events.last().unwrap();
    assert_eq!(complete.1["rowCount"], 2, "ch: {text}");
    assert_eq!(complete.1["truncated"], false, "ch: {text}");

    // 行限截断。
    let mut limited = serde_json::Map::new();
    limited.insert("rowLimit".into(), serde_json::json!(1));
    let (text, _) = query_sse(&e2e, &format!("SELECT id FROM {T_ROWS} ORDER BY id"), Some(limited)).await;
    let events = parse_sse(&text);
    let complete = events.last().unwrap();
    assert_eq!(complete.1["rowCount"], 1, "ch: {text}");
    assert_eq!(complete.1["truncated"], true, "ch: {text}");

    // 坏 SQL → DB_ERROR + engineCode 透传（CH 引擎原始码，实机钉定非空）。
    let (text, _) = query_sse(&e2e, "SELECT * FROM gw_ch_nope", None).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "ch: {text}");
    assert_eq!(events.last().unwrap().1["code"], "DB_ERROR", "ch: {text}");
    let engine_code = events.last().unwrap().1["engineCode"].as_str().unwrap_or("");
    assert!(!engine_code.is_empty(), "ch: engineCode must pass through: {text}");

    // DML：INSERT affectedRows 键存在（CH INSERT 经 MySQL 口的 affected 形态）。
    let text = run_sql(&e2e, &format!("INSERT INTO {T_ROWS} VALUES (3, 'c')")).await;
    let events = parse_sse(&text);
    assert!(events.last().unwrap().1["affectedRows"].is_u64(), "ch: {text}");
    let (text, _) = query_sse(&e2e, &format!("SELECT count() FROM {T_ROWS}"), None).await;
    let events = parse_sse(&text);
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"][0][0], 3, "ch: {text}");
}

// ── 类型解码矩阵（实机钉定到达形态，防静默落 null 回归）──
// 本测试独占 gw_ch_types。

#[tokio::test]
async fn ch_type_matrix() {
    let Some(e2e) = setup().await else { return };
    run_sql(&e2e, &format!("TRUNCATE TABLE {T_TYPES}")).await;
    run_sql(&e2e, &format!(
        "INSERT INTO {T_TYPES} VALUES (\
         1, 2, 3, 18446744073709551615, \
         -4, -5, 1.5, 2.5, \
         3.14, 'hello', NULL, \
         '2026-08-26', '2026-08-26 12:34:56', '2026-08-26 12:34:56.789', \
         ['a','b'], '123e4567-e89b-12d3-a456-426614174000', true)"
    )).await;

    let (text, _) = query_sse(&e2e, &format!("SELECT * FROM {T_TYPES}"), None).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "complete", "ch: {text}");
    let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
    let rows_ev = events.iter().find(|(e, _)| e == "rows").unwrap();
    let columns: Vec<&str> = meta.1["columns"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    let rows = rows_ev.1["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "ch: {text}");
    let row = &rows[0];
    // 诊断输出（--nocapture 可见）：列名 + MySQL wire 类型名 + 到达值——
    // 类型边界回归时的第一现场。
    eprintln!("CH_TYPE_MATRIX columns={columns:?}");
    eprintln!("CH_TYPE_MATRIX columnTypes={}", meta.1["columnTypes"]);
    eprintln!("CH_TYPE_MATRIX row={row}");

    let cell = |name: &str| -> serde_json::Value {
        let i = columns.iter().position(|c| *c == name).unwrap();
        row[i].clone()
    };
    // 实机钉定（2026-08-26，CH 26.7.3.19 MySQL 口）：
    // 整数族 → 数字（u64 走 decode_cell_mysql 的 u64 臂，BIGINT UNSIGNED
    // 最大值保真）；浮点 → 数字；Decimal → 保精度字符串（rust_decimal 臂）；
    // String → 字符串；Nullable → null。
    assert_eq!(cell("u8"), 1, "ch: {row}");
    assert_eq!(cell("u16"), 2, "ch: {row}");
    assert_eq!(cell("u32"), 3, "ch: {row}");
    assert_eq!(cell("u64"), serde_json::json!(18446744073709551615u64), "ch: {row}");
    assert_eq!(cell("i32"), -4, "ch: {row}");
    assert_eq!(cell("i64"), -5, "ch: {row}");
    assert_eq!(cell("f32"), 1.5, "ch: {row}");
    assert_eq!(cell("f64"), 2.5, "ch: {row}");
    assert_eq!(cell("d"), "3.14", "ch: Decimal must arrive as precision-preserving string: {row}");
    assert_eq!(cell("s"), "hello", "ch: {row}");
    assert_eq!(cell("ns"), serde_json::Value::Null, "ch: {row}");
    // 网关日期解码（chrono 臂）：Date → "YYYY-MM-DD"；DateTime/DateTime64
    // → "YYYY-MM-DD HH:MM:SS[.fff]"（DateTime64(3) 毫秒保留，空格分隔
    // SQL 惯例）。
    assert_eq!(cell("dt"), "2026-08-26", "ch: {row}");
    assert_eq!(cell("dtm"), "2026-08-26 12:34:56", "ch: {row}");
    assert_eq!(cell("dtm64"), "2026-08-26 12:34:56.789", "ch: {row}");
    // Array → 文本形态 CHAR；UUID → 字符串；Bool → TINYINT UNSIGNED 数字。
    assert_eq!(cell("arr"), "['a','b']", "ch: {row}");
    assert_eq!(cell("uu"), "123e4567-e89b-12d3-a456-426614174000", "ch: {row}");
    assert_eq!(cell("b"), 1, "ch: {row}");
}

// ── 超时（sleep(3)，CH sleep 上限恰好 3s）──

#[tokio::test]
async fn ch_timeout_fires_promptly_on_sleep() {
    let Some(e2e) = setup().await else { return };
    let mut body = serde_json::Map::new();
    body.insert("timeoutMs".into(), serde_json::json!(1500));
    let (text, elapsed) = query_sse(&e2e, "SELECT sleep(3)", Some(body)).await;

    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "ch: {text}");
    assert_eq!(events.last().unwrap().1["code"], "TIMEOUT", "ch: {text}");
    assert!(elapsed < 6500, "ch: timeout must return promptly, took {elapsed}ms");
}

// ── 取消（numbers 大扫描，X-Execution-Id）──

#[tokio::test]
async fn ch_cancel_fires_promptly_on_numbers_scan() {
    let Some(e2e) = setup().await else { return };
    let exec_id = "44444444-4444-4444-8444-444444444444";
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/api/gw/connections/{}/query", e2e.conn_id))
        .header("Authorization", format!("Bearer {}", e2e.token))
        .header("Content-Type", "application/json")
        .header("X-Execution-Id", exec_id)
        .body(axum::body::Body::from(
            serde_json::json!({
                "sql": "SELECT count() FROM numbers(100000000000)",
                "database": CH_DB,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = e2e.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 并发消费 body（通道背压不能堵死取消分支）。
    let consumer = tokio::spawn(async move { body_string(resp.into_body()).await });

    tokio::time::sleep(Duration::from_millis(600)).await;
    let cancel = e2e
        .app
        .clone()
        .oneshot(authed_delete(&e2e.token, &format!("/api/gw/executions/{exec_id}")))
        .await
        .unwrap();
    assert_eq!(cancel.status(), StatusCode::NO_CONTENT);

    let text = consumer.await.unwrap();
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "ch: {text}");
    assert_eq!(events.last().unwrap().1["code"], "CANCELLED", "ch: {text}");
}
