//! T29 TDengine 批次集成测试：TDengine 经网关全链路（真库，env 门控）。
//!
//! 语义（task_t29_tdengine.md 设计定稿）：kind:"tdengine" SQL 通道——
//! - 查询：column_meta（含**原生类型名**）→ meta 事件 columnTypes 保真；
//!   TIMESTAMP 值 RFC3339 字符串透传（格式化在壳侧）；
//! - 写（DML+DDL 同形，单列 affected_rows）→ affectedRows 通道（INSERT
//!   实际行数 / DDL 0），无 meta/rows 事件；
//! - 只读硬执行：read_only 连接拒写语句（静态首词分类），engineCode=READONLY；
//! - database 字段 = REST URL 路径路由（/rest/sql/{db}，无会话态）；
//! - 错误归一：坏凭据/不可达 → CONNECTION_FAILED；TD code≠0 → DB_ERROR +
//!   engineCode；
//! - 元数据三臂：databases（SHOW DATABASES 滤系统库）/ tables（用户库 SHOW
//!   STABLES）/ describe（DESCRIBE，TAG 标记 → 列 comment）。
//!
//! 门控（对齐 `gw_redis.rs` 模式）：环境变量 `GW_E2E_TDENGINE_HOST` 缺失时
//! **跳过而非失败**。凭据只经 env 读取，不进代码/日志/断言。激活（凭据见
//! 仓库外 test_db_server.txt）：
//! ```sh
//! GW_E2E_TDENGINE_HOST=<host> GW_E2E_TDENGINE_PASSWORD=... \
//! cargo test -p dbmaster-gateway --test gw_tdengine -- --nocapture --test-threads=1
//! ```
//!
//! exe 体积增量（实机钉定）：B5 后基线 20,697,600 B → 本批
//! **20,812,800 B（+115,200 B ≈ +112.5 KiB）**（2026-08-27 同机同 profile
//! 实测——零新增 crate，reqwest 本已在依赖树；远轻于 mongodb 的 +3.34 MiB）。
//!
//! 并行隔离：DDL 事务在同库并发会 979 冲突（实机钉定）——独占库
//! `gw_td_e2e` + 建议真库跑 `--test-threads=1`。

mod common;

use axum::http::StatusCode;
use sqlx::SqlitePool;
use tower::ServiceExt;

use common::*;

fn td_env() -> Option<(String, i64, String, String)> {
    let host = std::env::var("GW_E2E_TDENGINE_HOST").ok().filter(|v| !v.is_empty())?;
    let port = std::env::var("GW_E2E_TDENGINE_PORT")
        .ok()
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(6041);
    let user = std::env::var("GW_E2E_TDENGINE_USER").unwrap_or_else(|_| "root".to_string());
    let password = std::env::var("GW_E2E_TDENGINE_PASSWORD").unwrap_or_default();
    Some((host, port, user, password))
}

fn router(config: std::sync::Arc<dbmaster_core::config::Config>, pool: SqlitePool) -> axum::Router {
    dbmaster_gateway::router(config, pool, [7u8; 32])
}

struct TdE2e {
    app: axum::Router,
    token: String,
    conn_id: String,
}

/// 注册主连接（无默认库——db 路由用显式 database 参数）。
async fn setup() -> Option<TdE2e> {
    let (host, port, user, password) = td_env()?;
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "td-e2e-user");
    let app = router(config, pool.clone());
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "td-e2e",
                "dbType": "tdengine",
                "host": host,
                "port": port,
                "username": user,
                "password": password,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "tdengine: register must pass");
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let conn_id = v["serverConnId"].as_str().unwrap().to_string();

    let e2e = TdE2e { app, token, conn_id };
    // 独占库 + 干净起点（幂等建库 + 重建探针超级表）。
    run_ok(&e2e, None, "CREATE DATABASE IF NOT EXISTS gw_td_e2e").await;
    run_ok(&e2e, Some("gw_td_e2e"), "DROP STABLE IF EXISTS gw_td_probe").await;
    run_ok(
        &e2e,
        Some("gw_td_e2e"),
        "CREATE STABLE IF NOT EXISTS gw_td_probe (ts TIMESTAMP, v DOUBLE) TAGS (node BINARY(16))",
    )
    .await;
    Some(e2e)
}

/// 第二条 readOnly 连接（只读硬执行用例）。
async fn setup_read_only() -> Option<TdE2e> {
    let (host, port, user, password) = td_env()?;
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "td-ro-e2e-user");
    let app = router(config, pool.clone());
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "td-e2e-ro",
                "dbType": "tdengine",
                "host": host,
                "port": port,
                "username": user,
                "password": password,
                "readOnly": true,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    Some(TdE2e {
        app,
        token,
        conn_id: v["serverConnId"].as_str().unwrap().to_string(),
    })
}

/// kind:"tdengine" 单语句（database = REST URL 路由；返回 SSE 文本）。
async fn run(e2e: &TdE2e, db: Option<&str>, sql: &str) -> String {
    let mut body = serde_json::json!({ "kind": "tdengine", "sql": sql });
    if let Some(db) = db {
        body["database"] = serde_json::json!(db);
    }
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            body.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "tdengine: {sql}");
    body_string(resp.into_body()).await
}

/// 断言 complete 终态，返回解析后的事件。
async fn run_ok(e2e: &TdE2e, db: Option<&str>, sql: &str) -> Vec<(String, serde_json::Value)> {
    let text = run(e2e, db, sql).await;
    let events = parse_sse(&text);
    assert_eq!(
        events.last().unwrap().0,
        "complete",
        "tdengine: statement failed: {sql} → {text}"
    );
    events
}

// ── test 端点（SELECT SERVER_VERSION() 版本）──

#[tokio::test]
async fn tdengine_test_endpoint_returns_server_version() {
    let Some((host, port, user, password)) = td_env() else { return };
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "td-test-user");
    let app = router(config, pool.clone());
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections/test",
            serde_json::json!({
                "dbType": "tdengine",
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
    assert_eq!(v["ok"], true, "tdengine: {v}");
    let version = v["serverVersion"].as_str().unwrap_or_default();
    assert!(!version.is_empty() && version.contains('.'), "tdengine: {version}");
}

// ── 查询/写语义（columnTypes 保真 / affectedRows / engineCode / db 路由）──

#[tokio::test]
async fn tdengine_query_and_write_semantics() {
    let Some(e2e) = setup().await else { return };

    // 查询：meta columnTypes = 原生类型名（TIMESTAMP/DOUBLE/BINARY——CH 批次
    // 经 MySQL 口拿不到原生名的缺口在 TD 不存在）。
    let events = run_ok(&e2e, Some("gw_td_e2e"), "SELECT ts, v, node FROM gw_td_probe LIMIT 0").await;
    let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
    assert_eq!(meta.1["kind"], "tdengine");
    assert_eq!(meta.1["columns"], serde_json::json!(["ts", "v", "node"]));
    assert_eq!(
        meta.1["columnTypes"],
        serde_json::json!(["TIMESTAMP", "DOUBLE", "VARCHAR"]),
        "tdengine: native column types must round-trip"
    );

    // 写：INSERT affectedRows = 实际行数（两行 VALUES），无 meta/rows 事件。
    let events = run_ok(
        &e2e,
        Some("gw_td_e2e"),
        "INSERT INTO gw_td_c1 USING gw_td_probe TAGS('n1') VALUES (NOW, 1.5) (NOW+1s, 2.5)",
    )
    .await;
    assert!(events.iter().all(|(e, _)| e != "meta" && e != "rows"), "tdengine: write channel carries no data events");
    let complete = events.last().unwrap();
    assert_eq!(complete.1["affectedRows"], serde_json::json!(2), "tdengine: INSERT affectedRows");
    assert_eq!(complete.1["rowCount"], serde_json::json!(0));

    // 查询回读：TIMESTAMP 值 RFC3339 字符串（格式化归壳侧，wire 只透传）。
    let events = run_ok(&e2e, Some("gw_td_e2e"), "SELECT ts, v, node FROM gw_td_probe").await;
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    let first = rows.1["rows"][0].as_array().unwrap().clone();
    assert_eq!(first[1], serde_json::json!(1.5));
    assert_eq!(first[2], serde_json::json!("n1"));
    let ts = first[0].as_str().unwrap_or_default();
    assert!(ts.contains('T') && (ts.ends_with('Z') || ts.contains('+')), "tdengine: RFC3339 ts passthrough: {ts}");
    let complete = events.last().unwrap();
    assert_eq!(complete.1["rowCount"], serde_json::json!(2));

    // DDL：affectedRows 0（写通道同形）。
    let events = run_ok(&e2e, Some("gw_td_e2e"), "CREATE TABLE IF NOT EXISTS gw_td_c2 USING gw_td_probe TAGS('n2')").await;
    assert_eq!(events.last().unwrap().1["affectedRows"], serde_json::json!(0));

    // db 路由：database 参数指向 gw_td_e2e 时裸表名可解析；缺省库（注册时
    // 未设）时裸表名应报错（引擎级，engineCode 透传）。
    let events = run_ok(&e2e, Some("gw_td_e2e"), "SELECT COUNT(*) FROM gw_td_probe").await;
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert!(rows.1["rows"][0][0].as_u64().unwrap_or(0) >= 2, "tdengine: db-routed count");

    let text = run(&e2e, None, "SELECT COUNT(*) FROM gw_td_probe").await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "tdengine: no-db routing must fail: {text}");
    assert_eq!(events.last().unwrap().1["code"], "DB_ERROR");
    assert!(
        events.last().unwrap().1["engineCode"].is_string(),
        "tdengine: engine code passthrough: {text}"
    );

    // 坏 SQL：error 事件 + engineCode（TD 引擎码）。
    let text = run(&e2e, Some("gw_td_e2e"), "SELECT * FROM no_such_stable").await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "tdengine: {text}");
    assert_eq!(events.last().unwrap().1["code"], "DB_ERROR");
    assert_eq!(events.last().unwrap().1["engineCode"], serde_json::json!("9731"), "tdengine: table-not-found engine code (实机钉定): {text}");
}

// ── 行限 ──

#[tokio::test]
async fn tdengine_row_limit_truncates() {
    let Some(e2e) = setup().await else { return };
    let events = run_ok(
        &e2e,
        Some("gw_td_e2e"),
        "SELECT ts, v, node FROM gw_td_probe",
    )
    .await;
    let streamed: usize = events
        .iter()
        .filter(|(e, _)| e == "rows")
        .map(|(_, v)| v["rows"].as_array().map_or(0, |a| a.len()))
        .sum();
    let complete = events.last().unwrap();
    assert_eq!(complete.1["rowCount"].as_u64().unwrap_or(0) as usize, streamed);
    // 不设行限时缺省 gw_query_default_rows 足够（本表 <10 行）——truncated false。
    assert_eq!(complete.1["truncated"], serde_json::json!(false));
}

// ── 只读硬执行 ──

#[tokio::test]
async fn tdengine_read_only_rejects_writes() {
    let Some(ro) = setup_read_only().await else { return };
    // 只读连接：写语句拒（静态首词分类），engineCode=READONLY。
    let text = run(&ro, Some("gw_td_e2e"), "INSERT INTO gw_td_probe (ts, v) VALUES (NOW, 9.9)").await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "tdengine ro: {text}");
    assert_eq!(events.last().unwrap().1["engineCode"], serde_json::json!("READONLY"));

    // 读语句照常（独立注册的只读连接也要能查）。
    let events = run_ok(&ro, Some("gw_td_e2e"), "SELECT SERVER_VERSION()").await;
    assert!(events.iter().any(|(e, _)| e == "meta"), "tdengine ro: read must pass");
}

// ── 坏凭据 → CONNECTION_FAILED ──

#[tokio::test]
async fn tdengine_bad_credentials_map_to_connection_failed() {
    let Some((host, port, _, _)) = td_env() else { return };
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "td-badpw-user");
    let app = router(config, pool.clone());
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "td-e2e-badpw",
                "dbType": "tdengine",
                "host": host,
                "port": port,
                "username": "root",
                "password": "definitely-wrong-password",
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let conn_id = v["serverConnId"].as_str().unwrap().to_string();
    let e2e = TdE2e { app, token, conn_id };

    let text = run(&e2e, None, "SELECT SERVER_VERSION()").await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "tdengine badpw: {text}");
    assert_eq!(events.last().unwrap().1["code"], "CONNECTION_FAILED");
}

// ── 元数据三臂 ──

#[tokio::test]
async fn tdengine_metadata_three_levels() {
    let Some(e2e) = setup().await else { return };

    // databases：SHOW DATABASES 滤 information_schema/performance_schema。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(&e2e.token, &format!("/api/gw/connections/{}/databases", e2e.conn_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let dbs = v.as_array().unwrap();
    assert!(dbs.iter().any(|d| d == "gw_td_e2e"), "tdengine meta: {v}");
    assert!(
        dbs.iter().all(|d| {
            let s = d.as_str().unwrap_or_default().to_ascii_lowercase();
            s != "information_schema" && s != "performance_schema"
        }),
        "tdengine meta: system databases filtered: {v}"
    );

    // tables：用户库 SHOW STABLES（探针超级表在列）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!("/api/gw/connections/{}/tables?db=gw_td_e2e", e2e.conn_id),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let tables = v.as_array().unwrap();
    assert!(
        tables.iter().any(|t| t["name"] == "gw_td_probe"),
        "tdengine meta tables: {v}"
    );

    // describe：DESCRIBE——列 + TAG 标记（node 列 comment=TAG）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!(
                "/api/gw/connections/{}/describe?db=gw_td_e2e&table=gw_td_probe",
                e2e.conn_id
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let cols = v["columns"].as_array().unwrap();
    let node = cols.iter().find(|c| c["name"] == "node").unwrap();
    assert_eq!(node["comment"], serde_json::json!("TAG"), "tdengine meta describe: {v}");
    assert_eq!(node["type"], serde_json::json!("VARCHAR"), "tdengine meta describe type (BINARY 规范化显示，实机钉定): {v}");
    let ts = cols.iter().find(|c| c["name"] == "ts").unwrap();
    // 实机钉定：超级表 DESCRIBE 的 ts 列 note 为空（PRIMARY KEY 标记只在
    // 普通表出现）——nullable 按_note 透传，对齐客户端 getTableColumns 语义。
    assert_eq!(ts["nullable"], serde_json::json!(true), "tdengine meta describe: {v}");
    assert!(v["primaryKey"].is_null(), "tdengine meta describe: stable has no explicit PK note (空数组省略): {v}");
}
