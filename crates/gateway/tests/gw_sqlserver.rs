//! T28 集成测试：SQL Server 经网关全链路（真库，env 门控）。
//!
//! 门控（对齐 drift/tests/real_db_e2e.rs 模式）：环境变量
//! `GW_E2E_SQLSERVER_HOST` 缺失时全部测试**跳过而非失败**（普通
//! `cargo test` 无库照常绿）。凭据只经 env 读取，不进代码/日志/断言。
//!
//! 激活方式（凭据见仓库外 test_db_server.txt，勿写入命令行历史/脚本）：
//! ```sh
//! GW_E2E_SQLSERVER_HOST=<test-server-ip> \
//! GW_E2E_SQLSERVER_USER=<login> \
//! GW_E2E_SQLSERVER_PASSWORD=<password> \
//! cargo test -p dbmaster-gateway --test gw_sqlserver -- --nocapture
//! ```
//!
//! 覆盖面（#31 T28 server 侧验收）：
//! - 连接注册族：test 端点（serverVersion）+ register（vault 密文落库）；
//! - 树三级钻取：databases（滤系统库）/ tables（kind+comment+rowEstimate）/
//!   describe（列完整类型/默认值/注释 + PK + 索引列 + FK）；
//! - SSE：位置数组行、行限截断、DML affectedRows、坏 SQL engineCode；
//! - **超时语义（#30 / SS-TIMEOUT-301 不复发）**：WAITFOR DELAY 在
//!   timeoutMs 后收到 TIMEOUT 错误事件，且 sys.dm_exec_requests 无残留
//!   （服务端查询随连接 drop 终止）；
//! - **取消语义**：DELETE /executions/{id} → CANCELLED，同样零残留；
//! - 审计：query_exec 行只含稳定码，无 SQL 明文。

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

/// env 门控：HOST 缺失返回 None（测试跳过）。PORT 缺省 1433。
fn ss_env() -> Option<(String, i64, String, String)> {
    let host = std::env::var("GW_E2E_SQLSERVER_HOST").ok().filter(|h| !h.is_empty())?;
    let port = std::env::var("GW_E2E_SQLSERVER_PORT")
        .ok()
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(1433);
    let user = std::env::var("GW_E2E_SQLSERVER_USER").ok().filter(|u| !u.is_empty())?;
    let password = std::env::var("GW_E2E_SQLSERVER_PASSWORD").ok().filter(|p| !p.is_empty())?;
    Some((host, port, user, password))
}

/// e2e 场景共享态：router + token + 注册好的连接 id + 一次性库名。
struct SsE2e {
    app: axum::Router,
    token: String,
    conn_id: String,
    db: String,
    pool: SqlitePool,
}

/// setup：注册连接（vault 路径）+ 建一次性数据库与表/视图/注释。
async fn setup() -> Option<SsE2e> {
    let (host, port, user, password) = ss_env()?;
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "ss-e2e-user");
    let app = router(config, pool.clone());

    // 注册（草稿校验 + AES-256-GCM 入 vault + serverConnId）。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "ss-e2e",
                "dbType": "sqlserver",
                "host": host,
                "port": port,
                "username": user,
                "password": password,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register must pass draft validation");
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let conn_id = v["serverConnId"].as_str().unwrap().to_string();

    let db = format!(
        "gw_ss_e2e_{}_{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default() % 1_000_000
    );
    let e2e = SsE2e { app, token, conn_id, db, pool };
    // 上次中断残留的同名库先尽力清掉（DROP 不能在目标库上下文执行 → None）。
    let _ = run_ddl(&e2e, &format!("DROP DATABASE IF EXISTS [{}]", e2e.db), None).await;

    run_ddl(&e2e, &format!("CREATE DATABASE [{}]", e2e.db), None).await;
    let db_ctx = e2e.db.clone();
    for ddl in [
        "CREATE TABLE gw_parent (id INT PRIMARY KEY, label NVARCHAR(50) NOT NULL)",
        "CREATE TABLE gw_child ( \
            id INT PRIMARY KEY, \
            parent_id INT NOT NULL, \
            name NVARCHAR(50) NOT NULL DEFAULT N'anon', \
            price DECIMAL(18,2) NOT NULL DEFAULT 0, \
            created DATETIME2 NOT NULL DEFAULT SYSDATETIME(), \
            CONSTRAINT fk_gw_parent FOREIGN KEY (parent_id) REFERENCES gw_parent(id) \
         )",
        "CREATE INDEX ix_gw_child_name ON gw_child (name)",
        "CREATE VIEW gw_v AS SELECT id FROM gw_parent",
        "EXEC sp_addextendedproperty @name = N'MS_Description', @value = N'child table (e2e)', \
         @level0type = N'SCHEMA', @level0name = N'dbo', @level1type = N'TABLE', @level1name = N'gw_child'",
        "EXEC sp_addextendedproperty @name = N'MS_Description', @value = N'display name', \
         @level0type = N'SCHEMA', @level0name = N'dbo', @level1type = N'TABLE', @level1name = N'gw_child', \
         @level2type = N'COLUMN', @level2name = N'name'",
        "INSERT INTO gw_parent (id, label) VALUES (1, N'p1')",
    ] {
        run_ddl(&e2e, ddl, Some(&db_ctx)).await;
    }
    Some(e2e)
}

async fn teardown(e2e: &SsE2e) {
    let _ = run_ddl(e2e, &format!("DROP DATABASE IF EXISTS [{}]", e2e.db), None).await;
}

/// 单条 DDL/DML 经网关执行端点（complete 事件）。db 上下文 None = master
/// （CREATE/DROP DATABASE 必须在库外执行）。
async fn run_ddl(e2e: &SsE2e, sql: &str, db: Option<&str>) {
    let mut body = serde_json::Map::new();
    body.insert("sql".into(), serde_json::json!(sql));
    if let Some(db) = db {
        body.insert("database".into(), serde_json::json!(db));
    }
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
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "complete", "ddl failed: {sql} → {text}");
}

/// SSE 查询（返回 (SSE 文本, 耗时 ms)）；db=None 且 extra 无 database 时
/// 落连接缺省上下文（master）。
async fn query_sse(
    e2e: &SsE2e,
    sql: &str,
    db: Option<&str>,
    extra: Option<serde_json::Map<String, serde_json::Value>>,
) -> (String, u128) {
    let mut body = serde_json::Map::new();
    body.insert("sql".into(), serde_json::json!(sql));
    if let Some(db) = db {
        body.insert("database".into(), serde_json::json!(db));
    }
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
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_string(resp.into_body()).await;
    (text, started.elapsed().as_millis())
}

/// 等待本测试库上的 WAITFOR 请求清零（#30 零残留判据；连接 drop 后服务端
/// 终止会话有毫秒级延迟，轮询 3s）。按 database_id 过滤——并行测试各自
/// 独立库，互不干扰。
async fn wait_no_waitfor_requests(e2e: &SsE2e) -> bool {
    for _ in 0..15 {
        let (text, _) = query_sse(
            e2e,
            &format!(
                "SELECT COUNT(*) AS n FROM sys.dm_exec_requests                  WHERE command = 'WAITFOR' AND database_id = DB_ID(N'{}')",
                e2e.db
            ),
            None,
            None,
        )
        .await;
        let events = parse_sse(&text);
        if let Some((_, data)) = events.iter().find(|(e, _)| e == "rows") {
            if data["rows"][0][0].as_i64() == Some(0) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

// ── 连接注册族：test 端点（真库）+ register 密文 ──

#[tokio::test]
async fn sqlserver_test_endpoint_returns_server_version() {
    let Some((host, port, user, password)) = ss_env() else { return };
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "ss-test-user");
    let app = router(config, pool.clone());

    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections/test",
            serde_json::json!({
                "dbType": "sqlserver",
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
    assert_eq!(v["ok"], true, "test endpoint: {v}");
    // SERVERPROPERTY('ProductVersion') 形如 "16.0.4155.1"。
    assert!(v["serverVersion"].as_str().unwrap().split('.').count() >= 2);

    // 密文纪律：连接注册后库里无明文（dbType=mssql 别名同口径）。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "ss-cipher",
                "dbType": "mssql",
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
    let stored: String = sqlx::query_scalar(
        "SELECT password_encrypted FROM database_connections WHERE name = 'ss-cipher'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(stored.starts_with("v1:"));
    assert!(!stored.contains(&password));
}

// ── 树三级钻取 + SSE 基础语义 ──

#[tokio::test]
async fn sqlserver_tree_drill_and_sse_semantics() {
    let Some(e2e) = setup().await else { return };
    let db = e2e.db.clone();

    // 一级：databases 滤系统库、含一次性库。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(&e2e.token, &format!("/api/gw/connections/{}/databases", e2e.conn_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let dbs: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let names: Vec<&str> = dbs.as_array().unwrap().iter().map(|d| d.as_str().unwrap()).collect();
    assert!(names.contains(&db.as_str()));
    for sysdb in ["master", "model", "msdb", "tempdb"] {
        assert!(!names.contains(&sysdb), "system db {sysdb} must be filtered");
    }

    // 二级：tables —— kind/comment/rowEstimate 形状（camelCase、空省略）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!("/api/gw/connections/{}/tables?db={}", e2e.conn_id, db),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tables: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let by_name: serde_json::Map<String, serde_json::Value> = tables
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["name"].as_str().unwrap().to_string(), t.clone()))
        .collect();
    let parent = &by_name["gw_parent"];
    assert_eq!(parent["type"], "table");
    assert!(parent.get("comment").is_none(), "no comment → key omitted");
    let child = &by_name["gw_child"];
    assert_eq!(child["type"], "table");
    assert_eq!(child["comment"], "child table (e2e)");
    assert!(child["rowEstimate"].as_i64().is_some(), "rowEstimate present (heap partitions)");
    let view = &by_name["gw_v"];
    assert_eq!(view["type"], "view");
    assert!(view.get("rowEstimate").is_none(), "view has no rowEstimate key");

    // 三级：describe —— 列/PK/索引/FK 全件。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!(
                "/api/gw/connections/{}/describe?db={}&table=gw_child",
                e2e.conn_id, db
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let desc: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(desc["comment"], "child table (e2e)");
    let cols: Vec<&str> =
        desc["columns"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(cols, vec!["id", "parent_id", "name", "price", "created"]);
    let col_by_name: serde_json::Map<String, serde_json::Value> = desc["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap().to_string(), c.clone()))
        .collect();
    assert_eq!(col_by_name["name"]["type"], "nvarchar(50)");
    assert_eq!(col_by_name["price"]["type"], "decimal(18,2)");
    assert_eq!(col_by_name["id"]["nullable"], false);
    assert_eq!(col_by_name["name"]["nullable"], false);
    assert_eq!(col_by_name["price"]["defaultValue"], "0");
    assert_eq!(col_by_name["name"]["comment"], "display name");
    assert!(col_by_name["created"].get("comment").is_none());
    assert_eq!(desc["primaryKey"], serde_json::json!(["id"]));
    let ix: serde_json::Map<String, serde_json::Value> = desc["indexes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i["name"].as_str().unwrap().to_string(), i.clone()))
        .collect();
    assert_eq!(ix["ix_gw_child_name"]["columns"], serde_json::json!(["name"]));
    assert_eq!(ix["ix_gw_child_name"]["unique"], false);
    assert_eq!(ix.len(), 2, "PK index + secondary: {ix:?}");
    let fk = &desc["foreignKeys"][0];
    assert_eq!(fk["name"], "fk_gw_parent");
    assert_eq!(fk["columns"], serde_json::json!(["parent_id"]));
    assert_eq!(fk["refTable"], "gw_parent");
    assert_eq!(fk["refColumns"], serde_json::json!(["id"]));

    // SSE：空结果 = meta（空列数组，v1 与 sqlx 族同口径）+ complete 0 行。
    let (text, _) = query_sse(
        &e2e,
        "SELECT id, name, price, created FROM gw_child WHERE 1 = 0",
        Some(&db),
        None,
    )
    .await;
    let events = parse_sse(&text);
    let kinds: Vec<&str> = events.iter().map(|(e, _)| e.as_str()).collect();
    assert_eq!(kinds, vec!["meta", "complete"]);
    assert_eq!(events[0].1["columns"], serde_json::json!([]));
    assert_eq!(events[1].1["rowCount"], 0);

    run_ddl(
        &e2e,
        "INSERT INTO gw_child (id, parent_id, name, price) VALUES (1, 1, N'a', 1.5), (2, 1, N'b', 2.5), (3, 1, N'c', 3.5)",
        Some(&db),
    )
    .await;

    // 位置数组行 + 类型解码（int → 数字；decimal → 十进制字符串）。
    let (text, _) = query_sse(&e2e, "SELECT id, name, price FROM gw_child ORDER BY id", Some(&db), None).await;
    let events = parse_sse(&text);
    let rows_ev = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(
        rows_ev.1["rows"],
        serde_json::json!([[1, "a", "1.50"], [2, "b", "2.50"], [3, "c", "3.50"]])
    );
    let complete = events.last().unwrap();
    assert_eq!(complete.1["rowCount"], 3);
    assert_eq!(complete.1["truncated"], false);

    // 行限截断。
    let mut limited = serde_json::Map::new();
    limited.insert("rowLimit".into(), serde_json::json!(2));
    let (text, _) = query_sse(&e2e, "SELECT id FROM gw_child ORDER BY id", Some(&db), Some(limited)).await;
    let events = parse_sse(&text);
    let complete = events.last().unwrap();
    assert_eq!(complete.1["rowCount"], 2);
    assert_eq!(complete.1["truncated"], true);

    // 坏 SQL → DB_ERROR + engineCode（TDS 错误号 208 = Invalid object name）。
    let (text, _) = query_sse(&e2e, "SELECT * FROM gw_nope", Some(&db), None).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error");
    assert_eq!(events.last().unwrap().1["code"], "DB_ERROR");
    assert_eq!(events.last().unwrap().1["engineCode"], "208");

    teardown(&e2e).await;
}

// ── 超时/取消语义（#30 锚点：超时/取消后服务端查询必须终止）──

#[tokio::test]
async fn sqlserver_timeout_kills_waitfor_server_side() {
    let Some(e2e) = setup().await else { return };
    let mut body = serde_json::Map::new();
    body.insert("database".into(), serde_json::json!(e2e.db));
    body.insert("timeoutMs".into(), serde_json::json!(1500));
    let (text, elapsed) = query_sse(&e2e, "WAITFOR DELAY '0:0:20'", None, Some(body)).await;

    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "{text}");
    assert_eq!(events.last().unwrap().1["code"], "TIMEOUT");
    // 20s 的语句 1.5s 超时返回（容差给 TLS/TCP 慢环境）。
    assert!(elapsed < 6500, "timeout must return promptly, took {elapsed}ms");
    // 服务端零残留（#30：超时后连接 drop → WAITFOR 批处理被终止）。
    assert!(
        wait_no_waitfor_requests(&e2e).await,
        "server-side WAITFOR must be terminated after timeout"
    );
    teardown(&e2e).await;
}

#[tokio::test]
async fn sqlserver_cancel_kills_waitfor_server_side() {
    let Some(e2e) = setup().await else { return };
    let exec_id = "22222222-2222-4222-8222-222222222222";
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/api/gw/connections/{}/query", e2e.conn_id))
        .header("Authorization", format!("Bearer {}", e2e.token))
        .header("Content-Type", "application/json")
        .header("X-Execution-Id", exec_id)
        .body(axum::body::Body::from(
            serde_json::json!({
                "sql": "WAITFOR DELAY '0:0:30'",
                "database": e2e.db,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = e2e.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 并发消费 body（通道背压不能堵死执行任务的取消分支）。
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
    assert_eq!(events.last().unwrap().0, "error", "{text}");
    assert_eq!(events.last().unwrap().1["code"], "CANCELLED");
    assert!(
        wait_no_waitfor_requests(&e2e).await,
        "server-side WAITFOR must be terminated after cancel"
    );
    teardown(&e2e).await;
}

// ── 审计：SQL 明文禁入 ──

#[tokio::test]
async fn sqlserver_query_audit_contains_no_sql_text() {
    let Some(e2e) = setup().await else { return };
    let _ = query_sse(&e2e, "SELECT TOP 1 id FROM gw_parent", Some(&e2e.db), None).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let all: String = sqlx::query_scalar(
        "SELECT COALESCE(group_concat(COALESCE(error, '') || action, '|'), '') FROM gw_audit",
    )
    .fetch_one(&e2e.pool)
    .await
    .unwrap();
    let lowered = all.to_lowercase();
    assert!(!lowered.contains("waitfor"));
    assert!(!lowered.contains("select"));
    teardown(&e2e).await;
}
