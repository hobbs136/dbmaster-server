//! T29 非 SQL 批次（B1）集成测试：MongoDB 经网关全链路（真库，env 门控）。
//!
//! 语义（ADR-0006 §2.4）：kind:"mongo" + runCommand 单形状——
//! - 游标命令（find/aggregate/listCollections/listIndexes…）流式展平为
//!   文档行（单列 "doc"，值域 JSON；$oid/$date 等扩展类型为子文档形态）；
//! - 非游标命令单文档单列 "result"（count → {n,…}）；
//! - 写命令走 affectedRows 通道（响应 "n"）；read_only 连接对写命令硬拒
//!   （engineCode=READONLY）；
//! - 命令错误 codeName 透传 engineCode；
//! - 游标展平是手工 firstBatch/getMore 循环（mongo::cursor_stream）——
//!   batchSize 钉小（100）强制 getMore 分页实跑。
//!
//! 门控（对齐 `gw_clickhouse.rs` 模式）：环境变量 `GW_E2E_MONGO_HOST`
//! 缺失时**跳过而非失败**（普通 `cargo test` 无库照常绿）。凭据只经 env
//! 读取，不进代码/日志/断言。激活（凭据见仓库外 test_db_server.txt）：
//! ```sh
//! GW_E2E_MONGO_HOST=<ip> GW_E2E_MONGO_PORT=27017 GW_E2E_MONGO_USER=<user> \
//! GW_E2E_MONGO_PASSWORD=<pwd> \
//! cargo test -p dbmaster-gateway --test gw_mongodb -- --nocapture
//! ```
//!
//! exe 体积增量（B1.1，ADR-0006 §4 风险项登记）：release 基线 16,590,848 B
//! （commit a134fda，2026-08-25 构建）→ 引入 mongodb 3.8 crate 后
//! **20,095,488 B（+3,504,640 B ≈ +3.34 MiB）**（2026-08-27 实测，同机同
//! profile）。低于预估量级（tiberius +0.7MB 的 ~5 倍而非数倍 MiB 上限），
//! embedded 分发可接受。
//!
//! 并行隔离：cargo test 默认多线程——每个会写数据的测试独占一个
//! collection（先 drop 再建），只读测试的 seed 幂等（空库才插）。

mod common;

use axum::http::StatusCode;
use sqlx::SqlitePool;
use tower::ServiceExt;

use common::*;

const E2E_DB: &str = "gw_mongo_e2e";
const C_SEED: &str = "gw_seed";
const C_CMD: &str = "gw_cmd";
const C_RO: &str = "gw_ro";
const C_TYPES: &str = "gw_types";
const C_MORE: &str = "gw_more";

fn mongo_env() -> Option<(String, i64, String, String)> {
    let host = std::env::var("GW_E2E_MONGO_HOST").ok().filter(|v| !v.is_empty())?;
    let port = std::env::var("GW_E2E_MONGO_PORT")
        .ok()
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(27017);
    let user = std::env::var("GW_E2E_MONGO_USER").unwrap_or_default();
    let password = std::env::var("GW_E2E_MONGO_PASSWORD").unwrap_or_default();
    Some((host, port, user, password))
}

fn router(config: std::sync::Arc<dbmaster_core::config::Config>, pool: SqlitePool) -> axum::Router {
    dbmaster_gateway::router(config, pool, [7u8; 32])
}

struct MongoE2e {
    app: axum::Router,
    token: String,
    conn_id: String,
}

/// setup：注册连接（authSource=admin；extra 透传 direct 模式走真实清洗
/// 路径）+ seed 幂等（空库才插，并行 setup 双插无害——只读断言皆 contains）。
async fn setup() -> Option<MongoE2e> {
    let (host, port, user, password) = mongo_env()?;
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "mongo-e2e-user");
    let app = router(config, pool.clone());

    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "mongo-e2e",
                "dbType": "mongodb",
                "host": host,
                "port": port,
                "username": if user.is_empty() { serde_json::Value::Null } else { serde_json::json!(user) },
                "password": if password.is_empty() { serde_json::Value::Null } else { serde_json::json!(password) },
                "defaultDatabase": "admin",
                "extra": { "mongoConnectionMode": "direct" },
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "mongo: register must pass");
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let conn_id = v["serverConnId"].as_str().unwrap().to_string();
    let e2e = MongoE2e { app, token, conn_id };

    let (text, events) = run_cmd(&e2e, serde_json::json!({"count": C_SEED})).await;
    assert_eq!(events.last().unwrap().0, "complete", "mongo: seed count: {text}");
    let seeded = events
        .iter()
        .find(|(e, _)| e == "rows")
        .map(|(_, d)| d["rows"][0][0]["n"].as_i64().unwrap_or(0))
        .unwrap_or(0);
    if seeded == 0 {
        let (text, events) = run_cmd(
            &e2e,
            serde_json::json!({"insert": C_SEED, "documents": [
                {"name": "alice", "n": 1},
                {"name": "bob", "n": 2},
            ]}),
        )
        .await;
        assert_eq!(events.last().unwrap().0, "complete", "mongo: seed insert: {text}");
    }
    Some(e2e)
}

/// 经网关执行一条 mongo 命令（kind:"mongo"），返回 (SSE 文本, 事件序)。
async fn run_cmd(e2e: &MongoE2e, command: serde_json::Value) -> (String, Vec<(String, serde_json::Value)>) {
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({ "kind": "mongo", "command": command, "database": E2E_DB })
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "mongo: {command}");
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    (text, events)
}

/// run_cmd + complete 终态断言。
async fn run_ok(
    e2e: &MongoE2e,
    command: serde_json::Value,
) -> Vec<(String, serde_json::Value)> {
    let (text, events) = run_cmd(e2e, command.clone()).await;
    assert_eq!(
        events.last().unwrap().0,
        "complete",
        "mongo: command failed: {command} → {text}"
    );
    events
}

/// 幂等清场：drop collection（不存在时引擎报错——容忍，调用方不看结果）。
async fn reset_collection(e2e: &MongoE2e, coll: &str) {
    let _ = run_cmd(e2e, serde_json::json!({"drop": coll})).await;
}

// ── test 端点（buildInfo 版本）──

#[tokio::test]
async fn mongo_test_endpoint_returns_server_version() {
    let Some((host, port, user, password)) = mongo_env() else { return };
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "mongo-test-user");
    let app = router(config, pool.clone());

    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections/test",
            serde_json::json!({
                "dbType": "mongodb",
                "host": host,
                "port": port,
                "username": if user.is_empty() { serde_json::Value::Null } else { serde_json::json!(user) },
                "password": if password.is_empty() { serde_json::Value::Null } else { serde_json::json!(password) },
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["ok"], true, "mongo: {v}");
    let version = v["serverVersion"].as_str().unwrap_or_default();
    assert!(!version.is_empty() && version.contains('.'), "mongo: {version}");
}

// ── 树三级钻取（只读；setup 保证 seed 在册）──

#[tokio::test]
async fn mongo_tree_drill() {
    let Some(e2e) = setup().await else { return };

    // 一级：databases（admin/config/local 全保留——对齐客户端不滤除语义）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(&e2e.token, &format!("/api/gw/connections/{}/databases", e2e.conn_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let dbs: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let names: Vec<&str> = dbs.as_array().unwrap().iter().map(|d| d.as_str().unwrap()).collect();
    assert!(names.contains(&"admin"), "mongo: {names:?}");
    assert!(names.contains(&E2E_DB), "mongo: {names:?}");

    // 二级：tables = listCollections（seed collection 在册）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!("/api/gw/connections/{}/tables?db={E2E_DB}", e2e.conn_id),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tables: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let names: Vec<&str> = tables.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&C_SEED), "mongo: {names:?}");

    // 三级：describe = 采样推列（键并集）+ listIndexes（_id_ 唯一索引）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!("/api/gw/connections/{}/describe?db={E2E_DB}&table={C_SEED}", e2e.conn_id),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let desc: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let cols: Vec<&str> =
        desc["columns"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert!(cols.contains(&"name") && cols.contains(&"n"), "mongo: {desc}");
    let col_by_name: std::collections::HashMap<&str, &serde_json::Value> = desc["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap(), c))
        .collect();
    assert_eq!(col_by_name["name"]["type"], "string", "mongo: {desc}");
    assert_eq!(col_by_name["name"]["nullable"], true, "mongo: schemaless → nullable");
    let idx_names: Vec<&str> =
        desc["indexes"].as_array().unwrap().iter().map(|i| i["name"].as_str().unwrap()).collect();
    assert!(idx_names.contains(&"_id_"), "mongo: {desc}");
}

// ── runCommand 语义（独占 C_CMD）──

#[tokio::test]
async fn mongo_run_command_semantics() {
    let Some(e2e) = setup().await else { return };
    reset_collection(&e2e, C_CMD).await;

    // 写命令：affectedRows = 响应 "n"；无行事件。
    let events = run_ok(&e2e, serde_json::json!({"insert": C_CMD, "documents": [
        {"name": "alice", "n": 1},
        {"name": "bob", "n": 2},
    ]}))
    .await;
    let complete = events.last().unwrap();
    assert_eq!(complete.1["affectedRows"], 2, "mongo: {complete:?}");
    assert_eq!(complete.1["rowCount"], 0);
    assert!(!events.iter().any(|(e, _)| e == "rows"), "write must not emit rows");

    // 游标命令：meta 单列 doc + 文档行；kind 判别贯穿事件。
    let events = run_ok(&e2e, serde_json::json!({"find": C_CMD, "sort": {"_id": 1}})).await;
    let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
    assert_eq!(meta.1["kind"], "mongo");
    assert_eq!(meta.1["columns"], serde_json::json!(["doc"]));
    let rows_ev = events.iter().find(|(e, _)| e == "rows").unwrap();
    let rows = rows_ev.1["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0][0]["name"], "alice");
    assert_eq!(rows[1][0]["n"], 2);
    // _id 自动 ObjectId → 扩展 JSON 子文档形态。
    assert!(rows[0][0]["_id"]["$oid"].is_string(), "mongo: {:?}", rows[0]);
    assert_eq!(events.last().unwrap().1["rowCount"], 2);
    assert_eq!(events.last().unwrap().1["truncated"], false);

    // 非游标命令：单文档单列 result（count → {n,…}）。
    let events = run_ok(&e2e, serde_json::json!({"count": C_CMD})).await;
    let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
    assert_eq!(meta.1["columns"], serde_json::json!(["result"]));
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"][0][0]["n"], 2, "mongo: {rows:?}");
    assert_eq!(events.last().unwrap().1["rowCount"], 1);

    // 行限截断（游标路径）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({
                "kind": "mongo", "database": E2E_DB,
                "command": {"find": C_CMD}, "rowLimit": 1
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().1["rowCount"], 1, "mongo: {text}");
    assert_eq!(events.last().unwrap().1["truncated"], true);

    // 错误命令：codeName 透传 engineCode。
    let (text, events) = run_cmd(&e2e, serde_json::json!({"bogusCommandGw": 1})).await;
    assert_eq!(events.last().unwrap().0, "error", "mongo: {text}");
    assert_eq!(events.last().unwrap().1["code"], "DB_ERROR");
    assert_eq!(events.last().unwrap().1["engineCode"], "CommandNotFound", "mongo: {text}");
    assert_eq!(events.last().unwrap().1["kind"], "mongo");

    // 聚合走游标路径。
    let events = run_ok(
        &e2e,
        serde_json::json!({"aggregate": C_CMD, "pipeline": [
            {"$group": {"_id": "$name", "total": {"$sum": "$n"}}},
            {"$sort": {"_id": 1}},
        ], "cursor": {}}),
    )
    .await;
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"].as_array().unwrap().len(), 2, "mongo: {rows:?}");

    // 误配钉边界：mongo 连接 + kind:"sql" → error 事件（非 4xx——kind 合法，
    // 引擎族不匹配在执行层 fail-loud）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({"sql": "SELECT 1", "database": E2E_DB}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "mongo: {text}");
    assert_eq!(events.last().unwrap().1["code"], "UNSUPPORTED_KIND");
}

// ── 只读硬执行（独占 C_RO + 独立 readOnly 连接）──

#[tokio::test]
async fn mongo_readonly_rejects_write_commands() {
    let Some((host, port, user, password)) = mongo_env() else { return };
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "mongo-ro-user");
    let app = router(config, pool.clone());

    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "mongo-e2e-ro",
                "dbType": "mongodb",
                "host": host, "port": port,
                "username": if user.is_empty() { serde_json::Value::Null } else { serde_json::json!(user) },
                "password": if password.is_empty() { serde_json::Value::Null } else { serde_json::json!(password) },
                "defaultDatabase": "admin",
                "readOnly": true,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let ro_conn = v["serverConnId"].as_str().unwrap().to_string();
    let e2e = MongoE2e { app, token, conn_id: ro_conn };

    // 写命令 → DB_ERROR + engineCode READONLY（server 侧硬执行）。
    let (text, events) = run_cmd(&e2e, serde_json::json!({"insert": C_RO, "documents": [{"x": 1}]})).await;
    assert_eq!(events.last().unwrap().0, "error", "mongo: {text}");
    assert_eq!(events.last().unwrap().1["code"], "DB_ERROR");
    assert_eq!(events.last().unwrap().1["engineCode"], "READONLY", "mongo: {text}");

    // 读命令不受影响（seed collection 经 auth 库不查——find 一个 RO 专属
    // 集合，空结果也是 complete）。
    let events = run_ok(&e2e, serde_json::json!({"find": C_RO})).await;
    assert_eq!(events.last().unwrap().1["rowCount"], 0);
}

// ── 类型矩阵（入向普通 JSON / 出向扩展形态；独占 C_TYPES）──

#[tokio::test]
async fn mongo_type_matrix() {
    let Some(e2e) = setup().await else { return };
    reset_collection(&e2e, C_TYPES).await;

    // big = 2^53+1：超出 f64 精确域——JSON 数入 Int64、出 Int64，无损往返。
    let events = run_ok(
        &e2e,
        serde_json::json!({"insert": C_TYPES, "documents": [{
            "i": 5, "big": 9007199254740993i64, "dbl": 1.5,
            "s": "hello", "b": true, "nl": null,
            "arr": [1, "a"], "obj": {"k": "v"},
        }]}),
    )
    .await;
    assert_eq!(events.last().unwrap().1["affectedRows"], 1);

    let events = run_ok(&e2e, serde_json::json!({"find": C_TYPES})).await;
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    let doc = &rows.1["rows"][0][0];
    eprintln!("MONGO_TYPE_MATRIX doc={doc}");
    assert_eq!(doc["i"], 5, "mongo: {doc}");
    assert_eq!(doc["big"], serde_json::json!(9007199254740993i64), "i64 must survive exactly: {doc}");
    assert_eq!(doc["dbl"], 1.5);
    assert_eq!(doc["s"], "hello");
    assert_eq!(doc["b"], true);
    assert_eq!(doc["nl"], serde_json::Value::Null);
    assert_eq!(doc["arr"], serde_json::json!([1, "a"]));
    assert_eq!(doc["obj"]["k"], "v");
    assert!(doc["_id"]["$oid"].is_string());
}

// ── getMore 分页（手工游标循环实跑；独占 C_MORE）──

#[tokio::test]
async fn mongo_cursor_getmore_pagination() {
    let Some(e2e) = setup().await else { return };
    reset_collection(&e2e, C_MORE).await;

    // 5 × 500 文档批量插入。
    for batch in 0..5 {
        let docs: Vec<serde_json::Value> = (0..500)
            .map(|i| serde_json::json!({"batch": batch, "i": i}))
            .collect();
        run_ok(&e2e, serde_json::json!({"insert": C_MORE, "documents": docs})).await;
    }

    // batchSize 100 钉小 → firstBatch 100，其余 2400 走 getMore 循环。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({
                "kind": "mongo", "database": E2E_DB, "rowLimit": 3000,
                "command": {"find": C_MORE, "batchSize": 100, "sort": {"_id": 1}}
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "complete", "mongo: {text}");
    assert_eq!(events.last().unwrap().1["rowCount"], 2500, "mongo: {text}");
    assert_eq!(events.last().unwrap().1["truncated"], false, "mongo: {text}");
    let total: usize = events
        .iter()
        .filter(|(e, _)| e == "rows")
        .map(|(_, d)| d["rows"].as_array().unwrap().len())
        .sum();
    assert_eq!(total, 2500);
}
