//! T29 非 SQL 批次（B3）集成测试：Redis 经网关全链路（真库，env 门控）。
//!
//! 语义（ADR-0006 §2.3/§2.5/§2.6）：kind:"redis" 命令/pipeline 通道——
//! - 单命令：白名单结构化命令（SCAN/HGETALL/ZRANGE WITHSCORES…）语义列展平，
//!   其余 fallback 单列 result（RESP→JSON：int→number、bulk→string、
//!   nil→null、status→string）；RESP error → error 事件（engineCode=
//!   WRONGTYPE 等）；database 字段 = db index 路由（SELECT）；
//! - pipeline：[index, result] 两列逐条返回；atomic = MULTI/EXEC 包裹；
//! - 只读硬执行：read_only 连接拒写/危险命令（静态表 + ACL CAT 缓存），
//!   engineCode=READONLY；
//! - 订阅转发 SSE：GET /connections/{id}/redis/subscriptions（subscribed/
//!   message 事件；publish 走命令通道；上限 64；keyspace 通知闭环）；
//! - 元数据：databases（CONFIG GET databases）/ tables（SCAN 命名空间）/
//!   describe（TYPE 推列）。
//!
//! 门控（对齐 `gw_mongodb.rs` 模式）：环境变量 `GW_E2E_REDIS_HOST` 缺失时
//! **跳过而非失败**。凭据只经 env 读取，不进代码/日志/断言。激活（凭据见
//! 仓库外 test_db_server.txt）：
//! ```sh
//! GW_E2E_REDIS_HOST=<ip> GW_E2E_REDIS_PORT=6379 GW_E2E_REDIS_PASSWORD=<pwd> \
//! cargo test -p dbmaster-gateway --test gw_redis -- --nocapture
//! ```
//!
//! exe 体积增量（B3.1，ADR-0006 §4 风险项登记）：B2 后基线 20,095,488 B
//! → 引入 redis 1.6 crate 后 **20,697,600 B（+602,112 B ≈ +588 KiB）**
//!（2026-08-27 实测，同机同 profile——远轻于 mongodb 的 +3.34 MiB）。
//!
//! 并行隔离：写数据的测试用 `gw_b3*` 前缀 key（命令族共享 gw_b3:、树钻取
//! 独占 gw_b3t:、订阅独占 channel 名）；真库跑建议 `--test-threads=1`
//!（同前缀 key 的清场/写入串行化，避免 SCAN 采到他人半态）。

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use sqlx::SqlitePool;
use tower::ServiceExt;

use common::*;

fn redis_env() -> Option<(String, i64, String)> {
    let host = std::env::var("GW_E2E_REDIS_HOST").ok().filter(|v| !v.is_empty())?;
    let port = std::env::var("GW_E2E_REDIS_PORT")
        .ok()
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(6379);
    let password = std::env::var("GW_E2E_REDIS_PASSWORD").unwrap_or_default();
    Some((host, port, password))
}

fn router(config: std::sync::Arc<dbmaster_core::config::Config>, pool: SqlitePool) -> axum::Router {
    dbmaster_gateway::router(config, pool, [7u8; 32])
}

struct RedisE2e {
    app: axum::Router,
    token: String,
    conn_id: String,
}

async fn setup() -> Option<RedisE2e> {
    let (host, port, password) = redis_env()?;
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "redis-e2e-user");
    let app = router(config, pool.clone());

    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "redis-e2e",
                "dbType": "redis",
                "host": host,
                "port": port,
                "password": if password.is_empty() { serde_json::Value::Null } else { serde_json::json!(password) },
                "defaultDatabase": "0",
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "redis: register must pass");
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let conn_id = v["serverConnId"].as_str().unwrap().to_string();
    Some(RedisE2e { app, token, conn_id })
}

/// 第二条 readOnly 连接（只读硬执行用例）。
async fn setup_read_only() -> Option<RedisE2e> {
    let (host, port, password) = redis_env()?;
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "redis-ro-user");
    let app = router(config, pool.clone());
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "redis-e2e-ro",
                "dbType": "redis",
                "host": host,
                "port": port,
                "password": if password.is_empty() { serde_json::Value::Null } else { serde_json::json!(password) },
                "defaultDatabase": "0",
                "readOnly": true,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    Some(RedisE2e {
        app,
        token,
        conn_id: v["serverConnId"].as_str().unwrap().to_string(),
    })
}

/// kind:"redis" 命令（断言 complete 终态，返回 SSE 文本）。
async fn run_cmd(e2e: &RedisE2e, command: serde_json::Value) -> String {
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({ "kind": "redis", "command": command }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "redis: {command:?}");
    body_string(resp.into_body()).await
}

async fn run_cmd_ok(e2e: &RedisE2e, command: serde_json::Value) -> Vec<(String, serde_json::Value)> {
    let text = run_cmd(e2e, command.clone()).await;
    let events = parse_sse(&text);
    assert_eq!(
        events.last().unwrap().0,
        "complete",
        "redis: command failed: {command:?} → {text}"
    );
    events
}

// ── test 端点（INFO server 版本）──

#[tokio::test]
async fn redis_test_endpoint_returns_server_version() {
    let Some((host, port, password)) = redis_env() else { return };
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "redis-test-user");
    let app = router(config, pool.clone());
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections/test",
            serde_json::json!({
                "dbType": "redis",
                "host": host,
                "port": port,
                "password": if password.is_empty() { serde_json::Value::Null } else { serde_json::json!(password) },
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["ok"], true, "redis: {v}");
    let version = v["serverVersion"].as_str().unwrap_or_default();
    assert!(!version.is_empty() && version.contains('.'), "redis: {version}");
}

// ── 命令语义（fallback / 语义列 / nil / engineCode / db 路由）──

#[tokio::test]
async fn redis_command_semantics() {
    let Some(e2e) = setup().await else { return };
    let _ = run_cmd_ok(&e2e, serde_json::json!(["DEL", "gw_b3:k"])).await;

    // SET（status OK）→ fallback 单列 result。
    let events = run_cmd_ok(&e2e, serde_json::json!(["SET", "gw_b3:k", "hello"])).await;
    let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
    assert_eq!(meta.1["kind"], "redis");
    assert_eq!(meta.1["columns"], serde_json::json!(["result"]));
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"], serde_json::json!([["OK"]]));

    // GET → 字符串单值；DEL → 整数行。
    let events = run_cmd_ok(&e2e, serde_json::json!(["GET", "gw_b3:k"])).await;
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"], serde_json::json!([["hello"]]));

    let events = run_cmd_ok(&e2e, serde_json::json!(["DEL", "gw_b3:k"])).await;
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"], serde_json::json!([[1]]));

    // 不存在的 key → nil 单行。
    let events = run_cmd_ok(&e2e, serde_json::json!(["GET", "gw_b3:missing"])).await;
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"], serde_json::json!([[null]]));

    // RESP error → error 事件（engineCode = WRONGTYPE）。
    let _ = run_cmd_ok(&e2e, serde_json::json!(["SET", "gw_b3:s", "x"])).await;
    let text = run_cmd(&e2e, serde_json::json!(["LPUSH", "gw_b3:s", "y"])).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "redis: {text}");
    assert_eq!(events.last().unwrap().1["code"], "DB_ERROR");
    assert_eq!(events.last().unwrap().1["engineCode"], "WRONGTYPE", "redis: {text}");
    assert_eq!(events.last().unwrap().1["kind"], "redis");

    // 语义列：SCAN [cursor, key]。
    let _ = run_cmd_ok(&e2e, serde_json::json!(["SADD", "gw_b3:ns", "a"])).await;
    let events = run_cmd_ok(
        &e2e,
        serde_json::json!(["SCAN", "0", "MATCH", "gw_b3:ns", "COUNT", "100"]),
    )
    .await;
    let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
    assert_eq!(meta.1["columns"], serde_json::json!(["cursor", "key"]));
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"][0][1], "gw_b3:ns");

    // 语义列：HGETALL [field, value]。
    let _ = run_cmd_ok(&e2e, serde_json::json!(["DEL", "gw_b3:h"])).await;
    let _ = run_cmd_ok(&e2e, serde_json::json!(["HSET", "gw_b3:h", "a", "1", "b", "2"])).await;
    let events = run_cmd_ok(&e2e, serde_json::json!(["HGETALL", "gw_b3:h"])).await;
    let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
    assert_eq!(meta.1["columns"], serde_json::json!(["field", "value"]));

    // 语义列：ZRANGE WITHSCORES [member, score]。
    let _ = run_cmd_ok(&e2e, serde_json::json!(["DEL", "gw_b3:z"])).await;
    let _ = run_cmd_ok(&e2e, serde_json::json!(["ZADD", "gw_b3:z", "1.5", "m1", "2.5", "m2"])).await;
    let events = run_cmd_ok(
        &e2e,
        serde_json::json!(["ZRANGE", "gw_b3:z", "0", "-1", "WITHSCORES"]),
    )
    .await;
    let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
    assert_eq!(meta.1["columns"], serde_json::json!(["member", "score"]));
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"][0], serde_json::json!(["m1", 1.5]));

    // db 路由：database "1" 写入，db 0 不可见、db 1 可见。
    let _ = run_cmd_ok(&e2e, serde_json::json!(["DEL", "gw_b3:dbone"])).await;
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({
                "kind": "redis", "database": "1",
                "command": ["SET", "gw_b3:dbone", "v1"]
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(parse_sse(&body_string(resp.into_body()).await).last().unwrap().0, "complete");

    let events = run_cmd_ok(&e2e, serde_json::json!(["GET", "gw_b3:dbone"])).await;
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"], serde_json::json!([[null]]), "db0 must not see db1 key");

    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({
                "kind": "redis", "database": "1",
                "command": ["GET", "gw_b3:dbone"]
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let events = parse_sse(&body_string(resp.into_body()).await);
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"], serde_json::json!([["v1"]]));
}

// ── pipeline（[index, result] + atomic MULTI/EXEC）──

#[tokio::test]
async fn redis_pipeline_semantics() {
    let Some(e2e) = setup().await else { return };
    let _ = run_cmd_ok(&e2e, serde_json::json!(["DEL", "gw_b3:counter"])).await;

    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({
                "kind": "redis",
                "pipeline": [
                    ["INCR", "gw_b3:counter"],
                    ["INCR", "gw_b3:counter"],
                    ["SET", "gw_b3:pv", "ok"],
                ],
                "atomic": false
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "complete", "redis: {text}");
    let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
    assert_eq!(meta.1["columns"], serde_json::json!(["index", "result"]));
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(
        rows.1["rows"],
        serde_json::json!([[0, 1], [1, 2], [2, "OK"]]),
        "redis: {text}"
    );

    // atomic：MULTI/EXEC 包裹（结果逐条返回）。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_post_json(
            &e2e.token,
            &format!("/api/gw/connections/{}/query", e2e.conn_id),
            serde_json::json!({
                "kind": "redis",
                "pipeline": [
                    ["INCR", "gw_b3:counter"],
                    ["GET", "gw_b3:pv"],
                ],
                "atomic": true
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "complete", "redis: {text}");
    let rows = events.iter().find(|(e, _)| e == "rows").unwrap();
    assert_eq!(rows.1["rows"], serde_json::json!([[0, 3], [1, "ok"]]), "redis: {text}");
}

// ── 只读硬执行（read_only 连接拒写/危险；GET 放行）──

#[tokio::test]
async fn redis_readonly_rejects_write_and_dangerous() {
    let Some(ro) = setup_read_only().await else { return };
    async fn ro_cmd(
        ro: &RedisE2e,
        command: serde_json::Value,
    ) -> String {
        let resp = ro
            .app
            .clone()
            .oneshot(authed_post_json(
                &ro.token,
                &format!("/api/gw/connections/{}/query", ro.conn_id),
                serde_json::json!({ "kind": "redis", "command": command }).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        body_string(resp.into_body()).await
    }

    // 写命令（静态表命中）→ READONLY。
    let text = ro_cmd(&ro, serde_json::json!(["SET", "gw_b3:ro", "x"])).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "error", "redis: {text}");
    assert_eq!(events.last().unwrap().1["code"], "DB_ERROR");
    assert_eq!(events.last().unwrap().1["engineCode"], "READONLY", "redis: {text}");

    // 危险命令（KEYS，对齐客户端 validateCommand 语义）→ READONLY。
    let text = ro_cmd(&ro, serde_json::json!(["KEYS", "*"])).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().1["engineCode"], "READONLY", "redis: {text}");

    // 读命令放行。
    let text = ro_cmd(&ro, serde_json::json!(["GET", "gw_b3:ro"])).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "complete", "redis: {text}");
}

// ── 元数据三级（databases / tables 命名空间 / describe TYPE 推列）──

#[tokio::test]
async fn redis_tree_drill() {
    let Some(e2e) = setup().await else { return };
    // 种子：专属命名空间（SCAN 顺序不定，测试不与其他用例的 key 混采）——
    // gw_b3t 为 string 命名空间。
    let _ = run_cmd_ok(&e2e, serde_json::json!(["SET", "gw_b3t:s1", "alice"])).await;

    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(&e2e.token, &format!("/api/gw/connections/{}/databases", e2e.conn_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let dbs: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let names: Vec<&str> = dbs.as_array().unwrap().iter().map(|d| d.as_str().unwrap()).collect();
    assert!(names.contains(&"0"), "redis: {names:?}");

    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!("/api/gw/connections/{}/tables?db=0", e2e.conn_id),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tables: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let names: Vec<&str> = tables.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"gw_b3t"), "redis: {names:?}");

    // describe：gw_b3t 命名空间首个 key 是 string → 单 value 列。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!("/api/gw/connections/{}/describe?db=0&table=gw_b3t", e2e.conn_id),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let desc: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let cols: Vec<&str> =
        desc["columns"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(cols, vec!["value"], "redis: {desc}");

    let _ = run_cmd_ok(&e2e, serde_json::json!(["DEL", "gw_b3t:s1"])).await;
}

// ── 订阅转发 SSE（subscribed/message + publish 走命令通道 + psubscribe）──

#[tokio::test]
async fn redis_subscription_forwarding() {
    let Some(e2e) = setup().await else { return };

    // 订阅流（并发消费 body——SSE 会阻塞直到消息/断开）。
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "/api/gw/connections/{}/redis/subscriptions?channels=gw_b3:ch&patterns=gw_b3:pat*",
            e2e.conn_id
        ))
        .header("Authorization", format!("Bearer {}", e2e.token))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = e2e.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let consumer = tokio::spawn(async move { body_string(resp.into_body()).await });

    // 等 subscribed 确认送达（连接建立 + 订阅生效）。
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = run_cmd_ok(&e2e, serde_json::json!(["PUBLISH", "gw_b3:ch", "hello"])).await;
    let _ = run_cmd_ok(&e2e, serde_json::json!(["PUBLISH", "gw_b3:pat1", "pmatch"])).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 结束订阅：删连接触发注册表取消（流终止 → consumer 收尾）。
    let del = e2e
        .app
        .clone()
        .oneshot(authed_delete(&e2e.token, &format!("/api/gw/connections/{}", e2e.conn_id)))
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    let text = consumer.await.unwrap();
    let events = parse_sse(&text);
    let names: Vec<&str> = events.iter().map(|(e, _)| e.as_str()).collect();
    assert!(names.contains(&"subscribed"), "redis: {names:?} / {text}");
    assert!(names.contains(&"message"), "redis: {names:?} / {text}");

    let subscribed = events.iter().find(|(e, _)| e == "subscribed").unwrap();
    assert_eq!(subscribed.1["channels"], serde_json::json!(["gw_b3:ch"]));
    assert_eq!(subscribed.1["patterns"], serde_json::json!(["gw_b3:pat*"]));

    let messages: Vec<&serde_json::Value> = events
        .iter()
        .filter(|(e, _)| e == "message")
        .map(|(_, d)| d)
        .collect();
    assert!(
        messages.iter().any(|m| m["channel"] == "gw_b3:ch" && m["payload"] == "hello"),
        "redis: {messages:?}"
    );
    // psubscribe 命中的消息带 pattern 字段。
    assert!(
        messages
            .iter()
            .any(|m| m["channel"] == "gw_b3:pat1" && m["pattern"] == "gw_b3:pat*"),
        "redis: {messages:?}"
    );
}

/// keyspace 通知闭环：CONFIG SET（命令通道）+ psubscribe `__keyevent@0__:del`
/// + DEL → message 事件（ADR-0006 §2.5）。
#[tokio::test]
async fn redis_keyspace_notification_roundtrip() {
    let Some(e2e) = setup().await else { return };

    // 开启 keyevent 通知（E = 键事件通知，x = 过期；此处用 Ex 的 DEL 事件
    // 需要 E + 具体事件字母——DEL 属 keyspace 通用事件用 EA）。
    let _ = run_cmd_ok(&e2e, serde_json::json!(["CONFIG", "SET", "notify-keyspace-events", "EA"])).await;
    let _ = run_cmd_ok(&e2e, serde_json::json!(["SET", "gw_b3:gone", "x"])).await;

    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "/api/gw/connections/{}/redis/subscriptions?patterns=__keyevent@0__:del",
            e2e.conn_id
        ))
        .header("Authorization", format!("Bearer {}", e2e.token))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = e2e.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let consumer = tokio::spawn(async move { body_string(resp.into_body()).await });

    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = run_cmd_ok(&e2e, serde_json::json!(["DEL", "gw_b3:gone"])).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let del = e2e
        .app
        .clone()
        .oneshot(authed_delete(&e2e.token, &format!("/api/gw/connections/{}", e2e.conn_id)))
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    let text = consumer.await.unwrap();
    let events = parse_sse(&text);
    let hit = events.iter().any(|(e, d)| {
        e == "message" && d["channel"] == "__keyevent@0__:del" && d["payload"] == "gw_b3:gone"
    });
    assert!(hit, "redis keyspace: {text}");
}

/// 上限 64：65 个 channel → 400。
#[tokio::test]
async fn redis_subscription_limit_is_400() {
    let Some(e2e) = setup().await else { return };
    let mut uri = format!(
        "/api/gw/connections/{}/redis/subscriptions?",
        e2e.conn_id
    );
    for i in 0..65 {
        uri.push_str(&format!("channels=ch{i}"));
        if i < 64 {
            uri.push('&');
        }
    }
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(&e2e.token, &uri))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["error"]["code"], "CONFIG");

    // 空订阅目标 → 400。
    let resp = e2e
        .app
        .clone()
        .oneshot(authed_get(
            &e2e.token,
            &format!("/api/gw/connections/{}/redis/subscriptions", e2e.conn_id),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
