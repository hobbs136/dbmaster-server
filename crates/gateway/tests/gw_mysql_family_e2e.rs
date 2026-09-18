//! T22-T25 集成测试：MySQL 协议族四薄适配成员（OceanBase / TiDB /
//! StarRocks / MariaDB）经网关全链路（真库，env 门控）。
//!
//! 门控（对齐 `gw_sqlserver.rs` 模式）：环境变量 `GW_E2E_<FLAVOR>_HOST`
//! 缺失时对应 flavor **跳过而非失败**（普通 `cargo test` 无库照常绿）。
//! 凭据只经 env 读取，不进代码/日志/断言。激活（凭据见仓库外
//! test_db_server.txt）：
//! ```sh
//! GW_E2E_OB_HOST=<ip> GW_E2E_OB_PORT=32880 GW_E2E_OB_USER='root@sys' \
//! GW_E2E_OB_PASSWORD=<pwd> \
//! GW_E2E_TIDB_HOST=<ip> GW_E2E_TIDB_PORT=3400 GW_E2E_TIDB_USER=root \
//! GW_E2E_TIDB_PASSWORD= \
//! GW_E2E_STARROCKS_HOST=<ip> GW_E2E_STARROCKS_PORT=39130 \
//! GW_E2E_STARROCKS_USER=root GW_E2E_STARROCKS_PASSWORD=<pwd> \
//! GW_E2E_MARIADB_HOST=<ip> GW_E2E_MARIADB_PORT=3316 \
//! GW_E2E_MARIADB_USER=root GW_E2E_MARIADB_PASSWORD=<pwd> \
//! cargo test -p dbmaster-gateway --test gw_mysql_family_e2e -- --nocapture
//! ```
//!
//! 覆盖面（每库一致的五项验收）：连接注册族（test 端点 serverVersion +
//! register）/ 树三级钻取（databases 滤库噪音 / tables / describe）/
//! SSE（位置数组行、行限截断、错误透传 engineCode、timeoutMs 超时、
//! X-Execution-Id 取消）/ DML affectedRows。四库共用 MySQL 执行通道，
//! 行为差异全部来自 automation `mysql_family.rs` 的薄适配 profile。
//! 网关日期解码（CH 派生评估① 族级钉定）：family_date_matrix 钉定
//! DATE/DATETIME(3)/TIMESTAMP/TIME 经 chrono 臂的到达字符串形态。

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use sqlx::SqlitePool;
use tower::ServiceExt;

use common::*;

/// 每 flavor 的差异面（与 mysql_family.rs 的 profile 覆写一一对应）。
struct FlavorSpec {
    /// env 前缀（GW_E2E_OB → HOST/PORT/USER/PASSWORD）。
    env: &'static str,
    db_type: &'static str,
    /// serverVersion 期望子串（StarRocks 报 MySQL 兼容版本号，无引擎标记）。
    version_hint: Option<&'static str>,
    /// databases 端点必须滤除的目录噪音库（profile.system_databases 覆写面）。
    noise: &'static [&'static str],
    /// gw_child 建表 DDL（StarRocks 需 DUPLICATE KEY + 单副本）。
    child_ddl: &'static str,
    parent_ddl: &'static str,
    /// UPDATE 可用（StarRocks DUPLICATE 表不支持 UPDATE）。
    update_supported: bool,
    /// describe 期望 FK 非空（StarRocks 无 FK）。
    fk_expected: bool,
    /// 二级索引种子（StarRocks 的 CREATE INDEX 触发后台 schema change，
    /// 表长期 "not normal"——跳过）。
    index_seed: bool,
    /// 坏表名 SELECT 的 engineCode 透传（sqlx 对 MySQL 族透传 SQLSTATE）。
    unknown_table_code: &'static str,
}

fn specs() -> Vec<FlavorSpec> {
    let mut out = Vec::new();
    // T22 OceanBase（sys 租户 MySQL 5.7 模式）：只覆写系统库清单。
    if env_present("GW_E2E_OB_HOST") {
        out.push(FlavorSpec {
            env: "GW_E2E_OB",
            db_type: "oceanbase",
            version_hint: Some("OceanBase"),
            noise: &["oceanbase", "SYS", "LBACSYS", "ORAAUDITOR", "ocs", "sys_external_tbs", "information_schema"],
            parent_ddl: "CREATE TABLE gw_parent (id INT PRIMARY KEY, label VARCHAR(50) NOT NULL)",
            child_ddl: "CREATE TABLE gw_child (id INT PRIMARY KEY, parent_id INT NOT NULL, \
                        name VARCHAR(50) NOT NULL DEFAULT 'anon' COMMENT 'display name', \
                        price DECIMAL(18,2) NOT NULL DEFAULT 0, \
                        CONSTRAINT fk_gw_parent FOREIGN KEY (parent_id) REFERENCES gw_parent(id)) \
                        COMMENT='child table (e2e)'",
            update_supported: true,
            fk_expected: true,
            index_seed: true,
            unknown_table_code: "42S02",
        });
    }
    // T23 TiDB（默认无密码——空密码握手路径一并在注册/查询面验证）。
    if env_present("GW_E2E_TIDB_HOST") {
        out.push(FlavorSpec {
            env: "GW_E2E_TIDB",
            db_type: "tidb",
            version_hint: Some("TiDB"),
            noise: &["INFORMATION_SCHEMA", "PERFORMANCE_SCHEMA", "METRICS_SCHEMA", "information_schema"],
            parent_ddl: "CREATE TABLE gw_parent (id INT PRIMARY KEY, label VARCHAR(50) NOT NULL)",
            child_ddl: "CREATE TABLE gw_child (id INT PRIMARY KEY, parent_id INT NOT NULL, \
                        name VARCHAR(50) NOT NULL DEFAULT 'anon' COMMENT 'display name', \
                        price DECIMAL(18,2) NOT NULL DEFAULT 0, \
                        CONSTRAINT fk_gw_parent FOREIGN KEY (parent_id) REFERENCES gw_parent(id)) \
                        COMMENT='child table (e2e)'",
            update_supported: true,
            fk_expected: true,
            index_seed: true,
            unknown_table_code: "42S02",
        });
    }
    // T24 StarRocks（Doris 同款握手 + 全 raw_sql；事务能力位关闭不在此面）。
    if env_present("GW_E2E_STARROCKS_HOST") {
        out.push(FlavorSpec {
            env: "GW_E2E_STARROCKS",
            db_type: "starrocks",
            version_hint: None, // SELECT VERSION() = MySQL 兼容号（如 8.0.33）
            noise: &["information_schema", "sys", "_statistics_"],
            parent_ddl: "CREATE TABLE gw_parent (id INT NOT NULL, label VARCHAR(50) NOT NULL) \
                         DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 1 \
                         PROPERTIES (\"replication_num\"=\"1\")",
            child_ddl: "CREATE TABLE gw_child (id INT NOT NULL, parent_id INT NOT NULL, \
                        name VARCHAR(50) NOT NULL DEFAULT 'anon' COMMENT 'display name', \
                        price DECIMAL(18,2) NOT NULL) \
                        DUPLICATE KEY(id) COMMENT \"child table (e2e)\" \
                        DISTRIBUTED BY HASH(id) BUCKETS 1 \
                        PROPERTIES (\"replication_num\"=\"1\")",
            update_supported: false,
            fk_expected: false,
            index_seed: false,
            unknown_table_code: "42602",
        });
    }
    // T25 MariaDB（零覆写成员）。
    if env_present("GW_E2E_MARIADB_HOST") {
        out.push(FlavorSpec {
            env: "GW_E2E_MARIADB",
            db_type: "mariadb",
            version_hint: Some("MariaDB"),
            noise: &["information_schema", "performance_schema"],
            parent_ddl: "CREATE TABLE gw_parent (id INT PRIMARY KEY, label VARCHAR(50) NOT NULL)",
            child_ddl: "CREATE TABLE gw_child (id INT PRIMARY KEY, parent_id INT NOT NULL, \
                        name VARCHAR(50) NOT NULL DEFAULT 'anon' COMMENT 'display name', \
                        price DECIMAL(18,2) NOT NULL DEFAULT 0, \
                        CONSTRAINT fk_gw_parent FOREIGN KEY (parent_id) REFERENCES gw_parent(id)) \
                        COMMENT='child table (e2e)'",
            update_supported: true,
            fk_expected: true,
            index_seed: true,
            unknown_table_code: "42S02",
        });
    }
    out
}

fn env_present(key: &str) -> bool {
    std::env::var(key).ok().is_some_and(|v| !v.is_empty())
}

fn flavor_env(spec: &FlavorSpec) -> (String, i64, String, String) {
    let host = std::env::var(format!("{}_HOST", spec.env)).unwrap();
    let port = std::env::var(format!("{}_PORT", spec.env))
        .ok()
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(match spec.db_type {
            "oceanbase" => 2881,
            "tidb" => 4000,
            "starrocks" => 9030,
            _ => 3306,
        });
    let user = std::env::var(format!("{}_USER", spec.env)).unwrap();
    // 空密码（TiDB root）合法：env 设置为空串即无密码。
    let password = std::env::var(format!("{}_PASSWORD", spec.env)).unwrap_or_default();
    (host, port, user, password)
}

fn router(config: std::sync::Arc<dbmaster_core::config::Config>, pool: SqlitePool) -> axum::Router {
    dbmaster_gateway::router(config, pool, [7u8; 32])
}

/// 单 flavor 场景共享态。
struct FamilyE2e {
    tag: &'static str,
    app: axum::Router,
    token: String,
    conn_id: String,
    db: String,
}

/// setup：注册连接（charset/timezone 一并经会话 SET 路径下发）+ 建一次性库
/// 与表/视图/注释种子。密码可为空串（TiDB）。
async fn setup(spec: &FlavorSpec) -> Option<FamilyE2e> {
    let (host, port, user, password) = flavor_env(spec);
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, &format!("{}-e2e-user", spec.db_type));
    let app = router(config, pool.clone());

    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": format!("{}-e2e", spec.db_type),
                "dbType": spec.db_type,
                "host": host,
                "port": port,
                "username": user,
                "password": password,
                "charset": "utf8mb4",
                "timezone": "+00:00",
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "{tag}: register must pass draft validation",
        tag = spec.db_type
    );
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let conn_id = v["serverConnId"].as_str().unwrap().to_string();

    let db = format!(
        "gw_{}_e2e_{}_{}",
        spec.db_type,
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default() % 1_000_000
    );
    let e2e = FamilyE2e { tag: spec.db_type, app, token, conn_id, db };
    let _ = run_sql(&e2e, &format!("DROP DATABASE IF EXISTS {}", e2e.db), None).await;
    run_sql(&e2e, &format!("CREATE DATABASE {}", e2e.db), None).await;
    let db_ctx = e2e.db.clone();
    let mut seeds = vec![
        spec.parent_ddl.to_string(),
        spec.child_ddl.to_string(),
        "CREATE VIEW gw_v AS SELECT id FROM gw_parent".to_string(),
        "INSERT INTO gw_parent (id, label) VALUES (1, 'p1')".to_string(),
        // 两行种子：SSE 行断言/行限/DML 面共用。
        "INSERT INTO gw_child (id, parent_id, name, price) VALUES (1, 1, 'a', 1.5), (2, 1, 'b', 2.5)".to_string(),
    ];
    if spec.index_seed {
        seeds.insert(2, "CREATE INDEX ix_gw_child_name ON gw_child (name)".to_string());
    }
    for sql in seeds {
        run_sql(&e2e, &sql, Some(&db_ctx)).await;
    }
    Some(e2e)
}

async fn teardown(e2e: &FamilyE2e) {
    let _ = run_sql(e2e, &format!("DROP DATABASE IF EXISTS {}", e2e.db), None).await;
}

/// 单条语句经网关执行端点（complete 事件断言）。
async fn run_sql(e2e: &FamilyE2e, sql: &str, db: Option<&str>) -> String {
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
    assert_eq!(resp.status(), StatusCode::OK, "{tag}: {sql}", tag = e2e.tag);
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    assert_eq!(
        events.last().unwrap().0,
        "complete",
        "{tag}: statement failed: {sql} → {text}",
        tag = e2e.tag
    );
    text
}

/// SSE 查询（返回 (SSE 文本, 耗时 ms)）。
async fn query_sse(
    e2e: &FamilyE2e,
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
    assert_eq!(resp.status(), StatusCode::OK, "{tag}: {sql}", tag = e2e.tag);
    let text = body_string(resp.into_body()).await;
    (text, started.elapsed().as_millis())
}

// ── 连接注册族：test 端点（serverVersion）──

#[tokio::test]
async fn family_test_endpoint_returns_server_version() {
    for spec in specs() {
        let (host, port, user, password) = flavor_env(&spec);
        let config = test_config(GwKnobs::default());
        let pool = server_pool().await;
        let token = token_for(&config, &format!("{}-test-user", spec.db_type));
        let app = router(config, pool.clone());

        let resp = app
            .clone()
            .oneshot(authed_post_json(
                &token,
                "/api/gw/connections/test",
                serde_json::json!({
                    "dbType": spec.db_type,
                    "host": host,
                    "port": port,
                    "username": user,
                    "password": password,
                })
                .to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{tag}", tag = spec.db_type);
        let v: serde_json::Value =
            serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
        assert_eq!(v["ok"], true, "{tag}: {v}", tag = spec.db_type);
        let version = v["serverVersion"].as_str().unwrap_or_default();
        if let Some(hint) = spec.version_hint {
            assert!(
                version.contains(hint),
                "{tag}: serverVersion '{version}' must contain '{hint}'",
                tag = spec.db_type
            );
        } else {
            // StarRocks 报 MySQL 兼容版本号——只断言非空数字形态。
            assert!(!version.is_empty() && version.contains('.'), "{tag}: {version}", tag = spec.db_type);
        }
    }
}

// ── 树三级钻取 + SSE 基础语义 + DML affectedRows ──

#[tokio::test]
async fn family_tree_drill_and_sse_semantics() {
    for spec in specs() {
        let Some(e2e) = setup(&spec).await else { return };
        let tag = e2e.tag;
        let db = e2e.db.clone();

        // 一级：databases 滤库噪音、含一次性库。
        let resp = e2e
            .app
            .clone()
            .oneshot(authed_get(&e2e.token, &format!("/api/gw/connections/{}/databases", e2e.conn_id)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let dbs: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
        let names: Vec<&str> = dbs.as_array().unwrap().iter().map(|d| d.as_str().unwrap()).collect();
        assert!(names.contains(&db.as_str()), "{tag}: e2e db missing: {names:?}", tag = tag);
        for noise in spec.noise {
            assert!(!names.contains(noise), "{tag}: noise db {noise} must be filtered: {names:?}", tag = tag);
        }

        // 二级：tables —— kind（table/view）+ comment。
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
        assert_eq!(by_name["gw_child"]["type"], "table", "{tag}", tag = tag);
        assert_eq!(by_name["gw_child"]["comment"], "child table (e2e)", "{tag}", tag = tag);
        assert_eq!(by_name["gw_v"]["type"], "view", "{tag}: {tables}", tag = tag);
        // 视图无行数估计：多数库 NULL（键省略）；OB 对视图报 0——两者皆可。
        assert!(
            by_name["gw_v"].get("rowEstimate").is_none()
                || by_name["gw_v"]["rowEstimate"].as_i64() == Some(0),
            "{tag}: view rowEstimate must be absent or 0: {tables}",
            tag = tag
        );

        // 三级：describe —— 列（类型/默认值/注释）+ PK + 索引 + FK。
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
        assert_eq!(desc["comment"], "child table (e2e)", "{tag}", tag = tag);
        let cols: Vec<&str> =
            desc["columns"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(cols, vec!["id", "parent_id", "name", "price"], "{tag}", tag = tag);
        let col_by_name: serde_json::Map<String, serde_json::Value> = desc["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["name"].as_str().unwrap().to_string(), c.clone()))
            .collect();
        assert!(
            col_by_name["name"]["type"].as_str().unwrap().starts_with("varchar(50)"),
            "{tag}: {col_by_name:?}",
            tag = tag
        );
        assert!(
            col_by_name["price"]["type"]
                .as_str()
                .unwrap()
                .replace(' ', "")
                .starts_with("decimal(18,2)"),
            // StarRocks 的 column_type 带空格（decimal(18, 2)），归一后比对。
            "{tag}: {col_by_name:?}",
            tag = tag
        );
        assert_eq!(col_by_name["parent_id"]["nullable"], false, "{tag}", tag = tag);
        assert!(
            col_by_name["name"]["defaultValue"].as_str().unwrap().contains("anon"),
            "{tag}: defaultValue shape varies (quoted vs bare) — accept both",
            tag = tag
        );
        assert_eq!(col_by_name["name"]["comment"], "display name", "{tag}", tag = tag);
        if spec.fk_expected {
            assert_eq!(desc["primaryKey"], serde_json::json!(["id"]), "{tag}", tag = tag);
            let ix: serde_json::Map<String, serde_json::Value> = desc["indexes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| (i["name"].as_str().unwrap().to_string(), i.clone()))
                .collect();
            assert!(
                ix.contains_key("ix_gw_child_name"),
                "{tag}: secondary index missing: {ix:?}",
                tag = tag
            );
            assert_eq!(ix["ix_gw_child_name"]["columns"], serde_json::json!(["name"]), "{tag}", tag = tag);
            assert_eq!(ix["ix_gw_child_name"]["unique"], false, "{tag}", tag = tag);
            let fk = &desc["foreignKeys"][0];
            assert_eq!(fk["name"], "fk_gw_parent", "{tag}: {fk:?} (MariaDB/TiDB 名列一致)", tag = tag);
            assert_eq!(fk["columns"], serde_json::json!(["parent_id"]), "{tag}", tag = tag);
            assert_eq!(fk["refTable"], "gw_parent", "{tag}", tag = tag);
            assert_eq!(fk["refColumns"], serde_json::json!(["id"]), "{tag}", tag = tag);
        } else {
            // StarRocks：DUPLICATE 表无 PK/FK/二级索引目录（空集合键整体省略）。
            assert!(desc.get("primaryKey").is_none(), "{tag}: {desc}", tag = tag);
            assert!(desc.get("foreignKeys").is_none(), "{tag}: {desc}", tag = tag);
        }

        // SSE：空结果 = meta（空列数组）+ complete 0 行。
        let (text, _) = query_sse(&e2e, "SELECT id, name FROM gw_child WHERE 1 = 0", Some(&db), None).await;
        let events = parse_sse(&text);
        let kinds: Vec<&str> = events.iter().map(|(e, _)| e.as_str()).collect();
        assert_eq!(kinds, vec!["meta", "complete"], "{tag}: {text}", tag = tag);
        assert_eq!(events[0].1["columns"], serde_json::json!([]), "{tag}", tag = tag);
        assert_eq!(events[1].1["rowCount"], 0, "{tag}", tag = tag);

        // 位置数组行 + 类型解码（int → 数字）。DECIMAL 直读会落 null
        // （sqlx 对 NewDecimal 只开 bigdecimal/rust_decimal feature 才解码，
        // 全族既有缺口非本批引入——见任务记录），经 CAST AS CHAR 走字符串
        // 通道验证取值链；尾零形态各库不一（"1.5" vs "1.50"），断言前缀。
        let (text, _) =
            query_sse(&e2e, "SELECT id, name, CAST(price AS CHAR) AS price FROM gw_child ORDER BY id", Some(&db), None).await;
        let events = parse_sse(&text);
        let rows_ev = events.iter().find(|(e, _)| e == "rows").unwrap();
        let rows = rows_ev.1["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "{tag}", tag = tag);
        assert_eq!(rows[0][0], 1, "{tag}", tag = tag);
        assert_eq!(rows[0][1], "a", "{tag}", tag = tag);
        assert!(rows[0][2].as_str().unwrap_or("").starts_with("1.5"), "{tag}: {rows:?}", tag = tag);
        assert_eq!(rows[1][0], 2, "{tag}", tag = tag);
        assert_eq!(rows[1][1], "b", "{tag}", tag = tag);
        assert!(rows[1][2].as_str().unwrap_or("").starts_with("2.5"), "{tag}: {rows:?}", tag = tag);
        let complete = events.last().unwrap();
        assert_eq!(complete.1["rowCount"], 2, "{tag}", tag = tag);
        assert_eq!(complete.1["truncated"], false, "{tag}", tag = tag);

        // 行限截断。
        let mut limited = serde_json::Map::new();
        limited.insert("rowLimit".into(), serde_json::json!(1));
        let (text, _) =
            query_sse(&e2e, "SELECT id FROM gw_child ORDER BY id", Some(&db), Some(limited)).await;
        let events = parse_sse(&text);
        let complete = events.last().unwrap();
        assert_eq!(complete.1["rowCount"], 1, "{tag}", tag = tag);
        assert_eq!(complete.1["truncated"], true, "{tag}", tag = tag);

        // 坏 SQL → DB_ERROR + engineCode（各库引擎原始码透传）。
        let (text, _) = query_sse(&e2e, "SELECT * FROM gw_nope", Some(&db), None).await;
        let events = parse_sse(&text);
        assert_eq!(events.last().unwrap().0, "error", "{tag}: {text}", tag = tag);
        assert_eq!(events.last().unwrap().1["code"], "DB_ERROR", "{tag}", tag = tag);
        assert_eq!(
            events.last().unwrap().1["engineCode"].as_str().unwrap(),
            spec.unknown_table_code,
            "{tag}: engineCode must be the engine-native code",
            tag = tag
        );

        // DML affectedRows：INSERT 已在 setup；UPDATE/DELETE 面（StarRocks 无 UPDATE）。
        if spec.update_supported {
            let text = run_sql(&e2e, "UPDATE gw_child SET price = 9.9 WHERE id = 2", Some(&db)).await;
            let events = parse_sse(&text);
            assert_eq!(events.last().unwrap().1["affectedRows"], 1, "{tag}", tag = tag);
            let text = run_sql(&e2e, "DELETE FROM gw_child WHERE id = 2", Some(&db)).await;
            let events = parse_sse(&text);
            assert_eq!(events.last().unwrap().1["affectedRows"], 1, "{tag}", tag = tag);
        } else {
            // StarRocks：INSERT 后表短暂处于 schema-change 态（DELETE 报
            // "Table's state is not normal"），轮询重试至态恢复。
            let mut events = Vec::new();
            for _ in 0..10 {
                let mut body = serde_json::Map::new();
                body.insert("sql".into(), serde_json::json!("DELETE FROM gw_child WHERE id = 2"));
                body.insert("database".into(), serde_json::json!(&db));
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
                let text = body_string(resp.into_body()).await;
                events = parse_sse(&text);
                if events.last().unwrap().0 == "complete" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(700)).await;
            }
            assert_eq!(
                events.last().unwrap().0,
                "complete",
                "{tag}: DELETE must eventually succeed",
                tag = tag
            );
            // StarRocks DELETE 是标记删除，affected 数形态不保证——只断言键存在。
            assert!(events.last().unwrap().1["affectedRows"].is_u64(), "{tag}", tag = tag);
        }

        teardown(&e2e).await;
    }
}

// ── 超时/取消语义（SLEEP 族函数；超时/取消后执行池 drop 断连终止查询）──

#[tokio::test]
async fn family_timeout_fires_promptly_on_sleep() {
    for spec in specs() {
        let Some(e2e) = setup(&spec).await else { return };
        let mut body = serde_json::Map::new();
        body.insert("database".into(), serde_json::json!(e2e.db));
        body.insert("timeoutMs".into(), serde_json::json!(1500));
        let (text, elapsed) = query_sse(&e2e, "SELECT SLEEP(20)", None, Some(body)).await;

        let events = parse_sse(&text);
        assert_eq!(events.last().unwrap().0, "error", "{tag}: {text}", tag = e2e.tag);
        assert_eq!(events.last().unwrap().1["code"], "TIMEOUT", "{tag}", tag = e2e.tag);
        // 20s 的语句 1.5s 超时返回（容差给慢握手环境）。
        assert!(elapsed < 6500, "{tag}: timeout must return promptly, took {elapsed}ms", tag = e2e.tag);
        teardown(&e2e).await;
    }
}

#[tokio::test]
async fn family_cancel_fires_promptly_on_sleep() {
    for spec in specs() {
        let Some(e2e) = setup(&spec).await else { return };
        let exec_id = "33333333-3333-4333-8333-333333333333";
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/gw/connections/{}/query", e2e.conn_id))
            .header("Authorization", format!("Bearer {}", e2e.token))
            .header("Content-Type", "application/json")
            .header("X-Execution-Id", exec_id)
            .body(axum::body::Body::from(
                serde_json::json!({
                    "sql": "SELECT SLEEP(30)",
                    "database": e2e.db,
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
        assert_eq!(events.last().unwrap().0, "error", "{tag}: {text}", tag = e2e.tag);
        assert_eq!(events.last().unwrap().1["code"], "CANCELLED", "{tag}: {text}", tag = e2e.tag);
        teardown(&e2e).await;
    }
}

// ── 网关日期解码矩阵（CH 派生评估①：DATE/DATETIME/TIMESTAMP/TIME 经
// chrono 臂的到达形态；此前族级落 null 且 e2e 零覆盖）──
//
// TIMESTAMP 钉定依赖会话时区 '+00:00'（setup 注册参数，经会话 SET 下发）：
// 插入与回读同墙钟，断言确定。StarRocks 无 TIME 列类型、建表需 DUPLICATE
// KEY 形态——该 flavor 只钉 DATE/DATETIME。

#[tokio::test]
async fn family_date_matrix() {
    for spec in specs() {
        let Some(e2e) = setup(&spec).await else { return };
        let starrocks = spec.db_type == "starrocks";
        let ddl = if starrocks {
            "CREATE TABLE gw_type_dates (id INT NOT NULL, d DATE, dtm DATETIME(3)) \
             DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 1 \
             PROPERTIES (\"replication_num\"=\"1\")"
        } else {
            "CREATE TABLE gw_type_dates (id INT PRIMARY KEY, d DATE, dtm DATETIME(3), \
             ts TIMESTAMP NULL, tm TIME)"
        };
        run_sql(&e2e, ddl, Some(&e2e.db)).await;
        let insert = if starrocks {
            "INSERT INTO gw_type_dates VALUES (1, '2026-08-27', '2026-08-27 12:34:56.789')"
        } else {
            "INSERT INTO gw_type_dates VALUES (1, '2026-08-27', '2026-08-27 12:34:56.789', \
             '2026-08-27 12:34:56', '12:34:56')"
        };
        run_sql(&e2e, insert, Some(&e2e.db)).await;

        let (text, _) = query_sse(&e2e, "SELECT * FROM gw_type_dates", Some(&e2e.db), None).await;
        let events = parse_sse(&text);
        assert_eq!(events.last().unwrap().0, "complete", "{tag}: {text}", tag = e2e.tag);
        let meta = events.iter().find(|(e, _)| e == "meta").unwrap();
        let columns: Vec<&str> = meta.1["columns"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
        let row = events
            .iter()
            .find(|(e, _)| e == "rows")
            .unwrap()
            .1["rows"][0]
            .as_array()
            .unwrap()
            .clone();
        let cell = |name: &str| row[columns.iter().position(|c| *c == name).unwrap()].clone();

        // SQL 惯例空格分隔、自动小数位；TIMESTAMP = DateTime<Utc> 臂按 UTC
        // 墙钟渲染（会话时区 +00:00 下同插入墙钟）；TIME = NaiveTime 臂。
        assert_eq!(cell("d"), "2026-08-27", "{tag}: {row:?}", tag = e2e.tag);
        assert_eq!(cell("dtm"), "2026-08-27 12:34:56.789", "{tag}: {row:?}", tag = e2e.tag);
        if !starrocks {
            assert_eq!(cell("ts"), "2026-08-27 12:34:56", "{tag}: {row:?}", tag = e2e.tag);
            assert_eq!(cell("tm"), "12:34:56", "{tag}: {row:?}", tag = e2e.tag);
        }
        teardown(&e2e).await;
    }
}
