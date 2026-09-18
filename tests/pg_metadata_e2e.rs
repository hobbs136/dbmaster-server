//! Real-DB e2e for the PostgreSQL metadata surface (multi-schema enumeration +
//! `schema.table` addressing).
//!
//! 修复的缺陷：`list_tables` 只在 `public` 里列举、`describe_table` 的
//! `to_regclass('public.' || ...)` 硬编码 public 前缀——非 public schema 的
//! 对象**既不可枚举也不可寻址**。本测试对着真库钉死修复后的行为。
//!
//! Env-gated（照抄 `crates/drift/tests/real_db_e2e.rs` 的模式）：环境变量缺失
//! 即 skip（打印 `[skip]` 并返回），**不失败**——`cargo test` 在无库环境下
//! 仍然全绿。真跑（占位符替换为实际值；**凭据只经 env 传入，不进代码/注释/
//! 日志/断言**——示例凭据见工作区 `test_db_server.txt`，不在本仓库）：
//!
//! ```sh
//! DBMASTER_META_PG_HOST=<pg-host> \
//! DBMASTER_META_PG_PORT=<pg-port> \
//! DBMASTER_META_PG_USER=<pg-user> \
//! DBMASTER_META_PG_PASSWORD=<pg-password> \
//! DBMASTER_META_PG_DATABASE=postgres \
//!   cargo test -p dbmaster-server --test pg_metadata_e2e -- --nocapture
//! ```
//!
//! 为什么用分字段环境变量而不是单条 URL：sqlx 0.8 的 `PgConnectOptions`
//! **刻意不提供**密码读取接口（`get_password` 不存在，防凭据外泄），URL
//! 形态拿不回密码去填 `database_connections.password_encrypted`；分字段形态
//! 同时免掉密码里 `@` 的 URL 编码负担。
//!
//! 断言面（对应验收 3）：
//! - `list_tables` 跨 schema 枚举（含 `ecommerce.orders`），且不含任何
//!   `pg_catalog` / `information_schema` / `pg_toast%` 对象；
//! - `describe_table("ecommerce.orders")` 命中（列含 id/total + 主键），不再
//!   NOT_FOUND；
//! - 裸名 `describe_table("brands")` 与限定名 `describe_table("public.users")`
//!   都命中（两种寻址形态的兼容性）。

use dbmaster_automation::metadata;
use sqlx::SqlitePool;

/// 目标库（`list_tables` 的 database 参数）——env 未给 database 时的默认。
const PG_DB: &str = "postgres";
/// 非 public schema（验证跨 schema 枚举与限定寻址）。
const EXTRA_SCHEMA: &str = "ecommerce";

/// 真库连接目标（分字段 env）。
struct PgTarget {
    host: String,
    port: i64,
    username: String,
    password: String,
    database: String,
}

/// env-gated 入口：`DBMASTER_META_PG_HOST` 未设 → 打印 `[skip]` 并返回 None
/// （测试直接 return，不失败）。
fn env_gated() -> Option<PgTarget> {
    let host = std::env::var("DBMASTER_META_PG_HOST").unwrap_or_default();
    if host.is_empty() {
        eprintln!("[skip] DBMASTER_META_PG_HOST unset");
        return None;
    }
    Some(PgTarget {
        host,
        port: std::env::var("DBMASTER_META_PG_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(5432),
        username: std::env::var("DBMASTER_META_PG_USER").unwrap_or_else(|_| "postgres".to_string()),
        password: std::env::var("DBMASTER_META_PG_PASSWORD").unwrap_or_default(),
        database: std::env::var("DBMASTER_META_PG_DATABASE").unwrap_or_else(|_| PG_DB.to_string()),
    })
}

/// 建一个内存 server 库（真迁移）+ 一条指向真库 PG 的连接行，返回 conn_id。
/// 密码走 `enc:` 旧格式（`decrypt_password` 直读明文，无需 AES 钥匙）。
async fn seed_pg_connection(pool: &SqlitePool, target: &PgTarget) -> String {
    let id = format!("conn-pg-meta-e2e-{}", std::process::id());
    sqlx::query(
        "INSERT INTO database_connections
           (id, name, db_type, host, port, username, password_encrypted,
            default_database, created_by, created_at)
         VALUES (?, 'pg-meta-e2e', 'postgresql', ?, ?, ?, ?, ?, 'e2e', datetime('now'))",
    )
    .bind(&id)
    .bind(&target.host)
    .bind(target.port)
    .bind(&target.username)
    .bind(format!("enc:{}", target.password))
    .bind(&target.database)
    .execute(pool)
    .await
    .expect("seed database_connections row");
    id
}

/// 每个测试独立的 server 库 + 连接行（内存 sqlite + 真迁移）。
async fn setup(target: &PgTarget) -> (SqlitePool, String) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    dbmaster_core::db::run_migrations(&pool).await.unwrap();
    let conn_id = seed_pg_connection(&pool, target).await;
    (pool, conn_id)
}

#[tokio::test]
async fn pg_list_tables_enumerates_every_user_schema() {
    let Some(target) = env_gated() else {
        return;
    };
    let (pool, conn_id) = setup(&target).await;

    let tables = metadata::list_tables(&pool, &[0u8; 32], &conn_id, Some(&target.database))
        .await
        .expect("list_tables against real PG");
    let names: Vec<String> = tables.iter().map(|t| t.name.clone()).collect();
    let by_name = |n: &str| tables.iter().find(|t| t.name == n);
    eprintln!("[ok] pg list_tables → {names:?}");

    // public 对象保持裸名（既有输出不变）。
    for expected in ["brands", "users", "v_users"] {
        let t = by_name(expected)
            .unwrap_or_else(|| panic!("public 对象 '{expected}' 缺失；实际: {names:?}"));
        assert_eq!(t.schema, None, "public 对象不带 schema 字段");
    }
    assert_eq!(by_name("v_users").unwrap().kind, "view", "视图 kind 映射不变");

    // 非 public schema 的对象必须出现，且以 schema.table 命名 + 带 schema。
    let orders = by_name("ecommerce.orders")
        .unwrap_or_else(|| panic!("非 public 对象 'ecommerce.orders' 未枚举；实际: {names:?}"));
    assert_eq!(orders.schema.as_deref(), Some(EXTRA_SCHEMA));
    assert_eq!(orders.kind, "table");

    // 系统 schema 必须被滤除（pg_catalog / information_schema / pg_toast* /
    // pg_temp*——后两者实现上由 `nspname !~ '^pg_'` 一并覆盖）。
    for n in &names {
        let schema = n.split('.').next().unwrap_or("");
        assert!(
            !schema.starts_with("pg_") && schema != "information_schema",
            "系统 schema 对象泄漏进输出: {n}"
        );
    }
    eprintln!("[ok] pg list_tables 无系统 schema 对象（{} 项）", tables.len());
}

#[tokio::test]
async fn pg_describe_table_addresses_non_public_schema() {
    let Some(target) = env_gated() else {
        return;
    };
    let (pool, conn_id) = setup(&target).await;

    // ① 限定名寻址（修复前此处必然 NOT_FOUND）。
    let desc = metadata::describe_table(
        &pool, &[0u8; 32], &conn_id, Some(&target.database), "ecommerce.orders",
    )
    .await
    .expect("describe ecommerce.orders");
    let cols: Vec<&str> = desc.columns.iter().map(|c| c.name.as_str()).collect();
    eprintln!(
        "[ok] describe ecommerce.orders → columns={cols:?} pk={:?}",
        desc.primary_key
    );
    assert!(cols.contains(&"id"), "列 id 缺失: {cols:?}");
    assert!(cols.contains(&"total"), "列 total 缺失: {cols:?}");
    assert!(!desc.primary_key.is_empty(), "主键缺失");

    // ② 裸名寻址（search_path 解析，public 在默认 search_path 内）。
    let bare = metadata::describe_table(&pool, &[0u8; 32], &conn_id, Some(&target.database), "brands")
        .await
        .expect("describe brands (bare)");
    assert_eq!(bare.table, "brands");
    assert!(bare.columns.iter().any(|c| c.name == "id"), "brands.id 缺失");
    eprintln!("[ok] describe brands (裸名) → {} 列", bare.columns.len());

    // ③ 显式 public 限定名——与裸名等价的另一种寻址形态。
    let qualified_public = metadata::describe_table(
        &pool, &[0u8; 32], &conn_id, Some(&target.database), "public.users",
    )
    .await
    .expect("describe public.users");
    assert!(qualified_public.columns.iter().any(|c| c.name == "id"), "users.id 缺失");
    eprintln!(
        "[ok] describe public.users → {} 列, pk={:?}",
        qualified_public.columns.len(),
        qualified_public.primary_key
    );

    // ④ 不存在的对象仍按实际解析目标给 NOT_FOUND（文案不再写死 public）。
    let missing = metadata::describe_table(
        &pool, &[0u8; 32], &conn_id, Some(&target.database), "ecommerce.nope_not_here",
    )
    .await
    .expect_err("不存在的表必须 NOT_FOUND");
    assert_eq!(missing.code, "NOT_FOUND");
    assert!(
        missing.message.contains("schema 'ecommerce'"),
        "NOT_FOUND 文案应反映实际解析目标: {}",
        missing.message
    );
    eprintln!("[ok] NOT_FOUND 文案: {}", missing.message);
}
