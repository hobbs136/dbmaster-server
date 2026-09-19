//! ADR-0003 第一阶段：通用 DB 操作 API（执行任意 SQL + 目录列举）。
//!
//! 让 server 成为数据库网关——客户端（显示进程）通过这些端点操作数据库，
//! 不再直连业务库。第一阶段支持 MySQL / PostgreSQL / SQLite。
//!
//! 端点：
//! - GET  /api/db/:conn_id/databases          — 列库（读，不 gate）
//! - GET  /api/db/:conn_id/tables?db=X         — 列表（读，不 gate）
//! - GET  /api/db/:conn_id/columns?db=X&table=Y— 列列（读，不 gate）
//! - POST /api/db/:conn_id/query {db, sql, limit} — 执行 SQL（mutation gate）
//! - POST /api/db/:conn_id/test                — 测试连通性（读，不 gate）
//!
//! 安全：
//! - query 单语句（禁用多语句 `;` 尾部分号后跟内容）
//! - 行数上限（默认 10000）
//! - mutation（非 SELECT）走 gate_blocked
//! - 凭据 AES-256-GCM 解密，内存用完即 drop

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use dbmaster_core::auth::jwt::Claims;
use dbmaster_core::server::{AppState, CredentialKey};
use serde::Deserialize;
use sqlx::{Column, Row, SqlitePool};
use std::sync::Arc;
use std::time::Instant;

use crate::txn::{ConnParams, DbTxnSessionStore};
// T12s — gw 草稿测试失败的稳定码契约（值域常量 + 驱动错误判别）。
use crate::connect_error::{self, DraftTestError};

use crate::credential::decrypt_password;
// T28 — SQL Server（tiberius/TDS）后端基建（连接/解码/类型格式化）。
use crate::sqlserver::{decode_cell_tds, format_sqlserver_type, open_sqlserver};

// ── 连接行投影 ──

// pub(crate)：metadata.rs（T06 富元数据，MCP/网关同源）复用同一投影，
// 避免两处 SELECT 列清单漂移。
#[derive(sqlx::FromRow)]
pub(crate) struct DbConnectionRow {
    pub(crate) db_type: String,
    pub(crate) host: String,
    pub(crate) port: i64,
    pub(crate) username: String,
    pub(crate) password_encrypted: String,
    pub(crate) default_database: Option<String>,
    pub(crate) file_path: Option<String>,
    pub(crate) charset: Option<String>,
    pub(crate) timezone: Option<String>,
    /// T29 非 SQL 批次 — 集群/厂商专有配置 JSON blob（Mongo 集群四模式等；
    /// 注册时已 sanitize，见 gateway handlers）。SQL 族现不消费。
    pub(crate) extra: Option<String>,
    /// 0/1（sqlite BOOLEAN）——mongo 腿只读硬执行读取；SQL 族沿用客户端守卫。
    pub(crate) read_only: i64,
    /// 网络层批次（2026-08-29）— SSH 隧道秘密（password/privateKey/passphrase
    /// JSON 整体 encrypt_v1）。非秘密字段（sshHost 等）在 extra JSON。load_
    /// connection 收口解密；本字段绝不进日志 / 回显。
    pub(crate) ssh_secret_encrypted: Option<String>,
}

/// 按 id 加载连接行，解密密码。返回 (行, 明文密码)。
async fn load_and_decrypt(
    pool: &SqlitePool,
    state: &AppState,
    conn_id: &str,
) -> Result<(DbConnectionRow, String), (StatusCode, Json<serde_json::Value>)> {
    // T19 — 主体下沉到 (pool, key) 形态（MCP 写路径也走同一投影/解密），
    // 本函数保留 AppState 签名，13 个既有调用点不动。
    load_and_decrypt_key(pool, &state.credential_key, conn_id).await
}

/// [`load_and_decrypt`] 的 (pool, key) 形态——投影与解密的单一实现处。
async fn load_and_decrypt_key(
    pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
) -> Result<(DbConnectionRow, String), (StatusCode, Json<serde_json::Value>)> {
    let conn: DbConnectionRow = sqlx::query_as::<_, DbConnectionRow>(
        "SELECT db_type, host, port, username, password_encrypted,
                default_database, file_path, charset, timezone, extra, read_only,
                ssh_secret_encrypted
         FROM database_connections WHERE id = ?1",
    )
    .bind(conn_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| db_error("DB_ERROR", &e.to_string(), 500))?
    .ok_or_else(|| not_found("CONNECTION_NOT_FOUND", &format!("connection {conn_id} not found")))?;

    let password = decrypt_password(&conn.password_encrypted, key)
        .map_err(|e| db_error("DECRYPT_FAILED", &e.to_string(), 500))?;
    Ok((conn, password))
}

// ── DbBackend trait：per-DB 逻辑集中处（ADR-0003 重构）──
//
// 加新 SQL 库 = 写一个 impl 块（集中在此），不再散落到 8 个 handler 的 match
// 分支。pool 类型（Pool<MySql>/Pool<Postgres>/SqlitePool）是实现细节，不泄漏
// 到 trait，故可用 `dyn DbBackend` 分发。handler 退化为 load_and_decrypt →
// backend_for(db_type) → backend.method()。

/// Schema 对象分类（views/procedures/functions/triggers）。trait 共用。
#[derive(Clone, Copy)]
pub enum SchemaObjectKind {
    Views,
    Procedures,
    Functions,
    Triggers,
}

#[async_trait::async_trait]
pub(crate) trait DbBackend: Send + Sync {
    /// 测试连通性。返回 Err(message) 时 handler 报 connected:false（HTTP 仍 200）。
    /// message 已 redact（不泄露 host/凭据）。
    async fn test(&self, conn: &DbConnectionRow, password: &str)
        -> Result<(), String>;
    async fn list_databases(&self, conn: &DbConnectionRow, password: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>;
    async fn list_tables(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>;
    async fn list_columns(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<ColumnInfo>, (StatusCode, Json<serde_json::Value>)>;
    async fn list_schema_objects(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, kind: SchemaObjectKind)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>;
    async fn list_indexes(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>;
    async fn list_foreign_keys(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>;
    async fn execute_query(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, sql: &str, limit: usize, is_select: bool)
        -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)>;
}

/// 按 db_type 分发到对应 backend。未知类型返 UNSUPPORTED_DB_TYPE。
///
/// T21 — MySQL 协议族经 `mysql_family_for` 注册表优先命中（mysql / doris；
/// T22-T25 新成员在注册表加一行即自动生效），族成员共用
/// [`MysqlFamilyBackend`]，行为差异经薄适配 profile hook 注入。
pub(crate) fn backend_for(db_type: &str) -> Result<Box<dyn DbBackend>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(profile) = crate::mysql_family::mysql_family_for(db_type) {
        return Ok(Box::new(MysqlFamilyBackend { profile }));
    }
    match db_type.to_ascii_lowercase().as_str() {
        "postgres" | "postgresql" | "pg" => Ok(Box::new(PostgresBackend)),
        "sqlite" => Ok(Box::new(SqliteBackend)),
        "clickhouse" => Ok(Box::new(ClickhouseBackend)),
        // T28 — SQL Server 经 tiberius（ADR-0005 §2.4 首发试点；mssql 为
        // 常见别名，接受面与网关注册端点一致）。
        "sqlserver" | "mssql" => Ok(Box::new(SqlServerBackend)),
        other => Err(bad_request("UNSUPPORTED_DB_TYPE", &format!("unsupported db_type: {other}"))),
    }
}

/// MySQL 协议族统一 backend（T21 薄适配）：mysql / doris（及后续族成员）
/// 共用，握手 / 目录查询模式 / 会话 SET / 能力位差异全部来自注入的
/// profile（见 mysql_family.rs），本 impl 不再散落 db_type 特判。
struct MysqlFamilyBackend {
    profile: &'static dyn crate::mysql_family::MysqlFamilyHooks,
}struct PostgresBackend;
struct SqliteBackend;
struct ClickhouseBackend;
struct SqlServerBackend;

/// Quote a string literal for ClickHouse SQL: single-quote-wrapped with inner
/// single quotes doubled (SQL standard). Used because CH's MySQL-wire proto
/// doesn't support `?` prepared binds, so browse queries interpolate literals.
pub(crate) fn ch_str_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

// impl 块见文件下半部（调用 open_*/execute_sql_*/decode_* 等已有 helper）。

// ── 测试连通性 ──

#[derive(Deserialize)]
pub struct TestPath {
    pub conn_id: String,
}

pub async fn db_test(
    _claims: Claims,
    State(state): State<AppState>,
    Path(path): Path<TestPath>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    let backend = backend_for(&conn.db_type)?;
    let result = backend.test(&conn, &password).await;
    match result {
        Ok(_) => Ok(ok_response(serde_json::json!({"connected": true}))),
        Err(msg) => Ok(ok_response(serde_json::json!({
            "connected": false,
            "error": msg,
        }))),
    }
}

async fn test_mysql(conn: &DbConnectionRow, password: &str) -> anyhow::Result<()> {
    // T21 — 握手经族 profile（Doris 的 sql_mode workaround 在此生效）；
    // 空库名不下发（与 open_mysql_db 同一特判——Doris 拒绝空库名握手）。
    // 探测语句按执行模式走（Doris 的口不吃 PREPARE，raw_sql 探测）。
    let opts = mysql_connect_options(conn, password);
    let opts = match conn.default_database.as_deref().filter(|d| !d.is_empty()) {
        Some(db) => opts.database(db),
        None => opts,
    };
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;
    let mode = crate::mysql_family::mysql_profile_for(&conn.db_type).catalog_mode();
    crate::mysql_family::fetch_all_by_mode(&pool, mode, "SELECT 1", None).await?;
    Ok(())
}

async fn test_pg(conn: &DbConnectionRow, password: &str) -> anyhow::Result<()> {
    use sqlx::postgres::PgConnectOptions;
    let opts = PgConnectOptions::new()
        .host(&conn.host)
        .port(conn.port as u16)
        .username(&conn.username)
        .password(password)
        .application_name("dbmaster-gw")
        .database(conn.default_database.as_deref().unwrap_or(""));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;
    sqlx::query("SELECT 1").execute(&pool).await?;
    Ok(())
}

async fn test_sqlite(conn: &DbConnectionRow) -> anyhow::Result<()> {
    let path = conn.file_path.as_deref().ok_or_else(|| anyhow::anyhow!("sqlite connection missing file_path"))?;
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;
    sqlx::query("SELECT 1").execute(&pool).await?;
    Ok(())
}

/// T28 — SQL Server 连通性测试（每调用一条专用 tiberius 连接，SELECT 1）。
async fn test_sqlserver(conn: &DbConnectionRow, password: &str) -> anyhow::Result<()> {
    // T12s — 不再 `anyhow::anyhow!("{e}")` 抹类型：驱动错误对象是
    // error_code 判别的入口（Display/redact 文案逐字节不变）。
    let mut client = open_sqlserver(conn, password, None).await?;
    client.simple_query("SELECT 1").await?;
    Ok(())
}

/// T29 非 SQL 批次（B1）— MongoDB 连通性测试（admin ping；auth/网络问题
/// 在此一并失败，错误经调用方 redact）。
async fn test_mongo(conn: &DbConnectionRow, password: &str) -> anyhow::Result<()> {
    let client = crate::mongo::open_mongo(conn, password).await?;
    client
        .database("admin")
        .run_command(bson::doc! {"ping": 1})
        .await?;
    Ok(())
}

/// T29 非 SQL 批次（B3）— Redis 连通性测试（db 0 + PING）。
async fn test_redis(conn: &DbConnectionRow, password: &str) -> anyhow::Result<()> {
    let mut conn = crate::redis_leg::open_redis(conn, password, 0).await?;
    redis::cmd("PING")
        .query_async::<redis::Value>(&mut conn)
        .await?;
    Ok(())
}

// ── 草稿连接测试（网关 API v1 / T27：POST /api/gw/connections/test 后端）──

/// 未落库的连接草稿（客户端连接对话框「测试连接」用的字段集）。
/// 与 database_connections 行的差别：密码是明文（还未加密入库）。
#[derive(Debug)]
pub struct DraftConnection {
    pub db_type: String,
    pub host: String,
    pub port: i64,
    pub username: String,
    pub password: String,
    pub default_database: Option<String>,
    pub file_path: Option<String>,
    /// T29 非 SQL 批次 — 集群配置 JSON（网关注册/测试 wire 的 extra 透传，
    /// 已 sanitize 为存储形态字符串）。
    pub extra: Option<String>,
    /// 网络层批次（2026-08-29）— SSH 隧道参数（配置 + 秘密，内存明文——
    /// 草稿测试不落库）。None = 直连。
    pub ssh: Option<crate::ssh::SshTunnelParams>,
}

/// 测试草稿连接的可达性，成功时尽力取引擎版本（版本查询失败不阻塞——
/// 返回 Ok(None)，测试语义以 SELECT 1 为准）。
///
/// 与既有 db_test（按已注册 conn_id）互补：本函数面向「保存前测试」
/// （c01_port_contract §5：测试 = 远程调用，不落库）。错误消息经 redact
/// （不含 host/凭据）；T12s 起失败附稳定码 [`DraftTestError::code`]
/// （wire `error_code`，值域与码→语义见 `connect_error` 模块文档；
/// `error` 文案字段语义不变，gateway 侧只加性回传）。
pub async fn test_draft_connection(
    draft: &DraftConnection,
) -> Result<Option<String>, DraftTestError> {
    // 临时投影到 DbConnectionRow（test_* helper 的输入形状；不入库）。
    let mut conn = DbConnectionRow {
        db_type: draft.db_type.clone(),
        host: draft.host.clone(),
        port: draft.port,
        username: draft.username.clone(),
        password_encrypted: String::new(),
        default_database: draft.default_database.clone(),
        file_path: draft.file_path.clone(),
        charset: None,
        timezone: None,
        extra: draft.extra.clone(),
        read_only: 0,
        ssh_secret_encrypted: None,
    };
    // SSH 隧道收口（草稿路径；sqlite 无 host 不经隧道）。错误归一固定文案
    //（不含秘密）。
    if let Some(params) = &draft.ssh {
        if !draft.db_type.eq_ignore_ascii_case("sqlite") {
            match crate::ssh::apply_tunnel(
                &conn.host,
                conn.port,
                conn.extra.as_deref(),
                &params.config,
                &params.secrets,
            )
            .await
            {
                Ok((host, port, extra)) => {
                    conn.host = host;
                    conn.port = port;
                    conn.extra = extra;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "draft ssh tunnel resolve failed");
                    // T12s — 隧道建立失败 = 目标经网络不可达（码语义见
                    // connect_error 模块）；文案保持既有固定话术。
                    return Err(DraftTestError {
                        code: connect_error::UNREACHABLE,
                        message: "ssh tunnel setup failed".to_string(),
                    });
                }
            }
        }
    }
    match draft.db_type.to_ascii_lowercase().as_str() {
        // T21 — MySQL 协议族（mysql/doris 及后续薄适配成员）统一走族测试
        // 路径（握手差异经 mysql_connect_options 的 profile hook 生效）。
        t if crate::mysql_family::mysql_family_for(t).is_some() => {
            test_mysql(&conn, &draft.password)
                .await
                .map_err(draft_failure)?;
            Ok(non_empty_version(version_string(&conn, &draft.password).await))
        }
        "postgres" | "postgresql" | "pg" => {
            test_pg(&conn, &draft.password)
                .await
                .map_err(draft_failure)?;
            Ok(non_empty_version(version_string(&conn, &draft.password).await))
        }
        "sqlite" => {
            test_sqlite(&conn).await.map_err(draft_failure)?;
            Ok(non_empty_version(version_string(&conn, &draft.password).await))
        }
        // T28 — SQL Server（tiberius；mssql 别名同接受）。
        "sqlserver" | "mssql" => {
            test_sqlserver(&conn, &draft.password)
                .await
                .map_err(draft_failure)?;
            Ok(non_empty_version(version_string(&conn, &draft.password).await))
        }
        // T29 第三批 — ClickHouse 走 MySQL 兼容口（9004），复用 test_mysql
        // （与既有 ClickhouseBackend::test 同口径）；version_string 的默认
        // 臂已覆盖 CH（SELECT VERSION() 经 MySQL 口）。
        "clickhouse" => {
            test_mysql(&conn, &draft.password)
                .await
                .map_err(draft_failure)?;
            Ok(non_empty_version(version_string(&conn, &draft.password).await))
        }
        // T29 非 SQL 批次（B1）— MongoDB：ping 认可达性；版本走 buildInfo
        //（version_string 的 mongodb 臂同源）。
        "mongodb" | "mongo" => {
            test_mongo(&conn, &draft.password)
                .await
                .map_err(draft_failure)?;
            Ok(non_empty_version(version_string(&conn, &draft.password).await))
        }
        // T29 非 SQL 批次（B3）— Redis：PING 认可达性；版本走 INFO server 的
        // redis_version 行（version_string 的 redis 臂同源）。
        "redis" => {
            test_redis(&conn, &draft.password)
                .await
                .map_err(draft_failure)?;
            Ok(non_empty_version(version_string(&conn, &draft.password).await))
        }
        // T29 TDengine 批次 — taosAdapter REST：SELECT SERVER_VERSION() code==0
        // 即可达且凭据有效；版本同语句（tdengine_leg 同源）。T12s — 返回
        // 类型化 TdError，判别复用既有 REST 三分类（tdengine_failure）。
        "tdengine" => {
            crate::tdengine_leg::test_tdengine(&conn, &draft.password)
                .await
                .map_err(tdengine_failure)?;
            Ok(non_empty_version(version_string(&conn, &draft.password).await))
        }
        other => Err(DraftTestError {
            code: connect_error::DB_ERROR,
            message: format!("unsupported db_type: {other}"),
        }),
    }
}

/// 驱动错误 → 草稿测试失败：码判别（`connect_error::classify_driver_error`，
/// 纯函数、构造对象单测在 connect_error）+ redact 文案（与旧裸 String
/// 形态逐字节一致）。
fn draft_failure(e: anyhow::Error) -> DraftTestError {
    DraftTestError {
        code: connect_error::classify_driver_error(&e),
        message: redact(&e.to_string()),
    }
}

/// TDengine TdError → 草稿测试失败：复用 tdengine_leg 既有 REST 三分类
/// 判别（Auth/Transport/Http/Engine），文案与旧 String 形态逐字节一致。
fn tdengine_failure(e: crate::tdengine_leg::TdError) -> DraftTestError {
    use crate::tdengine_leg::TdError;
    let message = match &e {
        TdError::Auth => "authentication failed".to_string(),
        TdError::Transport => "connection failed".to_string(),
        TdError::Http(status, body) => format!("HTTP {status}: {body}"),
        TdError::Engine(code, desc) => format!("engine error {code}: {desc}"),
    };
    DraftTestError {
        code: match e {
            TdError::Auth => connect_error::AUTH_DENIED,
            TdError::Transport => connect_error::UNREACHABLE,
            TdError::Http(..) | TdError::Engine(..) => connect_error::DB_ERROR,
        },
        message: redact(&message),
    }
}

/// 版本查询失败/为空时省略（wire 上 serverVersion? 可选键）。
fn non_empty_version(v: String) -> Option<String> {
    if v.is_empty() { None } else { Some(v) }
}

/// 尽力取引擎版本字符串（失败返回空串——版本是展示性信息，不阻塞测试结论）。
/// 三族池类型不同，分支内各自完成查询与解码。
async fn version_string(conn: &DbConnectionRow, password: &str) -> String {
    match conn.db_type.to_ascii_lowercase().as_str() {
        "postgres" | "postgresql" | "pg" => {
            use sqlx::postgres::PgConnectOptions;
            let opts = PgConnectOptions::new()
                .host(&conn.host).port(conn.port as u16)
                .username(&conn.username).password(password)
                .application_name("dbmaster-gw")
                .database(conn.default_database.as_deref().unwrap_or("postgres"));
            let Ok(pool) = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts).await else {
                return String::new();
            };
            sqlx::query("SELECT version()")
                .fetch_optional(&pool).await.ok().flatten()
                .and_then(|r| r.try_get::<String, _>(0).ok())
                .unwrap_or_default()
        }
        "sqlite" => {
            let Some(path) = conn.file_path.as_deref() else { return String::new(); };
            let opts = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path).read_only(true).create_if_missing(false);
            let Ok(pool) = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(opts).await else {
                return String::new();
            };
            sqlx::query("SELECT sqlite_version()")
                .fetch_optional(&pool).await.ok().flatten()
                .and_then(|r| r.try_get::<String, _>(0).ok())
                .unwrap_or_default()
        }
        // T28 — SERVERPROPERTY('ProductVersion') 形如 "16.0.4155.1"（比
        // @@VERSION 的长横幅更适合 wire 上的 serverVersion 短字段）。
        // CAST 必须：SERVERPROPERTY 返回 sql_variant，tiberius 0.12 的解码器
        // 对 variant 类型 todo!() panic。
        "sqlserver" | "mssql" => {
            let Ok(mut client) = open_sqlserver(conn, password, None).await else {
                return String::new();
            };
            let Ok(stream) = client
                .simple_query("SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128))")
                .await
            else {
                return String::new();
            };
            let Ok(rows) = stream.into_first_result().await else {
                return String::new();
            };
            rows.first()
                .map(|r| decode_cell_tds(r, 0).as_str().unwrap_or_default().to_string())
                .unwrap_or_default()
        }
        // T29 非 SQL 批次（B1）— buildInfo.version（mongo.rs 尽力而为实现，
        // 失败返回空串）。
        "mongodb" | "mongo" => crate::mongo::server_version(conn, password).await,
        // T29 TDengine 批次 — SELECT SERVER_VERSION() 首行首列（形如
        // "3.3.6.0"；tdengine_leg 尽力而为实现）。
        "tdengine" => crate::tdengine_leg::server_version(conn, password).await,
        // T29 非 SQL 批次（B3）— INFO server 的 redis_version:x.y.z 行。
        "redis" => {
            let Ok(mut conn) = crate::redis_leg::open_redis(conn, password, 0).await else {
                return String::new();
            };
            let Ok(resp) = redis::cmd("INFO")
                .arg("server")
                .query_async::<redis::Value>(&mut conn)
                .await
            else {
                return String::new();
            };
            let redis::Value::BulkString(b) = resp else { return String::new() };
            String::from_utf8_lossy(&b)
                .lines()
                .find_map(|l| l.strip_prefix("redis_version:"))
                .unwrap_or_default()
                .trim()
                .to_string()
        }
        _ => {
            // T21 — MySQL 协议族（含 Doris）+ ClickHouse 兼容口：profile 握手
            // + 执行模式；SELECT VERSION() 尽力而为（失败返回空串）。
            let opts = mysql_connect_options(&conn, password);
            let opts = match conn.default_database.as_deref().filter(|d| !d.is_empty()) {
                Some(db) => opts.database(db),
                None => opts,
            };
            let Ok(pool) = sqlx::mysql::MySqlPoolOptions::new().max_connections(1).connect_with(opts).await else {
                return String::new();
            };
            let profile = crate::mysql_family::mysql_profile_for(&conn.db_type);
            crate::mysql_family::fetch_all_by_mode(&pool, profile.catalog_mode(), "SELECT VERSION()", None)
                .await
                .ok()
                .and_then(|rows| rows.first().map(|r| decode_mysql_string(r, 0)))
                .unwrap_or_default()
        }
    }
}

// ── 列举数据库 ──

pub async fn db_list_databases(
    _claims: Claims,
    State(state): State<AppState>,
    Path(path): Path<TestPath>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    let backend = backend_for(&conn.db_type)?;
    let dbs = backend.list_databases(&conn, &password).await?;
    Ok(ok_response(serde_json::json!(dbs)))
}

// ── 列举表 ──

#[derive(Deserialize)]
pub struct DbQuery {
    pub db: Option<String>,
}

pub async fn db_list_tables(
    _claims: Claims,
    State(state): State<AppState>,
    Path(path): Path<TestPath>,
    Query(q): Query<DbQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    let backend = backend_for(&conn.db_type)?;
    let db_name = q.db.or(conn.default_database.clone());
    let tables = backend.list_tables(&conn, &password, db_name.as_deref()).await?;
    Ok(ok_response(serde_json::json!(tables)))
}

// ── 列举列 ──

#[derive(Deserialize)]
pub struct ColumnQuery {
    pub db: Option<String>,
    pub table: String,
}

pub async fn db_list_columns(
    _claims: Claims,
    State(state): State<AppState>,
    Path(path): Path<TestPath>,
    Query(q): Query<ColumnQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    let backend = backend_for(&conn.db_type)?;
    let db_name = q.db.or(conn.default_database.clone());
    let columns = backend.list_columns(&conn, &password, db_name.as_deref(), &q.table).await?;
    Ok(ok_response(columns_json(columns)))
}

#[derive(sqlx::FromRow)]
pub(crate) struct ColumnInfo {
    name: String,
    data_type: String,
    is_primary_key: i64,
    is_nullable: i64,
    default_value: Option<String>,
}

fn columns_json(rows: Vec<ColumnInfo>) -> serde_json::Value {
    serde_json::Value::Array(rows.into_iter().map(|c| serde_json::json!({
        "name": c.name,
        "data_type": c.data_type,
        "is_primary_key": c.is_primary_key != 0,
        "is_nullable": c.is_nullable != 0,
        "default_value": c.default_value,
    })).collect())
}

// ── 列举 schema 对象（views / procedures / functions / triggers）──
// 4 个 handler 共用 trait 的 list_schema_objects，per-DB 逻辑在各 backend impl 里。

macro_rules! schema_object_handler {
    ($fn_name:ident, $kind:expr) => {
        pub async fn $fn_name(
            _claims: Claims,
            State(state): State<AppState>,
            Path(path): Path<TestPath>,
            Query(q): Query<DbQuery>,
        ) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
            let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
            let backend = backend_for(&conn.db_type)?;
            let db_name = q.db.or(conn.default_database.clone());
            let names = backend.list_schema_objects(&conn, &password, db_name.as_deref(), $kind).await?;
            Ok(ok_response(serde_json::json!(names)))
        }
    };
}

schema_object_handler!(db_list_views, SchemaObjectKind::Views);
schema_object_handler!(db_list_procedures, SchemaObjectKind::Procedures);
schema_object_handler!(db_list_functions, SchemaObjectKind::Functions);
schema_object_handler!(db_list_triggers, SchemaObjectKind::Triggers);

/// `GET /api/db/:conn_id/indexes?table=<t>` — list index names for a table.
// index listing (names only; full metadata is a later
// refinement). SQLite returns [] (PRAGMA index_list is handled client-side).
pub async fn db_list_indexes(
    _claims: Claims,
    State(state): State<AppState>,
    Path(path): Path<TestPath>,
    Query(q): Query<ColumnQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    let backend = backend_for(&conn.db_type)?;
    let db_name = q.db.or(conn.default_database.clone());
    let names = backend.list_indexes(&conn, &password, db_name.as_deref(), &q.table).await?;
    Ok(ok_response(serde_json::json!(names)))
}

/// `GET /api/db/:conn_id/foreign_keys?table=<t>` — list FK constraint names.
pub async fn db_list_foreign_keys(
    _claims: Claims,
    State(state): State<AppState>,
    Path(path): Path<TestPath>,
    Query(q): Query<ColumnQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    let backend = backend_for(&conn.db_type)?;
    let db_name = q.db.or(conn.default_database.clone());
    let names = backend.list_foreign_keys(&conn, &password, db_name.as_deref(), &q.table).await?;
    Ok(ok_response(serde_json::json!(names)))
}

// ── 执行任意 SQL ──

#[derive(Deserialize)]
pub struct QueryBody {
    pub db: Option<String>,
    pub sql: String,
    pub limit: Option<i64>,
}

pub async fn db_query(
    claims: Claims,
    State(state): State<AppState>,
    Path(path): Path<TestPath>,
    Json(body): Json<QueryBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // mutation（非 SELECT）走 gate
    let is_select = is_select_statement(&body.sql);
    if !is_select {
        if let Some(gated) = crate::handler::gate_blocked_pub(&state) {
            return Err(gated);
        }
    }

    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    let backend = backend_for(&conn.db_type)?;
    let db_name = body.db.or(conn.default_database.clone());
    let limit = body.limit.unwrap_or(10_000).min(100_000).max(1) as usize;
    let started = Instant::now();

    let mut result = backend
        .execute_query(&conn, &password, db_name.as_deref(), &body.sql, limit, is_select)
        .await?;

    let elapsed = started.elapsed().as_millis() as u64;
    // reports-M1（#29）— 慢查询旁路采样（成功路径；错误路径提前返回不采样）。
    crate::query_stats::record(
        elapsed,
        &crate::query_stats::CaptureContext {
            conn_id: &path.conn_id,
            db_kind: Some(&conn.db_type),
            database: db_name.as_deref(),
            user_id: Some(&claims.sub),
            entry: crate::query_stats::CaptureEntry::SyncQuery,
            outcome: crate::query_stats::CaptureOutcome::Ok,
        },
        &crate::query_stats::CapturePayload::Sql(&body.sql),
        result.get("rows").and_then(serde_json::Value::as_array).map(|a| a.len() as u64),
        result.get("affectedRows").and_then(serde_json::Value::as_u64),
    );
    if let Some(obj) = result.as_object_mut() {
        obj.insert("executionTimeMs".to_string(), serde_json::json!(elapsed));
    }
    Ok(ok_response(result))
}

// ── 事务端点（ADR-0003 S10）──────────────────────────────────────────────
// 四个端点，共用一个 session-pinned pool store（经 Extension 注入，不入
// AppState，避免 core crate 依赖 sqlx 业务类型）。事务控制语句
// (BEGIN/COMMIT/ROLLBACK) 不经 mutation gate——它们改的是事务状态，不是数据。

/// Path 提取器：带 session_id 的事务端点（query/commit/rollback）。
#[derive(Deserialize)]
pub struct TxnPath {
    pub conn_id: String,
    pub session_id: String,
}

/// `POST /api/db/:conn_id/txn/begin` body.
#[derive(Deserialize)]
pub struct TxnBeginBody {
    pub db: Option<String>,
}

/// `POST /api/db/:conn_id/txn/begin` — open a pinned transaction session.
///
/// Opens a `max_connections(1)` pool, emits the DB-family BEGIN statement,
/// registers the session, and returns `{sessionId}`. The plaintext password is
/// dropped at the end of this function (pool handshake complete); it is never
/// cached in the session.
pub async fn txn_begin(
    _claims: Claims,
    State(state): State<AppState>,
    Extension(store): Extension<Arc<DbTxnSessionStore>>,
    Path(path): Path<TestPath>,
    Json(body): Json<TxnBeginBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    // ClickHouse has no transactions — reject up front with a stable code.
    if conn.db_type == "clickhouse" {
        return Err(db_error(
            "UNSUPPORTED_TXN",
            "ClickHouse does not support transactions",
            400,
        ));
    }
    let port = conn.port as u16;
    let params = ConnParams {
        db_type: &conn.db_type,
        host: &conn.host,
        port,
        username: &conn.username,
        password: &password,
        database: body.db.as_deref().or(conn.default_database.as_deref()),
        charset: conn.charset.as_deref(),
        timezone: conn.timezone.as_deref(),
        file_path: conn.file_path.as_deref(),
    };
    let session_id = store.begin(params).await.map_err(|e| {
        db_error("TXN_BEGIN_FAILED", &redact(&e), 503)
    })?;
    Ok(ok_response(serde_json::json!({ "sessionId": session_id })))
}

/// `POST /api/db/:conn_id/txn/:session_id/query` — run a statement inside an
/// open transaction session. Body shape mirrors `db_query`'s `{db, sql, limit}`.
pub async fn txn_query(
    claims: Claims,
    State(_state): State<AppState>,
    Extension(store): Extension<Arc<DbTxnSessionStore>>,
    Path(path): Path<TxnPath>,
    Json(body): Json<QueryBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Transaction-scoped queries bypass the mutation gate — the user has
    // explicitly opened a transaction and is editing data on purpose. (The
    // stateless `db_query` path still gates non-SELECT; this path does not.)
    let is_select = is_select_statement(&body.sql);
    let limit = body.limit.unwrap_or(10_000).min(100_000).max(1) as usize;
    let started = Instant::now();
    let mut result = store
        .execute_in_txn(&path.session_id, &body.sql, limit, is_select)
        .await
        .map_err(|e| db_error("TXN_QUERY_FAILED", &redact(&e), 500))?;
    let elapsed = started.elapsed().as_millis() as u64;
    // reports-M1（#29）— 慢查询旁路采样。db_kind/database 不可得（session
    // 不保存两者）→ None，写入路径懒查 / 留空。
    crate::query_stats::record(
        elapsed,
        &crate::query_stats::CaptureContext {
            conn_id: &path.conn_id,
            db_kind: None,
            database: None,
            user_id: Some(&claims.sub),
            entry: crate::query_stats::CaptureEntry::TxnQuery,
            outcome: crate::query_stats::CaptureOutcome::Ok,
        },
        &crate::query_stats::CapturePayload::Sql(&body.sql),
        result.get("rows").and_then(serde_json::Value::as_array).map(|a| a.len() as u64),
        result.get("affectedRows").and_then(serde_json::Value::as_u64),
    );
    if let Some(obj) = result.as_object_mut() {
        obj.insert("executionTimeMs".to_string(), serde_json::json!(elapsed));
    }
    Ok(ok_response(result))
}

/// `POST /api/db/:conn_id/txn/:session_id/commit` — commit & close the session.
pub async fn txn_commit(
    _claims: Claims,
    Extension(store): Extension<Arc<DbTxnSessionStore>>,
    Path(path): Path<TxnPath>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    store.commit(&path.session_id).await.map_err(|e| {
        db_error("TXN_COMMIT_FAILED", &redact(&e), 500)
    })?;
    Ok(ok_response(serde_json::json!({ "committed": true })))
}

/// `POST /api/db/:conn_id/txn/:session_id/rollback` — rollback & close.
pub async fn txn_rollback(
    _claims: Claims,
    Extension(store): Extension<Arc<DbTxnSessionStore>>,
    Path(path): Path<TxnPath>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    store.rollback(&path.session_id).await.map_err(|e| {
        db_error("TXN_ROLLBACK_FAILED", &redact(&e), 500)
    })?;
    Ok(ok_response(serde_json::json!({ "rolledBack": true })))
}

// ── Admin endpoints (ADR-0003 S8b prep) ──────────────────────────────────
// KILL QUERY and multi-statement script execution. These cover the raw-SQL
// consumers that the stateless single-statement gateway cannot (process-kill
// needs an independent privileged connection; scripts need a real splitter
// that handles quotes/DELIMITER/BEGIN...END). The client still runs these
// locally today; the endpoints land first so S8b can switch the client over.

/// `POST /api/db/:conn_id/admin/kill` body `{thread_id}` — kill a MySQL query.
///
/// Opens a regular `max_connections(1)` pool and issues `KILL QUERY <id>`.
/// The target thread is the client-supplied id (the long-running query to
/// abort), not this connection's own thread, so a normal pool connection is
/// fine — unlike the client which must open a *separate* connection because
/// its main connection is busy running the query to be killed.
#[derive(Deserialize)]
pub struct AdminKillBody {
    pub thread_id: i64,
}

pub async fn admin_kill(
    _claims: Claims,
    State(state): State<AppState>,
    Path(path): Path<TestPath>,
    Json(body): Json<AdminKillBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    // T21 — KILL QUERY 能力位经 MySQL 族薄适配 profile（mysql/doris 支持；
    // 族外库一律拒绝，PG 用 pg_cancel_backend 是另一套语义）。
    if !crate::mysql_family::mysql_family_for(&conn.db_type)
        .is_some_and(|profile| profile.supports_kill_query())
    {
        return Err(db_error(
            "UNSUPPORTED",
            &format!("KILL not supported for db_type '{}'", conn.db_type),
            400,
        ));
    }
    let pool = open_mysql_db(&conn, &password, conn.default_database.as_deref()).await?;
    // thread_id is an integer from SHOW PROCESSLIST — inject as a bare number
    // (validated by the i64 type; no quoting needed, no injection surface).
    // T24 — 执行按族 profile 的模式分流：StarRocks 的 PREPARE 协议只吃
    // SELECT（KILL 报 1295），必须文本协议；MySQL/OB/TiDB/MariaDB 的
    // Prepare 模式行为不变，Doris 从 prepare 收敛到 raw（COM_QUERY 是
    // mysql CLI 的标准通道，语义一致）。
    let sql = format!("KILL QUERY {}", body.thread_id);
    let profile = crate::mysql_family::mysql_profile_for(&conn.db_type);
    crate::mysql_family::execute_by_mode(&pool, profile.catalog_mode(), &sql)
        .await
        .map_err(|e| db_error("KILL_FAILED", &redact(&e.to_string()), 500))?;
    Ok(ok_response(serde_json::json!({ "killed": true, "threadId": body.thread_id })))
}

/// `POST /api/db/:conn_id/admin/script` body `{db?, script, limit?}` — run a
/// multi-statement script, splitting with a real SQL-aware tokenizer.
///
/// Splits the script with [`crate::sql_split::split_sql_script`] (handles
/// quotes / comments / `BEGIN...END` / `DELIMITER`), then executes each
/// statement on the same `max_connections(1)` pool. Continues past errors
/// (DBA scripts commonly contain `DROP TABLE IF EXISTS` that may fail);
/// per-statement results — `{sql, ok, columns?, rows?, affectedRows?, error?}`
/// — are returned so the client can report which statements succeeded.
#[derive(Deserialize)]
pub struct AdminScriptBody {
    pub db: Option<String>,
    pub script: String,
    pub limit: Option<i64>,
}

pub async fn admin_script(
    claims: Claims,
    State(state): State<AppState>,
    Path(path): Path<TestPath>,
    Json(body): Json<AdminScriptBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (conn, password) = load_and_decrypt(&state.pool, &state, &path.conn_id).await?;
    let backend = backend_for(&conn.db_type)?;
    let db_name = body.db.or(conn.default_database.clone());
    let limit = body.limit.unwrap_or(10_000).min(100_000).max(1) as usize;

    let statements = crate::sql_split::split_sql_script(&body.script);
    let mut results = Vec::with_capacity(statements.len());
    for stmt in &statements {
        let is_select = is_select_statement(stmt);
        // reports-M1（#29）— 逐条计时是本设计唯一新增计时点（admin_script
        // 原本无单条耗时）。
        let stmt_started = Instant::now();
        let exec = backend
            .execute_query(&conn, &password, db_name.as_deref(), stmt, limit, is_select)
            .await;
        let stmt_elapsed = stmt_started.elapsed().as_millis() as u64;
        // 采样先于 match 消费 exec（错误码取信封稳定 code）。
        let (cap_outcome, cap_rows, cap_affected) = match &exec {
            Ok(v) => (
                crate::query_stats::CaptureOutcome::Ok,
                v.get("rows").and_then(serde_json::Value::as_array).map(|a| a.len() as u64),
                v.get("affectedRows").and_then(serde_json::Value::as_u64),
            ),
            Err((_status, err_body)) => (
                crate::query_stats::CaptureOutcome::Error(
                    err_body
                        .get("error")
                        .and_then(|e| e.get("code"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("DB_ERROR")
                        .to_string(),
                ),
                None,
                None,
            ),
        };
        crate::query_stats::record(
            stmt_elapsed,
            &crate::query_stats::CaptureContext {
                conn_id: &path.conn_id,
                db_kind: Some(&conn.db_type),
                database: db_name.as_deref(),
                user_id: Some(&claims.sub),
                entry: crate::query_stats::CaptureEntry::AdminScript,
                outcome: cap_outcome,
            },
            &crate::query_stats::CapturePayload::Sql(stmt),
            cap_rows,
            cap_affected,
        );
        let entry = match exec {
            Ok(value) => {
                // execute_query returns {columns, rows} or {columns:[], rows:[], affectedRows}
                let mut e = serde_json::json!({
                    "sql": stmt,
                    "ok": true,
                });
                if let Some(obj) = value.as_object() {
                    if let Some(ar) = obj.get("affectedRows") {
                        e["affectedRows"] = ar.clone();
                    }
                    if let Some(cols) = obj.get("columns") {
                        e["columns"] = cols.clone();
                    }
                    if let Some(rows) = obj.get("rows") {
                        e["rows"] = rows.clone();
                    }
                }
                e
            }
            Err((_status, err_body)) => {
                // err_body is the {ok:false, error:{code,message}} JSON; pull message.
                let msg = err_body
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("execution failed");
                serde_json::json!({
                    "sql": stmt,
                    "ok": false,
                    "error": msg,
                })
            }
        };
        results.push(entry);
    }
    Ok(ok_response(serde_json::json!({ "results": results })))
}

/// MySQL 族执行 SQL：SELECT 返回 columns+rows，DDL/DML 返回 affectedRows。
///
/// T21 — 两个分支都按族 profile 的执行模式分流（`fetch_all_by_mode` /
/// `execute_by_mode`）：MySQL prepare（绑定协议，既有通道）/ Doris
/// raw_sql（文本协议，规避其 prepare-ok 包不合规，与 stream_query 的
/// doris 通道同源）。
pub(crate) async fn execute_sql_mysql(
    pool: &sqlx::Pool<sqlx::MySql>,
    sql: &str,
    limit: usize,
    is_select: bool,
    mode: crate::mysql_family::CatalogQueryMode,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    if is_select {
        let rows = crate::mysql_family::fetch_all_by_mode(pool, mode, sql, None).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        rows_to_json_mysql(&rows, limit)
    } else {
        let affected = crate::mysql_family::execute_by_mode(pool, mode, sql).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(serde_json::json!({
            "columns": [],
            "rows": [],
            "affectedRows": affected,
        }))
    }
}

/// 把 sqlx MySqlRow 数组转成 {columns, rows} JSON。
/// 逐单元格 try decode（String → i64 → f64 → bool → bytes → null）。
fn rows_to_json_mysql(
    rows: &[sqlx::mysql::MySqlRow],
    limit: usize,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    if rows.is_empty() {
        return Ok(serde_json::json!({"columns": [], "rows": []}));
    }
    // 列名 + 类型
    let columns: Vec<(String, String)> = rows[0]
        .columns()
        .iter()
        .map(|c| (c.name().to_string(), c.type_info().to_string()))
        .collect();
    let col_names: Vec<String> = columns.iter().map(|(n, _)| n.clone()).collect();
    let col_types: serde_json::Value = columns
        .iter()
        .map(|(n, t)| serde_json::json!({"name": n, "type": t}))
        .collect();

    // 行数据
    let mut json_rows = Vec::with_capacity(rows.len().min(limit));
    for row in rows.iter().take(limit) {
        let mut map = serde_json::Map::new();
        for (i, (name, _)) in columns.iter().enumerate() {
            let val = decode_cell_mysql(row, i);
            map.insert(name.clone(), val);
        }
        json_rows.push(serde_json::Value::Object(map));
    }

    Ok(serde_json::json!({
        "columns": col_names,
        "columnTypes": col_types,
        "rows": json_rows,
    }))
}

/// Decode a single MySQL column to a `String`, tolerating VARBINARY/BINARY
/// columns (which `SHOW DATABASES`/`SHOW TABLES` return and sqlx cannot decode
/// as String directly). Tries String first, then Vec<u8>→UTF-8, else empty.
///
/// Used by the browse endpoints (db_list_databases/tables) whose SHOW-based
/// queries return binary-typed name columns. The query gateway (db_query)
/// doesn't need this — its `decode_cell_mysql` already runs the full type
/// chain; this is the string-only projection for name lists.
pub(crate) fn decode_mysql_string(row: &sqlx::mysql::MySqlRow, idx: usize) -> String {
    if let Ok(Some(s)) = row.try_get::<Option<String>, _>(idx) {
        return s;
    }
    if let Ok(Some(b)) = row.try_get::<Option<Vec<u8>>, _>(idx) {
        return String::from_utf8_lossy(&b).into_owned();
    }
    String::new()
}

/// MySQL 单元格 decode（类型猜测链）。
pub(crate) fn decode_cell_mysql(row: &sqlx::mysql::MySqlRow, idx: usize) -> serde_json::Value {
    // 按 String → i64 → u64 → f64 → bool → Vec<u8> → JSON → DECIMAL → null
    // T29 — u64 必须在 f64/bool 之前：BIGINT UNSIGNED 的 i64 解码失败后会
    // 被 bool 链吞成 true（实机 EXPLAIN 的 rows/id 列全变 true）。
    if let Ok(v) = row.try_get::<Option<String>, _>(idx) {
        return v.map(serde_json::Value::String).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<i64>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<u64>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<f64>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<bool>, _>(idx) {
        return v.map(serde_json::Value::Bool).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<Vec<u8>>, _>(idx) {
        return v.map(|b| {
            // bytes 尝试转 UTF-8 字符串，失败则 base64
            match String::from_utf8(b.clone()) {
                Ok(s) => serde_json::Value::String(s),
                Err(_) => serde_json::Value::String(format!("<{} bytes>", b.len())),
            }
        }).unwrap_or(serde_json::Value::Null);
    }
    // T29 — JSON 列（实机：JSON_EXTRACT 结果列直读落 null）：sqlx 原生
    // 支持 serde_json::Value 解码 JSON 类型（类型兼容表只匹配 JSON）。
    if let Ok(v) = row.try_get::<Option<serde_json::Value>, _>(idx) {
        return v.unwrap_or(serde_json::Value::Null);
    }
    // T29 — DECIMAL/NewDecimal 列（T24 既有缺口）：rust_decimal feature
    // 解码后转字符串保精度（与 T28 SS decimal 字符串口径一致）。
    if let Ok(v) = row.try_get::<Option<rust_decimal::Decimal>, _>(idx) {
        return v
            .map(|d| serde_json::Value::String(d.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    // 网关日期解码（CH 派生评估①，族级缺口）：sqlx chrono feature 接通
    // DATE/DATETIME/TIMESTAMP 解码（此前全落 null——MySQL 六库 + CH 经
    // MySQL 口共用本链，e2e 曾零覆盖）。格式取 SQL 惯例（空格分隔、自动
    // 小数位）；MySQL 口微秒精度上限，CH DateTime64(9) 纳秒截断到微秒。
    // TIMESTAMP 按 UTC 墙钟渲染（服务端无会话/客户端时区概念，与 psql
    // 按会话时区渲染同源近似）；TIME 超出 00:00:00-23:59:59（负值/跨日）
    // chrono 解不开 → 维持 null 边界。
    if let Ok(v) = row.try_get::<Option<NaiveDate>, _>(idx) {
        return v
            .map(|d| serde_json::Value::String(d.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<NaiveTime>, _>(idx) {
        return v
            .map(|t| serde_json::Value::String(t.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<NaiveDateTime>, _>(idx) {
        return v
            .map(|t| serde_json::Value::String(t.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<DateTime<Utc>>, _>(idx) {
        return v
            .map(|t| serde_json::Value::String(t.naive_utc().to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    serde_json::Value::Null
}

/// PG 执行 SQL。
pub(crate) async fn execute_sql_pg(
    pool: &sqlx::Pool<sqlx::Postgres>,
    sql: &str,
    limit: usize,
    is_select: bool,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    if is_select {
        let rows = sqlx::query(sql).fetch_all(pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        rows_to_json_pg(&rows, limit)
    } else {
        let result = sqlx::query(sql).execute(pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(serde_json::json!({
            "columns": [],
            "rows": [],
            "affectedRows": result.rows_affected(),
        }))
    }
}

fn rows_to_json_pg(
    rows: &[sqlx::postgres::PgRow],
    limit: usize,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    if rows.is_empty() {
        return Ok(serde_json::json!({"columns": [], "rows": []}));
    }
    let columns: Vec<(String, String)> = rows[0]
        .columns()
        .iter()
        .map(|c| (c.name().to_string(), c.type_info().to_string()))
        .collect();
    let col_names: Vec<String> = columns.iter().map(|(n, _)| n.clone()).collect();
    let col_types: serde_json::Value = columns
        .iter()
        .map(|(n, t)| serde_json::json!({"name": n, "type": t}))
        .collect();
    let mut json_rows = Vec::with_capacity(rows.len().min(limit));
    for row in rows.iter().take(limit) {
        let mut map = serde_json::Map::new();
        for (i, (name, _)) in columns.iter().enumerate() {
            let val = decode_cell_pg(row, i);
            map.insert(name.clone(), val);
        }
        json_rows.push(serde_json::Value::Object(map));
    }
    Ok(serde_json::json!({
        "columns": col_names,
        "columnTypes": col_types,
        "rows": json_rows,
    }))
}

pub(crate) fn decode_cell_pg(row: &sqlx::postgres::PgRow, idx: usize) -> serde_json::Value {
    // 按 String → bool → i16 → i32 → i64 → f32 → f64 → JSON → DECIMAL → null
    // T29 第二批实锤修复：sqlx PG 严格按 OID 匹配解码类型——INT4 只解 i32、
    // INT2 只解 i16、FLOAT4 只解 f32，旧实现只有 i64/f64 两臂 → int4 列
    // （PG 最常见的 integer）全灭为 null（PG E2E「update data / cursor
    // pagination / modify column 长度丢失」同根因）。
    if let Ok(v) = row.try_get::<Option<String>, _>(idx) {
        return v.map(serde_json::Value::String).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<bool>, _>(idx) {
        return v.map(serde_json::Value::Bool).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<i16>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<i32>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<i64>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<f32>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<f64>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    // JSON/JSONB 列（与 mysql 臂同口径）：sqlx PG 原生支持 serde_json::Value。
    if let Ok(v) = row.try_get::<Option<serde_json::Value>, _>(idx) {
        return v.unwrap_or(serde_json::Value::Null);
    }
    // NUMERIC 列：rust_decimal feature 解码后转字符串保精度（与 mysql
    // DECIMAL / SS decimal 字符串口径一致）。
    if let Ok(v) = row.try_get::<Option<rust_decimal::Decimal>, _>(idx) {
        return v
            .map(|d| serde_json::Value::String(d.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    // 网关日期解码（CH 派生评估① 顺带收口）：sqlx chrono feature——
    // DATE/TIME/TIMESTAMP（NaiveDateTime 严格匹配 TIMESTAMP，不含时区）
    // 与 TIMESTAMPTZ（DateTime<Utc>，UTC 墙钟渲染，无时区后缀；服务端无
    // 客户端时区概念）。uuid feature——PG UUID 列（uuid crate 本就是
    // 直接依赖）。
    if let Ok(v) = row.try_get::<Option<NaiveDate>, _>(idx) {
        return v
            .map(|d| serde_json::Value::String(d.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<NaiveTime>, _>(idx) {
        return v
            .map(|t| serde_json::Value::String(t.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<NaiveDateTime>, _>(idx) {
        return v
            .map(|t| serde_json::Value::String(t.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<DateTime<Utc>>, _>(idx) {
        return v
            .map(|t| serde_json::Value::String(t.naive_utc().to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<uuid::Uuid>, _>(idx) {
        return v
            .map(|u| serde_json::Value::String(u.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    // 其余类型（bytea/数组等）归一为 null——已知边界，见客户端
    // postgresql_gateway_adapter 头注。
    serde_json::Value::Null
}

/// SQLite 执行 SQL。
pub(crate) async fn execute_sql_sqlite(
    pool: &sqlx::SqlitePool,
    sql: &str,
    limit: usize,
    is_select: bool,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    if is_select {
        let rows = sqlx::query(sql).fetch_all(pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        rows_to_json_sqlite(&rows, limit)
    } else {
        let result = sqlx::query(sql).execute(pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(serde_json::json!({
            "columns": [],
            "rows": [],
            "affectedRows": result.rows_affected(),
        }))
    }
}

fn rows_to_json_sqlite(
    rows: &[sqlx::sqlite::SqliteRow],
    limit: usize,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    if rows.is_empty() {
        return Ok(serde_json::json!({"columns": [], "rows": []}));
    }
    let columns: Vec<(String, String)> = rows[0]
        .columns()
        .iter()
        .map(|c| (c.name().to_string(), c.type_info().to_string()))
        .collect();
    let col_names: Vec<String> = columns.iter().map(|(n, _)| n.clone()).collect();
    let col_types: serde_json::Value = columns
        .iter()
        .map(|(n, t)| serde_json::json!({"name": n, "type": t}))
        .collect();
    let mut json_rows = Vec::with_capacity(rows.len().min(limit));
    for row in rows.iter().take(limit) {
        let mut map = serde_json::Map::new();
        for (i, (name, _)) in columns.iter().enumerate() {
            let val = decode_cell_sqlite(row, i);
            map.insert(name.clone(), val);
        }
        json_rows.push(serde_json::Value::Object(map));
    }
    Ok(serde_json::json!({
        "columns": col_names,
        "columnTypes": col_types,
        "rows": json_rows,
    }))
}

pub(crate) fn decode_cell_sqlite(row: &sqlx::sqlite::SqliteRow, idx: usize) -> serde_json::Value {
    if let Ok(v) = row.try_get::<Option<String>, _>(idx) {
        return v.map(serde_json::Value::String).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<i64>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<f64>, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<bool>, _>(idx) {
        return v.map(serde_json::Value::Bool).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<Vec<u8>>, _>(idx) {
        return v.map(|b| match String::from_utf8(b.clone()) {
            Ok(s) => serde_json::Value::String(s),
            Err(_) => serde_json::Value::String(format!("<{} bytes>", b.len())),
        }).unwrap_or(serde_json::Value::Null);
    }
    serde_json::Value::Null
}

// ── 连接池辅助 ──

/// Apply charset/timezone session settings to a freshly-opened MySQL pool.
///
/// The pool is `max_connections(1)`, so the SET affects the single connection
/// that all subsequent queries on this pool reuse — mirroring what the client
/// does in `createTabSession` / `adapter.connect`. SET 语句集经族 profile
/// （T21：Doris 跳过 SET time_zone——不支持该语句）。Errors are logged but
/// non-fatal: a bad charset/timezone shouldn't block the connection.
pub(crate) async fn apply_mysql_session(
    pool: &sqlx::Pool<sqlx::MySql>,
    charset: Option<&str>,
    timezone: Option<&str>,
    db_type: &str,
) {
    // T21 — SET 语句集与执行模式都经族 profile（Doris：只 SET NAMES 且
    // raw_sql 下发——其口不吃 PREPARE）。
    let profile = crate::mysql_family::mysql_profile_for(db_type);
    for sql in profile.session_statements(charset, timezone) {
        if let Err(e) =
            crate::mysql_family::execute_by_mode(pool, profile.catalog_mode(), &sql).await
        {
            tracing::warn!(statement = %sql, error = %e, "session SET failed (non-fatal)");
        }
    }
}

// pub(crate) 连接 helper：metadata.rs（T06）复用同一连接生命周期（charset/
// timezone 会话设置、族 profile 握手、read_only 打开语义），不在第二个模块重写。
/// 基础连接参数（不含库名）。T21 — 握手差异经族 profile hook 注入：
/// Doris 的 MySQL 兼容口拒绝 sqlx 默认握手 SET 里的非恒表达式
/// （`sql_mode=(SELECT CONCAT(@@sql_mode, ...))` → errCode 2 "Set statement
/// does't support non-constant expr"），Doris profile 关掉 PIPES_AS_CONCAT /
/// NO_ENGINE_SUBSTITUTION 两个 sql_mode 项让整条 SET 不再发出（实机
/// 192.168.x.x Doris 3.0.2 验证）。SET NAMES utf8mb4 是常量表达式，
/// Doris 支持，保留。族外（ClickHouse 兼容口）回落默认 profile = 零变化。
///
/// T23 — 空密码**不下发** `.password("")`：sqlx 的 mysql_native_password
/// scramble 对空串仍算出 20 字节非空响应（SHA1("") 非空），服务端比对
/// 无密码用户必然 Access denied "(using password: YES)"——TiDB 的 root
/// 默认无密码（实机 1045 验证）。空密码 = 无密码用户，跳过设置即可；
/// 此前空密码一律连不上，修正为严格改进、无回归面。
fn mysql_connect_options(conn: &DbConnectionRow, password: &str) -> sqlx::mysql::MySqlConnectOptions {
    use sqlx::mysql::MySqlConnectOptions;
    let opts = MySqlConnectOptions::new()
        .host(&conn.host)
        .port(conn.port as u16)
        .username(&conn.username);
    let opts = if password.is_empty() { opts } else { opts.password(password) };
    crate::mysql_family::mysql_profile_for(&conn.db_type).handshake(opts)
}

pub(crate) async fn open_mysql(conn: &DbConnectionRow, password: &str) -> Result<sqlx::Pool<sqlx::MySql>, (StatusCode, Json<serde_json::Value>)> {
    let opts = mysql_connect_options(conn, password);
    let pool = sqlx::mysql::MySqlPoolOptions::new().max_connections(1).connect_with(opts).await
        .map_err(|e| db_error("CONNECT_FAILED", &redact(&e.to_string()), 503))?;
    apply_mysql_session(&pool, conn.charset.as_deref(), conn.timezone.as_deref(), &conn.db_type).await;
    Ok(pool)
}

pub(crate) async fn open_mysql_db(conn: &DbConnectionRow, password: &str, db: Option<&str>) -> Result<sqlx::Pool<sqlx::MySql>, (StatusCode, Json<serde_json::Value>)> {
    // 空 db 不下发 database()（Doris 拒绝空库名握手；txn.rs 同一特判）。
    let opts = match db.filter(|d| !d.is_empty()) {
        Some(d) => mysql_connect_options(conn, password).database(d),
        None => mysql_connect_options(conn, password),
    };
    let pool = sqlx::mysql::MySqlPoolOptions::new().max_connections(1).connect_with(opts).await
        .map_err(|e| db_error("CONNECT_FAILED", &redact(&e.to_string()), 503))?;
    apply_mysql_session(&pool, conn.charset.as_deref(), conn.timezone.as_deref(), &conn.db_type).await;
    Ok(pool)
}

pub(crate) async fn open_pg(conn: &DbConnectionRow, password: &str) -> Result<sqlx::Pool<sqlx::Postgres>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::postgres::PgConnectOptions;
    // T29 第二批：网关会话在 pg_stat_activity 中标记 application_name
    //（原为匿名空串，DBA 工具的可观测性缺口；进程列表树按此列展示）。
    let opts = PgConnectOptions::new()
        .host(&conn.host).port(conn.port as u16)
        .username(&conn.username).password(password)
        .application_name("dbmaster-gw");
    sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts).await
        .map_err(|e| db_error("CONNECT_FAILED", &redact(&e.to_string()), 503))
}

pub(crate) async fn open_pg_db(conn: &DbConnectionRow, password: &str, db: Option<&str>) -> Result<sqlx::Pool<sqlx::Postgres>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::postgres::PgConnectOptions;
    let opts = PgConnectOptions::new()
        .host(&conn.host).port(conn.port as u16)
        .username(&conn.username).password(password)
        .application_name("dbmaster-gw")
        .database(db.unwrap_or("postgres"));
    sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts).await
        .map_err(|e| db_error("CONNECT_FAILED", &redact(&e.to_string()), 503))
}

pub(crate) async fn open_sqlite(conn: &DbConnectionRow) -> Result<sqlx::SqlitePool, (StatusCode, Json<serde_json::Value>)> {
    let path = conn.file_path.as_deref()
        .ok_or_else(|| db_error("CONFIG_ERROR", "sqlite connection missing file_path", 400))?;
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .read_only(false) // DBA 工具需要写
        .create_if_missing(false);
    sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(opts).await
        .map_err(|e| db_error("CONNECT_FAILED", &redact(&e.to_string()), 503))
}

// ── SQL 安全辅助 ──

/// 判断是否 SELECT 语句（用于决定是否 gate + 是否返回结果集）。
/// 简单前缀检查（不解析 SQL）。WITH ... 也算 SELECT（CTE）。
pub(crate) fn is_select_statement(sql: &str) -> bool {
    let trimmed = sql.trim_start();
    let upper = trimmed.to_uppercase();
    upper.starts_with("SELECT") || upper.starts_with("WITH") || upper.starts_with("SHOW")
        || upper.starts_with("DESCRIBE") || upper.starts_with("EXPLAIN") || upper.starts_with("PRAGMA")
}

/// 是否 SHOW 语句（前缀检查，与 is_select_statement 同款口径）。T29 —
/// MySQL 族 PREPARE 协议对部分 SHOW 报 1295，stream_query 据此切文本协议。
pub(crate) fn is_show_statement(sql: &str) -> bool {
    let trimmed = sql.trim_start();
    trimmed.len() >= 4 && trimmed[..4].eq_ignore_ascii_case("SHOW")
}

/// Check if a SQL statement is a DDL statement (CREATE/ALTER/DROP/TRUNCATE/RENAME).
/// Used by the DDL approval execution guard to reject DML/query SQL.
pub(crate) fn is_ddl_statement(sql: &str) -> bool {
    let trimmed = sql.trim_start();
    let upper = trimmed.to_uppercase();
    upper.starts_with("CREATE")
        || upper.starts_with("ALTER")
        || upper.starts_with("DROP")
        || upper.starts_with("TRUNCATE")
        || upper.starts_with("RENAME")
}

/// Execute DDL statements on a target database connection.
///
/// Used by the DDL approvals flow (approve → async spawn → execute).
/// Security:
/// - DDL whitelist: each statement must be CREATE/ALTER/DROP/TRUNCATE/RENAME.
/// - Transactional: wraps all statements in START TRANSACTION/COMMIT/ROLLBACK
///   via the DbBackend trait (pinned-pool max=1). Any failure → ROLLBACK.
/// - ClickHouse rejected (no transaction support).
///
/// Returns Ok(()) on success, Err(message) on failure (message is redacted).
pub(crate) async fn execute_ddl_on_target(
    state: &AppState,
    target_db_id: &str,
    ddl_sql: &str,
) -> Result<(), String> {
    // T19 — 主体下沉到 (pool, key) 形态（REST 审批与 MCP execute_write
    // 共用同一执行实现），本函数保留 AppState 签名，approve handler 不动。
    execute_ddl_on_target_with_key(&state.pool, &state.credential_key, target_db_id, ddl_sql).await
}

/// [`execute_ddl_on_target`] 的 (pool, key) 形态——MCP 写路径
/// （dbx-response T19 `execute_write`）的执行后端入口。
///
/// MCP 工具层没有完整 AppState（对齐 `read_query::run_read_query` 的参数
/// 形态），但执行语义与 REST 审批「批准即执行」**完全同源**：DDL 白名单、
/// read_only / source_drift 守卫、ClickHouse 拒绝、顺序执行。勿在他处复制。
pub async fn execute_ddl_on_target_with_key(
    pool: &SqlitePool,
    credential_key: &CredentialKey,
    target_db_id: &str,
    ddl_sql: &str,
) -> Result<(), String> {
    let (conn, password) = load_and_decrypt_key(pool, credential_key, target_db_id)
        .await
        .map_err(|(_, err_body)| {
            err_body
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("credential decrypt failed")
                .to_string()
        })?;

    // Reject ClickHouse — no transaction support for DDL.
    if conn.db_type.eq_ignore_ascii_case("clickhouse") {
        return Err("ClickHouse does not support transactional DDL execution".to_string());
    }

    // Check read_only / source_drift guard.
    // kind and read_only are on database_connections; load_and_decrypt only
    // fetches the core fields, so we query them separately.
    let guard: Option<(String, i64)> = sqlx::query_as(
        "SELECT kind, read_only FROM database_connections WHERE id = ?1",
    )
    .bind(target_db_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if let Some((kind, read_only)) = guard {
        if read_only != 0 {
            return Err("target connection is read-only".to_string());
        }
        if kind == "source_drift" {
            return Err("cannot execute DDL on a source_drift connection".to_string());
        }
    }

    let backend = backend_for(&conn.db_type).map_err(|(_, err_body)| {
        err_body
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("unsupported db_type")
            .to_string()
    })?;

    let db_name = conn.default_database.clone();
    let statements = crate::sql_split::split_sql_script(ddl_sql);

    // Validate every statement is DDL (whitelist).
    for stmt in &statements {
        let s = stmt.trim();
        if s.is_empty() {
            continue;
        }
        if !is_ddl_statement(s) {
            return Err(format!(
                "rejected non-DDL statement (only CREATE/ALTER/DROP/TRUNCATE/RENAME allowed): {}",
                redact(s)
            ));
        }
    }

    // Execute each statement. On any failure, the caller (approve handler)
    // records status='failed' + exec_error. We don't use an explicit SQL
    // transaction here because DDL in MySQL/PG is often auto-commit per
    // statement; instead we execute sequentially and abort on first error.
    // (A full transactional DDL flow would require per-engine semantics that
    //  vary — MySQL DDL auto-commits, PG allows transactional DDL for some
    //  forms. Sequential-abort is the safest cross-engine default.)
    for stmt in &statements {
        let s = stmt.trim();
        if s.is_empty() {
            continue;
        }
        if let Err((_status, err_body)) = backend
            .execute_query(&conn, &password, db_name.as_deref(), s, 1, false)
            .await
        {
            let msg = err_body
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("execution failed");
            return Err(redact(msg));
        }
    }

    Ok(())
}

/// SQLite 标识符引用（PRAGMA table_info 需要裸表名，但防注入用引号包裹）。
pub(crate) fn quote_ident_sqlite(name: &str) -> String {
    // 只允许 [A-Za-z0-9_]（PRAGMA 的表名参数不解析 SQL 引用）
    if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        name.to_string()
    } else {
        // 有特殊字符，用双引号包裹（SQLite 标准）
        format!("\"{}\"", name.replace('"', "\"\""))
    }
}

/// 错误消息 redact（不泄露 host/SQL/凭据到 wire）。
///
/// 原始错误以 WARN 落 server 日志（截断 200 字符，与 file_path/config 分支
/// 的口径一致）——wire 保持脱敏，但运维排查（如 macOS 本地网络权限的
/// "No route to host"）不再被统一话术 "query execution failed" 挡住。
pub(crate) fn redact(s: &str) -> String {
    tracing::warn!(
        err = %s.chars().take(200).collect::<String>(),
        "db test/connect failed (redacted for wire)"
    );
    if s.contains("connect") || s.contains("Connection") {
        "database connection failed".to_string()
    } else if s.contains("file_path") || s.contains("config") {
        s.chars().take(200).collect()
    } else {
        "query execution failed".to_string()
    }
}

// ── 响应辅助 ──

pub(crate) fn ok_response(data: serde_json::Value) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "data": data, "error": null}))
}

pub(crate) fn db_error(code: &str, message: &str, status: u16) -> (StatusCode, Json<serde_json::Value>) {
    let sc = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (sc, Json(serde_json::json!({
        "ok": false, "data": null,
        "error": {"code": code, "message": message}
    })))
}

pub(crate) fn not_found(code: &str, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({
        "ok": false, "data": null,
        "error": {"code": code, "message": message}
    })))
}

fn bad_request(code: &str, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({
        "ok": false, "data": null,
        "error": {"code": code, "message": message}
    })))
}

// ── DbBackend 实现（per-DB 逻辑集中处）──
//
// 每个 impl 调用上面的 open_*/execute_sql_*/decode_* 等 helper。加新 SQL 库
// = 在此追加一个 struct + impl 块 + backend_for 加一行。

#[async_trait::async_trait]
impl DbBackend for MysqlFamilyBackend {
    async fn test(&self, conn: &DbConnectionRow, password: &str) -> Result<(), String> {
        test_mysql(conn, password).await.map_err(|e| redact(&e.to_string()))
    }

    async fn list_databases(&self, conn: &DbConnectionRow, password: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql(conn, password).await?;
        // SHOW DATABASES returns a VARBINARY column; decode_mysql_string tolerates it.
        // T21 — 执行模式经 profile（Doris 的 prepare-ok 包不合规 → raw_sql）。
        let rows = crate::mysql_family::fetch_all_by_mode(
            &pool, self.profile.catalog_mode(), "SHOW DATABASES", None,
        ).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.iter().map(|r| decode_mysql_string(r, 0)).collect())
    }

    async fn list_tables(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql_db(conn, password, db).await?;
        let rows = crate::mysql_family::fetch_all_by_mode(
            &pool, self.profile.catalog_mode(), "SHOW TABLES", None,
        ).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.iter().map(|r| decode_mysql_string(r, 0)).collect())
    }

    async fn list_columns(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<ColumnInfo>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql_db(conn, password, db).await?;
        // T21 — 过滤条件片段随执行模式派生（profile hook）：Prepare 模式
        // DATABASE() + `?` 绑定（= 既有 SQL）；RawSql 模式内联转义字面量。
        // RawSql 下无 default_database 时以空串条件兜底（无行，与
        // DATABASE() 为 NULL 的既有语义等价）。
        let db_name = db.or(conn.default_database.as_deref()).unwrap_or("");
        let sql = format!(
            "SELECT column_name, data_type,
                    CASE WHEN column_key = 'PRI' THEN 1 ELSE 0 END,
                    CASE WHEN is_nullable = 'YES' THEN 1 ELSE 0 END,
                    column_default
             FROM information_schema.columns
             WHERE {} AND {}
             ORDER BY ordinal_position",
            self.profile.schema_condition(db_name),
            self.profile.table_condition(table),
        );
        let bind = match self.profile.catalog_mode() {
            crate::mysql_family::CatalogQueryMode::Prepare => Some(table),
            crate::mysql_family::CatalogQueryMode::RawSql => None,
        };
        let rows = crate::mysql_family::fetch_all_by_mode(
            &pool, self.profile.catalog_mode(), &sql, bind,
        ).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.iter().map(|r| ColumnInfo {
            name: decode_mysql_string(r, 0),
            data_type: decode_mysql_string(r, 1),
            is_primary_key: r.try_get::<i64, _>(2).unwrap_or(0),
            is_nullable: r.try_get::<i64, _>(3).unwrap_or(0),
            default_value: {
                let opt: Option<Vec<u8>> = r.try_get(4).ok();
                opt.map(|b| String::from_utf8_lossy(&b).into_owned())
            },
        }).collect())
    }

    async fn list_schema_objects(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, kind: SchemaObjectKind)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql_db(conn, password, db).await?;
        let sql = match kind {
            SchemaObjectKind::Views => "SELECT table_name FROM information_schema.views WHERE table_schema = DATABASE() ORDER BY table_name",
            SchemaObjectKind::Procedures => "SELECT routine_name FROM information_schema.routines WHERE routine_schema = DATABASE() AND routine_type = 'PROCEDURE' ORDER BY routine_name",
            SchemaObjectKind::Functions => "SELECT routine_name FROM information_schema.routines WHERE routine_schema = DATABASE() AND routine_type = 'FUNCTION' ORDER BY routine_name",
            SchemaObjectKind::Triggers => "SELECT trigger_name FROM information_schema.triggers WHERE trigger_schema = DATABASE() ORDER BY trigger_name",
        };
        // DATABASE() 条件两模式通用（服务端求值）；执行模式经 profile。
        let rows = crate::mysql_family::fetch_all_by_mode(
            &pool, self.profile.catalog_mode(), sql, None,
        ).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.iter().map(|r| decode_mysql_string(r, 0)).collect())
    }

    async fn list_indexes(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql_db(conn, password, db).await?;
        let db_name = db.or(conn.default_database.as_deref()).unwrap_or("");
        let sql = format!(
            "SELECT index_name FROM information_schema.statistics WHERE {} AND {} GROUP BY index_name ORDER BY index_name",
            self.profile.schema_condition(db_name),
            self.profile.table_condition(table),
        );
        let bind = match self.profile.catalog_mode() {
            crate::mysql_family::CatalogQueryMode::Prepare => Some(table),
            crate::mysql_family::CatalogQueryMode::RawSql => None,
        };
        let rows = crate::mysql_family::fetch_all_by_mode(
            &pool, self.profile.catalog_mode(), &sql, bind,
        ).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.iter().map(|r| decode_mysql_string(r, 0)).collect())
    }

    async fn list_foreign_keys(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql_db(conn, password, db).await?;
        let db_name = db.or(conn.default_database.as_deref()).unwrap_or("");
        let sql = format!(
            "SELECT constraint_name FROM information_schema.key_column_usage WHERE {} AND {} AND constraint_name <> 'PRIMARY' ORDER BY constraint_name",
            self.profile.schema_condition(db_name),
            self.profile.table_condition(table),
        );
        let bind = match self.profile.catalog_mode() {
            crate::mysql_family::CatalogQueryMode::Prepare => Some(table),
            crate::mysql_family::CatalogQueryMode::RawSql => None,
        };
        let rows = crate::mysql_family::fetch_all_by_mode(
            &pool, self.profile.catalog_mode(), &sql, bind,
        ).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.iter().map(|r| decode_mysql_string(r, 0)).collect())
    }

    async fn execute_query(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, sql: &str, limit: usize, is_select: bool)
        -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql_db(conn, password, db).await?;
        // T21 — SELECT 按执行模式分流（MySQL prepare / Doris raw_sql，
        // read_query 经 backend_for 的 Doris 收口走同一通道）。
        execute_sql_mysql(&pool, sql, limit, is_select, self.profile.catalog_mode()).await
    }
}

#[async_trait::async_trait]
impl DbBackend for PostgresBackend {
    async fn test(&self, conn: &DbConnectionRow, password: &str) -> Result<(), String> {
        test_pg(conn, password).await.map_err(|e| redact(&e.to_string()))
    }

    async fn list_databases(&self, conn: &DbConnectionRow, password: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_pg(conn, password).await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname"
        ).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_tables(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_pg_db(conn, password, db).await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"
        ).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_columns(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<ColumnInfo>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_pg_db(conn, password, db).await?;
        let rows: Vec<ColumnInfo> = sqlx::query_as::<_, ColumnInfo>(
            "SELECT c.column_name AS name, c.data_type AS data_type,
                    CASE WHEN pk.column_name IS NOT NULL THEN 1 ELSE 0 END AS is_primary_key,
                    CASE WHEN c.is_nullable = 'YES' THEN 1 ELSE 0 END AS is_nullable,
                    c.column_default AS default_value
             FROM information_schema.columns c
             LEFT JOIN (
                 SELECT kcu.column_name FROM information_schema.table_constraints tc
                 JOIN information_schema.key_column_usage kcu
                   ON tc.constraint_name = kcu.constraint_name
                 WHERE tc.constraint_type = 'PRIMARY KEY' AND kcu.table_name = $1
             ) pk ON c.column_name = pk.column_name
             WHERE c.table_name = $1 AND c.table_schema = 'public'
             ORDER BY c.ordinal_position"
        ).bind(table).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows)
    }

    async fn list_schema_objects(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, kind: SchemaObjectKind)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_pg_db(conn, password, db).await?;
        let sql = match kind {
            SchemaObjectKind::Views => "SELECT viewname FROM pg_views WHERE schemaname = 'public' ORDER BY viewname",
            SchemaObjectKind::Procedures => "SELECT routine_name FROM information_schema.routines WHERE routine_schema = 'public' AND routine_type = 'PROCEDURE' ORDER BY routine_name",
            SchemaObjectKind::Functions => "SELECT routine_name FROM information_schema.routines WHERE routine_schema = 'public' AND routine_type = 'FUNCTION' ORDER BY routine_name",
            SchemaObjectKind::Triggers => "SELECT trigger_name FROM information_schema.triggers WHERE trigger_schema = 'public' ORDER BY trigger_name",
        };
        let rows: Vec<(String,)> = sqlx::query_as(sql).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_indexes(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_pg_db(conn, password, db).await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND tablename = $1 ORDER BY indexname"
        ).bind(table).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_foreign_keys(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_pg_db(conn, password, db).await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT conname FROM pg_constraint WHERE contype = 'f' AND conrelid = $1::regclass ORDER BY conname"
        ).bind(table).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn execute_query(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, sql: &str, limit: usize, is_select: bool)
        -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_pg_db(conn, password, db).await?;
        execute_sql_pg(&pool, sql, limit, is_select).await
    }
}

#[async_trait::async_trait]
impl DbBackend for SqliteBackend {
    async fn test(&self, conn: &DbConnectionRow, _password: &str) -> Result<(), String> {
        test_sqlite(conn).await.map_err(|e| redact(&e.to_string()))
    }

    async fn list_databases(&self, _conn: &DbConnectionRow, _password: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        // SQLite 没有"数据库列表"概念，返回 main。
        Ok(vec!["main".to_string()])
    }

    async fn list_tables(&self, conn: &DbConnectionRow, _password: &str, _db: Option<&str>)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_sqlite(conn).await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_columns(&self, conn: &DbConnectionRow, _password: &str, _db: Option<&str>, table: &str)
        -> Result<Vec<ColumnInfo>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_sqlite(conn).await?;
        let sql = format!("PRAGMA table_info({})", quote_ident_sqlite(table));
        let rows = sqlx::query(&sql).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        let mut cols = Vec::with_capacity(rows.len());
        for row in &rows {
            let name: String = row.try_get("name").unwrap_or_default();
            let data_type: String = row.try_get("type").unwrap_or_default();
            let notnull: i64 = row.try_get("notnull").unwrap_or(0);
            let pk: i64 = row.try_get("pk").unwrap_or(0);
            let dflt: Option<String> = row.try_get("dflt_value").ok();
            cols.push(ColumnInfo {
                name,
                data_type,
                is_primary_key: pk,
                // PRAGMA notnull=1 means NOT NULL → is_nullable = 0.
                is_nullable: if notnull == 0 { 1 } else { 0 },
                default_value: dflt,
            });
        }
        Ok(cols)
    }

    async fn list_schema_objects(&self, conn: &DbConnectionRow, _password: &str, _db: Option<&str>, kind: SchemaObjectKind)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        match kind {
            SchemaObjectKind::Views => {
                let pool = open_sqlite(conn).await?;
                let rows: Vec<(String,)> = sqlx::query_as(
                    "SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name"
                ).fetch_all(&pool).await
                    .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
                Ok(rows.into_iter().map(|r| r.0).collect())
            }
            // SQLite has no procedures/functions listable via master; triggers
            // exist but the client adapter treats them as empty. Return [].
            _ => Ok(Vec::new()),
        }
    }

    async fn list_indexes(&self, conn: &DbConnectionRow, _password: &str, _db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_sqlite(conn).await?;
        let sql = format!("PRAGMA index_list({})", quote_ident_sqlite(table));
        let rows = sqlx::query(&sql).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        let mut names = Vec::with_capacity(rows.len());
        for row in &rows {
            let name: String = row.try_get("name").unwrap_or_default();
            if !name.is_empty() { names.push(name); }
        }
        Ok(names)
    }

    async fn list_foreign_keys(&self, conn: &DbConnectionRow, _password: &str, _db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_sqlite(conn).await?;
        let sql = format!("PRAGMA foreign_key_list({})", quote_ident_sqlite(table));
        let rows = sqlx::query(&sql).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        let mut names = Vec::with_capacity(rows.len());
        for row in &rows {
            let table: String = row.try_get("table").unwrap_or_default();
            let to_col: String = row.try_get("to").unwrap_or_default();
            if !table.is_empty() {
                names.push(format!("fk_{table}_{to_col}"));
            }
        }
        Ok(names)
    }

    async fn execute_query(&self, conn: &DbConnectionRow, _password: &str, _db: Option<&str>, sql: &str, limit: usize, is_select: bool)
        -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_sqlite(conn).await?;
        execute_sql_sqlite(&pool, sql, limit, is_select).await
    }
}

// ── ClickHouse backend ──
//
// ClickHouse exposes a MySQL-wire-protocol compatibility port (9004 by
// convention), so this backend reuses sqlx's MySQL driver + the same
// open_mysql_db connection helper. The browse SQL differs from MySQL's
// information_schema — CH uses its own system.* tables. SHOW DATABASES /
// SHOW TABLES are also supported and used for the name-list endpoints.
//
// This is the payoff of the DbBackend trait: a new database in one impl
// block, no handler/routing changes.
#[async_trait::async_trait]
impl DbBackend for ClickhouseBackend {
    async fn test(&self, conn: &DbConnectionRow, password: &str) -> Result<(), String> {
        // Reuse the MySQL test path — CH's 9004 port speaks MySQL protocol.
        test_mysql(conn, password).await.map_err(|e| redact(&e.to_string()))
    }

    async fn list_databases(&self, conn: &DbConnectionRow, password: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql(conn, password).await?;
        let rows = sqlx::query("SHOW DATABASES").fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.iter().map(|r| decode_mysql_string(r, 0)).collect())
    }

    async fn list_tables(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql_db(conn, password, db).await?;
        // CH supports SHOW TABLES over the MySQL protocol.
        let rows = sqlx::query("SHOW TABLES").fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.iter().map(|r| decode_mysql_string(r, 0)).collect())
    }

    async fn list_columns(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<ColumnInfo>, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql_db(conn, password, db).await?;
        // CH's system.columns (26.x): database, table, name, type, position, ...
        // — no is_in_primary_key / nullable flag. Derive nullability from the
        // type string (Nullable(T) prefix); PK is a table-level MergeTree
        // property, report 0.
        //
        // CH's MySQL-wire proto does NOT support prepared-statement parameter
        // binding (`?`), so we interpolate escaped literals rather than bind.
        let db_name = db.or(conn.default_database.as_deref()).unwrap_or("default");
        let sql = format!(
            "SELECT name, type FROM system.columns \
             WHERE database = {} AND table = {} ORDER BY position",
            ch_str_literal(db_name),
            ch_str_literal(table),
        );
        let rows = sqlx::query(&sql).fetch_all(&pool).await
            .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
        Ok(rows.iter().map(|r| {
            let name = decode_mysql_string(r, 0);
            let col_type = decode_mysql_string(r, 1);
            let is_nullable = if col_type.starts_with("Nullable(") { 1 } else { 0 };
            ColumnInfo {
                name,
                data_type: col_type,
                is_primary_key: 0,
                is_nullable,
                default_value: None,
            }
        }).collect())
    }

    async fn list_schema_objects(&self, _conn: &DbConnectionRow, _password: &str, _db: Option<&str>, _kind: SchemaObjectKind)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        // ClickHouse has no views/procedures/functions/triggers in the
        // MySQL/PG sense (it has *materialized views* and *dictionaries*, but
        // those are distinct concepts). Return empty for all kinds — matches
        // the client adapter's pragmatic stance for unsupported categories.
        Ok(Vec::new())
    }

    async fn list_indexes(&self, _conn: &DbConnectionRow, _password: &str, _db: Option<&str>, _table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        // ClickHouse uses its own indexing model (MergeTree order by / primary
        // key, not discrete index objects). No index-name list to return.
        Ok(Vec::new())
    }

    async fn list_foreign_keys(&self, _conn: &DbConnectionRow, _password: &str, _db: Option<&str>, _table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        // ClickHouse has no foreign-key constraints.
        Ok(Vec::new())
    }

    async fn execute_query(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, sql: &str, limit: usize, is_select: bool)
        -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)>
    {
        let pool = open_mysql_db(conn, password, db).await?;
        // CH 非 MySQL 族注册表成员——回落默认 profile（Prepare，既有通道）。
        execute_sql_mysql(&pool, sql, limit, is_select, crate::mysql_family::CatalogQueryMode::Prepare).await
    }
}

// ── SQL Server backend（T28 / tiberius，ADR-0005 §2.4 首发试点）──
//
// 连接生命周期与 sqlx 族不同：无连接池，每次调用一条专用 Client<TcpStream>
// （drop 即断连终止服务端批处理——与网关 stream_query 的取消/超时语义同构）。
// 标识符/表名全部经 @P1 绑定参数（TDS 参数化查询），无字符串拼接注入面。

/// SS 查询辅助：开连接 → 参数化查询 → 首个结果集全量行。
async fn ss_query_rows(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    sql: &str,
    params: &[&dyn tiberius::ToSql],
) -> Result<Vec<tiberius::Row>, (StatusCode, Json<serde_json::Value>)> {
    let mut client = open_sqlserver(conn, password, db)
        .await
        .map_err(|e| db_error("CONNECT_FAILED", &redact(&e.to_string()), 503))?;
    let stream = client
        .query(sql, params)
        .await
        .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
    stream
        .into_first_result()
        .await
        .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))
}

/// SS 首列字符串解码（名字级列举端点的投影）。
fn ss_string(row: &tiberius::Row, idx: usize) -> String {
    decode_cell_tds(row, idx).as_str().unwrap_or_default().to_string()
}

/// SS 整数列解码（解码链，NULL/失败归 0）——TDS 强类型下单一具体类型
/// 直解不稳（同 metadata.rs 的发现）。
fn ss_i64(row: &tiberius::Row, idx: usize) -> i64 {
    decode_cell_tds(row, idx).as_i64().unwrap_or(0)
}

#[async_trait::async_trait]
impl DbBackend for SqlServerBackend {
    async fn test(&self, conn: &DbConnectionRow, password: &str) -> Result<(), String> {
        test_sqlserver(conn, password).await.map_err(|e| redact(&e.to_string()))
    }

    async fn list_databases(&self, conn: &DbConnectionRow, password: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        // 全量在线库（与 MySQL backend 的 SHOW DATABASES 不滤系统库同口径；
        // 富元数据面 metadata.rs 另滤 master/model/msdb/tempdb）。
        let rows = ss_query_rows(
            conn, password, None,
            "SELECT name FROM sys.databases ORDER BY name", &[],
        )
        .await?;
        Ok(rows.iter().map(|r| ss_string(r, 0)).collect())
    }

    async fn list_tables(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        // dbo schema only（对齐 PG backend 的 public-only 取舍；schema 透传 v1.1）。
        let rows = ss_query_rows(
            conn, password, db,
            "SELECT t.name FROM sys.tables t
             WHERE t.schema_id = SCHEMA_ID('dbo') ORDER BY t.name", &[],
        )
        .await?;
        Ok(rows.iter().map(|r| ss_string(r, 0)).collect())
    }

    async fn list_columns(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<ColumnInfo>, (StatusCode, Json<serde_json::Value>)>
    {
        let rows = ss_query_rows(
            conn, password, db,
            "SELECT c.name, tp.name AS type_name, c.max_length, c.precision, c.scale,
                    CASE WHEN c.is_nullable = 1 THEN 1 ELSE 0 END,
                    CASE WHEN c.is_identity = 1 OR EXISTS (
                        SELECT 1 FROM sys.index_columns ic
                        JOIN sys.indexes i
                          ON i.object_id = ic.object_id AND i.index_id = ic.index_id
                        WHERE ic.object_id = c.object_id AND ic.column_id = c.column_id
                          AND i.is_primary_key = 1
                    ) THEN 1 ELSE 0 END,
                    OBJECT_DEFINITION(c.default_object_id)
             FROM sys.columns c
             JOIN sys.types tp ON tp.user_type_id = c.user_type_id
             WHERE c.object_id = OBJECT_ID(@P1)
             ORDER BY c.column_id",
            &[&table],
        )
        .await?;
        Ok(rows
            .iter()
            .map(|r| ColumnInfo {
                name: ss_string(r, 0),
                data_type: format_sqlserver_type(
                    &ss_string(r, 1),
                    ss_i64(r, 2) as i16,
                    ss_i64(r, 3) as u8,
                    ss_i64(r, 4) as u8,
                ),
                is_primary_key: ss_i64(r, 6),
                is_nullable: ss_i64(r, 5),
                default_value: crate::sqlserver::strip_default_parens_opt(&decode_cell_tds(r, 7)),
            })
            .collect())
    }

    async fn list_schema_objects(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, kind: SchemaObjectKind)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let sql = match kind {
            SchemaObjectKind::Views => "SELECT name FROM sys.views WHERE schema_id = SCHEMA_ID('dbo') ORDER BY name",
            SchemaObjectKind::Procedures => "SELECT name FROM sys.procedures WHERE schema_id = SCHEMA_ID('dbo') ORDER BY name",
            // FN=标量函数 / IF/TF=表值 / AF=聚合（sys.objects 的函数类型族）。
            SchemaObjectKind::Functions => "SELECT name FROM sys.objects WHERE schema_id = SCHEMA_ID('dbo') AND type IN ('FN','AF','IF','TF') ORDER BY name",
            SchemaObjectKind::Triggers => "SELECT name FROM sys.objects WHERE type = 'TR' AND schema_id = SCHEMA_ID('dbo') ORDER BY name",
        };
        let rows = ss_query_rows(conn, password, db, sql, &[]).await?;
        Ok(rows.iter().map(|r| ss_string(r, 0)).collect())
    }

    async fn list_indexes(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let rows = ss_query_rows(
            conn, password, db,
            "SELECT i.name FROM sys.indexes i
             WHERE i.object_id = OBJECT_ID(@P1) AND i.name IS NOT NULL
             ORDER BY i.name",
            &[&table],
        )
        .await?;
        Ok(rows.iter().map(|r| ss_string(r, 0)).collect())
    }

    async fn list_foreign_keys(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, table: &str)
        -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)>
    {
        let rows = ss_query_rows(
            conn, password, db,
            "SELECT fk.name FROM sys.foreign_keys fk
             WHERE fk.parent_object_id = OBJECT_ID(@P1)
             ORDER BY fk.name",
            &[&table],
        )
        .await?;
        Ok(rows.iter().map(|r| ss_string(r, 0)).collect())
    }

    async fn execute_query(&self, conn: &DbConnectionRow, password: &str, db: Option<&str>, sql: &str, limit: usize, is_select: bool)
        -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)>
    {
        let mut client = open_sqlserver(conn, password, db)
            .await
            .map_err(|e| db_error("CONNECT_FAILED", &redact(&e.to_string()), 503))?;
        if is_select {
            let stream = client
                .query(sql, &[])
                .await
                .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
            let rows = stream
                .into_first_result()
                .await
                .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
            rows_to_json_sqlserver(&rows, limit)
        } else {
            // 原生 batch 执行（execute 的 sp_executesql 上下文拒模块 DDL，
            // 见 sqlserver::execute_tds 文档；admin/script 面常含 CREATE VIEW）。
            let affected = crate::sqlserver::execute_tds(&mut client, sql)
                .await
                .map_err(|e| db_error("QUERY_FAILED", &redact(&e.to_string()), 500))?;
            Ok(serde_json::json!({
                "columns": [],
                "rows": [],
                "affectedRows": affected,
            }))
        }
    }
}

/// SS 行数组 → REST 网关 {columns, columnTypes, rows} JSON（列名 map 行，
/// 与 rows_to_json_mysql 同形）。columnTypes 从首行解码值的 JSON 类型派生
/// （tiberius Column 不透出引擎类型名；REST 老网关面的展示性字段）。
fn rows_to_json_sqlserver(
    rows: &[tiberius::Row],
    limit: usize,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    if rows.is_empty() {
        return Ok(serde_json::json!({"columns": [], "rows": []}));
    }
    let first = &rows[0];
    let col_names: Vec<String> = first.columns().iter().map(|c| c.name().to_string()).collect();
    let first_vals: Vec<serde_json::Value> =
        (0..col_names.len()).map(|i| decode_cell_tds(first, i)).collect();
    let col_types: serde_json::Value = col_names
        .iter()
        .zip(&first_vals)
        .map(|(n, v)| {
            let t = match v {
                serde_json::Value::String(_) => "string",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Number(_) => "number",
                _ => "unknown",
            };
            serde_json::json!({"name": n, "type": t})
        })
        .collect();

    let mut json_rows = Vec::with_capacity(rows.len().min(limit));
    for (ri, row) in rows.iter().take(limit).enumerate() {
        let owned_vals: Vec<serde_json::Value>;
        let vals: &[serde_json::Value] = if ri == 0 {
            &first_vals
        } else {
            owned_vals = (0..col_names.len()).map(|i| decode_cell_tds(row, i)).collect();
            &owned_vals
        };
        let mut map = serde_json::Map::new();
        for (i, name) in col_names.iter().enumerate() {
            map.insert(name.clone(), vals[i].clone());
        }
        json_rows.push(serde_json::Value::Object(map));
    }

    Ok(serde_json::json!({
        "columns": col_names,
        "columnTypes": col_types,
        "rows": json_rows,
    }))
}
