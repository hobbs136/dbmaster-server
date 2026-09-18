//! 富元数据 API（dbx-response T06 / ADR-0005 §2.2）。
//!
//! 比 db_handler 的名字级目录列举更丰富：表/视图 + 注释 + 行数估计、
//! 列（类型/可空/默认/注释）、主键、索引列、外键详情——面向 AI 上下文
//! （对齐 dbx get_schema_context 的取舍：紧凑输出，缺省字段省略键，控制
//! agent 的 token 用量）。
//!
//! **同源纪律**：这是 MCP 元数据工具（T06）与未来网关 API v1（T27）的
//! 共同后端——mcp crate 不直连业务库，一律经本模块；连接生命周期复用
//! db_handler 的 open_* helper（charset/timezone 会话、doris 特判同一份）。
//!
//! **可见性**：与 `/api/connections` v1 语义一致——认证用户可见全部连接
//! （单 workspace 部署）；连接白名单（`mcp.allowed_connections`）是 T08。
//!
//! **错误纪律**：`MetadataError::message` 不含 host/凭据/用户 SQL 明文。
//! 连接失败统一 "database connection failed"；查询失败给截断后的引擎错误
//! 类别（本模块的目录 SQL 全部参数化绑定，错误文本不含调用方输入之外的信息）。
//!
//! 支持的引擎族与 db_handler::backend_for 对齐（MySQL/Doris 同族走
//! MySQL wire；ClickHouse 走 9004 兼容口）：MySQL / PostgreSQL / SQLite /
//! ClickHouse / Doris / SQL Server（T28，tiberius/TDS）。
//! T21 起 MySQL 族内的成员差异（握手/目录查询模式/系统库过滤等）经
//! `mysql_family.rs` 薄适配 profile 注入——`Family::MySql` 携带 profile。

use serde::Serialize;
use sqlx::{Row, SqlitePool};

use crate::credential::decrypt_password;
use crate::db_handler::{
    ch_str_literal, decode_mysql_string, open_mysql, open_mysql_db, open_pg_db, open_sqlite,
    quote_ident_sqlite, DbConnectionRow,
};
use dbmaster_core::server::CredentialKey;

// ── 公共投影类型（serde 直接面向 MCP 工具输出）──

/// 连接的安全投影——**永不**包含 host/username/凭据（MCP 工具契约）。
#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSummary {
    pub id: String,
    pub name: String,
    pub db_type: String,
    pub read_only: bool,
    pub default_database: Option<String>,
}

/// 一张表/视图的概要。`comment` / `row_estimate` 引擎没有就省略键。
///
/// `name` 的命名约定（仅 PG 多 schema 语义下与 `schema` 字段配合）：
/// `public` 的对象保持裸名（`brands`，既有 public-only 库的输出逐字节不变）；
/// 其余 schema 用 `schema.table` 限定（`ecommerce.orders`，多 schema 同名表
/// 可消歧）——该限定名可直接回喂 `describe_table`。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableSummary {
    pub name: String,
    /// 对象所在 schema（PG 非 `public` schema 才有值；键省略语义 = 默认
    /// schema）。`skip_serializing_if` 保证既有引擎/既有 public-only 库的
    /// 输出键集完全不变——MCP 输出是 AI 客户端消费的契约面，只加不删。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// "table" | "view"
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// 统计信息行数估计（InnoDB table_rows / PG reltuples / CH total_rows，
    /// 均为近似值；给 AI 上下文用，避免 agent 主动 COUNT(*)）。无统计时省略。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_estimate: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ColumnDetail {
    pub name: String,
    /// 引擎报告的完整类型（如 varchar(255)、Nullable(Int64)）。
    #[serde(rename = "type")]
    pub data_type: String,
    pub nullable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexDetail {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForeignKeyDetail {
    /// SQLite 的 PRAGMA foreign_key_list 无约束名（以 id 分组），此时省略。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub columns: Vec<String>,
    pub ref_table: String,
    pub ref_columns: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableDescription {
    pub table: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub columns: Vec<ColumnDetail>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub primary_key: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub indexes: Vec<IndexDetail>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub foreign_keys: Vec<ForeignKeyDetail>,
}

/// 元数据查询错误。`code` 稳定（MCP 工具错误 JSON 的 `error.code`），
/// `message` 已按模块级纪律清洗。
#[derive(Debug)]
pub struct MetadataError {
    pub code: &'static str,
    pub message: String,
}

impl MetadataError {
    fn not_found(what: &str) -> Self {
        Self { code: "NOT_FOUND", message: format!("{what} not found") }
    }

    fn unsupported(db_type: &str) -> Self {
        Self {
            code: "UNSUPPORTED_DB_TYPE",
            message: format!("unsupported db_type: {db_type}"),
        }
    }

    /// 连接阶段失败——一律不回传引擎错误细节（可能含 host/DNS）。
    fn connect_failed() -> Self {
        Self { code: "CONNECT_FAILED", message: "database connection failed".to_string() }
    }

    /// 查询阶段失败——错误来自本模块的固定目录 SQL，截断后回传引擎类别。
    fn query_failed(e: &sqlx::Error) -> Self {
        Self {
            code: "QUERY_FAILED",
            message: e.to_string().chars().take(200).collect(),
        }
    }

    /// T28 — SQL Server（tiberius）查询失败，同 query_failed 口径。
    fn query_failed_tds(e: tiberius::error::Error) -> Self {
        Self {
            code: "QUERY_FAILED",
            message: e.to_string().chars().take(200).collect(),
        }
    }

    /// T29 非 SQL 批次（B1）— MongoDB 命令失败，同 query_failed 口径（截断
    /// 引擎文本；本模块目录命令全部固定形状，错误文本不含调用方输入）。
    fn query_failed_mongo(e: &mongodb::error::Error) -> Self {
        Self {
            code: "QUERY_FAILED",
            message: e.to_string().chars().take(200).collect(),
        }
    }

    /// T29 TDengine 批次 — REST 通道失败归一：传输/认证连接级；引擎/HTTP
    /// 错误截断文本（desc 是引擎级消息，不含调用方输入）。
    fn from_td(e: crate::tdengine_leg::TdError) -> Self {
        use crate::tdengine_leg::TdError;
        match e {
            TdError::Transport | TdError::Auth => Self::connect_failed(),
            TdError::Http(status, body) => Self {
                code: "QUERY_FAILED",
                message: format!("taosAdapter HTTP {status}: {}", &body.chars().take(180).collect::<String>()),
            },
            TdError::Engine(code, desc) => Self {
                code: "QUERY_FAILED",
                message: format!("TDengine error {code}: {}", &desc.chars().take(180).collect::<String>()),
            },
        }
    }

    fn config(msg: &str) -> Self {
        Self { code: "CONFIG_ERROR", message: msg.to_string() }
    }
}

// ── 引擎族分发 ──

#[derive(Clone, Copy)]
pub(crate) enum Family {
    /// MySQL wire 族：mysql + doris（及 T22-T25 后续成员）。T21 起携带
    /// 薄适配 profile——族内差异（目录查询模式/系统库过滤/行数估计来源）
    /// 经 hook 注入，不再散落 db_type 特判。
    MySql(&'static dyn crate::mysql_family::MysqlFamilyHooks),
    Postgres,
    Sqlite,
    /// ClickHouse（MySQL 兼容口 9004，system.* 目录，无绑定参数）。
    Clickhouse,
    /// SQL Server（TDS/tiberius，T28）：sys.* 目录，dbo schema（v1 对齐 PG
    /// 的 public-only 取舍，schema 透传随 v1.1）。
    SqlServer,
    /// MongoDB（T29 非 SQL 批次 B1，ADR-0006 §2.6）：listDatabases /
    /// listCollections / 采样推列（对齐客户端 getTables/getTableColumns 的
    /// 退化实现语义）；列无固定 schema（nullable 恒 true）。
    Mongo,
    /// Redis（T29 非 SQL 批次 B3，ADR-0006 §2.6）：list_databases = CONFIG GET
    /// databases（上限 256，失败回落 INFO keyspace）；list_tables = SCAN 全
    /// key 按 `:` 前缀聚命名空间；describe = 命名空间采样首 key 按 TYPE 推列。
    Redis,
    /// TDengine（T29 TDengine 批次）：taosAdapter REST 通道。list_databases
    /// = SHOW DATABASES（滤 information_schema/performance_schema，对齐客户
    /// 端）；list_tables = SHOW STABLES（用户库）/ SHOW TABLES（系统库）；
    /// describe = DESCRIBE（note 列含 TAG 标记）。
    Tdengine,
}

/// 手动实现（族成员是 `&'static dyn`，不能 derive）；MySql 分支打印
/// profile 名，便于测试断言与诊断输出。
impl std::fmt::Debug for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Family::MySql(profile) => write!(f, "MySql({})", profile.name()),
            Family::Postgres => write!(f, "Postgres"),
            Family::Sqlite => write!(f, "Sqlite"),
            Family::Clickhouse => write!(f, "Clickhouse"),
            Family::SqlServer => write!(f, "SqlServer"),
            Family::Mongo => write!(f, "Mongo"),
            Family::Redis => write!(f, "Redis"),
            Family::Tdengine => write!(f, "Tdengine"),
        }
    }
}

fn family_for(db_type: &str) -> Result<Family, MetadataError> {
    // T21 — MySQL 协议族经薄适配注册表（mysql/doris 及后续成员一处注册，
    // backend_for / stream_query / txn 同源生效）。
    if let Some(profile) = crate::mysql_family::mysql_family_for(db_type) {
        return Ok(Family::MySql(profile));
    }
    match db_type.to_ascii_lowercase().as_str() {
        "postgres" | "postgresql" | "pg" => Ok(Family::Postgres),
        "sqlite" => Ok(Family::Sqlite),
        "clickhouse" => Ok(Family::Clickhouse),
        // T28 — mssql 为常见别名（与 backend_for / 网关注册端点同口径）。
        "sqlserver" | "mssql" => Ok(Family::SqlServer),
        // T29 非 SQL 批次（B1）— mongodb（canonical wire 名；mongo 别名同
        // mssql 先例接受）。执行走 stream_query 的 kind:"mongo" 通道。
        "mongodb" | "mongo" => Ok(Family::Mongo),
        // T29 非 SQL 批次（B3）— redis（执行 kind:"redis" 命令/pipeline 通道
        // + 订阅转发端点）。注意 health_check runner 是自己的 db_type match，
        // redis 仍走 connectivity-only 降级（无 Redis 监控语义，§2.6）。
        "redis" => Ok(Family::Redis),
        // T29 TDengine 批次 — kind:"tdengine" 通道（sql + REST db 路由）。
        // health_check runner 同样自有 db_type match（connectivity-only 降级）。
        "tdengine" => Ok(Family::Tdengine),
        other => Err(MetadataError::unsupported(other)),
    }
}

/// 加载连接行并按需解密密码。SQLite 不用密码（file_path 即凭据），跳过
/// 解密以容忍空存储值。
///
/// 网络层批次（2026-08-29）— 本函数是 SSH 隧道的统一收口：行带 ssh 配置
/// （extra 四键 + `ssh_secret_encrypted`）时解析/复用进程级隧道，把行
/// host/port 改写为本地转发端口并在 extra 注入 `tunneled:true`——后续
/// 所有腿（SQL 族 / redis / mongo / tdengine）与 TLS over tunnel 自然成立。
/// sqlite 不经隧道（无 host）；秘密解密与密码同层（只在内存传递，绝不
/// 进日志）。
pub(crate) async fn load_connection(    pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
) -> Result<(DbConnectionRow, Family, String), MetadataError> {
    let mut conn: DbConnectionRow = sqlx::query_as::<_, DbConnectionRow>(
        "SELECT db_type, host, port, username, password_encrypted,
                default_database, file_path, charset, timezone, extra, read_only,
                ssh_secret_encrypted
         FROM database_connections WHERE id = ?1",
    )
    .bind(conn_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| MetadataError {
        code: "DB_ERROR",
        message: format!("server database read failed: {}", &e.to_string().chars().take(120).collect::<String>()),
    })?
    .ok_or_else(|| MetadataError::not_found(&format!("connection '{conn_id}'")))?;

    let family = family_for(&conn.db_type)?;
    let password = match family {
        Family::Sqlite => String::new(),
        _ => decrypt_password(&conn.password_encrypted, key).map_err(|_| MetadataError {
            code: "DECRYPT_FAILED",
            message: "stored credential could not be decrypted".to_string(),
        })?,
    };
    // ── SSH 隧道收口（带配置的行才走；失败归一 CONNECTION_FAILED，不泄露
    // 秘密/内部细节）──
    if !matches!(family, Family::Sqlite) {
        if let Some(ssh_cfg) = crate::ssh::config_from_extra(conn.extra.as_deref()) {
            let secret_ct = conn.ssh_secret_encrypted.as_deref().unwrap_or("");
            let secrets: crate::ssh::SshSecrets = if secret_ct.is_empty() {
                return Err(MetadataError {
                    code: "CONNECTION_FAILED",
                    message: "ssh tunnel enabled but secret is missing".to_string(),
                });
            } else {
                crate::credential::decrypt_password(secret_ct, key)
                    .ok()
                    .and_then(|json| serde_json::from_str(&json).ok())
                    .ok_or_else(|| MetadataError {
                        code: "DECRYPT_FAILED",
                        message: "stored ssh secret could not be decrypted".to_string(),
                    })?
            };
            let (host, port, extra) = crate::ssh::apply_tunnel(
                &conn.host,
                conn.port,
                conn.extra.as_deref(),
                &ssh_cfg,
                &secrets,
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "ssh tunnel resolve failed");
                MetadataError {
                    code: "CONNECTION_FAILED",
                    message: "ssh tunnel setup failed".to_string(),
                }
            })?;
            conn.host = host;
            conn.port = port;
            conn.extra = extra;
        }
    }
    Ok((conn, family, password))
}

/// T29 非 SQL 批次（B3）— 网关订阅端点用：按 conn_id 开 Redis 订阅专用
/// 连接（校验 Family::Redis；PubSub 与 db 无关，固定 db 0——keyspace 通知
/// 的库路由在 pattern `__keyevent@<db>__` 里）。
pub async fn open_redis_pubsub_for(
    pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
) -> Result<redis::aio::PubSub, MetadataError> {
    let (conn, family, password) = load_connection(pool, key, conn_id).await?;
    if !matches!(family, Family::Redis) {
        return Err(MetadataError::unsupported(&conn.db_type));
    }
    crate::redis_leg::open_pubsub(&conn, &password)
        .await
        .map_err(|_| MetadataError::connect_failed())
}

// ── list_connections：安全投影，永不回凭据 ──

pub async fn list_connection_summaries(
    pool: &SqlitePool,
) -> Result<Vec<ConnectionSummary>, MetadataError> {
    sqlx::query_as::<_, ConnectionSummary>(
        "SELECT id, name, db_type, read_only != 0 AS read_only, default_database
         FROM database_connections ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| MetadataError {
        code: "DB_ERROR",
        message: format!("server database read failed: {}", &e.to_string().chars().take(120).collect::<String>()),
    })
}

// ── list_databases ──

/// 引擎内建库过滤（每个 MySQL 8 连接必然出现、对 AI 上下文纯噪音）已
/// T21 收敛到族薄适配 profile（`mysql_family.rs` 的
/// `MysqlFamilyHooks::system_databases` 默认值：information_schema /
/// performance_schema；`sys`/`mysql` 保留可查）。

/// SQL Server 系统库（master/model/msdb/tempdb）——目录噪音，滤除；用户库全保留。
const SQLSERVER_SYSTEM_DATABASES: [&str; 4] = ["master", "model", "msdb", "tempdb"];

/// T29 TDengine 批次 — 目录查询（SHOW/DESCRIBE）的通道超时（连接测试同值，
/// tdengine_leg::server_version/test_tdengine）。
const META_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// TDengine 标识符引用（反引号，内部反引号翻倍——TDengine SQL 语法）。
fn quote_ident_td(ident: &str) -> String {
    format!("`{}`", ident.replace('`', "``"))
}

// ── SQL Server（TDS）查询辅助（T28，供本模块三件复用）──

/// 开连接 → 参数化查询 → 首个结果集全量行。连接/查询两阶段错误分别归一
/// （连接失败不回传引擎细节，可能含 host/DNS）。
async fn ss_rows(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    sql: &str,
    params: &[&dyn tiberius::ToSql],
) -> Result<Vec<tiberius::Row>, MetadataError> {
    let mut client = crate::sqlserver::open_sqlserver(conn, password, db)
        .await
        .map_err(|_| MetadataError::connect_failed())?;
    let stream = client
        .query(sql, params)
        .await
        .map_err(MetadataError::query_failed_tds)?;
    stream.into_first_result().await.map_err(MetadataError::query_failed_tds)
}

/// TDS 行首列字符串（名字投影；NVARCHAR/sysname 列）。
fn ss_str(row: &tiberius::Row, idx: usize) -> String {
    crate::sqlserver::decode_cell_tds(row, idx)
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// TDS 行列的可选字符串（注释等 NULL 允许列），空串归一 None。
fn ss_opt_str(row: &tiberius::Row, idx: usize) -> Option<String> {
    non_empty(ss_str(row, idx))
}

/// TDS 行整数列解码（解码链，NULL/失败归 0）。
fn ss_i64(row: &tiberius::Row, idx: usize) -> i64 {
    crate::sqlserver::decode_cell_tds(row, idx).as_i64().unwrap_or(0)
}

// ── MongoDB 查询辅助（T29 非 SQL 批次 B1，供本模块三件复用）──

async fn open_mongo_conn(
    conn: &DbConnectionRow,
    password: &str,
) -> Result<mongodb::Client, MetadataError> {
    crate::mongo::open_mongo(conn, password)
        .await
        .map_err(|_| MetadataError::connect_failed())
}

async fn mongo_run(
    client: &mongodb::Client,
    db: &str,
    cmd: bson::Document,
) -> Result<bson::Document, MetadataError> {
    client
        .database(db)
        .run_command(cmd)
        .await
        .map_err(|e| MetadataError::query_failed_mongo(&e))
}

/// 命令响应的 cursor.firstBatch 文档列表（非游标响应 / 空批 → 空列表）。
fn mongo_batch(resp: &bson::Document) -> Vec<bson::Document> {
    crate::mongo::cursor_first_batch(resp).map(|(batch, _, _)| batch).unwrap_or_default()
}

// ── Redis 查询辅助（T29 非 SQL 批次 B3，供本模块三件复用）──

async fn open_redis_conn(
    conn: &DbConnectionRow,
    password: &str,
    db: i64,
) -> Result<redis::aio::MultiplexedConnection, MetadataError> {
    crate::redis_leg::open_redis(conn, password, db)
        .await
        .map_err(|_| MetadataError::connect_failed())
}

/// 单命令 → RESP 值（查询失败归 QUERY_FAILED）。
async fn redis_cmd(
    conn: &mut redis::aio::MultiplexedConnection,
    name: &str,
    args: &[&str],
) -> Result<redis::Value, MetadataError> {
    let mut cmd = redis::cmd(name);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.query_async(conn)
        .await
        .map_err(|e| {
            MetadataError {
                code: "QUERY_FAILED",
                message: e.to_string().chars().take(200).collect(),
            }
        })
}

/// SCAN 全量循环（COUNT 500；上限防失控），返回全部 key。
async fn redis_scan_all(
    conn: &mut redis::aio::MultiplexedConnection,
    pattern: &str,
    cap: usize,
) -> Result<Vec<String>, MetadataError> {
    let mut cursor: String = "0".to_string();
    let mut keys = Vec::new();
    loop {
        let resp = redis_cmd(conn, "SCAN", &[&cursor, "MATCH", pattern, "COUNT", "500"]).await?;
        let redis::Value::Array(outer) = resp else {
            return Err(MetadataError {
                code: "QUERY_FAILED",
                message: "unexpected SCAN response shape".to_string(),
            });
        };
        let (Some(next), Some(batch)) = (outer.first(), outer.get(1)) else {
            return Err(MetadataError {
                code: "QUERY_FAILED",
                message: "malformed SCAN response".to_string(),
            });
        };
        let next = match next {
            redis::Value::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
            _ => return Err(MetadataError {
                code: "QUERY_FAILED",
                message: "malformed SCAN cursor".to_string(),
            }),
        };
        if let redis::Value::Array(items) = batch {
            for item in items {
                if let redis::Value::BulkString(b) = item {
                    keys.push(String::from_utf8_lossy(b).into_owned());
                }
            }
        }
        if keys.len() >= cap || next == "0" {
            break;
        }
        cursor = next;
    }
    Ok(keys)
}

pub async fn list_databases(
    pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
) -> Result<Vec<String>, MetadataError> {
    let (conn, family, password) = load_connection(pool, key, conn_id).await?;
    match family {
        Family::Sqlite => Ok(vec!["main".to_string()]),
        Family::MySql(profile) => {
            let pool = open_mysql(&conn, &password).await.map_err(|_| MetadataError::connect_failed())?;
            // T21 — 执行模式经族 profile：Doris 的 SHOW DATABASES 经
            // PREPARE 会触发不合规 prepare-ok 包（10 vs 12 字节），
            // profile 定为 raw_sql 文本协议；MySQL 保持 PREPARE。
            let rows = crate::mysql_family::fetch_all_by_mode(
                &pool, profile.catalog_mode(), "SHOW DATABASES", None,
            )
            .await
            .map_err(|e| MetadataError::query_failed(&e))?;
            Ok(rows
                .iter()
                .map(|r| decode_mysql_string(r, 0))
                .filter(|d| !profile.system_databases().contains(&d.as_str()))
                .collect())
        }
        Family::Postgres => {
            let pool = open_pg_db(&conn, &password, None)
                .await
                .map_err(|_| MetadataError::connect_failed())?;
            let rows: Vec<(String,)> = sqlx::query_as(
                "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname",
            )
            .fetch_all(&pool)
            .await
            .map_err(|e| MetadataError::query_failed(&e))?;
            Ok(rows.into_iter().map(|r| r.0).collect())
        }
        Family::Clickhouse => {
            let pool = open_mysql(&conn, &password).await.map_err(|_| MetadataError::connect_failed())?;
            let rows = sqlx::query("SHOW DATABASES")
                .fetch_all(&pool)
                .await
                .map_err(|e| MetadataError::query_failed(&e))?;
            Ok(rows
                .iter()
                .map(|r| decode_mysql_string(r, 0))
                // CH 同时挂 INFORMATION_SCHEMA 大小写两个别名库，同样纯噪音。
                .filter(|d| !d.eq_ignore_ascii_case("information_schema") && d != "system_metadata")
                .collect())
        }
        Family::SqlServer => {
            let rows = ss_rows(&conn, &password, None, "SELECT name FROM sys.databases ORDER BY name", &[]).await?;
            Ok(rows
                .iter()
                .map(|r| ss_str(r, 0))
                // 四个系统库是纯目录噪音（对齐 MySQL 滤 information_schema/
                // performance_schema 的取舍）；用户库全保留。
                .filter(|d| !SQLSERVER_SYSTEM_DATABASES.contains(&d.as_str()))
                .collect())
        }
        // T29 非 SQL 批次（B1）— listDatabases：admin/config/local 全保留
        //（DBA 语义上可浏览，对齐客户端适配器 getDatabases 不滤除的既有行为）。
        Family::Mongo => {
            let client = open_mongo_conn(&conn, &password).await?;
            let resp = mongo_run(&client, "admin", bson::doc! {"listDatabases": 1}).await?;
            let names = resp
                .get("databases")
                .and_then(bson::Bson::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|d| {
                            d.as_document()
                                .and_then(|doc| doc.get_str("name").ok())
                                .map(str::to_string)
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(names)
        }
        // T29 非 SQL 批次（B3）— Redis：CONFIG GET databases（上限 256，对齐
        // 客户端 getDatabases 语义）；无权限回落 INFO keyspace 的非空库。
        Family::Redis => {
            let mut conn = open_redis_conn(&conn, &password, 0).await?;
            if let Ok(resp) = redis_cmd(&mut conn, "CONFIG", &["GET", "databases"]).await {
                if let redis::Value::Array(items) = resp {
                    if let Some(redis::Value::BulkString(b)) = items.get(1) {
                        let n: i64 = String::from_utf8_lossy(b).parse().unwrap_or(16);
                        let n = n.clamp(1, 256);
                        return Ok((0..n).map(|i| i.to_string()).collect());
                    }
                }
            }
            // 回落：INFO keyspace 的 dbN 行。
            if let Ok(redis::Value::BulkString(b)) =
                redis_cmd(&mut conn, "INFO", &["keyspace"]).await
            {
                let text = String::from_utf8_lossy(&b);
                let mut dbs: Vec<String> = text
                    .lines()
                    .filter_map(|l| l.strip_prefix("db"))
                    .filter_map(|rest| rest.split(':').next().map(str::to_string))
                    .collect();
                dbs.sort_by_key(|d| d.parse::<i64>().unwrap_or(0));
                if !dbs.is_empty() {
                    return Ok(dbs);
                }
            }
            Ok(vec!["0".to_string()])
        }
        // T29 TDengine 批次 — SHOW DATABASES 首列；滤 information_schema/
        // performance_schema（对齐客户端 getDatabases 既有过滤）。
        Family::Tdengine => {
            let outcome = crate::tdengine_leg::exec_sql(
                &conn, &password, None, "SHOW DATABASES", META_QUERY_TIMEOUT,
            )
            .await
            .map_err(MetadataError::from_td)?;
            Ok(outcome
                .rows
                .iter()
                .filter_map(|r| r.first().and_then(serde_json::Value::as_str))
                .filter(|d| {
                    !d.eq_ignore_ascii_case("information_schema")
                        && !d.eq_ignore_ascii_case("performance_schema")
                })
                .map(str::to_string)
                .collect())
        }
    }
}

// ── list_tables（含注释 + 行数估计）──

pub async fn list_tables(
    pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
) -> Result<Vec<TableSummary>, MetadataError> {
    let (conn, family, password) = load_connection(pool, key, conn_id).await?;
    let db_name = db.or(conn.default_database.as_deref());

    match family {
        Family::MySql(profile) => {
            let Some(db_name) = db_name else {
                return Err(MetadataError::config(
                    "no database specified and connection has no default_database",
                ));
            };
            let pool = open_mysql_db(&conn, &password, Some(db_name))
                .await
                .map_err(|_| MetadataError::connect_failed())?;
            // T21 — Doris 的 MySQL 口两处不合规（PREPARE information_schema
            // 报 UnsupportedCommand、prepare-ok 包短 2 字节）收敛为族 profile
            // 的 catalog_mode：RawSql 走 COM_QUERY 文本协议 + mysql_str_literal
            // 转义内联；MySQL 保持 Prepare 绑定参数（注入面默认收紧）。
            // 行数估计列同经 profile（默认 information_schema 的 table_rows）。
            let tables_sql = format!(
                "SELECT table_name, table_type, table_comment, {}
                 FROM information_schema.tables
                 WHERE {}
                 ORDER BY table_name",
                profile.row_estimate_expr(),
                profile.schema_condition(db_name),
            );
            let rows = crate::mysql_family::fetch_all_by_mode(
                &pool, profile.catalog_mode(), &tables_sql, None,
            )
            .await
            .map_err(|e| MetadataError::query_failed(&e))?;
            Ok(rows
                .iter()
                .map(|r| {
                    let kind = if decode_mysql_string(r, 1) == "VIEW" { "view" } else { "table" };
                    let comment = non_empty(decode_mysql_string(r, 2));
                    // 视图的 table_rows 为 NULL；InnoDB 表值为估计值。
                    let rows_est = mysql_row_count(r, 3);
                    TableSummary {
                        name: decode_mysql_string(r, 0),
                        // 单库（schema=库名）语义，无 schema 维度。
                        schema: None,
                        kind: kind.to_string(),
                        comment,
                        row_estimate: rows_est.filter(|n| *n >= 0),
                    }
                })
                .collect())
        }
        Family::Postgres => {
            let pool = open_pg_db(&conn, &password, db_name)
                .await
                .map_err(|_| MetadataError::connect_failed())?;
            // 枚举**全部用户 schema**（原为 `nspname = 'public'` 硬编码——
            // 非 public schema 的对象既不可见也不可寻址，本查询是修复点）。
            // 系统 schema 过滤用 PG 自身的保留前缀约定：所有内建 schema 以
            // `pg_` 开头（pg_catalog / pg_toast / pg_toast_temp_N /
            // pg_temp_N），另加 information_schema——等价于 psql `\dn` 的
            // 可见性口径（用户无法创建 `pg_` 前缀 schema，故无漏网用户库）。
            // 排序先 schema 后对象名（跨 schema 输出稳定，便于 diff/断言）。
            let rows = sqlx::query(
                "SELECT n.nspname,
                        c.relname,
                        CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'view' ELSE 'table' END,
                        obj_description(c.oid, 'pg_class'),
                        c.reltuples::bigint
                 FROM pg_class c
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE c.relkind IN ('r', 'p', 'v', 'm')
                   AND n.nspname <> 'information_schema'
                   AND n.nspname !~ '^pg_'
                 ORDER BY n.nspname, c.relname",
            )
            .fetch_all(&pool)
            .await
            .map_err(|e| MetadataError::query_failed(&e))?;
            Ok(rows
                .iter()
                .map(|r| {
                    // reltuples = -1 表示从未 ANALYZE（PG14+），无估计可言。
                    let estimate = r
                        .try_get::<i64, _>(4)
                        .ok()
                        .filter(|n| *n >= 0);
                    let (name, schema) = pg_display_name(
                        &r.try_get::<String, _>(0).unwrap_or_default(),
                        &r.try_get::<String, _>(1).unwrap_or_default(),
                    );
                    TableSummary {
                        name,
                        schema,
                        kind: r.try_get::<String, _>(2).unwrap_or_else(|_| "table".into()),
                        comment: r.try_get::<Option<String>, _>(3).ok().flatten(),
                        row_estimate: estimate,
                    }
                })
                .collect())
        }
        Family::Sqlite => {
            let pool = open_sqlite(&conn).await.map_err(|_| MetadataError::connect_failed())?;
            let rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT name, type FROM sqlite_master
                 WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .fetch_all(&pool)
            .await
            .map_err(|e| MetadataError::query_failed(&e))?;
            Ok(rows
                .into_iter()
                .map(|(name, ty)| TableSummary {
                    name,
                    schema: None, // sqlite 单文件单库（main）
                    kind: ty, // sqlite_master.type 就是 'table' | 'view'
                    // SQLite 无目录注释、无统计行数（ANALYZE 前无 sqlite_stat1）。
                    comment: None,
                    row_estimate: None,
                })
                .collect())
        }
        Family::Clickhouse => {
            let db = db_name.unwrap_or("default");
            let pool = open_mysql_db(&conn, &password, Some(db))
                .await
                .map_err(|_| MetadataError::connect_failed())?;
            let sql = format!(
                "SELECT name, engine, comment, total_rows FROM system.tables \
                 WHERE database = {} ORDER BY name",
                ch_str_literal(db),
            );
            let rows = sqlx::query(&sql)
                .fetch_all(&pool)
                .await
                .map_err(|e| MetadataError::query_failed(&e))?;
            Ok(rows
                .iter()
                .map(|r| {
                    let engine = decode_mysql_string(r, 1);
                    TableSummary {
                        name: decode_mysql_string(r, 0),
                        schema: None, // 单库查询（database 已由 db 参数选定）
                        kind: if engine == "View" { "view".to_string() } else { "table".to_string() },
                        comment: non_empty(decode_mysql_string(r, 2)),
                        row_estimate: mysql_row_count(r, 3),
                    }
                })
                .collect())
        }
        Family::SqlServer => {
            let Some(db_name) = db_name else {
                return Err(MetadataError::config(
                    "no database specified and connection has no default_database",
                ));
            };
            // 表 + 视图 UNION；行数估计来自 sys.partitions（heap index_id=0 /
            // 聚簇 index_id=1，精确值）；注释 = MS_Description 扩展属性。
            // schema 固定 dbo（对齐 PG public-only，v1.1 落实 schema 透传）。
            let rows = ss_rows(
                &conn, &password, Some(db_name),
                "SELECT t.name AS name, 'table' AS kind,
                        CAST(ep.value AS NVARCHAR(4000)) AS comment,
                        (SELECT SUM(p.rows) FROM sys.partitions p
                         WHERE p.object_id = t.object_id AND p.index_id IN (0, 1)) AS row_estimate
                 FROM sys.tables t
                 LEFT JOIN sys.extended_properties ep
                   ON ep.class = 1 AND ep.major_id = t.object_id
                  AND ep.minor_id = 0 AND ep.name = 'MS_Description'
                 WHERE t.schema_id = SCHEMA_ID('dbo')
                 UNION ALL
                 SELECT v.name, 'view', CAST(ep.value AS NVARCHAR(4000)), NULL
                 FROM sys.views v
                 LEFT JOIN sys.extended_properties ep
                   ON ep.class = 1 AND ep.major_id = v.object_id
                  AND ep.minor_id = 0 AND ep.name = 'MS_Description'
                 WHERE v.schema_id = SCHEMA_ID('dbo')
                 ORDER BY name",
                &[],
            )
            .await?;
            Ok(rows
                .iter()
                .map(|r| TableSummary {
                    name: ss_str(r, 0),
                    // dbo-only（v1 限制，schema 透传随 v1.1——与 PG 侧本轮
                    // 解耦：PG 已支持多 schema，SS 仍固定 dbo）。
                    schema: None,
                    kind: ss_str(r, 1),
                    comment: ss_opt_str(r, 2),
                    // SUM(p.rows) INT NULL（视图 NULL → 省略键）。经 decode
                    // 链取数（TDS 强类型 + sp_executesql 上下文的联合类型
                    // 推断，直解单一具体类型在实机验证不稳）。
                    row_estimate: crate::sqlserver::decode_cell_tds(r, 3).as_i64(),
                })
                .collect())
        }
        // T29 非 SQL 批次（B1）— listCollections：view → "view"，collection/
        // timeseries → "table"（wire 形状与 SQL 族同构）；无注释/行数估计。
        Family::Mongo => {
            let Some(db_name) = db_name else {
                return Err(MetadataError::config(
                    "no database specified and connection has no default_database",
                ));
            };
            let client = open_mongo_conn(&conn, &password).await?;
            let resp = mongo_run(&client, db_name, bson::doc! {"listCollections": 1}).await?;
            Ok(mongo_batch(&resp)
                .iter()
                .map(|c| TableSummary {
                    name: c.get_str("name").unwrap_or_default().to_string(),
                    schema: None, // collection 无 schema 维度（库即 database）
                    kind: if c.get_str("type") == Ok("view") { "view" } else { "table" }
                        .to_string(),
                    comment: None,
                    row_estimate: None,
                })
                .collect())
        }
        // T29 非 SQL 批次（B3）— Redis：SCAN 全 key（上限 10000 防失控）按
        // `:` 前缀聚命名空间（对齐客户端 getTables 语义），无前缀 key 归
        // 「(root)」桶。
        Family::Redis => {
            let db_idx = crate::redis_leg::db_index(&conn, db_name);
            let mut handle = open_redis_conn(&conn, &password, db_idx).await?;
            let keys = redis_scan_all(&mut handle, "*", 10_000).await?;
            let mut namespaces: Vec<String> = keys
                .iter()
                .map(|k| match k.split(':').next() {
                    Some(seg) if !seg.is_empty() && seg.len() < k.len() => seg.to_string(),
                    _ => "(root)".to_string(),
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            namespaces.sort();
            Ok(namespaces
                .into_iter()
                .map(|name| TableSummary {
                    name,
                    schema: None, // 命名空间聚桶非 schema（Redis 无 schema 概念）
                    kind: "table".to_string(),
                    comment: None,
                    row_estimate: None,
                })
                .collect())
        }
        // T29 TDengine 批次 — 用户库 SHOW STABLES（超级表；子表经 tbname
        // 按需查询，不上树），系统库（information_schema/performance_schema）
        // SHOW TABLES——对齐客户端 getTables 双路径语义。
        Family::Tdengine => {
            let Some(db_name) = db_name else {
                return Err(MetadataError::config(
                    "no database specified and connection has no default_database",
                ));
            };
            let system = db_name.eq_ignore_ascii_case("information_schema")
                || db_name.eq_ignore_ascii_case("performance_schema");
            let sql = if system { "SHOW TABLES" } else { "SHOW STABLES" };
            let outcome = crate::tdengine_leg::exec_sql(
                &conn, &password, Some(db_name), sql, META_QUERY_TIMEOUT,
            )
            .await
            .map_err(MetadataError::from_td)?;
            Ok(outcome
                .rows
                .iter()
                .filter_map(|r| r.first().and_then(serde_json::Value::as_str))
                .filter(|n| !n.is_empty())
                .map(|name| TableSummary {
                    name: name.to_string(),
                    schema: None, // TDengine 库内无 schema 维度
                    kind: "table".to_string(),
                    comment: None,
                    row_estimate: None,
                })
                .collect())
        }
    }
}

// ── describe_table（列 + PK + 索引 + FK）──

pub async fn describe_table(
    pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    table: &str,
) -> Result<TableDescription, MetadataError> {
    let (conn, family, password) = load_connection(pool, key, conn_id).await?;
    let db_name = db.or(conn.default_database.as_deref());

    match family {
        Family::MySql(profile) => describe_mysql(profile, &conn, &password, db_name, table).await,
        Family::Postgres => describe_pg(&conn, &password, db_name, table).await,
        Family::Sqlite => describe_sqlite(&conn, table).await,
        Family::Clickhouse => describe_clickhouse(&conn, &password, db_name, table).await,
        Family::SqlServer => describe_sqlserver(&conn, &password, db_name, table).await,
        Family::Mongo => describe_mongo(&conn, &password, db_name, table).await,
        Family::Redis => describe_redis(&conn, &password, db_name, table).await,
        Family::Tdengine => describe_tdengine(&conn, &password, db_name, table).await,
    }
}

/// T29 TDengine 批次 — DESCRIBE（3.3.6 实机钉定 7 列：field/type/length/
/// note/encode/compress/level）。TAG 标记在 note 列 → ColumnDetail.comment
/// 携 "TAG"（AI 上下文可辨别标签列）；note == "PRIMARY KEY" → primary_key。
/// nullable：PRIMARY KEY 列 false，其余（含 TAG）true——TDengine 时间戳主键
/// 非空是引擎约束，标签列可空。
async fn describe_tdengine(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    table: &str,
) -> Result<TableDescription, MetadataError> {
    let Some(db) = db else {
        return Err(MetadataError::config(
            "no database specified and connection has no default_database",
        ));
    };
    let outcome = crate::tdengine_leg::exec_sql(
        conn,
        password,
        Some(db),
        &format!("DESCRIBE {}", quote_ident_td(table)),
        META_QUERY_TIMEOUT,
    )
    .await
    .map_err(MetadataError::from_td)?;
    if outcome.rows.is_empty() {
        return Err(MetadataError::not_found(&format!(
            "table '{table}' (database '{db}')"
        )));
    }
    let mut columns = Vec::with_capacity(outcome.rows.len());
    let mut primary_key = Vec::new();
    for row in &outcome.rows {
        let name = row.first().and_then(serde_json::Value::as_str).unwrap_or_default();
        let ty = row.get(1).and_then(serde_json::Value::as_str).unwrap_or("");
        let note = row.get(3).and_then(serde_json::Value::as_str).unwrap_or("");
        if note == "PRIMARY KEY" {
            primary_key.push(name.to_string());
        }
        columns.push(ColumnDetail {
            name: name.to_string(),
            data_type: ty.to_string(),
            nullable: note != "PRIMARY KEY",
            default_value: None,
            comment: (note == "TAG").then(|| "TAG".to_string()),
        });
    }
    Ok(TableDescription {
        table: table.to_string(),
        comment: None,
        columns,
        primary_key,
        indexes: Vec::new(),
        foreign_keys: Vec::new(),
    })
}

async fn describe_mysql(
    profile: &'static dyn crate::mysql_family::MysqlFamilyHooks,
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    table: &str,
) -> Result<TableDescription, MetadataError> {
    let Some(db) = db else {
        return Err(MetadataError::config(
            "no database specified and connection has no default_database",
        ));
    };
    let pool = open_mysql_db(conn, password, Some(db))
        .await
        .map_err(|_| MetadataError::connect_failed())?;

    // T21 — schema/table 条件片段随族 profile 的 catalog_mode 派生：
    // Doris（RawSql）走转义字面量；MySQL（Prepare）绑定参数。
    let table_cond = profile.table_condition(table);
    let schema_cond = profile.schema_condition(db);
    // Prepare 模式的 table 条件是 `?` 占位——执行时绑定表名。
    let bind_table = match profile.catalog_mode() {
        crate::mysql_family::CatalogQueryMode::Prepare => Some(table),
        crate::mysql_family::CatalogQueryMode::RawSql => None,
    };

    // 表注释 + 类型（views 无注释/行数）。
    let meta_sql = format!(
        "SELECT table_comment FROM information_schema.tables
         WHERE {schema_cond} AND {table_cond}"
    );
    // raw_sql 无 fetch_optional——fetch_all 取首行（表名唯一）。
    let meta = crate::mysql_family::fetch_all_by_mode(
        &pool, profile.catalog_mode(), &meta_sql, bind_table,
    )
    .await
    .map_err(|e| MetadataError::query_failed(&e))?
    .into_iter()
    .next();

    // 列（column_type 带长度信息，比 data_type 更适合 AI 写 SQL）。
    let col_sql = format!(
        "SELECT column_name, column_type, is_nullable, column_default, column_comment,
                CASE WHEN column_key = 'PRI' THEN 1 ELSE 0 END
         FROM information_schema.columns
         WHERE {schema_cond} AND {table_cond}
         ORDER BY ordinal_position"
    );
    let col_rows = crate::mysql_family::fetch_all_by_mode(
        &pool, profile.catalog_mode(), &col_sql, bind_table,
    )
    .await
    .map_err(|e| MetadataError::query_failed(&e))?;

    if col_rows.is_empty() {
        return Err(MetadataError::not_found(&format!(
            "table '{table}' (database '{db}')"
        )));
    }

    let mut columns = Vec::with_capacity(col_rows.len());
    let mut primary_key = Vec::new();
    for r in &col_rows {
        let name = decode_mysql_string(r, 0);
        if r.try_get::<i64, _>(5).unwrap_or(0) == 1 {
            primary_key.push(name.clone());
        }
        columns.push(ColumnDetail {
            name,
            data_type: decode_mysql_string(r, 1),
            nullable: decode_mysql_string(r, 2) == "YES",
            default_value: {
                // information_schema 的默认值列常以 VARBINARY 回来（与既有
                // db_handler list_columns 同一解码路径）。
                let opt: Option<Vec<u8>> = r.try_get(3).ok();
                opt.map(|b| String::from_utf8_lossy(&b).into_owned())
            },
            comment: non_empty(decode_mysql_string(r, 4)),
        });
    }

    // 索引：行序 (index_name, seq_in_index) 已经把同名索引聚成连续段，
    // 就地分组避免 GROUP_CONCAT 的方言差异（Doris 不支持其 ORDER BY 子句）。
    let idx_sql = format!(
        "SELECT index_name, non_unique, column_name
         FROM information_schema.statistics
         WHERE {schema_cond} AND {table_cond}
         ORDER BY index_name, seq_in_index"
    );
    let idx_rows = crate::mysql_family::fetch_all_by_mode(
        &pool, profile.catalog_mode(), &idx_sql, bind_table,
    )
    .await
    .map_err(|e| MetadataError::query_failed(&e))?;
    let mut indexes: Vec<IndexDetail> = Vec::new();
    for r in &idx_rows {
        let name = decode_mysql_string(r, 0);
        let unique = r.try_get::<i64, _>(1).unwrap_or(1) == 0;
        let col = decode_mysql_string(r, 2);
        match indexes.last_mut() {
            Some(last) if last.name == name => last.columns.push(col),
            _ => indexes.push(IndexDetail { name, columns: vec![col], unique }),
        }
    }

    // 外键：按 constraint_name 聚列。
    let fk_sql = format!(
        "SELECT constraint_name, column_name, referenced_table_name, referenced_column_name
         FROM information_schema.key_column_usage
         WHERE {schema_cond} AND {table_cond}
           AND referenced_table_name IS NOT NULL
         ORDER BY constraint_name, ordinal_position"
    );
    let fk_rows = crate::mysql_family::fetch_all_by_mode(
        &pool, profile.catalog_mode(), &fk_sql, bind_table,
    )
    .await
    .map_err(|e| MetadataError::query_failed(&e))?;
    let mut foreign_keys: Vec<ForeignKeyDetail> = Vec::new();
    for r in &fk_rows {
        let name = non_empty(decode_mysql_string(r, 0));
        let col = decode_mysql_string(r, 1);
        let ref_table = decode_mysql_string(r, 2);
        let ref_col = decode_mysql_string(r, 3);
        match foreign_keys.last_mut() {
            Some(last) if last.name == name && last.ref_table == ref_table => {
                last.columns.push(col);
                last.ref_columns.push(ref_col);
            }
            _ => foreign_keys.push(ForeignKeyDetail {
                name,
                columns: vec![col],
                ref_table,
                ref_columns: vec![ref_col],
            }),
        }
    }

    Ok(TableDescription {
        table: table.to_string(),
        comment: meta.as_ref().map(|r| non_empty(decode_mysql_string(r, 0))).flatten(),
        columns,
        primary_key,
        indexes,
        foreign_keys,
    })
}

// ── PG 多 schema 寻址（本轮修复：非 public schema 从「不可枚举、不可寻址」
// 改为「枚举 + schema.table 限定寻址」）──

/// PG 对象显示名约定（消歧 + 向后兼容）：`public` 的对象保持**裸名**，其余
/// schema 用 `schema.table` 限定。返回 `(name, schema)`——schema 仅在非
/// public 时给出值，故 public-only 库的既有输出（含键集）逐字节不变。
fn pg_display_name(schema: &str, relname: &str) -> (String, Option<String>) {
    if schema == "public" {
        (relname.to_string(), None)
    } else {
        (format!("{schema}.{relname}"), Some(schema.to_string()))
    }
}

/// `describe_table` 的 PG relation 定位 SQL 片段。**编译期常量**：调用方
/// 输入永不进 SQL 文本；标识符一律经绑定参数 + 服务端 `quote_ident` 转义
/// （含空格/大写/引号的表名按标识符规则解析）。`to_regclass` 对不存在的
/// relation 返回 NULL（而非报错），空结果即 NOT_FOUND。
const PG_REGCLASS_BARE: &str = "to_regclass(quote_ident($1))";
/// 限定寻址（`schema.table`）：两段分别 quote_ident 后拼接。
const PG_REGCLASS_QUALIFIED: &str = "to_regclass(quote_ident($1) || '.' || quote_ident($2))";

/// 恰好一段 `.` 且两段均非空 → `(schema, table)`；其余一律 `None`（无 `.`、
/// 多段 `a.b.c`、空段 `.x` / `x.` / `..` 都按裸名走默认解析）。
fn split_pg_qualified(table: &str) -> Option<(&str, &str)> {
    let mut parts = table.split('.');
    let first = parts.next().unwrap_or_default();
    let second = parts.next().unwrap_or_default();
    match (parts.next(), first.is_empty(), second.is_empty()) {
        (None, false, false) => Some((first, second)),
        _ => None,
    }
}

/// `describe_pg` 的寻址解析结果：常量 SQL 片段 + 按 `$1..$n` 顺序的绑定值。
struct PgRelation {
    /// 插入 `{rel}` 的常量 SQL 片段（见 [`PG_REGCLASS_BARE`] / [`PG_REGCLASS_QUALIFIED`]）。
    regclass: &'static str,
    /// 绑定参数：1 个 = 裸名；2 个 = (schema, table)。
    params: Vec<String>,
}

impl PgRelation {
    /// 解析 `table` 参数：恰好 `schema.table` 形态 → 限定寻址；否则裸名走
    /// search_path（`public` 在默认 search_path 内，故既有裸名寻址行为不变）。
    /// 畸形输入不特殊报错——落 `to_regclass` NULL 的统一 NOT_FOUND，不做额外
    /// 区分（没有可被利用的解析歧义）。
    fn parse(table: &str) -> Self {
        match split_pg_qualified(table) {
            Some((schema, name)) => Self {
                regclass: PG_REGCLASS_QUALIFIED,
                params: vec![schema.to_string(), name.to_string()],
            },
            None => Self { regclass: PG_REGCLASS_BARE, params: vec![table.to_string()] },
        }
    }

    /// 限定寻址的 schema（裸名 → None）；NOT_FOUND 文案据此反映实际解析目标。
    fn schema(&self) -> Option<&str> {
        match self.params.as_slice() {
            [schema, _] => Some(schema.as_str()),
            _ => None,
        }
    }

    /// 实际定位的对象名（裸名 / 限定名的第二段）。
    fn object_name(&self) -> &str {
        self.params.last().map(String::as_str).unwrap_or_default()
    }
}

/// 按 [`PgRelation::params`] 顺序绑定（1 个或 2 个）。用 `macro_rules!` 而非
/// 泛型函数：sqlx 的 `bind` 是 `self -> Self`，而 `query_as` / `query_scalar`
/// 的构造器类型不同（`QueryAs` / `QueryScalar`），宏是此处最薄的统一层。
macro_rules! bind_rel {
    ($query:expr, $rel:expr) => {
        match $rel.params.as_slice() {
            [only] => $query.bind(only.as_str()),
            [schema, name] => $query.bind(schema.as_str()).bind(name.as_str()),
            _ => unreachable!("PgRelation carries 1 or 2 bind parameters"),
        }
    };
}

async fn describe_pg(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    table: &str,
) -> Result<TableDescription, MetadataError> {
    let pool = open_pg_db(conn, password, db)
        .await
        .map_err(|_| MetadataError::connect_failed())?;
    // schema.table 限定寻址（恰好一段 `.`）/ 裸名走 search_path——两种形态
    // 都只落到下面这组绑定参数上，SQL 文本不含调用方输入。
    let rel = PgRelation::parse(table);
    let rel_sql = rel.regclass;

    #[derive(sqlx::FromRow)]
    struct PgColumn {
        name: String,
        col_type: String,
        nullable: bool,
        col_default: Option<String>,
        comment: Option<String>,
    }
    let sql = format!(
        "SELECT a.attname AS name,
                format_type(a.atttypid, a.atttypmod) AS col_type,
                NOT a.attnotnull AS nullable,
                pg_get_expr(ad.adbin, ad.adrelid) AS col_default,
                col_description(a.attrelid, a.attnum) AS comment
         FROM pg_attribute a
         LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
         WHERE a.attrelid = {rel_sql} AND a.attnum > 0 AND NOT a.attisdropped
         ORDER BY a.attnum"
    );
    let columns: Vec<PgColumn> = bind_rel!(sqlx::query_as(&sql), rel)
        .fetch_all(&pool)
        .await
        .map_err(|e| MetadataError::query_failed(&e))?;

    if columns.is_empty() {
        // NOT_FOUND 文案反映**实际解析目标**（不再写死 schema 'public'）。
        let db_label = db.unwrap_or("postgres");
        let target = match rel.schema() {
            Some(schema) => {
                format!("table '{}' (schema '{schema}', database '{db_label}')", rel.object_name())
            }
            None => format!(
                "table '{}' (database '{db_label}', schema resolved via search_path)",
                rel.object_name()
            ),
        };
        return Err(MetadataError::not_found(&target));
    }

    let sql = format!(
        "SELECT a.attname
         FROM pg_index i
         JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
         JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
         WHERE i.indrelid = {rel_sql} AND i.indisprimary
         ORDER BY k.ord"
    );
    let primary_key: Vec<(String,)> = bind_rel!(sqlx::query_as(&sql), rel)
        .fetch_all(&pool)
        .await
        .map_err(|e| MetadataError::query_failed(&e))?;

    // 表达式索引的 indkey 含 0（无对应 attnum），列为空但保留索引名。
    #[derive(sqlx::FromRow)]
    struct PgIndex {
        name: String,
        unique: bool,
        cols: Option<String>,
    }
    let sql = format!(
        "SELECT ic.relname AS name, i.indisunique AS unique,
                (SELECT string_agg(a.attname, ',' ORDER BY t.ord)
                 FROM unnest(i.indkey) WITH ORDINALITY AS t(attnum, ord)
                 JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = t.attnum) AS cols
         FROM pg_index i
         JOIN pg_class ic ON ic.oid = i.indexrelid
         WHERE i.indrelid = {rel_sql}
         ORDER BY ic.relname"
    );
    let indexes: Vec<PgIndex> = bind_rel!(sqlx::query_as(&sql), rel)
        .fetch_all(&pool)
        .await
        .map_err(|e| MetadataError::query_failed(&e))?;

    #[derive(sqlx::FromRow)]
    struct PgFk {
        name: String,
        cols: Option<String>,
        ref_table: String,
        ref_cols: Option<String>,
    }
    let sql = format!(
        "SELECT con.conname AS name,
                (SELECT string_agg(a.attname, ',' ORDER BY t.ord)
                 FROM unnest(con.conkey) WITH ORDINALITY AS t(attnum, ord)
                 JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = t.attnum) AS cols,
                conf.relname AS ref_table,
                (SELECT string_agg(a.attname, ',' ORDER BY t.ord)
                 FROM unnest(con.confkey) WITH ORDINALITY AS t(attnum, ord)
                 JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = t.attnum) AS ref_cols
         FROM pg_constraint con
         JOIN pg_class conf ON conf.oid = con.confrelid
         WHERE con.contype = 'f' AND con.conrelid = {rel_sql}
         ORDER BY con.conname"
    );
    let fks: Vec<PgFk> = bind_rel!(sqlx::query_as(&sql), rel)
        .fetch_all(&pool)
        .await
        .map_err(|e| MetadataError::query_failed(&e))?;

    let sql = format!("SELECT obj_description({rel_sql}, 'pg_class')");
    let comment: Option<String> = bind_rel!(sqlx::query_scalar(&sql), rel)
        .fetch_one(&pool)
        .await
        .map_err(|e| MetadataError::query_failed(&e))?;

    Ok(TableDescription {
        table: table.to_string(),
        comment,
        columns: columns
            .into_iter()
            .map(|c| ColumnDetail {
                name: c.name,
                data_type: c.col_type,
                nullable: c.nullable,
                default_value: c.col_default,
                comment: c.comment,
            })
            .collect(),
        primary_key: primary_key.into_iter().map(|r| r.0).collect(),
        indexes: indexes
            .into_iter()
            .map(|i| IndexDetail {
                name: i.name,
                columns: split_csv(i.cols),
                unique: i.unique,
            })
            .collect(),
        foreign_keys: fks
            .into_iter()
            .map(|f| ForeignKeyDetail {
                name: Some(f.name),
                columns: split_csv(f.cols),
                ref_table: f.ref_table,
                ref_columns: split_csv(f.ref_cols),
            })
            .collect(),
    })
}

async fn describe_sqlite(
    conn: &DbConnectionRow,
    table: &str,
) -> Result<TableDescription, MetadataError> {
    let pool = open_sqlite(conn).await.map_err(|_| MetadataError::connect_failed())?;

    let sql = format!("PRAGMA table_info({})", quote_ident_sqlite(table));
    let rows = sqlx::query(&sql)
        .fetch_all(&pool)
        .await
        .map_err(|e| MetadataError::query_failed(&e))?;
    if rows.is_empty() {
        return Err(MetadataError::not_found(&format!("table '{table}'")));
    }

    let mut columns = Vec::with_capacity(rows.len());
    // (pk 序号, 列名)：pk>0 表示参与主键，值为主键内的顺序。
    let mut pk_cols: Vec<(i64, String)> = Vec::new();
    for r in &rows {
        let name: String = r.try_get("name").unwrap_or_default();
        let pk: i64 = r.try_get("pk").unwrap_or(0);
        if pk > 0 {
            pk_cols.push((pk, name.clone()));
        }
        let notnull: i64 = r.try_get("notnull").unwrap_or(0);
        columns.push(ColumnDetail {
            name,
            data_type: {
                let t: String = r.try_get("type").unwrap_or_default();
                if t.is_empty() { "BLOB".to_string() } else { t }
            },
            nullable: notnull == 0,
            default_value: r.try_get::<Option<String>, _>("dflt_value").ok().flatten(),
            // SQLite 无列注释。
            comment: None,
        });
    }
    pk_cols.sort_by_key(|(ord, _)| *ord);

    // 索引：过滤 sqlite_autoindex_%（UNIQUE 约束的内部实现，噪音）。
    let idx_sql = format!("PRAGMA index_list({})", quote_ident_sqlite(table));
    let idx_rows = sqlx::query(&idx_sql)
        .fetch_all(&pool)
        .await
        .map_err(|e| MetadataError::query_failed(&e))?;
    let mut indexes = Vec::new();
    for r in &idx_rows {
        let name: String = r.try_get("name").unwrap_or_default();
        if name.is_empty() || name.starts_with("sqlite_autoindex") {
            continue;
        }
        let unique: i64 = r.try_get("unique").unwrap_or(0);
        let info_sql = format!("PRAGMA index_info({})", quote_ident_sqlite(&name));
        let info_rows = sqlx::query(&info_sql)
            .fetch_all(&pool)
            .await
            .map_err(|e| MetadataError::query_failed(&e))?;
        let cols: Vec<String> = info_rows
            .iter()
            .filter_map(|ir| {
                let n: Option<String> = ir.try_get("name").ok();
                n.filter(|s| !s.is_empty())
            })
            .collect();
        indexes.push(IndexDetail { name, columns: cols, unique: unique == 1 });
    }

    // 外键：按 id 分组（同一约束的列共享 id，seq 决定列序）。
    let fk_sql = format!("PRAGMA foreign_key_list({})", quote_ident_sqlite(table));
    let fk_rows = sqlx::query(&fk_sql)
        .fetch_all(&pool)
        .await
        .map_err(|e| MetadataError::query_failed(&e))?;
    // 行序不保证按 id/seq，先收集再按 (id, seq) 排序分组。
    let mut entries: Vec<(i64, i64, String, String, String)> = Vec::new();
    for r in &fk_rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let seq: i64 = r.try_get("seq").unwrap_or(0);
        let ref_table: String = r.try_get("table").unwrap_or_default();
        let from: String = r.try_get("from").unwrap_or_default();
        let to: String = r.try_get("to").unwrap_or_default();
        entries.push((id, seq, ref_table, from, to));
    }
    entries.sort_by_key(|(id, seq, _, _, _)| (*id, *seq));
    let mut foreign_keys: Vec<ForeignKeyDetail> = Vec::new();
    let mut last_id: Option<i64> = None;
    for (id, _seq, ref_table, from, to) in entries {
        if last_id == Some(id) {
            if let Some(last) = foreign_keys.last_mut() {
                last.columns.push(from);
                last.ref_columns.push(to);
            }
        } else {
            foreign_keys.push(ForeignKeyDetail {
                // PRAGMA foreign_key_list 无约束名。
                name: None,
                columns: vec![from],
                ref_table,
                ref_columns: vec![to],
            });
            last_id = Some(id);
        }
    }

    Ok(TableDescription {
        table: table.to_string(),
        comment: None, // SQLite 无目录注释
        columns,
        primary_key: pk_cols.into_iter().map(|(_, n)| n).collect(),
        indexes,
        foreign_keys,
    })
}

async fn describe_clickhouse(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    table: &str,
) -> Result<TableDescription, MetadataError> {
    let db_name = db.unwrap_or("default");
    let pool = open_mysql_db(conn, password, Some(db_name))
        .await
        .map_err(|_| MetadataError::connect_failed())?;
    // CH 的 MySQL wire 口不支持 `?` 绑定，走转义字面量（ch_str_literal）。
    let sql = format!(
        "SELECT name, type, default_kind, default_expression, comment \
         FROM system.columns WHERE database = {} AND table = {} ORDER BY position",
        ch_str_literal(db_name),
        ch_str_literal(table),
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&pool)
        .await
        .map_err(|e| MetadataError::query_failed(&e))?;
    if rows.is_empty() {
        return Err(MetadataError::not_found(&format!(
            "table '{table}' (database '{db_name}')"
        )));
    }

    let columns: Vec<ColumnDetail> = rows
        .iter()
        .map(|r| {
            let col_type = decode_mysql_string(r, 1);
            let kind = decode_mysql_string(r, 2);
            let expr = decode_mysql_string(r, 3);
            // DEFAULT 直接给表达式；ALIAS/COMPUTED/MATERIALIZED 带种类标注。
            let default = if expr.is_empty() {
                None
            } else if kind == "DEFAULT" || kind.is_empty() {
                Some(expr)
            } else {
                Some(format!("{kind} {expr}"))
            };
            ColumnDetail {
                name: decode_mysql_string(r, 0),
                nullable: col_type.starts_with("Nullable("),
                data_type: col_type,
                default_value: default,
                comment: non_empty(decode_mysql_string(r, 4)),
            }
        })
        .collect();

    Ok(TableDescription {
        table: table.to_string(),
        comment: None, // 表注释在 list_tables（system.tables.comment）给出
        columns,
        // CH 的主键是 MergeTree 引擎级属性（ORDER BY），非列级约束；索引
        // 模型亦非离散索引对象——两者均留空（与 db_handler ClickHouse
        // backend 的既有口径一致）。
        primary_key: Vec::new(),
        indexes: Vec::new(),
        foreign_keys: Vec::new(),
    })
}

/// T28 — SQL Server describe：sys 目录三段查询（列+PK / 索引 / FK）+ 表注释。
/// dbo schema only（对齐 describe_pg 的 public-only；表名经 @P1 绑定参数）。
async fn describe_sqlserver(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    table: &str,
) -> Result<TableDescription, MetadataError> {
    let db_name = db.or(conn.default_database.as_deref());

    // 列（类型完整维度 + 默认值 + 注释 + 是否可空）。
    let col_rows = ss_rows(
        conn, password, db_name,
        "SELECT c.name, tp.name AS type_name, c.max_length, c.precision, c.scale,
                CASE WHEN c.is_nullable = 1 THEN 1 ELSE 0 END AS is_nullable,
                OBJECT_DEFINITION(c.default_object_id) AS default_expr,
                CAST(ep.value AS NVARCHAR(4000)) AS comment
         FROM sys.columns c
         JOIN sys.types tp ON tp.user_type_id = c.user_type_id
         LEFT JOIN sys.extended_properties ep
           ON ep.class = 1 AND ep.major_id = c.object_id
          AND ep.minor_id = c.column_id AND ep.name = 'MS_Description'
         WHERE c.object_id = OBJECT_ID(@P1)
         ORDER BY c.column_id",
        &[&table],
    )
    .await?;
    if col_rows.is_empty() {
        return Err(MetadataError::not_found(&format!(
            "table '{table}' (schema 'dbo', database '{}')",
            db_name.unwrap_or("master")
        )));
    }

    let mut columns = Vec::with_capacity(col_rows.len());
    for r in &col_rows {
        columns.push(ColumnDetail {
            name: ss_str(r, 0),
            data_type: crate::sqlserver::format_sqlserver_type(
                &ss_str(r, 1),
                ss_i64(r, 2) as i16,
                ss_i64(r, 3) as u8,
                ss_i64(r, 4) as u8,
            ),
            nullable: ss_i64(r, 5) == 1,
            default_value: crate::sqlserver::strip_default_parens_opt(&crate::sqlserver::decode_cell_tds(r, 6)),
            comment: ss_opt_str(r, 7),
        });
    }

    // 主键（key_ordinal 保序）。
    let pk_rows = ss_rows(
        conn, password, db_name,
        "SELECT c.name
         FROM sys.indexes i
         JOIN sys.index_columns ic
           ON ic.object_id = i.object_id AND ic.index_id = i.index_id
         JOIN sys.columns c
           ON c.object_id = ic.object_id AND c.column_id = ic.column_id
         WHERE i.object_id = OBJECT_ID(@P1) AND i.is_primary_key = 1
         ORDER BY ic.key_ordinal",
        &[&table],
    )
    .await?;
    let primary_key: Vec<String> = pk_rows.iter().map(|r| ss_str(r, 0)).collect();

    // 索引：行序 (name, key_ordinal) 聚连续段，就地分组（同 MySQL 口径，
    // 不用 string_agg 防方言差异）；过滤 included 列（非键列）。
    let idx_rows = ss_rows(
        conn, password, db_name,
        "SELECT i.name AS index_name,
                CASE WHEN i.is_unique = 1 THEN 1 ELSE 0 END AS is_unique,
                c.name AS column_name
         FROM sys.indexes i
         JOIN sys.index_columns ic
           ON ic.object_id = i.object_id AND ic.index_id = i.index_id
          AND ic.is_included_column = 0
         JOIN sys.columns c
           ON c.object_id = ic.object_id AND c.column_id = ic.column_id
         WHERE i.object_id = OBJECT_ID(@P1) AND i.name IS NOT NULL
         ORDER BY i.name, ic.key_ordinal",
        &[&table],
    )
    .await?;
    let mut indexes: Vec<IndexDetail> = Vec::new();
    for r in &idx_rows {
        let name = ss_str(r, 0);
        let unique = ss_i64(r, 1) == 1;
        let col = ss_str(r, 2);
        match indexes.last_mut() {
            Some(last) if last.name == name => last.columns.push(col),
            _ => indexes.push(IndexDetail { name, columns: vec![col], unique }),
        }
    }

    // 外键：按约束名聚列（constraint_column_id 保序）。
    let fk_rows = ss_rows(
        conn, password, db_name,
        "SELECT fk.name AS fk_name, pc.name AS column_name,
                OBJECT_NAME(fk.referenced_object_id) AS ref_table, rc.name AS ref_column
         FROM sys.foreign_keys fk
         JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
         JOIN sys.columns pc
           ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
         JOIN sys.columns rc
           ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
         WHERE fk.parent_object_id = OBJECT_ID(@P1)
         ORDER BY fk.name, fkc.constraint_column_id",
        &[&table],
    )
    .await?;
    let mut foreign_keys: Vec<ForeignKeyDetail> = Vec::new();
    for r in &fk_rows {
        let name = non_empty(ss_str(r, 0));
        let col = ss_str(r, 1);
        let ref_table = ss_str(r, 2);
        let ref_col = ss_str(r, 3);
        match foreign_keys.last_mut() {
            Some(last) if last.name == name && last.ref_table == ref_table => {
                last.columns.push(col);
                last.ref_columns.push(ref_col);
            }
            _ => foreign_keys.push(ForeignKeyDetail {
                name,
                columns: vec![col],
                ref_table,
                ref_columns: vec![ref_col],
            }),
        }
    }

    // 表注释（MS_Description）。
    let comment_rows = ss_rows(
        conn, password, db_name,
        "SELECT CAST(ep.value AS NVARCHAR(4000)) AS comment
         FROM sys.extended_properties ep
         WHERE ep.class = 1 AND ep.major_id = OBJECT_ID(@P1)
           AND ep.minor_id = 0 AND ep.name = 'MS_Description'",
        &[&table],
    )
    .await?;
    let comment = comment_rows.first().and_then(|r| ss_opt_str(r, 0));

    Ok(TableDescription {
        table: table.to_string(),
        comment,
        columns,
        primary_key,
        indexes,
        foreign_keys,
    })
}

/// T29 非 SQL 批次（B1）— MongoDB describe：listCollections nameOnly 验存在
/// → find 采样 20 文档推列（键并集保首见序、类型取首个非 null 值，对齐
/// 客户端 getTableColumns 退化实现）→ listIndexes 补索引（视图/无索引
/// 集合报错 → 空，不阻塞）。列无固定 schema：nullable 恒 true、无默认值。
async fn describe_mongo(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    table: &str,
) -> Result<TableDescription, MetadataError> {
    let db_name = crate::mongo::resolve_db(conn, db);
    let client = open_mongo_conn(conn, password).await?;

    // 存在性（nameOnly 轻查询）。
    let resp = mongo_run(
        &client,
        db_name,
        bson::doc! {"listCollections": 1, "filter": {"name": table}, "nameOnly": true},
    )
    .await?;
    if mongo_batch(&resp).is_empty() {
        return Err(MetadataError::not_found(&format!(
            "collection '{table}' (database '{db_name}')"
        )));
    }

    // 采样推列：键并集保首见序；类型先记 null 后被首个非 null 值覆盖。
    const SAMPLE_DOCS: i32 = 20;
    let resp = mongo_run(&client, db_name, bson::doc! {"find": table, "limit": SAMPLE_DOCS}).await?;
    let docs = mongo_batch(&resp);
    let mut names: Vec<String> = Vec::new();
    let mut types: Vec<&'static str> = Vec::new();
    for doc in &docs {
        for (key, value) in doc {
            match names.iter().position(|n| n == key) {
                Some(i) => {
                    if types[i] == "null" && !matches!(value, bson::Bson::Null) {
                        types[i] = crate::mongo::bson_type_name(value);
                    }
                }
                None => {
                    names.push(key.clone());
                    types.push(crate::mongo::bson_type_name(value));
                }
            }
        }
    }
    let columns: Vec<ColumnDetail> = names
        .into_iter()
        .zip(types)
        .map(|(name, data_type)| ColumnDetail {
            name,
            data_type: data_type.to_string(),
            nullable: true,
            default_value: None,
            comment: None,
        })
        .collect();

    // 索引：listIndexes（key 文档键序即索引列序）；失败 → 空（视图等）。
    let idx_docs = mongo_run(&client, db_name, bson::doc! {"listIndexes": table})
        .await
        .map(|resp| mongo_batch(&resp))
        .unwrap_or_default();
    let indexes: Vec<IndexDetail> = idx_docs
        .iter()
        .filter_map(|ix| {
            let name = ix.get_str("name").ok()?.to_string();
            let columns: Vec<String> =
                ix.get_document("key").ok()?.iter().map(|(k, _)| k.to_string()).collect();
            let unique = ix.get_bool("unique").unwrap_or(false);
            Some(IndexDetail { name, columns, unique })
        })
        .collect();

    Ok(TableDescription {
        table: table.to_string(),
        comment: None,
        columns,
        primary_key: Vec::new(),
        indexes,
        foreign_keys: Vec::new(),
    })
}

/// T29 非 SQL 批次（B3）— Redis describe：命名空间（`ns:*`）采样首个 key 的
/// TYPE 推列（对齐客户端 getTableColumns 退化实现）；全部列 nullable（值
/// schema 无约束）；无 PK/索引概念。`(root)` 命名空间以无 `:` 的裸 key 采样。
async fn describe_redis(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    table: &str,
) -> Result<TableDescription, MetadataError> {
    let db_idx = crate::redis_leg::db_index(conn, db);
    let mut handle = open_redis_conn(conn, password, db_idx).await?;
    let pattern = if table == "(root)" { "*" } else { &format!("{table}:*") };
    let keys = redis_scan_all(&mut handle, pattern, 20).await?;
    let Some(first_key) = keys.first() else {
        return Err(MetadataError::not_found(&format!(
            "namespace '{table}' (database '{db_idx}')"
        )));
    };

    let type_resp = redis_cmd(&mut handle, "TYPE", &[first_key]).await?;
    let key_type = match type_resp {
        redis::Value::SimpleString(s) => s.to_ascii_lowercase(),
        redis::Value::BulkString(b) => String::from_utf8_lossy(&b).to_ascii_lowercase(),
        _ => "none".to_string(),
    };
    let field_specs: &[(&str, &str)] = match key_type.as_str() {
        "hash" => &[("field", "string"), ("value", "string")],
        "list" => &[("index", "int"), ("value", "string")],
        "set" => &[("member", "string")],
        "zset" => &[("member", "string"), ("score", "double")],
        "stream" => &[("id", "string"), ("fields", "object")],
        // string / none / 未知类型：单值列。
        _ => &[("value", "string")],
    };
    let columns: Vec<ColumnDetail> = field_specs
        .iter()
        .map(|(name, ty)| ColumnDetail {
            name: name.to_string(),
            data_type: ty.to_string(),
            nullable: true,
            default_value: None,
            comment: None,
        })
        .collect();

    Ok(TableDescription {
        table: table.to_string(),
        comment: None,
        columns,
        primary_key: Vec::new(),
        indexes: Vec::new(),
        foreign_keys: Vec::new(),
    })
}

// ── 小工具 ──

/// 空串归一为 None（information_schema 的注释列常用 '' 而非 NULL）。
fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

/// MySQL wire 行数估计解码链：information_schema 的 table_rows 是
/// BIGINT UNSIGNED（sqlx 拒绝 u64→i64 直解），CH 的 total_rows 是
/// Nullable(UInt64)——按 i64 → u64 → f64 依次尝试（实机验证发现）。
fn mysql_row_count(row: &sqlx::mysql::MySqlRow, idx: usize) -> Option<i64> {
    row.try_get::<Option<i64>, _>(idx).ok().flatten()
        .or_else(|| row.try_get::<Option<u64>, _>(idx).ok().flatten().map(|v| v as i64))
        .or_else(|| row.try_get::<Option<f64>, _>(idx).ok().flatten().map(|v| v as i64))
}

/// db_type 是否 Doris 的判据已 T21 收敛到族薄适配注册表
/// （`mysql_family_for` / `MysqlFamilyHooks`，见 mysql_family.rs）；
/// MySQL 方言字符串字面量转义（`mysql_str_literal`）同迁该模块。

/// PG string_agg 逗号串拆列（trim 防御空白）。NULL → 空列表。
fn split_csv(s: Option<String>) -> Vec<String> {
    match s {
        Some(joined) if !joined.is_empty() => {
            joined.split(',').map(|p| p.trim().to_string()).collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_csv_handles_null_and_spaces() {
        assert!(split_csv(None).is_empty());
        assert!(split_csv(Some(String::new())).is_empty());
        assert_eq!(split_csv(Some("a, b".into())), vec!["a", "b"]);
    }

    #[test]
    fn non_empty_normalizes_empty_string() {
        assert!(non_empty(String::new()).is_none());
        assert_eq!(non_empty("hi".into()).as_deref(), Some("hi"));
    }

    #[test]
    fn family_for_covers_gateway_supported_set_plus_doris() {
        // 与 db_handler::backend_for 同集 + doris（同走 MySQL wire，经族
        // 薄适配注册表）。T28 增 sqlserver/mssql（tiberius）。
        assert!(matches!(family_for("mysql").unwrap(), Family::MySql(_)));
        assert!(matches!(family_for("Doris").unwrap(), Family::MySql(_)));
        assert!(matches!(family_for("postgresql").unwrap(), Family::Postgres));
        assert!(matches!(family_for("pg").unwrap(), Family::Postgres));
        assert!(matches!(family_for("sqlite").unwrap(), Family::Sqlite));
        assert!(matches!(family_for("clickhouse").unwrap(), Family::Clickhouse));
        assert!(matches!(family_for("sqlserver").unwrap(), Family::SqlServer));
        assert!(matches!(family_for("MSSQL").unwrap(), Family::SqlServer));
        let err = family_for("oracle").unwrap_err();
        assert_eq!(err.code, "UNSUPPORTED_DB_TYPE");
    }

    // ── PG 多 schema 命名约定 / 寻址解析（纯逻辑，不依赖真库）──

    #[test]
    fn pg_display_name_keeps_public_bare_and_qualifies_others() {
        // public 保持裸名（public-only 库的既有输出不变）。
        assert_eq!(pg_display_name("public", "brands"), ("brands".to_string(), None));
        // 非 public 用 schema.table 限定，且 schema 字段带值（可消歧）。
        assert_eq!(
            pg_display_name("ecommerce", "orders"),
            ("ecommerce.orders".to_string(), Some("ecommerce".to_string()))
        );
        // 对象名本身含点时，限定名仍以最后一段为对象名（schema 字段才是权威）。
        assert_eq!(
            pg_display_name("odd", "has.dot"),
            ("odd.has.dot".to_string(), Some("odd".to_string()))
        );
    }

    #[test]
    fn split_pg_qualified_accepts_exactly_one_non_empty_dot() {
        assert_eq!(split_pg_qualified("ecommerce.orders"), Some(("ecommerce", "orders")));
        // 无 `.` → 裸名路径。
        assert_eq!(split_pg_qualified("brands"), None);
        // 多段：不拆（整体按一个标识符解析，不产生第三段歧义）。
        assert_eq!(split_pg_qualified("a.b.c"), None);
        assert_eq!(split_pg_qualified(".."), None);
        // 空段：不拆（`.x` / `x.` 都不是合法限定名）。
        assert_eq!(split_pg_qualified(".x"), None);
        assert_eq!(split_pg_qualified("x."), None);
        assert_eq!(split_pg_qualified(""), None);
        // 对象名含空格/大写/引号时按裸名走（转义在 SQL 侧由 quote_ident 做）。
        assert_eq!(split_pg_qualified("My Table"), None);
        assert_eq!(split_pg_qualified("has\"quote"), None);
    }

    #[test]
    fn pg_relation_parse_picks_constant_sql_and_params() {
        // 裸名：单参数 + 裸名片段（search_path 解析）。
        let bare = PgRelation::parse("brands");
        assert_eq!(bare.regclass, PG_REGCLASS_BARE);
        assert_eq!(bare.params, vec!["brands".to_string()]);
        assert_eq!(bare.schema(), None);
        assert_eq!(bare.object_name(), "brands");

        // 限定名：两参数 + 限定片段。
        let qualified = PgRelation::parse("ecommerce.orders");
        assert_eq!(qualified.regclass, PG_REGCLASS_QUALIFIED);
        assert_eq!(qualified.params, vec!["ecommerce".to_string(), "orders".to_string()]);
        assert_eq!(qualified.schema(), Some("ecommerce"));
        assert_eq!(qualified.object_name(), "orders");

        // `public.users` 显式限定同样命中（与裸名 `users` 等价解析目标）。
        let public = PgRelation::parse("public.users");
        assert_eq!(public.regclass, PG_REGCLASS_QUALIFIED);
        assert_eq!(public.params, vec!["public".to_string(), "users".to_string()]);

        // 畸形输入回落到裸名路径（整体作为一个标识符，落 NOT_FOUND）。
        for malformed in ["a.b.c", ".x", "x.", ".."] {
            let rel = PgRelation::parse(malformed);
            assert_eq!(rel.regclass, PG_REGCLASS_BARE, "{malformed} 应走裸名路径");
            assert_eq!(rel.params, vec![malformed.to_string()]);
        }
    }

    #[test]
    fn pg_regclass_sql_never_inlines_caller_input() {
        // SQL 片段是编译期常量：两段都经服务端 quote_ident，无字符串拼接
        // 输入；注入尝试只会作为**绑定值**传递，不改变 SQL 结构。
        for sql in [PG_REGCLASS_BARE, PG_REGCLASS_QUALIFIED] {
            assert!(
                sql.starts_with("to_regclass(") && sql.ends_with(')'),
                "unexpected fragment: {sql}"
            );
        }
        assert!(PG_REGCLASS_BARE.contains("quote_ident($1)"));
        assert!(!PG_REGCLASS_BARE.contains("'public.'"), "public 前缀硬编码已移除");
        assert!(PG_REGCLASS_QUALIFIED.contains("quote_ident($1) || '.' || quote_ident($2)"));

        // 攻击性输入：整个字符串只作为绑定参数出现，SQL 片段不变。
        for hostile in [
            "ecommerce.orders'; DROP TABLE users; --",
            "public.\"users\"",
            "a.b'.c",
        ] {
            let rel = PgRelation::parse(hostile);
            assert!(
                rel.regclass == PG_REGCLASS_BARE || rel.regclass == PG_REGCLASS_QUALIFIED,
                "SQL 片段必须是常量之一，实际: {}",
                rel.regclass
            );
            assert!(
                !rel.regclass.contains("DROP") && !rel.regclass.contains(hostile),
                "SQL 片段不得含调用方输入"
            );
            // 输入的每一字节都只出现在绑定参数里（限定路径拆两段，裸名路径
            // 整串一段——两种情形 join 回原串）。
            assert_eq!(rel.params.join("."), hostile, "输入必须原样落绑定参数");
        }
    }

    // ── 契约兼容：TableSummary.schema 只加不删 ──

    #[test]
    fn table_summary_omits_schema_key_when_none() {
        let t = TableSummary {
            name: "brands".to_string(),
            schema: None,
            kind: "table".to_string(),
            comment: None,
            row_estimate: None,
        };
        let v = serde_json::to_value(t).unwrap();
        // 键集与加字段前逐字节一致（既有引擎/既有 public-only 库输出不变）。
        assert_eq!(v, serde_json::json!({ "name": "brands", "type": "table" }));
        assert!(v.get("schema").is_none());
    }

    #[test]
    fn table_summary_serializes_schema_when_present() {
        let t = TableSummary {
            name: "ecommerce.orders".to_string(),
            schema: Some("ecommerce".to_string()),
            kind: "table".to_string(),
            comment: Some("orders".to_string()),
            row_estimate: Some(42),
        };
        let v = serde_json::to_value(t).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "name": "ecommerce.orders",
                "schema": "ecommerce",
                "type": "table",
                "comment": "orders",
                "rowEstimate": 42
            })
        );
    }

    #[test]
    fn mysql_family_branch_carries_profile() {
        // Family::MySql 携带薄适配 profile——族内差异（目录查询模式等）的
        // 唯一来源；Doris 与 MySQL 的 profile 不同实例。
        let Family::MySql(mysql_profile) = family_for("mysql").unwrap() else {
            panic!("mysql must map to Family::MySql");
        };
        let Family::MySql(doris_profile) = family_for("doris").unwrap() else {
            panic!("doris must map to Family::MySql");
        };
        assert_eq!(mysql_profile.name(), "mysql");
        assert_eq!(doris_profile.name(), "doris");
        assert!(!std::ptr::eq(mysql_profile, doris_profile));
    }
}
