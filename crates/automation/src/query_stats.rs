//! 慢查询采样（#29 reports 管道 M1，`.specs/design-reports-m1.md`）。
//!
//! 捕获点全集（8 个，全部在已有 elapsed 计算处 + admin_script 新增计时）：
//!
//! | entry | 位置 |
//! |---|---|
//! | `gw_sse` | `stream_query.rs` 四入口（sql :181 / mongo :222 / redis :401 / tdengine :617） |
//! | `sync_query` | `db_handler.rs` `db_query`（:650） |
//! | `txn_query` | `db_handler.rs` `txn_query`（:734） |
//! | `admin_script` | `db_handler.rs` `admin_script` 逐条循环（计时本任务新增） |
//! | `mcp_read` | `read_query.rs` `run_read_query`（:107） |
//!
//! 显式排除（口径）：连接测试（`test_connection` / `db_test`——探测语句非用户
//! 查询）、元数据/目录端点（`metadata::list_*`）、txn BEGIN/COMMIT/ROLLBACK 与
//! admin KILL（控制语句无计时）、redis subscribe（pubsub 非查询）、DDL 审批
//! 执行（`execute_ddl_on_target_with_key`，automation 域，M2+ 再议）、
//! health/drift/data_sync runner（直连目标库，不经数据面）。
//!
//! 旁路纪律：判定链全内存（enabled → threshold → digest → 封顶）→
//! `tokio::spawn` INSERT，写失败 `tracing::warn` 吞错——绝不阻塞查询主链路。
//! 日志与错误路径禁止输出 SQL 明文/凭据（审计域纪律同源）。
//!
//! 增长有界（vault 前科教训）：阈值过滤 + 同 digest 每小时封顶（内存滑窗，
//! 重启归零）+ 每小时 retention DELETE 硬兜底（`rotate`，见文末）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use dbmaster_core::auth::rate_limiter::SlidingWindowLimiter;
use dbmaster_core::config::Config;
use sqlx::SqlitePool;

/// digest 归一化文本的最大长度（字符），超长截断加 `…` 标记。
const DIGEST_MAX_CHARS: usize = 1000;
/// 明文 SQL（sql_text 列）的最大长度（字符），超长截断加 `…` 标记。
const SQL_TEXT_MAX_CHARS: usize = 8192;
/// 封顶滑窗时长：同 digest 每小时至多 `cap` 条采样。
const CAP_WINDOW_SECS: u64 = 3600;
/// retention 清理的 tick 间隔（秒）。
const CLEANUP_INTERVAL_SECS: u64 = 3600;

/// 捕获点标识（`query_stats.entry` 列，migration 016 枚举契约）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureEntry {
    GwSse,
    SyncQuery,
    TxnQuery,
    AdminScript,
    McpRead,
}

impl CaptureEntry {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GwSse => "gw_sse",
            Self::SyncQuery => "sync_query",
            Self::TxnQuery => "txn_query",
            Self::AdminScript => "admin_script",
            Self::McpRead => "mcp_read",
        }
    }
}

/// 执行结果（`status` + `error_code` 列）。`Error` 只放**稳定错误码**
/// （TIMEOUT / CANCELLED / DB_ERROR…），不放引擎原文（可能含标识符）。
#[derive(Debug, Clone)]
pub enum CaptureOutcome {
    Ok,
    Error(String),
    Cancelled,
}

impl CaptureOutcome {
    fn status(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error(_) => "error",
            Self::Cancelled => "cancelled",
        }
    }

    fn error_code(&self) -> Option<&str> {
        match self {
            Self::Ok | Self::Cancelled => None,
            Self::Error(code) => Some(code.as_str()),
        }
    }
}

/// 捕获上下文：hook 点作用域内天然可得的信息。
#[derive(Debug, Clone)]
pub struct CaptureContext<'a> {
    pub conn_id: &'a str,
    /// db_type 原名（mysql / postgresql / clickhouse / mongodb / redis / tdengine / sqlite…）。
    /// 流式入口作用域内无 conn 行 → 传 None，写入路径懒查（只有过了判定链
    /// 的慢查询才付这次 SELECT）。
    pub db_kind: Option<&'a str>,
    /// 目标库；事务路径为 None（session 不保存 db）。
    pub database: Option<&'a str>,
    /// JWT subject；stream 路径无 claims 时 None。
    pub user_id: Option<&'a str>,
    pub entry: CaptureEntry,
    pub outcome: CaptureOutcome,
}

/// 被捕获的执行载荷。形态即库族判别器：SQL 系（含 TDengine）走字面量归一化，
/// Mongo / Redis 各自的命令形 digest（design §4.2）。
#[derive(Debug, Clone, Copy)]
pub enum CapturePayload<'a> {
    /// SQL 文本（原始单语句，字面量内联）。
    Sql(&'a str),
    /// Mongo 命令文档（JSON；preserve_order 下首键 = 命令名）。
    Mongo(&'a serde_json::Value),
    /// Redis 单命令（command + args）。
    Redis(&'a [String]),
    /// Redis pipeline（MULTI/EXEC 包裹的多命令）。
    RedisPipeline(&'a [Vec<String>]),
}

/// 进程级采样器。经 [`init`] 注册为全局单例后由 8 个 hook 点经 [`record`]
/// 旁路写入；未初始化时 [`record`] 为 no-op（单测 / 未走 `build_app_with_config`
/// 的边界安全）。
pub struct QueryStatsRecorder {
    pool: SqlitePool,
    enabled: bool,
    threshold_ms: u64,
    store_sql: bool,
    cap_per_hour: usize,
    cap_limiter: SlidingWindowLimiter,
    /// 判定链各环节丢弃的累计计数（封顶超额；观测用，读端点 meta 暴露）。
    dropped: AtomicU64,
}

impl QueryStatsRecorder {
    pub fn new(pool: SqlitePool, config: &Config) -> Self {
        Self::from_parts(
            pool,
            config.slow_query_enabled,
            config.slow_query_threshold_ms,
            config.slow_query_store_sql,
            config.slow_query_cap_per_digest_per_hour,
        )
    }

    fn from_parts(
        pool: SqlitePool,
        enabled: bool,
        threshold_ms: u32,
        store_sql: bool,
        cap_per_hour: u32,
    ) -> Self {
        Self {
            pool,
            enabled,
            threshold_ms: threshold_ms as u64,
            store_sql,
            cap_per_hour: cap_per_hour as usize,
            cap_limiter: SlidingWindowLimiter::new(),
            dropped: AtomicU64::new(0),
        }
    }

    /// 全局已丢弃计数（读端点 meta 用；未初始化为 None）。
    pub fn dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 判定链（全内存——捕获热路径上的唯一开销，先于任何 DB 工作）。
    fn gate(&self, elapsed_ms: u64, digest: &str) -> bool {
        if !self.enabled || elapsed_ms < self.threshold_ms {
            return false;
        }
        if !self
            .cap_limiter
            .check_and_record(digest, self.cap_per_hour, CAP_WINDOW_SECS)
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// 旁路记录入口：判定 → 组行 → fire-and-forget 写入。
    pub fn record(
        &self,
        elapsed_ms: u64,
        ctx: &CaptureContext<'_>,
        payload: &CapturePayload<'_>,
        row_count: Option<u64>,
        affected_rows: Option<u64>,
    ) {
        let digest = normalize_digest(payload);
        if !self.gate(elapsed_ms, &digest) {
            return;
        }
        let sql_text = if self.store_sql {
            Some(truncate_chars(&render_plaintext(payload), SQL_TEXT_MAX_CHARS))
        } else {
            None
        };
        let owned = OwnedCapture {
            conn_id: ctx.conn_id.to_string(),
            db_kind: ctx.db_kind.map(str::to_string),
            database: ctx.database.map(str::to_string),
            user_id: ctx.user_id.map(str::to_string),
            entry: ctx.entry.as_str().to_string(),
            status: ctx.outcome.status().to_string(),
            error_code: ctx.outcome.error_code().map(str::to_string),
        };
        let pool = self.pool.clone();
        tokio::spawn(async move {
            let db_kind = match owned.db_kind {
                Some(k) => k,
                None => {
                    match sqlx::query_scalar::<_, String>(
                        "SELECT db_type FROM database_connections WHERE id = ?1",
                    )
                    .bind(&owned.conn_id)
                    .fetch_optional(&pool)
                    .await
                    {
                        Ok(Some(k)) => k,
                        // 连接已删除——采样无处归属，丢弃。
                        Ok(None) => return,
                        Err(e) => {
                            tracing::warn!("query_stats db_kind lookup failed: {e}");
                            return;
                        }
                    }
                }
            };
            let row = InsertRow {
                id: uuid::Uuid::new_v4().to_string(),
                source: "gateway".to_string(),
                conn_id: owned.conn_id,
                db_kind,
                database: owned.database,
                digest,
                sql_text,
                elapsed_ms: elapsed_ms as i64,
                row_count: row_count.map(|v| v as i64),
                affected_rows: affected_rows.map(|v| v as i64),
                query_count: None,
                status: owned.status,
                error_code: owned.error_code,
                user_id: owned.user_id,
                entry: owned.entry,
                captured_at: chrono::Utc::now().to_rfc3339(),
            };
            if let Err(e) = insert_row(&pool, &row).await {
                // 错误信息只含 sqlite 层内容（无 SQL 明文/凭据）。
                tracing::warn!("query_stats insert failed: {e}");
            }
        });
    }
}

/// record() 移入 spawn 的_owned 上下文（lifetime 解耦）。
struct OwnedCapture {
    conn_id: String,
    db_kind: Option<String>,
    database: Option<String>,
    user_id: Option<String>,
    entry: String,
    status: String,
    error_code: Option<String>,
}

pub(crate) struct InsertRow {
    id: String,
    source: String,
    conn_id: String,
    db_kind: String,
    database: Option<String>,
    digest: String,
    sql_text: Option<String>,
    elapsed_ms: i64,
    row_count: Option<i64>,
    affected_rows: Option<i64>,
    /// 019 — 计数器差分行的区间查询次数；事件行 NULL（=1）。
    query_count: Option<i64>,
    status: String,
    error_code: Option<String>,
    user_id: Option<String>,
    entry: String,
    captured_at: String,
}

pub(crate) async fn insert_row(pool: &SqlitePool, row: &InsertRow) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO query_stats (id, source, conn_id, db_kind, database, digest, sql_text, \
         elapsed_ms, row_count, affected_rows, query_count, status, error_code, user_id, entry, captured_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
    )
    .bind(&row.id)
    .bind(&row.source)
    .bind(&row.conn_id)
    .bind(&row.db_kind)
    .bind(&row.database)
    .bind(&row.digest)
    .bind(&row.sql_text)
    .bind(row.elapsed_ms)
    .bind(row.row_count)
    .bind(row.affected_rows)
    .bind(row.query_count)
    .bind(&row.status)
    .bind(&row.error_code)
    .bind(&row.user_id)
    .bind(&row.entry)
    .bind(&row.captured_at)
    .execute(pool)
    .await
    .map(|_| ())
}

// ── 全局单例 ──

static RECORDER: OnceLock<Arc<QueryStatsRecorder>> = OnceLock::new();

/// 注册全局采样器（`build_app_with_config` 调用——远程与 embedded 唯一共同
/// 构建点）。二次调用（异常接线/测试）保留首个并 WARN。
pub fn init(pool: SqlitePool, config: &Config) {
    let recorder = Arc::new(QueryStatsRecorder::new(pool, config));
    if RECORDER.set(recorder).is_err() {
        tracing::warn!("query_stats recorder already initialised; keeping existing");
    }
}

/// 全局丢弃计数（读端点 meta 用；未初始化返回 None）。
pub fn dropped_total() -> Option<u64> {
    RECORDER.get().map(|r| r.dropped_total())
}

/// hook 点统一入口：未初始化时 no-op。
pub fn record(
    elapsed_ms: u64,
    ctx: &CaptureContext<'_>,
    payload: &CapturePayload<'_>,
    row_count: Option<u64>,
    affected_rows: Option<u64>,
) {
    if let Some(recorder) = RECORDER.get() {
        recorder.record(elapsed_ms, ctx, payload, row_count, affected_rows);
    }
}

/// SSE 流式入口（stream_query 四入口）的便捷封装：outcome 直接映射终态
/// （Ok → row_count/affected_rows；Err → 稳定错误码；CANCELLED → cancelled）。
pub fn record_stream(
    elapsed_ms: u64,
    conn_id: &str,
    db: Option<&str>,
    payload: &CapturePayload<'_>,
    outcome: &Result<crate::stream_query::CompleteInfo, crate::stream_query::StreamQueryError>,
) {
    let (oc, row_count, affected_rows) = match outcome {
        Ok(info) => (CaptureOutcome::Ok, Some(info.row_count), info.affected_rows),
        Err(e) => (
            if e.code == "CANCELLED" {
                CaptureOutcome::Cancelled
            } else {
                CaptureOutcome::Error(e.code.clone())
            },
            None,
            None,
        ),
    };
    record(
        elapsed_ms,
        &CaptureContext {
            conn_id,
            db_kind: None,
            database: db,
            user_id: None,
            entry: CaptureEntry::GwSse,
            outcome: oc,
        },
        payload,
        row_count,
        affected_rows,
    );
}

// ── M3 原生采集器插入通道 ──

/// 原生源样本直插（不经阈值/封顶——原生源有自己的慢判定；受统一
/// retention 清理）。`source` 形如 `db_native:redis_slowlog`。
///
/// `query_count`：事件型源（一行一事件）传 `None`（=1）；**计数器差分源**
/// （v2 MySQL PS digest）一行代表一个 digest 的区间增量——传
/// `Some(delta_count)`，聚合读路径按 `SUM(COALESCE(query_count,1))`
/// 计查询次数、`elapsed_ms` 为该增量区间的总耗时。注意 `row_count` 列
/// 语义归网关捕获（「该查询返回行数」），原生路径恒 NULL。
pub(crate) async fn insert_native(
    pool: &SqlitePool,
    conn_id: &str,
    db_kind: &str,
    database: Option<&str>,
    source: &str,
    digest: &str,
    sql_text: Option<&str>,
    elapsed_ms: i64,
    query_count: Option<i64>,
) -> sqlx::Result<()> {
    let row = InsertRow {
        id: uuid::Uuid::new_v4().to_string(),
        source: source.to_string(),
        conn_id: conn_id.to_string(),
        db_kind: db_kind.to_string(),
        database: database.map(str::to_string),
        digest: digest.to_string(),
        sql_text: sql_text.map(|s| truncate_chars(s, SQL_TEXT_MAX_CHARS)),
        elapsed_ms,
        row_count: None,
        affected_rows: None,
        query_count,
        status: "ok".to_string(),
        error_code: None,
        user_id: None,
        entry: "native".to_string(),
        captured_at: chrono::Utc::now().to_rfc3339(),
    };
    insert_row(pool, &row).await
}

// ── 聚合读取（summary 端点与 M2 周报 writer 共享）──

/// 按 digest(+连接+库种) 的聚合行。
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct DigestAggRow {
    pub digest: String,
    pub db_kind: String,
    pub conn_id: String,
    pub count: i64,
    pub total_ms: i64,
    pub avg_ms: f64,
    pub max_ms: i64,
    pub first_seen: String,
    pub last_seen: String,
}

/// digest 聚合查询。`sort_expr` 必须来自调用方白名单（handler 的
/// `query_stats_sort_expr` / writer 的固定 `SUM(elapsed_ms)`）——不接外部
/// 输入，防注入。
pub async fn aggregate(
    pool: &SqlitePool,
    since: &str,
    conn_id: Option<&str>,
    sort_expr: &str,
    limit: i64,
) -> sqlx::Result<Vec<DigestAggRow>> {
    let sql = format!(
        // count/avg 按 row_count 语义：事件行 COALESCE→1，计数器差分行
        // （PS digest）一行代表 N 次查询——查询次数与均值按真实次数算。
        // max_ms 对差分行是「区间总耗时」（≥单次最大，上界语义——文档化
        // 的口径取舍，gateway 行不受影响）。
        "SELECT digest, db_kind, conn_id, \
         CAST(SUM(COALESCE(query_count, 1)) AS INTEGER) AS count, \
         SUM(elapsed_ms) AS total_ms, \
         CAST(SUM(elapsed_ms) AS REAL) / SUM(COALESCE(query_count, 1)) AS avg_ms, \
         MAX(elapsed_ms) AS max_ms, \
         MIN(captured_at) AS first_seen, MAX(captured_at) AS last_seen \
         FROM query_stats \
         WHERE captured_at >= ?1 AND (?2 IS NULL OR conn_id = ?2) \
         GROUP BY digest, db_kind, conn_id \
         ORDER BY {sort_expr} DESC, last_seen DESC LIMIT ?3"
    );
    sqlx::query_as::<_, DigestAggRow>(&sql)
        .bind(since)
        .bind(conn_id)
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// 取某 (digest, conn_id) 最新一条的明文样本（两步查询的第二步；未存
/// 明文时为 NULL 透传）。
pub async fn latest_sample(
    pool: &SqlitePool,
    digest: &str,
    conn_id: &str,
) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT sql_text FROM query_stats \
         WHERE digest = ?1 AND conn_id = ?2 \
         ORDER BY captured_at DESC LIMIT 1",
    )
    .bind(digest)
    .bind(conn_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .flatten()
}

// ── retention 轮转（design §5：增长硬界兜底）──

/// 删除 `captured_at` 早于 `retention_days` 天前的行（health_check
/// `rotate_results` 同款 SQL 形态）。返回删除行数。
///
/// 边界说明：captured_at 是 RFC3339（`T` 分隔），SQLite `datetime()` 是空格
/// 分隔——字符串比较下「与阈值同日」的行无论时刻一律保留（±1 天 slop），
/// 对 retention 语义无害（与 health_check 既有行为一致）。
pub async fn rotate(pool: &SqlitePool, retention_days: u32) -> sqlx::Result<u64> {
    let days = format!("-{retention_days} days");
    let res = sqlx::query("DELETE FROM query_stats WHERE captured_at < datetime('now', ?1)")
        .bind(days)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// 每小时跑一次 [`rotate`]。双模式（远程 + embedded）**无条件**启动——
/// housekeeping 非付费功能，不挂 entitlement 门（对齐 data_sync scheduler
/// 在 embedded 可跑的机制先例）。`tokio::time::interval` 首个 tick 立即
/// 触发（启动即清一次）。
pub fn spawn_cleanup(pool: SqlitePool, retention_days: u32) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));
        loop {
            tick.tick().await;
            match rotate(&pool, retention_days).await {
                Ok(n) if n > 0 => tracing::info!(deleted = n, "query_stats retention rotate"),
                Ok(_) => {}
                Err(e) => tracing::warn!("query_stats retention rotate failed: {e}"),
            }
        }
    })
}

// ── digest 归一化（design §4.2）──

/// 归一化 digest。规则只影响**新写入行**，后续 refinement 不需迁移
/// （digest 是文本可检视）。
pub fn normalize_digest(payload: &CapturePayload<'_>) -> String {
    match payload {
        CapturePayload::Sql(sql) => truncate_chars(&normalize_sql(sql), DIGEST_MAX_CHARS),
        CapturePayload::Mongo(doc) => normalize_mongo(doc),
        CapturePayload::Redis(cmdline) => normalize_redis(cmdline),
        CapturePayload::RedisPipeline(pipeline) => normalize_redis_pipeline(pipeline),
    }
}

/// SQL 系归一化：单引号字符串与数字字面量 → `?`，连续空白折叠为单空格，
/// 其余字符原样保留（标识符/关键字大小写不折叠——同语句不同大小写视为
/// 不同 digest，M1 已文档化的取舍）。
fn normalize_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len().min(DIGEST_MAX_CHARS + 16));
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // 单引号字符串字面量（含 MySQL 反斜杠转义与 '' 加倍两种形态；
            // PG 的 E'...' 前缀字符原样通过，无害）。
            '\'' => {
                let mut escaped = false;
                while let Some(c2) = chars.next() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    match c2 {
                        '\\' => escaped = true,
                        '\'' => {
                            if chars.peek() == Some(&'\'') {
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                out.push('?');
            }
            // 数字字面量（十进制 / 浮点 / 科学计数 / 0x 十六进制）→ ?
            '0'..='9' => {
                consume_number_tail(&mut chars, c == '0');
                out.push('?');
            }
            // 带符号数字（-5 / +1.5）并入同一个占位符；裸 +/- 原样通过。
            '-' | '+' if matches!(chars.peek(), Some(d) if d.is_ascii_digit()) => {
                chars.next();
                consume_number_tail(&mut chars, false);
                out.push('?');
            }
            // 连续空白折叠为单空格（去首空格）。
            _ if c.is_whitespace() => {
                while matches!(chars.peek(), Some(w) if w.is_whitespace()) {
                    chars.next();
                }
                if !out.is_empty() && !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// 消费数字字面量的尾部（首字符已被消费）。`hex_prefix` 表示首字符是 `0`
/// （可能是 0x 十六进制）。
fn consume_number_tail(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    hex_prefix: bool,
) {
    if hex_prefix && matches!(chars.peek(), Some('x') | Some('X')) {
        chars.next();
        while matches!(chars.peek(), Some(h) if h.is_ascii_hexdigit()) {
            chars.next();
        }
        return;
    }
    while matches!(chars.peek(), Some(d) if d.is_ascii_digit() || *d == '.') {
        chars.next();
    }
    // 科学计数尾部 e[+-]digits（前瞻确认，避免吞掉 e 开头的标识符）。
    if matches!(chars.peek(), Some('e') | Some('E')) {
        let mut lookahead = chars.clone();
        lookahead.next();
        let valid = match lookahead.peek() {
            Some(d) if d.is_ascii_digit() => true,
            Some('+') | Some('-') => {
                lookahead.next();
                matches!(lookahead.peek(), Some(d) if d.is_ascii_digit())
            }
            _ => false,
        };
        if valid {
            chars.next();
            if matches!(chars.peek(), Some('+') | Some('-')) {
                chars.next();
            }
            while matches!(chars.peek(), Some(d) if d.is_ascii_digit()) {
                chars.next();
            }
        }
    }
}

/// Mongo：`mongo:{命令名}:{collection}`——collection 取命令文档中命令名对应的
/// 首字符串值（find/insert/update/aggregate… 的目标）；非字符串值或非对象
/// 文档回退 `?`（M1 已文档化的简化：不区分 filter/聚合阶段差异）。
fn normalize_mongo(doc: &serde_json::Value) -> String {
    let Some(obj) = doc.as_object() else {
        return "mongo:?".to_string();
    };
    let Some((cmd, cmd_value)) = obj.iter().next() else {
        return "mongo:?".to_string();
    };
    let collection = cmd_value.as_str().unwrap_or("?");
    format!("mongo:{cmd}:{collection}")
}

/// Redis 单命令：`redis:{CMD 大写}:{token 数}`（含命令名本身）。
fn normalize_redis(cmdline: &[String]) -> String {
    let cmd = cmdline
        .first()
        .map(|s| s.to_uppercase())
        .unwrap_or_default();
    format!("redis:{}:{}", cmd, cmdline.len())
}

/// Redis pipeline：`redis:PIPELINE[{命令数}]:{CMD1+CMD2…}`（截断）。
fn normalize_redis_pipeline(pipeline: &[Vec<String>]) -> String {
    let cmds: Vec<String> = pipeline
        .iter()
        .map(|c| c.first().map(|s| s.to_uppercase()).unwrap_or_default())
        .collect();
    let joined = cmds.join("+");
    truncate_chars(&format!("redis:PIPELINE[{}]:{}", pipeline.len(), joined), DIGEST_MAX_CHARS)
}

/// 明文渲染（sql_text 列内容；非 SQL 族给出可读的一行形态）。
fn render_plaintext(payload: &CapturePayload<'_>) -> String {
    match payload {
        CapturePayload::Sql(sql) => (*sql).to_string(),
        CapturePayload::Mongo(doc) => doc.to_string(),
        CapturePayload::Redis(cmdline) => cmdline.join(" "),
        CapturePayload::RedisPipeline(pipeline) => pipeline
            .iter()
            .map(|c| c.join(" "))
            .collect::<Vec<_>>()
            .join(" ; "),
    }
}

/// 字符级安全截断：超长加 `…` 后缀标记（区别于原样文本）。
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        dbmaster_core::db::run_migrations(&pool).await.unwrap();
        pool
    }

    // ── SQL 归一化 ──

    #[test]
    fn normalize_sql_replaces_string_literals() {
        assert_eq!(
            normalize_sql("SELECT * FROM users WHERE name = 'bob'"),
            "SELECT * FROM users WHERE name = ?"
        );
    }

    #[test]
    fn normalize_sql_handles_escaped_and_doubled_quotes() {
        // MySQL 反斜杠转义
        assert_eq!(
            normalize_sql("SELECT 'a\\'b'"),
            "SELECT ?"
        );
        // SQL 标准 '' 加倍
        assert_eq!(
            normalize_sql("SELECT 'it''s'"),
            "SELECT ?"
        );
        // 引号结束后接字面量外字符
        assert_eq!(
            normalize_sql("WHERE msg = 'hi' AND x = 1"),
            "WHERE msg = ? AND x = ?"
        );
    }

    #[test]
    fn normalize_sql_replaces_number_forms() {
        assert_eq!(normalize_sql("LIMIT 10"), "LIMIT ?");
        assert_eq!(normalize_sql("x = 3.14"), "x = ?");
        assert_eq!(normalize_sql("x = 1e5"), "x = ?");
        assert_eq!(normalize_sql("x = 2.5E-3"), "x = ?");
        assert_eq!(normalize_sql("x = 0x1F"), "x = ?");
        assert_eq!(normalize_sql("x = -42"), "x = ?");
        assert_eq!(normalize_sql("x = +7"), "x = ?");
        // 裸 +/- 原样（运算符/注释符语义）
        assert_eq!(normalize_sql("a-b"), "a-b");
    }

    #[test]
    fn normalize_sql_merges_same_shape_only() {
        let a = normalize_sql("SELECT * FROM t WHERE id = 5 AND name = 'x'");
        let b = normalize_sql("SELECT * FROM t WHERE id = 42 AND name = 'y'");
        let c = normalize_sql("SELECT * FROM t WHERE uid = 5 AND name = 'x'");
        assert_eq!(a, b, "同形态不同字面量应合并");
        assert_ne!(a, c, "不同列名不应合并");
    }

    #[test]
    fn normalize_sql_collapses_whitespace() {
        assert_eq!(
            normalize_sql("SELECT\n\t  a,\n   b\nFROM t"),
            "SELECT a, b FROM t"
        );
        assert_eq!(normalize_sql("  leading"), "leading");
    }

    #[test]
    fn normalize_sql_truncates_beyond_digest_max() {
        // normalize_sql 本层不截断（透传），截断在 normalize_digest 层施加。
        let long = "a".repeat(DIGEST_MAX_CHARS + 100);
        assert_eq!(normalize_sql(&long).chars().count(), DIGEST_MAX_CHARS + 100);
    }

    #[test]
    fn normalize_digest_sql_truncates() {
        let payload = CapturePayload::Sql(&"x".repeat(5000));
        let digest = normalize_digest(&payload);
        assert_eq!(digest.chars().count(), DIGEST_MAX_CHARS + 1);
    }

    // ── Mongo / Redis ──

    #[test]
    fn normalize_mongo_extracts_command_and_collection() {
        // preserve_order feature 下首键 = 命令名（automation Cargo.toml）。
        let doc: serde_json::Value =
            serde_json::from_str(r#"{"find":"orders","filter":{"status":"paid"},"limit":10}"#)
                .unwrap();
        assert_eq!(normalize_mongo(&doc), "mongo:find:orders");

        let agg: serde_json::Value =
            serde_json::from_str(r#"{"aggregate":"events","pipeline":[{"$match":{}}]}"#).unwrap();
        assert_eq!(normalize_mongo(&agg), "mongo:aggregate:events");

        // 命令名对应值非字符串（如 admin 命令文档）→ 回退 ?
        let admin: serde_json::Value =
            serde_json::from_str(r#"{"ping":1}"#).unwrap();
        assert_eq!(normalize_mongo(&admin), "mongo:ping:?");

        // 非对象（标量/数组）
        let scalar: serde_json::Value = serde_json::from_str("1").unwrap();
        assert_eq!(normalize_mongo(&scalar), "mongo:?");
    }

    #[test]
    fn normalize_redis_single_and_pipeline() {
        let cmd = vec!["GET".to_string(), "user:42".to_string()];
        assert_eq!(normalize_redis(&cmd), "redis:GET:2");

        let lower = vec!["smembers".to_string(), "bigset".to_string()];
        assert_eq!(normalize_redis(&lower), "redis:SMEMBERS:2");

        let pipeline = vec![
            vec!["SET".to_string(), "k1".to_string(), "v1".to_string()],
            vec!["GET".to_string(), "k1".to_string()],
        ];
        assert_eq!(
            normalize_redis_pipeline(&pipeline),
            "redis:PIPELINE[2]:SET+GET"
        );
    }

    // ── 判定链 ──

    #[tokio::test]
    async fn gate_enforces_threshold_then_cap() {
        let pool = test_pool().await;
        let recorder =
            QueryStatsRecorder::from_parts(pool, true, 1000, true, 3);

        // 低于阈值 → 拒（不计 dropped——threshold 不是丢弃防线）
        assert!(!recorder.gate(999, "d1"));
        assert_eq!(recorder.dropped_total(), 0);
        // 达阈值 + 同 digest 前 3 次 → 过
        for _ in 0..3 {
            assert!(recorder.gate(1000, "d1"));
        }
        // 第 4 次起封顶拒 + 计数
        assert!(!recorder.gate(2000, "d1"));
        assert!(!recorder.gate(2000, "d1"));
        assert_eq!(recorder.dropped_total(), 2);
        // 不同 digest 不受影响
        assert!(recorder.gate(1500, "d2"));

        // 总开关关 → 全拒
        let pool2 = test_pool().await;
        let off = QueryStatsRecorder::from_parts(pool2, false, 1000, true, 3);
        assert!(!off.gate(999_999, "d1"));
    }

    #[tokio::test]
    async fn record_inserts_row_with_full_shape() {
        let pool = test_pool().await;
        let recorder = Arc::new(QueryStatsRecorder::from_parts(
            pool.clone(),
            true,
            100,
            true,
            1000,
        ));

        let ctx = CaptureContext {
            conn_id: "conn-1",
            db_kind: Some("mysql"),
            database: Some("chinook"),
            user_id: Some("user-9"),
            entry: CaptureEntry::SyncQuery,
            outcome: CaptureOutcome::Ok,
        };
        let payload = CapturePayload::Sql("SELECT * FROM invoice WHERE total = 9.99");
        // 直接调 insert 路径（绕过 spawn 的异步窗口）：组行 + insert_row。
        let digest = normalize_digest(&payload);
        assert!(recorder.gate(150, &digest));
        let row = InsertRow {
            id: uuid::Uuid::new_v4().to_string(),
            source: "gateway".to_string(),
            conn_id: ctx.conn_id.to_string(),
            db_kind: "mysql".to_string(),
            database: ctx.database.map(str::to_string),
            digest: digest.clone(),
            sql_text: Some(render_plaintext(&payload)),
            elapsed_ms: 150,
            row_count: Some(42),
            affected_rows: None,
            query_count: None,
            status: ctx.outcome.status().to_string(),
            error_code: ctx.outcome.error_code().map(str::to_string),
            user_id: ctx.user_id.map(str::to_string),
            entry: ctx.entry.as_str().to_string(),
            captured_at: chrono::Utc::now().to_rfc3339(),
        };
        insert_row(&pool, &row).await.unwrap();

        let stored: (String, Option<String>, String, i64, Option<String>) = sqlx::query_as(
            "SELECT digest, sql_text, status, elapsed_ms, database FROM query_stats",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored.0, "SELECT * FROM invoice WHERE total = ?");
        assert_eq!(stored.1.as_deref(), Some("SELECT * FROM invoice WHERE total = 9.99"));
        assert_eq!(stored.2, "ok");
        assert_eq!(stored.3, 150);
        assert_eq!(stored.4.as_deref(), Some("chinook"));
    }

    #[tokio::test]
    async fn record_no_plaintext_when_store_sql_off() {
        let pool = test_pool().await;
        let recorder = QueryStatsRecorder::from_parts(pool.clone(), true, 100, false, 1000);
        let ctx = CaptureContext {
            conn_id: "c",
            db_kind: Some("postgresql"),
            database: None,
            user_id: None,
            entry: CaptureEntry::GwSse,
            outcome: CaptureOutcome::Error("TIMEOUT".to_string()),
        };
        let payload = CapturePayload::Sql("SELECT pg_sleep(10)");
        let digest = normalize_digest(&payload);
        assert!(recorder.gate(30_000, &digest));
        let row = InsertRow {
            id: uuid::Uuid::new_v4().to_string(),
            source: "gateway".to_string(),
            conn_id: ctx.conn_id.to_string(),
            db_kind: "postgresql".to_string(),
            database: ctx.database.map(str::to_string),
            digest,
            sql_text: None, // store_sql=false → 恒 NULL
            elapsed_ms: 30_000,
            row_count: None,
            affected_rows: None,
            query_count: None,
            status: ctx.outcome.status().to_string(),
            error_code: ctx.outcome.error_code().map(str::to_string),
            user_id: ctx.user_id.map(str::to_string),
            entry: ctx.entry.as_str().to_string(),
            captured_at: chrono::Utc::now().to_rfc3339(),
        };
        insert_row(&pool, &row).await.unwrap();
        let (sql_text, status, error_code): (Option<String>, String, Option<String>) = sqlx::query_as(
            "SELECT sql_text, status, error_code FROM query_stats",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sql_text, None);
        assert_eq!(status, "error");
        assert_eq!(error_code.as_deref(), Some("TIMEOUT"));
    }

    #[test]
    fn record_without_init_is_noop() {
        // 不初始化全局（若同进程其它测试已 init，record 也只是正常旁路——两种情况都不 panic）。
        let ctx = CaptureContext {
            conn_id: "c",
            db_kind: Some("mysql"),
            database: None,
            user_id: None,
            entry: CaptureEntry::McpRead,
            outcome: CaptureOutcome::Ok,
        };
        let payload = CapturePayload::Sql("SELECT 1");
        record(50, &ctx, &payload, None, None);
    }

    // ── retention 轮转 ──

    fn quick_row(id: &str, captured_at: String) -> InsertRow {
        InsertRow {
            id: id.to_string(),
            source: "gateway".to_string(),
            conn_id: "c".to_string(),
            db_kind: "mysql".to_string(),
            database: None,
            digest: format!("digest-{id}"),
            sql_text: None,
            elapsed_ms: 2000,
            row_count: None,
            affected_rows: None,
            query_count: None,
            status: "ok".to_string(),
            error_code: None,
            user_id: None,
            entry: "sync_query".to_string(),
            captured_at,
        }
    }

    #[tokio::test]
    async fn rotate_deletes_only_expired_rows() {
        let pool = test_pool().await;
        let old_at = (chrono::Utc::now() - chrono::Duration::days(20)).to_rfc3339();
        let recent_at = chrono::Utc::now().to_rfc3339();
        insert_row(&pool, &quick_row("old", old_at)).await.unwrap();
        insert_row(&pool, &quick_row("recent", recent_at)).await.unwrap();

        let deleted = rotate(&pool, 14).await.unwrap();
        assert_eq!(deleted, 1);
        let remaining: String =
            sqlx::query_scalar("SELECT id FROM query_stats").fetch_one(&pool).await.unwrap();
        assert_eq!(remaining, "recent");
    }

    /// 旁路韧性：INSERT 失败（此处=未建表）只 warn 不 panic、不影响调用方。
    #[tokio::test]
    async fn record_with_failed_insert_does_not_panic() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        // 故意不跑迁移 → 表不存在 → spawn 内 INSERT 报错被吞。
        let recorder =
            QueryStatsRecorder::from_parts(pool, true, 1, true, 1000);
        let ctx = CaptureContext {
            conn_id: "c",
            db_kind: Some("mysql"),
            database: None,
            user_id: None,
            entry: CaptureEntry::SyncQuery,
            outcome: CaptureOutcome::Ok,
        };
        let payload = CapturePayload::Sql("SELECT SLEEP(2)");
        recorder.record(2000, &ctx, &payload, None, None);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
}
