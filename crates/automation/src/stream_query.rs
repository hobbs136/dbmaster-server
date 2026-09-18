//! 网关 API v1 流式查询执行后端（dbx-response T27 / ADR-0005 §2.2）。
//!
//! 与 `metadata.rs` / `read_query.rs` 同层：DB 能力复用 db_handler 的
//! open_* 连接生命周期与 decode_cell_* 解码链，本模块只换执行形态——
//! **逐行流式**（sqlx `fetch` 增量消费）而非 fetch_all，输出**位置数组行**
//! （`[[v,v],…]`，网关 SSE chunk 契约，c01_port_contract §4.2），与既有
//! REST 网关的列名 map 行形态刻意不同。
//!
//! **执行语义（T07 已验证口径的流式版）**：
//! - 每次执行开 `max_connections(1)` 专用池——行限截断/取消/超时统一以
//!   drop 池收尾（断连即终止服务端查询，MySQL/PG 随连接死亡）；
//! - `row_limit` 行限：流式计数，打满即停（`truncated = row_count >= limit`
//!   保守判据，同 read_query.rs）；
//! - `timeout` 墙钟：deadline 覆盖连接 + 执行两阶段（select! 分支）；
//! - `cancel`：外部 CancellationToken（DELETE /executions/{id}）——发送
//!   背压也经 select! 的 `reserve()` 分支，取消在「客户端停止消费」时
//!   依然立即可达（#30 语义锚点：取消必须终止服务端执行）；
//! - 非查询语句（DDL/DML，按 db_handler 同款前缀判据）走 `execute()`，
//!   返回 `affected_rows`，无行事件。
//!
//! 错误纪律：`StreamQueryError.message` 连接失败固定文案（无 host/DNS），
//! 执行错误为截断后的引擎文本（与 read_query 透传口径一致）；`engine_code`
//! 透传引擎原始码（sqlx DatabaseError::code()：PG SQLSTATE / SQLite 扩展码…）。

use std::time::Duration;

use futures::StreamExt;
use serde_json::Value;
use sqlx::{Column, Row, SqlitePool};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::db_handler::{
    decode_cell_mysql, decode_cell_pg, decode_cell_sqlite, is_select_statement, is_show_statement,
    open_mysql_db,
    open_pg_db, open_sqlite,
};
use crate::metadata::{load_connection, Family};
use crate::sqlserver::{map_tds_row, open_sqlserver, tiberius_engine_code};
use dbmaster_core::server::CredentialKey;

/// 每个 rows 事件装载的行数（批大小）。500 行/批在 SSE 帧大小与事件数
/// 之间取中——与缺省行限同量级，结果集 ≤500 行时恰好一批。
const BATCH_SIZE: usize = 500;

/// 流式执行错误。`code` 稳定（网关 wire 错误码，c01_port_contract §4.4），
/// `engine_code` 为引擎原始码透传（可无）。
#[derive(Clone, Debug)]
pub struct StreamQueryError {
    pub code: String,
    pub message: String,
    pub engine_code: Option<String>,
}

/// 执行通道统一返回类型（T29 非 SQL 批次——网关层 sql/mongo 双通道经
/// Trait Object 分发需要具名）。
pub type StreamResult = Result<CompleteInfo, StreamQueryError>;

impl StreamQueryError {
    fn cancelled() -> Self {
        Self {
            code: "CANCELLED".to_string(),
            message: "execution cancelled by client".to_string(),
            engine_code: None,
        }
    }

    fn timeout(timeout_secs: u64) -> Self {
        Self {
            code: "TIMEOUT".to_string(),
            message: format!(
                "statement exceeded the {timeout_secs}s server-side timeout and was cancelled"
            ),
            engine_code: None,
        }
    }

    /// 连接阶段失败——不回传引擎细节（可能含 host/DNS）。契约码
    /// CONNECTION_FAILED（metadata.rs 内部叫 CONNECT_FAILED，此处归一）。
    fn connect_failed() -> Self {
        Self {
            code: "CONNECTION_FAILED".to_string(),
            message: "database connection failed".to_string(),
            engine_code: None,
        }
    }

    /// 执行阶段失败——引擎文本截断透传 + 引擎码。
    fn from_sqlx(e: sqlx::Error) -> Self {
        let engine_code = match &e {
            sqlx::Error::Database(db) => db.code().map(|c| c.to_string()),
            _ => None,
        };
        Self {
            code: "DB_ERROR".to_string(),
            message: e.to_string().chars().take(200).collect(),
            engine_code,
        }
    }

    /// T28 — tiberius 执行失败（同 from_sqlx 口径：引擎文本截断 + TDS 错误号）。
    fn from_tiberius(e: tiberius::error::Error) -> Self {
        Self {
            code: "DB_ERROR".to_string(),
            message: e.to_string().chars().take(200).collect(),
            engine_code: tiberius_engine_code(&e),
        }
    }

    /// T29 非 SQL 批次（B1）— MongoDB 执行失败。连接级（连接池被清/IO/
    /// 认证/选服失败）归 CONNECTION_FAILED 固定文案；命令错误截断引擎文本
    /// + codeName（Unauthorized/NamespaceNotFound/…）透传。
    fn from_mongo(e: mongodb::error::Error) -> Self {
        if crate::mongo::is_connection_level_error(&e) {
            return Self::connect_failed();
        }
        Self {
            code: "DB_ERROR".to_string(),
            message: e.to_string().chars().take(200).collect(),
            engine_code: crate::mongo::engine_code(&e),
        }
    }

    /// T29 非 SQL 批次（B3）— Redis 执行失败。服务端响应错误（WRONGTYPE 等）
    /// 带 code → DB_ERROR + engineCode；IO/认证/超时（无 code）归
    /// CONNECTION_FAILED（对齐 redis_leg::is_connection_level_error）。
    fn from_redis(e: redis::RedisError) -> Self {
        if crate::redis_leg::is_connection_level_error(&e) {
            return Self::connect_failed();
        }
        Self {
            code: "DB_ERROR".to_string(),
            message: e.to_string().chars().take(200).collect(),
            engine_code: e.code().map(str::to_string),
        }
    }
}

/// 终态信息（SSE complete 事件载荷，由网关层封装）。
#[derive(Clone, Debug)]
pub struct CompleteInfo {
    pub row_count: u64,
    pub truncated: bool,
    pub affected_rows: Option<u64>,
}

/// 流式执行的单个事件。meta/rows 是数据事件；Complete/Error 是终止事件
/// （同通道保序——终止事件永远最后到达），返回值 `Result` 与终态事件
/// 携带同一信息、仅供调用方审计。
#[derive(Debug)]
pub enum StreamQueryEvent {
    Meta { columns: Vec<String>, column_types: Option<Vec<String>> },
    Rows { rows: Vec<Vec<Value>> },
    Complete { info: CompleteInfo, elapsed_ms: u64 },
    Error(StreamQueryError),
}

/// 流式执行单条 SQL。
///
/// 全部事件（meta/rows/complete/error）经 `tx` 推送——同通道 FIFO 保证
/// 终止事件最后到达；返回值与终态事件同信息，仅供调用方审计。发送失败
/// （客户端断开）不视为错误——本函数静默行进到终止（取消/超时/行限语义
/// 保持可观察）。
#[allow(clippy::too_many_arguments)]
pub async fn run_stream_query(
    server_pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    sql: &str,
    row_limit: usize,
    timeout: Duration,
    cancel: CancellationToken,
    tx: mpsc::Sender<StreamQueryEvent>,
) -> Result<CompleteInfo, StreamQueryError> {
    let started = std::time::Instant::now();
    let outcome = run_inner(
        server_pool, key, conn_id, db, sql, row_limit, timeout, cancel, &tx,
    )
    .await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    // reports-M1（#29）— 慢查询旁路采样（判定全内存；未初始化 no-op）。
    crate::query_stats::record_stream(
        elapsed_ms,
        conn_id,
        db,
        &crate::query_stats::CapturePayload::Sql(sql),
        &outcome,
    );
    let terminal = match &outcome {
        Ok(info) => StreamQueryEvent::Complete { info: info.clone(), elapsed_ms },
        Err(e) => StreamQueryEvent::Error(e.clone()),
    };
    send_terminal(&tx, terminal).await;
    outcome
}

/// 终止事件交付：reserve 等容量（客户端慢消费时排队），客户端断开
/// （Err）即放弃——终止事件本来就没人收。
async fn send_terminal(tx: &mpsc::Sender<StreamQueryEvent>, ev: StreamQueryEvent) {
    if let Ok(permit) = tx.reserve().await {
        permit.send(ev);
    }
}

// ── kind:"mongo" 执行腿（T29 非 SQL 批次 B1，ADR-0006 §2.4）──
//
// runCommand 单形状：请求 command 为 JSON 对象（首键 = 命令名，键序经
// serde_json preserve_order 保真）。执行形态三分：
// - 写命令（静态集 + aggregate $out/$merge）→ affectedRows 通道（响应
//   "n" 计数；read_only 连接上先拒，engineCode=READONLY）；
// - 游标命令（find/aggregate/listCollections/listIndexes…——以响应是否
//   携带 cursor.firstBatch 判定，不靠命令名白名单）→ 文档流经 stream_rows
//   （每文档一行、单列 "doc"；getMore 由 mongo::cursor_stream 手工驱动）；
// - 其余命令 → 单文档单列 "result" + rowCount 1。
#[allow(clippy::too_many_arguments)]
pub async fn run_stream_mongo(
    server_pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    command: &Value,
    row_limit: usize,
    timeout: Duration,
    cancel: CancellationToken,
    tx: mpsc::Sender<StreamQueryEvent>,
) -> Result<CompleteInfo, StreamQueryError> {
    let started = std::time::Instant::now();
    let outcome = run_mongo_inner(server_pool, key, conn_id, db, command, row_limit, timeout, &cancel, &tx).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    // reports-M1（#29）— 慢查询旁路采样。
    crate::query_stats::record_stream(
        elapsed_ms,
        conn_id,
        db,
        &crate::query_stats::CapturePayload::Mongo(command),
        &outcome,
    );
    let terminal = match &outcome {
        Ok(info) => StreamQueryEvent::Complete { info: info.clone(), elapsed_ms },
        Err(e) => StreamQueryEvent::Error(e.clone()),
    };
    send_terminal(&tx, terminal).await;
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn run_mongo_inner(
    server_pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    command: &Value,
    row_limit: usize,
    timeout: Duration,
    cancel: &CancellationToken,
    tx: &mpsc::Sender<StreamQueryEvent>,
) -> Result<CompleteInfo, StreamQueryError> {
    use mongodb::bson::doc;

    let (conn, family, password) = load_connection(server_pool, key, conn_id)
        .await
        .map_err(|e| StreamQueryError {
            code: normalize_meta_code(e.code),
            message: e.message,
            engine_code: None,
        })?;
    if !matches!(family, Family::Mongo) {
        return Err(StreamQueryError {
            code: "UNSUPPORTED_KIND".to_string(),
            message: format!(
                "connection db_type '{}' does not accept kind \"mongo\" commands",
                conn.db_type
            ),
            engine_code: None,
        });
    }

    // 命令文档（首键 = 命令名，键序保真）+ 只读硬执行。
    let command_doc = crate::mongo::json_to_command_doc(command).map_err(|m| StreamQueryError {
        code: "DB_ERROR".to_string(),
        message: m,
        engine_code: None,
    })?;
    let Some(command_name) = crate::mongo::command_name_of(&command_doc) else {
        return Err(StreamQueryError {
            code: "DB_ERROR".to_string(),
            message: "command object must have at least one key".to_string(),
            engine_code: None,
        });
    };
    if conn.read_only != 0 && crate::mongo::is_write_command(&command_name, &command_doc) {
        return Err(StreamQueryError {
            code: "DB_ERROR".to_string(),
            message: "connection is read-only: write command rejected".to_string(),
            engine_code: Some("READONLY".to_string()),
        });
    }

    let row_limit = row_limit.max(1);
    let deadline = tokio::time::Instant::now() + timeout;
    let timeout_secs = timeout.as_secs();

    // 连接阶段（open + ping）纳入 deadline；ping 把 auth/网络问题归一到
    // CONNECTION_FAILED（对齐 sqlx 池连接语义——SQL 族的 auth 失败也是
    // 连接失败）。
    let client = tokio::time::timeout_at(deadline, crate::mongo::open_mongo(&conn, &password))
        .await
        .map_err(|_| StreamQueryError::timeout(timeout_secs))?
        .map_err(|_| StreamQueryError::connect_failed())?;
    let database = client.database(crate::mongo::resolve_db(&conn, db));
    tokio::time::timeout_at(deadline, database.run_command(doc! {"ping": 1}))
        .await
        .map_err(|_| StreamQueryError::timeout(timeout_secs))?
        .map_err(|_| StreamQueryError::connect_failed())?;

    if crate::mongo::is_write_command(&command_name, &command_doc) {
        // 写命令：affectedRows 通道（insert/update/delete 的响应 "n"；
        // findAndModify 等无 n → 0）。
        guard_execute(
            async {
                database
                    .run_command(command_doc)
                    .await
                    // "n" 实机 Int32（doc_count 解码链；findAndModify 等无 n → 0）。
                    .map(|resp| crate::mongo::doc_count(&resp, "n").unwrap_or(0).max(0) as u64)
            },
            StreamQueryError::from_mongo,
            deadline,
            timeout_secs,
            cancel,
        )
        .await
    } else {
        let resp = tokio::time::timeout_at(deadline, database.run_command(command_doc))
            .await
            .map_err(|_| StreamQueryError::timeout(timeout_secs))?
            .map_err(StreamQueryError::from_mongo)?;
        match crate::mongo::cursor_first_batch(&resp) {
            Some((batch, cursor_id, ns)) => {
                let doc_stream = crate::mongo::cursor_stream(database, batch, cursor_id, &ns);
                stream_rows(
                    Box::pin(doc_stream).map(|item| {
                        item.map(|doc| {
                            (
                                vec!["doc".to_string()],
                                vec![crate::mongo::document_to_json(doc)],
                                None,
                            )
                        })
                        .map_err(StreamQueryError::from_mongo)
                    }),
                    row_limit,
                    deadline,
                    timeout_secs,
                    cancel,
                    tx,
                )
                .await
            }
            None => {
                // 非游标命令：单文档单列（count → {n,...}、buildInfo →
                // {version,...} 等），rowCount 1。发送包在 select 内（对齐
                // stream_rows 冲刷纪律——慢客户端 + 取消/超时并发可中断）。
                let json = crate::mongo::document_to_json(resp);
                let flush = async {
                    let _ = tx
                        .send(StreamQueryEvent::Meta {
                            columns: vec!["result".to_string()],
                            column_types: None,
                        })
                        .await;
                    let _ = tx.send(StreamQueryEvent::Rows { rows: vec![vec![json]] }).await;
                };
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Err(StreamQueryError::cancelled()),
                    _ = tokio::time::sleep_until(deadline) => {
                        return Err(StreamQueryError::timeout(timeout_secs))
                    }
                    _ = flush => {},
                }
                Ok(CompleteInfo { row_count: 1, truncated: false, affected_rows: None })
            }
        }
    }
}

// ── kind:"redis" 执行腿（T29 非 SQL 批次 B3，ADR-0006 §2.3）──
//
// 请求二选一：`command`（单命令参数数组）或 `pipeline`（命令数组批量；
// `atomic` = server 侧 MULTI/EXEC 包裹，redis-rs pipe.atomic 处理
// QUEUED 校验；WATCH/UNWATCH fail-loud 不做——跨请求连接亲和，对齐 SQL
// 族事务先例）。只读硬执行：read_only 连接拒 Write 与 Unknown（未知保守
// 判写，分类 = 静态表 + ACL CAT 缓存）。行映射：白名单结构化命令给语义
// 列，其余单列 result；RESP error → error 事件（engineCode = WRONGTYPE 等）。
#[allow(clippy::too_many_arguments)]
pub async fn run_stream_redis(
    server_pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    command: Option<&[String]>,
    pipeline: Option<&[Vec<String>]>,
    atomic: bool,
    row_limit: usize,
    timeout: Duration,
    cancel: CancellationToken,
    tx: mpsc::Sender<StreamQueryEvent>,
) -> Result<CompleteInfo, StreamQueryError> {
    let started = std::time::Instant::now();
    let outcome = run_redis_inner(
        server_pool, key, conn_id, db, command, pipeline, atomic,
        row_limit, timeout, &cancel, &tx,
    )
    .await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    // reports-M1（#29）— 慢查询旁路采样（command / pipeline 二选一）。
    if let Some(payload) = command
        .map(crate::query_stats::CapturePayload::Redis)
        .or_else(|| pipeline.map(crate::query_stats::CapturePayload::RedisPipeline))
    {
        crate::query_stats::record_stream(elapsed_ms, conn_id, db, &payload, &outcome);
    }
    let terminal = match &outcome {
        Ok(info) => StreamQueryEvent::Complete { info: info.clone(), elapsed_ms },
        Err(e) => StreamQueryEvent::Error(e.clone()),
    };
    send_terminal(&tx, terminal).await;
    outcome
}

/// read_only 硬执行：任一命令分类非 Read 即拒（engineCode=READONLY）。
async fn redis_guard_read_only(
    conn_id: &str,
    conn: &mut redis::aio::MultiplexedConnection,
    names: impl Iterator<Item = &str>,
) -> Result<(), StreamQueryError> {
    for name in names {
        let class = crate::redis_leg::classify(conn_id, conn, name).await;
        if class != crate::redis_leg::RedisCommandClass::Read {
            return Err(StreamQueryError {
                code: "DB_ERROR".to_string(),
                message: "connection is read-only: write command rejected".to_string(),
                engine_code: Some("READONLY".to_string()),
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_redis_inner(
    server_pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    command: Option<&[String]>,
    pipeline: Option<&[Vec<String>]>,
    atomic: bool,
    row_limit: usize,
    timeout: Duration,
    cancel: &CancellationToken,
    tx: &mpsc::Sender<StreamQueryEvent>,
) -> Result<CompleteInfo, StreamQueryError> {
    let (conn, family, password) = load_connection(server_pool, key, conn_id)
        .await
        .map_err(|e| StreamQueryError {
            code: normalize_meta_code(e.code),
            message: e.message,
            engine_code: None,
        })?;
    if !matches!(family, Family::Redis) {
        return Err(StreamQueryError {
            code: "UNSUPPORTED_KIND".to_string(),
            message: format!(
                "connection db_type '{}' does not accept kind \"redis\" commands",
                conn.db_type
            ),
            engine_code: None,
        });
    }

    let row_limit = row_limit.max(1);
    let deadline = tokio::time::Instant::now() + timeout;
    let timeout_secs = timeout.as_secs();

    // 每执行独立连接（drop 即取消在途命令）；AUTH/SELECT 在连接建立时完成。
    let mut handle = tokio::time::timeout_at(
        deadline,
        crate::redis_leg::open_redis(&conn, &password, crate::redis_leg::db_index(&conn, db)),
    )
    .await
    .map_err(|_| StreamQueryError::timeout(timeout_secs))?
    .map_err(StreamQueryError::from_redis)?;

    let (columns, raw_rows) = if let Some(command) = command {
        let name = command
            .first()
            .ok_or_else(|| StreamQueryError {
                code: "DB_ERROR".to_string(),
                message: "command array must be non-empty".to_string(),
                engine_code: None,
            })?
            .as_str();
        // 只读硬执行（分类经 ACL CAT 缓存；Write 与 Unknown 均拒——未知
        // 保守判写，ADR-0006 §2.3）。
        if conn.read_only != 0 {
            let class = crate::redis_leg::classify(conn_id, &mut handle, name).await;
            if class != crate::redis_leg::RedisCommandClass::Read {
                return Err(StreamQueryError {
                    code: "DB_ERROR".to_string(),
                    message: "connection is read-only: write command rejected".to_string(),
                    engine_code: Some("READONLY".to_string()),
                });
            }
        }
        let mut cmd = redis::cmd(name);
        for arg in &command[1..] {
            cmd.arg(arg);
        }
        let resp = tokio::time::timeout_at(deadline, cmd.query_async::<redis::Value>(&mut handle))
            .await
            .map_err(|_| StreamQueryError::timeout(timeout_secs))?
            .map_err(StreamQueryError::from_redis)?;
        match crate::redis_leg::semantic_rows(name, &command[1..], &resp) {
            Some((cols, rows)) => (cols, rows),
            None => (
                vec!["result".to_string()],
                vec![crate::redis_leg::fallback_row(&resp)],
            ),
        }
    } else if let Some(pipeline) = pipeline {
        // pipeline 批量：单连接顺序执行；atomic = MULTI/EXEC 包裹。
        if conn.read_only != 0 {
            redis_guard_read_only(
                conn_id,
                &mut handle,
                pipeline.iter().filter_map(|c| c.first().map(String::as_str)),
            )
            .await?;
        }
        let mut pipe = redis::pipe();
        if atomic {
            pipe.atomic();
        }
        for cmd in pipeline {
            let Some(name) = cmd.first() else {
                return Err(StreamQueryError {
                    code: "DB_ERROR".to_string(),
                    message: "pipeline entry must be a non-empty command array".to_string(),
                    engine_code: None,
                });
            };
            let mut entry = pipe.cmd(name);
            for arg in &cmd[1..] {
                entry = entry.arg(arg);
            }
        }
        let results: Vec<redis::Value> =
            tokio::time::timeout_at(deadline, pipe.query_async(&mut handle))
                .await
                .map_err(|_| StreamQueryError::timeout(timeout_secs))?
                .map_err(StreamQueryError::from_redis)?;
        let rows = results
            .iter()
            .enumerate()
            .map(|(i, v)| {
                vec![
                    serde_json::Value::Number((i as u64).into()),
                    crate::redis_leg::resp_to_json(v.clone()),
                ]
            })
            .collect::<Vec<_>>();
        (
            vec!["index".to_string(), "result".to_string()],
            rows,
        )
    } else {
        return Err(StreamQueryError {
            code: "DB_ERROR".to_string(),
            message: "kind \"redis\" requires a command or pipeline".to_string(),
            engine_code: None,
        });
    };

    // 行限截断（保守判据）+ 事件发射（meta → 分批 rows；select 包裹对齐
    // 冲刷纪律——慢客户端 + 取消/超时并发可中断）。
    let total = raw_rows.len();
    let truncated = total >= row_limit;
    let rows: Vec<Vec<Value>> = raw_rows.into_iter().take(row_limit).collect();
    let row_count = rows.len() as u64;

    let flush = async {
        let _ = tx
            .send(StreamQueryEvent::Meta { columns, column_types: None })
            .await;
        for chunk in rows.chunks(BATCH_SIZE) {
            let _ = tx
                .send(StreamQueryEvent::Rows { rows: chunk.to_vec() })
                .await;
        }
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(StreamQueryError::cancelled()),
        _ = tokio::time::sleep_until(deadline) => {
            return Err(StreamQueryError::timeout(timeout_secs))
        }
        _ = flush => {},
    }
    Ok(CompleteInfo { row_count, truncated, affected_rows: None })
}

// ── kind:"tdengine" 执行腿（T29 TDengine 批次）──
//
// 通道 = taosAdapter REST（无状态）：SQL 原文 + URL 路径 db 路由 + Basic
// auth（tdengine_leg::exec_sql）。写（DML+DDL 同形——单列 affected_rows）
// 走 affectedRows 通道；查询 column_meta 含**原生类型名**（TIMESTAMP/
// BINARY…）→ meta 事件 columnTypes 保真（CH 批次经 MySQL 口的已知缺口在
// TD 不存在）。只读硬执行：静态首词分类拒写（engineCode=READONLY）。
// 错误归一：传输/认证 → CONNECTION_FAILED；TD code≠0 → DB_ERROR +
// engineCode；HTTP 其它 → DB_ERROR。
#[allow(clippy::too_many_arguments)]
pub async fn run_stream_tdengine(
    server_pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    sql: &str,
    row_limit: usize,
    timeout: Duration,
    cancel: CancellationToken,
    tx: mpsc::Sender<StreamQueryEvent>,
) -> Result<CompleteInfo, StreamQueryError> {
    let started = std::time::Instant::now();
    let outcome =
        run_tdengine_inner(server_pool, key, conn_id, db, sql, row_limit, timeout, &cancel, &tx)
            .await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    // reports-M1（#29）— 慢查询旁路采样。
    crate::query_stats::record_stream(
        elapsed_ms,
        conn_id,
        db,
        &crate::query_stats::CapturePayload::Sql(sql),
        &outcome,
    );
    let terminal = match &outcome {
        Ok(info) => StreamQueryEvent::Complete { info: info.clone(), elapsed_ms },
        Err(e) => StreamQueryEvent::Error(e.clone()),
    };
    send_terminal(&tx, terminal).await;
    outcome
}

/// TdError → 契约码（传输/认证连接级归一；引擎文本截断 + code 透传）。
fn from_td(e: crate::tdengine_leg::TdError) -> StreamQueryError {
    use crate::tdengine_leg::TdError;
    match e {
        TdError::Transport | TdError::Auth => StreamQueryError::connect_failed(),
        TdError::Http(status, body) => StreamQueryError {
            code: "DB_ERROR".to_string(),
            message: format!("taosAdapter HTTP {status}: {body}"),
            engine_code: None,
        },
        TdError::Engine(code, desc) => StreamQueryError {
            code: "DB_ERROR".to_string(),
            message: desc,
            engine_code: Some(code.to_string()),
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tdengine_inner(
    server_pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    sql: &str,
    row_limit: usize,
    timeout: Duration,
    cancel: &CancellationToken,
    tx: &mpsc::Sender<StreamQueryEvent>,
) -> Result<CompleteInfo, StreamQueryError> {
    let (conn, family, password) = load_connection(server_pool, key, conn_id)
        .await
        .map_err(|e| StreamQueryError {
            code: normalize_meta_code(e.code),
            message: e.message,
            engine_code: None,
        })?;
    if !matches!(family, Family::Tdengine) {
        return Err(StreamQueryError {
            code: "UNSUPPORTED_KIND".to_string(),
            message: format!(
                "connection db_type '{}' does not accept kind \"tdengine\" statements",
                conn.db_type
            ),
            engine_code: None,
        });
    }

    let db_name = db.or(conn.default_database.as_deref());
    let row_limit = row_limit.max(1);
    let deadline = tokio::time::Instant::now() + timeout;
    let timeout_secs = timeout.as_secs();

    let write = crate::tdengine_leg::is_write_statement(sql);
    if conn.read_only != 0 && write {
        return Err(StreamQueryError {
            code: "DB_ERROR".to_string(),
            message: "connection is read-only: write statement rejected".to_string(),
            engine_code: Some("READONLY".to_string()),
        });
    }

    // REST 一次性返回全量结果（无服务端流式）——超时/取消经 select 外包；
    // reqwest 客户端自带 timeout 兜底（两者同 deadline 量级）。
    let fut = crate::tdengine_leg::exec_sql(&conn, &password, db_name, sql, timeout);
    let outcome = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(StreamQueryError::cancelled()),
        _ = tokio::time::sleep_until(deadline) => {
            return Err(StreamQueryError::timeout(timeout_secs))
        }
        r = fut => r.map_err(from_td)?,
    };

    if write {
        // 写通道：INSERT 返回实际行数；DDL（CREATE/DROP/ALTER…）恒 0。
        return Ok(CompleteInfo {
            row_count: 0,
            truncated: false,
            affected_rows: Some(outcome.affected_rows().unwrap_or(0)),
        });
    }

    // 查询：meta（列名 + 原生类型名）→ 行限切片分批 → complete。
    let total = outcome.rows.len();
    let truncated = total > row_limit;
    let mut rows = outcome.rows;
    rows.truncate(row_limit);
    let row_count = rows.len() as u64;
    let columns: Vec<String> = outcome.columns.iter().map(|(n, _)| n.clone()).collect();
    let types: Vec<String> = outcome.columns.iter().map(|(_, t)| t.clone()).collect();

    let flush = async {
        let _ = tx
            .send(StreamQueryEvent::Meta {
                columns,
                column_types: Some(types),
            })
            .await;
        for chunk in rows.chunks(BATCH_SIZE) {
            let _ = tx.send(StreamQueryEvent::Rows { rows: chunk.to_vec() }).await;
        }
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(StreamQueryError::cancelled()),
        _ = tokio::time::sleep_until(deadline) => {
            return Err(StreamQueryError::timeout(timeout_secs))
        }
        _ = flush => {},
    }
    Ok(CompleteInfo { row_count, truncated, affected_rows: None })
}

#[allow(clippy::too_many_arguments)]
async fn run_inner(
    server_pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    sql: &str,
    row_limit: usize,
    timeout: Duration,
    cancel: CancellationToken,
    tx: &mpsc::Sender<StreamQueryEvent>,
) -> Result<CompleteInfo, StreamQueryError> {
    let (conn, family, password) = load_connection(server_pool, key, conn_id)
        .await
        .map_err(|e| StreamQueryError {
            code: normalize_meta_code(e.code),
            message: e.message,
            engine_code: None,
        })?;
    let db_name = db.or(conn.default_database.as_deref());
    // 防御：0 行上限会把 truncated 判据退化成永真（read_query 同款）。
    let row_limit = row_limit.max(1);
    let deadline = tokio::time::Instant::now() + timeout;
    let timeout_secs = timeout.as_secs();

    match family {
        Family::MySql(profile) => {
            let pool = open_mysql_db(&conn, &password, db_name)
                .await
                .map_err(|_| StreamQueryError::connect_failed())?;
            if is_select_statement(sql) {
                // T21 — 执行模式经族 profile（原 doris 特判收敛为 hook）：
                // Doris 的 MySQL 口不吃 PREPARE（T06 实机三坑）——raw_sql
                // 文本协议；MySQL 保持 sqlx::query（PREPARE）。
                // T29 — MySQL PREPARE 协议对部分 SHOW 报 1295（实机 SHOW
                // TRIGGERS）；SHOW 结果集全是文本列，文本协议零失真，故
                // SHOW 一律走 raw_sql。
                let raw = profile.catalog_mode()
                    == crate::mysql_family::CatalogQueryMode::RawSql
                    || is_show_statement(sql);
                let stream = if raw {
                    sqlx::raw_sql(sql).fetch(&pool)
                } else {
                    sqlx::query(sql).fetch(&pool)
                };
                stream_rows(
                    stream.map(|item| item.map(map_mysql_row).map_err(StreamQueryError::from_sqlx)),
                    row_limit, deadline, timeout_secs, &cancel, &tx,
                )
                .await
            } else {
                // T21 — 非查询语句同按族执行模式（MySQL prepare / Doris
                // raw_sql），affected_rows 语义不变。
                guard_execute(
                    crate::mysql_family::execute_by_mode(&pool, profile.catalog_mode(), sql),
                    StreamQueryError::from_sqlx,
                    deadline,
                    timeout_secs,
                    &cancel,
                )
                .await
            }
        }
        Family::Postgres => {
            let pool = open_pg_db(&conn, &password, db_name)
                .await
                .map_err(|_| StreamQueryError::connect_failed())?;
            if is_select_statement(sql) {
                stream_rows(
                    sqlx::query(sql).fetch(&pool)
                        .map(|item| item.map(map_pg_row).map_err(StreamQueryError::from_sqlx)),
                    row_limit, deadline, timeout_secs, &cancel, &tx,
                )
                .await
            } else {
                guard_execute(
                    async { sqlx::query(sql).execute(&pool).await.map(|r| r.rows_affected()) },
                    StreamQueryError::from_sqlx,
                    deadline,
                    timeout_secs,
                    &cancel,
                )
                .await
            }
        }
        Family::Sqlite => {
            let pool = open_sqlite(&conn)
                .await
                .map_err(|_| StreamQueryError::connect_failed())?;
            if is_select_statement(sql) {
                stream_rows(
                    sqlx::query(sql).fetch(&pool)
                        .map(|item| item.map(map_sqlite_row).map_err(StreamQueryError::from_sqlx)),
                    row_limit, deadline, timeout_secs, &cancel, &tx,
                )
                .await
            } else {
                guard_execute(
                    async { sqlx::query(sql).execute(&pool).await.map(|r| r.rows_affected()) },
                    StreamQueryError::from_sqlx,
                    deadline,
                    timeout_secs,
                    &cancel,
                )
                .await
            }
        }
        // T29 第三批 — ClickHouse：经 CH 的 MySQL 兼容口（默认 9004）复用
        // sqlx MySQL 驱动，零新依赖（路线 A；HTTP 8123 高保真路线留作后续
        // 增强）。执行协议实机钉定（gw_clickhouse e2e）：CH 的 COM_QUERY
        // 文本协议行解码在 sqlx 下对数值列报 "buffer exhausted"（CH wire
        // 怪癖），而 COM_STMT_PREPARE 二进制协议工作正常——故与既有
        // ClickhouseBackend 同口径走 `sqlx::query`（Prepare 模式，SQL 无
        // `?` 绑定时 CH 可正常执行；客户端侧字面量内联，见 ch_str_literal）。
        // 已知边界：columnTypes 为 MySQL wire 类型名（VAR_STRING/NEWDECIMAL
        // 等），非 CH 原生类型名（String/Decimal(10,2)）——原生名需查
        // system.columns 或走 HTTP 口，不在本批范围。
        Family::Clickhouse => {
            let pool = open_mysql_db(&conn, &password, db_name)
                .await
                .map_err(|_| StreamQueryError::connect_failed())?;
            if is_select_statement(sql) {
                stream_rows(
                    sqlx::query(sql).fetch(&pool)
                        .map(|item| item.map(map_mysql_row).map_err(StreamQueryError::from_sqlx)),
                    row_limit, deadline, timeout_secs, &cancel, &tx,
                )
                .await
            } else {
                guard_execute(
                    async { sqlx::query(sql).execute(&pool).await.map(|r| r.rows_affected()) },
                    StreamQueryError::from_sqlx,
                    deadline,
                    timeout_secs,
                    &cancel,
                )
                .await
            }
        }
        // T28 — SQL Server（tiberius）：每次执行一条专用连接；取消/超时/
        // 行限统一 drop client 断连终止服务端批处理（#30 锚点——SS 经网关
        // 后超时不再「静默成功」，TCP 断开会话即被服务端终止）。
        Family::SqlServer => {
            // 连接阶段也纳入 deadline（对死主机 TCP 连挂的保护；MySQL/PG
            // 族的 connect 在池层有 acquire 超时，这里显式包一层）。
            let mut client = tokio::time::timeout_at(
                deadline,
                open_sqlserver(&conn, &password, db_name),
            )
            .await
            .map_err(|_| StreamQueryError::timeout(timeout_secs))?
            .map_err(|_| StreamQueryError::connect_failed())?;
            if is_select_statement(sql) {
                // 单条语句直发（无参数拼接）；Metadata/Done 条目跳过——
                // 列名取自首行，与 sqlx 路径同口径（空结果 meta 列为空数组）。
                let stream = client
                    .simple_query(sql)
                    .await
                    .map_err(StreamQueryError::from_tiberius)?;
                stream_rows(
                    Box::pin(stream).filter_map(|item| {
                        // ready 包装保持 FilterMap Unpin（async 块的状态机
                        // 含非 Unpin 捕获会破坏 stream_rows 的 Unpin 约束）。
                        futures::future::ready(match item {
                            Ok(tiberius::QueryItem::Row(row)) => Some(Ok(map_tds_row(&row))),
                            Ok(_) => None,
                            Err(e) => Some(Err(StreamQueryError::from_tiberius(e))),
                        })
                    }),
                    row_limit, deadline, timeout_secs, &cancel, &tx,
                )
                .await
            } else {
                // 原生 batch 执行（execute 走 sp_executesql 会拒 CREATE VIEW/
                // PROC 等「模块」语句，见 sqlserver::execute_tds 文档）。
                guard_execute(
                    crate::sqlserver::execute_tds(&mut client, sql),
                    StreamQueryError::from_tiberius,
                    deadline,
                    timeout_secs,
                    &cancel,
                )
                .await
            }
        }
        // T29 非 SQL 批次（B1）— Mongo 连接不走 SQL 通道（语义完全不同）；
        // 此臂只防误配：kind:"sql" + mongodb 连接 = 客户端装配错误，fail-loud。
        Family::Mongo => Err(StreamQueryError {
            code: "UNSUPPORTED_KIND".to_string(),
            message: "mongodb connections require kind \"mongo\" with a command object"
                .to_string(),
            engine_code: None,
        }),
        // T29 非 SQL 批次（B3）— 同上：redis 连接只吃 kind:"redis"。
        Family::Redis => Err(StreamQueryError {
            code: "UNSUPPORTED_KIND".to_string(),
            message: "redis connections require kind \"redis\" with a command or pipeline"
                .to_string(),
            engine_code: None,
        }),
        // T29 TDengine 批次 — TDengine 连接只吃 kind:"tdengine"（SQL 形状
        // 但通道/响应语义独立，经 run_stream_tdengine 的 REST 腿执行）。
        Family::Tdengine => Err(StreamQueryError {
            code: "UNSUPPORTED_KIND".to_string(),
            message: "tdengine connections require kind \"tdengine\" statements"
                .to_string(),
            engine_code: None,
        }),
    }
}

// ── 引擎行归一（sqlx 行 → (列名, 位置数组, 列类型名?)），供泛型消费循环 ──
//
// T29 — 第三元素 = 列类型名（sqlx TypeInfo::name()，如 MySQL JSON /
// PG JSONB），随 meta 事件上抛恢复客户端 columnTypes 语义（T031 JSON
// 列识别的直连时代数据源）；tiberius 路径暂不提供（None）。
type MappedRow = (Vec<String>, Vec<Value>, Option<Vec<String>>);

fn map_mysql_row(row: sqlx::mysql::MySqlRow) -> MappedRow {
    let width = row.columns().len();
    let columns: Vec<String> = row.columns().iter().map(|c| c.name().to_string()).collect();
    let types: Vec<String> = row
        .columns()
        .iter()
        .map(|c| sqlx::TypeInfo::name(c.type_info()).to_string())
        .collect();
    let values = (0..width).map(|i| decode_cell_mysql(&row, i)).collect();
    (columns, values, Some(types))
}

fn map_pg_row(row: sqlx::postgres::PgRow) -> MappedRow {
    let width = row.columns().len();
    let columns: Vec<String> = row.columns().iter().map(|c| c.name().to_string()).collect();
    let types: Vec<String> = row
        .columns()
        .iter()
        .map(|c| sqlx::TypeInfo::name(c.type_info()).to_string())
        .collect();
    let values = (0..width).map(|i| decode_cell_pg(&row, i)).collect();
    (columns, values, Some(types))
}

fn map_sqlite_row(row: sqlx::sqlite::SqliteRow) -> MappedRow {
    let width = row.columns().len();
    let columns = row.columns().iter().map(|c| c.name().to_string()).collect();
    let values = (0..width).map(|i| decode_cell_sqlite(&row, i)).collect();
    (columns, values, None)
}

// ── 通用消费循环 / 非查询执行 ──

/// 消费归一行流：首行前发 meta，逐批（BATCH_SIZE）发 rows，行限打满即停。
///
/// select! 四分支（biased：取消/超时优先于进度）：
/// - `reserve()` 分支带「有待发数据」前置条件——满批等待通道容量即背压，
///   且取消/超时在此期间依然立即可达（send 不会脱离 select 阻塞）；
/// - `stream.next()` 分支带「批未满」前置条件——满批时暂停解码，不无限
///   占内存；
/// - 列名取自首行（sqlx 流式下 0 行结果拿不到列描述，空结果 meta 列为
///   空数组——与既有 REST 网关 fetch_all 空结果语义一致）。
async fn stream_rows<S>(
    mut stream: S,
    row_limit: usize,
    deadline: tokio::time::Instant,
    timeout_secs: u64,
    cancel: &CancellationToken,
    tx: &mpsc::Sender<StreamQueryEvent>,
) -> Result<CompleteInfo, StreamQueryError>
where
    S: futures::Stream<Item = Result<MappedRow, StreamQueryError>> + Unpin,
{
    let mut row_count: u64 = 0;
    let mut truncated = false;
    let mut batch: Vec<Vec<Value>> = Vec::new();
    let mut meta_pending: Option<(Vec<String>, Option<Vec<String>>)> = None;
    let mut stream_done = false;

    while !stream_done {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(StreamQueryError::cancelled()),
            _ = tokio::time::sleep_until(deadline) => return Err(StreamQueryError::timeout(timeout_secs)),
            // 满批（或首个 meta）等待通道容量——客户端消费慢时的背压点。
            res = tx.reserve(), if meta_pending.is_some() || batch.len() >= BATCH_SIZE => {
                if let Ok(permit) = res {
                    if let Some((columns, types)) = meta_pending.take() {
                        permit.send(StreamQueryEvent::Meta { columns, column_types: types });
                    } else {
                        permit.send(StreamQueryEvent::Rows { rows: std::mem::take(&mut batch) });
                    }
                }
                // Err(_) = 客户端断开：静默丢弃缓冲，行进到终止语义。
            }
            item = stream.next(), if batch.len() < BATCH_SIZE => match item {
                Some(Ok((columns, values, types))) => {
                    // 仅首行携带列名（列描述来自行）。不能以 meta_pending
                    // 是否为 None 判首——meta 经 reserve 发送后 pending 归
                    // None，第二行会误再置位（双 meta 实测踩过）。
                    if row_count == 0 {
                        meta_pending = Some((columns, types));
                    }
                    row_count += 1;
                    batch.push(values);
                    if row_count as usize >= row_limit {
                        // 恰好打满上限即可能还有更多行（保守判据，宁可多标）。
                        truncated = true;
                        stream_done = true;
                    }
                }
                Some(Err(e)) => return Err(e),
                None => stream_done = true,
            },
        }
    }

    // 尾批 + meta 兜底。顺序铁律：meta 先于 rows。冲刷同样包在 select 内
    // （通道满时 send 阻塞不能脱离取消/超时监控——慢客户端 + 恰在此时
    // 取消的组合下仍须可中断；被中断时返回已完成语义，丢弃未交付缓冲）。
    let flush = async {
        if let Some((columns, types)) = meta_pending.take() {
            let _ = tx.send(StreamQueryEvent::Meta { columns, column_types: types }).await;
        }
        if !batch.is_empty() {
            let _ = tx.send(StreamQueryEvent::Rows { rows: batch }).await;
        } else if row_count == 0 {
            // 空结果：sqlx 流式拿不到列描述（无行即无 metadata），meta 列为
            // 空数组——与既有 REST 网关 fetch_all 空结果语义一致。
            let _ = tx.send(StreamQueryEvent::Meta { columns: Vec::new(), column_types: None }).await;
        }
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {},
        _ = tokio::time::sleep_until(deadline) => {},
        _ = flush => {},
    }
    Ok(CompleteInfo { row_count, truncated, affected_rows: None })
}

/// 非查询语句（DDL/DML）执行：无行事件，返回 affected_rows。
/// 同样受 deadline/cancel 约束（大 UPDATE 可能跑很久）。错误经 `map_err`
/// 归一（sqlx / tiberius 两个执行族各传各的构造器）。
async fn guard_execute<F, E, M>(
    fut: F,
    map_err: M,
    deadline: tokio::time::Instant,
    timeout_secs: u64,
    cancel: &CancellationToken,
) -> Result<CompleteInfo, StreamQueryError>
where
    F: std::future::Future<Output = Result<u64, E>>,
    M: Fn(E) -> StreamQueryError,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(StreamQueryError::cancelled()),
        _ = tokio::time::sleep_until(deadline) => Err(StreamQueryError::timeout(timeout_secs)),
        r = fut => r.map(|affected| CompleteInfo {
            row_count: 0,
            truncated: false,
            affected_rows: Some(affected),
        }).map_err(map_err),
    }
}

/// metadata 错误码 → 网关契约码归一（CONNECT_FAILED→CONNECTION_FAILED、
/// QUERY_FAILED→DB_ERROR；其余已对齐）。pub：网关层元数据端点复用同一映射。
pub fn normalize_meta_code(code: &str) -> String {
    match code {
        "CONNECT_FAILED" => "CONNECTION_FAILED".to_string(),
        "QUERY_FAILED" => "DB_ERROR".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_code_normalization_matches_contract() {
        assert_eq!(normalize_meta_code("CONNECT_FAILED"), "CONNECTION_FAILED");
        assert_eq!(normalize_meta_code("QUERY_FAILED"), "DB_ERROR");
        assert_eq!(normalize_meta_code("NOT_FOUND"), "NOT_FOUND");
        assert_eq!(normalize_meta_code("UNSUPPORTED_DB_TYPE"), "UNSUPPORTED_DB_TYPE");
    }
}
