//! MCP read_query 执行后端（dbx-response T07 / ADR-0005 §2.2）。
//!
//! 与 `metadata.rs` 同层：DB 能力来自 db_handler 的既有 `DbBackend` 执行
//! 路径（网关 API 同源，本模块不重写驱动逻辑）。mcp crate 的 read_query
//! 工具在协议层做完 SELECT-only 风险门（risk.rs）后把单条 SQL 交给这里。
//!
//! **statement_timeout**：tokio 墙钟超时包住整个执行（连接池是每次调用
//! 新开的 `max_connections(1)`，超时 drop 即断连，MySQL/PG 服务端随连接
//! 终止查询；引擎原生 max_execution_time/statement_timeout 留给 M7 薄
//! 适配统一收口）。超时错误不含 SQL/host 明文。
//!
//! **行限**：调用方传入（默认 500，钳到 Config 上限）；`execute_query`
//! 原生支持 limit 截断，本层补 `rowCount` / `truncated` 语义。
//!
//! 错误纪律：`ReadQueryError.message` 不含 host/凭据；执行错误经
//! db_handler 的 redact 后透传（错误码保形）。

use std::time::{Duration, Instant};

use serde_json::Value;
use sqlx::SqlitePool;

use crate::db_handler::backend_for;
use crate::metadata::load_connection;
use dbmaster_core::server::CredentialKey;

/// read_query 执行错误。`code` 稳定（工具层透传给 agent）。
#[derive(Debug)]
pub struct ReadQueryError {
    pub code: String,
    pub message: String,
}

impl ReadQueryError {
    fn from_metadata(e: crate::metadata::MetadataError) -> Self {
        Self { code: e.code.to_string(), message: e.message }
    }

    /// db_handler 的 HTTP 错误元组 → 平面错误（message 已 redact）。
    fn from_http(status: axum::http::StatusCode, body: axum::Json<Value>) -> Self {
        let code = body
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("QUERY_FAILED")
            .to_string();
        let message = body
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("query execution failed")
            .to_string();
        // status 不进 message（对 agent 无用）；保留原 code 便于排障。
        let _ = status;
        Self { code, message }
    }
}

/// 执行单条已通过风险门的只读 SQL。
///
/// 返回 `{columns, columnTypes, rows, rowCount, truncated, executionTimeMs}`。
/// `truncated = rowCount == row_limit`（引擎截断的保守判据：恰好等于上限
/// 即可能还有更多行；limit=0 由调用方钳制，不会出现）。
pub async fn run_read_query(
    server_pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
    db: Option<&str>,
    sql: &str,
    row_limit: usize,
    timeout: Duration,
) -> Result<Value, ReadQueryError> {
    let (conn, _family, password) =
        load_connection(server_pool, key, conn_id).await.map_err(ReadQueryError::from_metadata)?;
    let backend = backend_for(&conn.db_type).map_err(|(status, body)| {
        ReadQueryError::from_http(status, body)
    })?;
    let db_name = db.or(conn.default_database.as_deref());
    // 防御：0 行上限会把 truncated 判据退化成永真。
    let row_limit = row_limit.max(1);

    let started = Instant::now();
    // is_select=true：execute_query 的 SELECT 分支（fetch_all + 行限截断）。
    let result = tokio::time::timeout(
        timeout,
        backend.execute_query(&conn, &password, db_name, sql, row_limit, true),
    )
    .await
    .map_err(|_| {
        // reports-M1（#29）— 超时即慢查询的定义本身，采样 TIMEOUT 终态
        // （elapsed = 超时上限）。
        crate::query_stats::record(
            timeout.as_millis() as u64,
            &crate::query_stats::CaptureContext {
                conn_id,
                db_kind: Some(&conn.db_type),
                database: db_name,
                user_id: None,
                entry: crate::query_stats::CaptureEntry::McpRead,
                outcome: crate::query_stats::CaptureOutcome::Error("TIMEOUT".to_string()),
            },
            &crate::query_stats::CapturePayload::Sql(sql),
            None,
            None,
        );
        ReadQueryError {
            code: "TIMEOUT".to_string(),
            message: format!(
                "statement exceeded the {}s server-side timeout and was cancelled",
                timeout.as_secs()
            ),
        }
    })?
    .map_err(|(status, body)| ReadQueryError::from_http(status, body))?;

    let row_count = result
        .get("rows")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    // reports-M1（#29）— 慢查询旁路采样（成功路径）。
    crate::query_stats::record(
        elapsed_ms,
        &crate::query_stats::CaptureContext {
            conn_id,
            db_kind: Some(&conn.db_type),
            database: db_name,
            user_id: None,
            entry: crate::query_stats::CaptureEntry::McpRead,
            outcome: crate::query_stats::CaptureOutcome::Ok,
        },
        &crate::query_stats::CapturePayload::Sql(sql),
        Some(row_count as u64),
        None,
    );
    let mut out = serde_json::json!({
        "rowCount": row_count,
        // 恰好打满上限即标记截断（宁可多标不漏标，agent 自会翻页/收紧）。
        "truncated": row_count >= row_limit,
        "executionTimeMs": elapsed_ms,
    });
    if let (Some(dst), Some(src)) = (out.as_object_mut(), result.as_object()) {
        for field in ["columns", "columnTypes", "rows"] {
            if let Some(v) = src.get(field) {
                dst.insert(field.to_string(), v.clone());
            }
        }
    }
    Ok(out)
}
