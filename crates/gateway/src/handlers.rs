//! `/api/gw/*` handlers（dbx-response T27 / c01_port_contract §4.1）。
//!
//! 元数据三端点是 automation `metadata.rs` 的薄透传（与 MCP 工具同源）；
//! 查询执行把 automation `stream_query.rs` 的事件流封装为 SSE 四事件
//! （meta/rows/complete/error），执行跑在 spawn 任务里——SSE body 只是
//! mpsc 接收端的视图，客户端断开不影响执行语义（取消必须显式经
//! DELETE /executions/{id}，#30 锚点）。

use std::convert::Infallible;
use std::time::{Duration, Instant};

use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    Extension, Json,
};
use dbmaster_automation::db_handler::{test_draft_connection, DraftConnection};
use dbmaster_automation::metadata as meta;
use dbmaster_automation::stream_query::{self, normalize_meta_code, StreamQueryEvent};
use dbmaster_core::auth::jwt::Claims;
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::{log_gw_event, GwAuditAction};
use crate::GwState;

// ── 公共 wire 辅助 ──

/// 网关错误响应统一形状：`{"error":{"code","message"}}`。
fn err_response(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": { "code": code, "message": message } }))).into_response()
}

/// metadata 错误 → 网关 wire（码归一 + HTTP 状态映射）。
fn meta_err(e: meta::MetadataError) -> Response {
    let code = normalize_meta_code(e.code);
    let status = match code.as_str() {
        "NOT_FOUND" => StatusCode::NOT_FOUND,
        "CONFIG_ERROR" | "UNSUPPORTED_DB_TYPE" => StatusCode::BAD_REQUEST,
        "CONNECTION_FAILED" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    err_response(status, &code, &e.message)
}

// ── 元数据三端点（+ 连接列表）──

/// GET /api/gw/connections — 安全投影（id/name/dbType/readOnly/defaultDatabase，
/// 永不回 host/凭据）。与 MCP list_connections 工具同源同形。
pub(crate) async fn list_connections(
    Extension(_claims): Extension<Claims>,
    State(st): State<GwState>,
) -> Response {
    match meta::list_connection_summaries(&st.pool).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => meta_err(e),
    }
}

/// GET /api/gw/connections/{id}/databases — string[]（MCP 同形）。
pub(crate) async fn gw_list_databases(
    Extension(_claims): Extension<Claims>,
    State(st): State<GwState>,
    Path(conn_id): Path<String>,
) -> Response {
    match meta::list_databases(&st.pool, &st.credential_key, &conn_id).await {
        Ok(dbs) => Json(dbs).into_response(),
        Err(e) => meta_err(e),
    }
}

#[derive(Deserialize)]
pub struct TablesQuery {
    pub db: Option<String>,
    /// v1 接受但**仍被忽略**（按 schema 过滤的能力待 v1.1，schema-aware
    /// 随 M7 薄适配）。显式传非空值不影响结果——客户端无需感知。
    ///
    /// 注意（本轮修订）：列表**内容**自 PG 多 schema 修复起已覆盖该库
    /// **全部用户 schema**（不再是 public-only），非 public 对象以
    /// `schema.table` 命名并带 `schema` 字段（见 automation
    /// `metadata::list_tables`）——被忽略的只是这个查询参数，不是 schema
    /// 维度本身。
    pub schema: Option<String>,
}

/// GET /api/gw/connections/{id}/tables?db=&schema= — TableSummary[]。
pub(crate) async fn gw_list_tables(
    Extension(_claims): Extension<Claims>,
    State(st): State<GwState>,
    Path(conn_id): Path<String>,
    Query(q): Query<TablesQuery>,
) -> Response {
    let _ = q.schema; // v1 仍忽略过滤（列表内容已跨 schema；见 TablesQuery 文档）
    match meta::list_tables(&st.pool, &st.credential_key, &conn_id, q.db.as_deref()).await {
        Ok(tables) => Json(tables).into_response(),
        Err(e) => meta_err(e),
    }
}

#[derive(Deserialize)]
pub struct DescribeQuery {
    pub db: Option<String>,
    pub table: String,
}

/// GET /api/gw/connections/{id}/describe?db=&table= — TableDescription。
pub(crate) async fn gw_describe_table(
    Extension(_claims): Extension<Claims>,
    State(st): State<GwState>,
    Path(conn_id): Path<String>,
    Query(q): Query<DescribeQuery>,
) -> Response {
    match meta::describe_table(&st.pool, &st.credential_key, &conn_id, q.db.as_deref(), &q.table)
        .await
    {
        Ok(desc) => Json(desc).into_response(),
        Err(e) => meta_err(e),
    }
}

// ── 查询执行（SSE）+ 取消 ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryBody {
    pub sql: Option<String>,
    /// 判别字段：v1 "sql"；T29 非 SQL 批次起 "mongo"（runCommand 单形状）
    /// / "redis"（命令/pipeline 通道）；T29 TDengine 批次 "tdengine"（SQL
    /// 形状，taosAdapter REST 通道）；其余仍 400。
    pub kind: Option<String>,
    /// kind:"mongo" 的命令文档（JSON 对象，首键 = 命令名，键序保真——
    /// 服务端 serde_json preserve_order）；kind:"redis" 的命令参数数组。
    pub command: Option<Value>,
    /// kind:"redis" 的 pipeline 批量（命令数组数组）；`atomic` = MULTI/EXEC
    /// server 侧包裹（ADR-0006 §2.3）。
    pub pipeline: Option<Vec<Vec<String>>>,
    pub atomic: Option<bool>,
    pub database: Option<String>,
    /// 同 TablesQuery.schema——v1 接受但忽略过滤（与列表内容是否跨
    /// schema 无关）。
    pub schema: Option<String>,
    /// 显式行限；缺省 `gw_query_default_rows`，钳到 `gw_query_max_rows`。
    pub row_limit: Option<u32>,
    /// statement_timeout 毫秒；缺省 `gw_query_timeout_secs`，钳 [1s, 600s]。
    pub timeout_ms: Option<u64>,
}

/// SSE 通道缓冲批数（×500 行/批 = 2000 行在途上限）。
const SSE_CHANNEL_BATCHES: usize = 4;

/// POST /api/gw/connections/{id}/query — SSE 流式执行。
///
/// 前置校验失败（kind/空 SQL/多语句）在流开始前返回 4xx JSON；执行期
/// 错误一律经 error 事件（SSE 已 200，无法再改状态码）。
///
/// `X-Execution-Id`：客户端可预置（uuid），否则 server 生成；响应头回显
/// ——取消（DELETE /api/gw/executions/{id}）可在任何时刻发起，包括流
/// 建立前（注册表无此 id 时幂等 no-op）。
pub(crate) async fn gw_query(
    Extension(claims): Extension<Claims>,
    State(st): State<GwState>,
    Path(conn_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<QueryBody>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return err_response(StatusCode::BAD_REQUEST, "CONFIG", "invalid JSON body"),
    };

    // ── 前置校验（流开始前，可 4xx）──
    let kind = body.kind.as_deref().unwrap_or("sql");
    let mut command: Option<Value> = None;
    let mut redis_command: Option<Vec<String>> = None;
    let mut pipeline: Option<Vec<Vec<String>>> = None;
    let atomic = body.atomic.unwrap_or(false);
    match kind {
        "sql" => {
            let Some(sql) = body.sql.as_deref().map(str::trim).filter(|s| !s.is_empty())
            else {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "CONFIG",
                    "sql must be a non-empty statement",
                );
            };
            // 单语句约束（契约 §7「明确不做：多语句」，同 read_query 口径——
            // 语句分析件复用 mcp risk；解析失败 0 条不在此拒，交引擎终裁）。
            if dbmaster_mcp::risk::statement_count(sql) > 1 {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "MULTI_STATEMENT",
                    "gateway v1 executes exactly one statement per request",
                );
            }
        }
        // T29 非 SQL 批次（B1）— mongo 命令对象前置校验（连接/引擎错误仍
        // 经 error 事件）。
        "mongo" => {
            let Some(cmd) = body.command.as_ref().filter(|v| v.as_object().is_some_and(|m| !m.is_empty())) else {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "CONFIG",
                    "kind \"mongo\" requires a non-empty command object",
                );
            };
            command = Some(cmd.clone());
        }
        // T29 非 SQL 批次（B3）— redis：command（字符串数组）或 pipeline
        //（数组数组）二选一；database 字段 = db index 路由。
        "redis" => {
            let cmd_array = body.command.as_ref().and_then(|v| v.as_array()).and_then(|a| {
                let parts: Option<Vec<String>> = a
                    .iter()
                    .map(|item| item.as_str().map(str::to_string))
                    .collect();
                parts.filter(|p: &Vec<String>| !p.is_empty())
            });
            let pipe_valid = body.pipeline.as_ref().is_some_and(|p| {
                !p.is_empty()
                    && p.iter().all(|entry| {
                        !entry.is_empty() && entry.iter().all(|arg| !arg.is_empty())
                    })
            });
            match (cmd_array, body.pipeline.as_ref(), pipe_valid) {
                (Some(cmd), None, _) => redis_command = Some(cmd),
                (None, Some(pipe), true) => pipeline = Some(pipe.clone()),
                (Some(_), Some(_), _) => {
                    return err_response(
                        StatusCode::BAD_REQUEST,
                        "CONFIG",
                        "kind \"redis\" accepts either command or pipeline, not both",
                    );
                }
                _ => {
                    return err_response(
                        StatusCode::BAD_REQUEST,
                        "CONFIG",
                        "kind \"redis\" requires a non-empty command array or pipeline",
                    );
                }
            }
        }
        // T29 TDengine 批次 — SQL 形状（sql + database 路由），校验与
        // "sql" 同口径（非空 + 单语句）；执行走 run_stream_tdengine。
        "tdengine" => {
            let Some(sql) = body.sql.as_deref().map(str::trim).filter(|s| !s.is_empty())
            else {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "CONFIG",
                    "sql must be a non-empty statement",
                );
            };
            if dbmaster_mcp::risk::statement_count(sql) > 1 {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "MULTI_STATEMENT",
                    "gateway v1 executes exactly one statement per request",
                );
            }
        }
        other => {
            return err_response(
                StatusCode::BAD_REQUEST,
                "UNSUPPORTED_KIND",
                &format!(
                    "unsupported kind \"{other}\": only \"sql\", \"mongo\", \"redis\" and \"tdengine\" are implemented"
                ),
            );
        }
    }
    let row_limit = body
        .row_limit
        .unwrap_or(st.config.gw_query_default_rows)
        .clamp(1, st.config.gw_query_max_rows) as usize;
    let timeout_ms = body
        .timeout_ms
        .unwrap_or(st.config.gw_query_timeout_secs as u64 * 1000)
        .clamp(1_000, 600_000);

    // ── 执行 id（客户端预置优先，须为合法 uuid——防注册表键注入垃圾）──
    let execution_id = headers
        .get("x-execution-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|s| uuid::Uuid::parse_str(s).is_ok())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // ── 执行任务（独立于 SSE body 的生命周期）──
    let (tx, rx) = tokio::sync::mpsc::channel::<StreamQueryEvent>(SSE_CHANNEL_BATCHES);
    let cancel_token = st.executions.register(execution_id.clone()).await;
    let registry = st.executions.clone();
    let pool = st.pool.clone();
    let key = st.credential_key;
    let user = claims.sub.clone();
    let conn_for_exec = conn_id.clone();
    let db_opt = body.database.clone();
    let sql_owned = body.sql.clone();
    let command_owned = command;
    let redis_command_owned = redis_command;
    let pipeline_owned = pipeline;
    let atomic_owned = atomic;
    let timeout = Duration::from_millis(timeout_ms);
    let exec_for_cleanup = execution_id.clone();
    let kind_owned = kind.to_string();
    // panic 补发通道：run_stream_query 按值消费 tx，panic 展开会连带 drop
    // 它（error 事件无处发，SSE 裸断）——闭包另持一份克隆用于兜底。
    let panic_tx = tx.clone();
    tokio::spawn(async move {
        // T28b：包 catch_unwind——tiberius 0.12 对部分列类型（sql_variant 的
        // SSVariant 等，`todo!()` panic）在流 poll 中崩掉执行任务时，SSE 会
        // 裸断（无 error 事件，客户端误判连接断开撕连接）。panic 在此转为
        // 结构化 error 事件（DB_ERROR），流以明确错误收尾。SELECT 返回此类
        // 列仍是用户侧已知边界（建议 CAST）；此处只保证失败可观测。
        // T29 非 SQL 批次——sql/mongo 双通道同一兜底（Trait Object 统一
        // 两签名差异）。
        let fut: std::pin::Pin<
            Box<dyn std::future::Future<Output = stream_query::StreamResult> + Send>,
        > = match kind_owned.as_str() {
            "mongo" => Box::pin(stream_query::run_stream_mongo(
                &pool,
                &key,
                &conn_for_exec,
                db_opt.as_deref(),
                command_owned.as_ref().expect("kind=mongo validated command"),
                row_limit,
                timeout,
                cancel_token,
                tx,
            )),
            "redis" => Box::pin(stream_query::run_stream_redis(
                &pool,
                &key,
                &conn_for_exec,
                db_opt.as_deref(),
                redis_command_owned.as_deref(),
                pipeline_owned.as_deref(),
                atomic_owned,
                row_limit,
                timeout,
                cancel_token,
                tx,
            )),
            "tdengine" => Box::pin(stream_query::run_stream_tdengine(
                &pool,
                &key,
                &conn_for_exec,
                db_opt.as_deref(),
                sql_owned.as_deref().unwrap_or(""),
                row_limit,
                timeout,
                cancel_token,
                tx,
            )),
            _ => Box::pin(stream_query::run_stream_query(
                &pool,
                &key,
                &conn_for_exec,
                db_opt.as_deref(),
                sql_owned.as_deref().unwrap_or(""),
                row_limit,
                timeout,
                cancel_token,
                tx,
            )),
        };
        let outcome = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(fut))
            .await
            .unwrap_or_else(|panic_payload| {
            let reason = panic_payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            // 兜底补发 error 事件（原 tx 已随展开的 future drop）。
            let _ = panic_tx.try_send(stream_query::StreamQueryEvent::Error(
                stream_query::StreamQueryError {
                    code: "DB_ERROR".to_string(),
                    message: format!(
                        "execution panicked in the TDS decode path ({reason}); \
                         CAST the column (e.g. sql_variant via SERVERPROPERTY) and retry"
                    ),
                    engine_code: None,
                },
            ));
            Err(stream_query::StreamQueryError {
                code: "DB_ERROR".to_string(),
                message: format!(
                    "execution panicked in the TDS decode path ({reason}); \
                     CAST the column (e.g. sql_variant via SERVERPROPERTY) and retry"
                ),
                engine_code: None,
            })
        });
        registry.remove(&exec_for_cleanup).await;
        // 审计：一行/执行；error 列只存稳定码（硬规则：无 SQL/引擎 message）。
        log_gw_event(
            &pool,
            Some(&user),
            GwAuditAction::QueryExec,
            outcome.err().map(|e| e.code.as_str().to_string()).as_deref(),
        )
        .await;
    });

    // ── SSE body：rx → 四事件流（seq id + keep-alive）──
    // T29 非 SQL 批次 — 事件 data 的 kind 判别字段随请求 kind（"sql"/
    // "mongo"；契约 §4.2 的判别贯穿四个事件）。
    let sse_kind = kind.to_string();
    let stream =
        futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|ev| (ev, rx)) })
            .enumerate()
            .map(move |(seq, ev)| Ok::<Event, Infallible>(sse_event(&sse_kind, ev, seq)));
    let sse = Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)));
    let mut resp = sse.into_response();
    let headers = resp.headers_mut();
    // 契约 §4.1：响应回显执行 id（取消句柄）。
    if let Ok(v) = HeaderValue::from_str(&execution_id) {
        headers.insert("x-execution-id", v);
    }
    headers.insert("cache-control", HeaderValue::from_static("no-cache"));
    resp
}

/// StreamQueryEvent → SSE Event（data = 契约 §4.2 的 chunk JSON；kind 判别
/// 字段随请求——"sql"/"mongo"）。可选键（wire 扩展，缺省省略）：
/// affectedRows（DDL/DML）、engineCode。
fn sse_event(kind: &str, ev: StreamQueryEvent, seq: usize) -> Event {
    let (name, data): (&str, Value) = match ev {
        StreamQueryEvent::Meta { columns, column_types } => {
            // T29 — columnTypes 可选 wire 扩展（列类型名，恢复客户端
            // T031 JSON 列识别数据源）；缺省省略保后向兼容。
            let mut v = json!({ "kind": kind, "type": "meta", "columns": columns });
            if let Some(types) = column_types {
                v["columnTypes"] = json!(types);
            }
            ("meta", v)
        }
        StreamQueryEvent::Rows { rows } => {
            ("rows", json!({ "kind": kind, "type": "rows", "rows": rows }))
        }
        StreamQueryEvent::Complete { info, elapsed_ms } => {
            let mut v = json!({
                "kind": kind, "type": "complete",
                "rowCount": info.row_count, "truncated": info.truncated,
                "elapsedMs": elapsed_ms,
            });
            if let Some(n) = info.affected_rows {
                v["affectedRows"] = json!(n);
            }
            ("complete", v)
        }
        StreamQueryEvent::Error(e) => {
            let mut v =
                json!({ "kind": kind, "type": "error", "code": e.code, "message": e.message });
            if let Some(code) = e.engine_code {
                v["engineCode"] = json!(code);
            }
            ("error", v)
        }
    };
    Event::default().event(name).id(seq.to_string()).data(data.to_string())
}

/// DELETE /api/gw/executions/{id} — 显式取消（幂等 204；未知/已结束 id no-op）。
pub(crate) async fn cancel_execution(
    Extension(_claims): Extension<Claims>,
    State(st): State<GwState>,
    Path(execution_id): Path<String>,
) -> Response {
    st.executions.cancel(&execution_id).await;
    StatusCode::NO_CONTENT.into_response()
}

// ── 连接配置语义（C10 / T28 前置）──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDraftBody {
    pub db_type: String,
    pub host: Option<String>,
    pub port: Option<i64>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub default_database: Option<String>,
    pub file_path: Option<String>,
    /// T29 非 SQL 批次 — 集群/厂商专有配置（Mongo 集群四模式 / Redis auth
    /// 模式）。注册前经 `sanitize_extra` 清洗（剔凭据类键、剥 URI userinfo）
    /// 再落 extra 列（ADR-0006 §2.2）。
    pub extra: Option<serde_json::Map<String, Value>>,
    /// 网络层批次（2026-08-29）— SSH 隧道配置块（字段存在即启用隧道；
    /// wire 契约见 automation::ssh::SshWire 文档）。非秘密字段合并进
    /// extra，秘密加密落 `ssh_secret_encrypted` 列；draft 测试路径内存
    /// 直传。TLS 透传走 extra 的 useTls/tlsInsecure 两键（非凭据）。
    pub ssh: Option<dbmaster_automation::ssh::SshWire>,
}

/// draft 的 extra + ssh 非秘密键（sshHost/sshPort/sshUsername/sshAuthMode）
/// 合并（后者覆盖——重注册改隧道配置必须生效）。ssh 秘密不进 extra（单独
/// 加密落列）；sshHost 等键名不含 password/secret/token，可安全过
/// `sanitize_extra`。
fn merged_extra(
    extra: Option<&serde_json::Map<String, Value>>,
    ssh: Option<&dbmaster_automation::ssh::SshWire>,
) -> Option<serde_json::Map<String, Value>> {
    let mut map = extra.cloned().unwrap_or_default();
    if let Some(wire) = ssh {
        if let Ok(params) = wire.validate() {
            for (k, v) in dbmaster_automation::ssh::extra_keys(&params.config) {
                map.insert(k.to_string(), v);
            }
        }
    }
    if map.is_empty() { None } else { Some(map) }
}

/// extra 清洗：丢凭据类键（password/secret/token，含嵌套键名判断）；疑似
/// URI 的字符串值剥 userinfo。清洗后为空 → None（不落空对象）。
///
/// 网络层批次 — `ssh` 键整体丢弃（纵深防御）：wire 契约里 SSH 配置只走
/// draft 顶层 `ssh` 字段（秘密单独加密落列）；客户端若把 ssh 对象（可能含
/// password/privateKey）塞进 extra，键名不含凭据子串会穿透下面的过滤——
/// server 不信任客户端组包路径，在此拦死。
fn sanitize_extra(extra: Option<&serde_json::Map<String, Value>>) -> Option<String> {
    let mut out = serde_json::Map::new();
    for (key, value) in extra? {
        let lowered = key.to_ascii_lowercase();
        if lowered.contains("password") || lowered.contains("secret") || lowered.contains("token")
        {
            continue;
        }
        if lowered == "ssh" {
            continue;
        }
        if lowered.contains("connectionstring")
            || lowered.contains("uri")
            || lowered.contains("url")
        {
            if let Some(s) = value.as_str() {
                out.insert(key.clone(), Value::String(strip_uri_credentials(s)));
                continue;
            }
        }
        out.insert(key.clone(), value.clone());
    }
    if out.is_empty() {
        None
    } else {
        Some(Value::Object(out).to_string())
    }
}

/// `scheme://user:pass@rest` → `scheme://rest`（userinfo 段含 '/' 视为路径
/// 的一部分，不动）；无 userinfo 原样返回。
fn strip_uri_credentials(s: &str) -> String {
    let Some(scheme_end) = s.find("://") else { return s.to_string() };
    let rest = &s[scheme_end + 3..];
    let Some(at) = rest.find('@') else { return s.to_string() };
    let userinfo = &rest[..at];
    if userinfo.is_empty() || userinfo.contains('/') {
        return s.to_string();
    }
    format!("{}{}", &s[..scheme_end + 3], &rest[at + 1..])
}

/// Gateway registration/test accepted db_type whitelist (= automation metadata family; execution side
/// T27 debut mysql/pg/sqlite/doris + T28 sqlserver + T29 batch-3 clickhouse via its MySQL-compatible
/// port, forced raw_sql). `mssql` is a common alias for `sqlserver` (same as backend_for).
/// T29 non-SQL: B1 adds `mongodb` (kind:"mongo" runCommand), B3 adds `redis` (kind:"redis"
/// command/pipeline + subscription endpoint, ADR-0006).
///
/// **T22-T25 landed**: the four MySQL-family members oceanbase / tidb / starrocks /
/// mariadb registered via automation `mysql_family.rs` thin profiles (probe-verified
/// differences only; MariaDB is a zero-override member). New-family-member onboarding
/// steps stay: profile struct + registry line server-side, wire value here, client UI
/// metadata per task_dbx_response.
const SUPPORTED_DB_TYPES: [&str; 16] = [
    "mysql", "doris", "postgres", "postgresql", "pg", "sqlite", "clickhouse", "sqlserver", "mssql",
    "oceanbase", "tidb", "starrocks", "mariadb", "mongodb", "redis", "tdengine",
];

/// 草稿字段族校验：sqlite 需 file_path；mongodb / redis 需 host/port（凭据
/// 可选——无认证实例合法；redis auth 三态由凭据存在性推导）。其余需
/// host/port/username/password。
/// 返回归一化 db_type 或 4xx Response。
fn validate_draft(body: &ConnectionDraftBody) -> Result<String, Response> {
    let db_type = body.db_type.trim().to_ascii_lowercase();
    if !SUPPORTED_DB_TYPES.contains(&db_type.as_str()) {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "UNSUPPORTED_DB_TYPE",
            &format!("unsupported db_type: {}", body.db_type),
        ));
    }
    // mongodb/redis：凭据可选（无认证实例）；host/port 仍必填。
    let credentials_optional = db_type == "mongodb" || db_type == "redis";
    let required_missing = if db_type == "sqlite" {
        body.file_path.as_deref().map(str::trim).filter(|s| !s.is_empty()).is_none()
    } else if credentials_optional {
        body.host.as_deref().map(str::trim).filter(|s| !s.is_empty()).is_none() || body.port.is_none()
    } else {
        body.host.as_deref().map(str::trim).filter(|s| !s.is_empty()).is_none()
            || body.port.is_none()
            || body.username.as_deref().map(str::trim).filter(|s| !s.is_empty()).is_none()
            || body.password.is_none()
    };
    if required_missing {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "CONFIG",
            if db_type == "sqlite" {
                "sqlite connection requires filePath"
            } else if credentials_optional {
                "host and port are required for this db_type"
            } else {
                "host, port, username and password are required for this db_type"
            },
        ));
    }
    Ok(db_type)
}

/// POST /api/gw/connections/test — 草稿测试（不落库；测试 = 远程调用，
/// c01_port_contract §5）。成功尽力附引擎版本。
pub(crate) async fn test_connection(
    Extension(_claims): Extension<Claims>,
    State(_st): State<GwState>,
    Json(body): Json<ConnectionDraftBody>,
) -> Response {
    if let Err(resp) = validate_draft(&body) {
        return resp;
    }
    // ssh 配置块校验（错误不带秘密）。
    let ssh_params = match &body.ssh {
        Some(wire) => match wire.validate() {
            Ok(p) => Some(p),
            Err(msg) => {
                return err_response(StatusCode::BAD_REQUEST, "CONFIG", &msg);
            }
        },
        None => None,
    };
    let draft = DraftConnection {
        db_type: body.db_type.trim().to_ascii_lowercase(),
        host: body.host.unwrap_or_default(),
        port: body.port.unwrap_or(0),
        username: body.username.unwrap_or_default(),
        password: body.password.unwrap_or_default(),
        default_database: body.default_database,
        file_path: body.file_path,
        extra: sanitize_extra(merged_extra(body.extra.as_ref(), body.ssh.as_ref()).as_ref()),
        ssh: ssh_params,
    };
    let started = Instant::now();
    let result = test_draft_connection(&draft).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(version) => {
            let mut data = json!({ "ok": true, "elapsedMs": elapsed_ms });
            if let Some(v) = version {
                data["serverVersion"] = json!(v);
            }
            (StatusCode::OK, Json(data)).into_response()
        }
        Err(msg) => (
            StatusCode::OK,
            Json(json!({ "ok": false, "error": msg, "elapsedMs": elapsed_ms })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterBody {
    pub name: String,
    #[serde(flatten)]
    pub draft: ConnectionDraftBody,
    pub read_only: Option<bool>,
    pub charset: Option<String>,
    pub timezone: Option<String>,
}

/// POST /api/gw/connections — 凭据入 server vault（AES-256-GCM），返回
/// serverConnId。kind 固定 'collab'（网关注册是交互连接，不走
/// source_drift canary 链路——那属于 automation 任务面）。
pub(crate) async fn register_connection(
    Extension(claims): Extension<Claims>,
    State(st): State<GwState>,
    Json(body): Json<RegisterBody>,
) -> Response {
    let db_type = match validate_draft(&body.draft) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let name = body.name.trim();
    if name.is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "CONFIG", "name must be non-empty");
    }
    let is_sqlite = db_type == "sqlite";
    // SQLite 无密码（file_path 即凭据）——存空串（与 mcp 测试基线一致）。
    let password_plain = body.draft.password.as_deref().unwrap_or("");
    let encrypted = match dbmaster_automation::credential::encrypt_v1(
        password_plain,
        &st.credential_key,
    ) {
        Ok(ct) => ct,
        Err(e) => {
            tracing::error!(error = %e, "credential encryption failed");
            return err_response(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "credential encryption failed");
        }
    };
    // T29 非 SQL 批次 — extra 清洗后落列（None 存 NULL）。
    // 网络层批次 — ssh 非秘密键合并进 extra；秘密 JSON（password/
    // privateKey/passphrase）encrypt_v1 整体加密落 ssh_secret_encrypted
    //（migration 020）。draft 不带 ssh 时置 None——编辑删掉隧道后重注册
    //（UPDATE 复用行路径）必须生效。
    let extra_json = sanitize_extra(merged_extra(body.draft.extra.as_ref(), body.draft.ssh.as_ref()).as_ref());
    let ssh_secret_encrypted: Option<String> = match &body.draft.ssh {
        Some(wire) => match wire.validate() {
            Ok(params) if !params.secrets.is_empty() => {
                let plain = serde_json::to_string(&params.secrets).unwrap_or_default();
                match dbmaster_automation::credential::encrypt_v1(&plain, &st.credential_key) {
                    Ok(ct) => Some(ct),
                    Err(e) => {
                        tracing::error!(error = %e, "ssh secret encryption failed");
                        return err_response(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "credential encryption failed");
                    }
                }
            }
            // ssh 块存在但秘密全空：视为清空既有隧道秘密（extra 的 ssh 非
            // 秘密键仍写入——隧道开关开着但没填凭据的编辑中间态）。
            Ok(_) => None,
            Err(msg) => return err_response(StatusCode::BAD_REQUEST, "CONFIG", &msg),
        },
        None => None,
    };
    // vault 无界增长根治①（P1）：注册幂等——同 owner + kind='collab' 下
    // 指纹（name+db_type+host+port+username+default_database+file_path，
    // 不含密码）命中既有行时复用 serverConnId，仅刷新凭据与网关会话参数
    // （charset/timezone/read_only/extra；连接编辑后重注册必须刷新，否则
    // 复用路径静默吃掉改动）。防 E2E / 清理脚本 / 客户端映射丢失后重连把
    // 同一逻辑连接堆成多行（启动卡顿修复 a63a5194 的根因面）。指纹不含
    // 创建路径（automation /api/connections 与本端点同落 kind='collab'，
    // 同指纹即同一逻辑连接——两路径收敛到一行）；并发双注册的竞态窗口按
    // best-effort 容忍（重复行不致命，后续注册仍会收敛）。
    let host_val = if is_sqlite { "unused".to_string() } else { body.draft.host.as_deref().unwrap_or_default().to_string() };
    let user_val = if is_sqlite { "unused".to_string() } else { body.draft.username.as_deref().unwrap_or_default().to_string() };
    let port_val = body.draft.port.unwrap_or(0);
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM database_connections \
         WHERE kind = 'collab' AND created_by = ?1 \
           AND name = ?2 AND db_type = ?3 AND host = ?4 AND port = ?5 \
           AND username = ?6 \
           AND IFNULL(default_database, '') = IFNULL(?7, '') \
           AND IFNULL(file_path, '') = IFNULL(?8, '') \
         LIMIT 1",
    )
    .bind(&claims.sub)
    .bind(name)
    .bind(&db_type)
    .bind(&host_val)
    .bind(port_val)
    .bind(&user_val)
    .bind(&body.draft.default_database)
    .bind(&body.draft.file_path)
    .fetch_optional(&st.pool)
    .await
    .unwrap_or(None); // 指纹查询失败不阻断注册（退化为原 INSERT 行为）
    if let Some(id) = existing {
        let updated = sqlx::query(
            "UPDATE database_connections SET password_encrypted = ?1, \
             charset = ?2, timezone = ?3, read_only = ?4, extra = ?5, \
             ssh_secret_encrypted = ?6 \
             WHERE id = ?7",
        )
        .bind(&encrypted)
        .bind(&body.charset)
        .bind(&body.timezone)
        .bind(body.read_only.unwrap_or(false))
        .bind(&extra_json)
        .bind(&ssh_secret_encrypted)
        .bind(&id)
        .execute(&st.pool)
        .await;
        if updated.is_ok() {
            log_gw_event(&st.pool, Some(&claims.sub), GwAuditAction::ConnectionRegistered, None)
                .await;
            return (StatusCode::OK, Json(json!({ "serverConnId": id, "reused": true }))).into_response();
        }
        // UPDATE 失败（行刚被并发删除等）→ 落回 INSERT 新建。
    }
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let result = sqlx::query(
        "INSERT INTO database_connections (
            id, name, db_type, host, port, username, password_encrypted,
            default_database, created_by, created_at, kind, file_path,
            charset, timezone, read_only, extra, ssh_secret_encrypted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'collab', ?11, ?12, ?13, ?14, ?15, ?16)",
    )
    .bind(&id)
    .bind(name)
    .bind(&db_type)
    .bind(&host_val)
    .bind(port_val)
    .bind(&user_val)
    .bind(&encrypted)
    .bind(&body.draft.default_database)
    .bind(&claims.sub)
    .bind(&now)
    .bind(&body.draft.file_path)
    .bind(&body.charset)
    .bind(&body.timezone)
    .bind(body.read_only.unwrap_or(false))
    .bind(&extra_json)
    .bind(&ssh_secret_encrypted)
    .execute(&st.pool)
    .await;
    match result {
        Ok(_) => {
            log_gw_event(&st.pool, Some(&claims.sub), GwAuditAction::ConnectionRegistered, None)
                .await;
            (StatusCode::OK, Json(json!({ "serverConnId": id }))).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "gateway connection insert failed");
            err_response(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "failed to register connection")
        }
    }
}

/// DELETE /api/gw/connections/{id} — 幂等 204（行不存在亦然，HTTP DELETE
/// 语义；级联由既有 FK 约束处理，同 automation delete_connection）。
pub(crate) async fn remove_connection(
    Extension(claims): Extension<Claims>,
    State(st): State<GwState>,
    Path(conn_id): Path<String>,
) -> Response {
    // T29 非 SQL 批次（B3）— 先杀该连接的活跃订阅流（ADR-0006 §2.5：
    // 订阅注册表挂连接删除；SSE 流经 take_until 令牌终止 → 订阅连接 drop）。
    st.redis_subs.revoke(&conn_id).await;
    let _ = sqlx::query("DELETE FROM database_connections WHERE id = ?1")
        .bind(&conn_id)
        .execute(&st.pool)
        .await;
    log_gw_event(&st.pool, Some(&claims.sub), GwAuditAction::ConnectionRemoved, None).await;
    StatusCode::NO_CONTENT.into_response()
}

// ── Redis 订阅转发（T29 非 SQL 批次 B3，ADR-0006 §2.5）──

/// 重复 query 参数手工解析（serde_urlencoded 不支持重复 key 进 Vec）：
/// `?channels=a&channels=b&patterns=p*` → (channels, patterns)。值做
/// 百分号解码（channel 名可含非 ASCII）。
fn parse_redis_sub_query(raw: Option<&str>) -> (Vec<String>, Vec<String>) {
    #[derive(Default)]
    struct Acc {
        channels: Vec<String>,
        patterns: Vec<String>,
    }
    fn percent_decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() + 1 && i + 2 < bytes.len() {
                let hex = &s[i + 1..i + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
            if bytes[i] == b'+' {
                out.push(b' ');
                i += 1;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    let acc = raw
        .map(|q| {
            let mut acc = Acc::default();
            for pair in q.split('&').filter(|p| !p.is_empty()) {
                if let Some((k, v)) = pair.split_once('=') {
                    let v = percent_decode(v);
                    match k {
                        "channels" => acc.channels.push(v),
                        "patterns" => acc.patterns.push(v),
                        _ => {}
                    }
                } else {
                    match pair {
                        "channels" => acc.channels.push(String::new()),
                        "patterns" => acc.patterns.push(String::new()),
                        _ => {}
                    }
                }
            }
            acc
        })
        .unwrap_or_default();
    (acc.channels, acc.patterns)
}

/// 单订阅流 channel/pattern 总数上限（防滥用，ADR-0006 §2.5）。
const REDIS_SUB_MAX_TARGETS: usize = 64;

/// GET /api/gw/connections/{id}/redis/subscriptions?channels=&patterns= —
/// 订阅转发 SSE。
///
/// 事件：`subscribed`（回执，含注册的 channels/patterns）/ `message`
///（channel/pattern/payload）/ 15s keep-alive。**生命周期挂 HTTP 连接**：
/// 客户端断开 SSE → 流 future drop → 专用订阅连接 drop；网关连接删除经
/// [crate::RedisSubRegistry] 令牌杀流。`publish` 走 query 端点命令通道。
pub(crate) async fn redis_subscribe(
    Extension(_claims): Extension<Claims>,
    State(st): State<GwState>,
    Path(conn_id): Path<String>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Response {
    let (channels, patterns) = parse_redis_sub_query(raw.as_deref());
    let channels: Vec<String> = channels.into_iter().filter(|c| !c.is_empty()).collect();
    let patterns: Vec<String> = patterns.into_iter().filter(|p| !p.is_empty()).collect();
    let total = channels.len() + patterns.len();
    if total == 0 {
        return err_response(
            StatusCode::BAD_REQUEST,
            "CONFIG",
            "at least one channel or pattern is required",
        );
    }
    if total > REDIS_SUB_MAX_TARGETS {
        return err_response(
            StatusCode::BAD_REQUEST,
            "CONFIG",
            &format!("too many subscription targets: {total} (max {REDIS_SUB_MAX_TARGETS})"),
        );
    }

    // 订阅连接建立 + 全量订阅（失败 = 连接/凭据级，流开始前 5xx）。
    let mut pubsub = match dbmaster_automation::metadata::open_redis_pubsub_for(
        &st.pool,
        &st.credential_key,
        &conn_id,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return meta_err(e),
    };
    for channel in &channels {
        if let Err(e) = pubsub.subscribe(channel).await {
            tracing::warn!(error = %e, "redis subscribe failed");
            return err_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "CONNECTION_FAILED",
                "redis subscription setup failed",
            );
        }
    }
    for pattern in &patterns {
        if let Err(e) = pubsub.psubscribe(pattern).await {
            tracing::warn!(error = %e, "redis psubscribe failed");
            return err_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "CONNECTION_FAILED",
                "redis subscription setup failed",
            );
        }
    }

    // 注册取消令牌（连接删除杀流；流自然结束的陈旧令牌随连接生命周期
    // 有界——见 RedisSubRegistry 文档）。
    let token = tokio_util::sync::CancellationToken::new();
    st.redis_subs.register(&conn_id, token.clone()).await;

    let receipt = json!({
        "type": "subscribed",
        "channels": channels,
        "patterns": patterns,
    });
    let stream = futures::stream::once(async move {
        Ok::<Event, Infallible>(
            Event::default().event("subscribed").data(receipt.to_string()),
        )
    })
    .chain(futures::stream::unfold(pubsub, |mut pubsub| async move {
        use futures::StreamExt;
        // on_message 借用 pubsub；借用块内 await，块尾释放（unfold 状态继续
        // 持有 pubsub）。
        let msg = {
            let mut messages = pubsub.on_message();
            messages.next().await
        };
        msg.map(|m| {
            let pattern = if m.from_pattern() {
                m.get_pattern::<String>().ok()
            } else {
                None
            };
            let data = json!({
                "type": "message",
                "channel": m.get_channel_name(),
                "pattern": pattern,
                "payload": String::from_utf8_lossy(m.get_payload_bytes()),
            });
            (
                Ok::<Event, Infallible>(
                    Event::default().event("message").data(data.to_string()),
                ),
                pubsub,
            )
        })
    }))
    // cancelled_owned：拥有型取消 future（流持有；token 克隆留给注册表，
    // 连接删除 revoke 时触发终止）。
    .take_until(token.cancelled_owned());
    let sse = Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)));
    sse.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_extra_drops_credential_keys_and_strips_uri_userinfo() {
        let mut extra = serde_json::Map::new();
        extra.insert("mongoConnectionMode".into(), json!("replicaSet"));
        extra.insert("mongoHosts".into(), json!(["a:27017", "b:27017"]));
        extra.insert("mongoConnectionString".into(), json!("mongodb://leak:me@h1:27017,h2/?replicaSet=rs0"));
        extra.insert("redisPassword".into(), json!("nope"));
        extra.insert("authToken".into(), json!("nope"));

        let stored = sanitize_extra(Some(&extra)).expect("non-empty after sanitize");
        assert!(!stored.contains("leak:me"), "uri userinfo must be stripped: {stored}");
        assert!(!stored.contains("nope"), "credential-like keys must be dropped: {stored}");
        assert!(stored.contains("replicaSet"));
        assert!(stored.contains("a:27017"));
        // 回读解析仍为对象（存储形态 = JSON 字符串）。
        let back: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(back["mongoConnectionString"], "mongodb://h1:27017,h2/?replicaSet=rs0");
    }

    #[test]
    fn sanitize_extra_keeps_ssh_non_secret_keys_and_tls_flags() {
        // 网络层批次 — ssh 非秘密四键 + TLS 两键不含 password/secret/token
        // 子串，须完整存活（load_connection 的隧道收口读它们）。
        let wire = serde_json::from_value::<dbmaster_automation::ssh::SshWire>(json!({
            "host": "jump.example.com", "port": 2222, "username": "deploy",
            "authMode": "password", "password": "sekrit"
        }))
        .expect("wire decode");
        let merged = merged_extra(None, Some(&wire)).expect("merged");
        let stored = sanitize_extra(Some(&merged)).expect("non-empty");
        assert!(stored.contains("jump.example.com"), "{stored}");
        assert!(stored.contains("sshAuthMode"));
        assert!(!stored.contains("sekrit"), "ssh secret must never land in extra: {stored}");

        let mut extra = merged_extra(None, None).unwrap_or_default();
        extra.insert("useTls".into(), json!(true));
        extra.insert("tlsInsecure".into(), json!(false));
        let stored = sanitize_extra(Some(&extra)).expect("non-empty");
        let back: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(back["useTls"], json!(true));
        assert_eq!(back["tlsInsecure"], json!(false));
        // 纵深防御：客户端把 ssh 对象（含秘密）塞进 extra → 整键丢弃
        //（伴一个合法键证明其余键存活；仅剩 ssh 时清洗为空 → None）。
        let mut hostile = serde_json::Map::new();
        hostile.insert("useTls".into(), json!(true));
        hostile.insert("ssh".into(), json!({"host": "h", "password": "sekrit"}));
        let stored = sanitize_extra(Some(&hostile)).expect("keep other keys path");
        assert!(!stored.contains("ssh"), "extra['ssh'] must be dropped: {stored}");
        assert!(!stored.contains("sekrit"), "secret must not survive: {stored}");
        let mut hostile2 = serde_json::Map::new();
        hostile2.insert("ssh".into(), json!({"password": "sekrit"}));
        assert!(sanitize_extra(Some(&hostile2)).is_none());
        // 无 extra 无 ssh → None。
        assert!(merged_extra(None, None).is_none());
    }

    #[test]
    fn sanitize_extra_none_or_all_dropped_yields_none() {
        assert!(sanitize_extra(None).is_none());
        let mut extra = serde_json::Map::new();
        extra.insert("password".into(), json!("x"));
        assert!(sanitize_extra(Some(&extra)).is_none());
    }

    #[test]
    fn strip_uri_credentials_leaves_plain_and_path_at_intact() {
        assert_eq!(strip_uri_credentials("mongodb://h:1"), "mongodb://h:1");
        assert_eq!(
            strip_uri_credentials("mongodb://u:p@h:1/?a=b"),
            "mongodb://h:1/?a=b"
        );
        // userinfo 段含 '/' → 视为路径一部分，不动；空 userinfo 无凭据
        // 语义，同样不动（不引入无谓改写）。
        assert_eq!(strip_uri_credentials("http://a/b@c"), "http://a/b@c");
        assert_eq!(strip_uri_credentials("mongodb://@h:1"), "mongodb://@h:1");
        assert_eq!(strip_uri_credentials("no-scheme@host"), "no-scheme@host");
    }
}
