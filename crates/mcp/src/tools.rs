//! Tier-1 只读元数据工具面（dbx-response T06，方案 §1.3）。
//!
//! 4 个钻取工具（`list_connections` → `list_databases` → `list_tables` →
//! `describe_table`）+ `read_query` 构成只读面；T19 起审批制写路径三工具
//! （`submit_write` / `get_approval` / `execute_write`）在 [`crate::write`]，
//! 本模块负责统一注册（tool_definitions）与分发（execute）。DB 能力全部
//! 来自 automation 的 `metadata` 模块（网关 API v1 同源，ADR-0005 §2.2），
//! 本 crate 不直连业务库。
//!
//! 工具结果形态（对齐 dbx get_schema_context 的取舍）：JSON 以紧凑文本
//! 作为 content（Claude Code/Cursor 直接读），同一 JSON 放 structured_content
//! （支持结构化输出的客户端免解析）。空 comment/row_estimate 等字段由
//! serde skip_serializing_if 省略，控制 agent token 用量。
//!
//! 错误形态：工具级错误走 `CallToolResult::error`（isError=true，agent 可见
//! 原因文案）——按 rmcp 语义这是「工具跑了但没成功」，协议级 Err 只留给
//! 路由不到工具的坏请求。
//!
//! 身份：guard（T04）把 Claims 放进 HTTP request extensions，rmcp 的
//! StreamableHttpService 把 `http::request::Parts` 注入消息 extensions，
//! 最终可在 `RequestContext.extensions` 读回——每次 tools/call 都取当次
//! 请求的身份（同一会话内换凭证也生效）。

use std::sync::Arc;

use dbmaster_automation::metadata as meta;
use dbmaster_core::auth::jwt::Claims;
use dbmaster_core::server::CredentialKey;
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, JsonObject, Tool};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::{json, Value};
use sqlx::SqlitePool;

use crate::audit::{log_mcp_event, McpAuditAction};

// ── 工具常量与定义（tools/list 契约）──

pub const TOOL_LIST_CONNECTIONS: &str = "list_connections";
pub const TOOL_LIST_DATABASES: &str = "list_databases";
pub const TOOL_LIST_TABLES: &str = "list_tables";
pub const TOOL_DESCRIBE_TABLE: &str = "describe_table";
pub const TOOL_READ_QUERY: &str = "read_query";

/// read_query 的行限/超时（来自 Config，router 注入 handler，pub 只是
/// 因为 DbMasterMcp::new 是 pub 的——类型对外无意义）。
/// 不传 max_rows 时的默认行限（任务口径 500）。
pub(crate) const READ_QUERY_DEFAULT_ROWS: usize = 500;

#[derive(Clone)]
pub struct ToolLimits {
    pub(crate) read_query_max_rows: usize,
    pub(crate) read_query_timeout_secs: u32,
}

/// JSON Schema 装箱（write.rs 的写路径工具构造共用）。
pub(crate) fn schema(v: Value) -> Arc<JsonObject> {
    Arc::new(v.as_object().expect("object schema").clone())
}

/// Tool/ToolAnnotations 均 #[non_exhaustive]，外部 crate 不能用结构体字面量
/// 构造——经 Default + 字段赋值（Tier-1 全只读，readOnlyHint 恒 true）。
/// name/description 需 'static（Cow<'static>）——调用方全部传 const。
fn tool(name: &'static str, title: &str, description: &str, input_schema: Value) -> Tool {
    let mut t = Tool::default();
    t.name = name.into();
    t.title = Some(title.to_string());
    t.description = Some(std::borrow::Cow::Owned(description.to_string()));
    t.input_schema = schema(input_schema);
    let mut annotations = rmcp::model::ToolAnnotations::default();
    annotations.read_only_hint = Some(true);
    t.annotations = Some(annotations);
    t
}

/// T06 工具面 + T19 写路径三工具（顺序即 tools/list 返回序——读面在前、
/// 审批制写面殿后）。
pub fn tool_definitions() -> Vec<Tool> {
    let mut tools = vec![
        tool(
            TOOL_LIST_CONNECTIONS,
            "List connections",
            "List the database connections registered on this dbmaster server. \
             Returns id, name, db_type, read_only and default_database for each — \
             never credentials. Start here, then drill down with list_databases / \
             list_tables.",
            json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        ),
        tool(
            TOOL_LIST_DATABASES,
            "List databases",
            "List the databases visible to one connection (for PostgreSQL this \
             is the databases in the cluster, not the schemas inside one — use \
             list_tables to enumerate the tables of every schema in a database). \
             Args: connection_id from list_connections. Engine-internal \
             catalogs (e.g. information_schema) are hidden to keep the \
             output compact.",
            json!({
                "type": "object",
                "properties": {
                    "connection_id": {
                        "type": "string",
                        "description": "Connection id from list_connections"
                    }
                },
                "required": ["connection_id"],
                "additionalProperties": false
            }),
        ),
        tool(
            TOOL_LIST_TABLES,
            "List tables",
            "List tables and views in a database, with comments and approximate \
             row-count estimates where the engine keeps statistics (estimates spare \
             you from COUNT(*)). On PostgreSQL every user schema of the database is \
             enumerated (system schemas are hidden); objects outside the public \
             schema are named 'schema.table' and carry a 'schema' field — pass that \
             qualified name to describe_table to address them. Two addressing \
             boundaries: a table name that itself contains '.' cannot be addressed \
             by the 'schema.table' form (only names without '.' round-trip), and a \
             bare name is resolved by the connection's search_path, so a '$user' \
             schema can take precedence over public for it. Args: connection_id; \
             optional database (defaults to the connection's default database).",
            json!({
                "type": "object",
                "properties": {
                    "connection_id": {
                        "type": "string",
                        "description": "Connection id from list_connections"
                    },
                    "database": {
                        "type": "string",
                        "description": "Database name from list_databases (optional)"
                    }
                },
                "required": ["connection_id"],
                "additionalProperties": false
            }),
        ),
        tool(
            TOOL_DESCRIBE_TABLE,
            "Describe table",
            "Describe one table for SQL writing: columns (name, type, nullable, \
             default, comment), primary key, indexes (with columns) and foreign \
             keys. Compact output. Args: connection_id, table; optional database.",
            json!({
                "type": "object",
                "properties": {
                    "connection_id": {
                        "type": "string",
                        "description": "Connection id from list_connections"
                    },
                    "table": {
                        "type": "string",
                        "description": "Table name from list_tables. A \
                                        'schema.table' qualified name addresses \
                                        that schema explicitly (PostgreSQL); not \
                                        usable when the object name itself \
                                        contains '.'. A bare name resolves via \
                                        the connection's search_path, where a \
                                        '$user' schema can take precedence over \
                                        public."
                    },
                    "database": {
                        "type": "string",
                        "description": "Database name (optional)"
                    }
                },
                "required": ["connection_id", "table"],
                "additionalProperties": false
            }),
        ),
        tool(
            TOOL_READ_QUERY,
            "Read query",
            "Execute ONE read-only SQL statement (SELECT / SHOW / plain EXPLAIN) \
             and return rows. Writes, DDL, USE, transactions and multiple \
             statements per call are rejected. Rows are server-capped: pass \
             max_rows to request fewer (default 500); long-running statements \
             are cancelled by a server-side timeout. Args: connection_id, sql; \
             optional database, max_rows.",
            json!({
                "type": "object",
                "properties": {
                    "connection_id": {
                        "type": "string",
                        "description": "Connection id from list_connections"
                    },
                    "sql": {
                        "type": "string",
                        "description": "A single read-only SQL statement"
                    },
                    "database": {
                        "type": "string",
                        "description": "Database name (optional; defaults to the connection's default)"
                    },
                    "max_rows": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Row cap for this call (optional; server default 500)"
                    }
                },
                "required": ["connection_id", "sql"],
                "additionalProperties": false
            }),
        ),
    ];
    // T19 — 写路径三工具（submit_write / get_approval / execute_write），
    // 定义与实现见 write.rs（审批制：提交 → 人批 → 幂等执行）。
    tools.extend(crate::write::tool_definitions());
    tools
}

// ── 工具层共享状态 ──

/// T08 — 连接白名单（`Config::mcp_allowed_connections`，对齐 dbx 的
/// connection allowlist）。**单一过滤点**：`allows(id, name)` 是唯一判定，
/// list_connections 的输出过滤与所有按 connection_id 取参的工具共用。
/// 条目按连接 **id 或 name** 精确匹配（运维认 name——桌面端可见；agent
/// 持 id——工具参数）。空表 = 放行全部（对齐 `/api/connections` v1 语义，
/// 产品默认）。
#[derive(Clone, Debug, Default)]
pub struct ConnectionWhitelist {
    entries: Vec<String>,
}

impl ConnectionWhitelist {
    pub(crate) fn new(entries: Vec<String>) -> Self {
        Self { entries }
    }

    /// 白名单外连接对 MCP 不可见/不可用。空表放行；非空时 id/name 任一
    /// 精确命中即放行。
    fn allows(&self, id: &str, name: &str) -> bool {
        self.entries.is_empty() || self.entries.iter().any(|e| e == id || e == name)
    }
}

/// 运行时 entitlement 的共享句柄——与 core `AppState.entitlement` 同一
/// `ArcSwap` 实例（`POST /api/license` 热换后长会话的下一次工具调用即读到
/// 新态）。D1（2026-08-27 拍板：写门读放）写路径 license 门的数据源。
pub type EntitlementArc =
    std::sync::Arc<arc_swap::ArcSwap<dbmaster_license::EntitlementState>>;

/// ServerHandler 持有的执行上下文：server 库连接池 + 凭据解密钥匙 +
/// read_query 行限/超时 + 连接白名单（T08）。连接可见性与 `/api/connections`
/// v1 语义一致（认证用户见全部）；白名单在其上收紧 MCP 面。
#[derive(Clone)]
pub(crate) struct ToolState {
    /// T19 起写路径（write.rs）直接复用池与凭据钥匙（执行体走 automation
    /// `execute_ddl_on_target_with_key`）；limits/whitelist 仍只经方法暴露。
    pub(crate) pool: SqlitePool,
    pub(crate) credential_key: CredentialKey,
    /// D1 写门数据源：Gated 时 `submit_write`/`execute_write` 拒绝（见
    /// [`ToolState::write_gate_blocked`]），读面（含 get_approval）放行。
    pub(crate) entitlement: EntitlementArc,
    limits: ToolLimits,
    whitelist: ConnectionWhitelist,
}

impl ToolState {
    pub(crate) fn new(
        pool: SqlitePool,
        credential_key: CredentialKey,
        entitlement: EntitlementArc,
        limits: ToolLimits,
        whitelist: ConnectionWhitelist,
    ) -> Self {
        Self { pool, credential_key, entitlement, limits, whitelist }
    }

    /// D1 写门（写门读放口径）：Gated 时返回静态拒因（文案会进 mcp_audit
    /// 与回给 agent，保持无变量插值）；不回显 GatedReason——与 automation
    /// 门（ADR-0002 v1-C-2）同取舍，客户端从 `/api/entitlement` 读细节。
    /// Trial/Licensed（含 embedded 合成 Licensed）返回 None 全放行。
    pub(crate) fn write_gate_blocked(&self) -> Option<String> {
        if matches!(
            &**self.entitlement.load(),
            dbmaster_license::EntitlementState::Gated { .. }
        ) {
            Some(
                "ENTITLEMENT_GATED: server license is gated — activate or renew \
                 to use write tools (read tools remain available)"
                    .to_string(),
            )
        } else {
            None
        }
    }

    /// list_connections 的输出过滤（应用在安全投影之后——投影裁键、白名
    /// 单裁行，两个契约互不掺和）。
    fn visible_summaries(
        &self,
        conns: Vec<meta::ConnectionSummary>,
    ) -> Vec<meta::ConnectionSummary> {
        conns
            .into_iter()
            .filter(|c| self.whitelist.allows(&c.id, &c.name))
            .collect()
    }

    /// 连接级工具（list_databases / list_tables / describe_table /
    /// read_query / submit_write / execute_write 白名单复检）的同一过滤点：
    /// 白名单外连接在触达目标库之前拒绝（防 agent 持旧 id / 探测绕过
    /// list_connections 的过滤）。未知 id 放行到底层，由 metadata /
    /// read_query 给出统一 NOT_FOUND 文案。
    pub(crate) async fn ensure_connection_allowed(&self, conn_id: &str) -> Result<(), String> {
        if self.whitelist.entries.is_empty() {
            return Ok(());
        }
        let conns = meta::list_connection_summaries(&self.pool).await
            .map_err(|e| format!("{}: {}", e.code, e.message))?;
        match conns.iter().find(|c| c.id == conn_id) {
            Some(c) if self.whitelist.allows(&c.id, &c.name) => Ok(()),
            Some(_) => Err(
                "CONNECTION_NOT_ALLOWED: connection is not exposed over MCP \
                 (not in mcp.allowed_connections)"
                    .to_string(),
            ),
            None => Ok(()),
        }
    }
}

// ── 身份提取 ──

/// 从当次请求的 extensions 取 guard 注入的 Claims（rmcp 把
/// `http::request::Parts` 透传进 RequestContext.extensions）。
fn caller_claims(context: &RequestContext<RoleServer>) -> Option<Claims> {
    context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Claims>())
        .cloned()
}

// ── 参数解析 ──

fn arg_str(args: &JsonObject, name: &str) -> Result<Option<String>, String> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(format!("argument '{name}' must be a string, got {other}")),
    }
}

/// 整数参数（MCP 数字是 f64 编码，取 u64 域内的整数值）。
fn arg_u64(args: &JsonObject, name: &str) -> Result<Option<u64>, String> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("argument '{name}' must be a non-negative integer")),
        Some(other) => Err(format!("argument '{name}' must be an integer, got {other}")),
    }
}

pub(crate) fn require_str(args: &JsonObject, name: &str) -> Result<String, String> {
    arg_str(args, name)?
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("missing required argument '{name}'"))
}

// ── 分发入口（handler::call_tool 调用）──

/// 执行一次 tools/call。返回 Ok(结果)——业务失败也在结果里（isError=true），
/// 并落 tool_call 审计行（status ok/error，error 列只放短原因）。
pub(crate) async fn dispatch(
    state: &ToolState,
    request: CallToolRequestParams,
    context: &RequestContext<RoleServer>,
) -> CallToolResult {
    let tool = request.name.to_string();
    let user = caller_claims(context);

    let result = execute(state, &tool, request.arguments.as_ref(), user.as_ref()).await;

    // tool_call 审计：每次调用一行，error 只放短原因（无 SQL/数据/PII）。
    let audit_user = user.as_ref().map(|c| c.sub.as_str());
    match &result {
        Ok(value) => {
            log_mcp_event(&state.pool, audit_user, McpAuditAction::ToolCall, Some(&tool), None).await;
            CallToolResult::structured(value.clone())
        }
        Err(msg) => {
            let reason: String = msg.chars().take(200).collect();
            log_mcp_event(
                &state.pool,
                audit_user,
                McpAuditAction::ToolCall,
                Some(&tool),
                Some(&reason),
            )
            .await;
            CallToolResult::error(vec![ContentBlock::text(json!({
                "error": { "code": "TOOL_ERROR", "message": msg }
            }).to_string())])
        }
    }
}

/// 无凭证身份 → 拒绝执行（防御：guard 已挡 401，此处兜底扩展链路缺失的场景，
/// fail-closed 而非放行）。写路径三工具（write.rs）需要 Claims 定提交者身份。
async fn execute(
    state: &ToolState,
    tool: &str,
    args: Option<&JsonObject>,
    user: Option<&Claims>,
) -> Result<Value, String> {
    let Some(user) = user else {
        return Err("unauthenticated tool call (no caller identity on request)".to_string());
    };
    let empty = JsonObject::new();
    let args = args.unwrap_or(&empty);

    match tool {
        TOOL_LIST_CONNECTIONS => {
            let conns = meta::list_connection_summaries(&state.pool).await
                .map_err(|e| format!("{}: {}", e.code, e.message))?;
            Ok(json!({ "connections": state.visible_summaries(conns) }))
        }
        TOOL_LIST_DATABASES => {
            let conn_id = require_str(args, "connection_id").map_err(bad_request)?;
            state.ensure_connection_allowed(&conn_id).await?;
            let dbs = meta::list_databases(&state.pool, &state.credential_key, &conn_id).await
                .map_err(|e| format!("{}: {}", e.code, e.message))?;
            Ok(json!({ "connection_id": conn_id, "databases": dbs }))
        }
        TOOL_LIST_TABLES => {
            let conn_id = require_str(args, "connection_id").map_err(bad_request)?;
            state.ensure_connection_allowed(&conn_id).await?;
            let db = arg_str(args, "database").map_err(bad_request)?;
            let tables = meta::list_tables(&state.pool, &state.credential_key, &conn_id, db.as_deref()).await
                .map_err(|e| format!("{}: {}", e.code, e.message))?;
            Ok(json!({ "connection_id": conn_id, "tables": tables }))
        }
        TOOL_DESCRIBE_TABLE => {
            let conn_id = require_str(args, "connection_id").map_err(bad_request)?;
            state.ensure_connection_allowed(&conn_id).await?;
            let table = require_str(args, "table").map_err(bad_request)?;
            let db = arg_str(args, "database").map_err(bad_request)?;
            let desc = meta::describe_table(&state.pool, &state.credential_key, &conn_id, db.as_deref(), &table).await
                .map_err(|e| format!("{}: {}", e.code, e.message))?;
            serde_json::to_value(desc).map_err(|e| format!("serialization failed: {e}"))
        }
        TOOL_READ_QUERY => run_read_query(state, args).await,
        // T19 — 审批制写路径（实现见 write.rs；均要求认证 Claims）。
        crate::write::TOOL_SUBMIT_WRITE => crate::write::submit_write(state, args, user).await,
        crate::write::TOOL_GET_APPROVAL => crate::write::get_approval(state, args, user).await,
        crate::write::TOOL_EXECUTE_WRITE => crate::write::execute_write(state, args, user).await,
        other => Err(format!("unknown tool '{other}'")),
    }
}

/// read_query：SELECT-only 强制（T05 分级）+ 单语句约束 + 服务端行限/超时。
/// 拒绝消息带 risk 等级与静态原因（无 SQL 明文——消息会进审计与回给 agent）。
async fn run_read_query(state: &ToolState, args: &JsonObject) -> Result<Value, String> {
    let conn_id = require_str(args, "connection_id").map_err(bad_request)?;
    let sql = require_str(args, "sql").map_err(bad_request)?;
    let db = arg_str(args, "database").map_err(bad_request)?;
    let max_rows = arg_u64(args, "max_rows").map_err(bad_request)?;

    // ── 白名单门（授权先于内容分析：不为不可用的连接花解析）──
    state.ensure_connection_allowed(&conn_id).await?;

    // ── 风险门（先于一切目标库 IO；fail-closed 由 risk.rs 保证）──
    let verdict = crate::risk::classify(&sql);
    if !verdict.is_read_only() {
        return Err(format!(
            "NOT_READ_ONLY: read_query executes read-only SQL only (risk class: {}); reasons: {}",
            verdict.class.as_str(),
            verdict.reasons.join("; "),
        ));
    }
    if crate::risk::statement_count(&sql) != 1 {
        return Err(
            "MULTI_STATEMENT: send exactly one SQL statement per read_query call".to_string(),
        );
    }

    // ── 行限：默认 500，钳到 Config 上限（超限静默钳制，truncated 会自证）──
    let limit = max_rows
        .map(|v| (v as usize).clamp(1, state.limits.read_query_max_rows))
        .unwrap_or(READ_QUERY_DEFAULT_ROWS)
        .min(state.limits.read_query_max_rows);
    let timeout = std::time::Duration::from_secs(state.limits.read_query_timeout_secs as u64);

    dbmaster_automation::read_query::run_read_query(
        &state.pool,
        &state.credential_key,
        &conn_id,
        db.as_deref(),
        &sql,
        limit,
        timeout,
    )
    .await
    .map_err(|e| format!("{}: {}", e.code, e.message))
}

/// 参数错误保持稳定形态（客户端 bug，越早暴露越好）。
pub(crate) fn bad_request(msg: String) -> String {
    format!("INVALID_ARGUMENT: {msg}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_definitions_cover_tier1_surface() {
        let tools = tool_definitions();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert_eq!(
            names,
            vec![
                TOOL_LIST_CONNECTIONS,
                TOOL_LIST_DATABASES,
                TOOL_LIST_TABLES,
                TOOL_DESCRIBE_TABLE,
                TOOL_READ_QUERY,
                crate::write::TOOL_SUBMIT_WRITE,
                crate::write::TOOL_GET_APPROVAL,
                crate::write::TOOL_EXECUTE_WRITE,
            ]
        );
        // 每个工具都有非空描述。
        for t in &tools {
            assert!(t.description.as_deref().is_some_and(|d| !d.is_empty()));
        }
        // 读面 5 工具 + get_approval（纯读）readOnlyHint=true；两个会改状态
        // 的写工具（submit 落审批行、execute 执行 DDL）必须为 false。
        let read_only_of = |t: &Tool| t.annotations.as_ref().and_then(|a| a.read_only_hint);
        for t in &tools[..5] {
            assert_eq!(read_only_of(t), Some(true));
        }
        let by_name = |n: &str| tools.iter().find(|t| t.name == n).expect(n);
        assert_eq!(read_only_of(by_name(crate::write::TOOL_GET_APPROVAL)), Some(true));
        for n in [crate::write::TOOL_SUBMIT_WRITE, crate::write::TOOL_EXECUTE_WRITE] {
            let t = by_name(n);
            assert_eq!(read_only_of(t), Some(false), "{n} 修改状态，readOnlyHint 必须 false");
        }
        // execute_write 声明幂等（乐观锁保证）且具破坏性（已审批 DDL 可能
        // DROP/TRUNCATE）——MCP 客户端据此提示用户。
        let exec = by_name(crate::write::TOOL_EXECUTE_WRITE);
        assert_eq!(
            exec.annotations.as_ref().and_then(|a| a.idempotent_hint),
            Some(true)
        );
        assert_eq!(
            exec.annotations.as_ref().and_then(|a| a.destructive_hint),
            Some(true)
        );
        // 带参工具声明了 required。
        let describe = &tools[3];
        let required = describe
            .input_schema
            .get("required")
            .and_then(|v| v.as_array())
            .expect("describe_table required");
        assert!(required.iter().any(|v| v == "connection_id"));
        assert!(required.iter().any(|v| v == "table"));
        let submit = by_name(crate::write::TOOL_SUBMIT_WRITE);
        let required = submit
            .input_schema
            .get("required")
            .and_then(|v| v.as_array())
            .expect("submit_write required");
        assert!(required.iter().any(|v| v == "connection_id"));
        assert!(required.iter().any(|v| v == "sql"));
    }

    #[test]
    fn arg_str_type_checks() {
        let mut args = JsonObject::new();
        args.insert("a".into(), json!("x"));
        args.insert("n".into(), json!(1));
        assert_eq!(arg_str(&args, "missing").unwrap(), None);
        assert_eq!(arg_str(&args, "a").unwrap().as_deref(), Some("x"));
        assert!(arg_str(&args, "n").is_err());
    }

    // T07 — read_query 的 max_rows（MCP 数字经 f64 编码）。
    #[test]
    fn arg_u64_accepts_integers_rejects_others() {
        let mut args = JsonObject::new();
        args.insert("i".into(), json!(500));
        args.insert("big".into(), json!(4_000_000_000u64));
        args.insert("f".into(), json!(1.5));
        args.insert("s".into(), json!("500"));
        args.insert("nul".into(), Value::Null);
        assert_eq!(arg_u64(&args, "missing").unwrap(), None);
        assert_eq!(arg_u64(&args, "nul").unwrap(), None);
        assert_eq!(arg_u64(&args, "i").unwrap(), Some(500));
        assert_eq!(arg_u64(&args, "big").unwrap(), Some(4_000_000_000));
        assert!(arg_u64(&args, "f").is_err(), "小数拒绝");
        assert!(arg_u64(&args, "s").is_err(), "字符串拒绝");
    }

    // T08 — 白名单谓词（单一过滤点的判定核心）。
    #[test]
    fn whitelist_empty_allows_everything() {
        let wl = ConnectionWhitelist::default();
        assert!(wl.allows("conn-1", "prod-main"));
        assert!(wl.allows("any", "thing"));
    }

    #[test]
    fn whitelist_matches_by_id_or_name_exactly() {
        let wl = ConnectionWhitelist::new(vec![
            "conn-9".to_string(),     // 按 id 放行
            "analytics".to_string(),  // 按 name 放行
        ]);
        assert!(wl.allows("conn-9", "nightly-etl"), "id 命中");
        assert!(wl.allows("conn-2", "analytics"), "name 命中");
        assert!(!wl.allows("conn-9x", "nightly-etl"), "id 前缀不算命中");
        assert!(!wl.allows("conn-2", "analytics2"), "name 前缀不算命中");
        assert!(!wl.allows("conn-1", "prod-main"), "两键都不命中");
        // 大小写敏感（与连接 id/name 的存储形态一致，不做隐式折叠）。
        assert!(!wl.allows("conn-2", "Analytics"));
    }
}
