//! MCP M2 写路径三工具（dbx-response T19 / 方案 M6）——**审批制**。
//!
//! 铁律：agent 只能**提交**（`submit_write`），人在客户端批准后才能执行
//! （`execute_write`）。审批载体完全复用 REST DDL 审批基建——`ddl_approvals`
//! 表（migrations 002 + 009）与 automation 的状态机词汇，不建新表、不改
//! REST 契约：
//!
//! - `submit_write`：白名单门 → 单语句约束 → risk 分级（写类是预期，**只
//!   记录不拦截**，等级/原因进返回）→ 落一行 pending（submitter_id=JWT
//!   sub，与 REST submit_approval 同款 INSERT）。
//! - `get_approval`：仅提交者本人可见（不存在与非本人统一 NOT_FOUND——
//!   防 agent 靠错误文案差异枚举他人 approval id）。
//! - `execute_write`：status 必须 approved（人在客户端批过）；幂等认领取
//!   `UPDATE ... WHERE exec_status='pending'` 乐观锁（并发双调用只有一次
//!   认领成功，输家读当前状态原样返回）；执行体复用 automation
//!   `execute_ddl_on_target_with_key`（与 REST「批准即执行」**同一实现**，
//!   DDL 白名单 / read_only / source_drift 守卫同源），终态落
//!   exec_status / executed_at / exec_error。
//!
//! 状态词汇（沿用 009 状态机，勿另造）：exec_status ∈ `pending` |
//! `executing` | `approved`（执行成功）| `failed`；status ∈ `pending` |
//! `approved` | `rejected` | `executing` | `failed`。执行失败与 REST 同款
//! 双列流转（status+exec_status 同变 'failed'）——重试需重新提交审批。
//!
//! 审计纪律：工具级错误文案全部为静态原因（无 SQL 明文——它们会进
//! mcp_audit 与回给 agent）；`execError` 是业务结果字段（db_handler redact
//! 后落 ddl_approvals），只进工具结果，不进 mcp_audit。
//!
//! D1 license 门（2026-08-27 拍板：**写门读放**）：`submit_write` 与
//! `execute_write` 在 Gated（Trial 到期/无有效 license）时拒绝（静态
//! `ENTITLEMENT_GATED` 文案，指引激活），门在参数校验之前；`get_approval`
//! 维持可见（visible-but-locked，与 automation 门 ADR-0002 v1-C-2 同哲
//! 学——AI 能看到却改不了，转化钩子在写路径）。embedded 合成 lifetime
//! Licensed、Trial/Licensed 全放行；门读 `ToolState` 持有的 ArcSwap，
//! `POST /api/license` 热换即时生效。

use dbmaster_automation::db_handler::execute_ddl_on_target_with_key;
use dbmaster_core::auth::jwt::Claims;
use rmcp::model::{JsonObject, Tool};
use serde_json::{json, Value};

use crate::tools::{bad_request, require_str, ToolState};

// ── 工具常量与定义（tools/list 契约）──

pub(crate) const TOOL_SUBMIT_WRITE: &str = "submit_write";
pub(crate) const TOOL_GET_APPROVAL: &str = "get_approval";
pub(crate) const TOOL_EXECUTE_WRITE: &str = "execute_write";

/// exec_status 的成功终态。009 状态机用 `'approved'` 表「执行成功」
/// （与 status 的 `'approved'` 同词）——沿用既有词汇，避免两套状态机漂移。
const EXEC_SUCCEEDED: &str = "approved";

/// 写路径工具构造（对齐 tools.rs 的 `tool()`，但注解按写语义给出：
/// readOnlyHint=false，destructive/idempotent 逐工具声明——MCP 客户端会
/// 据此提示用户）。name 需 'static——全部传 const。
fn write_tool(
    name: &'static str,
    title: &str,
    description: &str,
    input_schema: Value,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
) -> Tool {
    let mut t = Tool::default();
    t.name = name.into();
    t.title = Some(title.to_string());
    t.description = Some(std::borrow::Cow::Owned(description.to_string()));
    t.input_schema = crate::tools::schema(input_schema);
    let mut annotations = rmcp::model::ToolAnnotations::default();
    annotations.read_only_hint = Some(read_only);
    annotations.destructive_hint = Some(destructive);
    annotations.idempotent_hint = Some(idempotent);
    t.annotations = Some(annotations);
    t
}

/// T19 写路径工具面（顺序即 tools/list 返回序，接在 Tier-1 读面之后）。
pub(crate) fn tool_definitions() -> Vec<Tool> {
    vec![
        write_tool(
            TOOL_SUBMIT_WRITE,
            "Submit write for approval",
            "Submit ONE write statement for HUMAN APPROVAL — nothing is \
             executed at submit time. The statement lands in the dbmaster \
             approval queue (status=pending); a human must approve it in the \
             dbmaster client before execute_write can run it. Returns \
             approvalId (keep it) plus a risk assessment. The execution \
             backend accepts DDL only (CREATE/ALTER/DROP/TRUNCATE/RENAME); \
             data-modifying statements will be rejected at execution time. \
             Args: connection_id, sql.",
            json!({
                "type": "object",
                "properties": {
                    "connection_id": {
                        "type": "string",
                        "description": "Connection id from list_connections"
                    },
                    "sql": {
                        "type": "string",
                        "description": "A single write/DDL statement to be executed after human approval"
                    }
                },
                "required": ["connection_id", "sql"],
                "additionalProperties": false
            }),
            // 只落审批行，不触达目标库——不具破坏性；重复提交产生新审批
            // （语义上非幂等）。
            false, false, false,
        ),
        write_tool(
            TOOL_GET_APPROVAL,
            "Get approval status",
            "Get the current state of a write approval you submitted via \
             submit_write (only the submitter can see it). Returns status \
             (pending/approved/rejected/executing/failed), execStatus \
             (pending/executing/approved/failed — 'approved' means executed \
             successfully), execError after a failed execution, risk, and \
             timestamps. Poll this while waiting for the human decision. \
             Args: approval_id.",
            json!({
                "type": "object",
                "properties": {
                    "approval_id": {
                        "type": "string",
                        "description": "approvalId returned by submit_write"
                    }
                },
                "required": ["approval_id"],
                "additionalProperties": false
            }),
            // 纯读本人审批行，不改任何状态——按只读标注。
            true, false, true,
        ),
        write_tool(
            TOOL_EXECUTE_WRITE,
            "Execute approved write",
            "Execute an approval that a human has ALREADY approved — call \
             get_approval first and only execute when status is 'approved' \
             (otherwise fails with APPROVAL_NOT_APPROVED). Idempotent: if \
             execution already started or finished, returns the current \
             execStatus without executing again. Only the submitter can \
             execute. Args: approval_id.",
            json!({
                "type": "object",
                "properties": {
                    "approval_id": {
                        "type": "string",
                        "description": "approvalId returned by submit_write"
                    }
                },
                "required": ["approval_id"],
                "additionalProperties": false
            }),
            // 执行的是已审批 DDL（可能 DROP/TRUNCATE）——具破坏性；幂等由
            // 乐观锁保证（重复调用返回当前状态不重复执行）。
            false, true, true,
        ),
    ]
}

// ── ddl_approvals 行投影 ──

/// 审批行投影（002 + 009 列子集，工具面只需这些；submitter 过滤在
/// WHERE 里做，不单独投影）。
#[derive(sqlx::FromRow)]
struct ApprovalRow {
    id: String,
    ddl_sql: String,
    target_db_id: String,
    status: String,
    exec_status: String,
    exec_error: Option<String>,
    created_at: String,
    resolved_at: Option<String>,
}

/// 按 id 取**本人**提交的审批行。不存在与非本人统一 NOT_FOUND 文案
/// （防探测）；DB 故障给静态文案，细节走 tracing。
async fn load_own_approval(
    state: &ToolState,
    approval_id: &str,
    claims: &Claims,
) -> Result<ApprovalRow, String> {
    let row = sqlx::query_as::<_, ApprovalRow>(
        "SELECT id, ddl_sql, target_db_id, status, exec_status,
                exec_error, created_at, resolved_at
         FROM ddl_approvals WHERE id = ?1 AND submitter_id = ?2",
    )
    .bind(approval_id)
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "ddl_approvals load failed");
        "DB_ERROR: could not read the approval".to_string()
    })?;
    row.ok_or_else(|| {
        "NOT_FOUND: approval not found (unknown id, or not submitted by you)".to_string()
    })
}

/// 幂等短路返回：{approvalId, execStatus, execError?}（认领输家/已终态时）。
async fn current_exec_state(state: &ToolState, approval_id: &str) -> Result<Value, String> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT exec_status, exec_error FROM ddl_approvals WHERE id = ?1",
    )
    .bind(approval_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "ddl_approvals exec state reload failed");
        "DB_ERROR: could not read the approval state".to_string()
    })?;
    let Some((exec_status, exec_error)) = row else {
        return Err("NOT_FOUND: approval not found (unknown id, or not submitted by you)".to_string());
    };
    let mut out = json!({ "approvalId": approval_id, "execStatus": exec_status });
    if let Some(err) = exec_error {
        out["execError"] = json!(err);
    }
    Ok(out)
}

// ── 工具实现（tools::execute 分发）──

/// submit_write：提交写语句进审批队列（不执行）。校验链与 read_query 同款
/// 授权顺序：白名单 → 内容分析（风险分级 + 单语句）→ 落库。
pub(crate) async fn submit_write(
    state: &ToolState,
    args: &JsonObject,
    claims: &Claims,
) -> Result<Value, String> {
    // D1 写门（写门读放）：Gated 拒——先于一切参数/白名单/内容分析，
    // 不为 gated 实例花解析（与 automation mutation 门的顺序一致）。
    if let Some(err) = state.write_gate_blocked() {
        return Err(err);
    }
    let conn_id = require_str(args, "connection_id").map_err(bad_request)?;
    let sql = require_str(args, "sql").map_err(bad_request)?;

    // ── 白名单门（授权先于内容分析：不为不可用的连接花解析）──
    state.ensure_connection_allowed(&conn_id).await?;

    // ── 风险门（先于一切目标库 IO）：写类是预期、只记录不拦截；纯读语句
    //    不该走审批路径——静态拒因引导回 read_query。──
    let verdict = crate::risk::classify(&sql);
    if verdict.is_read_only() {
        return Err(
            "READ_ONLY_SQL: statement is read-only — use read_query instead \
             (no approval needed)"
                .to_string(),
        );
    }
    // 单语句约束（解析失败 statement_count=0 同样被拒——fail-closed 与
    // risk.rs 同一解析路径）。
    if crate::risk::statement_count(&sql) != 1 {
        return Err(
            "MULTI_STATEMENT: submit exactly one SQL statement per submit_write call"
                .to_string(),
        );
    }

    // ── 目标连接必须存在（FK 目标；给统一 NOT_FOUND 而非裸外键错误）──
    let known: Option<(String,)> =
        sqlx::query_as("SELECT id FROM database_connections WHERE id = ?1")
            .bind(&conn_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "connection existence check failed");
                "DB_ERROR: could not verify the connection".to_string()
            })?;
    if known.is_none() {
        return Err(format!(
            "NOT_FOUND: connection '{conn_id}' not found (check list_connections)"
        ));
    }

    // ── 落审批行（与 REST submit_approval 同款 INSERT；submitter 取当次
    //    请求的 JWT sub，status/exec_status 走默认 pending）──
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let insert = sqlx::query(
        "INSERT INTO ddl_approvals (id, ddl_sql, target_db_id, submitter_id, status, created_at)
         VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
    )
    .bind(&id)
    .bind(&sql)
    .bind(&conn_id)
    .bind(&claims.sub)
    .bind(&now)
    .execute(&state.pool)
    .await;
    if let Err(e) = insert {
        tracing::warn!(error = %e, "submit_write insert failed");
        return Err("SUBMIT_FAILED: could not create the approval".to_string());
    }

    Ok(json!({
        "approvalId": id,
        "status": "pending",
        "risk": { "level": verdict.class.as_str(), "reasons": verdict.reasons },
    }))
}

/// get_approval：读本人审批行（状态机字段 + 现算 risk——表无 risk 列，
/// 不改 schema，classify 是纯函数、确定性）。
pub(crate) async fn get_approval(
    state: &ToolState,
    args: &JsonObject,
    claims: &Claims,
) -> Result<Value, String> {
    let approval_id = require_str(args, "approval_id").map_err(bad_request)?;
    let row = load_own_approval(state, &approval_id, claims).await?;

    let verdict = crate::risk::classify(&row.ddl_sql);
    let mut out = json!({
        "approvalId": row.id,
        "status": row.status,
        "execStatus": row.exec_status,
        "risk": { "level": verdict.class.as_str(), "reasons": verdict.reasons },
        "createdAt": row.created_at,
    });
    if let Some(v) = row.resolved_at {
        out["resolvedAt"] = json!(v);
    }
    if let Some(err) = row.exec_error {
        out["execError"] = json!(err);
    }
    Ok(out)
}

/// execute_write：执行**已审批**的写语句（幂等）。
///
/// 校验链：存在且本人 → status=approved → 白名单复检（提交与执行之间
/// 配置可能变化）→ 乐观锁认领（exec_status pending→executing，并发双调用
/// 只执行一次）→ 同步执行到终态（agent 一次调用拿到结果；REST approve 是
/// spawn+202，两侧共用状态词汇与执行实现）。
pub(crate) async fn execute_write(
    state: &ToolState,
    args: &JsonObject,
    claims: &Claims,
) -> Result<Value, String> {
    // D1 写门（写门读放）：Gated 拒——先于审批行读取，gated 实例连已批
    // 审批的存在性都不触达（防靠错误文案差异探测）。
    if let Some(err) = state.write_gate_blocked() {
        return Err(err);
    }
    let approval_id = require_str(args, "approval_id").map_err(bad_request)?;
    let row = load_own_approval(state, &approval_id, claims).await?;

    // ── 审批门：只有人已批准（status=approved）的才能执行。执行失败的
    //    行 status 已流转 'failed'——同样被拒，重试走重新提交。──
    if row.status != "approved" {
        return Err(format!(
            "APPROVAL_NOT_APPROVED: approval status is '{}' — a human must approve it \
             (in the dbmaster client) before execute_write can run",
            row.status
        ));
    }

    // ── 白名单复检（授权是单一过滤点，执行时仍要过）──
    state.ensure_connection_allowed(&row.target_db_id).await?;

    // ── 幂等认领：pending → executing 只允许一次；输家（并发在途或已
    //    终态）读当前状态原样返回，不重复执行。──
    let now = chrono::Utc::now().to_rfc3339();
    let claim = sqlx::query(
        "UPDATE ddl_approvals SET exec_status = 'executing', executed_at = ?1
         WHERE id = ?2 AND exec_status = 'pending'",
    )
    .bind(&now)
    .bind(&approval_id)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "execute claim failed");
        "EXECUTE_FAILED: could not claim the approval for execution".to_string()
    })?;
    if claim.rows_affected() == 0 {
        return current_exec_state(state, &approval_id).await;
    }

    // ── 执行体：automation 与 REST「批准即执行」同一实现（DDL 白名单、
    //    read_only / source_drift / ClickHouse 守卫同源；错误已 redact）。──
    let exec = execute_ddl_on_target_with_key(
        &state.pool,
        &state.credential_key,
        &row.target_db_id,
        &row.ddl_sql,
    )
    .await;

    // ── 终态落库（对齐 REST approve 的写法：成功 status+exec_status 同为
    //    'approved'，失败同为 'failed' + exec_error）。落库失败只告警不
    //    谎报——DDL 结果对 agent 是权威事实（REST 同款取舍）。──
    match exec {
        Ok(()) => {
            let persist = sqlx::query(
                "UPDATE ddl_approvals SET status = 'approved', exec_status = 'approved' \
                 WHERE id = ?1",
            )
            .bind(&approval_id)
            .execute(&state.pool)
            .await;
            if let Err(e) = persist {
                tracing::error!(error = %e, approval_id, "exec terminal state persist failed");
            }
            Ok(json!({ "approvalId": approval_id, "execStatus": EXEC_SUCCEEDED }))
        }
        Err(err) => {
            let persist = sqlx::query(
                "UPDATE ddl_approvals
                 SET status = 'failed', exec_status = 'failed', exec_error = ?1
                 WHERE id = ?2",
            )
            .bind(&err)
            .bind(&approval_id)
            .execute(&state.pool)
            .await;
            if let Err(e) = persist {
                tracing::error!(error = %e, approval_id, "exec terminal state persist failed");
            }
            Ok(json!({
                "approvalId": approval_id,
                "execStatus": "failed",
                "execError": err,
            }))
        }
    }
}
