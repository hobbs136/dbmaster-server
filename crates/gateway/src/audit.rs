//! `gw_audit` writer（dbx-response T27 / migration 015）。
//!
//! Append-only 安全审计（网关面）：认证拒绝、限流拒绝、查询执行成败、
//! 连接注册/删除。纪律镜像 mcp_audit（migration 011 / mcp crate audit.rs）：
//!
//! 落库：`user_id`（JWT sub；未认证为 NULL）、`action`、`status`、`error`
//! （短摘要）、`at`。
//!
//! 硬规则（不落库）：token 本体、任何 SQL 文本、凭据、返回数据、PII。
//! `query_exec` 行的 error 列只存**稳定错误码**（CANCELLED/TIMEOUT/…），
//! 不存引擎 message（可能含标识符）。

use sqlx::SqlitePool;

/// 审计动作。序列化为 `action` 列的 wire 字符串（migration 015 枚举契约）。
#[derive(Debug, Clone, Copy)]
pub enum GwAuditAction {
    /// Bearer token 缺失/非法/过期 → 401。
    AuthRejected,
    /// per-user 滑动窗口耗尽 → 429。
    RateLimited,
    /// 一次查询执行（POST …/query）。error 列 = 稳定错误码（成功为 NULL）。
    QueryExec,
    /// 连接注册（POST /api/gw/connections，凭据入 vault）。
    ConnectionRegistered,
    /// 连接删除（DELETE /api/gw/connections/{id}）。
    ConnectionRemoved,
}

impl GwAuditAction {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::AuthRejected => "auth_rejected",
            Self::RateLimited => "rate_limited",
            Self::QueryExec => "query_exec",
            Self::ConnectionRegistered => "connection_registered",
            Self::ConnectionRemoved => "connection_removed",
        }
    }

    /// 不利事件（401/429）记 error；正常生命周期与成功查询记 ok
    /// （失败 query_exec 由非空 error 翻转）。
    fn default_status(&self) -> &'static str {
        match self {
            Self::AuthRejected | Self::RateLimited => "error",
            _ => "ok",
        }
    }
}

/// 追加一行审计。`error` 为已清洗短摘要（query_exec 传稳定错误码），
/// `user_id` 为 JWT sub 或 None。best-effort：审计写入失败不阻塞请求
/// （tracing error 是运维信号）。
pub async fn log_gw_event(
    pool: &SqlitePool,
    user_id: Option<&str>,
    action: GwAuditAction,
    error: Option<&str>,
) {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let err = error.map(truncate_bounded);
    let status = if err.is_none() { action.default_status() } else { "error" };
    // 全部参数绑定，注入面结构性不存在（同 mcp audit）。
    let result = sqlx::query(
        "INSERT INTO gw_audit (id, user_id, action, status, error, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(action.as_db_str())
    .bind(status)
    .bind(&err)
    .bind(&now)
    .execute(pool)
    .await;
    if let Err(e) = result {
        tracing::error!(action = action.as_db_str(), error = %e, "gw_audit insert failed");
    }
}

/// 限长（防灌表，同 mcp audit 的 500 上限）。
fn truncate_bounded(s: &str) -> String {
    const MAX: usize = 500;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(MAX).collect();
        format!("{truncated}…[truncated]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_wire_strings_stable() {
        // 与 migration 015 的枚举契约——不要重命名。
        assert_eq!(GwAuditAction::AuthRejected.as_db_str(), "auth_rejected");
        assert_eq!(GwAuditAction::RateLimited.as_db_str(), "rate_limited");
        assert_eq!(GwAuditAction::QueryExec.as_db_str(), "query_exec");
        assert_eq!(GwAuditAction::ConnectionRegistered.as_db_str(), "connection_registered");
        assert_eq!(GwAuditAction::ConnectionRemoved.as_db_str(), "connection_removed");
    }

    #[test]
    fn truncate_bounds_error_length() {
        let long = "x".repeat(600);
        let out = truncate_bounded(&long);
        assert!(out.chars().count() <= 500 + "…[truncated]".chars().count());
        assert!(out.ends_with("[truncated]"));
        assert_eq!(truncate_bounded("short"), "short");
    }
}
