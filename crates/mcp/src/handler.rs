//! MCP ServerHandler 实现（T03 骨架 → T06 起接入工具面）。

use std::future::Future;

use dbmaster_core::server::CredentialKey;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult, PaginatedRequestParams,
    ServerInfo,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::ServerHandler;
use sqlx::SqlitePool;

use crate::tools::{self, ToolState};

/// dbmaster MCP 服务身份与协议能力声明。
///
/// T06：`list_tools`/`call_tool` 落地 4 个 Tier-1 元数据工具（tools 能力位
/// 开启，client discover 可见）；工具执行经 `tools::dispatch`（automation
/// metadata 同源后端 + tool_call 审计）。
///
/// TODO(T07)：read_query（消费 risk.rs 的 SELECT-only 强制 + 行限 + 超时）。
///
/// D1 license 门（2026-08-27 拍板：写门读放）——会话级**不**设门
/// （initialize/tools/list 正常，AI agent 可发现全部工具）；门在工具级：
/// Gated 实例 `submit_write`/`execute_write` 拒（ENTITLEMENT_GATED），
/// 读面（含 get_approval）放行。embedded 合成 Licensed 自动全放行。
#[derive(Clone)]
pub struct DbMasterMcp {
    /// 工具层执行上下文：server 库池 + 凭据钥匙（工厂闭包逐会话克隆）。
    state: ToolState,
}

impl DbMasterMcp {
    pub fn new(
        pool: SqlitePool,
        credential_key: CredentialKey,
        entitlement: tools::EntitlementArc,
        limits: tools::ToolLimits,
        whitelist: tools::ConnectionWhitelist,
    ) -> Self {
        Self { state: ToolState::new(pool, credential_key, entitlement, limits, whitelist) }
    }
}

impl ServerHandler for DbMasterMcp {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo 为 #[non_exhaustive]：default 后改 pub 字段。
        // 名字固定 dbmaster-server（对外身份），版本取 workspace version。
        // capabilities.tools 从 T06 起开启（discover/list_tools 均可见）。
        let mut info = ServerInfo::default();
        info.server_info = Implementation::new("dbmaster-server", env!("CARGO_PKG_VERSION"));
        info.capabilities = rmcp::model::ServerCapabilities::builder()
            .enable_tools()
            .build();
        info
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + '_ {
        // 4 个工具远小于一页，无分页必要（cursor 留空 = 列表终结）。
        // SEP-2549（ttlMs/cacheScope）：rmcp 默认构造省略这两个字段，但部分
        // 客户端（ZCode 实配发现，2026-08-16）对 tools/list 结果启用严格
        // schema 视其为必填——补上。工具面只随 server 版本变化、对所有用户
        // 一致：Public + 5 分钟是保守且安全的缓存策略。
        let result = ListToolsResult::with_all_items(tools::tool_definitions())
            .with_ttl_ms(300_000)
            .with_cache_scope(rmcp::model::CacheScope::Public);
        std::future::ready(Ok(result))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, rmcp::ErrorData>> + '_ {
        // 工具执行（含目标库往返）是真实异步——async 块即返回的 Future。
        async move {
            let result = tools::dispatch(&self.state, request, &context).await;
            Ok(result.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limits() -> tools::ToolLimits {
        tools::ToolLimits {
            read_query_max_rows: 10000,
            read_query_timeout_secs: 30,
        }
    }

    #[tokio::test]
    async fn server_info_identifies_dbmaster_and_advertises_tools() {
        // connect_lazy 也要 Tokio 上下文（池内部 spawn）——放 tokio::test 里。
        let pool = SqlitePool::connect_lazy("sqlite::memory:").expect("lazy pool");
        let info = DbMasterMcp::new(
            pool,
            [0u8; 32],
            std::sync::Arc::new(arc_swap::ArcSwap::from(std::sync::Arc::new(
                dbmaster_license::EntitlementState::Trial {
                    expires_at: chrono::Utc::now() + chrono::Duration::days(14),
                },
            ))),
            test_limits(),
            tools::ConnectionWhitelist::default(),
        )
        .get_info();
        assert_eq!(info.server_info.name.as_str(), "dbmaster-server");
        assert!(!info.server_info.version.is_empty());
        // T06：tools 能力位开启（否则 client 不 discover 工具面）。
        assert!(
            info.capabilities.tools.is_some(),
            "tools capability must be advertised"
        );
    }
}
