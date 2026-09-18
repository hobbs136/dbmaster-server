//! dbmaster-mcp — MCP 端点（dbx-response 举措一 M1 / T03；ADR-0005 §2.2）。
//!
//! 职责边界：本 crate 是 MCP 协议层（握手/工具注册/风险分级/会话），DB 能力
//! 全部来自 server 侧驱动层（网关 API 同源），不在本 crate 内直连数据库。
//!
//! 传输：v1 只做 Streamable HTTP（挂现有 Axum router，同端口）；stdio 桥是
//! 远期可选项（方案 §1.3）。
//!
//! 挂载方式（src/lib.rs of dbmaster-server）：
//! `Router::new().merge(core).merge(automation).merge(dbmaster_mcp::router(cfg, pool))`

pub mod audit;
pub(crate) mod auth;
pub mod handler;
pub mod risk;
pub(crate) mod tokens;
pub(crate) mod tools;
// T19 — 审批制写路径三工具（submit_write / get_approval / execute_write）。
pub(crate) mod write;

/// D1 写门的 entitlement 句柄（tools 模块私有，类型经根 re-export 供
/// server 组合层与集成测试引用）。
pub use tools::EntitlementArc;

use std::sync::Arc;

use axum::{middleware, routing::{delete, post}, Router};
use dbmaster_core::config::Config;
use dbmaster_core::server::CredentialKey;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use sqlx::SqlitePool;

/// MCP 端点路径（Streamable HTTP：POST=消息，GET=SSE 流，DELETE=会话结束）。
pub const MCP_ENDPOINT: &str = "/mcp";

/// 构建 MCP 子 router：`/mcp` 端点 + `/api/mcp/tokens` 管理接口，由 server
/// 组合层 merge 进主 router。
///
/// `/mcp` 会话管理用进程内 `LocalSessionManager`（单实例部署语义）。
///
/// 认证/限流/审计（T04）：`auth::guard` 中间件在请求进入 rmcp service 前执行——
/// Bearer 凭证双 scheme（access JWT 或 `dbm_mcp_*` 长效专用 token，401）、
/// per-user 滑动窗口限流（429，上限 `Config::mcp_rate_limit_per_minute`）、
/// 安全事件落 `mcp_audit` 表（无 token/SQL 明文）。embedded 与远程模式同一
/// token 体系，两模式共用此路径。
///
/// 工具面（T06+T07）：4 个 Tier-1 元数据工具 + read_query（SELECT-only
/// 强制走 risk.rs，行限默认 500/上限 `Config::mcp_read_query_max_rows`，
/// 超时 `Config::mcp_read_query_timeout_secs`）。`credential_key` 供工具层
/// 解密目标库连接凭据（automation metadata/read_query 同源后端）；每次
/// tools/call 落 tool_call 审计行。
///
/// `/api/mcp/tokens`（长效 token 管理，用户拍板 2026-08-15）用 core `Claims`
/// extractor 鉴权——与 core router 同样注入 `Arc<Config>` 到 extensions。
///
/// D1 license 门（2026-08-27 拍板：**写门读放**）：Gated（Trial 到期/无有
/// 效 license）实例的 `submit_write`/`execute_write` 返回 ENTITLEMENT_GATED，
/// 会话建立与读工具（含 get_approval）维持可用（visible-but-locked，与
/// automation 门 ADR-0002 v1-C-2 同哲学）；embedded 合成 Licensed、Trial/
/// Licensed 全放行。entitlement 与 core AppState 持同一 ArcSwap——
/// `POST /api/license` 热换即时生效（长会话每次工具调用读最新态）。
pub fn router(
    config: Arc<Config>,
    pool: SqlitePool,
    credential_key: CredentialKey,
    entitlement: tools::EntitlementArc,
) -> Router {
    let guard = auth::McpAuthGuard::new(config.clone(), pool.clone());
    let handler_pool = pool.clone();
    let limits = tools::ToolLimits {
        read_query_max_rows: config.mcp_read_query_max_rows as usize,
        read_query_timeout_secs: config.mcp_read_query_timeout_secs,
    };
    // T08 — 连接白名单（空 = MCP 面可见全部，对齐 /api/connections）。
    let whitelist = tools::ConnectionWhitelist::new(config.mcp_allowed_connections.clone());
    // rmcp 的 DNS-rebinding 防护默认只放行回环 Host——LAN/公网部署必须显式
    // 配置（空列表 = 放行全部；见 Config::mcp_allowed_hosts 的安全取舍注记）。
    let mut http_config = StreamableHttpServerConfig::default();
    http_config.allowed_hosts = config.mcp_allowed_hosts.clone();
    let service = StreamableHttpService::new(
        move || {
            Ok(handler::DbMasterMcp::new(
                handler_pool.clone(),
                credential_key,
                entitlement.clone(),
                limits.clone(),
                whitelist.clone(),
            ))
        },
        Arc::new(LocalSessionManager::default()),
        http_config,
    );
    let endpoint = Router::new()
        .route_service(MCP_ENDPOINT, service)
        .layer(middleware::from_fn_with_state(guard, auth::guard));

    let config_for_extensions = config;
    let management = Router::new()
        .route(
            "/api/mcp/tokens",
            post(tokens::create).get(tokens::list),
        )
        .route("/api/mcp/tokens/:id", delete(tokens::revoke))
        .with_state(tokens::TokensState { pool })
        .layer(middleware::from_fn(
            move |mut req: axum::http::Request<axum::body::Body>,
                  next: middleware::Next| {
                let cfg = config_for_extensions.clone();
                async move {
                    req.extensions_mut().insert(cfg);
                    next.run(req).await
                }
            },
        ));

    management.merge(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn router_builds() {
        // 骨架冒烟：router 可构建（service_factory/session_manager/config 类型对齐）。
        let config = Arc::new(test_config());
        let pool = test_pool().await;
        let entitlement = Arc::new(arc_swap::ArcSwap::from(Arc::new(
            dbmaster_license::EntitlementState::Licensed {
                license: dbmaster_license::LicenseV2 {
                    email: "test@local".into(),
                    expires_at: None,
                    instance_id: "test".into(),
                    issued_at: "2026-01-01T00:00:00Z".into(),
                    license_type: "yearly".into(),
                },
                expires_at: None,
            },
        )));
        let _ = router(config, pool, [1u8; 32], entitlement);
    }

    pub(crate) fn test_config() -> Config {
        Config {
            host: "127.0.0.1".into(),
            port: 0,
            jwt_secret: "test-mcp-jwt-secret".into(),
            jwt_refresh_secret: "test-mcp-refresh-secret".into(),
            database_url: "sqlite::memory:".into(),
            funnel_lite_enabled: false,
            drift_default_interval_mins: 30,
            drift_webhook_timeout_secs: 10,
            data_sync_default_batch_size: 10000,
            data_sync_max_concurrency: 1,
            mcp_rate_limit_per_minute: 120,
            // T07 — read_query 行限上限 / 超时（测试默认值与生产默认一致）。
            mcp_read_query_max_rows: 10000,
            mcp_read_query_timeout_secs: 30,
            mcp_allowed_hosts: Vec::new(),
            mcp_allowed_connections: Vec::new(),
            gw_rate_limit_per_minute: 600,
            gw_query_default_rows: 500,
            gw_query_max_rows: 10000,
            gw_query_timeout_secs: 30,
            // reports-M1 — 与生产默认一致（tools_write.rs 同款补齐）。
            slow_query_enabled: true,
            slow_query_threshold_ms: 1000,
            slow_query_store_sql: true,
            slow_query_retention_days: 14,
            slow_query_cap_per_digest_per_hour: 20,
        }
    }

    pub(crate) async fn test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.expect("test pool");
        sqlx::query(
            // 与 migrations 011+013 对齐（tool 列 T06 起 tool_call 行使用）。
            "CREATE TABLE mcp_audit (
                id TEXT PRIMARY KEY, user_id TEXT, action TEXT NOT NULL,
                status TEXT NOT NULL, error TEXT, at TEXT NOT NULL, tool TEXT)",
        )
        .execute(&pool)
        .await
        .expect("create mcp_audit");
        pool
    }
}
