//! dbmaster-gateway — DB 网关 API v1（dbx-response T27 / ADR-0005 §2.2）。
//!
//! 客户端（Flutter 桌面端 / T28 起的网关壳 adapter → GatewayBacking）访问
//! 一切数据库的统一服务面。**本 crate 是 HTTP/SSE 协议薄层**：元数据直接
//! 调 automation `metadata.rs`（与 MCP 工具同源同一后端），查询执行调
//! automation `stream_query.rs`（流式位置数组行 + 取消/超时/行限）。
//!
//! **端点面**（c01_port_contract §4.1）：
//! - `GET  /api/gw/connections` — 连接安全投影列表（永不回凭据）
//! - `GET  /api/gw/connections/{id}/databases|tables|describe` — 元数据三端点
//! - `POST /api/gw/connections/{id}/query` — SSE 流式执行（meta/rows/
//!   complete/error 四事件 + seq id + keep-alive；X-Execution-Id 请求头
//!   可由客户端预置，响应头回显——取消可在任何时刻发起）
//! - `DELETE /api/gw/executions/{executionId}` — 显式取消（幂等 204）
//! - `POST /api/gw/connections/test` — 草稿测试（不落库）
//! - `POST /api/gw/connections` / `DELETE /api/gw/connections/{id}` — 连接
//!   注册族（T28 前置：凭据入 server vault，返回 serverConnId）
//!
//! **横切**（同 `/mcp` 模式，见 `auth.rs` / `audit.rs`）：Bearer access JWT
//! 认证（401 + 质询）、per-user 滑动窗口限流（`gw_rate_limit_per_minute`）、
//! gw_audit 审计（无 SQL 明文/凭据/PII）。连接可见性 = `/api/connections`
//! v1 语义（单 workspace 全可见）。
//!
//! **错误 wire**：`{"error":{"code","message","engineCode"?}}`，code 集 = 契约
//! §4.4（+MULTI_STATEMENT 扩展）。SSE 开始后错误只能经 error 事件。
//!
//! 挂载（src/lib.rs of dbmaster-server）：
//! `Router::new().merge(core).merge(automation).merge(mcp).merge(gateway)`

pub mod audit;
pub(crate) mod auth;
pub mod handlers;

use std::collections::HashMap;
use std::sync::Arc;

use axum::{middleware, routing, Router};
use dbmaster_core::auth::rate_limiter::SlidingWindowLimiter;
use dbmaster_core::config::Config;
use dbmaster_core::server::CredentialKey;
use sqlx::SqlitePool;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// 网关路由前缀（契约 §7 留给实现期命名的部分）。
pub const GW_PREFIX: &str = "/api/gw";

/// 活跃执行注册表：executionId → 取消令牌。
///
/// DELETE /executions/{id} 查表触发 cancel——server 侧终止执行（drop
/// 专用池断连），这是 #30 结案的语义锚点：取消必须可达服务端，不能只
/// 靠客户端停止订阅。条目在执行终态（complete/error）后由执行任务移除；
/// 对已消失 id 的取消幂等返回（no-op）。
#[derive(Clone, Default)]
pub struct ExecutionRegistry {
    inner: Arc<Mutex<HashMap<String, CancellationToken>>>,
}

impl ExecutionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一次执行，返回其取消令牌（执行任务 select 在 cancelled() 上）。
    pub async fn register(&self, execution_id: String) -> CancellationToken {
        let token = CancellationToken::new();
        self.inner.lock().await.insert(execution_id, token.clone());
        token
    }

    /// 触发取消。返回是否命中（未命中 = 已结束/未知 id，幂等 no-op）。
    pub async fn cancel(&self, execution_id: &str) -> bool {
        match self.inner.lock().await.get(execution_id) {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }

    /// 执行终态后清理（防注册表无限增长）。
    pub async fn remove(&self, execution_id: &str) {
        self.inner.lock().await.remove(execution_id);
    }
}

/// Redis 订阅注册表：conn_id → 活跃订阅流的取消令牌（T29 非 SQL 批次
/// B3，ADR-0006 §2.5）。生命周期双挂：客户端断开 SSE → 流 future drop →
/// 订阅连接 drop（无需显式清理）；网关连接删除 → [`RedisSubRegistry::revoke`]
/// 取消全部令牌杀流。条目在连接删除时整体移除（流自然结束的陈旧令牌随
/// 连接生命周期有界，不主动逐条清）。
#[derive(Clone, Default)]
pub struct RedisSubRegistry {
    inner: Arc<Mutex<HashMap<String, Vec<CancellationToken>>>>,
}

impl RedisSubRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一条活跃订阅流的取消令牌。
    pub async fn register(&self, conn_id: &str, token: CancellationToken) {
        self.inner
            .lock()
            .await
            .entry(conn_id.to_string())
            .or_default()
            .push(token);
    }

    /// 取消并移除该连接的全部订阅流（连接删除时调用）。
    pub async fn revoke(&self, conn_id: &str) {
        if let Some(tokens) = self.inner.lock().await.remove(conn_id) {
            for token in tokens {
                token.cancel();
            }
        }
    }
}

/// 网关共享状态：guard 与 handler 共用（cheap-clone：Arc/Pool/Copy）。
#[derive(Clone)]
pub(crate) struct GwState {
    pub config: Arc<Config>,
    pub pool: SqlitePool,
    pub credential_key: CredentialKey,
    pub limiter: Arc<SlidingWindowLimiter>,
    pub executions: ExecutionRegistry,
    pub redis_subs: RedisSubRegistry,
}

/// 构建网关子 router，由 server 组合层 merge 进主 router。
///
/// 认证/限流/审计中间件（`auth::guard`）罩住全部端点：JWT-only（网关的
/// 客户端是桌面端，持 access JWT；`dbm_mcp_*` 长效 token 是 MCP 面的
/// agent 凭证，不在本面消费——两面权限边界刻意分开）。
pub fn router(config: Arc<Config>, pool: SqlitePool, credential_key: CredentialKey) -> Router {
    let limiter = Arc::new(SlidingWindowLimiter::new());
    let state = GwState {
        config: config.clone(),
        pool: pool.clone(),
        credential_key,
        limiter: limiter.clone(),
        executions: ExecutionRegistry::new(),
        redis_subs: RedisSubRegistry::new(),
    };

    Router::new()
        .route(
            "/api/gw/connections",
            routing::get(handlers::list_connections).post(handlers::register_connection),
        )
        .route("/api/gw/connections/test", routing::post(handlers::test_connection))
        .route("/api/gw/connections/:id", routing::delete(handlers::remove_connection))
        .route(
            "/api/gw/connections/:id/databases",
            routing::get(handlers::gw_list_databases),
        )
        .route("/api/gw/connections/:id/tables", routing::get(handlers::gw_list_tables))
        .route(
            "/api/gw/connections/:id/describe",
            routing::get(handlers::gw_describe_table),
        )
        .route("/api/gw/connections/:id/query", routing::post(handlers::gw_query))
        .route("/api/gw/executions/:id", routing::delete(handlers::cancel_execution))
        // T29 非 SQL 批次（B3）— Redis 订阅转发 SSE（ADR-0006 §2.5）。
        .route(
            "/api/gw/connections/:id/redis/subscriptions",
            routing::get(handlers::redis_subscribe),
        )
        .layer(middleware::from_fn_with_state(
            GwState {
                config,
                pool,
                credential_key,
                limiter,
                executions: state.executions.clone(),
                redis_subs: state.redis_subs.clone(),
            },
            auth::guard,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execution_registry_cancel_is_idempotent() {
        let reg = ExecutionRegistry::new();
        let token = reg.register("exec-1".into()).await;
        assert!(reg.cancel("exec-1").await);
        assert!(token.is_cancelled());
        // 已移除/未知 id：no-op 不 panic。
        reg.remove("exec-1").await;
        assert!(!reg.cancel("exec-1").await);
        assert!(!reg.cancel("never-registered").await);
    }

    #[tokio::test]
    async fn execution_registry_reregister_replaces_token() {
        let reg = ExecutionRegistry::new();
        let t1 = reg.register("exec-1".into()).await;
        let t2 = reg.register("exec-1".into()).await;
        assert!(!t1.is_cancelled());
        assert!(reg.cancel("exec-1").await);
        assert!(t2.is_cancelled());
        assert!(!t1.is_cancelled());
    }
}
