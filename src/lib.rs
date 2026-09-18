//! dbmaster-server library target — app composition (ADR-0001 §7.1).
//!
//! Splits the binary into `lib.rs` (composition, reusable from integration tests)
//! and `main.rs` (bootstrap + serve). This module merges the core routes
//! (auth/workspace/telemetry/entitlement) with the automation routes
//! (connections/tasks/approvals/queries/reports) without forcing `core` to
//! depend on `automation` (which already depends on `core`).

use std::sync::Arc;

use axum::Router;
use dbmaster_core::config::Config;
use dbmaster_core::server::{
    AppState, CredentialKey, DataSyncRunner, DriftRunner, HealthCheckRunner,
};
use dbmaster_license::EntitlementState;
use sqlx::SqlitePool;

/// Build the complete Axum app: core routes merged with automation routes.
///
/// Loads [`Config`] from the environment (via `Config::from_env()`). Production
/// (non-embedded) callers should use this entry point. Embedded-mode callers
/// must use [`build_app_with_config`] so a parent-supplied `Config` (random JWT
/// secret, 127.0.0.1 bind, temp data dir) is honoured.
// CHANGE: ADR-0001 §7.1 — break core↔automation cycle by composing at the binary.
// CHANGE: drift_runner threaded through so AppState inside both the core and
// automation routers carries the manual-run bridge.
#[allow(clippy::too_many_arguments)]
pub fn build_app(
    pool: SqlitePool,
    credential_key: CredentialKey,
    entitlement: EntitlementState,
    install_uuid: String,
    drift_runner: Arc<dyn DriftRunner>,
    data_sync_runner: Arc<dyn DataSyncRunner>,
    health_check_runner: Arc<dyn HealthCheckRunner>,
) -> Router {
    // DEFENSIVE-NOTE: preserved verbatim for the non-embedded path so production
    // startup semantics are unchanged. A panic here surfaces as a process crash
    // with a clear message — acceptable for the env-coupled production path.
    let config = Config::from_env().expect("Failed to load server configuration");
    build_app_with_config(
        pool,
        config,
        credential_key,
        entitlement,
        install_uuid,
        drift_runner,
        data_sync_runner,
        health_check_runner,
        // the env-driven (non-embedded) path is always
        // remote mode: credential-retrieval endpoint disabled.
        false,
    )
}

/// Build the complete Axum app with an explicit [`Config`].
///
/// Same composition as [`build_app`], but the caller supplies the `Config`
/// directly. Added for ADR-0003 S2: the embedded server process cannot source
/// its config from the environment (random per-instance JWT secrets, OS-assigned
/// port, temp data dir) — it must inject a constructed `Config`.
// env-decoupled composition for embedded mode.
// added `embedded_mode` so the credential-retrieval
// endpoint is enabled only when the embedded bootstrap composes the app.
#[allow(clippy::too_many_arguments)]
pub fn build_app_with_config(
    pool: SqlitePool,
    config: Config,
    credential_key: CredentialKey,
    entitlement: EntitlementState,
    install_uuid: String,
    drift_runner: Arc<dyn DriftRunner>,
    data_sync_runner: Arc<dyn DataSyncRunner>,
    health_check_runner: Arc<dyn HealthCheckRunner>,
    embedded_mode: bool,
) -> Router {
    // reports-M1（#29）— 慢查询采样器注册（远程与 embedded 唯一共同构建点；
    // 未初始化时 record() 为 no-op）。放在 pool/config 被 clone 分发之前。
    dbmaster_automation::query_stats::init(pool.clone(), &config);

    // Build core router with the injected config (clone first — the automation
    // router below builds its own AppState and needs the same Config).
    // Clones are cheap: SqlitePool is Arc-interned, CredentialKey is [u8;32]
    // (Copy), EntitlementState holds a few Strings, Config holds small Strings.
    let core_app = dbmaster_core::server::build_router_with_config(
        pool.clone(),
        config.clone(),
        credential_key,
        entitlement.clone(),
        install_uuid.clone(),
        drift_runner.clone(),
        data_sync_runner.clone(),
        health_check_runner.clone(),
        embedded_mode,
    );

    // Clone for the MCP router before `pool`/`config` move into AppState
    // below (same cheap-clone rationale as the core router call above).
    let mcp_config = Arc::new(config.clone());
    let mcp_pool = pool.clone();
    // T27 — 同上：网关 router 在 config/pool move 进 AppState 前取副本。
    let gw_config = Arc::new(config.clone());
    let gw_pool = pool.clone();

    // Build automation router with a fresh AppState (same underlying pool +
    // same Config — both pieces see identical configuration).
    let state = if embedded_mode {
        AppState::new_embedded(
            pool,
            config,
            credential_key,
            entitlement,
            install_uuid,
            drift_runner,
            data_sync_runner,
            health_check_runner,
        )
    } else {
        AppState::new(
            pool,
            config,
            credential_key,
            entitlement,
            install_uuid,
            drift_runner,
            data_sync_runner,
            health_check_runner,
        )
    };
    // D1（写门读放）——MCP 写路径门与 AppState 持同一 entitlement ArcSwap
    // （热换即时生效）；在 `routes(state)` 拿走所有权前克隆。
    let mcp_entitlement = state.entitlement.clone();
    let automation_app = dbmaster_automation::routes(state);

    // MCP 端点（dbx-response 举措一 / T03+T04+T06）：无状态子 router（/mcp，
    // Streamable HTTP）。T04 起带认证（Bearer access JWT）/ per-user 限流
    // （Config::mcp_rate_limit_per_minute）/ mcp_audit 审计；T06 起 4 个元数据
    // 工具（credential_key 供工具层解密目标库凭据）；D1 license 门已接
    // （2026-08-27 拍板写门读放：Gated 拒 submit_write/execute_write，读面
    // 放行）。embedded 与远程模式同一路径（同一 JWT 体系）。
    // CredentialKey 是 [u8;32]（Copy），AppState 已在上方另行消费。
    let mcp_app = dbmaster_mcp::router(mcp_config, mcp_pool, credential_key, mcp_entitlement);

    // DB 网关 API v1（dbx-response T27 / ADR-0005 §2.2）：/api/gw/* 元数据
    // 三端点（与 MCP 工具同源 metadata.rs）+ SSE 流式查询执行（取消/超时/
    // 行限）+ 连接注册族（T28 前置）。认证（JWT）/限流/审计同 /mcp 模式
    // （gw_audit 表，migration 015）；embedded 与远程模式同一路径。
    let gw_app = dbmaster_gateway::router(gw_config, gw_pool, credential_key);

    core_app.merge(automation_app).merge(mcp_app).merge(gw_app)
}
