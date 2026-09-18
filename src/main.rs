//! DbMaster Server — Team collaboration and automation engine.
//!
//! Entry point: parses configuration, initializes the database pool,
//! runs migrations, loads credentials key + entitlement, and starts the Axum
//! HTTP server.
//!
//! Two run modes (ADR-0003):
//! - **Normal** (default): production server. Reads config from env vars
//!   (`Config::from_env`), enforces the ¥399/yr license entitlement.
//! - **Embedded** (`--embedded`): spawned as a child process by the Flutter
//!   desktop client. Binds 127.0.0.1 on an OS-assigned port, synthesizes a
//!   lifetime-licensed single-user entitlement, and emits a one-line JSON
//!   handshake to stdout so the parent process learns the port + access token.

use dbmaster_core::config::Config;
use dbmaster_core::db;
// CHANGE: ADR-0002 v1-C-9 — DriftRunner bridge type from drift.
use dbmaster_core::server::DriftRunner;
// CHANGE: data-sync 一期 — DataSyncRunner bridge type from the data_sync crate.
use dbmaster_core::server::DataSyncRunner;
// CHANGE: ADR-0004 §2.2 — HealthCheckRunner bridge type from the health_check crate.
use dbmaster_core::server::HealthCheckRunner;
use dbmaster_license::{EntitlementState, LicenseV2};
// CHANGE: ADR-0001 §4.8 D8.1 — sha2 to log key fingerprint without leaking it.
use sha2::{Digest, Sha256};

// CHANGE: ADR-0001 §4.8 D8.1 — dev fallback path generates an ephemeral key.
use rand::RngCore;

// CLI flag parsing for embedded mode.
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

// ── Copyright / license notice (AGPL-3.0-only migration) ──

/// Single-line copyright + license statement. Logged once at startup (both run
/// modes) and printed as part of `--version` output (see [`VERSION_DISPLAY`]).
const COPYRIGHT_LINE: &str = "Copyright (c) 2026 dbmaster contributors. License: AGPL-3.0-only";

/// `--version` payload: the crate version number, then the copyright/license
/// notice. clap prints this and exits inside `Cli::parse()` — before any
/// config load, DB connection, or migration — so the flag stays side-effect
/// free. (`concat!` only accepts literals, so the notice text is repeated
/// here; the `banner` test below pins it to [`COPYRIGHT_LINE`].)
const VERSION_DISPLAY: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nCopyright (c) 2026 dbmaster contributors. License: AGPL-3.0-only"
);

/// Command-line interface (ADR-0003 S2).
///
/// Default invocation (no flags) runs the production server exactly as before.
/// `--embedded` switches to the desktop-client child-process mode.
// clap-derive CLI. Kept deliberately minimal: only the
// embedded mode needs flags. Normal mode ignores them.
#[derive(Parser, Debug)]
#[command(
    name = "dbmaster-server",
    about = "DbMaster Server",
    version = VERSION_DISPLAY
)]
struct Cli {
    /// Run as an embedded child process of the desktop client (ADR-0003 S2).
    ///
    /// Binds 127.0.0.1 on an OS-assigned port, synthesizes a single-user
    /// lifetime-licensed entitlement, and emits a one-line JSON handshake to
    /// stdout. Mutually exclusive with the normal env-driven startup.
    #[arg(long)]
    embedded: bool,

    /// Data directory for the embedded server's SQLite database (ADR-0003 S2).
    ///
    /// Only meaningful with `--embedded`. Defaults to a per-process directory
    /// under the OS temp dir so concurrent embedded instances don't collide.
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing. Always writes to stderr so the embedded mode's
    // stdout handshake channel (a single JSON line) stays uncluttered.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dbmaster_server=info,tower_http=info".into()),
        )
        .init();

    // Copyright/license notice (AGPL-3.0-only): one line on stderr in both run
    // modes so every startup log carries the licensing statement.
    tracing::info!(
        "dbmaster-server v{} — {}",
        env!("CARGO_PKG_VERSION"),
        COPYRIGHT_LINE
    );

    if cli.embedded {
        run_embedded(cli.data_dir).await
    } else {
        run_normal().await
    }
}

// ── Normal (production) startup — unchanged behaviour ──

/// Production startup: env-driven config, license-enforced entitlement, both
/// schedulers, fixed host:port. Behaviour identical to pre-embedded main().
// extracted from main(); the env-coupled, license-gated
// path. Embedded mode bypasses this entirely.
async fn run_normal() -> anyhow::Result<()> {
    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Starting dbmaster-server v{}", env!("CARGO_PKG_VERSION"));

    // CHANGE: ADR-0001 §4.8 D8.1 — load credential key (env var, fail-fast in prod).
    let credential_key = load_credential_key()?;
    log_key_fingerprint(&credential_key);

    // Initialize database pool and run migrations
    let pool = db::init_pool(&config.database_url).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("Database initialized");

    // CHANGE: ADR-0001 §4.8 D8.3 — one-shot migration of legacy enc: rows to v1.
    // Idempotent; logs only row counts (no plaintext/ciphertext ever logged).
    let migrated = dbmaster_automation::credential::migrate_legacy_credentials(
        &pool,
        &credential_key,
    )
    .await?;
    if migrated > 0 {
        tracing::info!("migrated {} legacy credential rows to v1", migrated);
    }

    // CHANGE: ADR-0001 §5 / §7.1 — resolve entitlement (license → trial → gated).
    let entitlement = match dbmaster_license::resolve_entitlement(&pool).await {
        Ok(state) => state,
        Err(e) => {
            // Entitlement resolution failing is fatal per ADR (instance/trial IO
            // errors are not recoverable). Log details and exit non-zero.
            tracing::error!(error = ?e, "entitlement resolution failed; aborting startup");
            return Err(e);
        }
    };
    log_entitlement(&entitlement);

    // CHANGE: ADR-0002 §4.4.2 — read the install_uuid for the drift webhook
    // payload. resolve_entitlement above has already created the instance_meta
    // row, so this is a single SELECT. Threaded through AppState as Arc<String>.
    let install_uuid = dbmaster_license::get_install_uuid(&pool).await?;

    // CHANGE: ADR-0002 v1-C-9 — concrete DriftRunner impl shared by the manual
    // HTTP handler (via AppState) and the scheduler (via run_task). Stateless.
    let drift_runner: Arc<dyn DriftRunner> = Arc::new(dbmaster_drift::DriftRunnerHandle);
    // CHANGE: data-sync 一期 — concrete DataSyncRunner impl shared by the
    // manual HTTP handler (via AppState) and the data_sync scheduler.
    let data_sync_runner: Arc<dyn DataSyncRunner> =
        Arc::new(dbmaster_data_sync::DataSyncRunnerHandle);
    // CHANGE: ADR-0004 §2.2 — concrete HealthCheckRunner impl shared by the
    // manual HTTP handler (via AppState) and the health_check scheduler.
    let health_check_runner: Arc<dyn HealthCheckRunner> =
        Arc::new(dbmaster_health_check::HealthCheckRunnerHandle);

    // Build application state and router
    let app = dbmaster_server::build_app(
        pool.clone(),
        credential_key,
        entitlement.clone(),
        install_uuid.clone(),
        drift_runner.clone(),
        data_sync_runner.clone(),
        health_check_runner.clone(),
    );

    // CHANGE: ADR-0002 §4 D7 / Phase E — spawn the drift scheduler as a
    // background tokio task. Skipped when entitlement is Gated: a gated
    // install (trial expired / no license) has no paid-feature runs.
    // DEFENSIVE-NOTE: entitlement is resolved once at boot; mid-run changes
    // require restart. v1-acceptable per ADR §4 D7 (single-process model).
    //
    // data-sync 一期 + ADR-0004 health-check (M5/T28): the same gate applies —
    // a gated install has no schedulers. All three share a single scheduler
    // AppState (they're stateless apart from the runner Arcs + pool).
    let (drift_sched, data_sync_sched, health_check_sched) = if entitlement.is_gated() {
        tracing::info!("entitlement gated; drift + data_sync + health_check schedulers not started");
        (None, None, None)
    } else {
        // One shared scheduler AppState — each spawn_scheduler clones it.
        let sched_state = dbmaster_core::server::AppState::new(
            pool.clone(),
            dbmaster_core::config::Config::from_env()?,
            credential_key,
            entitlement.clone(),
            install_uuid.clone(),
            drift_runner.clone(),
            data_sync_runner.clone(),
            health_check_runner.clone(),
        );
        (
            Some(dbmaster_drift::spawn_scheduler(pool.clone(), sched_state.clone())),
            Some(dbmaster_data_sync::spawn_scheduler(pool.clone(), sched_state.clone())),
            Some(dbmaster_health_check::spawn_scheduler(pool.clone(), sched_state)),
        )
    };

    // reports-M2（#29）— 慢查询周报 ticker（每小时查「距上一份 > 7 天」即
    // 生成）。随 scheduler 同门：Gated 不启动（对齐 drift/data_sync/health
    // 惯例——无订阅实例不产 server 付费面数据）。
    if !entitlement.is_gated() {
        dbmaster_automation::report_writer::spawn_weekly(pool.clone());
        // reports-M3（#29）— 原生慢查源采集（每小时；同门）。
        dbmaster_automation::native_collector::spawn_collector(
            pool.clone(),
            credential_key,
        );
    }

    // Bind and serve
    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("Listening on {}", addr);

    // reports-M1（#29）— 慢查询 retention 轮转（无条件启动——housekeeping 非
    // 付费功能，不挂 entitlement 门；handle detach，进程退出即止）。
    dbmaster_automation::query_stats::spawn_cleanup(
        pool.clone(),
        config.slow_query_retention_days,
    );

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let server = axum::serve(listener, app);

    // Graceful shutdown: ctrl_c aborts both schedulers (in-flight runs finish
    // on their own per ADR §4.7 — v1 accepts "未发出的丢失").
    tokio::select! {
        res = server => {
            if let Some(h) = &drift_sched { h.abort(); }
            if let Some(h) = &data_sync_sched { h.abort(); }
            if let Some(h) = &health_check_sched { h.abort(); }
            res?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received SIGINT, shutting down");
            if let Some(h) = &drift_sched { h.abort(); }
            if let Some(h) = &data_sync_sched { h.abort(); }
            if let Some(h) = &health_check_sched { h.abort(); }
        }
    }

    Ok(())
}

// ── Embedded startup (ADR-0003 S2) ──

/// Embedded-mode startup (ADR-0003 S2).
///
/// Runs the server as a child process of the Flutter desktop client:
/// - Binds `127.0.0.1:0` (OS assigns an ephemeral port → zero conflicts).
/// - Builds a `Config` with random per-instance JWT secrets + temp data dir
///   (NOT read from env, so concurrent instances don't collide).
/// - Synthesizes a lifetime `Licensed` entitlement so the desktop's DBA write
///   operations (which the production ¥399/yr gate would block after a 14-day
///   trial) work without activation.
/// - Idempotently creates a single embedded user and issues a fresh token pair.
/// - Emits a one-line JSON handshake to **stdout** (tracing is on stderr) so
///   the parent process learns the port + tokens.
/// - Runs the data_sync scheduler (local data_sync is a free feature per ADR)
///   but NOT the drift scheduler (drift is a remote/team feature).
/// - Shuts down on stdin EOF (parent gone), ctrl_c, or server error.
async fn run_embedded(data_dir_override: Option<PathBuf>) -> anyhow::Result<()> {
    tracing::info!("Starting dbmaster-server v{} (EMBEDDED mode)", env!("CARGO_PKG_VERSION"));

    // ── Data dir: per-process temp dir unless overridden ──
    // Default under OS temp + process id so two embedded instances launched
    // concurrently (e.g. during dev) never touch the same SQLite file.
    let data_dir = match data_dir_override {
        Some(p) => p,
        None => std::env::temp_dir().join(format!("dbmaster-embedded-{}", std::process::id())),
    };
    std::fs::create_dir_all(&data_dir)?;
    let db_path = data_dir.join("dbmaster-embedded.db");
    let database_url = format!("sqlite:{}?mode=rwc", db_path.display());
    tracing::info!(data_dir = %data_dir.display(), "embedded data directory");

    // ── Random per-instance secrets (NOT from env) ──
    // Avoids cross-instance JWT collisions when multiple embedded servers run
    // on the same host. Each boot generates new secrets (acceptable: tokens
    // are short-lived and re-issued every launch by ensure_embedded_user).
    let jwt_secret = random_hex_secret(32);
    let jwt_refresh_secret = random_hex_secret(32);

    // Build the embedded Config. host is forced to loopback; port 0 lets the
    // OS pick. funnel_lite_enabled stays true (telemetry is still useful).
    let config = Config {
        host: "127.0.0.1".to_string(),
        port: 0,
        jwt_secret,
        jwt_refresh_secret,
        database_url: database_url.clone(),
        funnel_lite_enabled: true,
        drift_default_interval_mins: 30,
        drift_webhook_timeout_secs: 10,
        data_sync_default_batch_size: 10000,
        data_sync_max_concurrency: 1,
        // CHANGE: T04 — embedded MCP shares the default per-user limit; the
        // env knob is a remote-deployment tuning lever.
        mcp_rate_limit_per_minute: 120,
        // T07 — read_query 行限上限 / 超时（测试默认值与生产默认一致）。
        mcp_read_query_max_rows: 10000,
        mcp_read_query_timeout_secs: 30,
        mcp_allowed_hosts: Vec::new(),
        mcp_allowed_connections: Vec::new(),
        // T27 — 嵌入式网关与远程同默认限额（本地环回路径，无调优必要）。
        gw_rate_limit_per_minute: 600,
        gw_query_default_rows: 500,
        gw_query_max_rows: 10000,
        gw_query_timeout_secs: 30,
        // reports-M1（#29）— 嵌入式慢查询采样与远程同默认（embedded 是本功能
        // 主场景：桌面用户的全部查询经嵌入式 server，采样默认开）。
        slow_query_enabled: true,
        slow_query_threshold_ms: 1000,
        slow_query_store_sql: true,
        slow_query_retention_days: 14,
        slow_query_cap_per_digest_per_hour: 20,
    };

    // ── Credential key: random 32 bytes (no DBMASTER_DEV required) ──
    // the embedded server now persists connections to its
    // SQLite DB, so the AES-256 credential key MUST be stable across restarts
    // (a fresh key per boot would make every stored connection undecryptable
    // after the first run). Load it from `{data_dir}/credential.key`, creating
    // it on first launch. On IO failure we degrade to an ephemeral random key
    // + WARN (connections won't persist, but the server still boots).
    let credential_key = load_or_create_credential_key(&data_dir).await;
    log_key_fingerprint(&credential_key);

    // ── Pool + migrations ──
    // 迁移 checksum 漂移（历史构建行尾差异，2026-08-25 实锤）→ embedded 模式
    // 允许一次性备份 + 重建（本地可再生数据）；远程模式（上方 :97）仍硬失败。
    // rebuilt 标志由本 target 落 WARN（默认 filter 不含 dbmaster_core）。
    let (pool, db_rebuilt) =
        db::init_pool_with_embedded_rebuild(&database_url, &db_path).await?;
    if db_rebuilt {
        tracing::warn!(
            "embedded database was rebuilt after migration failure (old files kept as .bak-*)"
        );
    }
    tracing::info!("embedded database initialized");

    // reports-M1（#29）— 慢查询 retention 轮转（embedded 是本功能主场景）。
    dbmaster_automation::query_stats::spawn_cleanup(
        pool.clone(),
        config.slow_query_retention_days,
    );

    // reports-M2（#29）— 周报 ticker：embedded 合成 Licensed，无条件启动。
    dbmaster_automation::report_writer::spawn_weekly(pool.clone());

    // reports-M3（#29）— 原生慢查源采集（每小时；embedded 主场景同跑——
    // 桌面用户注册的 Redis/MySQL 连接即得整库慢查画像）。
    dbmaster_automation::native_collector::spawn_collector(
        pool.clone(),
        credential_key,
    );

    // ── install_uuid (same source as normal mode) ──
    let install_uuid = dbmaster_license::get_install_uuid(&pool).await?;

    // ── Synthesize entitlement: lifetime Licensed, no gate ──
    // Rationale (ADR-0003): embedded mode IS the free desktop tier — DBA write
    // operations must work without activation. We reuse the existing Licensed
    // variant (no EntitlementState schema change → no license-contract impact).
    // gate_blocked() checks is_gated(), which is false for Licensed → writes pass.
    let entitlement = EntitlementState::Licensed {
        license: LicenseV2 {
            email: "embedded@local".to_string(),
            expires_at: None, // lifetime
            instance_id: install_uuid.clone(),
            issued_at: chrono::Utc::now().to_rfc3339(),
            license_type: "embedded".to_string(),
        },
        expires_at: None,
    };
    log_entitlement(&entitlement);

    // ── Embedded single-user + fresh token pair ──
    // AppError doesn't impl std::error::Error (it's an axum response type), so
    // we map it to anyhow via its Debug form. The detail is logged, not shown
    // to a client (embedded mode has no client-facing error UI here).
    let (user_id, access_token, refresh_token) =
        dbmaster_core::user::handler::ensure_embedded_user_and_tokens(&pool, &config)
            .await
            .map_err(|e| anyhow::anyhow!("embedded user bootstrap failed: {e:?}"))?;
    tracing::info!(user_id = %user_id, "embedded user ready");

    // ── Runners ──
    // data_sync: real runner + scheduler (local data_sync is free per ADR).
    // drift: NOOP runner (we don't spawn its scheduler; drift is remote-only).
    let data_sync_runner: Arc<dyn DataSyncRunner> =
        Arc::new(dbmaster_data_sync::DataSyncRunnerHandle);
    let drift_runner: Arc<dyn DriftRunner> = Arc::new(NoopDriftRunner);
    // CHANGE: ADR-0004 §2.6 — health_check is remote-only (same as drift);
    // embedded mode uses a noop runner and does not spawn its scheduler.
    let health_check_runner: Arc<dyn HealthCheckRunner> = Arc::new(NoopHealthCheckRunner);

    // ── Build app with the injected config ──
    let app = dbmaster_server::build_app_with_config(
        pool.clone(),
        config.clone(),
        credential_key,
        entitlement.clone(),
        install_uuid.clone(),
        drift_runner.clone(),
        data_sync_runner.clone(),
        health_check_runner.clone(),
        // embedded mode: enables the credential-retrieval
        // endpoint and the embedded-mode AppState flag.
        true,
    );

    // ── data_sync scheduler AppState (mirrors normal mode) ──
    // embedded scheduler AppState also carries the
    // embedded_mode flag for consistency (the scheduler doesn't serve HTTP, so
    // the flag is moot here, but it keeps the state shape uniform).
    let ds_state = dbmaster_core::server::AppState::new_embedded(
        pool.clone(),
        config.clone(),
        credential_key,
        entitlement.clone(),
        install_uuid.clone(),
        drift_runner.clone(),
        data_sync_runner.clone(),
        health_check_runner.clone(),
    );
    let data_sync_sched = Some(dbmaster_data_sync::spawn_scheduler(pool.clone(), ds_state));

    // ── Bind 127.0.0.1:0 and read the OS-assigned port ──
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    let port = local_addr.port();
    tracing::info!(port, "embedded server bound to 127.0.0.1");

    // ── Emit the stdout handshake (single JSON line) ──
    // This is the contract the Flutter parent process reads to learn the port
    // + access token. Must be exactly one line, newline-terminated, to stdout.
    // All logging is on stderr, so stdout is reserved for this handshake.
    emit_ready_handshake(port, &access_token, &refresh_token, &install_uuid);

    let server = axum::serve(listener, app);

    // ── Shutdown: stdin EOF (parent gone) OR ctrl_c OR server error ──
    // stdin EOF is the most reliable parent-lifecycle signal: when the Flutter
    // process exits, its stdout/stdin pipes close, and the child sees EOF.
    // ctrl_c covers manual `kill` during development.
    tokio::select! {
        res = server => {
            tracing::info!("server future completed");
            if let Some(h) = &data_sync_sched { h.abort(); }
            res?;
        }
        _ = wait_for_stdin_eof() => {
            tracing::info!("stdin EOF (parent process gone); shutting down");
            if let Some(h) = &data_sync_sched { h.abort(); }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received SIGINT, shutting down");
            if let Some(h) = &data_sync_sched { h.abort(); }
        }
    }

    Ok(())
}

/// Print the embedded ready-handshake to stdout (one JSON line, then flush).
///
/// Contract (consumed by the Flutter `EmbeddedServerService`, ADR-0003 S2b):
/// ```json
/// {"type":"dbmaster_embedded_ready","port":<u16>,
///  "access_token":"...","refresh_token":"...","install_uuid":"...","version":"..."}
/// ```
// the single stdout output of embedded mode. Tracing is
// on stderr, so the parent can read this line reliably.
fn emit_ready_handshake(port: u16, access_token: &str, refresh_token: &str, install_uuid: &str) {
    let payload = serde_json::json!({
        "type": "dbmaster_embedded_ready",
        "port": port,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "install_uuid": install_uuid,
        "version": env!("CARGO_PKG_VERSION"),
    });
    println!("{}", payload);
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Wait for stdin to close (EOF). Resolves when the parent process exits and
/// its stdin pipe closes.
// parent-lifecycle binding. Spawned on a background
// thread because blocking stdin read isn't async; the thread is harmless
// (it just exits on EOF).
async fn wait_for_stdin_eof() {
    tokio::task::spawn_blocking(|| {
        use std::io::Read;
        let mut buf = [0u8; 1];
        // Read until EOF (0) or error — either means stdin closed/gone.
        let _ = std::io::stdin().read(&mut buf);
        // Drain the rest so a chatty parent's output doesn't keep us alive
        // unnecessarily; EOF is what we act on.
        loop {
            let mut sink = [0u8; 1024];
            match std::io::stdin().read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    })
    .await
    .ok();
}

/// A no-op drift runner used by embedded mode (its scheduler is never spawned).
// embedded mode skips drift (a remote/team feature), so
// the AppState carries a runner that does nothing rather than the real handle.
struct NoopDriftRunner;

#[async_trait::async_trait]
impl DriftRunner for NoopDriftRunner {
    async fn run(
        &self,
        _pool: &sqlx::SqlitePool,
        _state: &dbmaster_core::server::AppState,
        _task_id: &str,
        _triggered_by: &str,
    ) -> Result<(), String> {
        // Embedded mode never invokes drift (no scheduler, no manual HTTP run
        // reachable from the free desktop UI). Returning Ok is correct.
        Ok(())
    }
}

/// A no-op health_check runner used by embedded mode (its scheduler is never
/// spawned). Mirrors [`NoopDriftRunner`] — ADR-0004 §2.6 treats health_check
/// as a remote-only paid feature, identical to drift.
// CHANGE: ADR-0004 §2.6 — embedded noop so AppState shape is uniform without
// running the paid health-check engine in the free local desktop context.
struct NoopHealthCheckRunner;

#[async_trait::async_trait]
impl HealthCheckRunner for NoopHealthCheckRunner {
    async fn run(
        &self,
        _pool: &sqlx::SqlitePool,
        _state: &dbmaster_core::server::AppState,
        _task_id: &str,
        _triggered_by: &str,
    ) -> Result<(), String> {
        // Embedded mode never invokes health_check (no scheduler, no manual
        // HTTP run reachable from the free desktop UI). Returning Ok is correct.
        Ok(())
    }
}

/// Generate `n` random bytes as a lowercase hex string (used for JWT secrets).
fn random_hex_secret(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate 32 random bytes (used for the AES-256 credential key).
fn random_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Load the embedded server's persistent AES-256 credential key, or create it
/// on first launch.
///
/// Stored as 32 raw bytes at `{data_dir}/credential.key`. On Unix the file is
/// chmod 0600; on Windows we rely on the per-user app-support directory's ACL
/// (the data_dir itself lives under `getApplicationSupportDirectory`). A failure
/// to read/write degrades to an in-memory random key + WARN so the server still
/// boots (though connections won't survive the next restart).
// stable credential key so server-stored connections can
// be decrypted across embedded-server restarts.
async fn load_or_create_credential_key(data_dir: &std::path::Path) -> [u8; 32] {
    let key_path = data_dir.join("credential.key");
    // Try to read an existing key first.
    match std::fs::read(&key_path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            tracing::info!("loaded persistent embedded credential key");
            arr
        }
        Ok(bytes) => {
            tracing::warn!(
                len = bytes.len(),
                "credential.key exists but is not 32 bytes; regenerating (existing connections will be undecryptable)"
            );
            fresh_key_and_maybe_write(&key_path)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // First launch — create the key.
            fresh_key_and_maybe_write(&key_path)
        }
        Err(e) => {
            tracing::warn!(
                error = %e, "failed to read credential.key; using ephemeral random key (connections won't persist)"
            );
            random_bytes_32()
        }
    }
}

/// Generate a fresh key and attempt to persist it; return the key regardless.
fn fresh_key_and_maybe_write(key_path: &std::path::Path) -> [u8; 32] {
    let key = random_bytes_32();
    match std::fs::write(key_path, key) {
        Ok(_) => {
            // Best-effort restrict perms on Unix; Windows relies on dir ACL.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
            }
            tracing::info!("created new persistent embedded credential key");
        }
        Err(e) => {
            tracing::warn!(
                error = %e, "failed to write credential.key; using ephemeral key (connections won't persist)"
            );
        }
    }
    key
}

// ── Credential key bootstrap (ADR-0001 §4.8 D8.1) ──

const CREDENTIAL_KEY_ENV: &str = "DBMASTER_CREDENTIAL_KEY";
const DEV_MODE_ENV: &str = "DBMASTER_DEV";

/// Load the AES-256 master key.
///
/// Behavior:
/// - If `DBMASTER_CREDENTIAL_KEY` is set to 64 hex chars (32 bytes) → use it.
/// - Else if `DBMASTER_DEV=1` → generate an ephemeral key with a WARN log
///   (credentials encrypted with it will not survive a restart).
/// - Else → fail-fast: refuse to boot so no plaintext password is silently
///   written to disk.
// CHANGE: ADR-0001 §4.8 D8.1 — env var, fail-fast in prod, dev fallback.
fn load_credential_key() -> anyhow::Result<[u8; 32]> {
    match std::env::var(CREDENTIAL_KEY_ENV) {
        Ok(raw) => {
            let raw = raw.trim();
            let bytes = hex::decode(raw)
                .map_err(|e| anyhow::anyhow!("{CREDENTIAL_KEY_ENV}: invalid hex ({e})"))?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("{CREDENTIAL_KEY_ENV}: must be 32 bytes (64 hex chars)"))?;
            Ok(arr)
        }
        Err(_) => {
            let dev_mode = matches!(std::env::var(DEV_MODE_ENV).as_deref(), Ok("1"));
            if dev_mode {
                let mut buf = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut buf);
                tracing::warn!(
                    "{CREDENTIAL_KEY_ENV} not set; {DEV_MODE_ENV}=1 — generated ephemeral key. \
                     Credentials will NOT survive a restart."
                );
                Ok(buf)
            } else {
                // DEFENSIVE-NOTE: fail-fast — booting without a key would silently
                // fall back to plaintext, violating ADR §4.8 / global rule (no plaintext creds).
                Err(anyhow::anyhow!(
                    "{CREDENTIAL_KEY_ENV} not set and {DEV_MODE_ENV} != 1; refusing to start. \
                     Set {CREDENTIAL_KEY_ENV} to a 32-byte hex value (e.g. `openssl rand -hex 32`) \
                     or set {DEV_MODE_ENV}=1 for local development."
                ))
            }
        }
    }
}

/// Print the first 4 bytes of SHA-256(key) so operators can verify which key is
/// loaded without the key itself appearing in logs.
fn log_key_fingerprint(key: &[u8; 32]) {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let digest = hasher.finalize();
    let fp = hex::encode(&digest[..4]);
    tracing::info!("credential key loaded (sha256[:4]={fp})");
}

fn log_entitlement(state: &EntitlementState) {
    use dbmaster_license::RenewalTier;
    match state {
        EntitlementState::Licensed { license, expires_at } => {
            // DEFENSIVE-NOTE: do NOT log `license.email` (PII). Only type + expiry.
            tracing::info!(
                license_type = %license.license_type,
                expires_at = ?expires_at.map(|dt| dt.to_rfc3339()),
                "license active"
            );
        }
        EntitlementState::Trial { expires_at } => {
            tracing::info!(trial_expires_at = %expires_at.to_rfc3339(), "trial active");
        }
        EntitlementState::Gated { .. } => {
            tracing::warn!("no active license or trial; paid features gated");
        }
    }
    if let Some(tier) = state.renewal_banner() {
        let tier_str = match tier {
            RenewalTier::Soon => "soon",
            RenewalTier::Urgent => "urgent",
        };
        let days = state.days_until_expiry().unwrap_or(0);
        tracing::warn!(tier = tier_str, days_until_expiry = days, "renewal banner active");
    }
}

#[cfg(test)]
mod banner_tests {
    use super::{COPYRIGHT_LINE, VERSION_DISPLAY};

    /// Pins the AGPL-3.0-only migration wording: the startup banner text and
    /// the `--version` payload must carry the identical copyright/license
    /// notice, including the license identifier and the copyright line.
    #[test]
    fn copyright_notice_is_consistent() {
        let notice = VERSION_DISPLAY.split_once('\n').unwrap().1;
        assert_eq!(COPYRIGHT_LINE, notice);
        assert!(COPYRIGHT_LINE.contains("AGPL-3.0-only"));
        assert!(COPYRIGHT_LINE.contains("(c) 2026 dbmaster contributors"));
    }

    /// `--version` output must lead with the crate version number.
    #[test]
    fn version_display_starts_with_pkg_version() {
        assert!(VERSION_DISPLAY.starts_with(env!("CARGO_PKG_VERSION")));
    }
}
