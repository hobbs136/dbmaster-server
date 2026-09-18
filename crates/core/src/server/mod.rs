//! Server assembly — application state and router construction.

mod router;

pub use router::{build_router, build_router_with_config};

use crate::config::Config;
use async_trait::async_trait;
use dbmaster_license::EntitlementState;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// AES-256-GCM master key type alias (32 bytes). Carried in AppState so
/// connection-encryption handlers can reach it without re-reading env vars.
pub type CredentialKey = [u8; 32];

/// Per-install_uuid sliding-window counters for the anonymous telemetry
/// endpoint. In-memory only — a restart zeroes all counters (acceptable
/// for the 4-week funnel validation window per telemetry-funnel-plan.md §6.1.4).
pub type TelemetryRateLimits = Arc<Mutex<HashMap<String, Vec<Instant>>>>;

/// Bridge trait: run a drift task by id.
///
/// Lives in core (the lowest shared layer) so [`AppState`] can carry a trait
/// object without forcing automation → drift (which would cycle, since drift
/// already depends on automation for credential decrypt). The drift crate
/// provides the impl; the binary crate wires it into [`AppState::new`].
///
/// `triggered_by` follows ADR-0002 §4.2.4 — `"scheduler"` or
/// `"manual:<user_id>"`. Implementations are expected to log their own
/// outcome (the manual-run handler is fire-and-forget; it does not wait).
// CHANGE: ADR-0002 v1-C-9 — single reusable run entry shared by the scheduler
// and the manual-run HTTP handler.
#[async_trait]
pub trait DriftRunner: Send + Sync + 'static {
    /// Run the task end-to-end (canary → snapshot → diff → webhook → audit).
    /// Returns `Err(redacted_message)` on failure; the redaction is the
    /// implementation's responsibility (no credential / SQL / PII).
    async fn run(
        &self,
        pool: &SqlitePool,
        state: &AppState,
        task_id: &str,
        triggered_by: &str,
    ) -> Result<(), String>;
}

/// Bridge trait: run a data_sync task by id.
///
/// Mirrors [`DriftRunner`] — lives in core (lowest shared layer) so
/// [`AppState`] can carry a trait object without forcing automation →
/// data_sync (which would cycle, since data_sync already depends on
/// automation for credential decrypt). The data_sync crate provides the impl;
/// the binary crate wires it into [`AppState::new`].
///
/// The runner is responsible for: decrypting source/target credentials,
/// opening short-lived pools, time-batched JOIN-based ETL (main table +
/// LEFT JOINs), writing to the target, persisting progress/cursor to
/// `data_sync_runs`, and honouring `cancel_requested`. Returned errors must
/// be redacted (no credential / SQL / PII).
// CHANGE: data-sync 一期 — ETL runner bridge (mirrors DriftRunner pattern).
#[async_trait]
pub trait DataSyncRunner: Send + Sync + 'static {
    /// Run the task end-to-end. Returns `Err(redacted_message)` on failure.
    async fn run(
        &self,
        pool: &SqlitePool,
        state: &AppState,
        task_id: &str,
        triggered_by: &str,
    ) -> Result<(), String>;
}

/// Bridge trait: run a health_check task by id.
///
/// Mirrors [`DriftRunner`] / [`DataSyncRunner`] — lives in core (lowest shared
/// layer) so [`AppState`] can carry a trait object without forcing automation →
/// health_check (which would cycle, since health_check depends on automation
/// for credential decrypt). The health_check crate provides the impl; the
/// binary crate wires it into [`AppState::new`].
///
/// The runner is responsible for: decrypting the source connection credential,
/// opening a short-lived pool, running SELECT-only health probes (connectivity
/// + metrics), evaluating threshold-based alerts with flap-suppression,
/// delivering `dbmaster.health-event.v1` webhooks, and persisting results +
/// alert state. Returned errors must be redacted (no credential / SQL / PII).
// CHANGE: ADR-0004 §2.2 — health-check runner bridge (mirrors DriftRunner pattern).
#[async_trait]
pub trait HealthCheckRunner: Send + Sync + 'static {
    /// Run the task end-to-end. Returns `Err(redacted_message)` on failure.
    async fn run(
        &self,
        pool: &SqlitePool,
        state: &AppState,
        task_id: &str,
        triggered_by: &str,
    ) -> Result<(), String>;
}

/// Shared application state injected into all request handlers.
#[derive(Clone)]
pub struct AppState {
    /// SQLite connection pool.
    pub pool: SqlitePool,
    /// Server configuration (JWT secrets, etc.) — Arced for cheap cloning into extensions.
    pub config: Arc<Config>,
    /// Credential encryption key (AES-256-GCM). Arced to keep Clone cheap.
    // CHANGE: ADR-0001 §4.8 D8.1 — key in AppState, not re-read from env per request.
    pub credential_key: Arc<CredentialKey>,
    /// Entitlement snapshot. Originally resolved at startup (ADR-0001 §7.1);
    /// #3 (License HTTP API) makes it runtime-swappable via `POST /api/license`
    /// — the handler verifies the new license, atomically writes `.dbmlicense`,
    /// then `entitlement.store(new_state)` so HTTP gates reflect the change
    /// immediately (schedulers still require restart — see ADR-0001 §D7
    /// revision note). `ArcSwap` keeps reads lock-free; wrapped in `Arc` so
    /// `AppState: Clone` (axum requires it) clones the shared handle cheaply.
    pub entitlement: Arc<arc_swap::ArcSwap<EntitlementState>>,
    /// CHANGE: #3 — bearer token required for `POST /api/license` when
    /// `embedded_mode == false` (remote deployments). Loaded once at boot from
    /// env var `DBMASTER_SERVER_ADMIN_TOKEN`; `None` ⇒ POST is forbidden on
    /// remote servers. Embedded mode never reads this (loopback + access_token
    /// is already trusted). Ed25519 signature verification happens before any
    /// state change, so this token only rate-limits abuse — it is not the
    /// security boundary.
    pub admin_token: Option<String>,
    /// CHANGE: telemetry-funnel-plan.md §6.1.4 — per-install_uuid telemetry
    /// rate-limit counters. Mutex is held only for map mutation, never across I/O.
    pub telemetry_rate_limits: TelemetryRateLimits,
    /// CHANGE: ADR-0002 §4.4.2 — local install_uuid for the drift webhook
    /// payload (`instance_uuid` field). Resolved once at boot from
    /// `instance_meta` (same row entitlement reads) and carried as Arc<String>
    /// so Clone stays cheap. DEFENSIVE-NOTE: install_uuid is NOT PII per
    /// ADR §4.4.2; safe to emit in payloads and structured logs.
    pub install_uuid: Arc<String>,
    /// CHANGE: ADR-0002 v1-C-9 — the runner used by both the scheduler and
    /// the manual-run HTTP handler. Arc<dyn DriftRunner> so the automation
    /// crate can dispatch into drift without depending on drift.
    pub drift_runner: Arc<dyn DriftRunner>,
    /// CHANGE: data-sync 一期 — ETL runner used by both the data_sync
    /// scheduler and the manual-run HTTP handler. Arc<dyn DataSyncRunner>
    /// so automation can dispatch without depending on the data_sync crate.
    pub data_sync_runner: Arc<dyn DataSyncRunner>,
    /// CHANGE: ADR-0004 §2.2 — health-check runner used by both the
    /// health_check scheduler and the manual-run HTTP handler.
    /// Arc<dyn HealthCheckRunner> so automation can dispatch without
    /// depending on the health_check crate.
    pub health_check_runner: Arc<dyn HealthCheckRunner>,
    /// true when the server is running as the desktop
    /// client's embedded child process. Gates the GET /api/connections/:id/
    /// credential endpoint (plaintext-credential retrieval), which is only
    /// safe on the loopback embedded transport — never on a remote deployment.
    pub embedded_mode: bool,
}

impl AppState {
    /// Create a new AppState with the given pool, configuration, credential key,
    /// resolved entitlement, install_uuid, drift runner impl, and data_sync
    /// runner impl.
    // CHANGE: signature grows by data_sync_runner for the 一期 ETL bridge,
    // and by health_check_runner for ADR-0004.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: SqlitePool,
        config: Config,
        credential_key: CredentialKey,
        entitlement: EntitlementState,
        install_uuid: String,
        drift_runner: Arc<dyn DriftRunner>,
        data_sync_runner: Arc<dyn DataSyncRunner>,
        health_check_runner: Arc<dyn HealthCheckRunner>,
    ) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            credential_key: Arc::new(credential_key),
            entitlement: Arc::new(arc_swap::ArcSwap::from(Arc::new(entitlement))),
            // CHANGE: #3 — admin token for POST /api/license on remote servers.
            // None on embedded (won't be consulted). Empty env var also treated
            // as None so misconfiguration can't silently disable the gate.
            admin_token: std::env::var("DBMASTER_SERVER_ADMIN_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            // CHANGE: telemetry-funnel-plan.md §6.1.4 — fresh per-process counter.
            telemetry_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            install_uuid: Arc::new(install_uuid),
            drift_runner,
            data_sync_runner,
            health_check_runner,
            // normal (non-embedded) mode default.
            embedded_mode: false,
        }
    }

    /// Like [`new`](Self::new) but sets `embedded_mode = true`. Used by the
    /// embedded server bootstrap so the credential-retrieval endpoint is
    /// enabled and the plaintext-credential policy is enforced.
    // separate ctor keeps the (many) existing `new`
    /// callsites unchanged while letting embedded mode opt in.
    #[allow(clippy::too_many_arguments)]
    pub fn new_embedded(
        pool: SqlitePool,
        config: Config,
        credential_key: CredentialKey,
        entitlement: EntitlementState,
        install_uuid: String,
        drift_runner: Arc<dyn DriftRunner>,
        data_sync_runner: Arc<dyn DataSyncRunner>,
        health_check_runner: Arc<dyn HealthCheckRunner>,
    ) -> Self {
        let mut s = Self::new(
            pool, config, credential_key, entitlement, install_uuid,
            drift_runner, data_sync_runner, health_check_runner,
        );
        s.embedded_mode = true;
        s
    }
}
