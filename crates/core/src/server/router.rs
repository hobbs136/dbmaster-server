//! Axum Router assembly — core routes only.
//!
//! Automation routes live in `dbmaster_automation::routes()` and are merged by
//! the binary crate to avoid a core→automation dependency cycle (automation
//! already depends on core for [`AppState`]).

use std::sync::Arc;

use axum::{
    extract::State,
    middleware,
    routing::{delete, get, patch, post},
    Json, Router,
};
use sqlx::SqlitePool;
use tower_http::cors::CorsLayer;

use crate::auth::rate_limiter::RateLimiterLayer;
use crate::config::Config;
use crate::server::{AppState, CredentialKey, DataSyncRunner, DriftRunner, HealthCheckRunner};
use crate::telemetry;
use crate::user;
use crate::workspace;
// CHANGE: ADR-0001 §7.1 — entitlement snapshot exposed via /api/entitlement.
use dbmaster_license::EntitlementState;

/// Build the core Axum Router (auth, workspace, telemetry, entitlement).
///
/// Automation routes are NOT included here — the binary merges
/// `dbmaster_automation::routes(state)` separately.
///
/// Loads [`Config`] from the environment. Callers that must inject a
/// constructed `Config` (e.g. the ADR-0003 embedded server with a random
/// per-instance JWT secret) should use [`build_router_with_config`].
// CHANGE: signature carries drift_runner so AppState can be assembled inside
// build_router without build_router needing to know how to construct it (the
// binary owns the concrete impl).
#[allow(clippy::too_many_arguments)]
pub fn build_router(
    pool: SqlitePool,
    credential_key: CredentialKey,
    entitlement: EntitlementState,
    install_uuid: String,
    drift_runner: Arc<dyn DriftRunner>,
    data_sync_runner: Arc<dyn DataSyncRunner>,
    health_check_runner: Arc<dyn HealthCheckRunner>,
) -> Router {
    // delegates to build_router_with_config so there is a
    // single composition body; the env-coupled path is now a thin wrapper.
    // pass embedded_mode=false (this is the remote path).
    let config = Config::from_env().expect("Failed to load server configuration");
    build_router_with_config(
        pool,
        config,
        credential_key,
        entitlement,
        install_uuid,
        drift_runner,
        data_sync_runner,
        health_check_runner,
        false,
    )
}

/// Build the core Axum Router with an explicit [`Config`].
///
/// Identical composition to [`build_router`], but the caller supplies the
/// `Config` instead of reading it from the environment. Added for ADR-0003 S2
/// (embedded server: random JWT secret, 127.0.0.1 bind, temp data dir).
// env-decoupled composition so the embedded binary can
// inject a constructed Config without touching process env vars.
// added `embedded_mode` to flip the AppState ctor (and
// thus the credential-retrieval endpoint policy).
#[allow(clippy::too_many_arguments)]
pub fn build_router_with_config(
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
    let config_for_extensions: Arc<Config> = state.config.clone();

    // Rate limit auth routes: single shared layer instance → one per-IP
    // counter across all three auth endpoints (5 req/min, sliding window).
    let auth_routes = Router::new()
        .route("/api/auth/register", post(user::handler::register))
        .route("/api/auth/login", post(user::handler::login))
        .route("/api/auth/refresh", post(user::handler::refresh_token))
        .layer(RateLimiterLayer::new());

    // ── Assemble core routes ──
    Router::new()
        // ── Health check (no auth) ──
        .route("/api/health", get(health_check))
        // ── Entitlement: license/trial/gated state + renewal banner (C-12) ──
        .route("/api/entitlement", get(get_entitlement))
        // CHANGE: #3 — License HTTP API. /api/instance exposes install_uuid
        // (unauthenticated, like /api/entitlement — install_uuid is not PII per
        // ADR §4.4.2). /api/license is the runtime write path.
        .route("/api/instance", get(get_instance))
        .route("/api/license", post(post_license))
        // ── Auth routes (no auth required, rate-limited) ──
        .merge(auth_routes)
        // ── User profile (authenticated) ──
        .route("/api/me", get(user::handler::get_me))
        .route("/api/me", patch(user::handler::update_me))
        // ── Workspace routes (authenticated) — multi-segment first! ──
        .route(
            "/api/workspaces/:id/members/:uid",
            delete(workspace::handler::remove_member),
        )
        .route("/api/workspaces/:id/join", post(workspace::handler::join_workspace))
        .route("/api/workspaces/:id/leave", post(workspace::handler::leave_workspace))
        .route("/api/workspaces/:id", get(workspace::handler::get_workspace))
        .route("/api/workspaces/:id", delete(workspace::handler::delete_workspace))
        .route("/api/workspaces", get(workspace::handler::list_workspaces))
        .route("/api/workspaces", post(workspace::handler::create_workspace))
        // ── Telemetry (no auth, Server-side only) ──
        .route("/api/telemetry/event", post(telemetry::ingest_event))
        // Inject Arc<Config> into request extensions for the auth middleware
        .layer(middleware::from_fn(
            move |mut req: axum::http::Request<axum::body::Body>, next: middleware::Next| {
                let cfg = config_for_extensions.clone();
                async move {
                    req.extensions_mut().insert(cfg);
                    next.run(req).await
                }
            },
        ))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// `GET /api/health` — Health check endpoint (no authentication).
// CHANGE: telemetry-funnel-plan.md D5 — surface the funnel-lite kill switch so
// the desktop client can read it from the existing health GET (matching the
// desktop's current `/api/health` parsing — see dbmaster-flutter
// `telemetry_service.dart::refreshLiteFlag`). D5 placement pending architect
// ratification; if it later moves to `/api/feature-flags`, the desktop change
// is one URL.
async fn health_check(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "status": "ok",
        "funnel_lite_enabled": state.config.funnel_lite_enabled,
    }))
}

/// `GET /api/entitlement` — Returns the current entitlement state + renewal
/// banner. Drives the Server UI activation gate and expiry banner (ADR-0001 C-12).
///
/// No auth: the UI must be able to read this even when the user is logged out,
/// so it can prompt activation from the gated screen.
// CHANGE: ADR-0001 §4.7 D7=C / §8 C-12 — local expiry banner data contract.
async fn get_entitlement(State(state): State<AppState>) -> Json<serde_json::Value> {
    use dbmaster_license::{GatedReason, RenewalTier};
    // CHANGE: #3 — entitlement is now ArcSwap (runtime-swappable via POST
    // /api/license). load() returns a Guard deref-ing to &EntitlementState;
    // behavior unchanged for this read path.
    let ent = state.entitlement.load();
    let (state_str, days_until_expiry, expiry_iso) = match &**ent {
        EntitlementState::Licensed { license: _, expires_at } => {
            let iso = expires_at.map(|dt| dt.to_rfc3339());
            let d = expires_at.map(|dt| (dt - chrono::Utc::now()).num_days());
            ("licensed", d, iso)
        }
        EntitlementState::Trial { expires_at } => {
            let iso = expires_at.to_rfc3339();
            let d = (*expires_at - chrono::Utc::now()).num_days();
            ("trial", Some(d), Some(iso))
        }
        EntitlementState::Gated { reason } => {
            let reason_str = match reason {
                GatedReason::TrialExpired => "trial_expired",
                GatedReason::LicenseInvalid => "license_invalid",
                GatedReason::InstanceMismatch => "instance_mismatch",
                GatedReason::LicenseExpired => "license_expired",
            };
            // DEFENSIVE-NOTE: do not include license.email or instance_id here —
            // this endpoint is unauthenticated and must not leak PII.
            return Json(serde_json::json!({
                "ok": true,
                "data": {
                    "state": "gated",
                    "reason": reason_str,
                },
                "error": null,
            }));
        }
    };

    let banner = match ent.renewal_banner() {
        Some(RenewalTier::Soon) => serde_json::json!({"show": true, "tier": "soon"}),
        Some(RenewalTier::Urgent) => serde_json::json!({"show": true, "tier": "urgent"}),
        None => serde_json::json!({"show": false, "tier": null}),
    };

    let license_info = if let EntitlementState::Licensed { license, .. } = ent.as_ref() {
        Some(serde_json::json!({
            "type": license.license_type,
            "issued_at": license.issued_at,
        }))
    } else {
        None
    };

    Json(serde_json::json!({
        "ok": true,
        "data": {
            "state": state_str,
            "days_until_expiry": days_until_expiry,
            "expires_at": expiry_iso,
            "renewal_banner": banner,
            "license": license_info,
        },
        "error": null,
    }))
}

// ── #3: License HTTP API ──

/// `GET /api/instance` — unauthenticated. Exposes the server's `install_uuid`
/// (the identifier license signatures bind to) plus server version and
/// embedded-mode flag. Lets the client/admin learn the instance id before
/// initiating activation on tech-site.
// CHANGE: #3 — fills the gap that previously made remote-server activation
// impossible (the client had no way to learn install_uuid outside embedded
/// mode's stdout handshake).
async fn get_instance(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "data": {
            "install_uuid": state.install_uuid.as_str(),
            "version": env!("CARGO_PKG_VERSION"),
            "embedded_mode": state.embedded_mode,
        },
        "error": null,
    }))
}

/// `POST /api/license` body.
#[derive(serde::Deserialize)]
struct PostLicenseRequest {
    license: String,
}

/// `POST /api/license` — runtime license write + entitlement swap.
///
/// Flow (per design §6.1):
/// 1. embedded mode short-circuits to FORBIDDEN (already Licensed).
/// 2. remote mode: admin token required (env DBMASTER_SERVER_ADMIN_TOKEN).
/// 3. Reuse `resolve_entitlement_with_text` (parse + verify + instance match +
///    expiry). Trust anchor is the Ed25519 signature, NOT this handler's auth.
/// 4. On Licensed/Trial: atomically write `.dbmlicense`, then `ArcSwap::store`.
///    Write MUST succeed before swap (otherwise entitlement drifts from file).
/// 5. On Gated: return the specific reason, do NOT write the file (avoids
///    half-written state that would re-Gated on next boot).
///
/// Returns `{state, license_type?, expires_at?, scheduler_note}` so the caller
/// knows schedulers still need restart (decision point 3 = B).
// CHANGE: #3 — runtime entitlement swap endpoint.
async fn post_license(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<PostLicenseRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    use dbmaster_license::{write_license_file, EntitlementState};

    // (1) Embedded mode is already Licensed (mod.rs new_embedded synthesises a
    // lifetime license); POST here is meaningless. Return ok:false + FORBIDDEN.
    if state.embedded_mode {
        return Ok(Json(serde_json::json!({
            "ok": false,
            "data": null,
            "error": {
                "code": "FORBIDDEN",
                "message": "embedded mode is always Licensed; POST /api/license not applicable",
            }
        })));
    }

    // (2) Remote mode: admin token required. Ed25519 verify is the real trust
    // anchor (private key lives only in tech-site's env); this token only
    // rate-limits abuse (DoS via spam of invalid-license verify attempts).
    match &state.admin_token {
        None => {
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "ok": false, "data": null,
                    "error": {
                        "code": "FORBIDDEN",
                        "message": "POST /api/license requires DBMASTER_SERVER_ADMIN_TOKEN to be configured on remote servers",
                    }
                })),
            ));
        }
        Some(expected) => {
            let provided = headers
                .get("X-Admin-Token")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            // constant-time compare (subtle crate) — though the signature is
            // the real boundary, avoid leaking token via timing anyway.
            use subtle::ConstantTimeEq;
            let p = provided.as_bytes();
            let e = expected.as_bytes();
            let ok = p.len() == e.len() && p.ct_eq(e).unwrap_u8() == 1;
            if !ok {
                return Err((
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "ok": false, "data": null,
                        "error": {"code": "UNAUTHORIZED", "message": "invalid admin token"}
                    })),
                ));
            }
        }
    }

    // (3) Verify + resolve entitlement via the SAME pipeline boot uses.
    let new_state = dbmaster_license::resolve_entitlement_with_text(
        &state.pool,
        Some(body.license.clone()),
    )
    .await
    .map_err(|e| {
        (
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {"code": "INVALID_LICENSE", "message": e.to_string()}
            })),
        )
    })?;

    // (4-5) Branch on resolved state. Gated → do not write file (avoid
    // persisting a bad license that re-Gates on next boot).
    //
    // We split into two matches: first borrow `new_state` to extract display
    // fields for the response, then move it into the ArcSwap store. Doing it
    // in one `match new_state { ... }` would force cloning every field; this
    // way only the displayed strings are cloned.
    match &new_state {
        EntitlementState::Gated { reason } => {
            // Do NOT write file — bad license would persist + re-Gate on boot.
            use dbmaster_license::GatedReason;
            let code = match reason {
                GatedReason::TrialExpired => "TRIAL_EXPIRED",
                GatedReason::LicenseInvalid => "INVALID_LICENSE",
                GatedReason::InstanceMismatch => "INSTANCE_MISMATCH",
                GatedReason::LicenseExpired => "EXPIRED",
            };
            return Ok(Json(serde_json::json!({
                "ok": false,
                "data": null,
                "error": {
                    "code": code,
                    "message": format!("license rejected: {:?}", reason),
                }
            })));
        }
        _ => {} // Licensed/Trial fall through to the write+swap path below.
    }

    // Only Licensed/Trial reach here. Write file FIRST. If write fails, do NOT
    // swap (keeps the old entitlement consistent with the on-disk license).
    if let Err(e) = write_license_file(&body.license) {
        tracing::error!(error = %e, "license file write failed; entitlement NOT swapped");
        return Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {"code": "FILE_WRITE_FAILED", "message": e.to_string()}
            })),
        ));
    }

    // Atomic swap — HTTP gates reflect new state immediately. Extract display
    // fields after the move so the borrow checker is happy.
    state.entitlement.store(std::sync::Arc::new(new_state));
    let ent = state.entitlement.load();
    match &**ent {
        EntitlementState::Licensed { license, expires_at } => {
            let expires_iso = expires_at.map(|dt| dt.to_rfc3339());
            tracing::info!(
                license_type = %license.license_type,
                "entitlement swapped to Licensed via POST /api/license"
            );
            Ok(Json(serde_json::json!({
                "ok": true,
                "data": {
                    "state": "licensed",
                    "license_type": license.license_type,
                    "expires_at": expires_iso,
                    "scheduler_note": "restart_required_for_schedulers",
                },
                "error": null,
            })))
        }
        EntitlementState::Trial { expires_at } => {
            Ok(Json(serde_json::json!({
                "ok": true,
                "data": {
                    "state": "trial",
                    "expires_at": expires_at.to_rfc3339(),
                    "scheduler_note": "restart_required_for_schedulers",
                },
                "error": null,
            })))
        }
        EntitlementState::Gated { .. } => {
            // Unreachable: Gated was handled above and returned early.
            unreachable!("gated state should have been returned early above")
        }
    }
}
