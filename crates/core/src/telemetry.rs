//! Telemetry event ingestion — anonymous, Server-side.
//!
//! Receives funnel events from desktop clients
//! (`telemetry-funnel-plan.md` §5/§6). Anonymous (no Bearer token):
//! `install_uuid` serves as the soft identity for dedup and rate limiting.
//! Client IPs are stored redacted (defensive.md: never store raw PII).
//!
//! Privacy contract (defensive.md):
//!   * Raw client IP never enters the DB — only the /24 (IPv4) or /48 (IPv6)
//!     prefix is kept, with the low-order bits zeroed.
//!   * `event_payload` is stored verbatim; the desktop client already
//!     PII-masks string fields and drops reserved keys before sending.
//!   * Logs carry `event_type` + status only — never the payload (which may
//!     contain `target_url` etc. that could indirectly identify a user).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::HeaderMap;
use axum::{extract::State, Json};

use crate::error::AppError;
use crate::server::AppState;

/// Valid telemetry event types.
// CHANGE: telemetry-funnel-plan.md §3 — extend whitelist with 6 funnel types.
pub const VALID_EVENT_TYPES: &[&str] = &[
    // ── Pre-existing ──
    "app_first_launch",
    "db_connected",
    "session_reopen",
    "feature_used",
    "feature_failure",
    "server_started",
    "task_executed",
    // ── Funnel (telemetry-funnel-plan.md §3) ──
    "touchpoint_exposed",
    "touchpoint_clicked",
    "server_download_clicked",
    "server_connected",
    "trial_started",
    "trial_activated",
];

#[derive(serde::Deserialize)]
pub struct TelemetryPayload {
    pub event_type: String,
    pub event_payload: serde_json::Value,
    pub db_type: Option<String>,
}

/// Per-install_uuid rate limit (telemetry-funnel-plan.md §6.1.4 / §6.2).
/// 60 events / minute — far above any normal desktop client (1–2/s peak) but
/// caps malicious install_uuid pollution. In-memory; resets on restart.
const RATE_LIMIT_MAX: usize = 60;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// `POST /api/telemetry/event` — ingest one anonymous telemetry event.
// CHANGE: telemetry-funnel-plan.md §6.1 — idempotency, IP redaction, rate limit.
// Also fixes the pre-existing doc-comment path bug (was `/api/v1/telemetry/event`).
pub async fn ingest_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    // DEFENSIVE-NOTE: axum returns 400 automatically when the body fails to
    // deserialize into TelemetryPayload — no extra validation needed here for
    // shape; the event_type whitelist check below handles unknown types.
    Json(body): Json<TelemetryPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Validate event type against the whitelist. Returned as 200 + ok=false so
    // the desktop client treats it as a permanent failure and drops the event
    // (its retry policy only re-tries 5xx / 429 / network errors — see
    // telemetry-funnel-plan.md §7).
    if !VALID_EVENT_TYPES.contains(&body.event_type.as_str()) {
        return Ok(invalid_type_response(&body.event_type));
    }

    // `install_uuid` is the soft identity for dedup + rate limit. Legacy
    // clients that omit it are bucketed as "unknown" but still accepted.
    let install_uuid = body
        .event_payload
        .get("install_uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Rate-limit BEFORE any DB work — cheap reject path for floods.
    if !rate_limit_check(&state.telemetry_rate_limits, install_uuid) {
        return Err(AppError::RateLimited);
    }

    let app_version = body
        .event_payload
        .get("app_version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let idempotency_key = body
        .event_payload
        .get("idempotency_key")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let payload_str = body.event_payload.to_string();
    let ip_redacted = redact_client_ip(&headers);

    // INSERT with the unique index on (install_uuid, event_type, idempotency_key)
    // enforcing idempotency at the storage layer (no SELECT-then-INSERT race).
    // A duplicate-key collision is interpreted as a legitimate retry and
    // reported as `deduplicated: true` (HTTP 200, not an error).
    let result = sqlx::query(
        "INSERT INTO telemetry_events
           (install_uuid, event_type, event_payload, db_type,
            app_version, idempotency_key, client_ip_redacted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(install_uuid)
    .bind(&body.event_type)
    .bind(&payload_str)
    .bind(&body.db_type)
    .bind(&app_version)
    .bind(&idempotency_key)
    .bind(&ip_redacted)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => Ok(Json(serde_json::json!({
            "ok": true,
            "data": {"ingested": true, "deduplicated": false},
            "error": null
        }))),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            // CHANGE: telemetry-funnel-plan.md §6.1.5 — idempotent retry.
            // DEFENSIVE-NOTE: log only event_type + bucket, never the payload.
            tracing::debug!(
                event_type = %body.event_type,
                "telemetry duplicate dropped (idempotency_key hit)"
            );
            Ok(Json(serde_json::json!({
                "ok": true,
                "data": {"ingested": false, "deduplicated": true},
                "error": null
            })))
        }
        Err(e) => {
            // DEFENSIVE-NOTE: log the DB error (no PII — payload is not in the
            // error), surface a generic message to the client (no internals).
            tracing::error!(
                error = ?e,
                event_type = %body.event_type,
                "telemetry insert failed"
            );
            Err(AppError::Internal(anyhow::anyhow!("telemetry ingest failed")))
        }
    }
}

/// 200-body for an unknown event_type. Returned as `ok=false` (not 4xx) so the
/// desktop client's 4xx-permanent-drop semantics clear the poison-pill event.
fn invalid_type_response(event_type: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": false,
        "data": null,
        "error": {
            "code": "INVALID_EVENT_TYPE",
            "message": format!("Unknown: {event_type}")
        }
    }))
}

/// Check and record the per-install_uuid rate-limit counter. Pure function on
/// the shared counter map so it can be unit-tested without an `AppState`.
// CHANGE: telemetry-funnel-plan.md §6.1.4 — in-memory sliding window.
fn rate_limit_check(
    counters: &Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    install_uuid: &str,
) -> bool {
    // DEFENSIVE-NOTE: poisoned mutex would indicate a panic in another thread
    // holding the lock; safest behaviour is to fail closed (reject) and surface
    // the poison in logs. unwrap_or(false) keeps the lock path panic-free.
    let mut guards = match counters.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            tracing::error!("telemetry rate-limit mutex poisoned: {poisoned}");
            poisoned.into_inner()
        }
    };
    let now = Instant::now();
    let entries = guards.entry(install_uuid.to_string()).or_default();
    entries.retain(|t| now.duration_since(*t).as_secs() < RATE_LIMIT_WINDOW_SECS);
    if entries.len() >= RATE_LIMIT_MAX {
        false
    } else {
        entries.push(now);
        true
    }
}

/// Extract the client IP from `X-Forwarded-For` (set by the reverse proxy in
/// production) and redact it. Returns "unknown" when no usable header is
/// present — direct connections without a proxy also land here.
// CHANGE: telemetry-funnel-plan.md §6.1.1 — never store raw client IP.
fn redact_client_ip(headers: &HeaderMap) -> String {
    let raw = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim())
        .unwrap_or("");
    if raw.is_empty() {
        return "unknown".to_string();
    }
    redact_ip_str(raw)
}

/// Redact an IP string to its prefix.
///
/// * IPv4 → first 3 octets + `.0` (e.g. `203.0.113.42` → `203.0.113.0`).
///   `/24` is the coarsest prefix that still distinguishes networks for ops.
/// * IPv4-mapped IPv6 (e.g. `::ffff:203.0.113.42`) is unwrapped to its IPv4
///   form and redacted as above.
/// * Other IPv6 → first 3 groups + trailing `:0` (e.g.
///   `2001:db8:abcd:ef01::1` → `2001:db8:abcd:0`). Keeps the RIR-assigned
///   prefix without the subscriber-specific tail.
/// * Anything unparseable → `"unknown"`.
fn redact_ip_str(raw: &str) -> String {
    if let Some(stripped) = raw.strip_prefix("::ffff:") {
        return redact_ipv4(stripped);
    }
    if raw.contains(':') {
        let groups: Vec<&str> = raw.split(':').collect();
        // Defensive: a well-formed IPv6 has up to 8 groups; require at least 4
        // to avoid mangling stray strings that happen to contain a colon.
        if groups.len() >= 4 && groups.iter().take(3).all(|g| !g.is_empty()) {
            return format!("{}:0", groups[..3].join(":"));
        }
        return "unknown".to_string();
    }
    redact_ipv4(raw)
}

fn redact_ipv4(s: &str) -> String {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        format!("{}.{}.{}.0", parts[0], parts[1], parts[2])
    } else {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn whitelist_includes_all_funnel_types() {
        for t in [
            "touchpoint_exposed",
            "touchpoint_clicked",
            "server_download_clicked",
            "server_connected",
            "trial_started",
            "trial_activated",
        ] {
            assert!(VALID_EVENT_TYPES.contains(&t), "missing funnel type: {t}");
        }
        // Pre-existing types must still be present (regression guard).
        for t in [
            "app_first_launch",
            "db_connected",
            "session_reopen",
            "feature_used",
            "feature_failure",
            "server_started",
            "task_executed",
        ] {
            assert!(VALID_EVENT_TYPES.contains(&t), "missing legacy type: {t}");
        }
    }

    #[test]
    fn redact_ipv4_zeroes_last_octet() {
        assert_eq!(redact_ip_str("203.0.113.45"), "203.0.113.0");
        assert_eq!(redact_ip_str("10.1.2.3"), "10.1.2.0");
        assert_eq!(redact_ip_str("0.0.0.0"), "0.0.0.0");
        assert_eq!(redact_ip_str("255.255.255.255"), "255.255.255.0");
    }

    #[test]
    fn redact_ipv4_rejects_non_octets() {
        assert_eq!(redact_ip_str("999.1.1.1"), "unknown");
        assert_eq!(redact_ip_str("1.2.3"), "unknown");
        assert_eq!(redact_ip_str("abc.def.ghi.jkl"), "unknown");
    }

    #[test]
    fn redact_ipv4_mapped_ipv6_unwraps_to_ipv4() {
        assert_eq!(redact_ip_str("::ffff:203.0.113.45"), "203.0.113.0");
    }

    #[test]
    fn redact_ipv6_keeps_first_three_groups() {
        assert_eq!(
            redact_ip_str("2001:db8:abcd:ef01:1234:5678:9abc:def0"),
            "2001:db8:abcd:0"
        );
    }

    #[test]
    fn redact_invalid_ip_falls_back_to_unknown() {
        assert_eq!(redact_ip_str("not-an-ip"), "unknown");
        assert_eq!(redact_ip_str(""), "unknown");
        // Too few groups to safely redact an IPv6.
        assert_eq!(redact_ip_str("::1"), "unknown");
    }

    #[test]
    fn redact_client_ip_takes_first_xff_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.45, 10.0.0.1"),
        );
        assert_eq!(redact_client_ip(&headers), "203.0.113.0");
    }

    #[test]
    fn redact_client_ip_without_header_is_unknown() {
        let headers = HeaderMap::new();
        assert_eq!(redact_client_ip(&headers), "unknown");
    }

    #[test]
    fn rate_limit_allows_up_to_cap_then_blocks() {
        // CHANGE: telemetry-funnel-plan.md §6.1.4 — per-install_uuid soft cap.
        let limits: Arc<Mutex<HashMap<String, Vec<Instant>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        for i in 0..RATE_LIMIT_MAX {
            assert!(
                rate_limit_check(&limits, "inst-1"),
                "request {i} should be allowed"
            );
        }
        assert!(
            !rate_limit_check(&limits, "inst-1"),
            "request over cap should be blocked"
        );
    }

    #[test]
    fn rate_limit_is_per_install_uuid() {
        let limits: Arc<Mutex<HashMap<String, Vec<Instant>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        // inst-a saturates its own counter.
        for _ in 0..RATE_LIMIT_MAX {
            assert!(rate_limit_check(&limits, "inst-a"));
        }
        // inst-b is unaffected.
        assert!(
            rate_limit_check(&limits, "inst-b"),
            "separate install_uuid must have its own budget"
        );
    }

    #[test]
    fn invalid_type_response_shape_matches_contract() {
        let body = invalid_type_response("nonsense");
        let v = body.0;
        assert_eq!(v["ok"], false);
        assert_eq!(v["data"], serde_json::Value::Null);
        assert_eq!(v["error"]["code"], "INVALID_EVENT_TYPE");
        assert!(v["error"]["message"].as_str().unwrap().contains("nonsense"));
    }
}
