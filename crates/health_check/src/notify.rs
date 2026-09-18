//! Webhook delivery for health-check events — `dbmaster.health-event.v1`.
//!
//! Mirrors drift::notify / data_sync::notify transport layer (URL validation +
//! retry + backoff) with a health-check-specific payload struct. The three
//! crates cannot share a module because each WebhookPayload is hard-coupled to
//! its domain types. See ADR-0004 §2.5 + data_sync::notify §1 for the decision
//! to accept this duplication rather than introduce a shared crate dependency.
//!
//! Contract guarantees (same as drift / data_sync):
//! - Payload schema locked at `dbmaster.health-event.v1` (append-only).
//! - URL must be `https://` (anywhere) OR `http://localhost|127.0.0.1|[::1]`
//!   (dev-mode only). No host/port/user/password in the payload body.
//! - Retry: 4 total attempts (initial + 3 retries) with backoff 1s / 4s / 16s.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::alert::{AlertChange, Severity, Trigger};

/// Locked payload schema identifier.
pub const PAYLOAD_SCHEMA: &str = "dbmaster.health-event.v1";

/// Default per-request timeout (10s).
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Backoff intervals between retries (1s, 4s, 16s).
const DEFAULT_BACKOFFS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(4),
    Duration::from_secs(16),
];

/// Reference to the task that produced this event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRef {
    pub id: String,
    pub name: String,
}

/// Connection descriptor — id + name only, no host/port/user (定律 5 hard
/// exclusion, same as drift/data_sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRef {
    pub id: String,
    pub name: String,
}

/// Source DB descriptor (db_type + database name; no host/port).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRef {
    pub db_type: String,
    pub database: String,
}

/// Alert block embedded in the payload — one per [`AlertChange`] the run
/// produced. The M4 runner emits one webhook PER change (so receivers can
/// dedupe by event_id and route by metric without parsing a list).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    /// `connectivity` | `row_count` | `missing_pk` | `connection_count`.
    pub metric: String,
    /// `critical` | `warning` | `info`.
    pub severity: String,
    /// `alert` (newly breached) | `resolved` (recovered).
    pub state: String,
    /// Metric-specific context (latency/error/large_tables/table/count).
    /// Redacted before delivery — no credential / SQL / PII.
    pub detail: serde_json::Value,
}

/// The webhook payload. Fields are append-only after release (schema-locked,
/// ADR-0004 §2.5 evolution rule).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub schema: String,
    pub event_id: String,
    pub event_at: String,
    pub instance_uuid: String,
    pub task: TaskRef,
    pub connection: ConnectionRef,
    pub source: SourceRef,
    pub alert: AlertPayload,
}

impl WebhookPayload {
    /// Build a payload from an [`AlertChange`] + task/connection/source context.
    /// `event_id` should be a fresh uuid v4; `event_at` an RFC3339 UTC string.
    pub fn from_alert_change(
        event_id: impl Into<String>,
        event_at: impl Into<String>,
        instance_uuid: impl Into<String>,
        task: TaskRef,
        connection: ConnectionRef,
        source: SourceRef,
        change: &AlertChange,
    ) -> Self {
        let severity = match change.severity {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        let state = match change.trigger {
            Trigger::Alert => "alert",
            Trigger::Resolved => "resolved",
        };
        Self {
            schema: PAYLOAD_SCHEMA.to_string(),
            event_id: event_id.into(),
            event_at: event_at.into(),
            instance_uuid: instance_uuid.into(),
            task,
            connection,
            source,
            alert: AlertPayload {
                metric: change.metric.clone(),
                severity: severity.to_string(),
                state: state.to_string(),
                detail: change.detail.clone(),
            },
        }
    }

    /// #8 — Render as a Slack incoming-webhook text message.
    ///
    /// Slack rejects the full `dbmaster.health-event.v1` payload (expects
    /// `{"text": "..."}`); this method produces a concise alert summary.
    /// `detail` is already redacted by the runner (定律 5 — no credentials /
    /// SQL / PII), and is stringified defensively here in case it's a non-string
    /// JSON value (e.g. a number for thresholds).
    pub fn to_slack_text(&self) -> String {
        let detail_str = match &self.alert.detail {
            serde_json::Value::String(s) => s.clone(),
            other if !other.is_null() => other.to_string(),
            _ => String::new(),
        };
        // Truncate so a verbose detail doesn't blow past Slack's text limit.
        let detail = if detail_str.chars().count() > 400 {
            format!("{}…", detail_str.chars().take(400).collect::<String>())
        } else if detail_str.is_empty() {
            String::new()
        } else {
            detail_str
        };
        let emoji = match self.alert.severity.as_str() {
            "critical" => "🚨",
            "warning" => "⚠️",
            _ => "ℹ️",
        };
        let mut text = format!(
            "{emoji} *DBMaster health {sev}* on `{conn}` ({db_type}/{db})\n\
             Task `{task}` • metric `{metric}` • {state}",
            sev = self.alert.severity,
            conn = self.connection.name,
            db_type = self.source.db_type,
            db = self.source.database,
            task = self.task.name,
            metric = self.alert.metric,
            state = self.alert.state,
        );
        if !detail.is_empty() {
            text.push_str(&format!("\n>{detail}"));
        }
        text
    }
}

/// #8 — Returns true if the URL targets Slack's incoming-webhook host.
fn is_slack_url(url: &reqwest::Url) -> bool {
    match url.host_str() {
        Some(host) => host == "hooks.slack.com" || host.ends_with(".hooks.slack.com"),
        None => false,
    }
}

/// Outcome of a delivery attempt series.
#[derive(Debug, Clone)]
pub struct DeliveryReceipt {
    pub attempts: u32,
    pub final_status: DeliveryStatus,
    pub last_status_code: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryStatus {
    Delivered,
    PermanentFailure,
}

/// Errors that mean "do not retry" — caller must surface them.
#[derive(Debug)]
pub enum NotifyError {
    InsecureUrl,
    MalformedUrl(String),
    ClientBuild(String),
    AllAttemptsFailed {
        attempts: u32,
        last_status: Option<u16>,
        last_error: String,
    },
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsecureUrl => write!(f, "insecure webhook URL (require https or loopback)"),
            Self::MalformedUrl(s) => write!(f, "malformed webhook URL: {s}"),
            Self::ClientBuild(s) => write!(f, "reqwest client build failed: {s}"),
            Self::AllAttemptsFailed {
                attempts,
                last_status,
                last_error,
            } => write!(
                f,
                "all {attempts} webhook attempts failed (last_status={last_status:?}, last_error={last_error})"
            ),
        }
    }
}

impl std::error::Error for NotifyError {}

/// Validate a webhook URL: `https://` always OK; `http://` only to loopback
/// when `dev_mode=true`. Everything else rejected.
pub fn validate_webhook_url(url: &str, dev_mode: bool) -> Result<(), NotifyError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| NotifyError::MalformedUrl(url.to_string()))?;
    let scheme = scheme.trim();
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(());
    }
    if scheme.eq_ignore_ascii_case("http") && dev_mode {
        let authority = rest.split('/').next().unwrap_or("");
        let host = extract_host(authority);
        if is_loopback_host(host) {
            return Ok(());
        }
        return Err(NotifyError::InsecureUrl);
    }
    Err(NotifyError::InsecureUrl)
}

fn extract_host(authority: &str) -> &str {
    if let Some(stripped) = authority.strip_prefix('[') {
        return stripped.split(']').next().unwrap_or("");
    }
    authority.split(':').next().unwrap_or("")
}

fn is_loopback_host(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

/// Deliver with default backoff (1s/4s/16s, 4 total attempts).
pub async fn deliver(
    payload: &WebhookPayload,
    url: &str,
    timeout: Duration,
    dev_mode: bool,
) -> Result<DeliveryReceipt, NotifyError> {
    deliver_with_backoff(payload, url, timeout, dev_mode, &DEFAULT_BACKOFFS).await
}

/// Deliver with explicit backoff schedule (tests can pass zero waits).
pub async fn deliver_with_backoff(
    payload: &WebhookPayload,
    url: &str,
    timeout: Duration,
    dev_mode: bool,
    backoffs: &[Duration],
) -> Result<DeliveryReceipt, NotifyError> {
    validate_webhook_url(url, dev_mode)?;

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!(
            "dbmaster-server/",
            env!("CARGO_PKG_VERSION"),
            " health-check-webhook"
        ))
        .build()
        .map_err(|e| NotifyError::ClientBuild(e.to_string()))?;

    let req_url = reqwest::Url::parse(url)
        .map_err(|e| NotifyError::MalformedUrl(e.to_string()))?;

    // #8 — Slack incoming-webhook detection. Switches the POST body to
    // Slack's `{"text": "..."}` envelope (the full health-event payload is
    // rejected by hooks.slack.com).
    let slack_body = if is_slack_url(&req_url) {
        Some(serde_json::json!({ "text": payload.to_slack_text() }))
    } else {
        None
    };

    let total_attempts = (backoffs.len() + 1) as u32;
    let mut last_status: Option<u16> = None;
    let mut last_error = String::new();

    for attempt in 1..=total_attempts {
        if attempt > 1 {
            let idx = (attempt - 2) as usize;
            let wait = backoffs.get(idx).copied().unwrap_or(Duration::ZERO);
            tokio::time::sleep(wait).await;
        }

        let request_builder = client
            .post(req_url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        let result = match &slack_body {
            Some(body) => request_builder.json(body).send().await,
            None => request_builder.json(payload).send().await,
        };

        match result {
            Ok(resp) => {
                let status = resp.status();
                last_status = Some(status.as_u16());
                if status.is_success() {
                    return Ok(DeliveryReceipt {
                        attempts: attempt,
                        final_status: DeliveryStatus::Delivered,
                        last_status_code: Some(status.as_u16()),
                    });
                }
                last_error = format!("HTTP {}", status.as_u16());
                tracing::warn!(
                    attempt,
                    status = status.as_u16(),
                    "health-check webhook attempt failed; will retry"
                );
            }
            Err(e) => {
                last_status = None;
                last_error = e.to_string();
                tracing::warn!(
                    attempt,
                    error = %e,
                    "health-check webhook transport error; will retry"
                );
            }
        }
    }

    Err(NotifyError::AllAttemptsFailed {
        attempts: total_attempts,
        last_status,
        last_error,
    })
}

/// Extract the first webhook URL from a `notify_channels` JSON array string
/// (stored in `scheduled_tasks.notify_channels`). Returns `None` if the array
/// is empty or the first entry has no `url` field.
///
/// Copied from data_sync::notify (9-line function, no cross-crate deps).
pub fn first_webhook_url(notify_channels_json: &str) -> Option<String> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(notify_channels_json).ok()?;
    let first = arr.first()?;
    first.get("url").and_then(|v| v.as_str()).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_alert_change(trigger: Trigger, severity: Severity) -> AlertChange {
        AlertChange {
            metric: "connectivity".to_string(),
            severity,
            trigger,
            detail: serde_json::json!({ "latency_ms": 0 }),
        }
    }

    #[test]
    fn payload_carries_schema_constant() {
        let change = sample_alert_change(Trigger::Alert, Severity::Critical);
        let p = WebhookPayload::from_alert_change(
            "evt-1", "2026-08-12T00:00:00Z", "inst-1",
            TaskRef { id: "t1".into(), name: "task".into() },
            ConnectionRef { id: "c1".into(), name: "conn".into() },
            SourceRef { db_type: "mysql".into(), database: "prod".into() },
            &change,
        );
        assert_eq!(p.schema, "dbmaster.health-event.v1");
    }

    #[test]
    fn from_alert_change_maps_severity_and_trigger() {
        let alert = sample_alert_change(Trigger::Alert, Severity::Critical);
        let p = WebhookPayload::from_alert_change(
            "e", "t", "u",
            TaskRef { id: "t".into(), name: "n".into() },
            ConnectionRef { id: "c".into(), name: "n".into() },
            SourceRef { db_type: "mysql".into(), database: "d".into() },
            &alert,
        );
        assert_eq!(p.alert.severity, "critical");
        assert_eq!(p.alert.state, "alert");

        let resolved = sample_alert_change(Trigger::Resolved, Severity::Info);
        let p2 = WebhookPayload::from_alert_change(
            "e", "t", "u",
            TaskRef { id: "t".into(), name: "n".into() },
            ConnectionRef { id: "c".into(), name: "n".into() },
            SourceRef { db_type: "postgres".into(), database: "d".into() },
            &resolved,
        );
        assert_eq!(p2.alert.severity, "info");
        assert_eq!(p2.alert.state, "resolved");
    }

    #[test]
    fn payload_serializes_round_trip() {
        let change = sample_alert_change(Trigger::Alert, Severity::Warning);
        let p = WebhookPayload::from_alert_change(
            "evt-uuid", "2026-08-12T00:00:00Z", "inst-uuid",
            TaskRef { id: "task-1".into(), name: "Prod MySQL".into() },
            ConnectionRef { id: "conn-1".into(), name: "prod-db".into() },
            SourceRef { db_type: "mysql".into(), database: "shop".into() },
            &change,
        );
        let json = serde_json::to_string(&p).unwrap();
        let back: WebhookPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.alert.metric, "connectivity");
        assert_eq!(back.source.db_type, "mysql");
        assert_eq!(back.task.id, "task-1");
    }

    // ── #8 Slack formatting ──

    fn sample_slack_payload(severity: Severity, trigger: Trigger, detail: serde_json::Value) -> WebhookPayload {
        let change = AlertChange {
            metric: "connectivity".to_string(),
            severity,
            trigger,
            detail,
        };
        WebhookPayload::from_alert_change(
            "evt-1", "2026-08-06T12:00:00Z", "install-uuid",
            TaskRef { id: "t1".into(), name: "shop-health".into() },
            ConnectionRef { id: "c1".into(), name: "shop-prod".into() },
            SourceRef { db_type: "mysql".into(), database: "shop".into() },
            &change,
        )
    }

    #[test]
    fn slack_text_critical_alert_includes_emoji_conn_metric() {
        let p = sample_slack_payload(
            Severity::Critical,
            Trigger::Alert,
            serde_json::json!({ "latency_ms": 0, "error": "refused" }),
        );
        let text = p.to_slack_text();
        assert!(text.starts_with("🚨"), "missing critical emoji: {text}");
        assert!(text.contains("critical"), "missing severity: {text}");
        assert!(text.contains("shop-prod"), "missing connection: {text}");
        assert!(text.contains("connectivity"), "missing metric: {text}");
        assert!(text.contains("refused"), "missing detail: {text}");
    }

    #[test]
    fn slack_text_warning_uses_warning_emoji() {
        let p = sample_slack_payload(
            Severity::Warning,
            Trigger::Alert,
            serde_json::json!({ "rows": 10_000_000 }),
        );
        let text = p.to_slack_text();
        assert!(text.starts_with("⚠️"), "missing warning emoji: {text}");
        // Numeric detail value is stringified
        assert!(text.contains("10000000"));
    }

    #[test]
    fn slack_text_resolved_state_labeled() {
        let p = sample_slack_payload(
            Severity::Info,
            Trigger::Resolved,
            serde_json::json!("back online"),
        );
        let text = p.to_slack_text();
        assert!(text.contains("resolved"), "missing resolved state: {text}");
    }

    #[test]
    fn slack_text_truncates_oversize_detail() {
        let long = serde_json::json!(format!("{}{}", "x".repeat(1000), "y"));
        let p = sample_slack_payload(Severity::Critical, Trigger::Alert, long);
        let text = p.to_slack_text();
        assert!(text.chars().count() < 1000);
        assert!(text.contains('…'));
    }

    #[test]
    fn is_slack_url_detects_canonical_and_subdomain() {
        assert!(is_slack_url(&reqwest::Url::parse("https://hooks.slack.com/services/T/B/X").unwrap()));
        assert!(is_slack_url(&reqwest::Url::parse("https://team.hooks.slack.com/x").unwrap()));
        assert!(!is_slack_url(&reqwest::Url::parse("https://example.com/webhook").unwrap()));
        assert!(!is_slack_url(&reqwest::Url::parse("https://hooks.slack.com.evil.example.com/x").unwrap()));
    }

    #[test]
    fn validate_https_always_ok() {
        assert!(validate_webhook_url("https://hooks.example.com/x", false).is_ok());
        assert!(validate_webhook_url("https://hooks.example.com/x", true).is_ok());
    }

    #[test]
    fn validate_http_loopback_only_in_dev_mode() {
        // Dev mode → loopback OK.
        assert!(validate_webhook_url("http://localhost:9999/hook", true).is_ok());
        assert!(validate_webhook_url("http://127.0.0.1:9999/hook", true).is_ok());
        assert!(validate_webhook_url("http://[::1]:9999/hook", true).is_ok());
        // Dev mode → non-loopback http rejected.
        assert!(validate_webhook_url("http://hooks.example.com/x", true).is_err());
        // Prod mode → all http rejected.
        assert!(validate_webhook_url("http://localhost:9999/hook", false).is_err());
    }

    #[test]
    fn validate_rejects_malformed() {
        assert!(validate_webhook_url("not-a-url", false).is_err());
        assert!(validate_webhook_url("ftp://x", false).is_err());
    }

    #[test]
    fn first_webhook_url_extracts_first_url() {
        let json = r#"[{"url":"https://a.example.com/h"},{"url":"https://b.example.com/h"}]"#;
        assert_eq!(
            first_webhook_url(json).as_deref(),
            Some("https://a.example.com/h")
        );
    }

    #[test]
    fn first_webhook_url_none_on_empty_or_malformed() {
        assert!(first_webhook_url("[]").is_none());
        assert!(first_webhook_url("not json").is_none());
        assert!(first_webhook_url(r#"[{"no_url":true}]"#).is_none());
    }

    #[test]
    fn payload_excludes_connection_credentials_by_construction() {
        // ConnectionRef only carries id+name; there is no host/port/user field
        // to leak. This test documents that invariant.
        let change = sample_alert_change(Trigger::Alert, Severity::Critical);
        let p = WebhookPayload::from_alert_change(
            "e", "t", "u",
            TaskRef { id: "t".into(), name: "n".into() },
            ConnectionRef { id: "c".into(), name: "n".into() },
            SourceRef { db_type: "mysql".into(), database: "d".into() },
            &change,
        );
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("password"));
        assert!(!json.contains("host"));
        assert!(!json.contains("port"));
        assert!(!json.contains("user"));
    }
}
