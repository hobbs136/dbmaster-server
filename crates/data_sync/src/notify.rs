//! Webhook delivery for data-sync events — `dbmaster.data-sync-event.v1`.
//!
//! Mirrors drift::notify's transport layer (URL validation + retry + backoff)
//! but with a data-sync-specific payload struct. The two crates cannot share
//! a module because drift::notify's WebhookPayload is hard-coupled to
//! drift::diff types (Drift/DriftKindCounts). See plan M1.2 for the decision
//! to accept this duplication rather than introduce a shared crate dependency.
//!
//! Contract guarantees (same as drift::notify):
//! - Payload schema locked at `dbmaster.data-sync-event.v1`.
//! - URL must be `https://` (anywhere) OR `http://localhost|127.0.0.1|[::1]`
//!   (dev-mode only). No host/port/user/password in the payload body.
//! - Retry: 4 total attempts (initial + 3 retries) with backoff 1s / 4s / 16s.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Locked payload schema identifier.
pub const PAYLOAD_SCHEMA: &str = "dbmaster.data-sync-event.v1";

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

/// Connection descriptor — name only, no host/port/user (定律 5 hard exclusion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRef {
    pub id: String,
    pub name: String,
}

/// Run outcome summary embedded in the webhook payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSummary {
    pub processed_rows: u64,
    pub failed_rows: u64,
    pub duration_ms: u64,
    pub canceled: bool,
}

/// The webhook payload. Fields are append-only after release (schema-locked).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub schema: String,
    pub event_id: String,
    pub event_at: String,
    pub instance_uuid: String,
    pub task: TaskRef,
    pub source: ConnectionRef,
    pub target: ConnectionRef,
    pub summary: SyncSummary,
    /// Present only on failure (redacted, no credentials).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl WebhookPayload {
    pub fn new(
        event_id: impl Into<String>,
        event_at: impl Into<String>,
        instance_uuid: impl Into<String>,
        task: TaskRef,
        source: ConnectionRef,
        target: ConnectionRef,
        summary: SyncSummary,
        error: Option<String>,
    ) -> Self {
        Self {
            schema: PAYLOAD_SCHEMA.to_string(),
            event_id: event_id.into(),
            event_at: event_at.into(),
            instance_uuid: instance_uuid.into(),
            task,
            source,
            target,
            summary,
            error,
        }
    }

    /// #8 — Render as a Slack incoming-webhook text message.
    ///
    /// Slack rejects the full `dbmaster.data-sync-event.v1` payload (expects
    /// `{"text": "..."}`); this method produces a concise summary. The
    /// `error` field (when present) is included — it's already redacted by
    /// the runner (定律 5 hard exclusion: no credentials / SQL / PII).
    pub fn to_slack_text(&self) -> String {
        let status = if self.summary.canceled {
            "canceled"
        } else if self.summary.failed_rows > 0 || self.error.is_some() {
            "failed"
        } else {
            "completed"
        };
        let mut text = format!(
            "*DBMaster data sync {status}* `{src}` → `{dst}`\n\
             Task `{task}` • {processed} row(s) processed ({failed} failed) in {ms} ms",
            src = self.source.name,
            dst = self.target.name,
            task = self.task.name,
            processed = self.summary.processed_rows,
            failed = self.summary.failed_rows,
            ms = self.summary.duration_ms,
        );
        if let Some(err) = &self.error {
            // Truncate so a verbose driver error doesn't blow past Slack's
            // 3000-char text limit (the runner already redacts to first line +
            // 200 chars; this is a defensive second guard).
            let truncated = if err.chars().count() > 400 {
                format!("{}…", err.chars().take(400).collect::<String>())
            } else {
                err.clone()
            };
            text.push_str(&format!("\n>Error: {truncated}"));
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
            Self::AllAttemptsFailed { attempts, last_status, last_error } => write!(
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
            " data-sync-webhook"
        ))
        .build()
        .map_err(|e| NotifyError::ClientBuild(e.to_string()))?;

    let req_url = reqwest::Url::parse(url)
        .map_err(|e| NotifyError::MalformedUrl(e.to_string()))?;

    // #8 — Slack incoming-webhook detection. Switches the POST body to
    // Slack's `{"text": "..."}` envelope (the full data-sync-event payload
    // is rejected by hooks.slack.com).
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
                    "data-sync webhook attempt failed; will retry"
                );
            }
            Err(e) => {
                last_status = None;
                last_error = e.to_string();
                tracing::warn!(attempt, error = %e, "data-sync webhook transport error; will retry");
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
/// Copied from drift::runner (9-line function, no drift dependencies).
pub fn first_webhook_url(notify_channels_json: &str) -> Option<String> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(notify_channels_json).ok()?;
    let first = arr.first()?;
    first.get("url").and_then(|v| v.as_str()).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(canceled: bool, failed: u64, error: Option<&str>) -> WebhookPayload {
        WebhookPayload::new(
            "evt-1",
            "2026-08-06T12:00:00Z",
            "install-uuid",
            TaskRef { id: "t1".into(), name: "nightly".into() },
            ConnectionRef { id: "src".into(), name: "shop-prod".into() },
            ConnectionRef { id: "dst".into(), name: "shop-replica".into() },
            SyncSummary {
                processed_rows: 100,
                failed_rows: failed,
                duration_ms: 5000,
                canceled,
            },
            error.map(String::from),
        )
    }

    #[test]
    fn slack_text_completed_status() {
        let p = sample_payload(false, 0, None);
        let text = p.to_slack_text();
        assert!(text.contains("completed"), "missing completed status: {text}");
        assert!(text.contains("shop-prod"), "missing source: {text}");
        assert!(text.contains("shop-replica"), "missing target: {text}");
        assert!(text.contains("nightly"), "missing task name: {text}");
        assert!(text.contains("100 row"), "missing row count: {text}");
    }

    #[test]
    fn slack_text_canceled_status() {
        let p = sample_payload(true, 0, None);
        assert!(p.to_slack_text().contains("canceled"));
    }

    #[test]
    fn slack_text_failed_status_includes_redacted_error() {
        let p = sample_payload(false, 5, Some("connection refused"));
        let text = p.to_slack_text();
        assert!(text.contains("failed"));
        assert!(text.contains("connection refused"));
    }

    #[test]
    fn slack_text_truncates_oversize_error() {
        let long = "x".repeat(1000);
        let p = sample_payload(false, 1, Some(&long));
        let text = p.to_slack_text();
        // Defensive truncation keeps Slack text under ~400 chars
        assert!(text.chars().count() < 1000);
        assert!(text.contains('…'), "expected truncation marker: {text}");
    }

    #[test]
    fn is_slack_url_detects_canonical_and_subdomain() {
        assert!(is_slack_url(&reqwest::Url::parse("https://hooks.slack.com/services/T/B/X").unwrap()));
        assert!(is_slack_url(&reqwest::Url::parse("https://team.hooks.slack.com/x").unwrap()));
        assert!(!is_slack_url(&reqwest::Url::parse("https://example.com/webhook").unwrap()));
        assert!(!is_slack_url(&reqwest::Url::parse("https://hooks.slack.com.evil.example.com/x").unwrap()));
    }
}
