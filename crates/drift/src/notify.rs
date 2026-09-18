//! Webhook delivery — `dbmaster.drift-event.v1` payload (ADR-0002 §4.4.2 /
//! v1-C-7 / v1-C-13).
//!
//! Contract guarantees:
//! - Payload schema is locked at `dbmaster.drift-event.v1`; field set and the
//!   11-kind enumeration are append-only (定律 2 / ADR §11 Q5).
//! - URL must be `https://` (anywhere) OR `http://localhost|127.0.0.1|[::1]`
//!   (dev-mode only). Any other form is refused before any network call
//!   (定律 5 — payload never traverses a plaintext link).
//! - Body never carries host/port/user/password or row data — structurally
//!   impossible: those fields simply aren't on [`WebhookPayload`].
//! - Retry: 4 total attempts (initial + 3 retries) with exponential backoff
//!   1s / 4s / 16s. HTTP 2xx ⇒ success; anything else (3xx/4xx/5xx/timeout/
//!   transport) ⇒ retry.
//! - Permanent failure returns `Err`; the runner records it in
//!   `task_run_history.error` (no silent swallow).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::diff::{Drift, DriftKindCounts};

/// Locked payload schema identifier (ADR §4.4.2). Embedded as the top-level
/// `schema` field so receivers can dispatch by it.
pub const PAYLOAD_SCHEMA: &str = "dbmaster.drift-event.v1";

/// Default per-request timeout (env-overridable via
/// `DBMASTER_DRIFT_WEBHOOK_TIMEOUT_SECS`, default 10).
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Default per-request timeout used in tests (kept tiny so the suite is fast).
#[cfg(test)]
const TEST_TIMEOUT: Duration = Duration::from_millis(500);

/// Backoff intervals between retries (1s, 4s, 16s per ADR §4.4.2). Injected
/// via `deliver_with_backoff` so tests can run with zero waits.
const DEFAULT_BACKOFFS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(4),
    Duration::from_secs(16),
];

/// Reference to the task that produced this event (ADR §4.4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRef {
    pub id: String,
    pub name: String,
}

/// Reference to the connection (ADR §4.4.2 — name is customer-supplied,
/// customer's responsibility for PII content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRef {
    pub id: String,
    pub name: String,
}

/// Source DB descriptor. Hard-limited to flavor + database name — no host,
/// no port, no user (定律 5 / ADR §4.4.2 hard exclusion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRef {
    /// Lowercase flavor string: "mysql" | "postgres" (DbType::as_wire_str).
    pub db_type: String,
    pub database: String,
}

/// Drift summary block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftSummary {
    pub prior_snapshot_at: Option<String>,
    pub new_snapshot_at: String,
    pub change_count: u32,
    pub kinds: DriftKindCounts,
}

/// Full `dbmaster.drift-event.v1` payload. Structurally enforces the field
/// set: nothing the runner doesn't put here can leak out (定律 5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub schema: String,
    pub event_id: String,
    pub event_at: String,
    pub instance_uuid: String,
    pub task: TaskRef,
    pub connection: ConnectionRef,
    pub source: SourceRef,
    pub drift_summary: DriftSummary,
    /// All drifts, untruncated (ADR §11 Q5 — v1 does not truncate).
    pub drifts: Vec<Drift>,
}

impl WebhookPayload {
    /// Convenience builder; caller still fills `task`/`connection`/`source`/etc.
    pub fn new(
        event_id: String,
        event_at: String,
        instance_uuid: String,
        drifts: Vec<Drift>,
        prior_snapshot_at: Option<String>,
        new_snapshot_at: String,
    ) -> Self {
        use crate::diff::summarize;
        let kinds = summarize(&drifts);
        let change_count = kinds.total();
        Self {
            schema: PAYLOAD_SCHEMA.to_string(),
            event_id,
            event_at,
            instance_uuid,
            task: TaskRef {
                id: String::new(),
                name: String::new(),
            },
            connection: ConnectionRef {
                id: String::new(),
                name: String::new(),
            },
            source: SourceRef {
                db_type: String::new(),
                database: String::new(),
            },
            drift_summary: DriftSummary {
                prior_snapshot_at,
                new_snapshot_at,
                change_count,
                kinds,
            },
            drifts,
        }
    }

    /// #8 — Render as a Slack incoming-webhook text message.
    ///
    /// Slack rejects the full `dbmaster.drift-event.v1` payload (expects
    /// `{"text": "..."}`); this method produces a concise human-readable
    /// summary suitable for a Slack notification. Drift details (the `drifts`
    /// vec) are deliberately omitted — Slack messages should be glanceable,
    /// and the v1 contract hard-excludes row data (定律 5) anyway. Operators
    /// who want details follow up in the desktop UI.
    pub fn to_slack_text(&self) -> String {
        format!(
            "*DBMaster drift detected* on `{conn}` ({db_type}/{db})\n\
             Task `{task}` • {n} change(s) detected",
            conn = self.connection.name,
            db_type = self.source.db_type,
            db = self.source.database,
            task = self.task.name,
            n = self.drift_summary.change_count,
        )
    }
}

/// #8 — Returns true if the URL targets Slack's incoming-webhook host.
/// Used by `deliver_with_backoff` to switch the POST body from the full
/// domain payload to Slack's `{"text": "..."}` envelope.
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
// CHANGE: manual Error impl (matches crates/automation/src/credential.rs
// style — keeps the workspace off the `thiserror` macro and consistent).
#[derive(Debug)]
pub enum NotifyError {
    /// URL is http:// but not localhost, or a non-http(s) scheme.
    InsecureUrl,
    /// URL failed to parse (missing scheme, malformed).
    MalformedUrl(String),
    /// reqwest client construction failed (TLS backend unavailable, etc.).
    ClientBuild(String),
    /// All retries exhausted.
    AllAttemptsFailed {
        attempts: u32,
        last_status: Option<u16>,
        last_error: String,
    },
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsecureUrl => write!(
                f,
                "webhook URL rejected: must be https, or http://localhost in dev mode"
            ),
            Self::MalformedUrl(s) => write!(f, "webhook URL is malformed: {s}"),
            Self::ClientBuild(s) => write!(f, "HTTP client build failed: {s}"),
            Self::AllAttemptsFailed {
                attempts,
                last_status,
                last_error,
            } => write!(
                f,
                "webhook delivery failed after {attempts} attempts; last_status={last_status:?}; last_error={last_error}"
            ),
        }
    }
}

impl std::error::Error for NotifyError {}

/// Validate a webhook URL against the ADR §4.4.2 transport rule.
///
/// `dev_mode=true` allows `http://localhost`, `http://127.0.0.1`, and
/// `http://[::1]` (loopback only). `https://` is accepted in either mode.
/// Everything else (http to a non-loopback host, file://, ftp://, etc.) is
/// rejected with [`NotifyError::InsecureUrl`] before any bytes hit the wire.
pub fn validate_webhook_url(url: &str, dev_mode: bool) -> Result<(), NotifyError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| NotifyError::MalformedUrl(url.to_string()))?;
    let scheme = scheme.trim();
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(());
    }
    if scheme.eq_ignore_ascii_case("http") && dev_mode {
        // `rest` = `host[:port]/path...`; extract host (before first `:` or `/`).
        // IPv6 literals are bracketed, e.g. `[::1]:port — handle the brackets
        // so the colons inside the address don't confuse the parser.
        let authority = rest.split('/').next().unwrap_or("");
        let host = extract_host(authority);
        if is_loopback_host(host) {
            return Ok(());
        }
        return Err(NotifyError::InsecureUrl);
    }
    Err(NotifyError::InsecureUrl)
}

/// Pull the bare host out of an authority string. Handles IPv6 brackets.
fn extract_host(authority: &str) -> &str {
    if let Some(stripped) = authority.strip_prefix('[') {
        // `[::1]:port` → return `::1`.
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

/// Deliver with default backoffs (1s/4s/16s). Used by the Phase E runner.
pub async fn deliver(
    payload: &WebhookPayload,
    url: &str,
    timeout: Duration,
    dev_mode: bool,
) -> Result<DeliveryReceipt, NotifyError> {
    deliver_with_backoff(payload, url, timeout, dev_mode, &DEFAULT_BACKOFFS).await
}

/// Deliver with explicit backoff schedule — exposed so tests can pass zero
/// waits. The schedule has `backoffs.len()` retries; total attempts =
/// `backoffs.len() + 1`.
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
            " drift-webhook"
        ))
        .build()
        .map_err(|e| NotifyError::ClientBuild(e.to_string()))?;

    // DEFENSIVE-NOTE: the URL was validated above, but reqwest still does its
    // own parse. Surface that as MalformedUrl (not a transport retry).
    let req_url = reqwest::Url::parse(url)
        .map_err(|e| NotifyError::MalformedUrl(e.to_string()))?;

    let total_attempts = (backoffs.len() + 1) as u32;
    let mut last_status: Option<u16> = None;
    let mut last_error = String::new();

    // #8 — Slack incoming-webhook detection. Slack URLs (hooks.slack.com)
    // reject the full domain payload; switch to `{"text": "..."}` envelope.
    // The text is a glanceable summary; full schema is for non-Slack webhooks.
    let slack_body = if is_slack_url(&req_url) {
        Some(serde_json::json!({ "text": payload.to_slack_text() }))
    } else {
        None
    };

    for attempt in 1..=total_attempts {
        // Sleep before retries (attempt 1 = first try, no sleep).
        if attempt > 1 {
            let idx = (attempt - 2) as usize;
            let wait = backoffs.get(idx).copied().unwrap_or(Duration::ZERO);
            tokio::time::sleep(wait).await;
        }

        let request_builder = client
            .post(req_url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        // Dispatch on Slack vs full payload. reqwest's `.json()` owns the
        // serialization; we can't call it twice on the same builder, so branch.
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
                    "webhook attempt failed; will retry"
                );
            }
            Err(e) => {
                last_status = None;
                last_error = e.to_string();
                tracing::warn!(attempt, error = %e, "webhook transport error; will retry");
            }
        }
    }

    Err(NotifyError::AllAttemptsFailed {
        attempts: total_attempts,
        last_status,
        last_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::DriftKind;
    use crate::snapshot::DbType;
    use tokio::io::AsyncWriteExt;

    /// Minimal sample payload — content doesn't matter for transport tests
    /// but exercises the serializer so we know it's well-formed JSON.
    fn sample_payload() -> WebhookPayload {
        let drift = Drift {
            kind: DriftKind::TableAdded,
            object: crate::diff::DriftObject {
                schema: Some("public".into()),
                table: Some("t".into()),
                column: None,
                index: None,
            },
            before: serde_json::Value::Null,
            after: serde_json::json!({"columns": 0}),
        };
        let mut p = WebhookPayload::new(
            "evt-1".into(),
            "2026-08-06T12:00:00Z".into(),
            "install-uuid".into(),
            vec![drift],
            None,
            "2026-08-06T12:00:05Z".into(),
        );
        p.task = TaskRef {
            id: "task-1".into(),
            name: "watch".into(),
        };
        p.connection = ConnectionRef {
            id: "conn-1".into(),
            name: "shop".into(),
        };
        p.source = SourceRef {
            db_type: DbType::Postgres.as_wire_str().into(),
            database: "shop".into(),
        };
        p
    }

    // ── URL validation (pure; no network) ──

    // ── #8 Slack formatting (pure; no network) ──

    #[test]
    fn slack_text_includes_connection_task_change_count() {
        let p = sample_payload();
        let text = p.to_slack_text();
        // Glanceable summary: connection, source db, task name, change count.
        assert!(text.contains("shop"), "missing connection/db name: {text}");
        assert!(text.contains("postgres"), "missing db_type: {text}");
        assert!(text.contains("watch"), "missing task name: {text}");
        // sample_payload has 1 drift → change_count = 1
        assert!(text.contains("1 change"), "missing/incorrect count: {text}");
        // Slack heading for clarity
        assert!(text.contains("drift detected"));
    }

    #[test]
    fn is_slack_url_detects_canonical_and_subdomain() {
        assert!(is_slack_url(&reqwest::Url::parse("https://hooks.slack.com/services/T/B/X").unwrap()));
        assert!(is_slack_url(&reqwest::Url::parse("https://teamname.hooks.slack.com/services/T/B/X").unwrap()));
        // Non-Slack webhook hosts must NOT trigger Slack envelope
        assert!(!is_slack_url(&reqwest::Url::parse("https://example.com/webhook").unwrap()));
        assert!(!is_slack_url(&reqwest::Url::parse("https://discord.com/api/webhooks/x").unwrap()));
        // Defensive: a URL that merely contains "slack" substring in path
        assert!(!is_slack_url(&reqwest::Url::parse("https://example.com/slack-hook").unwrap()));
    }

    #[test]
    fn https_url_accepted_in_prod() {
        assert!(validate_webhook_url("https://example.com/hook", false).is_ok());
    }

    #[test]
    fn http_non_localhost_rejected_in_prod() {
        assert!(matches!(
            validate_webhook_url("http://example.com/hook", false),
            Err(NotifyError::InsecureUrl)
        ));
    }

    #[test]
    fn http_non_localhost_rejected_in_dev_too() {
        // dev_mode only allows loopback.
        assert!(matches!(
            validate_webhook_url("http://example.com/hook", true),
            Err(NotifyError::InsecureUrl)
        ));
    }

    #[test]
    fn http_localhost_accepted_in_dev() {
        assert!(validate_webhook_url("http://localhost:9999/hook", true).is_ok());
        assert!(validate_webhook_url("http://127.0.0.1:9999/hook", true).is_ok());
        assert!(validate_webhook_url("http://[::1]:9999/hook", true).is_ok());
    }

    #[test]
    fn http_localhost_rejected_in_prod() {
        assert!(matches!(
            validate_webhook_url("http://localhost:9999/hook", false),
            Err(NotifyError::InsecureUrl)
        ));
    }

    #[test]
    fn non_http_scheme_rejected() {
        assert!(matches!(
            validate_webhook_url("file:///etc/passwd", false),
            Err(NotifyError::InsecureUrl)
        ));
        assert!(matches!(
            validate_webhook_url("ftp://x/y", false),
            Err(NotifyError::InsecureUrl)
        ));
    }

    #[test]
    fn malformed_url_no_scheme_rejected() {
        assert!(matches!(
            validate_webhook_url("just-a-host/path", false),
            Err(NotifyError::MalformedUrl(_))
        ));
    }

    // ── Payload schema (定律 2 contract) ──

    #[test]
    fn payload_serializes_with_locked_top_level_fields() {
        let p = sample_payload();
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        let obj = v.as_object().unwrap();
        // Hard-assert the field set; new fields appended in v2 must not break
        // these (定律 2 — only-add-not-delete).
        for key in [
            "schema",
            "event_id",
            "event_at",
            "instance_uuid",
            "task",
            "connection",
            "source",
            "drift_summary",
            "drifts",
        ] {
            assert!(obj.contains_key(key), "payload missing top-level field {key}");
        }
        assert_eq!(obj["schema"], "dbmaster.drift-event.v1");
    }

    #[test]
    fn payload_excludes_connection_secrets() {
        // Structurally — ConnectionRef has only id/name; SourceRef has only
        // db_type/database. No host/port/user/password can be carried. Grep
        // the serialized JSON to make this a sticky test.
        let p = sample_payload();
        let json = serde_json::to_string(&p).unwrap();
        for needle in ["host", "port", "username", "user", "password"] {
            // "user_id" appears in drift data sometimes — but our sample has none.
            assert!(
                !json.to_lowercase().contains(&format!("\"{needle}\"")),
                "payload leaked '{needle}' key"
            );
        }
    }

    #[test]
    fn drift_summary_change_count_matches_drifts_len() {
        let p = sample_payload();
        assert_eq!(p.drift_summary.change_count, p.drifts.len() as u32);
    }

    // ── Live delivery via in-process TCP responder ──

    /// Tiny in-process HTTP/1.1 responder that always answers with the
    /// canned status, reading one full request (line + headers + body).
    async fn spawn_responder(status_code: u16) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://127.0.0.1:{}/hook", addr.port());
        tokio::spawn(async move {
            // Accept multiple loops so retries all hit the same responder.
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    // Read request line + headers + body (best-effort; the
                    // test client sends small JSON).
                    let _ = sock.readable().await;
                    let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                    let body = format!(
                        "HTTP/1.1 {} OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        status_code
                    );
                    let _ = sock.write_all(body.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        url
    }

    /// A responder that reads the request then never writes a reply, forcing
    /// the client to time out on every attempt.
    async fn spawn_black_hole() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://127.0.0.1:{}/hook", addr.port());
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.readable().await;
                    let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                    // Intentionally never write — let the client time out.
                    tokio::time::sleep(TEST_TIMEOUT * 10).await;
                });
            }
        });
        url
    }

    /// Tiny in-process HTTP/1.1 responder that always answers with the
    /// canned status, reading one full request (line + headers + body).
    #[tokio::test]
    async fn deliver_succeeds_on_2xx() {
        let url = spawn_responder(200).await;
        let p = sample_payload();
        let receipt = deliver_with_backoff(&p, &url, TEST_TIMEOUT, true, &[Duration::ZERO]).await;
        assert!(receipt.is_ok(), "{:?}", receipt.err());
        let r = receipt.unwrap();
        assert_eq!(r.final_status, DeliveryStatus::Delivered);
        assert_eq!(r.attempts, 1);
        assert_eq!(r.last_status_code, Some(200));
    }

    #[tokio::test]
    async fn deliver_retries_on_5xx_then_fails() {
        let url = spawn_responder(500).await;
        let p = sample_payload();
        // 2 retries ⇒ 3 total attempts.
        let res =
            deliver_with_backoff(&p, &url, TEST_TIMEOUT, true, &[Duration::ZERO, Duration::ZERO])
                .await;
        assert!(matches!(res, Err(NotifyError::AllAttemptsFailed { attempts: 3, .. })));
    }

    #[tokio::test]
    async fn deliver_retries_on_4xx_then_fails() {
        let url = spawn_responder(404).await;
        let p = sample_payload();
        let res =
            deliver_with_backoff(&p, &url, TEST_TIMEOUT, true, &[Duration::ZERO]).await;
        assert!(matches!(res, Err(NotifyError::AllAttemptsFailed { attempts: 2, .. })));
    }

    #[tokio::test]
    async fn deliver_retries_on_timeout_then_fails() {
        let url = spawn_black_hole().await;
        let p = sample_payload();
        let res =
            deliver_with_backoff(&p, &url, TEST_TIMEOUT, true, &[Duration::ZERO]).await;
        match res {
            Err(NotifyError::AllAttemptsFailed { attempts, .. }) => assert_eq!(attempts, 2),
            other => panic!("expected AllAttemptsFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deliver_rejects_http_non_localhost_in_prod_without_network() {
        let p = sample_payload();
        // Should fail at validation — never opens a socket.
        let res = deliver_with_backoff(&p, "http://example.com/x", TEST_TIMEOUT, false, &[]).await;
        assert!(matches!(res, Err(NotifyError::InsecureUrl)));
    }

    #[tokio::test]
    async fn deliver_accepts_https_url_even_when_unreachable() {
        // https URL passes validation; the deliver fails at network layer.
        // (We don't actually open this — use an unreachable port on localhost
        // via https with a non-RFC host so DNS fails fast.)
        let p = sample_payload();
        // Use https with a non-loopback host that will fail to connect.
        let res = deliver_with_backoff(
            &p,
            "https://localhost:1/hook",
            Duration::from_millis(100),
            false,
            &[],
        )
        .await;
        // Validation passes; we expect AllAttemptsFailed (connection refused).
        assert!(matches!(res, Err(NotifyError::AllAttemptsFailed { .. })));
    }
}
