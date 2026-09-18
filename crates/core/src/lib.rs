// dbmaster-core — Authentication, workspace management, REST API, telemetry (Apache 2.0)
pub mod config;
pub mod db;
pub mod error;
pub mod auth;
pub mod user;
pub mod workspace;
pub mod server;
// CHANGE: telemetry-funnel-plan.md §6 — telemetry hardening landed (whitelist,
// idempotency, IP redaction, rate limit). The pre-existing unused-imports allow
// is no longer needed and has been removed.
pub mod telemetry;
