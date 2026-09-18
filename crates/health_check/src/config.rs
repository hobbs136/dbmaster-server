//! Strongly-typed config model for `health_check` tasks.
//!
//! Stored as JSON in `scheduled_tasks.config`. Shaped by ADR-0004 §3.1:
//! metric on/off flags + alerting thresholds + retention. The wire format is
//! consumed by the M4 runner when it parses a task row.
//!
//! Trust boundary: unlike `data_sync`, none of these fields are identifiers
//! that reach SQL string assembly — they are numeric thresholds and booleans.
//! `validate()` clamps them to safe ranges rather than rejecting outright
//! (a misconfigured threshold should be corrected, not abort the task).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A `health_check` task's full configuration (the JSON stored in
/// `scheduled_tasks.config`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckTaskConfig {
    /// Per-metric on/off flags. `connectivity` is always treated as enabled
    /// regardless of this flag (it is the core probe).
    #[serde(default = "default_metrics")]
    pub metrics: MetricFlags,
    /// Consecutive failure / over-threshold count required to flip from
    /// `Failing` to `Alerting` (flap suppression). Default 3.
    #[serde(default = "default_fail_threshold")]
    pub fail_threshold: u32,
    /// Tables with an estimated row count above this trigger a `row_count`
    /// alert (large-table flag). Default 10_000_000.
    #[serde(default = "default_large_table_threshold")]
    pub large_table_threshold: u64,
    /// Connection count above which `connection_count` alerts. Default 100.
    #[serde(default = "default_connection_count_threshold")]
    pub connection_count_threshold: u64,
    /// Days to retain `health_check_results` rows before the runner rotates
    /// (DELETE) them. Default 30.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

/// Per-metric enable flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricFlags {
    /// Connectivity + latency probe (`SELECT 1` timed). Always treated as on.
    #[serde(default = "default_true")]
    pub connectivity: bool,
    /// Table-row estimate (TOP N largest tables).
    #[serde(default = "default_true")]
    pub row_count: bool,
    /// Missing-primary-key detection (incremental alerting).
    #[serde(default = "default_true")]
    pub missing_pk: bool,
    /// Connection count (threads connected / pg_stat_activity).
    #[serde(default = "default_true")]
    pub connection_count: bool,
}

/// Validation error for a `health_check` task config.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{field} must be between {min} and {max} (got {value})")]
    OutOfRange {
        field: &'static str,
        min: u32,
        max: u32,
        value: u32,
    },
}

impl Default for HealthCheckTaskConfig {
    fn default() -> Self {
        Self {
            metrics: default_metrics(),
            fail_threshold: default_fail_threshold(),
            large_table_threshold: default_large_table_threshold(),
            connection_count_threshold: default_connection_count_threshold(),
            retention_days: default_retention_days(),
        }
    }
}

impl Default for MetricFlags {
    fn default() -> Self {
        default_metrics()
    }
}

impl HealthCheckTaskConfig {
    /// Clamp thresholds into safe ranges. Returns `Err` only for values that
    /// cannot be sensibly clamped (none currently — all clamps are silent).
    /// Kept as `Result` to mirror `data_sync::config::validate` and to leave
    /// room for future hard-reject fields.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // fail_threshold: 1..=10 (1 = no flap suppression; 10 = very tolerant).
        if !(1..=10).contains(&self.fail_threshold) {
            return Err(ConfigError::OutOfRange {
                field: "fail_threshold",
                min: 1,
                max: 10,
                value: self.fail_threshold,
            });
        }
        // retention_days: 1..=365 (1 day .. 1 year).
        if !(1..=365).contains(&self.retention_days) {
            return Err(ConfigError::OutOfRange {
                field: "retention_days",
                min: 1,
                max: 365,
                value: self.retention_days,
            });
        }
        Ok(())
    }

    /// Deserialize from a JSON string, falling back to [`Default`] on parse
    /// failure (a corrupt config row should not abort the whole task list).
    /// The M4 runner uses this when reading `scheduled_tasks.config`.
    pub fn from_json_or_default(raw: &str) -> Self {
        serde_json::from_str::<Self>(raw).unwrap_or_default()
    }
}

// ── Default value functions (serde `default = "..."` requires free fns) ──

fn default_metrics() -> MetricFlags {
    MetricFlags {
        connectivity: true,
        row_count: true,
        missing_pk: true,
        connection_count: true,
    }
}

fn default_true() -> bool {
    true
}

fn default_fail_threshold() -> u32 {
    3
}

fn default_large_table_threshold() -> u64 {
    10_000_000
}

fn default_connection_count_threshold() -> u64 {
    100
}

fn default_retention_days() -> u32 {
    30
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;

    #[test]
    fn defaults_are_all_enabled() {
        let c = HealthCheckTaskConfig::default();
        assert!(c.metrics.connectivity && c.metrics.row_count);
        assert!(c.metrics.missing_pk && c.metrics.connection_count);
        assert_eq!(c.fail_threshold, 3);
        assert_eq!(c.large_table_threshold, 10_000_000);
        assert_eq!(c.connection_count_threshold, 100);
        assert_eq!(c.retention_days, 30);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn json_roundtrip_preserves_fields() {
        let c = HealthCheckTaskConfig {
            metrics: MetricFlags {
                connectivity: true,
                row_count: false,
                missing_pk: true,
                connection_count: false,
            },
            fail_threshold: 5,
            large_table_threshold: 500_000,
            connection_count_threshold: 42,
            retention_days: 7,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: HealthCheckTaskConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.fail_threshold, 5);
        assert!(!back.metrics.row_count);
        assert_eq!(back.connection_count_threshold, 42);
        assert_eq!(back.retention_days, 7);
    }

    #[test]
    fn missing_fields_use_serde_defaults() {
        // Empty JSON object → all defaults via #[serde(default = ...)].
        let c: HealthCheckTaskConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(c.fail_threshold, 3);
        assert!(c.metrics.connectivity);
        assert_eq!(c.retention_days, 30);
    }

    #[test]
    fn from_json_or_default_recovers_from_garbage() {
        let c = HealthCheckTaskConfig::from_json_or_default("not json");
        assert_eq!(c.fail_threshold, 3); // fell back to default
    }

    #[test]
    fn validate_rejects_fail_threshold_out_of_range() {
        let mut c = HealthCheckTaskConfig::default();
        c.fail_threshold = 0;
        assert!(c.validate().is_err());
        c.fail_threshold = 11;
        assert!(c.validate().is_err());
        c.fail_threshold = 1;
        assert!(c.validate().is_ok());
        c.fail_threshold = 10;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_retention_out_of_range() {
        let mut c = HealthCheckTaskConfig::default();
        c.retention_days = 0;
        assert!(c.validate().is_err());
        c.retention_days = 366;
        assert!(c.validate().is_err());
        c.retention_days = 365;
        assert!(c.validate().is_ok());
    }
}
