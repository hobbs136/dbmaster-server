//! 14-day trial state machine (ADR-0001 D5=A).
//!
//! On first launch with no license and no trial row, a 14-day window is
//! written to `instance_meta`. The window is read-only thereafter; deletion of
//! the row resets trial (honest-user mode, accepted per ADR §4.5).

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;

/// Trial window length in days (ADR §4.5).
pub const TRIAL_DAYS: i64 = 14;

/// Result of evaluating trial state for the current instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrialStatus {
    /// Trial window is open until this instant.
    Active { expires_at: DateTime<Utc> },
    /// Trial window has elapsed.
    Expired,
    /// No trial row yet and we chose not to start one (e.g. license active).
    NotStarted,
}

/// Ensure the trial window is materialised on `instance_meta` and report status.
///
/// - If `trial_started_at` / `trial_expires_at` are both NULL → write
///   `now` / `now + TRIAL_DAYS` and return [`TrialStatus::Active`].
/// - If both are set → read them and classify as Active / Expired.
/// - Partial set (one NULL, other not) is treated as corrupt and re-initialised
///   with a WARN log (defensive: surface but repair rather than crash).
pub async fn ensure_trial_status(pool: &SqlitePool) -> Result<TrialStatus> {
    let row = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT trial_started_at, trial_expires_at FROM instance_meta LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("read trial window")?;

    let Some((started_raw, expires_raw)) = row else {
        // No instance row — caller should have created one. Treat as not started.
        return Ok(TrialStatus::NotStarted);
    };

    match (started_raw.as_deref(), expires_raw.as_deref()) {
        (Some(s), Some(e)) => {
            let expires = parse_iso8601(e).context("parse trial_expires_at")?;
            let _started = parse_iso8601(s).context("parse trial_started_at")?;
            if Utc::now() < expires {
                Ok(TrialStatus::Active { expires_at: expires })
            } else {
                Ok(TrialStatus::Expired)
            }
        }
        (None, None) => start_trial(pool).await,
        // Corrupt partial row — repair.
        _ => {
            tracing::warn!(
                "instance_meta has partially-set trial columns; re-initialising trial window"
            );
            start_trial(pool).await
        }
    }
}

async fn start_trial(pool: &SqlitePool) -> Result<TrialStatus> {
    let now = Utc::now();
    let expires = now + Duration::days(TRIAL_DAYS);
    let now_s = now.to_rfc3339();
    let expires_s = expires.to_rfc3339();

    let affected = sqlx::query(
        "UPDATE instance_meta SET trial_started_at = ?1, trial_expires_at = ?2",
    )
    .bind(&now_s)
    .bind(&expires_s)
    .execute(pool)
    .await
    .context("start trial window")?
    .rows_affected();

    if affected == 0 {
        // No instance row yet — caller bug; surface as error rather than silent.
        anyhow::bail!("no instance_meta row; call get_or_create_instance first");
    }
    tracing::info!(trial_expires_at = %expires_s, "trial window started");
    Ok(TrialStatus::Active { expires_at: expires })
}

fn parse_iso8601(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)
        .context("parse ISO-8601")?
        .with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_pool_with_instance() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE instance_meta (
                install_uuid TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                trial_started_at TEXT,
                trial_expires_at TEXT
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO instance_meta (install_uuid, created_at) VALUES ('test', '2026-01-01T00:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    #[tokio::test]
    async fn first_call_starts_trial() {
        let pool = setup_pool_with_instance().await;
        let status = ensure_trial_status(&pool).await.unwrap();
        match status {
            TrialStatus::Active { expires_at } => {
                let delta = expires_at - Utc::now();
                // 14 days ± 2 minutes (test latency tolerance).
                assert!(delta.num_minutes() > 14 * 24 * 60 - 2);
                assert!(delta.num_minutes() < 14 * 24 * 60 + 2);
            }
            other => panic!("expected Active, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn second_call_keeps_existing_window() {
        let pool = setup_pool_with_instance().await;
        let first = ensure_trial_status(&pool).await.unwrap();
        let second = ensure_trial_status(&pool).await.unwrap();
        match (first, second) {
            (TrialStatus::Active { expires_at: a }, TrialStatus::Active { expires_at: b }) => {
                assert_eq!(a, b, "re-calling must not slide the window");
            }
            _ => panic!("both calls must return Active"),
        }
    }

    #[tokio::test]
    async fn past_expires_at_returns_expired() {
        let pool = setup_pool_with_instance().await;
        let past = (Utc::now() - Duration::days(1)).to_rfc3339();
        let started = (Utc::now() - Duration::days(15)).to_rfc3339();
        sqlx::query(
            "UPDATE instance_meta SET trial_started_at = ?1, trial_expires_at = ?2",
        )
        .bind(started)
        .bind(past)
        .execute(&pool)
        .await
        .unwrap();

        let status = ensure_trial_status(&pool).await.unwrap();
        assert_eq!(status, TrialStatus::Expired);
    }

    #[tokio::test]
    async fn deleted_row_resets_trial() {
        // Simulate honest-user "delete row → new install" by wiping and re-creating.
        let pool = setup_pool_with_instance().await;
        let _ = ensure_trial_status(&pool).await.unwrap();
        sqlx::query("DELETE FROM instance_meta").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO instance_meta (install_uuid, created_at) VALUES ('new', '2026-01-02T00:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        let status = ensure_trial_status(&pool).await.unwrap();
        assert!(matches!(status, TrialStatus::Active { .. }));
    }

    #[tokio::test]
    async fn corrupt_partial_row_repaired() {
        let pool = setup_pool_with_instance().await;
        // Partial: only started_at set.
        sqlx::query("UPDATE instance_meta SET trial_started_at = '2026-01-01T00:00:00Z'")
            .execute(&pool)
            .await
            .unwrap();
        let status = ensure_trial_status(&pool).await.unwrap();
        assert!(matches!(status, TrialStatus::Active { .. }));
    }
}
