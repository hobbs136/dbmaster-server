//! Instance identity — install_uuid generation and persistence (ADR-0001 D4=A).
//!
//! On first launch, a 32-byte random `install_uuid` is generated and stored in
//! the `instance_meta` table. Deletion of the row resets identity (honest-user
//! mode, accepted per ADR §4.4 / §6).

use anyhow::{Context, Result};
use rand::RngCore;
use sqlx::SqlitePool;

/// Row in `instance_meta`. `trial_*` columns are owned by [`crate::trial`].
#[derive(Debug, Clone)]
pub struct InstanceMeta {
    pub install_uuid: String,
    pub created_at: String,
    pub trial_started_at: Option<String>,
    pub trial_expires_at: Option<String>,
}

/// Generate a fresh 32-byte install_uuid as lower-case hex (64 chars).
pub fn generate_install_uuid() -> String {
    // CHANGE: ADR-0001 §4.4 D4=A — 32 random bytes, hex-encoded.
    let mut buf = [0u8; 32];
    // OsRng is the cryptographic CSPRNG; rely on getrandom backing.
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Convenience accessor returning just the install_uuid.
///
/// DEFENSIVE-NOTE: this is a thin wrapper over [`get_or_create_instance`] — it
/// will create the row on first call (idempotent). Callers that need a strict
/// read-only lookup should ensure the row was created earlier (boot does this
/// via [`crate::entitlement::resolve_entitlement`] before any handler runs).
// CHANGE: v1 schema-drift webhook payload needs the install_uuid wired through
// AppState; this exposes a single-field accessor so callers don't pull the
// full InstanceMeta.
pub async fn get_install_uuid(pool: &SqlitePool) -> Result<String> {
    Ok(get_or_create_instance(pool).await?.install_uuid)
}

/// Return the instance row, creating it on first launch.
///
/// Concurrency: SQLite serialises writers; the INSERT OR IGNORE is idempotent
/// so racing spawns converge on the first-inserted uuid.
pub async fn get_or_create_instance(pool: &SqlitePool) -> Result<InstanceMeta> {
    // Fast path: row exists.
    if let Some(existing) = sqlx::query_as::<_, InstanceMeta>(
        "SELECT install_uuid, created_at, trial_started_at, trial_expires_at
         FROM instance_meta LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    {
        return Ok(existing);
    }

    let install_uuid = generate_install_uuid();
    let created_at = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO instance_meta (install_uuid, created_at) VALUES (?1, ?2)",
    )
    .bind(&install_uuid)
    .bind(&created_at)
    .execute(pool)
    .await
    .context("insert instance_meta")?;

    // Re-read in case a concurrent writer inserted first — converge on stored row.
    // DEFENSIVE-NOTE: avoid `.context()` chained on `Option` — anyhow::Context has
    // an Option impl that unwraps to T and would hide the None branch. Use map_err
    // on the outer Result, then ok_or_else on the inner Option explicitly.
    let row: Option<InstanceMeta> = sqlx::query_as::<_, InstanceMeta>(
        "SELECT install_uuid, created_at, trial_started_at, trial_expires_at
         FROM instance_meta LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| anyhow::anyhow!("read instance_meta after insert: {e}"))?;

    row.ok_or_else(|| anyhow::anyhow!("instance_meta row missing after insert"))
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for InstanceMeta {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> sqlx::Result<Self> {
        use sqlx::Row;
        Ok(Self {
            install_uuid: row.try_get("install_uuid")?,
            created_at: row.try_get("created_at")?,
            trial_started_at: row.try_get("trial_started_at")?,
            trial_expires_at: row.try_get("trial_expires_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_pool() -> std::pin::Pin<Box<dyn std::future::Future<Output = SqlitePool> + Send>> {
        Box::pin(async {
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
            pool
        })
    }

    #[tokio::test]
    async fn first_call_creates_row() {
        let pool = random_pool().await;
        let meta = get_or_create_instance(&pool).await.unwrap();
        assert_eq!(meta.install_uuid.len(), 64);
        assert!(meta.trial_started_at.is_none());
        assert!(meta.trial_expires_at.is_none());
    }

    #[tokio::test]
    async fn second_call_returns_same_uuid() {
        let pool = random_pool().await;
        let first = get_or_create_instance(&pool).await.unwrap();
        let second = get_or_create_instance(&pool).await.unwrap();
        assert_eq!(first.install_uuid, second.install_uuid);
    }

    #[tokio::test]
    async fn concurrent_calls_converge() {
        // Spawn two concurrent get_or_create calls; both must return identical uuid.
        let pool = std::sync::Arc::new(random_pool().await);
        let p1 = pool.clone();
        let p2 = pool.clone();
        let (a, b) = tokio::join!(
            tokio::spawn(async move { get_or_create_instance(&p1).await.unwrap() }),
            tokio::spawn(async move { get_or_create_instance(&p2).await.unwrap() }),
        );
        assert_eq!(a.unwrap().install_uuid, b.unwrap().install_uuid);
    }

    #[test]
    fn generated_uuid_is_hex_64() {
        let id = generate_install_uuid();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
