//! Connection credential encryption — AES-256-GCM (ADR-0001 §4.8 D8).
//!
//! Two storage formats coexist during the migration window:
//! - `v1:<nonce_b64>:<ct+tag_b64>` — current, AES-256-GCM.
//! - `enc:<plaintext>` — legacy plaintext (pre-ADR); retained read-only with WARN.
//!
//! The legacy `enc:` format is only accepted by [`decrypt_password`]; all writes
//! go through [`encrypt_v1`]. A one-shot migration
//! ([`migrate_legacy_credentials`]) re-encrypts remaining `enc:` rows.
//!
//! Master key: 32 bytes supplied by the caller; per ADR §4.8 D8.1 the key is
//! loaded from `DBMASTER_CREDENTIAL_KEY` env var by the bootstrap code, never
//! stored in the DB or logged.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use sqlx::SqlitePool;

/// Stored ciphertext prefix. Versioned to allow future format changes without
/// re-deriving a parser from ambiguity (the lesson of `enc:`).
pub const V1_PREFIX: &str = "v1:";
/// Legacy plaintext prefix (pre-ADR). Read-only; never produced by this module.
pub const LEGACY_ENC_PREFIX: &str = "enc:";

/// AES-GCM nonce length in bytes (96 bits, the GCM standard).
const NONCE_LEN: usize = 12;
/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;

/// Failures surfaced by credential decode/decrypt.
#[derive(Debug)]
pub enum CredentialError {
    /// Stored value uses neither `v1:` nor `enc:` prefix.
    UnknownFormat,
    /// `v1:` value is malformed (missing nonce/ciphertext segments, bad base64).
    Malformed,
    /// Decryption failed (wrong key, corrupted ciphertext, or tampered GCM tag).
    DecryptFailed,
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFormat => write!(f, "unknown credential format"),
            Self::Malformed => write!(f, "malformed v1 credential"),
            Self::DecryptFailed => write!(f, "credential decryption failed"),
        }
    }
}

impl std::error::Error for CredentialError {}

/// Encrypt `plaintext` with a 32-byte key using AES-256-GCM.
///
/// Output format: `v1:<nonce_b64>:<ct+tag_b64>`. A fresh 12-byte random nonce
/// is drawn per call; nonce reuse under the same key would catastrophically
/// break GCM confidentiality, so [`rand::rngs::OsRng`] is used unconditionally.
// CHANGE: ADR-0001 §4.8 D8.2 — v1 AES-256-GCM format.
pub fn encrypt_v1(plaintext: &str, key: &[u8; KEY_LEN]) -> Result<String> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    // OsRng backed by getrandom; never reuse a nonce by drawing fresh each call.
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext.as_bytes(), aad: b"dbmaster-credential-v1" })
        .map_err(|e| anyhow!("aes-gcm encrypt: {e}"))?;

    Ok(format!(
        "{prefix}{nonce}:{ct}",
        prefix = V1_PREFIX,
        nonce = B64.encode(nonce_bytes),
        ct = B64.encode(&ct),
    ))
}

/// Decrypt a `v1:<nonce_b64>:<ct+tag_b64>` value. Does NOT accept legacy `enc:`.
pub fn decrypt_v1(stored: &str, key: &[u8; KEY_LEN]) -> Result<String, CredentialError> {
    let rest = stored.strip_prefix(V1_PREFIX).ok_or(CredentialError::UnknownFormat)?;
    let (nonce_b64, ct_b64) = rest.split_once(':').ok_or(CredentialError::Malformed)?;
    let nonce_bytes = B64
        .decode(nonce_b64)
        .map_err(|_| CredentialError::Malformed)?;
    let ct = B64.decode(ct_b64).map_err(|_| CredentialError::Malformed)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CredentialError::Malformed);
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(nonce, Payload { msg: &ct, aad: b"dbmaster-credential-v1" })
        .map_err(|_| CredentialError::DecryptFailed)?;
    String::from_utf8(pt).map_err(|_| CredentialError::DecryptFailed)
}

/// Decrypt a stored credential, accepting both `v1:` and legacy `enc:` formats.
///
/// Legacy `enc:` rows are returned as-is with a WARN log; the operator is
/// expected to run [`migrate_legacy_credentials`] to clear them.
// CHANGE: ADR-0001 §4.8 D8.3 — backwards-compatible decode.
pub fn decrypt_password(stored: &str, key: &[u8; KEY_LEN]) -> Result<String, CredentialError> {
    if let Some(plain) = stored.strip_prefix(LEGACY_ENC_PREFIX) {
        tracing::warn!(
            "legacy plaintext credential (enc: prefix) decrypt-skipped; run migration to v1"
        );
        return Ok(plain.to_string());
    }
    decrypt_v1(stored, key)
}

/// Re-encrypt every `enc:` row in `database_connections.password_encrypted`
/// to the `v1:` format. Idempotent: rows already in `v1:` (or any non-`enc:`
/// form) are left untouched. Returns the count of rows migrated.
///
/// DEFENSIVE-NOTE: never logs plaintext or ciphertext; only row counts.
/// On per-row failure, aborts the whole migration (surfaces error) so a
/// partial migration leaves the remaining rows readable in their original form.
// CHANGE: ADR-0001 §4.8 D8.3 — one-shot migration.
pub async fn migrate_legacy_credentials(
    pool: &SqlitePool,
    key: &[u8; KEY_LEN],
) -> Result<usize> {
    use sqlx::Row;

    let rows = sqlx::query("SELECT id, password_encrypted FROM database_connections")
        .fetch_all(pool)
        .await
        .context("scan database_connections for migration")?;

    let mut migrated = 0usize;
    for row in rows {
        let id: String = row.try_get("id").context("read id")?;
        let stored: String = row.try_get("password_encrypted").context("read password_encrypted")?;

        if !stored.starts_with(LEGACY_ENC_PREFIX) {
            continue;
        }

        let plaintext = stored
            .strip_prefix(LEGACY_ENC_PREFIX)
            .ok_or_else(|| anyhow!("strip enc: prefix"))?;
        let new_ct = encrypt_v1(plaintext, key)?;
        sqlx::query("UPDATE database_connections SET password_encrypted = ?1 WHERE id = ?2")
            .bind(&new_ct)
            .bind(&id)
            .execute(pool)
            .await
            .with_context(|| format!("update row {}", redact_id(&id)))?;
        migrated += 1;
    }
    if migrated > 0 {
        tracing::info!("credential migration: re-encrypted {} rows to v1", migrated);
    }
    Ok(migrated)
}

/// Render an id safe for logging: keep first 4 chars (UUID prefix), mask the rest.
fn redact_id(id: &str) -> String {
    let len = id.chars().count();
    if len <= 4 {
        return "***".into();
    }
    let head: String = id.chars().take(4).collect();
    format!("{head}***({len})")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        k
    }

    #[test]
    fn encrypt_v1_format_is_correct() {
        let key = fixed_key();
        let ct = encrypt_v1("hunter2", &key).unwrap();
        assert!(ct.starts_with("v1:"));
        let rest = &ct[V1_PREFIX.len()..];
        let (nonce_b64, ct_b64) = rest.split_once(':').unwrap();
        assert_eq!(B64.decode(nonce_b64).unwrap().len(), NONCE_LEN);
        assert!(!ct_b64.is_empty());
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let key = fixed_key();
        for msg in ["", "x", "password123", "ユニコード密码🔐", std::str::from_utf8(&[b'a'; 256]).unwrap()] {
            let ct = encrypt_v1(msg, &key).unwrap();
            let pt = decrypt_v1(&ct, &key).unwrap();
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn two_encryptions_produce_different_ciphertexts() {
        // Fresh nonce per call ⇒ distinct ciphertexts for same plaintext.
        let key = fixed_key();
        let a = encrypt_v1("same", &key).unwrap();
        let b = encrypt_v1("same", &key).unwrap();
        assert_ne!(a, b);
        assert_eq!(decrypt_v1(&a, &key).unwrap(), "same");
        assert_eq!(decrypt_v1(&b, &key).unwrap(), "same");
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = fixed_key();
        let mut wrong = key;
        wrong[0] ^= 0xFF;
        let ct = encrypt_v1("secret", &key).unwrap();
        assert!(matches!(
            decrypt_v1(&ct, &wrong),
            Err(CredentialError::DecryptFailed)
        ));
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = fixed_key();
        let ct = encrypt_v1("secret", &key).unwrap();
        let rest = &ct[V1_PREFIX.len()..];
        let (nonce_b64, ct_b64) = rest.split_once(':').unwrap();
        // Flip one bit in the ciphertext base64.
        let mut tampered_ct: Vec<u8> = ct_b64.bytes().collect();
        tampered_ct[0] = if tampered_ct[0] == b'A' { b'B' } else { b'A' };
        let tampered_b64 = String::from_utf8(tampered_ct).unwrap();
        let tampered = format!("{prefix}{nonce}:{ct}", prefix = V1_PREFIX, nonce = nonce_b64, ct = tampered_b64);
        assert!(matches!(
            decrypt_v1(&tampered, &key),
            Err(CredentialError::DecryptFailed) | Err(CredentialError::Malformed)
        ));
    }

    #[test]
    fn decrypt_v1_rejects_unknown_format() {
        let key = fixed_key();
        assert!(matches!(
            decrypt_v1("not-a-v1-string", &key),
            Err(CredentialError::UnknownFormat)
        ));
        assert!(matches!(
            decrypt_v1("enc:legacy-plain", &key),
            Err(CredentialError::UnknownFormat)
        ));
    }

    #[test]
    fn decrypt_v1_rejects_malformed_v1() {
        let key = fixed_key();
        // Missing ct segment.
        assert!(matches!(
            decrypt_v1("v1:AAAA", &key),
            Err(CredentialError::Malformed)
        ));
        // Nonce wrong length.
        assert!(matches!(
            decrypt_v1("v1:AA:BB", &key),
            Err(CredentialError::Malformed)
        ));
    }

    #[test]
    fn decrypt_password_accepts_legacy_enc() {
        let key = fixed_key();
        let pt = decrypt_password("enc:legacy-plaintext", &key).unwrap();
        assert_eq!(pt, "legacy-plaintext");
    }

    #[test]
    fn decrypt_password_accepts_v1() {
        let key = fixed_key();
        let ct = encrypt_v1("via-v1", &key).unwrap();
        let pt = decrypt_password(&ct, &key).unwrap();
        assert_eq!(pt, "via-v1");
    }

    #[test]
    fn decrypt_password_rejects_truly_unknown() {
        let key = fixed_key();
        assert!(decrypt_password("???unknown", &key).is_err());
    }

    // ── Migration ──

    async fn setup_pool_with_rows() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE database_connections (
                id TEXT PRIMARY KEY,
                password_encrypted TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO database_connections (id, password_encrypted) VALUES ('a', 'enc:plain-a')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO database_connections (id, password_encrypted) VALUES ('b', 'enc:plain-b')")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    #[tokio::test]
    async fn migrate_converts_all_legacy_rows() {
        let pool = setup_pool_with_rows().await;
        let key = fixed_key();
        let n = migrate_legacy_credentials(&pool, &key).await.unwrap();
        assert_eq!(n, 2);

        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, password_encrypted FROM database_connections ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        for (_, stored) in &rows {
            assert!(stored.starts_with("v1:"), "all rows must be v1 after migration");
        }
        assert_eq!(decrypt_password(&rows[0].1, &key).unwrap(), "plain-a");
        assert_eq!(decrypt_password(&rows[1].1, &key).unwrap(), "plain-b");
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let pool = setup_pool_with_rows().await;
        let key = fixed_key();
        let _ = migrate_legacy_credentials(&pool, &key).await.unwrap();
        let n = migrate_legacy_credentials(&pool, &key).await.unwrap();
        assert_eq!(n, 0, "second run should be a no-op");
    }

    #[tokio::test]
    async fn migrate_skips_v1_rows() {
        let pool = setup_pool_with_rows().await;
        let key = fixed_key();
        // Pre-encrypt row 'b' as v1 before migration.
        let already_v1 = encrypt_v1("already-v1", &key).unwrap();
        sqlx::query("UPDATE database_connections SET password_encrypted = ?1 WHERE id = 'b'")
            .bind(already_v1)
            .execute(&pool)
            .await
            .unwrap();

        let n = migrate_legacy_credentials(&pool, &key).await.unwrap();
        assert_eq!(n, 1, "only the enc: row should be migrated");

        let stored_b: String =
            sqlx::query_scalar("SELECT password_encrypted FROM database_connections WHERE id='b'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(decrypt_password(&stored_b, &key).unwrap(), "already-v1");
    }
}
