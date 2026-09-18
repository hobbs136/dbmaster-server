//! Entitlement state resolution and types (ADR-0001 §5 / §7.1).
//!
//! On startup, [`resolve_entitlement`] reads the local license file (if any),
//! parses + verifies it, compares `instance_id` against the local install_uuid,
//! checks `expires_at` freshness, and returns one of [`EntitlementState`].
//! With no license file present it falls back to the 14-day trial window,
//! materialising it on first launch.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use sqlx::SqlitePool;

use crate::{
    get_or_create_instance, ensure_trial_status, parse_license, trusted_verifying_key,
    verify_license_with_pk, LicenseV2, ParseError, TrialStatus, VerifyError,
};

/// Where the `.dbmlicense` file path comes from.
const LICENSE_FILE_ENV: &str = "DBMASTER_LICENSE_FILE";
const LICENSE_FILE_DEFAULT: &str = ".dbmlicense";

/// Renewal-banner thresholds (days). 30 = first reminder; 7 = urgent.
pub const RENEWAL_THRESHOLD_DAYS: i64 = 30;
pub const RENEWAL_URGENT_DAYS: i64 = 7;

/// Authoritative entitlement derived at startup.
#[derive(Debug, Clone)]
pub enum EntitlementState {
    /// A valid license file is loaded and matches this instance.
    Licensed {
        license: LicenseV2,
        /// Mirrors `license.expires_at` parsed; `None` for lifetime.
        expires_at: Option<DateTime<Utc>>,
    },
    /// No license; 14-day trial window is open.
    Trial { expires_at: DateTime<Utc> },
    /// No license and trial elapsed (or license fails any check). Paid
    /// features must gate; UI should prompt activation.
    Gated {
        reason: GatedReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatedReason {
    /// Trial window has expired.
    TrialExpired,
    /// License file present but signature/version/product invalid.
    LicenseInvalid,
    /// License `instance_id` does not match local install_uuid.
    InstanceMismatch,
    /// License `expires_at` is in the past.
    LicenseExpired,
}

impl EntitlementState {
    /// Whether paid features should be gated (i.e. not operable).
    pub fn is_gated(&self) -> bool {
        matches!(self, Self::Gated { .. })
    }

    /// Days until the active entitlement lapses; None for lifetime or gated.
    ///
    /// Returns negative values for already-lapsed (caller should treat ≤0 as
    /// expired). Returned for both Licensed (yearly) and Trial so the UI can
    /// drive distinct messages; lifetime licenses return None.
    pub fn days_until_expiry(&self) -> Option<i64> {
        match self {
            Self::Licensed { expires_at: Some(exp), .. } => Some((*exp - Utc::now()).num_days()),
            Self::Licensed { expires_at: None, .. } => None, // lifetime
            Self::Trial { expires_at } => Some((*expires_at - Utc::now()).num_days()),
            Self::Gated { .. } => None,
        }
    }

    /// Whether the LICENSE renewal banner should be shown, and at which tier.
    ///
    /// Per ADR §4.7 D7=C this banner is specific to yearly licenses nearing
    /// expiry. Trial and lifetime return None — the UI uses
    /// [`days_until_expiry`] directly to render a separate trial-ending prompt.
    pub fn renewal_banner(&self) -> Option<RenewalTier> {
        let days = match self {
            Self::Licensed { expires_at: Some(_), .. } => self.days_until_expiry()?,
            _ => return None,
        };
        if days <= RENEWAL_URGENT_DAYS {
            Some(RenewalTier::Urgent)
        } else if days <= RENEWAL_THRESHOLD_DAYS {
            Some(RenewalTier::Soon)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalTier {
    /// ≤ 30 days remaining.
    Soon,
    /// ≤ 7 days remaining.
    Urgent,
}

/// Compute the authoritative entitlement on startup.
///
/// Reads the license file from `DBMASTER_LICENSE_FILE` (or `.dbmlicense` by
/// default). Falls back to the 14-day trial window when no license is present.
pub async fn resolve_entitlement(pool: &SqlitePool) -> Result<EntitlementState> {
    let license_text = read_license_file();
    resolve_entitlement_with_text(pool, license_text).await
}

/// Same as [`resolve_entitlement`] but with the license text supplied by the
/// caller. Exposed for tests that need deterministic behavior without env-var
/// manipulation (which would race under parallel test execution).
// CHANGE: ADR-0001 §7.1 — injectable license text for testability.
pub async fn resolve_entitlement_with_text(
    pool: &SqlitePool,
    license_text: Option<String>,
) -> Result<EntitlementState> {
    let instance = get_or_create_instance(pool)
        .await
        .context("ensure instance_meta")?;

    if let Some(text) = license_text {
        return resolve_from_license_text(&text, &instance.install_uuid).await;
    }

    // No license file → trial path.
    let status = ensure_trial_status(pool).await.context("ensure trial status")?;
    Ok(match status {
        TrialStatus::Active { expires_at } => EntitlementState::Trial { expires_at },
        TrialStatus::Expired => EntitlementState::Gated { reason: GatedReason::TrialExpired },
        TrialStatus::NotStarted => EntitlementState::Gated { reason: GatedReason::TrialExpired },
    })
}

async fn resolve_from_license_text(
    text: &str,
    local_install_uuid: &str,
) -> Result<EntitlementState> {
    // #12: resolve the trusted key via trusted_verifying_key() (production
    // const in release; debug-gated override for the integration test) and
    // delegate to the explicit-key variant. Tests call the _with_pk variant
    // directly with the dev key, decoupling them from the production constant.
    let public_key = match trusted_verifying_key() {
        Ok(pk) => pk,
        Err(_) => {
            tracing::warn!("trusted public key is unparseable; gating");
            return Ok(EntitlementState::Gated { reason: GatedReason::LicenseInvalid });
        }
    };
    resolve_from_license_text_with_pk(text, local_install_uuid, &public_key).await
}

/// Verify + resolve against an explicit public key. Production reaches this via
/// [`resolve_from_license_text`] + [`trusted_verifying_key`]; tests call it with
/// the dev verifying key so they do NOT depend on `SERVER_PUBLIC_KEY_HEX`.
async fn resolve_from_license_text_with_pk(
    text: &str,
    local_install_uuid: &str,
    public_key: &VerifyingKey,
) -> Result<EntitlementState> {
    // Parse + verify; downgrade any failure to Gated rather than aborting boot.
    let parsed = match parse_license(text) {
        Ok(p) => p,
        Err(ParseError::MissingBlock) => {
            // No BEGIN/END block at all → treat as "no license" and let caller
            // proceed to trial. (Re-route via explicit trial path.)
            tracing::info!("license file present but no v2 block; ignoring");
            return Ok(EntitlementState::Gated { reason: GatedReason::LicenseInvalid });
        }
        Err(e) => {
            tracing::warn!(error = %e, "license parse failed; gating");
            return Ok(EntitlementState::Gated { reason: GatedReason::LicenseInvalid });
        }
    };

    match verify_license_with_pk(&parsed, public_key) {
        Ok(license) => Ok(license_state(license, local_install_uuid)),
        Err(VerifyError::SignatureMismatch)
        | Err(VerifyError::WrongProduct(_))
        | Err(VerifyError::WrongVersion(_))
        | Err(VerifyError::InvalidType(_))
        | Err(VerifyError::InvalidPublicKey)
        | Err(VerifyError::InvalidSignatureEncoding) => {
            tracing::warn!(error = ?VerifyError::SignatureMismatch, "license verify failed; gating");
            Ok(EntitlementState::Gated { reason: GatedReason::LicenseInvalid })
        }
    }
}

fn license_state(license: LicenseV2, local_install_uuid: &str) -> EntitlementState {
    if license.instance_id != local_install_uuid {
        tracing::warn!("license instance_id does not match local install_uuid; gating");
        return EntitlementState::Gated { reason: GatedReason::InstanceMismatch };
    }
    let expires_at = license
        .expires_at
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    if let Some(exp) = expires_at {
        if Utc::now() > exp {
            return EntitlementState::Gated { reason: GatedReason::LicenseExpired };
        }
    }

    EntitlementState::Licensed { license, expires_at }
}

/// Read the license file path, or `None` if neither env nor default file exists.
///
/// DEFENSIVE-NOTE: IO errors (permission denied, malformed path) are surfaced
/// as `None` rather than crashing boot — the result is "act as if no license
/// present" so the user lands in trial/gated rather than losing the server.
fn read_license_file() -> Option<String> {
    let path = std::env::var(LICENSE_FILE_ENV)
        .unwrap_or_else(|_| LICENSE_FILE_DEFAULT.to_string());
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "license file unreadable; ignoring");
            None
        }
    }
}

// ── #3: License HTTP API (write side) ──

/// Resolve the `.dbmlicense` path from env (`DBMASTER_LICENSE_FILE`) or default
/// (`.dbmlicense`). Public so the POST /api/license handler and tests can share
/// the same resolution as [`read_license_file`].
// CHANGE: #3 — POST /api/license needs to write the file; expose the path
// resolver so callers don't duplicate the env-var logic.
pub fn license_file_path() -> std::path::PathBuf {
    std::env::var(LICENSE_FILE_ENV)
        .unwrap_or_else(|_| LICENSE_FILE_DEFAULT.to_string())
        .into()
}

/// Atomically write the license PEM text to the resolved file path
/// (`DBMASTER_LICENSE_FILE` or `.dbmlicense`).
///
/// Strategy: write to `<path>.tmp` in the same directory, then rename. Rename
/// within the same filesystem is atomic on Unix & Windows, so a crash mid-write
/// can never leave a half-written license file (which would cause the next
/// boot's `read_license_file` → parse to fail and the server to land in
/// `Gated` despite the user having a valid license).
///
/// On Unix, attempts to chmod the file to `0600` (owner-only) since the PEM
/// contains the licensee email + instance_id. The chmod is best-effort: a
/// failure is logged but does NOT fail the write (the file is still correctly
/// written; default umask applies).
///
/// Errors surface as `io::Error` so the POST handler can return a 500 without
/// swapping the in-memory entitlement (per design §6.1 step 5/6 ordering:
/// write must succeed before swap).
// CHANGE: #3 — write side of the license HTTP API.
pub fn write_license_file(text: &str) -> std::io::Result<()> {
    let path = license_file_path();
    // Same-directory temp file → guarantees same filesystem (rename atomic).
    // `.with_extension("dbmlicense.tmp")` produces `<base>.dbmlicense.tmp` for
    // the default `.dbmlicense` path; for a custom env path the extension
    // replacement is still well-defined.
    let mut tmp_path = path.clone();
    let mut new_name = tmp_path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    new_name.push(".tmp");
    tmp_path.set_file_name(new_name);

    std::fs::write(&tmp_path, text)?;

    // Best-effort 0600 on Unix (license PEM carries email + instance_id).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!(path = %tmp_path.display(), error = %e, "could not chmod license tmp file to 0600; continuing");
        }
    }

    std::fs::rename(&tmp_path, &path)?;
    tracing::info!(path = %path.display(), "license file written");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::generate_install_uuid;

    // ── #3: write_license_file (T6) ──

    /// Serializes the LICENSE_FILE_ENV-manipulating tests below. The env var
    /// is process-global; without this lock, parallel execution races and
    /// write_license_file_creates_with_content / _overwrites_existing /
    /// _atomic_no_tmp_left would clobber each other's paths. Poison is
    /// recovered so a single failure doesn't cascade.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper: set $DBMASTER_LICENSE_FILE to a temp file path and return its parent
    /// dir so the test keeps a reference for cleanup. Tests must each set their
    /// own env var (process-wide) — we run serially under ENV_LOCK.
    fn with_temp_license_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.dbmlicense");
        std::env::set_var(LICENSE_FILE_ENV, &path);
        (dir, path)
    }

    #[test]
    fn write_license_file_creates_with_content() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_dir, path) = with_temp_license_file();
        let pem = "-----BEGIN DBMASTER SERVER LICENSE-----\nhello\n-----END-----\n";
        write_license_file(pem).expect("write ok");
        let read_back = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read_back, pem);
    }

    #[test]
    fn write_license_file_atomic_no_tmp_left() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_dir, path) = with_temp_license_file();
        write_license_file("content").unwrap();
        let mut tmp = path.clone();
        let mut name = tmp.file_name().unwrap().to_os_string();
        name.push(".tmp");
        tmp.set_file_name(name);
        assert!(
            !tmp.exists(),
            "temp file {:?} should have been renamed away",
            tmp
        );
        assert!(path.exists(), "final file should exist");
    }

    #[test]
    fn write_license_file_overwrites_existing() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_dir, path) = with_temp_license_file();
        write_license_file("old content").unwrap();
        write_license_file("new content").unwrap();
        let read_back = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read_back, "new content");
    }

    #[test]
    fn license_file_path_honors_env_var() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom.lic");
        std::env::set_var(LICENSE_FILE_ENV, &custom);
        assert_eq!(license_file_path(), custom);
        std::env::remove_var(LICENSE_FILE_ENV);
        // default fallback
        assert_eq!(license_file_path(), std::path::PathBuf::from(LICENSE_FILE_DEFAULT));
    }

    // ── existing entitlement tests below ──

    fn fixture_yearly(instance_id: &str) -> LicenseV2 {
        LicenseV2 {
            email: "alice@example.com".into(),
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            instance_id: instance_id.into(),
            issued_at: "2026-08-05T00:00:00Z".into(),
            license_type: "yearly".into(),
        }
    }

    fn fixture_lifetime(instance_id: &str) -> LicenseV2 {
        LicenseV2 {
            email: "bob@example.com".into(),
            expires_at: None,
            instance_id: instance_id.into(),
            issued_at: "2026-08-05T00:00:00Z".into(),
            license_type: "lifetime".into(),
        }
    }

    #[test]
    fn licensed_yearly_active() {
        let id = generate_install_uuid();
        let lic = fixture_yearly(&id);
        let state = license_state(lic.clone(), &id);
        assert!(!state.is_gated());
        assert!(state.days_until_expiry().unwrap_or(0) > 0);
        assert_eq!(state.renewal_banner(), None); // far future
    }

    #[test]
    fn licensed_lifetime_no_banner() {
        let id = generate_install_uuid();
        let lic = fixture_lifetime(&id);
        let state = license_state(lic, &id);
        assert!(!state.is_gated());
        assert_eq!(state.days_until_expiry(), None);
        assert_eq!(state.renewal_banner(), None);
    }

    #[test]
    fn licensed_instance_mismatch_gated() {
        let id = generate_install_uuid();
        let lic = fixture_yearly(&id);
        let state = license_state(lic, "some-other-uuid");
        assert!(matches!(
            state,
            EntitlementState::Gated { reason: GatedReason::InstanceMismatch }
        ));
    }

    #[test]
    fn licensed_expired_gated() {
        let id = generate_install_uuid();
        let lic = LicenseV2 {
            expires_at: Some("2000-01-01T00:00:00Z".into()),
            ..fixture_yearly(&id)
        };
        let state = license_state(lic, &id);
        assert!(matches!(
            state,
            EntitlementState::Gated { reason: GatedReason::LicenseExpired }
        ));
    }

    #[test]
    fn renewal_banner_soon_under_30_days() {
        let id = generate_install_uuid();
        let in_20 = (Utc::now() + chrono::Duration::days(20)).to_rfc3339();
        let lic = LicenseV2 {
            expires_at: Some(in_20),
            ..fixture_yearly(&id)
        };
        let state = license_state(lic, &id);
        assert_eq!(state.renewal_banner(), Some(RenewalTier::Soon));
    }

    #[test]
    fn renewal_banner_urgent_under_7_days() {
        let id = generate_install_uuid();
        let in_3 = (Utc::now() + chrono::Duration::days(3)).to_rfc3339();
        let lic = LicenseV2 {
            expires_at: Some(in_3),
            ..fixture_yearly(&id)
        };
        let state = license_state(lic, &id);
        assert_eq!(state.renewal_banner(), Some(RenewalTier::Urgent));
    }

    // ── resolve_entitlement_with_text: full integration (parse → verify → match) ──

    use ed25519_dalek::{Signer, SigningKey};

    /// Same dev seed as crate-root tests; kept private to this test module.
    /// C-8: this seed is unified with the tech-site Go signer. Single source of
    /// truth: tests/golden_license.json (see crate-root golden_* tests).
    const TEST_DEV_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xf5, 0xeb, 0x81, 0xfa, 0xb4, 0xe6, 0x68, 0x9d, 0x08, 0xfb,
        0x4e, 0xce, 0xa2, 0xc2, 0x55, 0x60, 0x96, 0x0b, 0x4d, 0x3e, 0xea, 0x45, 0x04, 0xd0, 0x3b,
        0x5d, 0x0a,
    ];

    fn render_license_pem(license: &LicenseV2, signature_hex: &str) -> String {
        let exp = license.expires_at.as_deref().unwrap_or("");
        format!(
            "-----BEGIN DBMASTER SERVER LICENSE-----\n\
             email: {email}\n\
             expires_at: {exp}\n\
             instance_id: {iid}\n\
             issued_at: {iat}\n\
             product: server\n\
             type: {typ}\n\
             v: 2\n\
             signature: {sig}\n\
             -----END DBMASTER SERVER LICENSE-----",
            email = license.email,
            iid = license.instance_id,
            iat = license.issued_at,
            typ = license.license_type,
            sig = signature_hex,
        )
    }

    async fn setup_pool_with_instance() -> (SqlitePool, String) {
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
        let meta = crate::get_or_create_instance(&pool).await.unwrap();
        (pool, meta.install_uuid)
    }

    fn sign_for_dev(lic: &LicenseV2) -> String {
        let sk = SigningKey::from_bytes(&TEST_DEV_SEED);
        let sig = sk.sign(&lic.canonical_bytes());
        hex::encode(sig.to_bytes())
    }

    /// Dev public key (counterpart of TEST_DEV_SEED). The 3 verify-path tests
    /// below resolve against THIS via resolve_from_license_text_with_pk, not the
    /// production SERVER_PUBLIC_KEY_HEX — #12 decoupling.
    fn dev_verifying_key() -> VerifyingKey {
        SigningKey::from_bytes(&TEST_DEV_SEED).verifying_key()
    }

    /// End-to-end: a real signed license → resolve → Licensed.
    #[tokio::test]
    async fn resolve_entitlement_with_matching_license_returns_licensed() {
        let (_pool, install_uuid) = setup_pool_with_instance().await;

        let lic = fixture_yearly(&install_uuid);
        let pem = render_license_pem(&lic, &sign_for_dev(&lic));

        // #12: resolve against the dev key directly (decoupled from the
        // production SERVER_PUBLIC_KEY_HEX).
        let state = resolve_from_license_text_with_pk(&pem, &install_uuid, &dev_verifying_key())
            .await
            .unwrap();
        assert!(
            matches!(state, EntitlementState::Licensed { .. }),
            "expected Licensed, got {state:?}"
        );
        assert!(!state.is_gated());
    }

    /// End-to-end: license signed for a different install_uuid → Gated (mismatch).
    #[tokio::test]
    async fn resolve_entitlement_with_mismatched_license_returns_gated() {
        let (_pool, local_uuid) = setup_pool_with_instance().await;

        let lic = fixture_yearly("some-other-machine-uuid");
        let pem = render_license_pem(&lic, &sign_for_dev(&lic));

        let state = resolve_from_license_text_with_pk(&pem, &local_uuid, &dev_verifying_key())
            .await
            .unwrap();
        assert!(matches!(
            state,
            EntitlementState::Gated {
                reason: GatedReason::InstanceMismatch
            }
        ));
    }

    /// End-to-end: tampered signature → Gated (license_invalid).
    #[tokio::test]
    async fn resolve_entitlement_with_tampered_license_returns_gated() {
        let (_pool, install_uuid) = setup_pool_with_instance().await;

        let lic = fixture_yearly(&install_uuid);
        let mut sig = sign_for_dev(&lic).into_bytes();
        sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
        let bad_sig = String::from_utf8(sig).unwrap();
        let pem = render_license_pem(&lic, &bad_sig);

        let state = resolve_from_license_text_with_pk(&pem, &install_uuid, &dev_verifying_key())
            .await
            .unwrap();
        assert!(matches!(
            state,
            EntitlementState::Gated {
                reason: GatedReason::LicenseInvalid
            }
        ));
    }

    /// End-to-end: no license text → trial window starts on first call.
    #[tokio::test]
    async fn resolve_entitlement_without_license_starts_trial() {
        let (pool, _install_uuid) = setup_pool_with_instance().await;
        let state = resolve_entitlement_with_text(&pool, None).await.unwrap();
        assert!(matches!(state, EntitlementState::Trial { .. }));
    }
}
