//! dbmaster-license — Ed25519 v2 license verification + entitlement state.
//!
//! ADR-0001 (Status: Accepted) implementation:
//! - v2 canonical (line-based, LF, lexicographic, no trailing newline).
//! - Embedded Server Ed25519 public key (compile-time constant).
//! - `parse_license` decodes the PEM-like text block; `verify_license` checks
//!   signature + version + product.
//! - `entitlement`, `instance`, `trial` modules own runtime state resolution.
//!
//! Cross-language contract (shared with tech-site Go `signLicense`):
//! ```text
//! email:{email}
//! expires_at:{iso8601 or empty line for lifetime}
//! instance_id:{install_uuid}
//! issued_at:{iso8601}
//! product:server
//! type:yearly|lifetime
//! v:2
//! ```

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub mod entitlement;
pub mod instance;
pub mod trial;

// CHANGE: ADR-0001 §7.1 — module re-exports for entitlement pipeline.
pub use entitlement::{
    license_file_path, resolve_entitlement, resolve_entitlement_with_text, EntitlementState,
    GatedReason, RenewalTier, RENEWAL_THRESHOLD_DAYS, RENEWAL_URGENT_DAYS, write_license_file,
};
// CHANGE: expose get_install_uuid for AppState wiring (webhook payload).
pub use instance::{generate_install_uuid, get_install_uuid, get_or_create_instance, InstanceMeta};
pub use trial::{ensure_trial_status, TrialStatus, TRIAL_DAYS};

/// Embedded Server Ed25519 public key (32 bytes, hex) — the **production**
/// trust anchor (#12). The matching private seed is held offline by the
/// issuer (签发方) and injected into the tech-site signer via the
/// `DBMASTER_SERVER_LICENSE_PRIVATE_KEY` env var; it is NEVER in this repo,
/// never in tests, never in logs.
///
/// **Tests are decoupled from this constant.** Unit tests sign + verify with a
/// fixed dev keypair via [`verify_license_with_pk`] (see `TEST_DEV_SEED`),
/// so rotating this constant breaks zero tests. The server's end-to-end
/// integration test (`tests/license_api_test.rs`) signs with that same dev
/// keypair and, because it must exercise the *real* handler path (which uses
/// this constant), sets the `DBMASTER_LICENSE_VERIFY_PUBKEY_OVERRIDE_HEX` env
/// var to the dev pubkey. That override is honored ONLY in debug/test builds
/// (`cfg(debug_assertions)`); release builds compile the override out entirely,
/// so shipped binaries trust this constant and nothing else.
///
/// The dev keypair + golden signatures shared with the Go `signLicense` side
/// live in `tests/golden_license.json` (C-8 integration gate, `dev_only: true`
/// guard refuses to load a production key).
// CHANGE: ADR-0001 §4.1 D1=B — Server-independent keypair, public key builtin.
// CHANGE: #12 — replaced the DEV/TEST seed-derived pubkey with the production
// trust anchor; tests decoupled via verify_license_with_pk + debug-gated override.
pub const SERVER_PUBLIC_KEY_HEX: &str =
    "6ef69c43723d19bdb1e40ed1fc31a6ba82936042994f1117decec6f42b33541f";

/// Env var consulted (debug/test builds only) to override the trusted public
/// key for the end-to-end integration test, so it can sign fixtures with the
/// dev keypair without chaining the test suite to [`SERVER_PUBLIC_KEY_HEX`].
/// Release builds never read this — see [`trusted_verifying_key`].
#[cfg(debug_assertions)]
const VERIFY_PUBKEY_OVERRIDE_ENV: &str = "DBMASTER_LICENSE_VERIFY_PUBKEY_OVERRIDE_HEX";

/// Resolve the Ed25519 verifying key trusted by this build. Release builds
/// always use [`SERVER_PUBLIC_KEY_HEX`]. Debug/test builds additionally honor
/// [`VERIFY_PUBKEY_OVERRIDE_ENV`] so the integration test can drive the real
/// handler with a dev keypair. The `cfg(debug_assertions)` override is the ONLY
/// way to diverge from the compiled constant, and it is absent from release
/// binaries — there is no runtime path for an operator or attacker to redirect
/// verification in a shipped build.
fn trusted_verifying_key() -> Result<VerifyingKey, VerifyError> {
    let hex_str: String = {
        #[cfg(debug_assertions)]
        {
            if let Ok(pk) = std::env::var(VERIFY_PUBKEY_OVERRIDE_ENV) {
                let pk = pk.trim();
                if !pk.is_empty() {
                    pk.to_string()
                } else {
                    SERVER_PUBLIC_KEY_HEX.to_string()
                }
            } else {
                SERVER_PUBLIC_KEY_HEX.to_string()
            }
        }
        #[cfg(not(debug_assertions))]
        {
            SERVER_PUBLIC_KEY_HEX.to_string()
        }
    };
    let pk_bytes = hex::decode(&hex_str).map_err(|_| VerifyError::InvalidPublicKey)?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&pk_arr).map_err(|_| VerifyError::InvalidPublicKey)
}

/// License product tag — Server licenses always carry `product:server`.
pub const PRODUCT_SERVER: &str = "server";

/// License format version.
pub const LICENSE_VERSION: u8 = 2;

// ── Parsed / verified license types ──

/// Fields extracted from a `.dbmlicense` PEM-like block, prior to verification.
///
/// Field ordering matches the v2 canonical contract (lexicographic).
/// `version` and `product` are validated by [`verify_license`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLicense {
    pub email: String,
    /// ISO-8601 expiry; `None` for `lifetime` licenses (canonical line left empty).
    pub expires_at: Option<String>,
    pub instance_id: String,
    pub issued_at: String,
    pub product: String,
    /// `"yearly"` or `"lifetime"`.
    pub license_type: String,
    pub version: u8,
    pub signature_hex: String,
}

/// Verified license payload (post-`verify_license`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseV2 {
    pub email: String,
    pub expires_at: Option<String>,
    pub instance_id: String,
    pub issued_at: String,
    pub license_type: String,
}

impl LicenseV2 {
    /// Canonical bytes for signing/verifying.
    ///
    /// Lines are emitted in lexicographic key order, LF-separated, no trailing
    /// newline. Lifetime licenses emit an empty `expires_at:` line to keep the
    /// canonical form positional and stable across format-compatible changes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // CHANGE: ADR-0001 §4.3 D3=C v2 canonical (byte-exact).
        let expires_line = self.expires_at.as_deref().unwrap_or("");
        let canonical = format!(
            "email:{email}\n\
             expires_at:{exp}\n\
             instance_id:{iid}\n\
             issued_at:{iat}\n\
             product:{product}\n\
             type:{typ}\n\
             v:{ver}",
            email = self.email,
            exp = expires_line,
            iid = self.instance_id,
            iat = self.issued_at,
            product = PRODUCT_SERVER,
            typ = self.license_type,
            ver = LICENSE_VERSION,
        );
        canonical.into_bytes()
    }
}

// ── Errors ──

/// Failures arising during [`parse_license`].
#[derive(Debug)]
pub enum ParseError {
    /// License block not found (expected BEGIN/END markers).
    MissingBlock,
    /// A required field was absent.
    MissingField(&'static str),
    /// A required field was present but empty.
    EmptyField(&'static str),
    /// `v:` value did not parse as a u8.
    InvalidVersion(String),
    /// `expires_at:` value did not look like ISO-8601.
    InvalidExpiresAt(String),
    /// A field appeared twice in the block.
    DuplicateField(&'static str),
    /// No `signature:` line, or line malformed.
    MissingSignature,
    /// A field appeared with an unknown key.
    UnknownField(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBlock => write!(f, "license block not found (expected BEGIN/END markers)"),
            Self::MissingField(n) => write!(f, "missing required field: {n}"),
            Self::EmptyField(n) => write!(f, "field {n} must be non-empty"),
            Self::InvalidVersion(v) => write!(f, "invalid version: {v}"),
            Self::InvalidExpiresAt(v) => write!(f, "invalid expires_at (expected ISO-8601): {v}"),
            Self::DuplicateField(n) => write!(f, "duplicate field: {n}"),
            Self::MissingSignature => write!(f, "signature line missing or malformed"),
            Self::UnknownField(k) => write!(f, "unknown field: {k}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Failures arising during [`verify_license`].
#[derive(Debug)]
pub enum VerifyError {
    /// `product` field is not `"server"`.
    WrongProduct(String),
    /// `v` field is not `2`.
    WrongVersion(u8),
    /// `type` field is neither `"yearly"` nor `"lifetime"`.
    InvalidType(String),
    InvalidPublicKey,
    InvalidSignatureEncoding,
    SignatureMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongProduct(p) => write!(f, "wrong product: {p} (expected 'server')"),
            Self::WrongVersion(v) => write!(f, "wrong version: {v} (expected 2)"),
            Self::InvalidType(t) => write!(f, "invalid type: {t} (expected 'yearly' or 'lifetime')"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSignatureEncoding => write!(f, "invalid signature encoding"),
            Self::SignatureMismatch => write!(f, "signature mismatch"),
        }
    }
}

impl std::error::Error for VerifyError {}

// ── Parsing ──

const BEGIN_MARKER: &str = "-----BEGIN DBMASTER SERVER LICENSE-----";
const END_MARKER: &str = "-----END DBMASTER SERVER LICENSE-----";

/// Parse a PEM-like license block into a [`ParsedLicense`].
///
/// Recognises fields of the form `key: value` (single space after the colon,
/// matching the Go signer's PEM rendering). The canonical form used for
/// signing/verifying uses `key:value` (no space); the difference is intentional
/// and [`LicenseV2::canonical_bytes`] emits the no-space form.
///
/// Unknown fields are rejected rather than silently dropped, to surface
/// malformed licenses early.
// CHANGE: ADR-0001 §4.3 D3=C — PEM parser for v2 license block.
pub fn parse_license(text: &str) -> Result<ParsedLicense, ParseError> {
    let begin = text.find(BEGIN_MARKER).ok_or(ParseError::MissingBlock)?;
    let end = text.find(END_MARKER).ok_or(ParseError::MissingBlock)?;
    if end <= begin {
        return Err(ParseError::MissingBlock);
    }
    let body = &text[begin + BEGIN_MARKER.len()..end];

    let mut email: Option<String> = None;
    let mut expires_at_raw: Option<String> = None;
    let mut instance_id: Option<String> = None;
    let mut issued_at: Option<String> = None;
    let mut product: Option<String> = None;
    let mut license_type: Option<String> = None;
    let mut version: Option<String> = None;
    let mut signature_hex: Option<String> = None;

    for raw_line in body.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Each field is "key: value" — split on the first ':'.
        let (key, value) = trimmed
            .split_once(':')
            .ok_or(ParseError::MissingSignature)?;
        let key = key.trim();
        // Tolerate either "key: value" (PEM display) or "key:value" (canonical).
        let value = value.trim().to_string();

        match key {
            "email" => {
                if email.is_some() {
                    return Err(ParseError::DuplicateField("email"));
                }
                email = Some(value);
            }
            "expires_at" => {
                if expires_at_raw.is_some() {
                    return Err(ParseError::DuplicateField("expires_at"));
                }
                expires_at_raw = Some(value);
            }
            "instance_id" => {
                if instance_id.is_some() {
                    return Err(ParseError::DuplicateField("instance_id"));
                }
                instance_id = Some(value);
            }
            "issued_at" => {
                if issued_at.is_some() {
                    return Err(ParseError::DuplicateField("issued_at"));
                }
                issued_at = Some(value);
            }
            "product" => {
                if product.is_some() {
                    return Err(ParseError::DuplicateField("product"));
                }
                product = Some(value);
            }
            "type" => {
                if license_type.is_some() {
                    return Err(ParseError::DuplicateField("type"));
                }
                license_type = Some(value);
            }
            "v" => {
                if version.is_some() {
                    return Err(ParseError::DuplicateField("v"));
                }
                version = Some(value);
            }
            "signature" => {
                if signature_hex.is_some() {
                    return Err(ParseError::DuplicateField("signature"));
                }
                signature_hex = Some(value);
            }
            _ => return Err(ParseError::UnknownField(key.to_string())), // strict: reject unknown
        }
    }

    let email = email.ok_or(ParseError::MissingField("email"))?;
    let instance_id = instance_id.ok_or(ParseError::MissingField("instance_id"))?;
    let issued_at = issued_at.ok_or(ParseError::MissingField("issued_at"))?;
    let product = product.ok_or(ParseError::MissingField("product"))?;
    let license_type = license_type.ok_or(ParseError::MissingField("type"))?;
    let signature_hex = signature_hex.ok_or(ParseError::MissingSignature)?;
    let version_str = version.ok_or(ParseError::MissingField("v"))?;

    if email.is_empty() {
        return Err(ParseError::EmptyField("email"));
    }
    if instance_id.is_empty() {
        return Err(ParseError::EmptyField("instance_id"));
    }
    if issued_at.is_empty() {
        return Err(ParseError::EmptyField("issued_at"));
    }

    let version: u8 = version_str
        .parse()
        .map_err(|_| ParseError::InvalidVersion(version_str.clone()))?;

    // expires_at: empty string is valid only for `lifetime` type. Non-empty must
    // look like ISO-8601 (cheap sanity check; full parsing happens at verify time).
    let expires_at = match expires_at_raw.as_deref() {
        None => None,
        Some("") => None,
        Some(s) => {
            // Cheap ISO-8601 sanity: contains 'T' and ends with 'Z' or has offset.
            if !s.contains('T') {
                return Err(ParseError::InvalidExpiresAt(s.to_string()));
            }
            Some(s.to_string())
        }
    };

    // If expires_at present, type must be yearly; if absent, type must be lifetime.
    // (Loose check: enforce non-contradictory at parse time.)
    match (license_type.as_str(), expires_at.is_some()) {
        ("lifetime", false) | ("yearly", true) => {}
        _ => return Err(ParseError::MissingField("type_expires_at_mismatch")),
    }

    Ok(ParsedLicense {
        email,
        expires_at,
        instance_id,
        issued_at,
        product,
        license_type,
        version,
        signature_hex,
    })
}

// ── Verification ──

/// Verify a parsed license against the embedded public key.
///
/// Checks version, product, type, and Ed25519 signature over the v2 canonical
/// bytes. Returns the verified [`LicenseV2`] payload on success.
///
/// `instance_id` equality with the local install_uuid and `expires_at`
/// freshness are **not** checked here — those are runtime concerns handled by
/// [`entitlement::resolve_entitlement`].
// CHANGE: ADR-0001 §4.3 D3=C + §4.1 D1=B — builtin public key, v2 canonical.
// CHANGE: #12 — splits into verify_license_with_pk (core, test-injectable) +
// verify_license (production, resolves the trusted key via trusted_verifying_key).
pub fn verify_license(parsed: &ParsedLicense) -> Result<LicenseV2, VerifyError> {
    let public_key = trusted_verifying_key()?;
    verify_license_with_pk(parsed, &public_key)
}

/// Core verification against an explicit public key — field checks + signature.
/// Tests call this with the dev verifying key (derived from `TEST_DEV_SEED`)
/// so they do NOT depend on [`SERVER_PUBLIC_KEY_HEX`]; rotating the production
/// constant therefore breaks zero tests. Production code reaches this via
/// [`verify_license`] + [`trusted_verifying_key`].
fn verify_license_with_pk(
    parsed: &ParsedLicense,
    public_key: &VerifyingKey,
) -> Result<LicenseV2, VerifyError> {
    if parsed.product != PRODUCT_SERVER {
        return Err(VerifyError::WrongProduct(parsed.product.clone()));
    }
    if parsed.version != LICENSE_VERSION {
        return Err(VerifyError::WrongVersion(parsed.version));
    }
    if !matches!(parsed.license_type.as_str(), "yearly" | "lifetime") {
        return Err(VerifyError::InvalidType(parsed.license_type.clone()));
    }

    let sig_bytes = hex::decode(&parsed.signature_hex)
        .map_err(|_| VerifyError::InvalidSignatureEncoding)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::InvalidSignatureEncoding)?;

    let license = LicenseV2 {
        email: parsed.email.clone(),
        expires_at: parsed.expires_at.clone(),
        instance_id: parsed.instance_id.clone(),
        issued_at: parsed.issued_at.clone(),
        license_type: parsed.license_type.clone(),
    };
    let canonical = license.canonical_bytes();

    public_key
        .verify(&canonical, &signature)
        .map_err(|_| VerifyError::SignatureMismatch)?;

    Ok(license)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Development seed for test-fixture signing only.
    /// NOT a real key. Public-key counterpart is [`SERVER_PUBLIC_KEY_HEX`] above.
    /// Anyone can reproduce this seed and forge test licenses; it MUST NOT ship
    /// to production. Picked as a fixed 32-byte value to make verify-path tests
    /// deterministic.
    ///
    /// C-8 integration gate: this seed is UNIFIED with the tech-site Go signer
    /// (`testSignerSeedHex` in dbmaster-tech-site/activate_test.go). Both sides
    /// read tests/golden_license.json and assert the seed + derived pubkey match.
    /// Drift = test failure on the diverged side.
    const TEST_DEV_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xf5, 0xeb, 0x81, 0xfa, 0xb4, 0xe6, 0x68, 0x9d, 0x08, 0xfb,
        0x4e, 0xce, 0xa2, 0xc2, 0x55, 0x60, 0x96, 0x0b, 0x4d, 0x3e, 0xea, 0x45, 0x04, 0xd0, 0x3b,
        0x5d, 0x0a,
    ];

    fn dev_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_DEV_SEED)
    }

    /// The dev public key (counterpart of [`TEST_DEV_SEED`]). Tests verify
    /// against THIS, not the production [`SERVER_PUBLIC_KEY_HEX`] — see
    /// [`verify_license_with_pk`] (#12 decoupling).
    fn dev_verifying_key() -> VerifyingKey {
        dev_signing_key().verifying_key()
    }

    fn sign_canonical(license: &LicenseV2) -> String {
        let sk = dev_signing_key();
        let sig = sk.sign(&license.canonical_bytes());
        hex::encode(sig.to_bytes())
    }

    fn fixture_yearly() -> LicenseV2 {
        LicenseV2 {
            email: "alice@example.com".into(),
            expires_at: Some("2027-08-05T00:00:00Z".into()),
            instance_id: "abcdef0123456789".into(),
            issued_at: "2026-08-05T00:00:00Z".into(),
            license_type: "yearly".into(),
        }
    }

    fn fixture_lifetime() -> LicenseV2 {
        LicenseV2 {
            email: "bob@example.com".into(),
            expires_at: None,
            instance_id: "fffffffbbbbbbbb".into(),
            issued_at: "2026-08-05T00:00:00Z".into(),
            license_type: "lifetime".into(),
        }
    }

    fn render_pem(license: &LicenseV2, signature_hex: &str) -> String {
        let exp = license.expires_at.as_deref().unwrap_or("");
        format!(
            "{begin}\n\
             email: {email}\n\
             expires_at: {exp}\n\
             instance_id: {iid}\n\
             issued_at: {iat}\n\
             product: server\n\
             type: {typ}\n\
             v: 2\n\
             signature: {sig}\n\
             {end}",
            begin = BEGIN_MARKER,
            end = END_MARKER,
            email = license.email,
            iid = license.instance_id,
            iat = license.issued_at,
            typ = license.license_type,
            sig = signature_hex,
        )
    }

    // ── canonical_bytes ──

    #[test]
    fn canonical_yearly_is_exact() {
        let lic = fixture_yearly();
        let expected = "email:alice@example.com\n\
                        expires_at:2027-08-05T00:00:00Z\n\
                        instance_id:abcdef0123456789\n\
                        issued_at:2026-08-05T00:00:00Z\n\
                        product:server\n\
                        type:yearly\n\
                        v:2";
        assert_eq!(lic.canonical_bytes(), expected.as_bytes());
    }

    #[test]
    fn canonical_lifetime_has_empty_expires_line() {
        let lic = fixture_lifetime();
        let cb = lic.canonical_bytes();
        let s = std::str::from_utf8(&cb).unwrap();
        assert!(
            s.contains("expires_at:\n"),
            "lifetime canonical must keep empty expires_at line; got: {s}"
        );
        assert!(!s.ends_with('\n'), "no trailing newline");
    }

    // ── verify_license: normal + tamper + wrong-version/product/type ──

    #[test]
    fn verify_yearly_ok() {
        let lic = fixture_yearly();
        let sig = sign_canonical(&lic);
        let parsed = ParsedLicense {
            email: lic.email.clone(),
            expires_at: lic.expires_at.clone(),
            instance_id: lic.instance_id.clone(),
            issued_at: lic.issued_at.clone(),
            product: "server".into(),
            license_type: "yearly".into(),
            version: 2,
            signature_hex: sig,
        };
        let out = verify_license_with_pk(&parsed, &dev_verifying_key()).expect("must verify");
        assert_eq!(out, lic);
    }

    #[test]
    fn verify_lifetime_ok() {
        let lic = fixture_lifetime();
        let sig = sign_canonical(&lic);
        let parsed = ParsedLicense {
            email: lic.email.clone(),
            expires_at: None,
            instance_id: lic.instance_id.clone(),
            issued_at: lic.issued_at.clone(),
            product: "server".into(),
            license_type: "lifetime".into(),
            version: 2,
            signature_hex: sig,
        };
        verify_license_with_pk(&parsed, &dev_verifying_key()).expect("lifetime must verify");
    }

    #[test]
    fn verify_tampered_signature_fails() {
        let lic = fixture_yearly();
        let mut sig = sign_canonical(&lic);
        // Flip one hex char.
        let mut bytes = sig.into_bytes();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        sig = String::from_utf8(bytes).unwrap();
        let parsed = ParsedLicense {
            email: lic.email,
            expires_at: lic.expires_at,
            instance_id: lic.instance_id,
            issued_at: lic.issued_at,
            product: "server".into(),
            license_type: "yearly".into(),
            version: 2,
            signature_hex: sig,
        };
        assert!(matches!(
            verify_license_with_pk(&parsed, &dev_verifying_key()),
            Err(VerifyError::SignatureMismatch)
        ));
    }

    #[test]
    fn verify_tampered_payload_fails() {
        // Sign one payload, swap instance_id in parsed → signature must not match.
        let lic = fixture_yearly();
        let sig = sign_canonical(&lic);
        let parsed = ParsedLicense {
            email: lic.email,
            expires_at: lic.expires_at,
            instance_id: "tampered_instance".into(),
            issued_at: lic.issued_at,
            product: "server".into(),
            license_type: "yearly".into(),
            version: 2,
            signature_hex: sig,
        };
        assert!(matches!(
            verify_license_with_pk(&parsed, &dev_verifying_key()),
            Err(VerifyError::SignatureMismatch)
        ));
    }

    #[test]
    fn verify_wrong_version_rejected_before_signature() {
        let lic = fixture_yearly();
        let sig = sign_canonical(&lic);
        let parsed = ParsedLicense {
            email: lic.email,
            expires_at: lic.expires_at,
            instance_id: lic.instance_id,
            issued_at: lic.issued_at,
            product: "server".into(),
            license_type: "yearly".into(),
            version: 1, // wrong
            signature_hex: sig,
        };
        assert!(matches!(
            verify_license_with_pk(&parsed, &dev_verifying_key()),
            Err(VerifyError::WrongVersion(1))
        ));
    }

    #[test]
    fn verify_wrong_product_rejected() {
        let lic = fixture_yearly();
        let sig = sign_canonical(&lic);
        let parsed = ParsedLicense {
            email: lic.email,
            expires_at: lic.expires_at,
            instance_id: lic.instance_id,
            issued_at: lic.issued_at,
            product: "desktop".into(), // wrong product
            license_type: "yearly".into(),
            version: 2,
            signature_hex: sig,
        };
        assert!(matches!(
            verify_license_with_pk(&parsed, &dev_verifying_key()),
            Err(VerifyError::WrongProduct(_))
        ));
    }

    #[test]
    fn verify_invalid_type_rejected() {
        let lic = fixture_yearly();
        let sig = sign_canonical(&lic);
        let parsed = ParsedLicense {
            email: lic.email,
            expires_at: lic.expires_at,
            instance_id: lic.instance_id,
            issued_at: lic.issued_at,
            product: "server".into(),
            license_type: "monthly".into(), // invalid
            version: 2,
            signature_hex: sig,
        };
        assert!(matches!(
            verify_license_with_pk(&parsed, &dev_verifying_key()),
            Err(VerifyError::InvalidType(_))
        ));
    }

    #[test]
    fn verify_bad_signature_hex_rejected() {
        let lic = fixture_yearly();
        let parsed = ParsedLicense {
            email: lic.email,
            expires_at: lic.expires_at,
            instance_id: lic.instance_id,
            issued_at: lic.issued_at,
            product: "server".into(),
            license_type: "yearly".into(),
            version: 2,
            signature_hex: "nothex".into(),
        };
        assert!(matches!(
            verify_license_with_pk(&parsed, &dev_verifying_key()),
            Err(VerifyError::InvalidSignatureEncoding)
        ));
    }

    // ── parse_license ──

    #[test]
    fn parse_yearly_roundtrip() {
        let lic = fixture_yearly();
        let sig = sign_canonical(&lic);
        let pem = render_pem(&lic, &sig);
        let parsed = parse_license(&pem).expect("parse ok");
        assert_eq!(parsed.email, lic.email);
        assert_eq!(parsed.expires_at.as_deref(), Some("2027-08-05T00:00:00Z"));
        assert_eq!(parsed.instance_id, lic.instance_id);
        assert_eq!(parsed.issued_at, lic.issued_at);
        assert_eq!(parsed.product, "server");
        assert_eq!(parsed.license_type, "yearly");
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.signature_hex, sig);
    }

    #[test]
    fn parse_lifetime_empty_expires_ok() {
        let lic = fixture_lifetime();
        let sig = sign_canonical(&lic);
        let pem = render_pem(&lic, &sig);
        let parsed = parse_license(&pem).expect("parse ok");
        assert!(parsed.expires_at.is_none());
        assert_eq!(parsed.license_type, "lifetime");
    }

    #[test]
    fn parse_missing_block_rejected() {
        assert!(matches!(
            parse_license("just some text, no markers"),
            Err(ParseError::MissingBlock)
        ));
    }

    #[test]
    fn parse_missing_field_rejected() {
        // Construct a block missing `issued_at`.
        let block = format!(
            "{begin}\nemail: a@b.com\nexpires_at: 2027-01-01T00:00:00Z\n\
             instance_id: x\nproduct: server\ntype: yearly\nv: 2\nsignature: abcd\n{end}",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        );
        assert!(matches!(
            parse_license(&block),
            Err(ParseError::MissingField("issued_at"))
        ));
    }

    #[test]
    fn parse_wrong_version_string_rejected() {
        let block = format!(
            "{begin}\nemail: a@b.com\nexpires_at: 2027-01-01T00:00:00Z\n\
             instance_id: x\nissued_at: 2026-01-01T00:00:00Z\nproduct: server\n\
             type: yearly\nv: not-a-number\nsignature: abcd\n{end}",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        );
        assert!(matches!(
            parse_license(&block),
            Err(ParseError::InvalidVersion(_))
        ));
    }

    #[test]
    fn parse_duplicate_field_rejected() {
        let block = format!(
            "{begin}\nemail: a@b.com\nemail: c@d.com\nexpires_at: 2027-01-01T00:00:00Z\n\
             instance_id: x\nissued_at: 2026-01-01T00:00:00Z\nproduct: server\n\
             type: yearly\nv: 2\nsignature: abcd\n{end}",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        );
        assert!(matches!(
            parse_license(&block),
            Err(ParseError::DuplicateField("email"))
        ));
    }

    #[test]
    fn parse_yearly_missing_expires_rejected() {
        // type:yearly but no expires_at line → mismatch.
        let block = format!(
            "{begin}\nemail: a@b.com\ninstance_id: x\nissued_at: 2026-01-01T00:00:00Z\n\
             product: server\ntype: yearly\nv: 2\nsignature: abcd\n{end}",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        );
        assert!(parse_license(&block).is_err());
    }

    // ── end-to-end: parse → verify ──

    #[test]
    fn parse_then_verify_yearly() {
        let lic = fixture_yearly();
        let sig = sign_canonical(&lic);
        let pem = render_pem(&lic, &sig);
        let parsed = parse_license(&pem).expect("parse");
        let verified = verify_license_with_pk(&parsed, &dev_verifying_key()).expect("verify");
        assert_eq!(verified, lic);
    }

    // ── C-8 integration gate: golden cross-language verification ──
    //
    // CHANGE: C-8 — byte-level interop lock between Go signLicense (tech-site)
    // and Rust verify_license (this crate). Reads tests/golden_license.json
    // (mirrored at dbmaster-tech-site/testdata/golden_license.json — the single
    // source of truth) and proves:
    //  1. The golden keypair.public_key_hex equals the DEV verifying key
    //     (TEST_DEV_SEED) — #12 decoupled this from the production const so the
    //     golden stays a dev-only fixture set (dev_only: true guard).
    //  2. The compiled-in TEST_DEV_SEED equals golden.keypair.seed_hex (bytes).
    //  3. For each fixture: Rust's LicenseV2::canonical_bytes matches the golden
    //     canonical string byte-for-byte (i.e. Go and Rust agree on the form).
    //  4. For each fixture: the golden signature — produced by Go — verifies
    //     under Rust's verify_license + the embedded public key.
    //  5. Reverse direction: Rust re-signs the canonical with TEST_DEV_SEED and
    //     produces byte-identical signature (Ed25519 is deterministic).

    use serde::Deserialize;

    #[derive(Deserialize)]
    struct GoldenKeypair {
        seed_hex: String,
        public_key_hex: String,
        #[allow(dead_code)]
        dev_only: bool,
    }

    #[derive(Deserialize)]
    struct GoldenFixture {
        #[allow(dead_code)]
        name: String,
        email: String,
        instance_id: String,
        license_type: String,
        issued_at: String,
        // Empty string for lifetime; keep as String to mirror the JSON shape.
        expires_at: String,
        canonical: String,
        signature_hex: String,
    }

    #[derive(Deserialize)]
    struct GoldenFile {
        keypair: GoldenKeypair,
        fixtures: Vec<GoldenFixture>,
    }

    const GOLDEN_JSON: &str = include_str!("../tests/golden_license.json");

    fn load_golden() -> GoldenFile {
        let g: GoldenFile = serde_json::from_str(GOLDEN_JSON)
            .expect("tests/golden_license.json must parse");
        assert!(g.keypair.dev_only, "golden keypair must be dev_only — refusing to load a production key into tests");
        g
    }

    fn license_v2_from_fixture(f: &GoldenFixture) -> LicenseV2 {
        LicenseV2 {
            email: f.email.clone(),
            expires_at: if f.expires_at.is_empty() { None } else { Some(f.expires_at.clone()) },
            instance_id: f.instance_id.clone(),
            issued_at: f.issued_at.clone(),
            license_type: f.license_type.clone(),
        }
    }

    #[test]
    fn golden_pubkey_matches_dev_verifying_key() {
        // #12: golden fixtures are signed by the DEV keypair, so the golden
        // pubkey must equal the dev verifying key (NOT the production const).
        let g = load_golden();
        let dev_pubkey_hex = hex::encode(dev_verifying_key().to_bytes());
        assert_eq!(
            g.keypair.public_key_hex, dev_pubkey_hex,
            "tests/golden_license.json keypair.public_key_hex must match the dev verifying key (TEST_DEV_SEED)"
        );
    }

    #[test]
    fn golden_seed_matches_test_dev_seed() {
        let g = load_golden();
        let want_bytes = hex::decode(&g.keypair.seed_hex).expect("seed hex decodes");
        let want: [u8; 32] = want_bytes
            .as_slice()
            .try_into()
            .expect("seed is 32 bytes");
        assert_eq!(
            want, TEST_DEV_SEED,
            "tests/golden_license.json keypair.seed_hex must equal TEST_DEV_SEED"
        );
    }

    #[test]
    fn golden_cross_language_signatures_verify() {
        let g = load_golden();
        assert!(!g.fixtures.is_empty(), "golden must contain at least one fixture");

        let signing_key = SigningKey::from_bytes(&TEST_DEV_SEED);

        for f in &g.fixtures {
            let lic = license_v2_from_fixture(f);

            // (3) Canonical byte-equality.
            assert_eq!(
                lic.canonical_bytes(),
                f.canonical.as_bytes(),
                "fixture {}: Rust canonical_bytes diverges from golden",
                f.name
            );

            // (4) Verify the Go-produced signature through the public API
            // (parse + verify) — exercises the same path the runtime uses.
            let parsed = ParsedLicense {
                email: lic.email.clone(),
                expires_at: lic.expires_at.clone(),
                instance_id: lic.instance_id.clone(),
                issued_at: lic.issued_at.clone(),
                product: PRODUCT_SERVER.into(),
                license_type: lic.license_type.clone(),
                version: LICENSE_VERSION,
                signature_hex: f.signature_hex.clone(),
            };
            let verified = verify_license_with_pk(&parsed, &dev_verifying_key())
                .unwrap_or_else(|e| panic!("fixture {}: golden signature must verify in Rust (got {e:?})", f.name));
            assert_eq!(verified, lic, "fixture {}: verified payload must match", f.name);

            // (5) Reverse: Rust re-signs → deterministic same-bytes signature.
            let resigned = signing_key.sign(&lic.canonical_bytes());
            let resigned_hex = hex::encode(resigned.to_bytes());
            assert_eq!(
                resigned_hex, f.signature_hex,
                "fixture {}: Rust re-sign must produce byte-identical signature to Go",
                f.name
            );
        }
    }

    // ── #12: production public-key constant guards ──

    #[test]
    fn server_public_key_const_is_valid_ed25519_key() {
        // Catch a typo in SERVER_PUBLIC_KEY_HEX (wrong length / non-hex) before
        // it ships: every license would fail to verify with InvalidPublicKey.
        let bytes = hex::decode(SERVER_PUBLIC_KEY_HEX).expect("const must be hex");
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .expect("const must decode to exactly 32 bytes");
        VerifyingKey::from_bytes(&arr).expect("const must be a valid Ed25519 verifying key");
    }

    #[test]
    fn server_public_key_const_is_not_the_dev_key() {
        // Forcing function for #12: if someone reverts SERVER_PUBLIC_KEY_HEX to
        // the forgeable DEV seed-derived pubkey, this fails the build. The dev
        // pubkey is the public counterpart of TEST_DEV_SEED (a published RFC
        // 8032 test vector) — anyone can reproduce it and forge licenses.
        let dev_pubkey_hex = hex::encode(dev_verifying_key().to_bytes());
        assert_ne!(
            SERVER_PUBLIC_KEY_HEX, dev_pubkey_hex,
            "SERVER_PUBLIC_KEY_HEX must NOT be the DEV/test key — rotate to a production keypair"
        );
    }
}
