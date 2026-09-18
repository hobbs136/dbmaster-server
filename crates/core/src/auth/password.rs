//! Password hashing and verification using Argon2id.
//!
//! Argon2id is the winner of the Password Hashing Competition (2015)
//! and is memory-hard — resistant to GPU/ASIC attacks.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Hash a plaintext password using Argon2id with a random salt.
///
/// # Errors
///
/// Returns an error if hashing fails (e.g. OOM, invalid parameters).
/// This should never happen with default parameters on reasonable hardware.
pub fn hash_password(plain: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(plain.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against an Argon2id hash.
///
/// Returns `Ok(true)` if the password matches, `Ok(false)` if it doesn't,
/// and an error only if the hash string itself is malformed.
pub fn verify_password(
    plain: &str,
    hash: &str,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let password = "correct-horse-battery-staple";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
    }

    #[test]
    fn wrong_password_fails() {
        let hash = hash_password("real-password").unwrap();
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn same_password_produces_different_hashes() {
        let h1 = hash_password("same").unwrap();
        let h2 = hash_password("same").unwrap();
        assert_ne!(h1, h2); // different salts
        assert!(verify_password("same", &h1).unwrap());
        assert!(verify_password("same", &h2).unwrap());
    }
}
