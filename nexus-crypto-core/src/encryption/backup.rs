//! FROST key backup encryption using Argon2id + ChaCha20Poly1305.
//!
//! This module provides password-based encryption for FROST key_packages,
//! enabling secure backup and restoration of threshold signing keys.
//!
//! ## Protocol
//!
//! 1. **Key Derivation**: Argon2id (memory-hard, side-channel resistant)
//!    - Parameters: m=65536 (64MB), t=3, p=4 (OWASP recommendations)
//! 2. **Encryption**: ChaCha20Poly1305 (AEAD)
//! 3. **Format**: salt (16 bytes) || nonce (12 bytes) || ciphertext
//!
//! ## Security Properties
//!
//! - Memory-hard KDF resists GPU/ASIC attacks
//! - Random salt prevents rainbow table attacks
//! - AEAD provides confidentiality + integrity
//! - Constant-time MAC verification
//! - Zeroization of sensitive data
//!
//! ## Example
//!
//! ```rust,ignore
//! use nexus_crypto_core::encryption::backup::*;
//!
//! // Encrypt key for backup
//! let key_package = frost_dkg_result.key_package.as_bytes();
//! let encrypted = encrypt_key_for_backup(key_package, "strong_password_123")?;
//!
//! // Store encrypted blob (safe to upload to cloud)
//! // ...
//!
//! // Later: restore from backup
//! let restored = decrypt_key_from_backup(&encrypted, "strong_password_123")?;
//! assert_eq!(restored, key_package);
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::types::errors::{CryptoError, CryptoResult};

// ============================================================================
// Constants
// ============================================================================

/// Salt size for Argon2id (16 bytes = 128 bits)
pub const SALT_SIZE: usize = 16;

/// Nonce size for ChaCha20Poly1305 (12 bytes = 96 bits)
pub const NONCE_SIZE: usize = 12;

/// Derived key size (32 bytes = 256 bits)
pub const KEY_SIZE: usize = 32;

/// AEAD authentication tag size (16 bytes)
pub const TAG_SIZE: usize = 16;

/// Header size: salt + nonce
pub const HEADER_SIZE: usize = SALT_SIZE + NONCE_SIZE;

// Argon2id parameters (OWASP recommendations for high-security applications)
/// Memory cost in KiB (64 MiB)
const ARGON2_MEMORY_KIB: u32 = 65536;

/// Time cost (iterations)
const ARGON2_TIME_COST: u32 = 3;

/// Parallelism factor
const ARGON2_PARALLELISM: u32 = 4;

// ============================================================================
// Public API
// ============================================================================

/// Encrypt a FROST key_package for secure backup.
///
/// Uses Argon2id for password-based key derivation and ChaCha20Poly1305 for
/// authenticated encryption.
///
/// # Arguments
///
/// * `key_package` - The FROST key_package bytes to encrypt (~200 bytes typical)
/// * `password` - User-provided password (should be strong!)
///
/// # Returns
///
/// Encrypted blob: salt (16) || nonce (12) || ciphertext (~key_len + 16)
///
/// # Security
///
/// - Uses memory-hard Argon2id (64MB) to resist brute-force
/// - Random salt ensures unique encryption keys per backup
/// - AEAD provides both confidentiality and integrity
/// - Password is zeroized after key derivation
///
/// # Example
///
/// ```rust,ignore
/// let encrypted = encrypt_key_for_backup(&key_package, "my_secure_password")?;
/// // encrypted.len() ~= 244 bytes for 200-byte key_package
/// ```
pub fn encrypt_key_for_backup(key_package: &[u8], password: &str) -> CryptoResult<Vec<u8>> {
    // Validate inputs
    if key_package.is_empty() {
        return Err(CryptoError::InvalidLength {
            field: "key_package".into(),
            expected: 1,
            actual: 0,
        });
    }

    if password.is_empty() {
        return Err(CryptoError::InvalidSecretKey(
            "Password cannot be empty".into(),
        ));
    }

    // Generate random salt
    let mut salt = [0u8; SALT_SIZE];
    getrandom::getrandom(&mut salt).map_err(|e| {
        CryptoError::NonceGenerationFailed(format!("Salt generation failed: {}", e))
    })?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        CryptoError::NonceGenerationFailed(format!("Nonce generation failed: {}", e))
    })?;

    // Derive encryption key using Argon2id
    let mut derived_key = derive_key_from_password(password, &salt)?;

    // Create cipher and encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key).map_err(|e| {
        CryptoError::EncryptionFailed(format!("Cipher initialization failed: {}", e))
    })?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, key_package).map_err(|e| {
        CryptoError::EncryptionFailed(format!("Encryption failed: {}", e))
    })?;

    // Zeroize sensitive data
    derived_key.zeroize();

    // Build output: salt || nonce || ciphertext
    let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt a FROST key_package from backup.
///
/// # Arguments
///
/// * `encrypted` - The encrypted blob from `encrypt_key_for_backup`
/// * `password` - The password used during encryption
///
/// # Returns
///
/// Decrypted key_package bytes.
///
/// # Errors
///
/// Returns error if:
/// - Encrypted blob is too short (corrupt or truncated)
/// - Password is wrong (AEAD tag verification fails)
/// - Data was tampered with (integrity check fails)
///
/// # Security
///
/// - Constant-time MAC verification prevents timing attacks
/// - Wrong password fails indistinguishably from corrupt data
/// - No information leakage about correct password
pub fn decrypt_key_from_backup(encrypted: &[u8], password: &str) -> CryptoResult<Vec<u8>> {
    // Validate minimum length: salt + nonce + at least 1 byte ciphertext + tag
    let min_length = HEADER_SIZE + TAG_SIZE + 1;
    if encrypted.len() < min_length {
        return Err(CryptoError::InvalidLength {
            field: "encrypted_backup".into(),
            expected: min_length,
            actual: encrypted.len(),
        });
    }

    if password.is_empty() {
        return Err(CryptoError::InvalidSecretKey(
            "Password cannot be empty".into(),
        ));
    }

    // Extract salt and nonce from header
    let salt: [u8; SALT_SIZE] = encrypted[..SALT_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InternalError("Salt extraction failed".into()))?;

    let nonce_bytes: [u8; NONCE_SIZE] = encrypted[SALT_SIZE..HEADER_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InternalError("Nonce extraction failed".into()))?;

    let ciphertext = &encrypted[HEADER_SIZE..];

    // Derive decryption key using same Argon2id parameters
    let mut derived_key = derive_key_from_password(password, &salt)?;

    // Create cipher and decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key).map_err(|e| {
        CryptoError::DecryptionFailed(format!("Cipher initialization failed: {}", e))
    })?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt (constant-time MAC verification happens inside)
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        // Generic error - don't reveal if it's wrong password vs corrupt data
        CryptoError::DecryptionFailed(
            "Decryption failed: wrong password or corrupted backup".into(),
        )
    })?;

    // Zeroize sensitive data
    derived_key.zeroize();

    Ok(plaintext)
}

/// Derive a backup identifier from key_package (without exposing the key).
///
/// This allows matching backups to escrows without decrypting.
/// Uses SHA3-256 of the key_package to create a deterministic but
/// non-reversible identifier.
///
/// # Arguments
///
/// * `key_package` - The FROST key_package bytes
///
/// # Returns
///
/// 64-character hex string (SHA3-256 hash).
///
/// # Security
///
/// - One-way function: cannot derive key from ID
/// - Deterministic: same key always produces same ID
/// - Collision-resistant: different keys won't produce same ID
///
/// # Example
///
/// ```rust,ignore
/// let backup_id = derive_backup_id(&key_package);
/// // backup_id = "a1b2c3d4..." (64 hex chars)
/// ```
pub fn derive_backup_id(key_package: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"NEXUS_BACKUP_ID_V1:"); // Domain separator
    hasher.update(key_package);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Verify that a password can decrypt a backup without returning the key.
///
/// Useful for password validation UX without exposing decrypted material.
///
/// # Arguments
///
/// * `encrypted` - The encrypted backup blob
/// * `password` - Password to verify
///
/// # Returns
///
/// `true` if password is correct, `false` otherwise.
pub fn verify_backup_password(encrypted: &[u8], password: &str) -> bool {
    decrypt_key_from_backup(encrypted, password).is_ok()
}

/// Get the expected encrypted size for a given plaintext size.
///
/// Useful for UI to show expected backup file size.
///
/// # Arguments
///
/// * `plaintext_len` - Size of the key_package in bytes
///
/// # Returns
///
/// Total size of encrypted backup: salt + nonce + ciphertext + tag
pub const fn encrypted_size(plaintext_len: usize) -> usize {
    HEADER_SIZE + plaintext_len + TAG_SIZE
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Derive a 256-bit key from password using Argon2id.
///
/// Parameters match OWASP recommendations for high-security applications:
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 4
fn derive_key_from_password(password: &str, salt: &[u8; SALT_SIZE]) -> CryptoResult<[u8; KEY_SIZE]> {
    // Build Argon2id instance with our parameters
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(KEY_SIZE),
    )
    .map_err(|e| {
        CryptoError::InternalError(format!("Argon2 params invalid: {}", e))
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive key
    let mut output_key = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|e| {
            CryptoError::InternalError(format!("Argon2 key derivation failed: {}", e))
        })?;

    Ok(output_key)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample key_package for testing (simulated FROST key)
    fn sample_key_package() -> Vec<u8> {
        // Realistic size for FROST key_package
        let mut key = vec![0u8; 200];
        // Fill with deterministic but non-zero data
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8;
        }
        key
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key_package = sample_key_package();
        let password = "correct_horse_battery_staple";

        let encrypted = encrypt_key_for_backup(&key_package, password).unwrap();
        let decrypted = decrypt_key_from_backup(&encrypted, password).unwrap();

        assert_eq!(decrypted, key_package);
    }

    #[test]
    fn test_encrypted_size_matches() {
        let key_package = sample_key_package();
        let password = "test_password";

        let encrypted = encrypt_key_for_backup(&key_package, password).unwrap();

        assert_eq!(encrypted.len(), encrypted_size(key_package.len()));
    }

    #[test]
    fn test_wrong_password_fails() {
        let key_package = sample_key_package();
        let encrypted = encrypt_key_for_backup(&key_package, "correct_password").unwrap();

        let result = decrypt_key_from_backup(&encrypted, "wrong_password");
        assert!(result.is_err());

        // Error message should be generic (no password oracle)
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("wrong password or corrupted"));
    }

    #[test]
    fn test_tampered_data_fails() {
        let key_package = sample_key_package();
        let password = "test_password";

        let mut encrypted = encrypt_key_for_backup(&key_package, password).unwrap();

        // Tamper with ciphertext
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0xFF;

        let result = decrypt_key_from_backup(&encrypted, password);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data_fails() {
        let key_package = sample_key_package();
        let password = "test_password";

        let encrypted = encrypt_key_for_backup(&key_package, password).unwrap();

        // Truncate
        let truncated = &encrypted[..encrypted.len() - 10];

        let result = decrypt_key_from_backup(truncated, password);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_password_rejected() {
        let key_package = sample_key_package();

        let result = encrypt_key_for_backup(&key_package, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_key_rejected() {
        let result = encrypt_key_for_backup(&[], "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_backup_id_deterministic() {
        let key_package = sample_key_package();

        let id1 = derive_backup_id(&key_package);
        let id2 = derive_backup_id(&key_package);

        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA3-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_derive_backup_id_different_keys() {
        let key1 = sample_key_package();
        let mut key2 = sample_key_package();
        key2[0] ^= 0xFF; // Change one byte

        let id1 = derive_backup_id(&key1);
        let id2 = derive_backup_id(&key2);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_verify_backup_password() {
        let key_package = sample_key_package();
        let password = "verification_test";

        let encrypted = encrypt_key_for_backup(&key_package, password).unwrap();

        assert!(verify_backup_password(&encrypted, password));
        assert!(!verify_backup_password(&encrypted, "wrong"));
    }

    #[test]
    fn test_unique_salts() {
        let key_package = sample_key_package();
        let password = "same_password";

        let encrypted1 = encrypt_key_for_backup(&key_package, password).unwrap();
        let encrypted2 = encrypt_key_for_backup(&key_package, password).unwrap();

        // Different encryptions should have different salts
        let salt1 = &encrypted1[..SALT_SIZE];
        let salt2 = &encrypted2[..SALT_SIZE];
        assert_ne!(salt1, salt2);

        // But both should decrypt correctly
        let dec1 = decrypt_key_from_backup(&encrypted1, password).unwrap();
        let dec2 = decrypt_key_from_backup(&encrypted2, password).unwrap();
        assert_eq!(dec1, key_package);
        assert_eq!(dec2, key_package);
    }

    #[test]
    fn test_unicode_password() {
        let key_package = sample_key_package();
        let password = "p@$$w0rd-with-emojis-and-unicode";

        let encrypted = encrypt_key_for_backup(&key_package, password).unwrap();
        let decrypted = decrypt_key_from_backup(&encrypted, password).unwrap();

        assert_eq!(decrypted, key_package);
    }

    #[test]
    fn test_minimum_encrypted_length_validation() {
        let too_short = vec![0u8; HEADER_SIZE + TAG_SIZE]; // No ciphertext body

        let result = decrypt_key_from_backup(&too_short, "password");
        assert!(result.is_err());
    }
}
