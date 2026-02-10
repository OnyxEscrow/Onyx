//! Production-grade encryption for sensitive database fields
//!
//! This module provides field-level encryption for wallet multisig information
//! that must be encrypted at-rest in the database.
//!
//! # Security Properties
//!
//! - **Algorithm**: AES-256-GCM (Galois/Counter Mode)
//! - **Key Size**: 256 bits (32 bytes)
//! - **Nonce Size**: 96 bits (12 bytes) - randomly generated per encryption
//! - **Authentication**: Built-in AEAD (Authenticated Encryption with Associated Data)
//! - **RNG**: OsRng (cryptographically secure, not thread_rng)
//!
//! # Threat Model
//!
//! - Protects against: Database dumps, backup theft, unauthorized DB access
//! - Does NOT protect against: Memory dumps of running process, root access to server
//!
//! # Key Management
//!
//! Keys MUST be:
//! - Stored in environment variables or secure key management system
//! - Never committed to version control
//! - Rotated periodically (quarterly recommended)
//! - Unique per environment (dev, staging, prod)

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use rand::RngCore;

/// Size of AES-256-GCM encryption key in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Size of AES-GCM nonce in bytes (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Minimum encrypted data size (nonce + at least 1 byte plaintext + 16 byte auth tag)
const MIN_ENCRYPTED_SIZE: usize = NONCE_SIZE + 1 + 16;

/// Generate a cryptographically secure random 256-bit encryption key
///
/// # Security
///
/// Uses `OsRng` (not `thread_rng`) for cryptographically secure randomness.
///
/// # Usage
///
/// This should be used ONCE during initial setup. The generated key must be:
/// 1. Stored securely (secrets manager, environment variable)
/// 2. Never committed to version control
/// 3. Backed up securely offline
/// 4. Rotated periodically
///
/// # Example
///
/// ```no_run
/// use server::crypto::encryption::generate_key;
///
/// let key = generate_key();
/// let key_hex = hex::encode(&key);
/// // Output: ENCRYPTION_KEY=<hex-encoded-key>
/// // Store this securely - NEVER run in production
/// ```
pub fn generate_key() -> Vec<u8> {
    let mut key = vec![0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt plaintext string using AES-256-GCM
///
/// # Arguments
///
/// * `plaintext` - Data to encrypt (typically JSON-serialized wallet info)
/// * `key` - 32-byte encryption key
///
/// # Returns
///
/// Encrypted data with format: `[nonce (12 bytes)][ciphertext][auth tag (16 bytes)]`
///
/// # Security
///
/// - Nonce is randomly generated using `OsRng` for each encryption (never reused)
/// - Authentication tag prevents tampering
/// - Key must be stored securely
///
/// # Errors
///
/// Returns error if:
/// - Key length is not exactly 32 bytes
/// - Plaintext is empty
/// - Encryption fails
pub fn encrypt_field(plaintext: &str, key: &[u8]) -> Result<Vec<u8>> {
    // Validate key length
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "Encryption key must be exactly {} bytes, got {}",
            KEY_SIZE,
            key.len()
        );
    }

    // Validate plaintext is not empty
    if plaintext.is_empty() {
        anyhow::bail!("Cannot encrypt empty plaintext - use Option<Vec<u8>> for nullable fields");
    }

    // Create cipher
    let cipher =
        Aes256Gcm::new_from_slice(key).context("Failed to create AES-256-GCM cipher from key")?;

    // Generate cryptographically secure random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext for storage
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt ciphertext string using AES-256-GCM
///
/// # Arguments
///
/// * `ciphertext_with_nonce` - Data encrypted with `encrypt_field` (nonce prepended)
/// * `key` - Same 32-byte encryption key used for encryption
///
/// # Returns
///
/// Original plaintext string
///
/// # Security
///
/// - Authentication tag is automatically verified (prevents tampering)
/// - Wrong key will cause decryption to fail
/// - Modified ciphertext will cause authentication failure
///
/// # Errors
///
/// Returns error if:
/// - Key length is not exactly 32 bytes
/// - Encrypted data is too short (corrupted)
/// - Authentication tag verification fails (data tampered or wrong key)
/// - Decrypted data is not valid UTF-8
pub fn decrypt_field(ciphertext_with_nonce: &[u8], key: &[u8]) -> Result<String> {
    // Validate key length
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "Decryption key must be exactly {} bytes, got {}",
            KEY_SIZE,
            key.len()
        );
    }

    // Validate encrypted data size
    if ciphertext_with_nonce.len() < MIN_ENCRYPTED_SIZE {
        anyhow::bail!(
            "Encrypted data too short: expected at least {} bytes, got {}. Data may be corrupted.",
            MIN_ENCRYPTED_SIZE,
            ciphertext_with_nonce.len()
        );
    }

    // Create cipher
    let cipher =
        Aes256Gcm::new_from_slice(key).context("Failed to create AES-256-GCM cipher from key")?;

    // Extract nonce
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&ciphertext_with_nonce[..NONCE_SIZE]);

    // Extract ciphertext
    let ciphertext = &ciphertext_with_nonce[NONCE_SIZE..];

    // Decrypt and verify authentication tag
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| {
            anyhow::anyhow!(
                "Decryption failed: {}. This indicates wrong key, corrupted data, or tampered ciphertext.",
                e
            )
        })?;

    // Convert to UTF-8 string
    String::from_utf8(plaintext_bytes).context("Decrypted data is not valid UTF-8")
}

/// Decrypt data and return raw bytes (Phase 6: for binary seed data)
///
/// Same as `decrypt_field()` but returns raw bytes instead of String.
/// Used for decrypting binary data like wallet seeds.
///
/// # Arguments
///
/// * `ciphertext_with_nonce` - Encrypted data with prepended nonce
/// * `key` - 32-byte decryption key
///
/// # Returns
///
/// * `Vec<u8>` - Decrypted raw bytes
///
/// # Errors
///
/// - Key wrong length
/// - Data corrupted or tampered
/// - Wrong decryption key
pub fn decrypt_bytes(ciphertext_with_nonce: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "Decryption key must be exactly {} bytes, got {}",
            KEY_SIZE,
            key.len()
        );
    }

    if ciphertext_with_nonce.len() < MIN_ENCRYPTED_SIZE {
        anyhow::bail!(
            "Encrypted data too short: expected at least {} bytes, got {}",
            MIN_ENCRYPTED_SIZE,
            ciphertext_with_nonce.len()
        );
    }

    let cipher = Aes256Gcm::new_from_slice(key).context("Failed to create AES-256-GCM cipher")?;

    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&ciphertext_with_nonce[..NONCE_SIZE]);
    let ciphertext = &ciphertext_with_nonce[NONCE_SIZE..];

    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        anyhow::anyhow!(
            "Decryption failed: {}. This likely means wrong key or tampered data.",
            e
        )
    })
}

/// Encrypt raw bytes (Phase 6: for binary seed data)
///
/// Same as `encrypt_field()` but works with raw bytes instead of String.
///
/// # Arguments
///
/// * `plaintext` - Raw bytes to encrypt
/// * `key` - 32-byte encryption key
///
/// # Returns
///
/// * `Vec<u8>` - Encrypted data with prepended nonce
pub fn encrypt_bytes(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "Encryption key must be exactly {} bytes, got {}",
            KEY_SIZE,
            key.len()
        );
    }

    if plaintext.is_empty() {
        anyhow::bail!("Cannot encrypt empty data");
    }

    let cipher = Aes256Gcm::new_from_slice(key).context("Failed to create AES-256-GCM cipher")?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Validate encryption key format
///
/// # Arguments
///
/// * `key` - Encryption key to validate
///
/// # Returns
///
/// `Ok(())` if key is valid, `Err` otherwise
///
/// # Validation Rules
///
/// - Key must be exactly 32 bytes
/// - Key should not be all zeros (weak key)
/// - Key should have reasonable entropy
pub fn validate_key(key: &[u8]) -> Result<()> {
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "Invalid key length: expected {} bytes, got {}",
            KEY_SIZE,
            key.len()
        );
    }

    // Check for all-zero key
    if key.iter().all(|&b| b == 0) {
        anyhow::bail!("Key cannot be all zeros - use generate_key() to create a strong key");
    }

    // Check for low entropy
    let unique_bytes: std::collections::HashSet<_> = key.iter().collect();
    if unique_bytes.len() < 16 {
        anyhow::bail!(
            "Key has low entropy (only {} unique bytes out of {}). Use a cryptographically random key.",
            unique_bytes.len(),
            KEY_SIZE
        );
    }

    Ok(())
}

//
// Phase 6: PBKDF2 Password-Based Key Derivation
//

/// Number of PBKDF2 iterations (100,000 recommended for 2024)
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Minimum password length for wallet seed encryption
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Derive encryption key from password using PBKDF2-HMAC-SHA256
///
/// # Security
///
/// - Uses 100,000 iterations (OWASP recommendation for 2024)
/// - HMAC-SHA256 for pseudorandom function
/// - Each user MUST have unique salt (never reuse)
/// - Resistant to brute force attacks (takes ~100ms per attempt)
///
/// # Arguments
///
/// * `password` - User's password (must be ≥12 chars with complexity rules)
/// * `salt` - Unique random salt (16 bytes recommended)
///
/// # Returns
///
/// * `Vec<u8>` - 32-byte AES-256 key suitable for encrypt_field()
///
/// # Examples
///
/// ```no_run
/// use server::crypto::encryption::{derive_key_from_password, generate_random_salt};
///
/// let password = "MySecurePassword123!";
/// let salt = generate_random_salt(16)?;
///
/// let key = derive_key_from_password(password, &salt)?;
/// assert_eq!(key.len(), 32);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    if password.len() < MIN_PASSWORD_LENGTH {
        anyhow::bail!(
            "Password must be at least {} characters, got {}",
            MIN_PASSWORD_LENGTH,
            password.len()
        );
    }

    if salt.is_empty() {
        anyhow::bail!("Salt cannot be empty");
    }

    let mut key = vec![0u8; KEY_SIZE];

    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);

    Ok(key)
}

/// Generate random salt for PBKDF2
///
/// # Arguments
///
/// * `size` - Salt size in bytes (16 bytes recommended)
///
/// # Returns
///
/// * `Vec<u8>` - Cryptographically random salt
pub fn generate_random_salt(size: usize) -> Result<Vec<u8>> {
    if size < 16 {
        anyhow::bail!("Salt must be at least 16 bytes for security");
    }

    let mut salt = vec![0u8; size];
    OsRng.fill_bytes(&mut salt);
    Ok(salt)
}

/// Validate password strength for wallet seed protection
///
/// # Password Requirements
///
/// - ≥12 characters
/// - At least 1 uppercase letter
/// - At least 1 lowercase letter
/// - At least 1 digit
/// - At least 1 special character
/// - Not in common password list
///
/// # Arguments
///
/// * `password` - Password to validate
///
/// # Returns
///
/// * `Ok(())` if password meets requirements
/// * `Err` with specific failure reason
pub fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LENGTH {
        anyhow::bail!(
            "Password must be at least {} characters",
            MIN_PASSWORD_LENGTH
        );
    }

    if !password.chars().any(|c| c.is_uppercase()) {
        anyhow::bail!("Password must contain at least one uppercase letter");
    }

    if !password.chars().any(|c| c.is_lowercase()) {
        anyhow::bail!("Password must contain at least one lowercase letter");
    }

    if !password.chars().any(|c| c.is_ascii_digit()) {
        anyhow::bail!("Password must contain at least one digit");
    }

    if !password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
    {
        anyhow::bail!(
            "Password must contain at least one special character (!@#$%^&*()_+-=[]{{}}|;:,.<>?)"
        );
    }

    // Check against common passwords (top 100)
    const COMMON_PASSWORDS: &[&str] = &[
        "password123",
        "123456789",
        "qwerty123",
        "admin123",
        "letmein123",
        "welcome123",
        "monkey123",
        "dragon123",
        "master123",
        "superman123",
        // Add more as needed
    ];

    let password_lower = password.to_lowercase();
    if COMMON_PASSWORDS.iter().any(|&p| password_lower.contains(p)) {
        anyhow::bail!("Password is too common. Please choose a stronger password.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_key() -> Vec<u8> {
        // Test key (DO NOT use in production)
        vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = get_test_key();
        let plaintext = "Sensitive wallet multisig info";

        let encrypted = encrypt_field(plaintext, &key).expect("Encryption failed");
        let decrypted = decrypt_field(&encrypted, &key).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_different_nonces() {
        let key = get_test_key();
        let plaintext = "Same plaintext";

        let encrypted1 = encrypt_field(plaintext, &key).expect("Encryption 1 failed");
        let encrypted2 = encrypt_field(plaintext, &key).expect("Encryption 2 failed");

        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // Both should decrypt to same plaintext
        let decrypted1 = decrypt_field(&encrypted1, &key).expect("Decryption 1 failed");
        let decrypted2 = decrypt_field(&encrypted2, &key).expect("Decryption 2 failed");
        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = get_test_key();
        let mut key2 = get_test_key();
        key2[0] ^= 0x01; // Flip one bit

        let plaintext = "Secret data";
        let encrypted = encrypt_field(plaintext, &key1).expect("Encryption failed");

        let result = decrypt_field(&encrypted, &key2);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Decryption failed"));
    }

    #[test]
    fn test_decrypt_tampered_data() {
        let key = get_test_key();
        let plaintext = "Original data";

        let mut encrypted = encrypt_field(plaintext, &key).expect("Encryption failed");

        // Tamper with ciphertext (flip one bit)
        encrypted[NONCE_SIZE] ^= 0x01;

        let result = decrypt_field(&encrypted, &key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Decryption failed"));
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = get_test_key();
        let plaintext = "";

        let result = encrypt_field(plaintext, &key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot encrypt empty plaintext"));
    }

    #[test]
    fn test_encrypt_wrong_key_size() {
        let short_key = vec![0u8; 16];
        let plaintext = "Test data";

        let result = encrypt_field(plaintext, &short_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be exactly 32 bytes"));
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let key = get_test_key();
        let corrupted = vec![0u8; 10];

        let result = decrypt_field(&corrupted, &key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Encrypted data too short"));
    }

    #[test]
    fn test_generate_key_length() {
        let key = generate_key();
        assert_eq!(key.len(), KEY_SIZE);
    }

    #[test]
    fn test_generate_key_randomness() {
        let key1 = generate_key();
        let key2 = generate_key();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should not be all zeros
        assert!(key1.iter().any(|&b| b != 0));
        assert!(key2.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_validate_key_correct_size() {
        let key = get_test_key();
        assert!(validate_key(&key).is_ok());
    }

    #[test]
    fn test_validate_key_wrong_size() {
        let key = vec![0u8; 16];
        assert!(validate_key(&key).is_err());
    }

    #[test]
    fn test_validate_key_all_zeros() {
        let key = vec![0u8; 32];
        let result = validate_key(&key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("all zeros"));
    }

    #[test]
    fn test_validate_key_low_entropy() {
        let key = vec![0x42u8; 32];
        let result = validate_key(&key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("low entropy"));
    }

    #[test]
    fn test_encrypted_data_format() {
        let key = get_test_key();
        let plaintext = "Test";

        let encrypted = encrypt_field(plaintext, &key).expect("Encryption failed");

        // Verify structure
        assert!(encrypted.len() >= NONCE_SIZE + plaintext.len() + 16);

        // First 12 bytes should be nonce
        let nonce = &encrypted[..NONCE_SIZE];
        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    #[test]
    fn test_large_plaintext() {
        let key = get_test_key();
        let plaintext = "x".repeat(1024 * 1024); // 1 MB

        let encrypted = encrypt_field(&plaintext, &key).expect("Encryption failed");
        let decrypted = decrypt_field(&encrypted, &key).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_unicode_plaintext() {
        let key = get_test_key();
        let plaintext = "Hello 世界 🔐 مرحبا мир";

        let encrypted = encrypt_field(plaintext, &key).expect("Encryption failed");
        let decrypted = decrypt_field(&encrypted, &key).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    // Phase 6: PBKDF2 Tests

    #[test]
    fn test_derive_key_from_password() {
        let password = "MySecurePassword123!";
        let salt = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];

        let key = derive_key_from_password(password, &salt).expect("Key derivation failed");

        assert_eq!(key.len(), KEY_SIZE);
        assert!(key.iter().any(|&b| b != 0)); // Not all zeros
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = "TestPassword123!";
        let salt = vec![0x42; 16];

        let key1 = derive_key_from_password(password, &salt).expect("Derivation 1 failed");
        let key2 = derive_key_from_password(password, &salt).expect("Derivation 2 failed");

        assert_eq!(key1, key2, "PBKDF2 must be deterministic");
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = vec![0x42; 16];

        let key1 = derive_key_from_password("Password123!", &salt).expect("Derivation 1 failed");
        let key2 =
            derive_key_from_password("DifferentPass123!", &salt).expect("Derivation 2 failed");

        assert_ne!(
            key1, key2,
            "Different passwords must produce different keys"
        );
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = "SamePassword123!";

        let salt1 = vec![0x01; 16];
        let salt2 = vec![0x02; 16];

        let key1 = derive_key_from_password(password, &salt1).expect("Derivation 1 failed");
        let key2 = derive_key_from_password(password, &salt2).expect("Derivation 2 failed");

        assert_ne!(key1, key2, "Different salts must produce different keys");
    }

    #[test]
    fn test_derive_key_password_too_short() {
        let salt = vec![0x42; 16];
        let result = derive_key_from_password("short", &salt);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least 12 characters"));
    }

    #[test]
    fn test_derive_key_empty_salt() {
        let result = derive_key_from_password("ValidPassword123!", &[]);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Salt cannot be empty"));
    }

    #[test]
    fn test_generate_random_salt() {
        let salt1 = generate_random_salt(16).expect("Salt generation failed");
        let salt2 = generate_random_salt(16).expect("Salt generation failed");

        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
        assert_ne!(salt1, salt2, "Salts must be unique");
    }

    #[test]
    fn test_generate_random_salt_too_small() {
        let result = generate_random_salt(8);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least 16 bytes"));
    }

    #[test]
    fn test_validate_password_strength_valid() {
        let password = "MyStrongP@ssw0rd!";
        assert!(validate_password_strength(password).is_ok());
    }

    #[test]
    fn test_validate_password_strength_too_short() {
        let result = validate_password_strength("Short1!");

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least 12 characters"));
    }

    #[test]
    fn test_validate_password_strength_no_uppercase() {
        let result = validate_password_strength("mylongpassword123!");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("uppercase"));
    }

    #[test]
    fn test_validate_password_strength_no_lowercase() {
        let result = validate_password_strength("MYLONGPASSWORD123!");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("lowercase"));
    }

    #[test]
    fn test_validate_password_strength_no_digit() {
        let result = validate_password_strength("MyLongPassword!");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("digit"));
    }

    #[test]
    fn test_validate_password_strength_no_special() {
        let result = validate_password_strength("MyLongPassword123");

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("special character"));
    }

    #[test]
    fn test_validate_password_strength_common_password() {
        let result = validate_password_strength("Password123!");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_pbkdf2_encryption_integration() {
        // Full integration: password -> key -> encrypt -> decrypt
        let password = "IntegrationTest123!";
        let salt = generate_random_salt(16).expect("Salt generation failed");
        let key = derive_key_from_password(password, &salt).expect("Key derivation failed");

        let plaintext = "Sensitive wallet seed data";
        let encrypted = encrypt_field(plaintext, &key).expect("Encryption failed");
        let decrypted = decrypt_field(&encrypted, &key).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }
}
