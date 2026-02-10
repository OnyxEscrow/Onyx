//! MFA/TOTP Service for Two-Factor Authentication
//!
//! Implements RFC 6238 TOTP (Time-based One-Time Password) with:
//! - Google Authenticator / Authy compatibility
//! - QR code generation for easy setup
//! - Encrypted secret storage
//! - Recovery codes for account recovery
//! - Rate limiting on verification attempts
//!
//! ## Security Features
//! - TOTP secrets encrypted at rest (AES-256-GCM)
//! - Recovery codes hashed with Argon2id
//! - Lockout after 5 failed attempts (15 min)
//! - Audit logging of all MFA events

use anyhow::{anyhow, Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use data_encoding::BASE32;
use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};

/// MFA configuration constants
pub const TOTP_DIGITS: usize = 6;
pub const TOTP_PERIOD: u64 = 30; // seconds
pub const TOTP_ALGORITHM: Algorithm = Algorithm::SHA1; // Google Authenticator standard
pub const RECOVERY_CODE_COUNT: usize = 10;
pub const RECOVERY_CODE_LENGTH: usize = 8;
pub const MAX_FAILED_ATTEMPTS: i32 = 5;
pub const LOCKOUT_DURATION_SECS: i64 = 900; // 15 minutes

/// MFA Service for TOTP operations
pub struct MfaService {
    /// Issuer name shown in authenticator apps
    issuer: String,
    /// Encryption key for TOTP secrets (32 bytes)
    encryption_key: Vec<u8>,
}

impl MfaService {
    /// Create a new MFA service
    ///
    /// # Arguments
    /// * `issuer` - Name shown in authenticator apps (e.g., "NEXUS")
    /// * `encryption_key` - 32-byte key for encrypting TOTP secrets
    pub fn new(issuer: impl Into<String>, encryption_key: Vec<u8>) -> Result<Self> {
        if encryption_key.len() != 32 {
            return Err(anyhow!(
                "Encryption key must be 32 bytes, got {}",
                encryption_key.len()
            ));
        }
        Ok(Self {
            issuer: issuer.into(),
            encryption_key,
        })
    }

    /// Generate a new TOTP secret for a user
    ///
    /// Returns (encrypted_secret, qr_code_data_uri, recovery_codes)
    pub fn setup_mfa(&self, username: &str) -> Result<MfaSetupResult> {
        // Generate random 20-byte secret (160 bits, standard for TOTP)
        let secret = Secret::generate_secret();
        let secret_bytes = secret
            .to_bytes()
            .map_err(|e| anyhow!("Secret error: {}", e))?;

        // Create TOTP instance
        let totp = TOTP::new(
            TOTP_ALGORITHM,
            TOTP_DIGITS,
            1, // skew (allow 1 period before/after)
            TOTP_PERIOD,
            secret_bytes.clone(),
            Some(self.issuer.clone()),
            username.to_string(),
        )
        .map_err(|e| anyhow!("Failed to create TOTP: {}", e))?;

        // Generate QR code as data URI (for display in browser)
        let qr_code = totp
            .get_qr_base64()
            .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;

        // Get the otpauth URL for manual entry
        let otpauth_url = totp.get_url();

        // Encrypt the secret for storage
        let encrypted_secret = self.encrypt_secret(&secret_bytes)?;

        // Generate recovery codes
        let (recovery_codes, hashed_codes) = self.generate_recovery_codes()?;

        Ok(MfaSetupResult {
            encrypted_secret,
            qr_code_data_uri: format!("data:image/png;base64,{}", qr_code),
            otpauth_url,
            recovery_codes,
            hashed_recovery_codes: hashed_codes,
            secret_base32: BASE32.encode(&secret_bytes), // For manual entry
        })
    }

    /// Verify a TOTP code
    ///
    /// Returns true if the code is valid for the given secret
    pub fn verify_totp(&self, encrypted_secret: &[u8], code: &str) -> Result<bool> {
        // Validate code format
        if code.len() != TOTP_DIGITS || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }

        // Decrypt the secret
        let secret_bytes = self.decrypt_secret(encrypted_secret)?;

        // Create TOTP instance
        let totp = TOTP::new(
            TOTP_ALGORITHM,
            TOTP_DIGITS,
            1, // skew
            TOTP_PERIOD,
            secret_bytes,
            None,
            String::new(),
        )
        .map_err(|e| anyhow!("Failed to create TOTP: {}", e))?;

        // Verify the code
        Ok(totp.check_current(code).unwrap_or(false))
    }

    /// Verify a recovery code
    ///
    /// Returns the index of the used code if valid (for marking as used)
    pub fn verify_recovery_code(
        &self,
        hashed_codes: &[String],
        provided_code: &str,
    ) -> Result<Option<usize>> {
        let argon2 = Argon2::default();

        // Normalize code (remove dashes, uppercase)
        let normalized = provided_code
            .replace('-', "")
            .replace(' ', "")
            .to_uppercase();

        for (i, hashed) in hashed_codes.iter().enumerate() {
            if hashed.is_empty() {
                continue; // Already used
            }

            if let Ok(parsed_hash) = PasswordHash::new(hashed) {
                if argon2
                    .verify_password(normalized.as_bytes(), &parsed_hash)
                    .is_ok()
                {
                    return Ok(Some(i));
                }
            }
        }

        Ok(None)
    }

    /// Generate recovery codes
    ///
    /// Returns (plaintext_codes, hashed_codes)
    fn generate_recovery_codes(&self) -> Result<(Vec<String>, Vec<String>)> {
        let mut rng = rand::thread_rng();
        let argon2 = Argon2::default();

        let mut plaintext_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        let mut hashed_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);

        for _ in 0..RECOVERY_CODE_COUNT {
            // Generate random alphanumeric code
            let code: String = (0..RECOVERY_CODE_LENGTH)
                .map(|_| {
                    let idx = rng.gen_range(0..36);
                    if idx < 10 {
                        (b'0' + idx) as char
                    } else {
                        (b'A' + idx - 10) as char
                    }
                })
                .collect();

            // Format with dash for readability (XXXX-XXXX)
            let formatted = format!("{}-{}", &code[0..4], &code[4..8]);
            plaintext_codes.push(formatted);

            // Hash for storage
            let salt = SaltString::generate(&mut OsRng);
            let hash = argon2
                .hash_password(code.as_bytes(), &salt)
                .map_err(|e| anyhow!("Failed to hash recovery code: {}", e))?
                .to_string();
            hashed_codes.push(hash);
        }

        Ok((plaintext_codes, hashed_codes))
    }

    /// Encrypt TOTP secret for storage
    fn encrypt_secret(&self, secret: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, secret)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);

        Ok(result)
    }

    /// Decrypt TOTP secret from storage
    fn decrypt_secret(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        if encrypted.len() < 12 {
            return Err(anyhow!("Encrypted secret too short"));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }

    /// Check if user is locked out due to failed attempts
    pub fn is_locked_out(locked_until: Option<&str>) -> bool {
        if let Some(locked) = locked_until {
            if let Ok(lock_time) = chrono::DateTime::parse_from_rfc3339(locked) {
                return Utc::now() < lock_time;
            }
        }
        false
    }

    /// Calculate lockout end time
    pub fn calculate_lockout_time() -> String {
        let lockout_end =
            Utc::now() + chrono::Duration::try_seconds(LOCKOUT_DURATION_SECS).unwrap_or_default();
        lockout_end.to_rfc3339()
    }

    /// Generate current TOTP code (for testing only)
    #[cfg(test)]
    pub fn generate_current_code(&self, encrypted_secret: &[u8]) -> Result<String> {
        let secret_bytes = self.decrypt_secret(encrypted_secret)?;
        let totp = TOTP::new(
            TOTP_ALGORITHM,
            TOTP_DIGITS,
            1,
            TOTP_PERIOD,
            secret_bytes,
            None,
            String::new(),
        )
        .map_err(|e| anyhow!("Failed to create TOTP: {}", e))?;

        Ok(totp.generate_current().unwrap_or_default())
    }
}

/// Result of MFA setup
#[derive(Debug, Clone)]
pub struct MfaSetupResult {
    /// Encrypted TOTP secret (store in DB)
    pub encrypted_secret: Vec<u8>,
    /// QR code as data URI (display to user)
    pub qr_code_data_uri: String,
    /// otpauth:// URL for manual entry
    pub otpauth_url: String,
    /// Plaintext recovery codes (show to user ONCE)
    pub recovery_codes: Vec<String>,
    /// Hashed recovery codes (store in DB)
    pub hashed_recovery_codes: Vec<String>,
    /// Base32 secret for manual entry
    pub secret_base32: String,
}

/// MFA verification result
#[derive(Debug, Clone)]
pub enum MfaVerifyResult {
    /// Code is valid
    Success,
    /// Code is invalid
    InvalidCode,
    /// Recovery code used (index of code)
    RecoveryCodeUsed(usize),
    /// Account is locked
    LockedOut { until: String },
    /// Too many failed attempts, now locked
    NowLocked { until: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0u8; 32] // Test key (don't use in production!)
    }

    #[test]
    fn test_mfa_setup() {
        let service = MfaService::new("NEXUS-Test", test_key()).unwrap();
        let result = service.setup_mfa("testuser").unwrap();

        assert!(!result.encrypted_secret.is_empty());
        assert!(result
            .qr_code_data_uri
            .starts_with("data:image/png;base64,"));
        assert!(result.otpauth_url.contains("otpauth://totp/"));
        assert_eq!(result.recovery_codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(result.hashed_recovery_codes.len(), RECOVERY_CODE_COUNT);
    }

    #[test]
    fn test_totp_verification() {
        let service = MfaService::new("NEXUS-Test", test_key()).unwrap();
        let result = service.setup_mfa("testuser").unwrap();

        // Generate current code
        let code = service
            .generate_current_code(&result.encrypted_secret)
            .unwrap();

        // Verify it
        assert!(service
            .verify_totp(&result.encrypted_secret, &code)
            .unwrap());

        // Invalid code should fail
        assert!(!service
            .verify_totp(&result.encrypted_secret, "000000")
            .unwrap());
    }

    #[test]
    fn test_recovery_code_verification() {
        let service = MfaService::new("NEXUS-Test", test_key()).unwrap();
        let result = service.setup_mfa("testuser").unwrap();

        // First recovery code should verify
        let first_code = &result.recovery_codes[0];
        let verified = service
            .verify_recovery_code(&result.hashed_recovery_codes, first_code)
            .unwrap();
        assert_eq!(verified, Some(0));

        // Code without dashes should also work
        let no_dashes = first_code.replace('-', "");
        let verified = service
            .verify_recovery_code(&result.hashed_recovery_codes, &no_dashes)
            .unwrap();
        assert_eq!(verified, Some(0));

        // Invalid code should not verify
        let verified = service
            .verify_recovery_code(&result.hashed_recovery_codes, "XXXX-YYYY")
            .unwrap();
        assert_eq!(verified, None);
    }

    #[test]
    fn test_lockout_check() {
        // Not locked
        assert!(!MfaService::is_locked_out(None));

        // Future time = locked
        let future = (Utc::now() + chrono::Duration::try_hours(1).unwrap()).to_rfc3339();
        assert!(MfaService::is_locked_out(Some(&future)));

        // Past time = not locked
        let past = (Utc::now() - chrono::Duration::try_hours(1).unwrap()).to_rfc3339();
        assert!(!MfaService::is_locked_out(Some(&past)));
    }
}
