//! Arbiter Key Vault - Encrypted storage for arbiter FROST key packages
//!
//! Uses Argon2id for key derivation and ChaCha20Poly1305 for encryption.
//! Key packages are stored in Redis with a 30-day TTL.

use anyhow::{Context, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use redis::AsyncCommands;
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info};

use crate::redis_pool::{get_conn, RedisPool};

/// Redis key prefix for arbiter key packages
const KEY_PREFIX: &str = "nexus:arbiter_vault:";

/// Redis key prefix for DKG round secrets (temporary)
const DKG_R1_PREFIX: &str = "nexus:arbiter_dkg:r1:";
const DKG_R2_PREFIX: &str = "nexus:arbiter_dkg:r2:";

/// TTL for stored key packages (30 days = escrow lifetime)
const KEY_TTL_SECS: i64 = 30 * 24 * 60 * 60; // 2,592,000 seconds

/// TTL for DKG secrets (1 hour - should complete within minutes)
const DKG_SECRET_TTL_SECS: i64 = 60 * 60;

/// Arbiter Key Vault for secure FROST key_package storage
#[derive(Clone)]
pub struct ArbiterKeyVault {
    redis_pool: RedisPool,
    encryption_key: [u8; 32],
}

impl ArbiterKeyVault {
    /// Create a new ArbiterKeyVault
    ///
    /// # Arguments
    /// * `redis_pool` - Redis connection pool
    /// * `master_password` - Master password for key derivation
    ///
    /// # Key Derivation
    /// Uses Argon2id with default parameters to derive a 256-bit encryption key
    /// from the master password. The salt is derived from a fixed application ID
    /// to ensure deterministic key derivation across restarts.
    pub fn new(redis_pool: RedisPool, master_password: SecretString) -> Result<Self> {
        // Derive encryption key from master password using Argon2id
        let encryption_key = Self::derive_key(master_password.expose_secret())?;

        info!("ArbiterKeyVault initialized");
        Ok(Self {
            redis_pool,
            encryption_key,
        })
    }

    /// Derive a 256-bit encryption key from the master password
    ///
    /// Uses Argon2id with a fixed salt based on application ID for determinism.
    fn derive_key(password: &str) -> Result<[u8; 32]> {
        // Use a fixed salt for deterministic key derivation
        // This is acceptable because the password provides the entropy
        let salt =
            SaltString::encode_b64(b"NEXUS_ARBITER_VAULT_V1").context("Failed to create salt")?;

        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .context("Failed to hash password with Argon2id")?;

        // Extract the hash output (32 bytes for our key)
        let hash_output = password_hash
            .hash
            .ok_or_else(|| anyhow::anyhow!("Argon2 password hash missing output"))?;

        let hash_bytes = hash_output.as_bytes();
        if hash_bytes.len() < 32 {
            return Err(anyhow::anyhow!(
                "Argon2 hash output too short: {} bytes",
                hash_bytes.len()
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);
        Ok(key)
    }

    /// Store an arbiter's key_package for an escrow
    ///
    /// # Arguments
    /// * `escrow_id` - The escrow ID
    /// * `key_package_hex` - Hex-encoded FROST key_package
    ///
    /// # Encryption
    /// Uses ChaCha20Poly1305 with a random nonce. The nonce is prepended to
    /// the ciphertext for storage.
    pub async fn store_key_package(&self, escrow_id: &str, key_package_hex: &str) -> Result<()> {
        // Encrypt the key package
        let encrypted = self.encrypt(key_package_hex.as_bytes())?;

        // Store in Redis with TTL
        let mut conn = get_conn(&self.redis_pool).await?;
        let key = format!("{KEY_PREFIX}{escrow_id}");

        // Store as base64-encoded ciphertext
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);
        conn.set_ex::<_, _, ()>(&key, &encoded, KEY_TTL_SECS as u64)
            .await
            .context("Failed to store key_package in Redis")?;

        debug!(
            escrow_id = %escrow_id,
            "Key package stored in vault with {}d TTL",
            KEY_TTL_SECS / 86400
        );

        Ok(())
    }

    /// Retrieve an arbiter's key_package for an escrow
    ///
    /// # Arguments
    /// * `escrow_id` - The escrow ID
    ///
    /// # Returns
    /// * `Ok(Some(key_package_hex))` - Decrypted key_package
    /// * `Ok(None)` - Key package not found or expired
    /// * `Err(_)` - Decryption or Redis error
    pub async fn retrieve_key_package(&self, escrow_id: &str) -> Result<Option<String>> {
        let mut conn = get_conn(&self.redis_pool).await?;
        let key = format!("{KEY_PREFIX}{escrow_id}");

        let encoded: Option<String> = conn
            .get(&key)
            .await
            .context("Failed to get key_package from Redis")?;

        match encoded {
            Some(data) => {
                // Decode base64
                let encrypted =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data)
                        .context("Failed to decode base64 ciphertext")?;

                // Decrypt
                let decrypted = self.decrypt(&encrypted)?;
                let key_package_hex =
                    String::from_utf8(decrypted).context("Decrypted data is not valid UTF-8")?;

                debug!(escrow_id = %escrow_id, "Key package retrieved from vault");
                Ok(Some(key_package_hex))
            }
            None => {
                debug!(escrow_id = %escrow_id, "Key package not found in vault");
                Ok(None)
            }
        }
    }

    /// Check if a key_package exists for an escrow
    pub async fn has_key_package(&self, escrow_id: &str) -> Result<bool> {
        let mut conn = get_conn(&self.redis_pool).await?;
        let key = format!("{KEY_PREFIX}{escrow_id}");

        let exists: bool = conn
            .exists(&key)
            .await
            .context("Failed to check key existence in Redis")?;

        Ok(exists)
    }

    /// Delete a key_package for an escrow (cleanup after completion)
    pub async fn delete_key_package(&self, escrow_id: &str) -> Result<()> {
        let mut conn = get_conn(&self.redis_pool).await?;
        let key = format!("{KEY_PREFIX}{escrow_id}");

        conn.del::<_, ()>(&key)
            .await
            .context("Failed to delete key_package from Redis")?;

        info!(escrow_id = %escrow_id, "Key package deleted from vault");
        Ok(())
    }

    /// Encrypt data using ChaCha20Poly1305
    ///
    /// Returns: nonce (12 bytes) || ciphertext (with auth tag)
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to generate nonce: {e}"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create cipher
        let key = Key::from_slice(&self.encryption_key);
        let cipher = ChaCha20Poly1305::new(key);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data using ChaCha20Poly1305
    ///
    /// Expects: nonce (12 bytes) || ciphertext (with auth tag)
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(anyhow::anyhow!("Encrypted data too short"));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Create cipher
        let key = Key::from_slice(&self.encryption_key);
        let cipher = ChaCha20Poly1305::new(key);

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

        Ok(plaintext)
    }

    // =========================================================================
    // DKG Round Secrets (Temporary storage during DKG)
    // =========================================================================

    /// Store arbiter's Round 1 secret during DKG
    ///
    /// This is temporary storage (1 hour TTL) for the secret needed in Round 2.
    pub async fn store_dkg_round1_secret(&self, escrow_id: &str, secret_hex: &str) -> Result<()> {
        let encrypted = self.encrypt(secret_hex.as_bytes())?;
        let mut conn = get_conn(&self.redis_pool).await?;
        let key = format!("{DKG_R1_PREFIX}{escrow_id}");

        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);
        conn.set_ex::<_, _, ()>(&key, &encoded, DKG_SECRET_TTL_SECS as u64)
            .await
            .context("Failed to store R1 secret in Redis")?;

        debug!(escrow_id = %escrow_id, "DKG R1 secret stored");
        Ok(())
    }

    /// Retrieve arbiter's Round 1 secret
    pub async fn get_dkg_round1_secret(&self, escrow_id: &str) -> Result<Option<String>> {
        let mut conn = get_conn(&self.redis_pool).await?;
        let key = format!("{DKG_R1_PREFIX}{escrow_id}");

        let encoded: Option<String> = conn.get(&key).await.context("Failed to get R1 secret")?;

        match encoded {
            Some(data) => {
                let encrypted =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data)
                        .context("Failed to decode R1 secret")?;
                let decrypted = self.decrypt(&encrypted)?;
                let secret_hex =
                    String::from_utf8(decrypted).context("R1 secret is not valid UTF-8")?;
                Ok(Some(secret_hex))
            }
            None => Ok(None),
        }
    }

    /// Store arbiter's Round 2 secret during DKG
    pub async fn store_dkg_round2_secret(&self, escrow_id: &str, secret_hex: &str) -> Result<()> {
        let encrypted = self.encrypt(secret_hex.as_bytes())?;
        let mut conn = get_conn(&self.redis_pool).await?;
        let key = format!("{DKG_R2_PREFIX}{escrow_id}");

        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);
        conn.set_ex::<_, _, ()>(&key, &encoded, DKG_SECRET_TTL_SECS as u64)
            .await
            .context("Failed to store R2 secret in Redis")?;

        debug!(escrow_id = %escrow_id, "DKG R2 secret stored");
        Ok(())
    }

    /// Retrieve arbiter's Round 2 secret
    pub async fn get_dkg_round2_secret(&self, escrow_id: &str) -> Result<Option<String>> {
        let mut conn = get_conn(&self.redis_pool).await?;
        let key = format!("{DKG_R2_PREFIX}{escrow_id}");

        let encoded: Option<String> = conn.get(&key).await.context("Failed to get R2 secret")?;

        match encoded {
            Some(data) => {
                let encrypted =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data)
                        .context("Failed to decode R2 secret")?;
                let decrypted = self.decrypt(&encrypted)?;
                let secret_hex =
                    String::from_utf8(decrypted).context("R2 secret is not valid UTF-8")?;
                Ok(Some(secret_hex))
            }
            None => Ok(None),
        }
    }

    /// Cleanup temporary DKG secrets after finalization
    pub async fn cleanup_dkg_secrets(&self, escrow_id: &str) -> Result<()> {
        let mut conn = get_conn(&self.redis_pool).await?;
        let r1_key = format!("{DKG_R1_PREFIX}{escrow_id}");
        let r2_key = format!("{DKG_R2_PREFIX}{escrow_id}");

        conn.del::<_, ()>(&r1_key).await.ok();
        conn.del::<_, ()>(&r2_key).await.ok();

        debug!(escrow_id = %escrow_id, "DKG secrets cleaned up");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let password = "test_password_for_vault";
        let key = ArbiterKeyVault::derive_key(password).unwrap();
        assert_eq!(key.len(), 32);

        // Verify determinism
        let key2 = ArbiterKeyVault::derive_key(password).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_encryption_roundtrip() {
        let password = "test_password_for_vault";
        let key = ArbiterKeyVault::derive_key(password).unwrap();

        // Create vault-like encryption context
        let vault = ArbiterKeyVaultContext {
            encryption_key: key,
        };

        let plaintext = b"secret_key_package_data_12345";
        let encrypted = vault.encrypt(plaintext).unwrap();
        let decrypted = vault.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    // Helper struct for testing encryption without Redis
    struct ArbiterKeyVaultContext {
        encryption_key: [u8; 32],
    }

    impl ArbiterKeyVaultContext {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            let mut nonce_bytes = [0u8; 12];
            getrandom::getrandom(&mut nonce_bytes).unwrap();
            let nonce = Nonce::from_slice(&nonce_bytes);

            let key = Key::from_slice(&self.encryption_key);
            let cipher = ChaCha20Poly1305::new(key);

            let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();

            let mut result = Vec::with_capacity(12 + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);

            Ok(result)
        }

        fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
            let (nonce_bytes, ciphertext) = data.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);

            let key = Key::from_slice(&self.encryption_key);
            let cipher = ChaCha20Poly1305::new(key);

            let plaintext = cipher.decrypt(nonce, ciphertext).unwrap();
            Ok(plaintext)
        }
    }
}
