//! Cryptographic validation of multisig_info submissions (TM-003)
//!
//! This module prevents attacks where participants submit malicious or
//! backdoored multisig information by requiring proof-of-possession via
//! challenge-response signatures.
//!
//! # Security Model
//!
//! - Server generates random challenge (nonce + timestamp + escrow_id)
//! - Participant signs challenge with their multisig private key
//! - Server verifies signature matches submitted multisig_info public key
//! - Only valid signatures are accepted
//!
//! # Attack Prevention
//!
//! - ❌ Cannot submit someone else's multisig_info (no private key)
//! - ❌ Cannot submit backdoored keys without controlling them
//! - ❌ Cannot replay old signatures (nonce + timestamp binding)
//!
//! # Usage
//!
//! ```rust,no_run
//! use server::crypto::multisig_validation::{MultisigChallenge, verify_multisig_submission};
//!
//! // 1. Generate challenge for user
//! let challenge = MultisigChallenge::generate(escrow_id);
//! let challenge_message = challenge.message();
//!
//! // 2. User signs challenge offline (in their wallet)
//! // signature = monero_wallet.sign(challenge_message)
//!
//! // 3. Server verifies submission
//! verify_multisig_submission(&multisig_info, &signature, &challenge)?;
//! ```

use anyhow::{Context, Result};
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// Re-export the SQLite-backed store from models
pub use crate::models::multisig_challenge::SqliteChallengeStore;

/// Challenge expiry time (5 minutes)
const CHALLENGE_EXPIRY_SECS: u64 = 300;

/// Challenge nonce for proof-of-possession
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigChallenge {
    /// Random nonce (32 bytes)
    pub nonce: [u8; 32],

    /// Escrow ID this challenge is for
    pub escrow_id: Uuid,

    /// Unix timestamp when challenge was created
    pub created_at: u64,
}

impl MultisigChallenge {
    /// Generate new challenge for escrow
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// let challenge = MultisigChallenge::generate(escrow_id);
    /// let message = challenge.message();
    /// // Send message to user for signing
    /// ```
    pub fn generate(escrow_id: Uuid) -> Self {
        use rand::RngCore;

        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        Self {
            nonce,
            escrow_id,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Get challenge message to sign
    ///
    /// This message is what the user must sign with their multisig private key
    /// to prove they control the multisig_info they're submitting.
    ///
    /// # Format
    ///
    /// ```text
    /// BLAKE2b-512(
    ///     "MONERO_MARKETPLACE_MULTISIG_CHALLENGE" ||
    ///     nonce ||
    ///     escrow_id ||
    ///     timestamp
    /// )
    /// ```
    pub fn message(&self) -> Vec<u8> {
        let mut hasher = Blake2b512::new();

        // Domain separation
        hasher.update(b"MONERO_MARKETPLACE_MULTISIG_CHALLENGE");

        // Challenge components
        hasher.update(&self.nonce);
        hasher.update(self.escrow_id.as_bytes());
        hasher.update(&self.created_at.to_le_bytes());

        hasher.finalize().to_vec()
    }

    /// Check if challenge is still valid (not expired)
    ///
    /// Challenges expire after 5 minutes to prevent replay attacks
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.created_at < CHALLENGE_EXPIRY_SECS
    }

    /// Get remaining time before expiry (in seconds)
    pub fn time_remaining(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let elapsed = now - self.created_at;
        if elapsed >= CHALLENGE_EXPIRY_SECS {
            0
        } else {
            CHALLENGE_EXPIRY_SECS - elapsed
        }
    }
}

/// DEPRECATED: In-memory ChallengeStore - use SqliteChallengeStore instead
///
/// This struct is kept for backward compatibility during migration.
/// All new code should use `SqliteChallengeStore` from `crate::models::multisig_challenge`.
///
/// # Migration
///
/// ```rust,ignore
/// // Old (deprecated):
/// let store = ChallengeStore::new();
/// store.store(user_id, escrow_id, challenge);
///
/// // New (recommended):
/// let store = SqliteChallengeStore::new(pool);
/// store.store(user_id, escrow_id, &challenge.nonce, challenge.created_at, expires_at)?;
/// ```
#[deprecated(
    since = "0.6.0",
    note = "Use SqliteChallengeStore for persistent storage. In-memory store loses data on restart."
)]
pub struct ChallengeStore {
    pub(crate) challenges: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<(Uuid, Uuid), MultisigChallenge>>>,
}

#[allow(deprecated)]
impl ChallengeStore {
    pub fn new() -> Self {
        tracing::warn!(
            "ChallengeStore::new() is deprecated. Use SqliteChallengeStore::new(pool) instead."
        );
        Self {
            challenges: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Store a new challenge for user/escrow
    pub fn store(&self, user_id: Uuid, escrow_id: Uuid, challenge: MultisigChallenge) {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.insert((user_id, escrow_id), challenge);
    }

    /// Retrieve challenge for user/escrow
    pub fn get(&self, user_id: Uuid, escrow_id: Uuid) -> Option<MultisigChallenge> {
        let challenges = self.challenges.lock().unwrap();
        challenges.get(&(user_id, escrow_id)).cloned()
    }

    /// Remove challenge after use (one-time use)
    pub fn remove(&self, user_id: Uuid, escrow_id: Uuid) {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.remove(&(user_id, escrow_id));
    }

    /// Clean up expired challenges (should be called periodically)
    pub fn cleanup_expired(&self) {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.retain(|_, challenge| challenge.is_valid());
    }
}

#[allow(deprecated)]
impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify multisig_info submission with challenge-response signature
///
/// # Arguments
///
/// * `multisig_info` - The submitted multisig info string
/// * `signature` - Ed25519 signature over challenge message (64 bytes)
/// * `challenge` - Original challenge sent to participant
///
/// # Returns
///
/// Ok(()) if proof-of-possession is valid, Err otherwise
///
/// # Errors
///
/// Returns error if:
/// - Challenge expired (>5 minutes old)
/// - Cannot extract public key from multisig_info
/// - Signature verification fails
///
/// # Example
///
/// ```rust,no_run
/// let challenge = MultisigChallenge::generate(escrow_id);
/// // ... user signs challenge ...
/// verify_multisig_submission(&multisig_info, &signature, &challenge)?;
/// ```
pub fn verify_multisig_submission(
    multisig_info: &str,
    signature: &[u8],
    challenge: &MultisigChallenge,
) -> Result<()> {
    // 1. Check challenge hasn't expired
    if !challenge.is_valid() {
        anyhow::bail!(
            "Challenge expired ({} seconds old, max {})",
            challenge.created_at,
            CHALLENGE_EXPIRY_SECS
        );
    }

    // 2. Extract public key from multisig_info
    // NOTE: This is a SIMPLIFIED implementation for Monero's multisig format
    // In production, you need to properly parse Monero's actual multisig_info structure
    let public_key = extract_public_key_from_multisig_info(multisig_info)
        .context("Failed to extract public key from multisig_info")?;

    // 3. Parse signature
    if signature.len() != 64 {
        anyhow::bail!(
            "Invalid signature length: expected 64 bytes, got {}",
            signature.len()
        );
    }

    let sig_bytes: [u8; 64] = signature.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    // 4. Verify signature
    let message = challenge.message();

    public_key
        .verify(&message, &sig)
        .map_err(|e| {
            anyhow::anyhow!(
                "Signature verification failed: {}. \
                 This means the submitter does not control the private key \
                 for the submitted multisig_info.",
                e
            )
        })?;

    tracing::info!(
        "✅ Multisig submission verified for escrow {}",
        challenge.escrow_id
    );

    Ok(())
}

/// Extract public key from Monero multisig_info string
///
/// # IMPORTANT - Production Implementation Required
///
/// This is a **SIMPLIFIED** implementation. Monero's actual multisig_info format
/// is more complex and not publicly documented. For production:
///
/// 1. Use `monero-rust` crate to properly parse multisig_info
/// 2. Extract the actual public spend key from the structure
/// 3. Validate checksums and format
///
/// # Current Implementation
///
/// Assumes format: "MultisigV1" + hex_encoded_data
/// Extracts first 32 bytes as public key (SIMPLIFIED)
///
/// # Arguments
///
/// * `multisig_info` - Monero multisig info string (starts with "MultisigV1")
///
/// # Returns
///
/// Ed25519 public key (32 bytes)
fn extract_public_key_from_multisig_info(multisig_info: &str) -> Result<VerifyingKey> {
    // Validate prefix
    if !multisig_info.starts_with("MultisigV1") {
        anyhow::bail!(
            "Invalid multisig_info format: must start with 'MultisigV1', got: {}",
            &multisig_info[..20.min(multisig_info.len())]
        );
    }

    // Skip "MultisigV1" prefix (10 chars)
    let hex_data = &multisig_info[10..];

    // Decode hex
    let bytes = hex::decode(hex_data).context(
        "multisig_info is not valid hex after 'MultisigV1' prefix. \
         Expected format: MultisigV1[hex_data]"
    )?;

    // Extract first 32 bytes as public key
    // NOTE: This is a SIMPLIFICATION - actual Monero format is more complex
    if bytes.len() < 32 {
        anyhow::bail!(
            "multisig_info too short: expected at least 32 bytes after prefix, got {}",
            bytes.len()
        );
    }

    let pubkey_bytes = &bytes[0..32];

    VerifyingKey::from_bytes(pubkey_bytes.try_into().context("Invalid key length")?).map_err(|e| {
        anyhow::anyhow!(
            "Invalid public key in multisig_info: {}. \
             The extracted bytes do not form a valid Ed25519 public key.",
            e
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_challenge_generation() {
        let escrow_id = Uuid::new_v4();
        let challenge = MultisigChallenge::generate(escrow_id);

        assert_eq!(challenge.escrow_id, escrow_id);
        assert!(challenge.is_valid());
        assert_eq!(challenge.nonce.len(), 32);
        assert!(challenge.time_remaining() > 0);
    }

    #[test]
    fn test_challenge_message() {
        let escrow_id = Uuid::new_v4();
        let challenge = MultisigChallenge::generate(escrow_id);

        let message1 = challenge.message();
        let message2 = challenge.message();

        // Message should be deterministic
        assert_eq!(message1, message2);
        assert_eq!(message1.len(), 64); // BLAKE2b-512 output
    }

    #[test]
    fn test_challenge_expiry() {
        let mut challenge = MultisigChallenge::generate(Uuid::new_v4());

        // Fresh challenge should be valid
        assert!(challenge.is_valid());

        // Backdate challenge by 6 minutes (past expiry)
        challenge.created_at -= 360;

        // Should now be expired
        assert!(!challenge.is_valid());
        assert_eq!(challenge.time_remaining(), 0);
    }

    #[test]
    fn test_challenge_store() {
        let store = ChallengeStore::new();
        let user_id = Uuid::new_v4();
        let escrow_id = Uuid::new_v4();
        let challenge = MultisigChallenge::generate(escrow_id);

        // Store challenge
        store.store(user_id, escrow_id, challenge.clone());

        // Retrieve challenge
        let retrieved = store.get(user_id, escrow_id).unwrap();
        assert_eq!(retrieved.escrow_id, challenge.escrow_id);

        // Remove challenge
        store.remove(user_id, escrow_id);
        assert!(store.get(user_id, escrow_id).is_none());
    }

    #[test]
    fn test_extract_public_key_valid() -> Result<()> {
        // Create a fake multisig_info with valid public key
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.as_bytes());

        let fake_multisig_info = format!("MultisigV1{}", pubkey_hex);

        let extracted = extract_public_key_from_multisig_info(&fake_multisig_info)?;
        assert_eq!(extracted.as_bytes(), verifying_key.as_bytes());

        Ok(())
    }

    #[test]
    fn test_extract_public_key_invalid_prefix() {
        let result = extract_public_key_from_multisig_info("InvalidPrefix...");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("MultisigV1"));
    }

    #[test]
    fn test_verify_multisig_submission_success() -> Result<()> {
        // Generate signing key
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();

        // Create fake multisig_info
        let pubkey_hex = hex::encode(verifying_key.as_bytes());
        let multisig_info = format!("MultisigV1{}", pubkey_hex);

        // Generate challenge
        let escrow_id = Uuid::new_v4();
        let challenge = MultisigChallenge::generate(escrow_id);

        // Sign challenge
        let message = challenge.message();
        let signature = signing_key.sign(&message);

        // Verify submission
        let result = verify_multisig_submission(
            &multisig_info,
            signature.to_bytes().as_ref(),
            &challenge,
        );

        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_multisig_submission_wrong_signature() -> Result<()> {
        // Generate two different signing keys
        let signing_key1 = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let signing_key2 = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key1 = signing_key1.verifying_key();

        // Create multisig_info with signing_key1's public key
        let pubkey_hex = hex::encode(verifying_key1.as_bytes());
        let multisig_info = format!("MultisigV1{}", pubkey_hex);

        // Generate challenge
        let challenge = MultisigChallenge::generate(Uuid::new_v4());

        // Sign with signing_key2 (WRONG KEY)
        let message = challenge.message();
        let wrong_signature = signing_key2.sign(&message);

        // Verification should fail
        let result = verify_multisig_submission(
            &multisig_info,
            wrong_signature.to_bytes().as_ref(),
            &challenge,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Signature verification failed"));
        Ok(())
    }

    #[test]
    fn test_verify_multisig_submission_expired_challenge() -> Result<()> {
        // Generate signing key
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();

        // Create multisig_info
        let pubkey_hex = hex::encode(verifying_key.as_bytes());
        let multisig_info = format!("MultisigV1{}", pubkey_hex);

        // Generate expired challenge
        let mut challenge = MultisigChallenge::generate(Uuid::new_v4());
        challenge.created_at -= 400; // Expire it

        // Sign challenge
        let message = challenge.message();
        let signature = signing_key.sign(&message);

        // Verification should fail due to expiry
        let result = verify_multisig_submission(
            &multisig_info,
            signature.to_bytes().as_ref(),
            &challenge,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
        Ok(())
    }
}
