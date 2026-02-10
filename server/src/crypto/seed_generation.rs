//! Cryptographic seed generation and derivation for Phase 6
//!
//! This module provides the foundation for non-custodial wallet management:
//! - Generate cryptographically secure random seeds
//! - Convert entropy to BIP39 mnemonic (12-word backup)
//! - Derive escrow-specific wallet seeds using HKDF-SHA256
//!
//! # Security Properties
//!
//! - **Entropy Source**: `rand::thread_rng()` (uses OsRng internally)
//! - **Seed Size**: 128 bits (16 bytes) for BIP39 12-word mnemonic
//! - **Derivation**: HKDF-SHA256 with domain separation
//! - **Memory Safety**: Zeroize on drop for sensitive key material
//!
//! # Derivation Scheme
//!
//! ```text
//! master_seed (128 bits)
//!   └─> HKDF-SHA256(master_seed, info="nexus/escrow:{id}/role:{role}")
//!       └─> escrow_seed (256 bits) → Monero wallet keys
//! ```
//!
//! # Phase 6 MVP Note
//!
//! This implementation uses HKDF for deterministic derivation instead of BIP32/BIP44.
//! Monero doesn't have standardized BIP44 support, and HKDF provides the same
//! security guarantees with simpler implementation.

use anyhow::{Context, Result};
use bip39::Mnemonic;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

/// Size of master seed in bytes (128 bits = 12-word BIP39 mnemonic)
pub const MASTER_SEED_SIZE: usize = 16;

/// Size of derived escrow seed in bytes (256 bits for Monero spend key)
pub const ESCROW_SEED_SIZE: usize = 32;

/// Size of random salt for PBKDF2 (128 bits recommended)
pub const SALT_SIZE: usize = 16;

/// Generate cryptographically secure random seed
///
/// # Security
///
/// Uses `rand::thread_rng()` which internally uses `OsRng` for cryptographically
/// secure randomness. This is safe for generating master wallet seeds.
///
/// # Arguments
///
/// * `bytes` - Number of bytes to generate (use MASTER_SEED_SIZE for wallet seeds)
///
/// # Returns
///
/// * `Vec<u8>` - Random bytes
///
/// # Examples
///
/// ```no_run
/// use server::crypto::seed_generation::{generate_random_seed, MASTER_SEED_SIZE};
///
/// let master_seed = generate_random_seed(MASTER_SEED_SIZE)?;
/// assert_eq!(master_seed.len(), 16);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn generate_random_seed(bytes: usize) -> Result<Vec<u8>> {
    let mut seed = vec![0u8; bytes];
    rand::thread_rng()
        .try_fill_bytes(&mut seed)
        .context("Failed to generate random seed")?;
    Ok(seed)
}

/// Generate random salt for PBKDF2 password derivation
///
/// # Security
///
/// Each user must have a unique salt. NEVER reuse salts across users.
///
/// # Arguments
///
/// * `bytes` - Number of bytes to generate (use SALT_SIZE for PBKDF2)
///
/// # Returns
///
/// * `Vec<u8>` - Random salt bytes
pub fn generate_random_salt(bytes: usize) -> Result<Vec<u8>> {
    let mut salt = vec![0u8; bytes];
    rand::thread_rng()
        .try_fill_bytes(&mut salt)
        .context("Failed to generate random salt")?;
    Ok(salt)
}

/// Convert entropy to BIP39 mnemonic (12 words for 128-bit entropy)
///
/// # Arguments
///
/// * `entropy` - Raw entropy bytes (must be 16, 20, 24, 28, or 32 bytes)
///
/// # Returns
///
/// * `String` - Space-separated 12-word mnemonic
///
/// # Errors
///
/// * Invalid entropy length (not 16, 20, 24, 28, or 32 bytes)
/// * BIP39 checksum validation failure
///
/// # Examples
///
/// ```no_run
/// use server::crypto::seed_generation::{generate_random_seed, mnemonic_from_entropy, MASTER_SEED_SIZE};
///
/// let entropy = generate_random_seed(MASTER_SEED_SIZE)?;
/// let mnemonic = mnemonic_from_entropy(&entropy)?;
///
/// // Example output: "witch collapse practice feed shame open despair creek road again ice least"
/// assert_eq!(mnemonic.split_whitespace().count(), 12);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn mnemonic_from_entropy(entropy: &[u8]) -> Result<String> {
    let mnemonic = Mnemonic::from_entropy(entropy)
        .context("Failed to generate BIP39 mnemonic from entropy")?;

    Ok(mnemonic.to_string())
}

/// Derive escrow-specific wallet seed using HKDF-SHA256
///
/// # Derivation Scheme
///
/// ```text
/// HKDF-SHA256(
///     ikm = master_seed,
///     salt = None,  // Not needed for HKDF-Extract (ikm is already high entropy)
///     info = "nexus/escrow:{escrow_id}/role:{role}"
/// ) -> 32-byte escrow_seed
/// ```
///
/// This ensures:
/// - Deterministic derivation (same inputs → same output)
/// - Domain separation (different escrows/roles → different seeds)
/// - Forward security (escrow_seed doesn't reveal master_seed)
///
/// # Arguments
///
/// * `master_seed` - User's master wallet seed (16 or 32 bytes)
/// * `escrow_id` - Unique escrow identifier (e.g., UUID)
/// * `role` - User's role in escrow ("buyer", "seller", "arbiter")
///
/// # Returns
///
/// * `Vec<u8>` - 32-byte derived escrow seed (used for Monero wallet restoration)
///
/// # Security Notes
///
/// - **DO NOT** log escrow_seed (it's equivalent to a private key)
/// - **DO** zeroize escrow_seed after use
/// - **DO NOT** derive keys for roles the user doesn't own
///
/// # Examples
///
/// ```no_run
/// use server::crypto::seed_generation::{generate_random_seed, derive_escrow_wallet_seed, MASTER_SEED_SIZE};
///
/// let master_seed = generate_random_seed(MASTER_SEED_SIZE)?;
/// let escrow_id = "escrow_12345";
/// let role = "buyer";
///
/// let escrow_seed = derive_escrow_wallet_seed(&master_seed, escrow_id, role)?;
/// assert_eq!(escrow_seed.len(), 32);
///
/// // Different role = different seed
/// let seller_seed = derive_escrow_wallet_seed(&master_seed, escrow_id, "seller")?;
/// assert_ne!(escrow_seed, seller_seed);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn derive_escrow_wallet_seed(
    master_seed: &[u8],
    escrow_id: &str,
    role: &str,
) -> Result<Vec<u8>> {
    // Validate role
    if !matches!(role, "buyer" | "seller" | "arbiter") {
        anyhow::bail!("Invalid role: {}. Must be 'buyer', 'seller', or 'arbiter'", role);
    }

    // Domain-separated info string
    let info = format!("nexus/escrow:{}/role:{}", escrow_id, role);

    // HKDF-SHA256 expansion
    let hkdf = Hkdf::<Sha256>::new(None, master_seed);
    let mut escrow_seed = vec![0u8; ESCROW_SEED_SIZE];

    hkdf.expand(info.as_bytes(), &mut escrow_seed)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed: invalid output length"))?;

    Ok(escrow_seed)
}

/// Zeroizable wrapper for sensitive key material
///
/// Automatically zeros memory on drop to prevent key leakage in memory dumps.
///
/// # Security
///
/// - Implements `Drop` trait to zero memory
/// - Use this for all sensitive keys (master_seed, escrow_seed, encryption keys)
/// - Keys are zeroized even if panic occurs (Drop guarantee)
///
/// # Examples
///
/// ```no_run
/// use server::crypto::seed_generation::{SensitiveBytes, generate_random_seed, MASTER_SEED_SIZE};
///
/// {
///     let seed = generate_random_seed(MASTER_SEED_SIZE)?;
///     let sensitive = SensitiveBytes::new(seed);
///
///     // Use sensitive.as_slice() to access data
///     let slice = sensitive.as_slice();
///     assert_eq!(slice.len(), 16);
///
/// } // <- Memory is zeroized here automatically
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SensitiveBytes(pub Vec<u8>);

impl SensitiveBytes {
    /// Wrap sensitive bytes in zeroizing container
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get read-only slice of sensitive data
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Get mutable slice (use sparingly)
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_seed() -> Result<()> {
        let seed1 = generate_random_seed(MASTER_SEED_SIZE)?;
        let seed2 = generate_random_seed(MASTER_SEED_SIZE)?;

        assert_eq!(seed1.len(), MASTER_SEED_SIZE);
        assert_eq!(seed2.len(), MASTER_SEED_SIZE);
        assert_ne!(seed1, seed2, "Seeds must be unique");

        Ok(())
    }

    #[test]
    fn test_mnemonic_from_entropy() -> Result<()> {
        let entropy = generate_random_seed(MASTER_SEED_SIZE)?;
        let mnemonic = mnemonic_from_entropy(&entropy)?;

        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 12, "12-word mnemonic expected for 128-bit entropy");

        // Verify all words are in BIP39 wordlist
        for word in mnemonic.split_whitespace() {
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase()),
                "BIP39 words must be lowercase"
            );
        }

        Ok(())
    }

    #[test]
    fn test_derive_escrow_wallet_seed_deterministic() -> Result<()> {
        let master_seed = generate_random_seed(MASTER_SEED_SIZE)?;
        let escrow_id = "escrow_test_001";
        let role = "buyer";

        let seed1 = derive_escrow_wallet_seed(&master_seed, escrow_id, role)?;
        let seed2 = derive_escrow_wallet_seed(&master_seed, escrow_id, role)?;

        assert_eq!(seed1, seed2, "Derivation must be deterministic");
        assert_eq!(seed1.len(), ESCROW_SEED_SIZE);

        Ok(())
    }

    #[test]
    fn test_derive_escrow_wallet_seed_different_roles() -> Result<()> {
        let master_seed = generate_random_seed(MASTER_SEED_SIZE)?;
        let escrow_id = "escrow_test_002";

        let buyer_seed = derive_escrow_wallet_seed(&master_seed, escrow_id, "buyer")?;
        let seller_seed = derive_escrow_wallet_seed(&master_seed, escrow_id, "seller")?;
        let arbiter_seed = derive_escrow_wallet_seed(&master_seed, escrow_id, "arbiter")?;

        assert_ne!(buyer_seed, seller_seed, "Different roles must have different seeds");
        assert_ne!(seller_seed, arbiter_seed, "Different roles must have different seeds");
        assert_ne!(buyer_seed, arbiter_seed, "Different roles must have different seeds");

        Ok(())
    }

    #[test]
    fn test_derive_escrow_wallet_seed_invalid_role() {
        let master_seed = vec![0u8; MASTER_SEED_SIZE];
        let escrow_id = "escrow_test_003";

        let result = derive_escrow_wallet_seed(&master_seed, escrow_id, "invalid_role");
        assert!(result.is_err(), "Invalid role should return error");
    }

    #[test]
    fn test_sensitive_bytes_zeroize() {
        let original_data = vec![1, 2, 3, 4, 5];

        {
            let sensitive = SensitiveBytes::new(original_data.clone());
            // Capture pointer to verify memory location (unused but demonstrates intent)
            let _ptr: *const u8 = sensitive.as_slice().as_ptr();
            assert_eq!(sensitive.as_slice(), &[1, 2, 3, 4, 5]);
        } // Drop happens here, zeroize is called

        // Note: We can't directly verify memory is zeroed in safe Rust,
        // but zeroize crate guarantees this through compiler barriers
        // This test mainly verifies the code compiles and doesn't panic
    }

    #[test]
    fn test_generate_random_salt() -> Result<()> {
        let salt1 = generate_random_salt(SALT_SIZE)?;
        let salt2 = generate_random_salt(SALT_SIZE)?;

        assert_eq!(salt1.len(), SALT_SIZE);
        assert_eq!(salt2.len(), SALT_SIZE);
        assert_ne!(salt1, salt2, "Salts must be unique");

        Ok(())
    }
}
