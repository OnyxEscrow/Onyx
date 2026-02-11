//! Nonce generation for MuSig2-style CLSAG multisig.

use alloc::string::String;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
use monero_generators::hash_to_point;
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use crate::types::errors::{CryptoError, CryptoResult};

/// Result of nonce commitment generation.
///
/// Contains both public values (to be shared) and the secret alpha
/// (to be kept in memory only).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct NonceCommitmentResult {
    /// Keccak256 commitment hash: `H("MUSIG2_NONCE_COMMITMENT`" || R || R')
    #[zeroize(skip)]
    pub commitment_hash: String,

    /// R = α*G (public nonce point, hex)
    #[zeroize(skip)]
    pub r_public: String,

    /// R' = α*Hp(P) (public nonce point for key image, hex)
    #[zeroize(skip)]
    pub r_prime_public: String,

    /// Secret nonce α (hex) - NEVER persist, keep in memory only!
    pub alpha_secret: String,
}

/// Generate MuSig2-style nonce commitment for CLSAG multisig.
///
/// This solves the "Sanity check failed" issue where each signer
/// had unique alpha causing L₁ ≠ L₂. With MuSig2-style nonce aggregation:
///
/// 1. Each signer generates random α (nonce)
/// 2. Computes R = α*G and R' = α*Hp(P)
/// 3. Computes commitment H(R || R')
/// 4. Returns {`commitment_hash`, `r_public`, `r_prime_public`, `alpha_secret`}
///
/// # Security
///
/// - `alpha_secret` MUST be kept in memory only
/// - NEVER persist to localStorage or any storage
/// - Each nonce MUST be used exactly once
/// - Nonce reuse enables private key extraction
///
/// # Arguments
///
/// * `multisig_pub_key` - The aggregated multisig public key (32 bytes, hex)
///
/// # Returns
///
/// `NonceCommitmentResult` containing the commitment and secret
///
/// # Errors
///
/// - `InvalidInput` if `multisig_pub_key` is invalid hex or wrong length
/// - `CryptoOperation` if RNG fails
pub fn generate_nonce_commitment(multisig_pub_key: &str) -> CryptoResult<NonceCommitmentResult> {
    // Validate multisig public key
    let pubkey_bytes = hex::decode(multisig_pub_key)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid multisig_pub_key hex: {e}")))?;

    if pubkey_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "multisig_pub_key".into(),
            expected: 32,
            actual: pubkey_bytes.len(),
        });
    }

    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    // Generate random nonce (alpha) using getrandom
    let mut alpha_bytes = [0u8; 32];
    getrandom::getrandom(&mut alpha_bytes)
        .map_err(|e| CryptoError::NonceGenerationFailed(format!("RNG error: {e}")))?;

    let alpha = Scalar::from_bytes_mod_order(alpha_bytes);

    // Compute R = alpha * G
    let r_point = &alpha * ED25519_BASEPOINT_TABLE;
    let r_public = hex::encode(r_point.compress().to_bytes());

    // Compute R' = alpha * Hp(P)
    let hp = hash_to_point(pubkey_arr);
    let r_prime_point = alpha * hp;
    let r_prime_public = hex::encode(r_prime_point.compress().to_bytes());

    // Compute commitment H("MUSIG2_NONCE_COMMITMENT" || R || R')
    let mut hasher = Keccak256::new();
    hasher.update(b"MUSIG2_NONCE_COMMITMENT");
    hasher.update(r_point.compress().as_bytes());
    hasher.update(r_prime_point.compress().as_bytes());
    let commitment_hash = hex::encode(hasher.finalize());

    // Return alpha_secret (hex) - caller MUST keep in memory only!
    let alpha_hex = hex::encode(alpha.to_bytes());

    // Zeroize the raw bytes
    alpha_bytes.zeroize();

    Ok(NonceCommitmentResult {
        commitment_hash,
        r_public,
        r_prime_public,
        alpha_secret: alpha_hex,
    })
}

/// Generate nonce commitment with a specific seed (for testing only).
///
/// # Warning
///
/// This function is intended for deterministic testing only.
/// NEVER use in production - always use `generate_nonce_commitment()`.
#[cfg(feature = "test-helpers")]
pub fn generate_nonce_commitment_deterministic(
    multisig_pub_key: &str,
    seed: &[u8; 32],
) -> CryptoResult<NonceCommitmentResult> {
    let pubkey_bytes = hex::decode(multisig_pub_key).map_err(|e| {
        CryptoError::HexDecodeFailed(format!("Invalid multisig_pub_key hex: {}", e))
    })?;

    if pubkey_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "multisig_pub_key".into(),
            expected: 32,
            actual: pubkey_bytes.len(),
        });
    }

    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    let alpha = Scalar::from_bytes_mod_order(*seed);
    let r_point = &alpha * ED25519_BASEPOINT_TABLE;
    let r_public = hex::encode(r_point.compress().to_bytes());

    let hp = hash_to_point(pubkey_arr);
    let r_prime_point = alpha * hp;
    let r_prime_public = hex::encode(r_prime_point.compress().to_bytes());

    let mut hasher = Keccak256::new();
    hasher.update(b"MUSIG2_NONCE_COMMITMENT");
    hasher.update(r_point.compress().as_bytes());
    hasher.update(r_prime_point.compress().as_bytes());
    let commitment_hash = hex::encode(hasher.finalize());

    let alpha_hex = hex::encode(alpha.to_bytes());

    Ok(NonceCommitmentResult {
        commitment_hash,
        r_public,
        r_prime_public,
        alpha_secret: alpha_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector: known multisig pubkey
    const TEST_PUBKEY: &str = "5866666666666666666666666666666666666666666666666666666666666666";

    #[test]
    fn test_generate_nonce_commitment() {
        let result = generate_nonce_commitment(TEST_PUBKEY).unwrap();

        // Verify all fields are present and have correct lengths
        assert_eq!(result.commitment_hash.len(), 64); // Keccak256 = 32 bytes = 64 hex
        assert_eq!(result.r_public.len(), 64); // Edwards point = 32 bytes
        assert_eq!(result.r_prime_public.len(), 64); // Edwards point = 32 bytes
        assert_eq!(result.alpha_secret.len(), 64); // Scalar = 32 bytes
    }

    #[test]
    fn test_nonce_uniqueness() {
        // Each call should produce different nonces
        let result1 = generate_nonce_commitment(TEST_PUBKEY).unwrap();
        let result2 = generate_nonce_commitment(TEST_PUBKEY).unwrap();

        assert_ne!(result1.alpha_secret, result2.alpha_secret);
        assert_ne!(result1.r_public, result2.r_public);
        assert_ne!(result1.commitment_hash, result2.commitment_hash);
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let result = generate_nonce_commitment("1234"); // Too short
        assert!(result.is_err());

        if let Err(CryptoError::InvalidLength {
            field,
            expected,
            actual,
        }) = result
        {
            assert_eq!(field, "multisig_pub_key");
            assert_eq!(expected, 32);
            assert_eq!(actual, 2); // "1234" decodes to 2 bytes
        } else {
            panic!("Expected InvalidLength error");
        }
    }

    #[test]
    fn test_invalid_pubkey_hex() {
        let result = generate_nonce_commitment(
            "not_valid_hex_not_valid_hex_not_valid_hex_not_valid_hex_not_valid_",
        );
        assert!(result.is_err());
    }
}
