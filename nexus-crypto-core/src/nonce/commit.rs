//! Nonce commitment computation and verification.

use alloc::string::String;
use sha3::{Digest, Keccak256};

use crate::types::errors::{CryptoError, CryptoResult};

/// Domain separator for MuSig2 nonce commitments.
const MUSIG2_NONCE_COMMITMENT_DOMAIN: &[u8] = b"MUSIG2_NONCE_COMMITMENT";

/// Compute the commitment hash for a nonce pair.
///
/// This computes: H("MUSIG2_NONCE_COMMITMENT" || R || R')
///
/// # Arguments
///
/// * `r_public` - R = α*G (hex, 32 bytes compressed)
/// * `r_prime_public` - R' = α*Hp(P) (hex, 32 bytes compressed)
///
/// # Returns
///
/// The commitment hash as hex string (64 chars)
pub fn compute_nonce_commitment_hash(r_public: &str, r_prime_public: &str) -> CryptoResult<String> {
    let r_bytes = hex::decode(r_public)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid r_public hex: {}", e)))?;

    let r_prime_bytes = hex::decode(r_prime_public)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid r_prime_public hex: {}", e)))?;

    if r_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "r_public".into(),
            expected: 32,
            actual: r_bytes.len(),
        });
    }

    if r_prime_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "r_prime_public".into(),
            expected: 32,
            actual: r_prime_bytes.len(),
        });
    }

    let mut hasher = Keccak256::new();
    hasher.update(MUSIG2_NONCE_COMMITMENT_DOMAIN);
    hasher.update(&r_bytes);
    hasher.update(&r_prime_bytes);

    Ok(hex::encode(hasher.finalize()))
}

/// Verify that a commitment hash matches the revealed nonces.
///
/// After the commitment phase, both signers reveal their R and R' values.
/// This function verifies that the revealed values match the original commitment.
///
/// # Arguments
///
/// * `commitment_hash` - The original commitment hash (hex, 32 bytes)
/// * `r_public` - The revealed R = α*G (hex, 32 bytes)
/// * `r_prime_public` - The revealed R' = α*Hp(P) (hex, 32 bytes)
///
/// # Returns
///
/// `Ok(true)` if the commitment is valid, `Ok(false)` if mismatch
pub fn verify_nonce_commitment(
    commitment_hash: &str,
    r_public: &str,
    r_prime_public: &str,
) -> CryptoResult<bool> {
    let computed = compute_nonce_commitment_hash(r_public, r_prime_public)?;
    Ok(computed == commitment_hash)
}

/// Verify commitment with constant-time comparison.
///
/// Use this variant when timing side-channels are a concern.
pub fn verify_nonce_commitment_ct(
    commitment_hash: &str,
    r_public: &str,
    r_prime_public: &str,
) -> CryptoResult<bool> {
    let expected = hex::decode(commitment_hash)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid commitment_hash hex: {}", e)))?;

    let computed_hex = compute_nonce_commitment_hash(r_public, r_prime_public)?;
    let computed = hex::decode(&computed_hex)
        .map_err(|e| CryptoError::InternalError(format!("Internal error: {}", e)))?;

    if expected.len() != computed.len() {
        return Ok(false);
    }

    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(computed.iter()) {
        diff |= a ^ b;
    }

    Ok(diff == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors (pre-computed)
    const TEST_R: &str = "5866666666666666666666666666666666666666666666666666666666666666";
    const TEST_R_PRIME: &str = "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022";

    #[test]
    fn test_compute_commitment_hash() {
        let hash = compute_nonce_commitment_hash(TEST_R, TEST_R_PRIME).unwrap();

        // Hash should be 64 hex chars (32 bytes)
        assert_eq!(hash.len(), 64);

        // Same inputs should produce same hash
        let hash2 = compute_nonce_commitment_hash(TEST_R, TEST_R_PRIME).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_commitment_deterministic() {
        // Commitment should be deterministic
        let hash1 = compute_nonce_commitment_hash(TEST_R, TEST_R_PRIME).unwrap();
        let hash2 = compute_nonce_commitment_hash(TEST_R, TEST_R_PRIME).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_verify_commitment_valid() {
        let hash = compute_nonce_commitment_hash(TEST_R, TEST_R_PRIME).unwrap();
        let valid = verify_nonce_commitment(&hash, TEST_R, TEST_R_PRIME).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_commitment_invalid() {
        let hash = compute_nonce_commitment_hash(TEST_R, TEST_R_PRIME).unwrap();

        // Modify one byte of R
        let bad_r = "6866666666666666666666666666666666666666666666666666666666666666";
        let valid = verify_nonce_commitment(&hash, bad_r, TEST_R_PRIME).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_commitment_ct() {
        let hash = compute_nonce_commitment_hash(TEST_R, TEST_R_PRIME).unwrap();

        // Valid
        let valid = verify_nonce_commitment_ct(&hash, TEST_R, TEST_R_PRIME).unwrap();
        assert!(valid);

        // Invalid
        let bad_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let invalid = verify_nonce_commitment_ct(bad_hash, TEST_R, TEST_R_PRIME).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_invalid_hex() {
        let result = compute_nonce_commitment_hash("not_hex", TEST_R_PRIME);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_length() {
        let result = compute_nonce_commitment_hash("1234", TEST_R_PRIME);
        assert!(result.is_err());
    }
}
