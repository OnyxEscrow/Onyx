//! Nonce aggregation for MuSig2-style CLSAG multisig.

use alloc::string::String;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

use crate::types::errors::{CryptoError, CryptoResult};

/// Result of nonce aggregation.
///
/// Contains the aggregated R values that both signers use for L computation.
#[derive(Debug, Clone)]
pub struct AggregatedNonces {
    /// R_agg = R₁ + R₂ (hex, compressed Edwards point)
    pub r_agg: String,

    /// R'_agg = R'₁ + R'₂ (hex, compressed Edwards point)
    pub r_prime_agg: String,
}

/// Aggregate two signers' nonces for MuSig2-style CLSAG.
///
/// After commitment reveal, the server (or either signer) computes:
/// - R_agg = R₁ + R₂
/// - R'_agg = R'₁ + R'₂
///
/// Both signers then use R_agg in their L computation, ensuring L₁ = L₂.
///
/// # Arguments
///
/// * `r1` - Signer 1's R = α₁*G (hex, 32 bytes)
/// * `r2` - Signer 2's R = α₂*G (hex, 32 bytes)
///
/// # Returns
///
/// The aggregated R point as hex string
///
/// # Errors
///
/// - `InvalidInput` if R values are invalid hex or not valid curve points
/// - `CryptoOperation` if point addition fails (shouldn't happen with valid points)
pub fn aggregate_nonces(r1: &str, r2: &str) -> CryptoResult<String> {
    let r1_point = parse_compressed_point(r1, "r1")?;
    let r2_point = parse_compressed_point(r2, "r2")?;

    let r_agg = r1_point + r2_point;

    Ok(hex::encode(r_agg.compress().to_bytes()))
}

/// Aggregate both R and R' nonces for complete MuSig2 aggregation.
///
/// This is the full aggregation needed for CLSAG:
/// - R_agg = R₁ + R₂ (for public key nonce)
/// - R'_agg = R'₁ + R'₂ (for key image nonce)
///
/// # Arguments
///
/// * `r1` - Signer 1's R = α₁*G
/// * `r1_prime` - Signer 1's R' = α₁*Hp(P)
/// * `r2` - Signer 2's R = α₂*G
/// * `r2_prime` - Signer 2's R' = α₂*Hp(P)
///
/// # Returns
///
/// `AggregatedNonces` containing both R_agg and R'_agg
pub fn aggregate_nonces_full(
    r1: &str,
    r1_prime: &str,
    r2: &str,
    r2_prime: &str,
) -> CryptoResult<AggregatedNonces> {
    let r1_point = parse_compressed_point(r1, "r1")?;
    let r1_prime_point = parse_compressed_point(r1_prime, "r1_prime")?;
    let r2_point = parse_compressed_point(r2, "r2")?;
    let r2_prime_point = parse_compressed_point(r2_prime, "r2_prime")?;

    let r_agg = r1_point + r2_point;
    let r_prime_agg = r1_prime_point + r2_prime_point;

    Ok(AggregatedNonces {
        r_agg: hex::encode(r_agg.compress().to_bytes()),
        r_prime_agg: hex::encode(r_prime_agg.compress().to_bytes()),
    })
}

/// Parse a hex-encoded compressed Edwards point.
fn parse_compressed_point(hex_str: &str, name: &str) -> CryptoResult<EdwardsPoint> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid {} hex: {}", name, e)))?;

    if bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: name.into(),
            expected: 32,
            actual: bytes.len(),
        });
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);

    let compressed = CompressedEdwardsY(arr);
    compressed.decompress().ok_or_else(|| {
        CryptoError::InvalidPublicKey(format!("{} is not a valid curve point", name))
    })
}

/// Verify that aggregated nonces match the component nonces.
///
/// Used to verify the server's aggregation is correct.
pub fn verify_nonce_aggregation(r1: &str, r2: &str, r_agg_claimed: &str) -> CryptoResult<bool> {
    let computed = aggregate_nonces(r1, r2)?;
    Ok(computed == r_agg_claimed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::Scalar;

    #[test]
    fn test_aggregate_nonces() {
        // Generate two deterministic nonces
        let alpha1 = Scalar::from_bytes_mod_order([1u8; 32]);
        let alpha2 = Scalar::from_bytes_mod_order([2u8; 32]);

        let r1 = &alpha1 * ED25519_BASEPOINT_TABLE;
        let r2 = &alpha2 * ED25519_BASEPOINT_TABLE;

        let r1_hex = hex::encode(r1.compress().to_bytes());
        let r2_hex = hex::encode(r2.compress().to_bytes());

        let r_agg_hex = aggregate_nonces(&r1_hex, &r2_hex).unwrap();

        // Verify: R_agg should equal R1 + R2
        let expected = r1 + r2;
        let expected_hex = hex::encode(expected.compress().to_bytes());

        assert_eq!(r_agg_hex, expected_hex);
    }

    #[test]
    fn test_aggregate_nonces_full() {
        let alpha1 = Scalar::from_bytes_mod_order([1u8; 32]);
        let alpha2 = Scalar::from_bytes_mod_order([2u8; 32]);

        let r1 = &alpha1 * ED25519_BASEPOINT_TABLE;
        let r2 = &alpha2 * ED25519_BASEPOINT_TABLE;

        // For simplicity, use same values for R' (in practice, these would be alpha * Hp(P))
        let r1_hex = hex::encode(r1.compress().to_bytes());
        let r2_hex = hex::encode(r2.compress().to_bytes());

        let result = aggregate_nonces_full(&r1_hex, &r1_hex, &r2_hex, &r2_hex).unwrap();

        // Verify lengths
        assert_eq!(result.r_agg.len(), 64);
        assert_eq!(result.r_prime_agg.len(), 64);
    }

    #[test]
    fn test_verify_nonce_aggregation() {
        let alpha1 = Scalar::from_bytes_mod_order([3u8; 32]);
        let alpha2 = Scalar::from_bytes_mod_order([4u8; 32]);

        let r1 = &alpha1 * ED25519_BASEPOINT_TABLE;
        let r2 = &alpha2 * ED25519_BASEPOINT_TABLE;

        let r1_hex = hex::encode(r1.compress().to_bytes());
        let r2_hex = hex::encode(r2.compress().to_bytes());

        let r_agg_hex = aggregate_nonces(&r1_hex, &r2_hex).unwrap();

        // Valid aggregation
        assert!(verify_nonce_aggregation(&r1_hex, &r2_hex, &r_agg_hex).unwrap());

        // Invalid aggregation (wrong R_agg)
        let bad_r_agg = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_nonce_aggregation(&r1_hex, &r2_hex, bad_r_agg).unwrap());
    }

    #[test]
    fn test_commutative_aggregation() {
        // R1 + R2 should equal R2 + R1
        let alpha1 = Scalar::from_bytes_mod_order([5u8; 32]);
        let alpha2 = Scalar::from_bytes_mod_order([6u8; 32]);

        let r1 = &alpha1 * ED25519_BASEPOINT_TABLE;
        let r2 = &alpha2 * ED25519_BASEPOINT_TABLE;

        let r1_hex = hex::encode(r1.compress().to_bytes());
        let r2_hex = hex::encode(r2.compress().to_bytes());

        let agg1 = aggregate_nonces(&r1_hex, &r2_hex).unwrap();
        let agg2 = aggregate_nonces(&r2_hex, &r1_hex).unwrap();

        assert_eq!(agg1, agg2);
    }

    #[test]
    fn test_invalid_hex() {
        // Invalid hex string should error
        let invalid_hex = "not_valid_hex_string_at_all_definitely_not_valid";
        let valid = "5866666666666666666666666666666666666666666666666666666666666666";

        let result = aggregate_nonces(invalid_hex, valid);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_length() {
        // Too short - should error
        let too_short = "1234";
        let valid = "5866666666666666666666666666666666666666666666666666666666666666";

        let result = aggregate_nonces(too_short, valid);
        assert!(result.is_err());
    }
}
