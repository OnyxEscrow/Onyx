//! Key image generation for Monero ring signatures.
//!
//! Key images are used to prevent double-spending in Monero. Each output can only
//! be spent once, and the key image is a cryptographic proof that links spends
//! without revealing which output was spent.
//!
//! ## Full Key Image
//!
//! For a single-signer spend with private key `x` and public key `P`:
//! ```text
//! KI = x * Hp(P)
//! ```
//! Where `Hp` is hash-to-point (Monero's `ge_fromfe_frombytes_vartime`).
//!
//! ## Partial Key Images (2-of-3 FROST)
//!
//! For threshold signing, each signer contributes a partial key image:
//! ```text
//! pKI_i = λ_i * x_i * Hp(P)
//! ```
//! Where `λ_i` is the Lagrange coefficient for signer `i`.
//!
//! The server aggregates:
//! ```text
//! KI = pKI_1 + pKI_2 = (λ_1*x_1 + λ_2*x_2) * Hp(P)
//! ```
//!
//! ## Key Image with Output Derivation
//!
//! For spending a real Monero output, the effective spend key includes derivation:
//! ```text
//! x_eff = Hs(8*a*R || idx) + λ*s
//! pKI = x_eff * Hp(P)
//! ```
//! Where:
//! - `a` is the shared view key
//! - `R` is the tx public key from the funding transaction
//! - `idx` is the output index (varint encoded)
//! - `s` is the signer's secret share
//! - `λ` is the Lagrange coefficient

use alloc::string::String;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, Scalar};
use monero_generators::hash_to_point;
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use crate::cmd::encode_varint;
use crate::types::errors::{CryptoError, CryptoResult};

/// Result of key image computation.
#[derive(Debug, Clone)]
pub struct KeyImageResult {
    /// The key image (hex, 32 bytes compressed point)
    pub key_image: String,
    /// The public key P = x*G (hex, 32 bytes)
    pub public_key: String,
}

/// Result of partial key image computation.
#[derive(Debug, Clone)]
pub struct PartialKeyImageResult {
    /// The partial key image contribution (hex, 32 bytes)
    pub partial_key_image: String,
    /// The one-time output public key used (hex, echo for verification)
    pub one_time_pubkey: String,
    /// Whether Lagrange coefficient was applied
    pub lagrange_applied: bool,
}

/// Result of partial key image with derivation.
#[derive(Debug, Clone)]
pub struct PartialKeyImageWithDerivationResult {
    /// The partial key image contribution (hex, 32 bytes)
    pub partial_key_image: String,
    /// The derivation scalar Hs(8*a*R || idx) for debugging
    pub derivation_scalar: String,
    /// The one-time output public key (hex)
    pub one_time_pubkey: String,
    /// Whether Lagrange coefficient was applied
    pub lagrange_applied: bool,
}

/// Compute full key image from a private spend key.
///
/// This is for single-signer scenarios (NOT multisig).
///
/// # Formula
/// ```text
/// P = x * G
/// KI = x * Hp(P)
/// ```
///
/// # Arguments
/// * `spend_key_priv_hex` - Private spend key (hex, 32 bytes)
///
/// # Returns
/// `KeyImageResult` with the key image and derived public key
pub fn compute_key_image(spend_key_priv_hex: &str) -> CryptoResult<KeyImageResult> {
    // Decode spend key
    let spend_bytes = hex::decode(spend_key_priv_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid spend key hex: {e}")))?;

    if spend_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "spend_key".into(),
            expected: 32,
            actual: spend_bytes.len(),
        });
    }

    let mut spend_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // Compute public key P = x * G
    let public_key = ED25519_BASEPOINT_TABLE * &spend_scalar;
    let public_key_bytes = public_key.compress().to_bytes();

    // Compute Hp(P) using hash_to_point
    let hp = hash_to_point(public_key_bytes);

    // Compute key image KI = x * Hp(P)
    let key_image = spend_scalar * hp;
    let key_image_bytes = key_image.compress().to_bytes();

    // Zeroize sensitive data
    spend_key_arr.zeroize();

    Ok(KeyImageResult {
        key_image: hex::encode(key_image_bytes),
        public_key: hex::encode(public_key_bytes),
    })
}

/// Compute partial key image for 2-of-3 FROST multisig.
///
/// Each signer contributes a partial key image weighted by their Lagrange coefficient:
/// ```text
/// pKI_i = λ_i * x_i * Hp(P)
/// ```
///
/// The server aggregates partial key images from 2 signers:
/// ```text
/// KI = pKI_1 + pKI_2 = (λ_1*x_1 + λ_2*x_2) * Hp(P)
/// ```
///
/// # Arguments
/// * `spend_key_priv_hex` - Signer's private spend key share (hex, 32 bytes)
/// * `one_time_pubkey_hex` - The one-time output public key P (hex, 32 bytes)
///   This is the actual output being spent: `ring[signer_idx][0]`
/// * `lagrange_coefficient_hex` - FROST Lagrange coefficient `λ_i` (hex, 32 bytes)
///
/// # Security
/// - The partial key image does NOT reveal the private spend key
/// - Safe to send to server for aggregation
/// - Both signers' partials are needed to reconstruct the full key image
pub fn compute_partial_key_image(
    spend_key_priv_hex: &str,
    one_time_pubkey_hex: &str,
    lagrange_coefficient_hex: &str,
) -> CryptoResult<PartialKeyImageResult> {
    // Parse spend key
    let spend_bytes = hex::decode(spend_key_priv_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid spend key hex: {e}")))?;

    if spend_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "spend_key".into(),
            expected: 32,
            actual: spend_bytes.len(),
        });
    }

    let mut spend_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // Parse Lagrange coefficient
    let lambda_bytes = hex::decode(lagrange_coefficient_hex).map_err(|e| {
        CryptoError::HexDecodeFailed(format!("Invalid lagrange coefficient hex: {e}"))
    })?;

    if lambda_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "lagrange_coefficient".into(),
            expected: 32,
            actual: lambda_bytes.len(),
        });
    }

    let mut lambda_arr = [0u8; 32];
    lambda_arr.copy_from_slice(&lambda_bytes);
    let lambda = Scalar::from_bytes_mod_order(lambda_arr);

    // Apply Lagrange coefficient: effective_spend = λ * x
    let effective_spend = lambda * spend_scalar;

    // Parse one-time output public key
    let pubkey_bytes = hex::decode(one_time_pubkey_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid one_time_pubkey hex: {e}")))?;

    if pubkey_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "one_time_pubkey".into(),
            expected: 32,
            actual: pubkey_bytes.len(),
        });
    }

    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    // Compute Hp(P) - hash-to-point of the one-time output public key
    let hp = hash_to_point(pubkey_arr);

    // Compute partial key image: pKI = (λ * x) * Hp(P)
    let partial_key_image = effective_spend * hp;
    let partial_key_image_bytes = partial_key_image.compress().to_bytes();

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    lambda_arr.zeroize();

    Ok(PartialKeyImageResult {
        partial_key_image: hex::encode(partial_key_image_bytes),
        one_time_pubkey: one_time_pubkey_hex.to_string(),
        lagrange_applied: true,
    })
}

/// Compute partial key image WITH output secret derivation.
///
/// This is the CORRECT implementation for spending real Monero outputs.
/// The first signer must include the derivation term.
///
/// # Formula
/// ```text
/// D = 8 * a * R                           (shared secret with cofactor)
/// derivation = Hs(D || varint(idx))       (hash-to-scalar)
/// effective_spend = derivation + λ * s    (only spend share is weighted)
/// pKI = effective_spend * Hp(P)
/// ```
///
/// # Arguments
/// * `spend_key_hex` - Signer's private spend key share (hex, 32 bytes)
/// * `tx_pub_key_hex` - TX public key R from the funding transaction (hex, 32 bytes)
/// * `view_key_shared_hex` - Shared multisig view key a (hex, 32 bytes)
/// * `output_index` - Output index in the funding transaction (typically 0)
/// * `one_time_pubkey_hex` - The one-time output public key P (hex, 32 bytes)
/// * `lagrange_coefficient_hex` - FROST Lagrange coefficient `λ_i` (hex, 32 bytes)
///
/// # Note
/// Only the FIRST signer includes derivation to avoid double-counting.
/// The second signer uses `compute_partial_key_image` without derivation.
pub fn compute_partial_key_image_with_derivation(
    spend_key_hex: &str,
    tx_pub_key_hex: &str,
    view_key_shared_hex: &str,
    output_index: u64,
    one_time_pubkey_hex: &str,
    lagrange_coefficient_hex: &str,
) -> CryptoResult<PartialKeyImageWithDerivationResult> {
    // 1. Parse spend key
    let spend_bytes = hex::decode(spend_key_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid spend key hex: {e}")))?;

    if spend_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "spend_key".into(),
            expected: 32,
            actual: spend_bytes.len(),
        });
    }

    let mut spend_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // 2. Parse Lagrange coefficient
    let lambda_bytes = hex::decode(lagrange_coefficient_hex).map_err(|e| {
        CryptoError::HexDecodeFailed(format!("Invalid lagrange coefficient hex: {e}"))
    })?;

    if lambda_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "lagrange_coefficient".into(),
            expected: 32,
            actual: lambda_bytes.len(),
        });
    }

    let mut lambda_arr = [0u8; 32];
    lambda_arr.copy_from_slice(&lambda_bytes);
    let lambda = Scalar::from_bytes_mod_order(lambda_arr);

    // 3. Parse tx_pub_key (R)
    let tx_pub_bytes = hex::decode(tx_pub_key_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid tx_pub_key hex: {e}")))?;

    if tx_pub_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "tx_pub_key".into(),
            expected: 32,
            actual: tx_pub_bytes.len(),
        });
    }

    let mut tx_pub_arr = [0u8; 32];
    tx_pub_arr.copy_from_slice(&tx_pub_bytes);
    let tx_pub_point = CompressedEdwardsY(tx_pub_arr).decompress().ok_or_else(|| {
        CryptoError::InvalidPublicKey("tx_pub_key point decompression failed".into())
    })?;

    // 4. Parse shared view key
    let view_bytes = hex::decode(view_key_shared_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid view key hex: {e}")))?;

    if view_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "view_key".into(),
            expected: 32,
            actual: view_bytes.len(),
        });
    }

    let mut view_key_arr = [0u8; 32];
    view_key_arr.copy_from_slice(&view_bytes);
    let view_scalar = Scalar::from_bytes_mod_order(view_key_arr);

    // 5. Parse one_time_pubkey (P)
    let pubkey_bytes = hex::decode(one_time_pubkey_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid one_time_pubkey hex: {e}")))?;

    if pubkey_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "one_time_pubkey".into(),
            expected: 32,
            actual: pubkey_bytes.len(),
        });
    }

    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    // 6. Compute shared secret with cofactor: D = 8 * a * R
    let shared_secret_point = (view_scalar * tx_pub_point).mul_by_cofactor();
    let shared_secret_bytes = shared_secret_point.compress().to_bytes();

    // 7. Compute derivation scalar: Hs(D || varint(output_index))
    let mut hasher = Keccak256::new();
    hasher.update(shared_secret_bytes);
    hasher.update(encode_varint(output_index));
    let derivation_hash: [u8; 32] = hasher.finalize().into();
    let derivation_scalar = Scalar::from_bytes_mod_order(derivation_hash);

    // 8. Compute effective spend: derivation + λ * spend_share
    // Only spend share is weighted by Lagrange coefficient
    let weighted_spend = lambda * spend_scalar;
    let effective_spend_scalar = derivation_scalar + weighted_spend;

    // 9. Compute Hp(P)
    let hp = hash_to_point(pubkey_arr);

    // 10. Compute partial key image: pKI = effective_spend * Hp(P)
    let partial_key_image = effective_spend_scalar * hp;
    let partial_key_image_bytes = partial_key_image.compress().to_bytes();

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    view_key_arr.zeroize();
    lambda_arr.zeroize();

    Ok(PartialKeyImageWithDerivationResult {
        partial_key_image: hex::encode(partial_key_image_bytes),
        derivation_scalar: hex::encode(derivation_hash),
        one_time_pubkey: one_time_pubkey_hex.to_string(),
        lagrange_applied: true,
    })
}

/// Aggregate two partial key images.
///
/// For 2-of-3 FROST, the key image is:
/// ```text
/// KI = pKI_1 + pKI_2
/// ```
///
/// # Arguments
/// * `pki1_hex` - First partial key image (hex, 32 bytes)
/// * `pki2_hex` - Second partial key image (hex, 32 bytes)
///
/// # Returns
/// The aggregated key image (hex)
pub fn aggregate_partial_key_images(pki1_hex: &str, pki2_hex: &str) -> CryptoResult<String> {
    let pki1_bytes = hex::decode(pki1_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid pki1 hex: {e}")))?;

    if pki1_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "pki1".into(),
            expected: 32,
            actual: pki1_bytes.len(),
        });
    }

    let pki2_bytes = hex::decode(pki2_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid pki2 hex: {e}")))?;

    if pki2_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "pki2".into(),
            expected: 32,
            actual: pki2_bytes.len(),
        });
    }

    let mut arr1 = [0u8; 32];
    arr1.copy_from_slice(&pki1_bytes);
    let pki1_point = CompressedEdwardsY(arr1)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("pki1 point decompression failed".into()))?;

    let mut arr2 = [0u8; 32];
    arr2.copy_from_slice(&pki2_bytes);
    let pki2_point = CompressedEdwardsY(arr2)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("pki2 point decompression failed".into()))?;

    let aggregated = pki1_point + pki2_point;
    Ok(hex::encode(aggregated.compress().to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector: known scalar (NOT a real private key!)
    const TEST_SPEND_KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const TEST_PUBKEY: &str = "5866666666666666666666666666666666666666666666666666666666666666";
    const TEST_LAMBDA: &str = "0100000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_compute_key_image() {
        let result = compute_key_image(TEST_SPEND_KEY).unwrap();

        // Key image should be 64 hex chars (32 bytes)
        assert_eq!(result.key_image.len(), 64);
        assert_eq!(result.public_key.len(), 64);
    }

    #[test]
    fn test_compute_key_image_deterministic() {
        let result1 = compute_key_image(TEST_SPEND_KEY).unwrap();
        let result2 = compute_key_image(TEST_SPEND_KEY).unwrap();

        assert_eq!(result1.key_image, result2.key_image);
        assert_eq!(result1.public_key, result2.public_key);
    }

    #[test]
    fn test_compute_partial_key_image() {
        let result = compute_partial_key_image(TEST_SPEND_KEY, TEST_PUBKEY, TEST_LAMBDA).unwrap();

        assert_eq!(result.partial_key_image.len(), 64);
        assert!(result.lagrange_applied);
    }

    #[test]
    fn test_compute_partial_key_image_deterministic() {
        let result1 = compute_partial_key_image(TEST_SPEND_KEY, TEST_PUBKEY, TEST_LAMBDA).unwrap();
        let result2 = compute_partial_key_image(TEST_SPEND_KEY, TEST_PUBKEY, TEST_LAMBDA).unwrap();

        assert_eq!(result1.partial_key_image, result2.partial_key_image);
    }

    #[test]
    fn test_invalid_spend_key_length() {
        let result = compute_key_image("1234");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_spend_key_hex() {
        let result =
            compute_key_image("not_valid_hex_at_all_not_valid_hex_at_all_not_valid_hex_at_all_");
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_partial_key_images() {
        // Generate two partial key images with different "signers"
        let spend1 = "0100000000000000000000000000000000000000000000000000000000000000";
        let spend2 = "0200000000000000000000000000000000000000000000000000000000000000";

        let pki1 = compute_partial_key_image(spend1, TEST_PUBKEY, TEST_LAMBDA).unwrap();
        let pki2 = compute_partial_key_image(spend2, TEST_PUBKEY, TEST_LAMBDA).unwrap();

        let aggregated =
            aggregate_partial_key_images(&pki1.partial_key_image, &pki2.partial_key_image).unwrap();

        assert_eq!(aggregated.len(), 64);
    }

    #[test]
    fn test_compute_partial_key_image_with_derivation() {
        // Test vectors (not real keys!)
        let spend = "0100000000000000000000000000000000000000000000000000000000000000";
        let tx_pub = "5866666666666666666666666666666666666666666666666666666666666666";
        let view = "0200000000000000000000000000000000000000000000000000000000000000";
        let one_time = "5866666666666666666666666666666666666666666666666666666666666666";
        let lambda = "0100000000000000000000000000000000000000000000000000000000000000";

        let result =
            compute_partial_key_image_with_derivation(spend, tx_pub, view, 0, one_time, lambda)
                .unwrap();

        assert_eq!(result.partial_key_image.len(), 64);
        assert_eq!(result.derivation_scalar.len(), 64);
        assert!(result.lagrange_applied);
    }
}
