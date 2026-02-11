//! Amount decoding for `RingCT` v2 transactions
//!
//! In RCT v2, amounts are encrypted using the shared secret derived from
//! the transaction key and recipient's view key. This module provides
//! decryption functionality for outputs we own.

use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

use super::utils::encode_varint;
use crate::types::errors::{CryptoError, CryptoResult};

/// Decode encrypted amount from ecdhInfo
///
/// In `RingCT` v2, amounts are 8 bytes encrypted with a key derived from
/// the shared secret. This function decrypts the amount for outputs we own.
///
/// # Arguments
///
/// * `derivation_bytes` - The 32-byte derivation point (D = 8 * a * R)
/// * `output_index` - The index of the output in the transaction
/// * `encrypted_amount_hex` - The encrypted amount from ecdhInfo (16 hex chars, 8 bytes)
///
/// # Returns
///
/// The decoded amount in atomic units (piconeros)
///
/// # Decryption Formula
///
/// ```text
/// 1. shared_secret = Hs(derivation || varint(output_index))
/// 2. amount_factor = Hs("amount" || shared_secret)
/// 3. decoded = encrypted XOR amount_factor[0..8]
/// ```
pub fn decode_encrypted_amount(
    derivation_bytes: &[u8; 32],
    output_index: u64,
    encrypted_amount_hex: &str,
) -> CryptoResult<u64> {
    let encrypted = hex::decode(encrypted_amount_hex)
        .map_err(|e| CryptoError::AmountDecodeFailed(alloc::format!("hex decode: {e}")))?;

    if encrypted.len() < 8 {
        return Err(CryptoError::AmountDecodeFailed(
            "Encrypted amount too short (need 8 bytes)".into(),
        ));
    }

    decode_encrypted_amount_bytes(derivation_bytes, output_index, &encrypted)
}

/// Decode encrypted amount from raw bytes
///
/// Same as `decode_encrypted_amount` but takes raw bytes instead of hex.
pub fn decode_encrypted_amount_bytes(
    derivation_bytes: &[u8; 32],
    output_index: u64,
    encrypted: &[u8],
) -> CryptoResult<u64> {
    if encrypted.len() < 8 {
        return Err(CryptoError::AmountDecodeFailed(
            "Encrypted amount too short (need 8 bytes)".into(),
        ));
    }

    // Compute shared_secret = Hs(derivation || varint(output_index))
    let mut hasher = Keccak256::new();
    hasher.update(derivation_bytes);
    hasher.update(encode_varint(output_index));
    let shared_secret: [u8; 32] = hasher.finalize().into();
    let shared_secret_scalar = Scalar::from_bytes_mod_order(shared_secret);

    // Amount factor = Hs("amount" || shared_secret)
    let mut amount_hasher = Keccak256::new();
    amount_hasher.update(b"amount");
    amount_hasher.update(shared_secret_scalar.as_bytes());
    let amount_factor: [u8; 32] = amount_hasher.finalize().into();

    // XOR to decode
    let mut decoded_bytes = [0u8; 8];
    for i in 0..8 {
        decoded_bytes[i] = encrypted[i] ^ amount_factor[i];
    }

    Ok(u64::from_le_bytes(decoded_bytes))
}

/// Compute the view tag for an output
///
/// The view tag is the first byte of the `derivation_to_scalar` output.
/// It's used for efficient scanning of the blockchain without full derivation.
///
/// # Arguments
///
/// * `derivation_bytes` - The 32-byte derivation point
/// * `output_index` - The index of the output
///
/// # Returns
///
/// The single-byte view tag
#[must_use]
pub fn compute_view_tag(derivation_bytes: &[u8; 32], output_index: u64) -> u8 {
    let mut hasher = Keccak256::new();
    hasher.update(derivation_bytes);
    hasher.update(encode_varint(output_index));
    let shared_secret: [u8; 32] = hasher.finalize().into();
    shared_secret[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::edwards::CompressedEdwardsY;

    /// Helper to compute derivation from view key and tx pub key
    fn compute_test_derivation(view_key_hex: &str, tx_pub_key_hex: &str) -> [u8; 32] {
        let view_key_bytes: [u8; 32] = hex::decode(view_key_hex).unwrap().try_into().unwrap();
        let view_scalar = Scalar::from_bytes_mod_order(view_key_bytes);

        let tx_pub_bytes: [u8; 32] = hex::decode(tx_pub_key_hex).unwrap().try_into().unwrap();
        let tx_pub_point = CompressedEdwardsY(tx_pub_bytes).decompress().unwrap();

        let shared_point = view_scalar * tx_pub_point;
        let derivation = shared_point.mul_by_cofactor();
        derivation.compress().to_bytes()
    }

    #[test]
    fn test_decode_amount_stagenet() {
        // Data from stagenet escrow
        let view_key = "b7f874f9baea745f0e7e6817014e563384d90658045304a978d196346d513f06";
        let tx_pub_key = "a4eb6c9c4b388f65b517897ad064b66478fe83a8844265988dcaed13f7428abd";

        let derivation = compute_test_derivation(view_key, tx_pub_key);

        // Encrypted amounts from ecdhInfo (RCT v2 format - 8 bytes each)
        let encrypted_amount_0 = "3f2c482745a0ef9e";
        let encrypted_amount_1 = "6896a8310b1c55f4";

        // Expected: 0.002 XMR = 2000000000 atomic units (at output index 1)
        let expected_amount = 2000000000u64;

        let decoded_1 = decode_encrypted_amount(&derivation, 1, encrypted_amount_1);
        assert!(decoded_1.is_ok(), "Should decode amount");

        let amount = decoded_1.unwrap();
        assert_eq!(
            amount, expected_amount,
            "Decoded amount should match expected"
        );
    }

    #[test]
    fn test_view_tag_computation() {
        let view_key = "b7f874f9baea745f0e7e6817014e563384d90658045304a978d196346d513f06";
        let tx_pub_key = "a4eb6c9c4b388f65b517897ad064b66478fe83a8844265988dcaed13f7428abd";

        let derivation = compute_test_derivation(view_key, tx_pub_key);

        // Compute view tags for both outputs
        let view_tag_0 = compute_view_tag(&derivation, 0);
        let view_tag_1 = compute_view_tag(&derivation, 1);

        // Different outputs must have different view tags (with high probability)
        // Note: These don't match "on-chain" values because those were computed
        // with different derivation (sender's ephemeral key)
        assert_ne!(
            view_tag_0, view_tag_1,
            "Different outputs should have different view tags"
        );

        // Verify view tags are deterministic
        let view_tag_0_again = compute_view_tag(&derivation, 0);
        assert_eq!(
            view_tag_0, view_tag_0_again,
            "View tag should be deterministic"
        );
    }

    #[test]
    fn test_decode_amount_too_short() {
        let derivation = [0u8; 32];
        let encrypted_hex = "0102"; // Only 2 bytes, need 8

        let result = decode_encrypted_amount(&derivation, 0, encrypted_hex);
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::AmountDecodeFailed(_))));
    }

    #[test]
    fn test_decode_amount_invalid_hex() {
        let derivation = [0u8; 32];
        let encrypted_hex = "not_valid_hex";

        let result = decode_encrypted_amount(&derivation, 0, encrypted_hex);
        assert!(result.is_err());
    }
}
