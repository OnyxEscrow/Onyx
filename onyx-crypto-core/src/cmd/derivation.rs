//! Core commitment mask derivation function
//!
//! This is the fundamental operation enabling zero-friction escrow funding.
//! The server can derive the mask silently without any user interaction.

use alloc::string::String;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

use super::utils::encode_varint;
use crate::types::errors::{CryptoError, CryptoResult};

/// Derive the commitment mask from view key and tx_pub_key
///
/// This is the core function that enables zero-friction escrow funding.
/// The server can derive the mask silently without any user interaction.
///
/// # Arguments
///
/// * `view_key_priv_hex` - The private view key (64 hex chars)
/// * `tx_pub_key_hex` - The transaction public key R (64 hex chars, from tx extra field)
/// * `output_index` - The index of the output in the transaction (usually 0)
///
/// # Returns
///
/// The commitment mask as a 64-character hex string
///
/// # Derivation Formula (Monero-compatible)
///
/// ```text
/// 1. derivation = 8 * view_priv * tx_pub_key (point, cofactor applied)
/// 2. shared_secret = Hs(derivation || varint(output_index)) (scalar)
/// 3. mask = Hs("commitment_mask" || shared_secret)
/// ```
///
/// # Example
///
/// ```rust,ignore
/// use onyx_crypto_core::cmd::derive_commitment_mask;
///
/// let view_key = "b7f874f9baea745f0e7e6817014e563384d90658045304a978d196346d513f06";
/// let tx_pub_key = "a4eb6c9c4b388f65b517897ad064b66478fe83a8844265988dcaed13f7428abd";
///
/// let mask = derive_commitment_mask(view_key, tx_pub_key, 0)?;
/// assert_eq!(mask.len(), 64); // 32 bytes as hex
/// ```
pub fn derive_commitment_mask(
    view_key_priv_hex: &str,
    tx_pub_key_hex: &str,
    output_index: u64,
) -> CryptoResult<String> {
    // 1. Parse view key (scalar) - 32 bytes from hex
    let view_key_bytes = hex::decode(view_key_priv_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(alloc::format!("view_key: {}", e)))?;

    if view_key_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "view_key".into(),
            expected: 32,
            actual: view_key_bytes.len(),
        });
    }

    let view_key_array: [u8; 32] = view_key_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSecretKey("View key conversion failed".into()))?;

    let view_scalar = Scalar::from_bytes_mod_order(view_key_array);

    // 2. Parse tx_pub_key (compressed Edwards point) - 32 bytes from hex
    let tx_pub_bytes = hex::decode(tx_pub_key_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(alloc::format!("tx_pub_key: {}", e)))?;

    if tx_pub_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "tx_pub_key".into(),
            expected: 32,
            actual: tx_pub_bytes.len(),
        });
    }

    let tx_pub_array: [u8; 32] = tx_pub_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey("Tx pub key conversion failed".into()))?;

    let tx_pub_compressed = CompressedEdwardsY(tx_pub_array);

    let tx_pub_point = tx_pub_compressed
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("Point decompression failed".into()))?;

    // 3. Compute derivation: D = 8 * a * R (view_priv * tx_pub_key with cofactor)
    let shared_point = view_scalar * tx_pub_point;
    let derivation = shared_point.mul_by_cofactor();

    // 4. Compute shared_secret = Hs(derivation || varint(output_index))
    // This is Monero's derivation_to_scalar function
    let mut scalar_hasher = Keccak256::new();
    scalar_hasher.update(derivation.compress().as_bytes());
    let varint_index = encode_varint(output_index);
    scalar_hasher.update(&varint_index);
    let shared_secret: [u8; 32] = scalar_hasher.finalize().into();

    // 5. Reduce to scalar (sc_reduce32 in Monero)
    let shared_secret_scalar = Scalar::from_bytes_mod_order(shared_secret);

    // 6. Compute mask = Hs("commitment_mask" || shared_secret)
    // This is Monero's genCommitmentMask function
    let mut mask_hasher = Keccak256::new();
    mask_hasher.update(b"commitment_mask");
    mask_hasher.update(shared_secret_scalar.as_bytes());
    let mask_bytes: [u8; 32] = mask_hasher.finalize().into();

    // 7. Reduce to scalar (mod curve order l)
    let mask_scalar = Scalar::from_bytes_mod_order(mask_bytes);

    Ok(hex::encode(mask_scalar.as_bytes()))
}

/// Compute the derivation point (D = 8 * a * R)
///
/// This intermediate value is used by multiple CMD operations.
/// Exposed for advanced use cases requiring the raw derivation.
///
/// # Arguments
///
/// * `view_key_priv_hex` - The private view key (64 hex chars)
/// * `tx_pub_key_hex` - The transaction public key R (64 hex chars)
///
/// # Returns
///
/// The 32-byte derivation point (compressed Edwards Y)
pub fn compute_derivation(view_key_priv_hex: &str, tx_pub_key_hex: &str) -> CryptoResult<[u8; 32]> {
    // Parse view key
    let view_key_bytes = hex::decode(view_key_priv_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(alloc::format!("view_key: {}", e)))?;

    if view_key_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "view_key".into(),
            expected: 32,
            actual: view_key_bytes.len(),
        });
    }

    let view_key_array: [u8; 32] = view_key_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSecretKey("View key conversion failed".into()))?;

    let view_scalar = Scalar::from_bytes_mod_order(view_key_array);

    // Parse tx_pub_key
    let tx_pub_bytes = hex::decode(tx_pub_key_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(alloc::format!("tx_pub_key: {}", e)))?;

    if tx_pub_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "tx_pub_key".into(),
            expected: 32,
            actual: tx_pub_bytes.len(),
        });
    }

    let tx_pub_array: [u8; 32] = tx_pub_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey("Tx pub key conversion failed".into()))?;

    let tx_pub_point = CompressedEdwardsY(tx_pub_array)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("Point decompression failed".into()))?;

    // D = 8 * a * R
    let shared_point = view_scalar * tx_pub_point;
    let derivation = shared_point.mul_by_cofactor();

    Ok(derivation.compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_commitment_mask_basic() {
        // Test with synthetic data - verifies the function doesn't panic
        // Real validation requires actual Monero test vectors

        // Generate a synthetic view key (not cryptographically meaningful)
        let view_key = "0100000000000000000000000000000000000000000000000000000000000000";

        // Use the ed25519 basepoint as tx_pub_key (known valid point)
        // Basepoint compressed: 5866666666666666666666666666666666666666666666666666666666666666
        let tx_pub_key = "5866666666666666666666666666666666666666666666666666666666666666";

        let result = derive_commitment_mask(view_key, tx_pub_key, 0);
        assert!(result.is_ok(), "Should derive mask without error");

        let mask = result.unwrap();
        assert_eq!(mask.len(), 64, "Mask should be 64 hex chars (32 bytes)");

        // Verify it's valid hex
        assert!(hex::decode(&mask).is_ok(), "Mask should be valid hex");
    }

    #[test]
    fn test_invalid_view_key_length() {
        let view_key = "0100"; // Too short
        let tx_pub_key = "5866666666666666666666666666666666666666666666666666666666666666";

        let result = derive_commitment_mask(view_key, tx_pub_key, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_tx_pub_key() {
        let view_key = "0100000000000000000000000000000000000000000000000000000000000000";
        let tx_pub_key = "invalid_hex";

        let result = derive_commitment_mask(view_key, tx_pub_key, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_output_indices_produce_different_masks() {
        let view_key = "0100000000000000000000000000000000000000000000000000000000000000";
        let tx_pub_key = "5866666666666666666666666666666666666666666666666666666666666666";

        let mask_0 = derive_commitment_mask(view_key, tx_pub_key, 0).unwrap();
        let mask_1 = derive_commitment_mask(view_key, tx_pub_key, 1).unwrap();

        assert_ne!(
            mask_0, mask_1,
            "Different output indices should produce different masks"
        );
    }

    #[test]
    fn test_real_stagenet_escrow_mask() {
        // Real data from stagenet escrow 80c90464-6f4a-42ee-8c2e-9579c56b3ce9
        // tx_hash: b833ae6cb0d2f7cee2ef5efc0e281bb035664f652b153e3b14ec0e0ed6f0893e
        let view_key = "b7f874f9baea745f0e7e6817014e563384d90658045304a978d196346d513f06";
        let tx_pub_key = "a4eb6c9c4b388f65b517897ad064b66478fe83a8844265988dcaed13f7428abd";

        let result = derive_commitment_mask(view_key, tx_pub_key, 0);
        assert!(result.is_ok(), "Should derive mask for real stagenet data");

        let mask = result.unwrap();
        assert_eq!(mask.len(), 64, "Mask should be 64 hex chars");
        assert!(hex::decode(&mask).is_ok(), "Mask should be valid hex");
    }

    #[test]
    fn test_compute_derivation() {
        let view_key = "0100000000000000000000000000000000000000000000000000000000000000";
        let tx_pub_key = "5866666666666666666666666666666666666666666666666666666666666666";

        let result = compute_derivation(view_key, tx_pub_key);
        assert!(result.is_ok());

        let derivation = result.unwrap();
        assert_eq!(derivation.len(), 32);
    }
}
