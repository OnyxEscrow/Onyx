//! Output ownership verification and mask derivation
//!
//! This module provides functionality to identify which transaction outputs
//! belong to a multisig address and derive the corresponding commitment masks.

use alloc::string::String;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

use crate::types::errors::{CryptoError, CryptoResult};
use super::derivation::derive_commitment_mask;
use super::amounts::decode_encrypted_amount_bytes;
use super::utils::{encode_varint, extract_spend_pub_from_address};

/// Result of output ownership verification and mask derivation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputOwnershipResult {
    /// The output index that belongs to us
    pub output_index: u64,
    /// The derived commitment mask for that output
    pub commitment_mask: String,
    /// The decoded amount (if decoding succeeded)
    pub decoded_amount: Option<u64>,
}

/// Find our output in a transaction and derive the commitment mask
///
/// This function iterates over all transaction outputs, checks ownership
/// using the output key verification (P = Hs(derivation || i) * G + B),
/// and derives the commitment mask for the output that belongs to us.
///
/// # Arguments
///
/// * `view_key_priv_hex` - The private view key (64 hex chars)
/// * `tx_pub_key_hex` - The transaction public key R (64 hex chars)
/// * `multisig_address` - The multisig address (to extract spend public key)
/// * `output_keys` - List of output public keys from the transaction (each 64 hex chars)
/// * `encrypted_amounts` - Optional: encrypted amounts from ecdhInfo (8 bytes each, hex encoded)
///
/// # Returns
///
/// `OutputOwnershipResult` containing the output_index and derived mask,
/// or an error if no matching output is found.
///
/// # Output Key Verification Formula
///
/// For each output index i:
/// ```text
/// 1. shared_secret = Hs(derivation || varint(i))
/// 2. expected_key = shared_secret * G + B (where B is spend public key)
/// 3. If expected_key == output_key[i], this output is ours
/// ```
pub fn find_our_output_and_derive_mask(
    view_key_priv_hex: &str,
    tx_pub_key_hex: &str,
    multisig_address: &str,
    output_keys: &[String],
    encrypted_amounts: Option<&[String]>,
) -> CryptoResult<OutputOwnershipResult> {
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

    // Extract spend public key from multisig address
    let spend_pub_bytes = extract_spend_pub_from_address(multisig_address)?;
    let spend_pub_point = CompressedEdwardsY(spend_pub_bytes)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("Spend public key decompression failed".into()))?;

    // Compute derivation: D = 8 * view_priv * tx_pub_key
    let shared_point = view_scalar * tx_pub_point;
    let derivation = shared_point.mul_by_cofactor();
    let derivation_bytes = derivation.compress().to_bytes();

    // Try each output index
    for (idx, output_key_hex) in output_keys.iter().enumerate() {
        let output_idx = idx as u64;

        // Parse on-chain output key
        let onchain_key_bytes = match hex::decode(output_key_hex) {
            Ok(bytes) => bytes,
            Err(_) => continue, // Skip invalid output
        };
        if onchain_key_bytes.len() != 32 {
            continue; // Skip invalid output
        }

        // Compute expected one-time output key: P = Hs(derivation || i) * G + B
        let mut hasher = Keccak256::new();
        hasher.update(&derivation_bytes);
        hasher.update(&encode_varint(output_idx));
        let shared_secret: [u8; 32] = hasher.finalize().into();
        let scalar = Scalar::from_bytes_mod_order(shared_secret);

        let scalar_g = scalar * ED25519_BASEPOINT_POINT;
        let expected_output_key = scalar_g + spend_pub_point;
        let expected_output_key_hex = hex::encode(expected_output_key.compress().to_bytes());

        // Check if this output belongs to us
        if expected_output_key_hex == *output_key_hex {
            // Found our output! Derive the mask
            let mask = derive_commitment_mask(view_key_priv_hex, tx_pub_key_hex, output_idx)?;

            // Optionally decode the amount
            let decoded_amount = if let Some(amounts) = encrypted_amounts {
                if let Some(encrypted_hex) = amounts.get(idx) {
                    let encrypted = match hex::decode(encrypted_hex) {
                        Ok(bytes) if bytes.len() >= 8 => bytes,
                        _ => return Ok(OutputOwnershipResult {
                            output_index: output_idx,
                            commitment_mask: mask,
                            decoded_amount: None,
                        }),
                    };
                    decode_encrypted_amount_bytes(&derivation_bytes, output_idx, &encrypted).ok()
                } else {
                    None
                }
            } else {
                None
            };

            return Ok(OutputOwnershipResult {
                output_index: output_idx,
                commitment_mask: mask,
                decoded_amount,
            });
        }
    }

    Err(CryptoError::MaskDerivationFailed(
        "No matching output found - none of the outputs belong to our address".into()
    ))
}

/// Find our output by view tag (fast path)
///
/// Uses the view tag for efficient pre-filtering before full derivation.
/// This is an optimization for scanning large numbers of transactions.
///
/// # Arguments
///
/// * `view_key_priv_hex` - The private view key
/// * `tx_pub_key_hex` - The transaction public key
/// * `multisig_address` - The multisig address
/// * `output_keys` - List of output public keys
/// * `view_tags` - View tags for each output (1 byte each)
/// * `encrypted_amounts` - Optional encrypted amounts
///
/// # Returns
///
/// Same as `find_our_output_and_derive_mask` but faster for non-matching outputs.
pub fn find_our_output_by_view_tag(
    view_key_priv_hex: &str,
    tx_pub_key_hex: &str,
    multisig_address: &str,
    output_keys: &[String],
    view_tags: &[u8],
    encrypted_amounts: Option<&[String]>,
) -> CryptoResult<OutputOwnershipResult> {
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
    let tx_pub_array: [u8; 32] = tx_pub_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey("Tx pub key conversion failed".into()))?;
    let tx_pub_point = CompressedEdwardsY(tx_pub_array)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("Point decompression failed".into()))?;

    // Extract spend public key
    let spend_pub_bytes = extract_spend_pub_from_address(multisig_address)?;
    let spend_pub_point = CompressedEdwardsY(spend_pub_bytes)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("Spend public key decompression failed".into()))?;

    // Compute derivation
    let shared_point = view_scalar * tx_pub_point;
    let derivation = shared_point.mul_by_cofactor();
    let derivation_bytes = derivation.compress().to_bytes();

    // Try outputs that match the view tag first (fast path)
    for (idx, output_key_hex) in output_keys.iter().enumerate() {
        let output_idx = idx as u64;

        // Compute expected view tag
        let mut hasher = Keccak256::new();
        hasher.update(&derivation_bytes);
        hasher.update(&encode_varint(output_idx));
        let shared_secret: [u8; 32] = hasher.finalize().into();
        let expected_view_tag = shared_secret[0];

        // Skip if view tag doesn't match (fast rejection)
        if let Some(&on_chain_tag) = view_tags.get(idx) {
            if on_chain_tag != expected_view_tag {
                continue;
            }
        }

        // View tag matches, do full verification
        let onchain_key_bytes: [u8; 32] = match hex::decode(output_key_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => continue,
        };

        let scalar = Scalar::from_bytes_mod_order(shared_secret);
        let scalar_g = scalar * ED25519_BASEPOINT_POINT;
        let expected_output_key = scalar_g + spend_pub_point;
        let expected_output_key_bytes = expected_output_key.compress().to_bytes();

        if expected_output_key_bytes == onchain_key_bytes {
            let mask = derive_commitment_mask(view_key_priv_hex, tx_pub_key_hex, output_idx)?;

            let decoded_amount = if let Some(amounts) = encrypted_amounts {
                if let Some(encrypted_hex) = amounts.get(idx) {
                    hex::decode(encrypted_hex)
                        .ok()
                        .and_then(|encrypted| {
                            decode_encrypted_amount_bytes(&derivation_bytes, output_idx, &encrypted).ok()
                        })
                } else {
                    None
                }
            } else {
                None
            };

            return Ok(OutputOwnershipResult {
                output_index: output_idx,
                commitment_mask: mask,
                decoded_amount,
            });
        }
    }

    Err(CryptoError::MaskDerivationFailed(
        "No matching output found".into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_find_our_output_stagenet() {
        // Real data from stagenet escrow
        let view_key = "b7f874f9baea745f0e7e6817014e563384d90658045304a978d196346d513f06";
        let tx_pub_key = "a4eb6c9c4b388f65b517897ad064b66478fe83a8844265988dcaed13f7428abd";
        let address = "54FYy396FN5SXMhYsCgY49JzH2FyPM9ei14guJpsTCY8jGXbfDKsTNfdeAWJ5ThRLr9ye95tb5yWWUAzcS5vdJdkEaqYhKj";

        // On-chain output keys
        let output_keys = vec![
            "31a6ef3f4b55665225bb4235111539e668cd89d08975b7062479b88849c3eb4c".to_string(),
            "1ba8ba77bf373920a84462077713e24144c418ec715d03972f22d4738c262142".to_string(),
        ];

        // Encrypted amounts
        let encrypted_amounts = vec![
            "3f2c482745a0ef9e".to_string(),
            "6896a8310b1c55f4".to_string(),
        ];

        let result = find_our_output_and_derive_mask(
            view_key,
            tx_pub_key,
            address,
            &output_keys,
            Some(&encrypted_amounts),
        );

        assert!(result.is_ok(), "Should find our output");
        let ownership = result.unwrap();

        // Output 1 belongs to us (not output 0)
        assert_eq!(ownership.output_index, 1, "Output 1 should be ours");
        assert_eq!(ownership.commitment_mask.len(), 64, "Mask should be 64 hex chars");

        // Verify decoded amount
        assert_eq!(ownership.decoded_amount, Some(2000000000), "Amount should be 0.002 XMR");
    }

    #[test]
    fn test_find_our_output_not_found() {
        let view_key = "0100000000000000000000000000000000000000000000000000000000000000";
        let tx_pub_key = "5866666666666666666666666666666666666666666666666666666666666666";
        let address = "54FYy396FN5SXMhYsCgY49JzH2FyPM9ei14guJpsTCY8jGXbfDKsTNfdeAWJ5ThRLr9ye95tb5yWWUAzcS5vdJdkEaqYhKj";

        // Random output keys that don't belong to us
        let output_keys = vec![
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        ];

        let result = find_our_output_and_derive_mask(
            view_key,
            tx_pub_key,
            address,
            &output_keys,
            None,
        );

        assert!(result.is_err(), "Should not find our output");
        assert!(matches!(result, Err(CryptoError::MaskDerivationFailed(_))));
    }

    #[test]
    fn test_find_output_by_view_tag() {
        use super::super::amounts::compute_view_tag;
        use super::super::derivation::compute_derivation;

        let view_key = "b7f874f9baea745f0e7e6817014e563384d90658045304a978d196346d513f06";
        let tx_pub_key = "a4eb6c9c4b388f65b517897ad064b66478fe83a8844265988dcaed13f7428abd";
        let address = "54FYy396FN5SXMhYsCgY49JzH2FyPM9ei14guJpsTCY8jGXbfDKsTNfdeAWJ5ThRLr9ye95tb5yWWUAzcS5vdJdkEaqYhKj";

        let output_keys = vec![
            "31a6ef3f4b55665225bb4235111539e668cd89d08975b7062479b88849c3eb4c".to_string(),
            "1ba8ba77bf373920a84462077713e24144c418ec715d03972f22d4738c262142".to_string(),
        ];

        // Compute view tags from our derivation (not from on-chain data)
        // In production, these would come from the blockchain
        let derivation = compute_derivation(view_key, tx_pub_key).unwrap();
        let view_tags = vec![
            compute_view_tag(&derivation, 0),
            compute_view_tag(&derivation, 1),
        ];

        let encrypted_amounts = vec![
            "3f2c482745a0ef9e".to_string(),
            "6896a8310b1c55f4".to_string(),
        ];

        let result = find_our_output_by_view_tag(
            view_key,
            tx_pub_key,
            address,
            &output_keys,
            &view_tags,
            Some(&encrypted_amounts),
        );

        assert!(result.is_ok(), "Should find output by view tag");
        let ownership = result.unwrap();
        assert_eq!(ownership.output_index, 1);
    }

    #[test]
    fn test_output_ownership_result_equality() {
        let r1 = OutputOwnershipResult {
            output_index: 1,
            commitment_mask: "abc123".into(),
            decoded_amount: Some(1000),
        };

        let r2 = OutputOwnershipResult {
            output_index: 1,
            commitment_mask: "abc123".into(),
            decoded_amount: Some(1000),
        };

        assert_eq!(r1, r2);
    }
}
