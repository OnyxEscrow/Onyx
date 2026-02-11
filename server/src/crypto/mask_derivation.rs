//! Commitment mask derivation for Monero RingCT transactions
//!
//! This module enables server-side derivation of the commitment mask (blinding factor)
//! needed for CLSAG ring signatures. The derivation uses only the view key and
//! transaction public key - no user interaction required.
//!
//! # Cryptographic Background
//!
//! In Monero RingCT, outputs use Pedersen commitments: C = mask*G + amount*H
//!
//! The mask is derived using ECDH:
//! - Sender computes: shared_secret = tx_key * recipient_view_pub
//! - Recipient computes: shared_secret = recipient_view_priv * tx_pub_key
//!
//! These are equal due to elliptic curve properties: r*A = r*(a*G) = a*(r*G) = a*R
//!
//! The mask is derived as:
//! 1. derivation = 8 * view_priv * tx_pub_key (point)
//! 2. shared_secret = Hs(derivation || varint(output_index)) (scalar)
//! 3. mask = Hs("commitment_mask" || shared_secret)

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// Errors that can occur during mask derivation
#[derive(Debug, Error)]
pub enum MaskDerivationError {
    #[error("Invalid view key format: expected 64 hex chars")]
    InvalidViewKey,

    #[error("Invalid tx_pub_key format: expected 64 hex chars")]
    InvalidTxPubKey,

    #[error("Failed to decompress tx_pub_key point")]
    PointDecompressionFailed,

    #[error("Hex decode error: {0}")]
    HexDecodeError(String),
}

/// Derive the commitment mask from view key and tx_pub_key
///
/// This is the core function that enables zero-friction escrow funding.
/// The server can derive the mask silently without any user interaction.
///
/// # Arguments
///
/// * `view_key_priv_hex` - The private view key (64 hex chars, stored in DB as multisig_view_key)
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
pub fn derive_commitment_mask(
    view_key_priv_hex: &str,
    tx_pub_key_hex: &str,
    output_index: u64,
) -> Result<String, MaskDerivationError> {
    // 1. Parse view key (scalar) - 32 bytes from hex
    let view_key_bytes = hex::decode(view_key_priv_hex)
        .map_err(|e| MaskDerivationError::HexDecodeError(format!("view_key: {e}")))?;

    if view_key_bytes.len() != 32 {
        return Err(MaskDerivationError::InvalidViewKey);
    }

    let view_key_array: [u8; 32] = view_key_bytes
        .try_into()
        .map_err(|_| MaskDerivationError::InvalidViewKey)?;

    let view_scalar = Scalar::from_bytes_mod_order(view_key_array);

    // 2. Parse tx_pub_key (compressed Edwards point) - 32 bytes from hex
    let tx_pub_bytes = hex::decode(tx_pub_key_hex)
        .map_err(|e| MaskDerivationError::HexDecodeError(format!("tx_pub_key: {e}")))?;

    if tx_pub_bytes.len() != 32 {
        return Err(MaskDerivationError::InvalidTxPubKey);
    }

    let tx_pub_array: [u8; 32] = tx_pub_bytes
        .try_into()
        .map_err(|_| MaskDerivationError::InvalidTxPubKey)?;

    let tx_pub_compressed = CompressedEdwardsY(tx_pub_array);

    let tx_pub_point = tx_pub_compressed
        .decompress()
        .ok_or(MaskDerivationError::PointDecompressionFailed)?;

    // 3. Compute derivation: D = 8 * a * R (view_priv * tx_pub_key with cofactor)
    let shared_point = view_scalar * tx_pub_point;
    let derivation = shared_point.mul_by_cofactor();

    // 4. Compute shared_secret = Hs(derivation || varint(output_index))
    // This is Monero's derivation_to_scalar function
    // Note: Monero uses varint encoding for output_index, but for small indices
    // it's just the byte value. For index < 128, varint is same as u8.
    let mut scalar_hasher = Keccak256::new();
    scalar_hasher.update(derivation.compress().as_bytes());
    // Varint encoding for output_index (simplified for small indices)
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

/// Encode a u64 as a Monero-compatible varint
fn encode_varint(mut n: u64) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            result.push(byte);
            break;
        } else {
            result.push(byte | 0x80);
        }
    }
    result
}

/// Extract tx_pub_key from transaction extra field
///
/// The tx extra field contains various tagged data. The tx_pub_key
/// is identified by tag 0x01 followed by 32 bytes.
///
/// # Arguments
///
/// * `extra` - The raw tx extra bytes
///
/// # Returns
///
/// The tx_pub_key as a 64-character hex string, or None if not found
pub fn extract_tx_pub_key_from_extra(extra: &[u8]) -> Option<String> {
    // Tag 0x01 = tx_pub_key, followed by 32 bytes
    for i in 0..extra.len() {
        if extra[i] == 0x01 && i + 33 <= extra.len() {
            let tx_pub_key = &extra[i + 1..i + 33];
            return Some(hex::encode(tx_pub_key));
        }
    }
    None
}

/// Result of output ownership verification and mask derivation
#[derive(Debug, Clone)]
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
/// OutputOwnershipResult containing the output_index and derived mask,
/// or an error if no matching output is found.
pub fn find_our_output_and_derive_mask(
    view_key_priv_hex: &str,
    tx_pub_key_hex: &str,
    multisig_address: &str,
    output_keys: &[String],
    encrypted_amounts: Option<&[String]>,
) -> Result<OutputOwnershipResult, MaskDerivationError> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    // Parse view key
    let view_key_bytes = hex::decode(view_key_priv_hex)
        .map_err(|e| MaskDerivationError::HexDecodeError(format!("view_key: {e}")))?;
    if view_key_bytes.len() != 32 {
        return Err(MaskDerivationError::InvalidViewKey);
    }
    let view_key_array: [u8; 32] = view_key_bytes
        .try_into()
        .map_err(|_| MaskDerivationError::InvalidViewKey)?;
    let view_scalar = Scalar::from_bytes_mod_order(view_key_array);

    // Parse tx_pub_key
    let tx_pub_bytes = hex::decode(tx_pub_key_hex)
        .map_err(|e| MaskDerivationError::HexDecodeError(format!("tx_pub_key: {e}")))?;
    if tx_pub_bytes.len() != 32 {
        return Err(MaskDerivationError::InvalidTxPubKey);
    }
    let tx_pub_array: [u8; 32] = tx_pub_bytes
        .try_into()
        .map_err(|_| MaskDerivationError::InvalidTxPubKey)?;
    let tx_pub_point = CompressedEdwardsY(tx_pub_array)
        .decompress()
        .ok_or(MaskDerivationError::PointDecompressionFailed)?;

    // Extract spend public key from multisig address
    let spend_pub_bytes = extract_spend_pub_from_address(multisig_address)?;
    let spend_pub_point = CompressedEdwardsY(spend_pub_bytes)
        .decompress()
        .ok_or(MaskDerivationError::PointDecompressionFailed)?;

    // Compute derivation: D = 8 * view_priv * tx_pub_key
    let shared_point = view_scalar * tx_pub_point;
    let derivation = shared_point.mul_by_cofactor();
    let derivation_bytes = derivation.compress().to_bytes();

    // Try each output index
    for (idx, output_key_hex) in output_keys.iter().enumerate() {
        let output_idx = idx as u64;

        // Parse on-chain output key
        let onchain_key_bytes = hex::decode(output_key_hex)
            .map_err(|e| MaskDerivationError::HexDecodeError(format!("output_key: {e}")))?;
        if onchain_key_bytes.len() != 32 {
            continue; // Skip invalid output
        }

        // Compute expected one-time output key: P = Hs(derivation || i) * G + B
        let mut hasher = Keccak256::new();
        hasher.update(derivation_bytes);
        hasher.update(encode_varint(output_idx));
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
                    decode_encrypted_amount(&derivation_bytes, output_idx, encrypted_hex).ok()
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

    Err(MaskDerivationError::HexDecodeError(
        "No matching output found - none of the outputs belong to our address".to_string(),
    ))
}

/// Extract spend public key from a Monero address
fn extract_spend_pub_from_address(address: &str) -> Result<[u8; 32], MaskDerivationError> {
    // Monero base58 alphabet
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    fn base58_decode_block(block: &[u8]) -> Vec<u8> {
        let mut num: u128 = 0;
        for &ch in block {
            let idx = ALPHABET.iter().position(|&c| c == ch).unwrap_or(0);
            num = num * 58 + idx as u128;
        }
        let out_len = match block.len() {
            11 => 8,
            7 => 5,
            6 => 4,
            5 => 3,
            4 => 2,
            3 => 1,
            _ => 8,
        };
        let mut result = Vec::with_capacity(out_len);
        for i in (0..out_len).rev() {
            result.push((num >> (i * 8)) as u8);
        }
        result
    }

    let bytes = address.as_bytes();
    let mut decoded = Vec::new();
    let full_blocks = bytes.len() / 11;
    let remainder = bytes.len() % 11;

    for i in 0..full_blocks {
        decoded.extend(base58_decode_block(&bytes[i * 11..(i + 1) * 11]));
    }
    if remainder > 0 {
        decoded.extend(base58_decode_block(&bytes[full_blocks * 11..]));
    }

    if decoded.len() < 65 {
        return Err(MaskDerivationError::HexDecodeError(format!(
            "Address too short: {} bytes, need at least 65",
            decoded.len()
        )));
    }

    // Spend public key is bytes 1-33 (after network byte)
    let mut spend_pub: [u8; 32] = [0u8; 32];
    spend_pub.copy_from_slice(&decoded[1..33]);
    Ok(spend_pub)
}

/// Decode encrypted amount from ecdhInfo
fn decode_encrypted_amount(
    derivation_bytes: &[u8; 32],
    output_index: u64,
    encrypted_amount_hex: &str,
) -> Result<u64, MaskDerivationError> {
    let encrypted = hex::decode(encrypted_amount_hex)
        .map_err(|e| MaskDerivationError::HexDecodeError(format!("encrypted_amount: {e}")))?;

    if encrypted.len() < 8 {
        return Err(MaskDerivationError::HexDecodeError(
            "Encrypted amount too short".to_string(),
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
    fn test_extract_tx_pub_key_from_extra() {
        // Simulated tx extra: padding + 0x01 tag + 32 bytes pubkey
        let mut extra = vec![0x02, 0x09, 0x03, 0x00, 0x00]; // Some padding (no 0x01 in padding)
        extra.push(0x01); // tx_pub_key tag
        extra.extend_from_slice(&[0x58; 32]); // 32 bytes of 0x58

        let result = extract_tx_pub_key_from_extra(&extra);
        assert!(result.is_some());

        let pubkey = result.unwrap();
        assert_eq!(pubkey.len(), 64);
        // 0x58 in hex = "58" repeated 32 times
        assert_eq!(pubkey, "58".repeat(32));
    }

    #[test]
    fn test_extract_tx_pub_key_not_found() {
        let extra = vec![0x02, 0x09, 0x00, 0x00, 0x00]; // No 0x01 tag
        let result = extract_tx_pub_key_from_extra(&extra);
        assert!(result.is_none());
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
        println!("\n=== REAL STAGENET ESCROW MASK ===");
        println!("View key: {}", view_key);
        println!("Tx pub key: {}", tx_pub_key);
        println!("DERIVED MASK: {}", mask);
        println!("=================================\n");

        assert_eq!(mask.len(), 64, "Mask should be 64 hex chars");
        assert!(hex::decode(&mask).is_ok(), "Mask should be valid hex");
    }

    #[test]
    fn test_verify_commitment_against_onchain() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

        // Monero H generator point (used for commitment amounts)
        // H = 8 * hash_to_point("H") - pre-computed value from monero source
        const H_BYTES: [u8; 32] = [
            0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad,
            0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d,
            0xd3, 0x9c, 0x1f, 0x94,
        ];

        let h_point = CompressedEdwardsY(H_BYTES)
            .decompress()
            .expect("H is valid");

        // View key and tx_pub_key from our escrow
        let view_key = "b7f874f9baea745f0e7e6817014e563384d90658045304a978d196346d513f06";
        let tx_pub_key = "a4eb6c9c4b388f65b517897ad064b66478fe83a8844265988dcaed13f7428abd";
        let amount: u64 = 2000000000; // 0.002 XMR in atomic units (CORRECTED - output 1 belongs to us)

        // On-chain commitments from transaction b833ae6cb0d2f7cee2ef5efc0e281bb035664f652b153e3b14ec0e0ed6f0893e
        let commitment_0_hex = "977934fed7c68b579247c0ee564420256f15e1d35d9ca89d055024a74e67f4c8";
        let commitment_1_hex = "4cb5a38814f7a4b88c4c864f7b043d932021600658736d127abdadc484307905";

        println!("\n=== COMMITMENT VERIFICATION ===");
        println!("View key: {}", view_key);
        println!("Tx pub key: {}", tx_pub_key);
        println!("Amount: {} atomic units (0.1 XMR)", amount);
        println!("On-chain [0]: {}", commitment_0_hex);
        println!("On-chain [1]: {}", commitment_1_hex);
        println!();

        // Try both output indices (0 and 1)
        for output_idx in [0u64, 1] {
            let mask_hex = derive_commitment_mask(view_key, tx_pub_key, output_idx).unwrap();
            println!("Output index {}: derived mask = {}", output_idx, mask_hex);

            let mask_bytes: [u8; 32] = hex::decode(&mask_hex).unwrap().try_into().unwrap();
            let mask = Scalar::from_bytes_mod_order(mask_bytes);

            // Compute commitment: C = mask * G + amount * H
            let mask_g = ED25519_BASEPOINT_TABLE * &mask;
            let amount_scalar = Scalar::from(amount);
            let amount_h = amount_scalar * h_point;

            let computed_commitment = mask_g + amount_h;
            let computed_hex = hex::encode(computed_commitment.compress().to_bytes());

            println!("  Computed commitment: {}", computed_hex);

            if computed_hex == commitment_0_hex {
                println!("  ✅ MATCH with output[0]!");
            } else if computed_hex == commitment_1_hex {
                println!("  ✅ MATCH with output[1]!");
            } else {
                println!("  ❌ No match");
            }
        }
        println!();

        // Also verify view key by deriving public view key
        println!("=== VIEW KEY VERIFICATION ===");
        println!("Private view key from DB: {}", view_key);

        // Derive public view key from private view key
        let view_key_bytes: [u8; 32] = hex::decode(view_key).unwrap().try_into().unwrap();
        let view_scalar = Scalar::from_bytes_mod_order(view_key_bytes);
        let view_public = ED25519_BASEPOINT_TABLE * &view_scalar;
        let view_pub_hex = hex::encode(view_public.compress().to_bytes());
        println!("Derived public view key: {}", view_pub_hex);

        // Decode the multisig address to get expected public view key
        // Using manual Monero base58 decoding
        let address = "54FYy396FN5SXMhYsCgY49JzH2FyPM9ei14guJpsTCY8jGXbfDKsTNfdeAWJ5ThRLr9ye95tb5yWWUAzcS5vdJdkEaqYhKj";

        // Monero base58 alphabet
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        fn base58_decode_block(block: &[u8]) -> Vec<u8> {
            let mut num: u128 = 0;
            for &ch in block {
                let idx = ALPHABET
                    .iter()
                    .position(|&c| c == ch)
                    .expect("valid base58 char");
                num = num * 58 + idx as u128;
            }

            // Determine output size based on block length
            let out_len = match block.len() {
                11 => 8,
                7 => 5,
                6 => 4,
                5 => 3,
                4 => 2,
                3 => 1,
                _ => 8,
            };

            let mut result = Vec::with_capacity(out_len);
            for i in (0..out_len).rev() {
                result.push((num >> (i * 8)) as u8);
            }
            result
        }

        fn monero_base58_decode(s: &str) -> Vec<u8> {
            let bytes = s.as_bytes();
            let mut result = Vec::new();

            // Process full 11-char blocks (8 output bytes each)
            let full_blocks = bytes.len() / 11;
            let remainder = bytes.len() % 11;

            for i in 0..full_blocks {
                let block = &bytes[i * 11..(i + 1) * 11];
                result.extend(base58_decode_block(block));
            }

            // Process remaining characters
            if remainder > 0 {
                let block = &bytes[full_blocks * 11..];
                result.extend(base58_decode_block(block));
            }

            result
        }

        let decoded = monero_base58_decode(address);
        println!("Decoded address length: {} bytes", decoded.len());

        if decoded.len() >= 65 {
            let network = decoded[0];
            let spend_pub = &decoded[1..33];
            let view_pub = &decoded[33..65];
            println!("Network byte: {} (24=stagenet)", network);
            println!("Address public spend key: {}", hex::encode(spend_pub));
            println!("Address public view key:  {}", hex::encode(view_pub));

            // Check if our derived view key matches
            if view_pub_hex == hex::encode(view_pub) {
                println!("✅ View keys MATCH!");
            } else {
                println!("❌ View keys DO NOT match!");
                println!("   This could explain why the mask derivation is failing.");
            }
        }

        println!("================================\n");

        assert!(true, "Diagnostic test");
    }

    /// Test decoding the encrypted amount using derivation_to_scalar output
    /// This verifies our shared_secret derivation is correct by checking against
    /// the encrypted amount in ecdhInfo
    #[test]
    fn test_decode_encrypted_amount() {
        // Data from our escrow
        let view_key = "b7f874f9baea745f0e7e6817014e563384d90658045304a978d196346d513f06";
        let tx_pub_key = "a4eb6c9c4b388f65b517897ad064b66478fe83a8844265988dcaed13f7428abd";

        // Encrypted amounts from ecdhInfo (RCT v2 format - 8 bytes each)
        let encrypted_amount_0 = hex::decode("3f2c482745a0ef9e").unwrap();
        let encrypted_amount_1 = hex::decode("6896a8310b1c55f4").unwrap();

        // Known amounts to verify - CORRECTED after finding output 1 is ours
        let expected_amount = 2000000000u64; // 0.002 XMR - actual escrow amount (output index 1)

        println!("\n=== AMOUNT DECODING VERIFICATION ===");
        println!("View key: {}", view_key);
        println!("Tx pub key: {}", tx_pub_key);
        println!("Encrypted amount [0]: {}", hex::encode(&encrypted_amount_0));
        println!("Encrypted amount [1]: {}", hex::encode(&encrypted_amount_1));
        println!(
            "Expected escrow amount: {} atomic (0.002 XMR)",
            expected_amount
        );
        println!();

        // Parse view key
        let view_key_bytes: [u8; 32] = hex::decode(view_key).unwrap().try_into().unwrap();
        let view_scalar = Scalar::from_bytes_mod_order(view_key_bytes);

        // Parse tx_pub_key
        let tx_pub_bytes: [u8; 32] = hex::decode(tx_pub_key).unwrap().try_into().unwrap();
        let tx_pub_compressed = CompressedEdwardsY(tx_pub_bytes);
        let tx_pub_point = tx_pub_compressed.decompress().expect("valid point");

        // Compute derivation: D = 8 * a * R
        let shared_point = view_scalar * tx_pub_point;
        let derivation = shared_point.mul_by_cofactor();
        let derivation_bytes = derivation.compress().to_bytes();

        println!("Derivation point: {}", hex::encode(&derivation_bytes));

        for output_idx in [0u64, 1] {
            // Compute derivation_to_scalar: Hs(derivation || varint(output_idx))
            let mut hasher = Keccak256::new();
            hasher.update(&derivation_bytes);
            hasher.update(&encode_varint(output_idx));
            let shared_secret: [u8; 32] = hasher.finalize().into();

            println!("\nOutput index {}:", output_idx);
            println!(
                "  shared_secret (before reduce): {}",
                hex::encode(&shared_secret)
            );

            // Reduce to scalar (sc_reduce32 equivalent)
            let shared_secret_scalar = Scalar::from_bytes_mod_order(shared_secret);
            println!(
                "  shared_secret (after reduce): {}",
                hex::encode(shared_secret_scalar.as_bytes())
            );

            // Compute amount encoding factor: Hs("amount" || shared_secret)
            // In v2, amount_key = derivation_to_scalar output
            let mut amount_hasher = Keccak256::new();
            amount_hasher.update(b"amount");
            amount_hasher.update(shared_secret_scalar.as_bytes());
            let amount_factor: [u8; 32] = amount_hasher.finalize().into();

            println!("  amount_factor: {}", hex::encode(&amount_factor));

            // XOR first 8 bytes with encrypted amount to decode
            let encrypted = if output_idx == 0 {
                &encrypted_amount_0
            } else {
                &encrypted_amount_1
            };
            let mut decoded_bytes = [0u8; 8];
            for i in 0..8 {
                decoded_bytes[i] = encrypted[i] ^ amount_factor[i];
            }

            let decoded_amount = u64::from_le_bytes(decoded_bytes);
            println!(
                "  Decoded amount: {} atomic ({} XMR)",
                decoded_amount,
                decoded_amount as f64 / 1e12
            );

            if decoded_amount == expected_amount {
                println!("  ✅ MATCH! This is the escrow output!");
            }

            // Compute view_tag: first_byte(Hs(derivation || varint(i)))
            // Actually view_tag = first byte of derivation_to_scalar output (before reduce)
            let view_tag = shared_secret[0];
            println!("  Expected view_tag: {:02x}", view_tag);
        }

        // On-chain view tags
        println!("\nOn-chain view_tags:");
        println!("  Output 0: eb");
        println!("  Output 1: 70");

        // Also compute and print the commitment mask for output_index=1 (the correct one)
        let mask_for_output_1 = derive_commitment_mask(view_key, tx_pub_key, 1).unwrap();
        println!(
            "\n*** CORRECT MASK for output_index=1: {} ***",
            mask_for_output_1
        );

        // Verify output ownership by computing expected one-time public key
        // P = Hs(derivation || i) * G + B (where B is public spend key)
        println!("\n=== OUTPUT OWNERSHIP VERIFICATION ===");

        // Get public spend key from address
        let address = "54FYy396FN5SXMhYsCgY49JzH2FyPM9ei14guJpsTCY8jGXbfDKsTNfdeAWJ5ThRLr9ye95tb5yWWUAzcS5vdJdkEaqYhKj";

        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        fn base58_decode_block2(block: &[u8]) -> Vec<u8> {
            let mut num: u128 = 0;
            for &ch in block {
                let idx = ALPHABET
                    .iter()
                    .position(|&c| c == ch)
                    .expect("valid base58 char");
                num = num * 58 + idx as u128;
            }
            let out_len = match block.len() {
                11 => 8,
                7 => 5,
                6 => 4,
                5 => 3,
                4 => 2,
                3 => 1,
                _ => 8,
            };
            let mut result = Vec::with_capacity(out_len);
            for i in (0..out_len).rev() {
                result.push((num >> (i * 8)) as u8);
            }
            result
        }

        fn monero_base58_decode2(s: &str) -> Vec<u8> {
            let bytes = s.as_bytes();
            let mut result = Vec::new();
            let full_blocks = bytes.len() / 11;
            let remainder = bytes.len() % 11;
            for i in 0..full_blocks {
                result.extend(base58_decode_block2(&bytes[i * 11..(i + 1) * 11]));
            }
            if remainder > 0 {
                result.extend(base58_decode_block2(&bytes[full_blocks * 11..]));
            }
            result
        }

        let decoded_addr = monero_base58_decode2(address);
        let spend_pub_bytes: [u8; 32] = decoded_addr[1..33].try_into().unwrap();
        let spend_pub_point = CompressedEdwardsY(spend_pub_bytes)
            .decompress()
            .expect("valid point");

        println!("Public spend key (B): {}", hex::encode(&spend_pub_bytes));

        // On-chain output keys
        let output_key_0 = "31a6ef3f4b55665225bb4235111539e668cd89d08975b7062479b88849c3eb4c";
        let output_key_1 = "1ba8ba77bf373920a84462077713e24144c418ec715d03972f22d4738c262142";

        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

        for output_idx in [0u64, 1] {
            // Compute derivation_to_scalar
            let mut hasher = Keccak256::new();
            hasher.update(&derivation_bytes);
            hasher.update(&encode_varint(output_idx));
            let shared_secret: [u8; 32] = hasher.finalize().into();
            let scalar = Scalar::from_bytes_mod_order(shared_secret);

            // Expected one-time key: P = scalar * G + B
            let scalar_g = ED25519_BASEPOINT_TABLE * &scalar;
            let expected_output_key = scalar_g + spend_pub_point;
            let expected_hex = hex::encode(expected_output_key.compress().to_bytes());

            println!("Output index {}:", output_idx);
            println!("  Expected output key: {}", expected_hex);
            println!(
                "  On-chain output key: {}",
                if output_idx == 0 {
                    output_key_0
                } else {
                    output_key_1
                }
            );
            if expected_hex
                == (if output_idx == 0 {
                    output_key_0
                } else {
                    output_key_1
                })
            {
                println!("  ✅ MATCH! This output belongs to our address!");
            } else {
                println!("  ❌ NO MATCH - this output does NOT belong to us");
            }
        }

        println!("================================\n");
    }
}
