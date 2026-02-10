//! Utility functions for CMD protocol
//!
//! Contains varint encoding, tx_pub_key extraction, and address parsing.

use alloc::string::String;
use alloc::vec::Vec;

use crate::types::errors::{CryptoError, CryptoResult};

/// Encode a u64 as a Monero-compatible varint
///
/// Monero uses variable-length integer encoding where:
/// - Each byte holds 7 bits of data
/// - The high bit (0x80) indicates continuation
/// - For indices < 128, the result is a single byte
///
/// # Example
///
/// ```rust
/// use onyx_crypto_core::cmd::encode_varint;
///
/// assert_eq!(encode_varint(0), vec![0]);
/// assert_eq!(encode_varint(127), vec![127]);
/// assert_eq!(encode_varint(128), vec![0x80, 0x01]);
/// ```
pub fn encode_varint(mut n: u64) -> Vec<u8> {
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
///
/// # Example
///
/// ```rust
/// use onyx_crypto_core::cmd::extract_tx_pub_key_from_extra;
///
/// // Simulated tx extra with padding + 0x01 tag + 32 bytes pubkey
/// let mut extra = vec![0x02, 0x09, 0x03, 0x00, 0x00]; // padding
/// extra.push(0x01); // tx_pub_key tag
/// extra.extend_from_slice(&[0x58; 32]); // 32 bytes of 0x58
///
/// let result = extract_tx_pub_key_from_extra(&extra);
/// assert!(result.is_some());
/// ```
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

/// Monero base58 alphabet
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a single base58 block to bytes
fn base58_decode_block(block: &[u8]) -> Vec<u8> {
    let mut num: u128 = 0;
    for &ch in block {
        let idx = BASE58_ALPHABET.iter().position(|&c| c == ch).unwrap_or(0);
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

/// Decode a Monero base58 address to raw bytes
pub fn monero_base58_decode(s: &str) -> Vec<u8> {
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

/// Extract spend public key from a Monero address
///
/// Monero addresses are base58-encoded with the following structure:
/// - 1 byte: network prefix
/// - 32 bytes: public spend key
/// - 32 bytes: public view key
/// - 4 bytes: checksum
///
/// # Arguments
///
/// * `address` - A standard Monero address (95 characters)
///
/// # Returns
///
/// The 32-byte public spend key
pub fn extract_spend_pub_from_address(address: &str) -> CryptoResult<[u8; 32]> {
    let decoded = monero_base58_decode(address);

    if decoded.len() < 65 {
        return Err(CryptoError::MaskDerivationFailed(alloc::format!(
            "Address too short: {} bytes, need at least 65",
            decoded.len()
        )));
    }

    // Spend public key is bytes 1-33 (after network byte)
    let mut spend_pub: [u8; 32] = [0u8; 32];
    spend_pub.copy_from_slice(&decoded[1..33]);
    Ok(spend_pub)
}

/// Extract view public key from a Monero address
///
/// # Arguments
///
/// * `address` - A standard Monero address (95 characters)
///
/// # Returns
///
/// The 32-byte public view key
pub fn extract_view_pub_from_address(address: &str) -> CryptoResult<[u8; 32]> {
    let decoded = monero_base58_decode(address);

    if decoded.len() < 65 {
        return Err(CryptoError::MaskDerivationFailed(alloc::format!(
            "Address too short: {} bytes, need at least 65",
            decoded.len()
        )));
    }

    // View public key is bytes 33-65
    let mut view_pub: [u8; 32] = [0u8; 32];
    view_pub.copy_from_slice(&decoded[33..65]);
    Ok(view_pub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_varint_small() {
        assert_eq!(encode_varint(0), vec![0]);
        assert_eq!(encode_varint(1), vec![1]);
        assert_eq!(encode_varint(127), vec![127]);
    }

    #[test]
    fn test_encode_varint_128() {
        // 128 = 0b10000000
        // varint: [0x80, 0x01] where 0x80 = 0 + continuation, 0x01 = 1
        assert_eq!(encode_varint(128), vec![0x80, 0x01]);
    }

    #[test]
    fn test_encode_varint_large() {
        // 300 = 0b100101100
        // Split: 7 bits = 0101100 = 44, then 2 bits = 10 = 2
        // varint: [44 | 0x80, 2] = [172, 2]
        assert_eq!(encode_varint(300), vec![0xac, 0x02]);
    }

    #[test]
    fn test_extract_tx_pub_key_found() {
        let mut extra = vec![0x02, 0x09, 0x03, 0x00, 0x00]; // padding
        extra.push(0x01); // tx_pub_key tag
        extra.extend_from_slice(&[0x58; 32]); // 32 bytes of 0x58

        let result = extract_tx_pub_key_from_extra(&extra);
        assert!(result.is_some());

        let pubkey = result.unwrap();
        assert_eq!(pubkey.len(), 64);
        assert_eq!(pubkey, "58".repeat(32));
    }

    #[test]
    fn test_extract_tx_pub_key_not_found() {
        let extra = vec![0x02, 0x09, 0x00, 0x00, 0x00]; // No 0x01 tag
        let result = extract_tx_pub_key_from_extra(&extra);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_spend_pub_from_stagenet_address() {
        // Real stagenet address
        let address = "54FYy396FN5SXMhYsCgY49JzH2FyPM9ei14guJpsTCY8jGXbfDKsTNfdeAWJ5ThRLr9ye95tb5yWWUAzcS5vdJdkEaqYhKj";
        let result = extract_spend_pub_from_address(address);
        assert!(result.is_ok());
        let spend_pub = result.unwrap();
        assert_eq!(spend_pub.len(), 32);
    }

    #[test]
    fn test_extract_view_pub_from_stagenet_address() {
        let address = "54FYy396FN5SXMhYsCgY49JzH2FyPM9ei14guJpsTCY8jGXbfDKsTNfdeAWJ5ThRLr9ye95tb5yWWUAzcS5vdJdkEaqYhKj";
        let result = extract_view_pub_from_address(address);
        assert!(result.is_ok());
        let view_pub = result.unwrap();
        assert_eq!(view_pub.len(), 32);
    }
}
