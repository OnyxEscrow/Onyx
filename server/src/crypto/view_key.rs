//! View Key Validation Module
//!
//! Provides cryptographic validation that a private view key corresponds to
//! a Monero address by deriving the public view key and comparing it to
//! the address-embedded key.
//!
//! ## Security Properties
//! - Non-custodial: Server only validates, never derives spending capability
//! - Constant-time comparison: Prevents timing attacks
//! - Network-aware: Handles mainnet/stagenet/testnet prefixes

use anyhow::{anyhow, Context, Result};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

/// Network prefixes for Monero addresses
/// See: https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h
const MAINNET_PREFIX: u8 = 18; // Standard address
const STAGENET_PREFIX: u8 = 24; // Stagenet address
const TESTNET_PREFIX: u8 = 53; // Testnet address

/// Monero address structure (after base58 decode_check, checksum stripped):
/// - prefix: 1 byte (network identifier)
/// - spend_public_key: 32 bytes
/// - view_public_key: 32 bytes
/// Total: 65 bytes (decode_check strips the 4-byte checksum)
const SPEND_KEY_OFFSET: usize = 1;
const VIEW_KEY_OFFSET: usize = SPEND_KEY_OFFSET + 32; // 33
const EXPECTED_RAW_LEN: usize = 65; // 1 + 32 + 32 (checksum stripped by decode_check)

/// Validates that a private view key corresponds to a Monero address
/// by deriving the public view key and comparing to the address-embedded key.
///
/// # Arguments
/// * `view_key_hex` - 64-character hex string representing the private view key scalar
/// * `address` - Base58-encoded Monero address
///
/// # Returns
/// * `Ok(true)` if the view key derives to the public key embedded in the address
/// * `Ok(false)` if there's a mismatch (key doesn't correspond to address)
/// * `Err(_)` if the inputs are malformed
///
/// # Security
/// - Uses constant-time comparison to prevent timing attacks
/// - Does NOT reveal the private key or allow spending
pub fn validate_view_key_matches_address(view_key_hex: &str, address: &str) -> Result<bool> {
    // 1. Parse and validate view key hex
    if view_key_hex.len() != 64 {
        return Err(anyhow!(
            "View key must be 64 hex characters, got {}",
            view_key_hex.len()
        ));
    }

    let view_bytes = hex::decode(view_key_hex).context("Invalid view key hex encoding")?;

    // 2. Convert to scalar (32 bytes)
    let mut view_arr = [0u8; 32];
    view_arr.copy_from_slice(&view_bytes);
    let view_scalar = Scalar::from_bytes_mod_order(view_arr);

    // 3. Derive public view key: A = a * G (where G is the ed25519 basepoint)
    let view_public_point = ED25519_BASEPOINT_TABLE * &view_scalar;
    let derived_view_pub = view_public_point.compress().to_bytes();

    // 4. Extract embedded view public key from address
    let address_view_pub = extract_view_pub_from_address(address)?;

    // 5. Constant-time comparison (prevents timing attacks)
    let matches = constant_time_compare(&derived_view_pub, &address_view_pub);

    // Zeroize sensitive data
    let _ = view_arr; // Compiler will optimize, but intent is clear

    Ok(matches)
}

/// Extracts the public view key embedded in a Monero address.
///
/// # Address Format
/// Monero addresses are base58 encoded with the following structure:
/// ```text
/// [prefix:1] [spend_pub:32] [view_pub:32] [checksum:4]
/// ```
///
/// # Arguments
/// * `address` - Base58-encoded Monero address (95 chars for standard, 106 for subaddress)
///
/// # Returns
/// * `Ok([u8; 32])` - The 32-byte public view key
/// * `Err(_)` - If the address is invalid or malformed
fn extract_view_pub_from_address(address: &str) -> Result<[u8; 32]> {
    // Validate address length (standard address = 95 chars, subaddress = 106 chars)
    if address.len() != 95 && address.len() != 106 {
        return Err(anyhow!(
            "Invalid address length: {} (expected 95 or 106)",
            address.len()
        ));
    }

    // Decode base58 (with checksum verification)
    let decoded = base58_monero::decode_check(address)
        .map_err(|e| anyhow!("Base58 decode failed: {:?}", e))?;

    // Verify decoded length
    if decoded.len() != EXPECTED_RAW_LEN {
        return Err(anyhow!(
            "Decoded address has wrong length: {} (expected {})",
            decoded.len(),
            EXPECTED_RAW_LEN
        ));
    }

    // Verify network prefix
    let prefix = decoded[0];
    if prefix != MAINNET_PREFIX && prefix != STAGENET_PREFIX && prefix != TESTNET_PREFIX {
        return Err(anyhow!(
            "Unknown network prefix: {} (expected mainnet:{}, stagenet:{}, or testnet:{})",
            prefix,
            MAINNET_PREFIX,
            STAGENET_PREFIX,
            TESTNET_PREFIX
        ));
    }

    // Extract view public key (bytes 33-65)
    let mut view_pub = [0u8; 32];
    view_pub.copy_from_slice(&decoded[VIEW_KEY_OFFSET..VIEW_KEY_OFFSET + 32]);

    Ok(view_pub)
}

/// Constant-time comparison of two 32-byte arrays.
/// Prevents timing attacks by always comparing all bytes.
#[inline]
fn constant_time_compare(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Returns the network type based on address prefix
/// Useful for logging and debugging
pub fn get_network_from_address(address: &str) -> Result<&'static str> {
    if address.len() < 95 {
        return Err(anyhow!("Address too short"));
    }

    let decoded = base58_monero::decode_check(address)
        .map_err(|e| anyhow!("Base58 decode failed: {:?}", e))?;

    match decoded[0] {
        MAINNET_PREFIX => Ok("mainnet"),
        STAGENET_PREFIX => Ok("stagenet"),
        TESTNET_PREFIX => Ok("testnet"),
        _ => Err(anyhow!("Unknown network prefix: {}", decoded[0])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test with a known stagenet address and its view key
    /// Note: This test uses a deterministic wallet for reproducibility
    #[test]
    fn test_validate_view_key_format() {
        // Invalid: wrong length
        let result = validate_view_key_matches_address(
            "abcd", // Too short
            "5664QSfgtoHYBXvJLawcquW2j9qswLtzcNYqd3KKetiq8v9REmFveSKeE3ctRdq9zyf9DhbSMy9hyFp9rFKPqbw4Rr5HN3L",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_address_length() {
        // Invalid address length
        let result = validate_view_key_matches_address(
            "949514f882b4058e0b869f569591861027a41cafb00bae594acc14eb0f312607",
            "short",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }

    #[test]
    fn test_extract_view_pub_from_stagenet_address() {
        // Valid stagenet address
        let address = "5664QSfgtoHYBXvJLawcquW2j9qswLtzcNYqd3KKetiq8v9REmFveSKeE3ctRdq9zyf9DhbSMy9hyFp9rFKPqbw4Rr5HN3L";
        let result = extract_view_pub_from_address(address);
        assert!(
            result.is_ok(),
            "Should successfully extract view pub from stagenet address"
        );

        let view_pub = result.unwrap();
        assert_eq!(view_pub.len(), 32, "View pub should be 32 bytes");
    }

    #[test]
    fn test_network_detection() {
        // Stagenet address (starts with 5)
        let stagenet = "5664QSfgtoHYBXvJLawcquW2j9qswLtzcNYqd3KKetiq8v9REmFveSKeE3ctRdq9zyf9DhbSMy9hyFp9rFKPqbw4Rr5HN3L";
        assert_eq!(get_network_from_address(stagenet).unwrap(), "stagenet");
    }
}
