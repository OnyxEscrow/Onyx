//! Key Derivation and View Key Validation
//!
//! This module provides cryptographic functions for:
//! - View key derivation and validation
//! - Public key extraction from scalars
//! - Constant-time comparisons for security
//!
//! ## Security Properties
//!
//! - **Non-custodial**: Functions only validate, never derive spending capability
//! - **Constant-time**: Comparisons prevent timing attacks
//! - **Network-aware**: Handles mainnet/stagenet/testnet correctly

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

use crate::keys::validate::decode_address;
use crate::types::address::MoneroNetwork;
use crate::types::errors::{CryptoError, CryptoResult};

// =============================================================================
// View Key Validation
// =============================================================================

/// Validates that a private view key corresponds to a Monero address
///
/// Derives the public view key from the private key and compares it to the
/// public view key embedded in the address.
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
/// - The private view key only allows viewing, not spending
///
/// # Example
/// ```rust,ignore
/// use onyx_crypto_core::keys::derive::validate_view_key_matches_address;
///
/// let matches = validate_view_key_matches_address(
///     "949514f882b4058e0b869f569591861027a41cafb00bae594acc14eb0f312607",
///     "5664QSfgtoHYBXvJLawcquW2j9qswLtzcNYqd3KKetiq..."
/// )?;
/// ```
pub fn validate_view_key_matches_address(view_key_hex: &str, address: &str) -> CryptoResult<bool> {
    // 1. Parse and validate view key hex
    if view_key_hex.len() != 64 {
        return Err(CryptoError::InvalidLength {
            field: "view_key_hex".into(),
            expected: 64,
            actual: view_key_hex.len(),
        });
    }

    let view_bytes = hex::decode(view_key_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid view key hex: {e}")))?;

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

    // Zeroize the scalar (though Scalar may already do this)
    // The original array is on the stack and will be cleared
    zeroize::Zeroize::zeroize(&mut view_arr);

    Ok(matches)
}

/// Extracts the public view key embedded in a Monero address
///
/// # Address Format
/// Monero addresses (after base58 decode) have this structure:
/// ```text
/// [prefix:1] [spend_pub:32] [view_pub:32]
/// ```
///
/// # Arguments
/// * `address` - Base58-encoded Monero address
///
/// # Returns
/// * `Ok([u8; 32])` - The 32-byte public view key
/// * `Err(_)` - If the address is invalid
pub fn extract_view_pub_from_address(address: &str) -> CryptoResult<[u8; 32]> {
    // Use our decode_address function for validation
    let decoded = decode_address(address)?;
    Ok(decoded.view_key)
}

/// Extracts the public spend key embedded in a Monero address
///
/// # Arguments
/// * `address` - Base58-encoded Monero address
///
/// # Returns
/// * `Ok([u8; 32])` - The 32-byte public spend key
/// * `Err(_)` - If the address is invalid
pub fn extract_spend_pub_from_address(address: &str) -> CryptoResult<[u8; 32]> {
    let decoded = decode_address(address)?;
    Ok(decoded.spend_key)
}

/// Derives a public key from a private key scalar
///
/// Computes: P = k * G where G is the Ed25519 basepoint
///
/// # Arguments
/// * `private_key` - 32-byte private key (scalar)
///
/// # Returns
/// * 32-byte compressed Edwards point (public key)
///
/// # Security
/// This is a one-way operation. The private key cannot be recovered
/// from the public key.
#[must_use]
pub fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*private_key);
    let point = ED25519_BASEPOINT_TABLE * &scalar;
    point.compress().to_bytes()
}

/// Derives a public key from a private key hex string
///
/// # Arguments
/// * `private_key_hex` - 64-character hex string
///
/// # Returns
/// * `Ok([u8; 32])` - The derived public key
/// * `Err(_)` - If the hex is invalid
pub fn derive_public_key_from_hex(private_key_hex: &str) -> CryptoResult<[u8; 32]> {
    if private_key_hex.len() != 64 {
        return Err(CryptoError::InvalidLength {
            field: "private_key_hex".into(),
            expected: 64,
            actual: private_key_hex.len(),
        });
    }

    let bytes = hex::decode(private_key_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid private key hex: {e}")))?;

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);

    let result = derive_public_key(&arr);

    // Zeroize the private key copy
    zeroize::Zeroize::zeroize(&mut arr);

    Ok(result)
}

/// Returns the network type detected from an address
///
/// # Arguments
/// * `address` - Base58-encoded Monero address
///
/// # Returns
/// * `Ok(MoneroNetwork)` - The detected network
/// * `Err(_)` - If the address is invalid
pub fn get_network_from_address(address: &str) -> CryptoResult<MoneroNetwork> {
    let decoded = decode_address(address)?;
    Ok(decoded.network)
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Constant-time comparison of two 32-byte arrays
///
/// Prevents timing attacks by always comparing all bytes regardless
/// of where the first difference occurs.
///
/// # Security
/// This function is designed to take the same amount of time
/// regardless of input values, preventing timing side-channels.
#[inline]
#[must_use]
pub fn constant_time_compare(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time comparison of two arbitrary-length slices
///
/// Returns false immediately if lengths differ (this is not constant-time
/// for length, only for content).
#[inline]
#[must_use]
pub fn constant_time_compare_slices(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Known stagenet address for testing
    const STAGENET_ADDRESS: &str = "5664QSfgtoHYBXvJLawcquW2j9qswLtzcNYqd3KKetiq8v9REmFveSKeE3ctRdq9zyf9DhbSMy9hyFp9rFKPqbw4Rr5HN3L";

    #[test]
    fn test_validate_view_key_format_too_short() {
        let result = validate_view_key_matches_address("abcd", STAGENET_ADDRESS);
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::InvalidLength { .. })));
    }

    #[test]
    fn test_validate_view_key_invalid_hex() {
        let result = validate_view_key_matches_address(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            STAGENET_ADDRESS,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_address_length() {
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
    fn test_constant_time_compare_slices() {
        let a = vec![1u8, 2, 3, 4];
        let b = vec![1u8, 2, 3, 4];
        let c = vec![1u8, 2, 3, 5];
        let d = vec![1u8, 2, 3];

        assert!(constant_time_compare_slices(&a, &b));
        assert!(!constant_time_compare_slices(&a, &c));
        assert!(!constant_time_compare_slices(&a, &d));
    }

    #[test]
    fn test_extract_view_pub_from_stagenet_address() {
        let result = extract_view_pub_from_address(STAGENET_ADDRESS);
        assert!(result.is_ok());
        let view_pub = result.unwrap();
        assert_eq!(view_pub.len(), 32);
        // View key should be non-zero
        assert!(view_pub.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_extract_spend_pub_from_stagenet_address() {
        let result = extract_spend_pub_from_address(STAGENET_ADDRESS);
        assert!(result.is_ok());
        let spend_pub = result.unwrap();
        assert_eq!(spend_pub.len(), 32);
        // Spend key should be non-zero
        assert!(spend_pub.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_get_network_from_address() {
        let result = get_network_from_address(STAGENET_ADDRESS);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MoneroNetwork::Stagenet);
    }

    #[test]
    fn test_derive_public_key() {
        // Known test vector: zero scalar should give identity (though not practical)
        // Using a non-zero scalar
        let private_key = [1u8; 32];
        let public_key = derive_public_key(&private_key);

        // Should be non-zero
        assert!(public_key.iter().any(|&b| b != 0));
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn test_derive_public_key_deterministic() {
        let private_key = [42u8; 32];
        let pub1 = derive_public_key(&private_key);
        let pub2 = derive_public_key(&private_key);
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_derive_public_key_from_hex() {
        let hex_key = "0".repeat(64);
        let result = derive_public_key_from_hex(&hex_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_public_key_from_hex_invalid_length() {
        let result = derive_public_key_from_hex("abcd");
        assert!(matches!(result, Err(CryptoError::InvalidLength { .. })));
    }
}
