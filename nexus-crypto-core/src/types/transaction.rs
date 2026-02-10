//! Transaction-related types for Monero cryptographic operations
//!
//! This module provides type-safe representations of transaction components
//! used in CLSAG signing and CMD protocol.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// =============================================================================
// Transaction Identifiers
// =============================================================================

/// Length of a Monero transaction hash in bytes
pub const TX_HASH_LENGTH: usize = 32;

/// Length of a Monero key image in bytes
pub const KEY_IMAGE_LENGTH: usize = 32;

/// Monero transaction hash (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxHash(pub [u8; TX_HASH_LENGTH]);

impl TxHash {
    /// Create a new transaction hash from bytes
    #[must_use]
    pub const fn new(bytes: [u8; TX_HASH_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Create from a hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, &'static str> {
        if hex_str.len() != TX_HASH_LENGTH * 2 {
            return Err("Invalid hex length for transaction hash");
        }

        let mut bytes = [0u8; TX_HASH_LENGTH];
        hex::decode_to_slice(hex_str, &mut bytes).map_err(|_| "Invalid hex characters")?;
        Ok(Self(bytes))
    }

    /// Convert to hex string
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the underlying bytes
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TX_HASH_LENGTH] {
        &self.0
    }
}

impl AsRef<[u8]> for TxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// =============================================================================
// Key Image
// =============================================================================

/// Monero key image (32 bytes Edwards point)
///
/// Key images are used to detect double-spending. They are derived as:
/// `I = x * H_p(P)` where x is the private key and P is the public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyImage(pub [u8; KEY_IMAGE_LENGTH]);

impl KeyImage {
    /// Create a new key image from bytes
    #[must_use]
    pub const fn new(bytes: [u8; KEY_IMAGE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Create from a hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, &'static str> {
        if hex_str.len() != KEY_IMAGE_LENGTH * 2 {
            return Err("Invalid hex length for key image");
        }

        let mut bytes = [0u8; KEY_IMAGE_LENGTH];
        hex::decode_to_slice(hex_str, &mut bytes).map_err(|_| "Invalid hex characters")?;
        Ok(Self(bytes))
    }

    /// Convert to hex string
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the underlying bytes
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_IMAGE_LENGTH] {
        &self.0
    }
}

impl AsRef<[u8]> for KeyImage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// =============================================================================
// Ring Member (for CLSAG)
// =============================================================================

/// A member of a ring used in CLSAG signatures
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingMember {
    /// Public key (stealth address)
    pub public_key: [u8; 32],
    /// Pedersen commitment to amount
    pub commitment: [u8; 32],
}

impl RingMember {
    /// Create a new ring member
    #[must_use]
    pub const fn new(public_key: [u8; 32], commitment: [u8; 32]) -> Self {
        Self {
            public_key,
            commitment,
        }
    }

    /// Create from hex strings
    pub fn from_hex(pubkey_hex: &str, commitment_hex: &str) -> Result<Self, &'static str> {
        let mut public_key = [0u8; 32];
        let mut commitment = [0u8; 32];

        hex::decode_to_slice(pubkey_hex, &mut public_key)
            .map_err(|_| "Invalid hex for public key")?;
        hex::decode_to_slice(commitment_hex, &mut commitment)
            .map_err(|_| "Invalid hex for commitment")?;

        Ok(Self {
            public_key,
            commitment,
        })
    }
}

// =============================================================================
// Output Information
// =============================================================================

/// Information about a transaction output needed for spending
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputInfo {
    /// Global output index
    pub global_index: u64,
    /// Output public key (stealth address)
    pub public_key: [u8; 32],
    /// Pedersen commitment
    pub commitment: [u8; 32],
    /// Amount (may be encrypted in RingCT)
    pub amount: u64,
    /// Transaction public key for derivation
    pub tx_public_key: [u8; 32],
    /// Output index within the transaction
    pub internal_output_index: u32,
}

// =============================================================================
// Partial Signature Data (for 2-of-3 signing)
// =============================================================================

/// Data exchanged between signers in round-robin CLSAG
///
/// This structure contains all the cryptographic data needed for
/// the second signer to complete a CLSAG signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignatureData {
    /// First component of CLSAG (c1)
    pub c1: [u8; 32],
    /// S-values for all ring members (32 bytes each)
    pub s_values: Vec<[u8; 32]>,
    /// D point for linking
    pub d: [u8; 32],
    /// Pseudo output commitment
    pub pseudo_out: [u8; 32],
    /// Key image
    pub key_image: [u8; 32],
    /// mu_P aggregate scalar
    pub mu_p: [u8; 32],
    /// mu_C aggregate scalar
    pub mu_c: [u8; 32],
    /// First signer's partial s[l] value
    pub s_l_partial: [u8; 32],
    /// Real input index in ring
    pub signer_index: usize,
    /// Mask delta for output commitment
    pub mask_delta: [u8; 32],
    /// Transaction prefix hash
    pub tx_prefix_hash: [u8; 32],
    /// Ring data: pairs of (pubkey, commitment)
    pub ring: Vec<([u8; 32], [u8; 32])>,
}

// =============================================================================
// CLSAG Signature
// =============================================================================

/// A complete CLSAG ring signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClsagSignature {
    /// Starting challenge
    pub c1: [u8; 32],
    /// S-values for each ring member
    pub s_values: Vec<[u8; 32]>,
    /// D point (for linking)
    pub d: [u8; 32],
}

impl ClsagSignature {
    /// Get the ring size
    #[must_use]
    pub fn ring_size(&self) -> usize {
        self.s_values.len()
    }

    /// Verify the signature has valid structure
    #[must_use]
    pub fn is_valid_structure(&self, expected_ring_size: usize) -> bool {
        self.s_values.len() == expected_ring_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_hash_from_hex() {
        let hex_str = "0".repeat(64);
        let hash = TxHash::from_hex(&hex_str).unwrap();
        assert_eq!(hash.0, [0u8; 32]);
        assert_eq!(hash.to_hex(), hex_str);
    }

    #[test]
    fn test_tx_hash_invalid_length() {
        let short_hex = "0".repeat(63);
        assert!(TxHash::from_hex(&short_hex).is_err());
    }

    #[test]
    fn test_key_image_from_hex() {
        let hex_str = "a".repeat(64);
        let ki = KeyImage::from_hex(&hex_str).unwrap();
        assert_eq!(ki.0, [0xaa; 32]);
    }

    #[test]
    fn test_ring_member_from_hex() {
        let pubkey_hex = "0".repeat(64);
        let commit_hex = "1".repeat(64);
        let member = RingMember::from_hex(&pubkey_hex, &commit_hex).unwrap();
        assert_eq!(member.public_key, [0u8; 32]);
        assert_eq!(member.commitment, [0x11; 32]);
    }

    #[test]
    fn test_clsag_signature_ring_size() {
        let sig = ClsagSignature {
            c1: [0u8; 32],
            s_values: vec![[0u8; 32]; 11],
            d: [0u8; 32],
        };
        assert_eq!(sig.ring_size(), 11);
        assert!(sig.is_valid_structure(11));
        assert!(!sig.is_valid_structure(10));
    }
}
