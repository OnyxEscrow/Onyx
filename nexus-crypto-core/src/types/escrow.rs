//! Escrow-related cryptographic types
//!
//! This module provides types specifically for cryptographic operations
//! in 2-of-3 multisig escrow scenarios.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// =============================================================================
// Escrow Roles
// =============================================================================

/// Role in a 2-of-3 escrow arrangement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EscrowRole {
    /// The buyer (customer)
    Buyer,
    /// The vendor (seller)
    Vendor,
    /// The arbiter (platform)
    Arbiter,
}

impl EscrowRole {
    /// Get the FROST identifier for this role (1-3)
    #[must_use]
    pub const fn frost_identifier(&self) -> u16 {
        match self {
            Self::Buyer => 1,
            Self::Vendor => 2,
            Self::Arbiter => 3,
        }
    }

    /// Create from FROST identifier
    #[must_use]
    pub const fn from_frost_identifier(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::Buyer),
            2 => Some(Self::Vendor),
            3 => Some(Self::Arbiter),
            _ => None,
        }
    }

    /// Get string representation
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Buyer => "buyer",
            Self::Vendor => "vendor",
            Self::Arbiter => "arbiter",
        }
    }
}

impl core::fmt::Display for EscrowRole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Signing Pair
// =============================================================================

/// A pair of signers for a 2-of-3 transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SigningPair {
    /// First signer in the pair
    pub first_signer: EscrowRole,
    /// Second signer in the pair
    pub second_signer: EscrowRole,
}

impl SigningPair {
    /// Create a new signing pair
    ///
    /// # Panics
    /// Panics if first_signer == second_signer
    #[must_use]
    pub fn new(first_signer: EscrowRole, second_signer: EscrowRole) -> Self {
        assert_ne!(
            first_signer, second_signer,
            "Signing pair must have different roles"
        );
        Self {
            first_signer,
            second_signer,
        }
    }

    /// Get the pair for release transaction (buyer + vendor)
    #[must_use]
    pub const fn release() -> Self {
        Self {
            first_signer: EscrowRole::Buyer,
            second_signer: EscrowRole::Vendor,
        }
    }

    /// Get the pair for refund transaction (buyer + arbiter)
    #[must_use]
    pub const fn refund() -> Self {
        Self {
            first_signer: EscrowRole::Buyer,
            second_signer: EscrowRole::Arbiter,
        }
    }

    /// Get the pair for dispute resolution (vendor + arbiter)
    #[must_use]
    pub const fn dispute() -> Self {
        Self {
            first_signer: EscrowRole::Vendor,
            second_signer: EscrowRole::Arbiter,
        }
    }

    /// Check if this pair includes a specific role
    #[must_use]
    pub fn includes(&self, role: EscrowRole) -> bool {
        self.first_signer == role || self.second_signer == role
    }

    /// Get the FROST identifiers for this pair
    #[must_use]
    pub fn frost_identifiers(&self) -> (u16, u16) {
        (
            self.first_signer.frost_identifier(),
            self.second_signer.frost_identifier(),
        )
    }
}

// =============================================================================
// FROST Key Share
// =============================================================================

/// A participant's FROST key share for 2-of-3 signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostKeyShare {
    /// Participant identifier (1-3)
    pub identifier: u16,
    /// Secret share (32 bytes, zeroize on drop)
    #[serde(with = "hex_serde")]
    pub secret_share: [u8; 32],
    /// Group public key (32 bytes)
    #[serde(with = "hex_serde")]
    pub group_public_key: [u8; 32],
    /// Verification shares for all participants
    pub verification_shares: Vec<VerificationShare>,
}

/// Verification share for a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationShare {
    /// Participant identifier
    pub identifier: u16,
    /// Verification key (32 bytes)
    #[serde(with = "hex_serde")]
    pub key: [u8; 32],
}

// =============================================================================
// Nonce Commitment (MuSig2-style)
// =============================================================================

/// Nonce commitment for signing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceCommitment {
    /// Commitment hash (Keccak256 of nonce point)
    #[serde(with = "hex_serde")]
    pub commitment: [u8; 32],
    /// Participant identifier
    pub identifier: u16,
}

/// Revealed nonce point
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceReveal {
    /// Nonce point (Ed25519 point, 32 bytes compressed)
    #[serde(with = "hex_serde")]
    pub nonce_point: [u8; 32],
    /// Participant identifier
    pub identifier: u16,
}

// =============================================================================
// Escrow Address Info
// =============================================================================

/// Information about a generated escrow address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowAddressInfo {
    /// The Monero address (base58 encoded)
    pub address: String,
    /// The group public key
    #[serde(with = "hex_serde")]
    pub group_public_key: [u8; 32],
    /// The group view key (derived)
    #[serde(with = "hex_serde")]
    pub group_view_key: [u8; 32],
    /// Escrow ID this address is for
    pub escrow_id: String,
}

// =============================================================================
// Hex Serialization Helper
// =============================================================================

mod hex_serde {
    use alloc::string::String;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escrow_role_frost_id() {
        assert_eq!(EscrowRole::Buyer.frost_identifier(), 1);
        assert_eq!(EscrowRole::Vendor.frost_identifier(), 2);
        assert_eq!(EscrowRole::Arbiter.frost_identifier(), 3);
    }

    #[test]
    fn test_escrow_role_from_frost_id() {
        assert_eq!(
            EscrowRole::from_frost_identifier(1),
            Some(EscrowRole::Buyer)
        );
        assert_eq!(
            EscrowRole::from_frost_identifier(2),
            Some(EscrowRole::Vendor)
        );
        assert_eq!(
            EscrowRole::from_frost_identifier(3),
            Some(EscrowRole::Arbiter)
        );
        assert_eq!(EscrowRole::from_frost_identifier(0), None);
        assert_eq!(EscrowRole::from_frost_identifier(4), None);
    }

    #[test]
    fn test_signing_pair_release() {
        let pair = SigningPair::release();
        assert_eq!(pair.first_signer, EscrowRole::Buyer);
        assert_eq!(pair.second_signer, EscrowRole::Vendor);
        assert!(pair.includes(EscrowRole::Buyer));
        assert!(pair.includes(EscrowRole::Vendor));
        assert!(!pair.includes(EscrowRole::Arbiter));
    }

    #[test]
    fn test_signing_pair_refund() {
        let pair = SigningPair::refund();
        assert!(pair.includes(EscrowRole::Buyer));
        assert!(pair.includes(EscrowRole::Arbiter));
        assert!(!pair.includes(EscrowRole::Vendor));
    }

    #[test]
    fn test_signing_pair_frost_ids() {
        let pair = SigningPair::release();
        assert_eq!(pair.frost_identifiers(), (1, 2));

        let pair = SigningPair::refund();
        assert_eq!(pair.frost_identifiers(), (1, 3));

        let pair = SigningPair::dispute();
        assert_eq!(pair.frost_identifiers(), (2, 3));
    }

    #[test]
    #[should_panic(expected = "Signing pair must have different roles")]
    fn test_signing_pair_same_role_panics() {
        let _ = SigningPair::new(EscrowRole::Buyer, EscrowRole::Buyer);
    }

    #[test]
    fn test_nonce_commitment_eq() {
        let nc1 = NonceCommitment {
            commitment: [1u8; 32],
            identifier: 1,
        };
        let nc2 = NonceCommitment {
            commitment: [1u8; 32],
            identifier: 1,
        };
        assert_eq!(nc1, nc2);
    }
}
