//! Monero address types and network definitions
//!
//! This module provides type-safe representations of Monero addresses
//! and network configurations.

use core::fmt;
use serde::{Deserialize, Serialize};

// =============================================================================
// Network Definition
// =============================================================================

/// Monero network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MoneroNetwork {
    /// Mainnet (production network)
    Mainnet,
    /// Stagenet (testing network with separate blockchain)
    Stagenet,
    /// Testnet (development network)
    Testnet,
}

impl MoneroNetwork {
    /// Get the address prefix for standard addresses
    #[must_use]
    pub const fn address_prefix(&self) -> u8 {
        match self {
            Self::Mainnet => 18,  // '4' in base58
            Self::Stagenet => 24, // '5' in base58
            Self::Testnet => 53,  // '9' in base58
        }
    }

    /// Get the address prefix for subaddresses
    #[must_use]
    pub const fn subaddress_prefix(&self) -> u8 {
        match self {
            Self::Mainnet => 42,  // '8' in base58
            Self::Stagenet => 36, // '7' in base58
            Self::Testnet => 63,  // 'B' in base58
        }
    }

    /// Get the address prefix for integrated addresses
    #[must_use]
    pub const fn integrated_prefix(&self) -> u8 {
        match self {
            Self::Mainnet => 19,  // '4' in base58 (longer)
            Self::Stagenet => 25, // '5' in base58 (longer)
            Self::Testnet => 54,  // '9' or 'A' in base58
        }
    }

    /// Get the expected first character for standard addresses
    #[must_use]
    pub const fn standard_first_char(&self) -> char {
        match self {
            Self::Mainnet => '4',
            Self::Stagenet => '5',
            Self::Testnet => '9',
        }
    }

    /// Get the expected first character for subaddresses
    #[must_use]
    pub const fn subaddress_first_char(&self) -> char {
        match self {
            Self::Mainnet => '8',
            Self::Stagenet => '7',
            Self::Testnet => 'B',
        }
    }

    /// Check if an address prefix matches this network
    #[must_use]
    pub fn matches_prefix(&self, first_char: char) -> bool {
        first_char == self.standard_first_char() || first_char == self.subaddress_first_char()
    }

    /// Parse network from string
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mainnet" | "main" => Some(Self::Mainnet),
            "stagenet" | "stage" => Some(Self::Stagenet),
            "testnet" | "test" => Some(Self::Testnet),
            _ => None,
        }
    }
}

impl fmt::Display for MoneroNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Stagenet => write!(f, "stagenet"),
            Self::Testnet => write!(f, "testnet"),
        }
    }
}

impl Default for MoneroNetwork {
    fn default() -> Self {
        Self::Mainnet
    }
}

// =============================================================================
// Address Types
// =============================================================================

/// Type of Monero address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressType {
    /// Standard address (derived from spend key)
    Standard,
    /// Subaddress (account + address index derivation)
    Subaddress,
    /// Integrated address (standard + 8-byte payment ID)
    Integrated,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard => write!(f, "standard"),
            Self::Subaddress => write!(f, "subaddress"),
            Self::Integrated => write!(f, "integrated"),
        }
    }
}

/// Decoded Monero address components
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAddress {
    /// Network this address belongs to
    pub network: MoneroNetwork,
    /// Type of address
    pub address_type: AddressType,
    /// Public spend key (32 bytes)
    pub spend_key: [u8; 32],
    /// Public view key (32 bytes)
    pub view_key: [u8; 32],
    /// Payment ID for integrated addresses (8 bytes)
    pub payment_id: Option<[u8; 8]>,
}

impl DecodedAddress {
    /// Create a new standard address
    #[must_use]
    pub fn new_standard(network: MoneroNetwork, spend_key: [u8; 32], view_key: [u8; 32]) -> Self {
        Self {
            network,
            address_type: AddressType::Standard,
            spend_key,
            view_key,
            payment_id: None,
        }
    }

    /// Create a new subaddress
    #[must_use]
    pub fn new_subaddress(network: MoneroNetwork, spend_key: [u8; 32], view_key: [u8; 32]) -> Self {
        Self {
            network,
            address_type: AddressType::Subaddress,
            spend_key,
            view_key,
            payment_id: None,
        }
    }

    /// Create a new integrated address
    #[must_use]
    pub fn new_integrated(
        network: MoneroNetwork,
        spend_key: [u8; 32],
        view_key: [u8; 32],
        payment_id: [u8; 8],
    ) -> Self {
        Self {
            network,
            address_type: AddressType::Integrated,
            spend_key,
            view_key,
            payment_id: Some(payment_id),
        }
    }

    /// Check if this is a standard address
    #[must_use]
    pub fn is_standard(&self) -> bool {
        matches!(self.address_type, AddressType::Standard)
    }

    /// Check if this is a subaddress
    #[must_use]
    pub fn is_subaddress(&self) -> bool {
        matches!(self.address_type, AddressType::Subaddress)
    }

    /// Check if this is an integrated address
    #[must_use]
    pub fn is_integrated(&self) -> bool {
        matches!(self.address_type, AddressType::Integrated)
    }
}

// =============================================================================
// Key Types (for address operations)
// =============================================================================

/// Length of a Monero public key in bytes
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Length of a Monero address checksum in bytes
pub const CHECKSUM_LENGTH: usize = 4;

/// Length of a standard Monero address after base58 decoding
pub const STANDARD_ADDRESS_DECODED_LENGTH: usize = 1 + PUBLIC_KEY_LENGTH * 2 + CHECKSUM_LENGTH; // 69

/// Length of an integrated address after base58 decoding
pub const INTEGRATED_ADDRESS_DECODED_LENGTH: usize =
    1 + PUBLIC_KEY_LENGTH * 2 + 8 + CHECKSUM_LENGTH; // 77

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_prefixes() {
        assert_eq!(MoneroNetwork::Mainnet.address_prefix(), 18);
        assert_eq!(MoneroNetwork::Stagenet.address_prefix(), 24);
        assert_eq!(MoneroNetwork::Testnet.address_prefix(), 53);
    }

    #[test]
    fn test_network_first_chars() {
        assert_eq!(MoneroNetwork::Mainnet.standard_first_char(), '4');
        assert_eq!(MoneroNetwork::Stagenet.standard_first_char(), '5');
        assert_eq!(MoneroNetwork::Testnet.standard_first_char(), '9');
    }

    #[test]
    fn test_network_matches_prefix() {
        assert!(MoneroNetwork::Mainnet.matches_prefix('4'));
        assert!(MoneroNetwork::Mainnet.matches_prefix('8'));
        assert!(!MoneroNetwork::Mainnet.matches_prefix('5'));
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!(
            MoneroNetwork::from_str("mainnet"),
            Some(MoneroNetwork::Mainnet)
        );
        assert_eq!(
            MoneroNetwork::from_str("STAGENET"),
            Some(MoneroNetwork::Stagenet)
        );
        assert_eq!(
            MoneroNetwork::from_str("test"),
            Some(MoneroNetwork::Testnet)
        );
        assert_eq!(MoneroNetwork::from_str("invalid"), None);
    }

    #[test]
    fn test_address_type_display() {
        assert_eq!(AddressType::Standard.to_string(), "standard");
        assert_eq!(AddressType::Subaddress.to_string(), "subaddress");
        assert_eq!(AddressType::Integrated.to_string(), "integrated");
    }

    #[test]
    fn test_decoded_address_constructors() {
        let spend_key = [1u8; 32];
        let view_key = [2u8; 32];
        let payment_id = [3u8; 8];

        let standard = DecodedAddress::new_standard(MoneroNetwork::Mainnet, spend_key, view_key);
        assert!(standard.is_standard());
        assert!(!standard.is_subaddress());

        let subaddr = DecodedAddress::new_subaddress(MoneroNetwork::Mainnet, spend_key, view_key);
        assert!(subaddr.is_subaddress());

        let integrated =
            DecodedAddress::new_integrated(MoneroNetwork::Mainnet, spend_key, view_key, payment_id);
        assert!(integrated.is_integrated());
        assert_eq!(integrated.payment_id, Some(payment_id));
    }
}
