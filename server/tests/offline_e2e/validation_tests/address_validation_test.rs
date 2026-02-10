//! Address Validation Tests
//!
//! Tests for Monero address validation:
//! - Standard address format (95 characters, prefix 4/8)
//! - Subaddress format (95 characters, prefix 8)
//! - Integrated address format (106 characters, prefix 4)
//! - Testnet vs Mainnet prefixes
//! - Invalid address rejection
//!
//! Reference: Monero address format specification

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// ADDRESS CONSTANTS
// ============================================================================

/// Standard mainnet address length
const STANDARD_ADDRESS_LEN: usize = 95;

/// Integrated mainnet address length (includes payment ID)
const INTEGRATED_ADDRESS_LEN: usize = 106;

/// Mainnet standard address prefix
const MAINNET_STANDARD_PREFIX: u8 = 18;  // '4' in base58

/// Mainnet subaddress prefix
const MAINNET_SUBADDRESS_PREFIX: u8 = 42; // '8' in base58

/// Mainnet integrated address prefix
const MAINNET_INTEGRATED_PREFIX: u8 = 19; // '4' in base58 (different checksum)

/// Testnet standard address prefix
const TESTNET_STANDARD_PREFIX: u8 = 53;  // '9' in base58

/// Testnet subaddress prefix
const TESTNET_SUBADDRESS_PREFIX: u8 = 63; // 'A' in base58

/// Testnet integrated address prefix
const TESTNET_INTEGRATED_PREFIX: u8 = 54;

// ============================================================================
// ADDRESS TYPE ENUM
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    MainnetStandard,
    MainnetSubaddress,
    MainnetIntegrated,
    TestnetStandard,
    TestnetSubaddress,
    TestnetIntegrated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Stagenet,
}

// ============================================================================
// ADDRESS VALIDATION
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct AddressValidationResult {
    pub is_valid: bool,
    pub address_type: Option<AddressType>,
    pub network: Option<Network>,
    pub error: Option<AddressError>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AddressError {
    InvalidLength(usize),
    InvalidPrefix(char),
    InvalidCharacters,
    ChecksumMismatch,
    EmptyAddress,
    InvalidBase58,
}

/// Validate a Monero address string
pub fn validate_address(address: &str) -> AddressValidationResult {
    // Empty check (before trim)
    if address.is_empty() {
        return AddressValidationResult {
            is_valid: false,
            address_type: None,
            network: None,
            error: Some(AddressError::EmptyAddress),
        };
    }

    // Trim whitespace
    let address = address.trim();

    // Empty check (after trim - for whitespace-only input)
    if address.is_empty() {
        return AddressValidationResult {
            is_valid: false,
            address_type: None,
            network: None,
            error: Some(AddressError::EmptyAddress),
        };
    }

    // Length check
    let len = address.len();
    if len != STANDARD_ADDRESS_LEN && len != INTEGRATED_ADDRESS_LEN {
        return AddressValidationResult {
            is_valid: false,
            address_type: None,
            network: None,
            error: Some(AddressError::InvalidLength(len)),
        };
    }

    // First character determines network and type
    let first_char = address.chars().next().unwrap();
    let (address_type, network) = match first_char {
        '4' => {
            if len == INTEGRATED_ADDRESS_LEN {
                (AddressType::MainnetIntegrated, Network::Mainnet)
            } else {
                (AddressType::MainnetStandard, Network::Mainnet)
            }
        }
        '8' => (AddressType::MainnetSubaddress, Network::Mainnet),
        '9' => {
            if len == INTEGRATED_ADDRESS_LEN {
                (AddressType::TestnetIntegrated, Network::Testnet)
            } else {
                (AddressType::TestnetStandard, Network::Testnet)
            }
        }
        'A' | 'B' => (AddressType::TestnetSubaddress, Network::Testnet),
        _ => {
            return AddressValidationResult {
                is_valid: false,
                address_type: None,
                network: None,
                error: Some(AddressError::InvalidPrefix(first_char)),
            };
        }
    };

    // Character validation (Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz)
    const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for c in address.chars() {
        if !BASE58_ALPHABET.contains(c) {
            return AddressValidationResult {
                is_valid: false,
                address_type: Some(address_type),
                network: Some(network),
                error: Some(AddressError::InvalidCharacters),
            };
        }
    }

    // For this test suite, we don't implement full checksum validation
    // In production, you would decode Base58 and verify the checksum

    AddressValidationResult {
        is_valid: true,
        address_type: Some(address_type),
        network: Some(network),
        error: None,
    }
}

/// Check if address is valid for a specific network
pub fn is_valid_for_network(address: &str, network: Network) -> bool {
    let result = validate_address(address);
    result.is_valid && result.network == Some(network)
}

/// Check if address is a subaddress
pub fn is_subaddress(address: &str) -> bool {
    let result = validate_address(address);
    matches!(
        result.address_type,
        Some(AddressType::MainnetSubaddress) | Some(AddressType::TestnetSubaddress)
    )
}

/// Check if address is an integrated address
pub fn is_integrated_address(address: &str) -> bool {
    let result = validate_address(address);
    matches!(
        result.address_type,
        Some(AddressType::MainnetIntegrated) | Some(AddressType::TestnetIntegrated)
    )
}

// ============================================================================
// VALID ADDRESS TESTS
// ============================================================================

/// Generate a valid-looking mainnet address (for testing format validation)
fn generate_test_mainnet_address() -> String {
    // 4 + 94 chars of valid base58 = 95 total
    // Using 'A' repeated 94 times (valid base58 char)
    let suffix = "A".repeat(94);
    format!("4{}", suffix)
}

/// Generate a valid-looking testnet address
fn generate_test_testnet_address() -> String {
    // 9 + 94 chars = 95 total
    let suffix = "A".repeat(94);
    format!("9{}", suffix)
}

/// Generate a valid-looking subaddress
fn generate_test_subaddress() -> String {
    // 8 + 94 chars = 95 total
    let suffix = "A".repeat(94);
    format!("8{}", suffix)
}

/// Generate a valid-looking integrated address
fn generate_test_integrated_address() -> String {
    // 4 + 105 chars = 106 total (integrated addresses are longer)
    let suffix = "A".repeat(105);
    format!("4{}", suffix)
}

#[test]
fn test_valid_mainnet_address() {
    let address = generate_test_mainnet_address();
    let result = validate_address(&address);

    assert!(result.is_valid);
    assert_eq!(result.address_type, Some(AddressType::MainnetStandard));
    assert_eq!(result.network, Some(Network::Mainnet));
    assert!(result.error.is_none());
}

#[test]
fn test_valid_testnet_address() {
    let address = generate_test_testnet_address();
    let result = validate_address(&address);

    assert!(result.is_valid);
    assert_eq!(result.address_type, Some(AddressType::TestnetStandard));
    assert_eq!(result.network, Some(Network::Testnet));
}

#[test]
fn test_valid_subaddress() {
    let address = generate_test_subaddress();
    let result = validate_address(&address);

    assert!(result.is_valid);
    assert_eq!(result.address_type, Some(AddressType::MainnetSubaddress));
    assert!(is_subaddress(&address));
}

#[test]
fn test_valid_integrated_address() {
    let address = generate_test_integrated_address();
    let result = validate_address(&address);

    assert!(result.is_valid);
    assert_eq!(result.address_type, Some(AddressType::MainnetIntegrated));
    assert!(is_integrated_address(&address));
}

// ============================================================================
// LENGTH VALIDATION TESTS
// ============================================================================

#[test]
fn test_address_too_short() {
    let short_address = "4abc";
    let result = validate_address(short_address);

    assert!(!result.is_valid);
    assert_eq!(result.error, Some(AddressError::InvalidLength(4)));
}

#[test]
fn test_address_too_long() {
    let mut long_address = generate_test_mainnet_address();
    long_address.push_str("extra");
    let result = validate_address(&long_address);

    assert!(!result.is_valid);
    assert_eq!(result.error, Some(AddressError::InvalidLength(100)));
}

#[test]
fn test_address_exactly_95_chars() {
    let address = generate_test_mainnet_address();
    assert_eq!(address.len(), 95);

    let result = validate_address(&address);
    assert!(result.is_valid);
}

#[test]
fn test_address_exactly_106_chars() {
    let address = generate_test_integrated_address();
    assert_eq!(address.len(), 106);

    let result = validate_address(&address);
    assert!(result.is_valid);
}

#[test]
fn test_94_char_address_invalid() {
    let suffix = "1".repeat(93);
    let address = format!("4{}", suffix); // 94 chars total
    let result = validate_address(&address);

    assert!(!result.is_valid);
    assert_eq!(result.error, Some(AddressError::InvalidLength(94)));
}

#[test]
fn test_96_char_address_invalid() {
    let suffix = "1".repeat(95);
    let address = format!("4{}", suffix); // 96 chars total
    let result = validate_address(&address);

    assert!(!result.is_valid);
    assert_eq!(result.error, Some(AddressError::InvalidLength(96)));
}

// ============================================================================
// PREFIX VALIDATION TESTS
// ============================================================================

#[test]
fn test_invalid_prefix() {
    let suffix = "1".repeat(94);
    let address = format!("X{}", suffix);
    let result = validate_address(&address);

    assert!(!result.is_valid);
    assert_eq!(result.error, Some(AddressError::InvalidPrefix('X')));
}

#[test]
fn test_all_valid_prefixes() {
    let suffix = "1".repeat(94);

    // Mainnet standard (4)
    let addr = format!("4{}", &suffix);
    assert!(validate_address(&addr).is_valid, "Prefix '4' should be valid");

    // Mainnet subaddress (8)
    let addr = format!("8{}", &suffix);
    assert!(validate_address(&addr).is_valid, "Prefix '8' should be valid");

    // Testnet standard (9)
    let addr = format!("9{}", &suffix);
    assert!(validate_address(&addr).is_valid, "Prefix '9' should be valid");

    // Testnet subaddress (A)
    let addr = format!("A{}", &suffix);
    assert!(validate_address(&addr).is_valid, "Prefix 'A' should be valid");
}

#[test]
fn test_numeric_prefix_invalid() {
    let suffix = "1".repeat(94);

    // '0' is not in base58
    let addr = format!("0{}", &suffix);
    let result = validate_address(&addr);
    assert!(!result.is_valid);
}

// ============================================================================
// CHARACTER VALIDATION TESTS
// ============================================================================

#[test]
fn test_invalid_base58_chars() {
    // Characters NOT in base58: 0, I, O, l
    let invalid_chars = ['0', 'I', 'O', 'l'];

    for c in invalid_chars {
        let mut address = generate_test_mainnet_address();
        // Replace a character with invalid one
        let mut chars: Vec<char> = address.chars().collect();
        chars[10] = c;
        address = chars.into_iter().collect();

        let result = validate_address(&address);
        assert!(
            !result.is_valid || result.error == Some(AddressError::InvalidCharacters),
            "Character '{}' should be invalid",
            c
        );
    }
}

#[test]
fn test_lowercase_valid() {
    // Base58 includes lowercase a-z except 'l'
    let valid_lowercase = "abcdefghijkmnopqrstuvwxyz"; // Note: no 'l'

    for c in valid_lowercase.chars() {
        let suffix = format!("{}{}", c, "1".repeat(93));
        let address = format!("4{}", suffix);
        let result = validate_address(&address);
        assert!(
            result.is_valid,
            "Lowercase '{}' should be valid in base58",
            c
        );
    }
}

#[test]
fn test_special_chars_invalid() {
    let special_chars = ['!', '@', '#', '$', '%', ' ', '-', '_', '.'];

    for c in special_chars {
        let mut address = generate_test_mainnet_address();
        let mut chars: Vec<char> = address.chars().collect();
        chars[10] = c;
        address = chars.into_iter().collect();

        let result = validate_address(&address);
        assert!(
            !result.is_valid,
            "Special character '{}' should be invalid",
            c
        );
    }
}

// ============================================================================
// NETWORK-SPECIFIC TESTS
// ============================================================================

#[test]
fn test_mainnet_address_on_testnet_invalid() {
    let address = generate_test_mainnet_address();

    assert!(!is_valid_for_network(&address, Network::Testnet));
    assert!(is_valid_for_network(&address, Network::Mainnet));
}

#[test]
fn test_testnet_address_on_mainnet_invalid() {
    let address = generate_test_testnet_address();

    assert!(!is_valid_for_network(&address, Network::Mainnet));
    assert!(is_valid_for_network(&address, Network::Testnet));
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_empty_address() {
    let result = validate_address("");

    assert!(!result.is_valid);
    assert_eq!(result.error, Some(AddressError::EmptyAddress));
}

#[test]
fn test_whitespace_only() {
    let result = validate_address("   ");

    assert!(!result.is_valid);
    assert_eq!(result.error, Some(AddressError::EmptyAddress));
}

#[test]
fn test_address_with_leading_whitespace() {
    let address = format!("  {}", generate_test_mainnet_address());
    let result = validate_address(&address);

    // Should trim and validate successfully
    assert!(result.is_valid);
}

#[test]
fn test_address_with_trailing_whitespace() {
    let address = format!("{}  ", generate_test_mainnet_address());
    let result = validate_address(&address);

    assert!(result.is_valid);
}

#[test]
fn test_all_same_character() {
    // 95 '1's with valid prefix
    let address = "4".to_string() + &"1".repeat(94);
    let result = validate_address(&address);

    assert!(result.is_valid);
}

// ============================================================================
// HELPER FUNCTION TESTS
// ============================================================================

#[test]
fn test_is_subaddress_helper() {
    let standard = generate_test_mainnet_address();
    let subaddr = generate_test_subaddress();

    assert!(!is_subaddress(&standard));
    assert!(is_subaddress(&subaddr));
}

#[test]
fn test_is_integrated_helper() {
    let standard = generate_test_mainnet_address();
    let integrated = generate_test_integrated_address();

    assert!(!is_integrated_address(&standard));
    assert!(is_integrated_address(&integrated));
}

// ============================================================================
// DETERMINISM TESTS
// ============================================================================

#[test]
fn test_validation_deterministic() {
    let address = generate_test_mainnet_address();

    let result1 = validate_address(&address);
    let result2 = validate_address(&address);

    assert_eq!(result1, result2);
}

#[test]
fn test_validation_consistent_for_random_input() {
    let mut rng = DeterministicRng::with_name("addr_consistency");

    for _ in 0..100 {
        let random_bytes = rng.gen_32_bytes();
        let random_str: String = random_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let r1 = validate_address(&random_str);
        let r2 = validate_address(&random_str);

        assert_eq!(r1.is_valid, r2.is_valid);
        assert_eq!(r1.error, r2.error);
    }
}
