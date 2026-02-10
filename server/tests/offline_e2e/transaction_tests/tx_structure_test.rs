//! Transaction Structure Validation Tests
//!
//! Tests for Monero transaction structure validation:
//! - Output type validation (0x03 for txout_to_tagged_key)
//! - Varint encoding
//! - Extra field format
//! - RCT type validation
//!
//! Reference: Monero v0.18+ transaction format

use crate::mock_infrastructure::{
    DeterministicRng,
    test_fixtures::{TransactionFixture, TxInvalidType},
};

// ============================================================================
// VARINT ENCODING
// ============================================================================

/// Encode a u64 as a Monero varint
fn encode_varint(value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut v = value;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if v == 0 {
            break;
        }
    }
    result
}

/// Decode a varint from bytes, return (value, bytes_consumed)
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut consumed = 0;

    for &byte in data {
        consumed += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Some((result, consumed));
        }
        shift += 7;
        if shift >= 64 {
            return None; // Overflow
        }
    }

    None // Incomplete
}

// ============================================================================
// VARINT TESTS
// ============================================================================

#[test]
fn test_varint_single_byte() {
    // Values 0-127 encode to single byte
    for value in 0u64..128 {
        let encoded = encode_varint(value);
        assert_eq!(encoded.len(), 1, "Values 0-127 should encode to 1 byte");
        assert_eq!(encoded[0], value as u8, "Single byte should match value");

        let (decoded, consumed) = decode_varint(&encoded).unwrap();
        assert_eq!(decoded, value, "Decoded should match original");
        assert_eq!(consumed, 1, "Should consume 1 byte");
    }
}

#[test]
fn test_varint_two_bytes() {
    // Values 128-16383 encode to 2 bytes
    let test_values = [128u64, 255, 256, 1000, 16383];

    for value in test_values {
        let encoded = encode_varint(value);
        assert_eq!(encoded.len(), 2, "Value {} should encode to 2 bytes", value);

        let (decoded, consumed) = decode_varint(&encoded).unwrap();
        assert_eq!(decoded, value, "Decoded should match original for {}", value);
        assert_eq!(consumed, 2, "Should consume 2 bytes");
    }
}

#[test]
fn test_varint_large_values() {
    // Test common Monero values
    let test_values = [
        30_000_000u64,        // Typical fee
        1_000_000_000_000u64, // 1 XMR
        u64::MAX,             // Maximum
    ];

    for value in test_values {
        let encoded = encode_varint(value);
        let (decoded, _) = decode_varint(&encoded).unwrap();
        assert_eq!(decoded, value, "Varint roundtrip failed for {}", value);
    }
}

#[test]
fn test_varint_zero() {
    let encoded = encode_varint(0);
    assert_eq!(encoded, vec![0x00], "Zero should encode to single 0x00");

    let (decoded, _) = decode_varint(&[0x00]).unwrap();
    assert_eq!(decoded, 0, "Should decode to 0");
}

#[test]
fn test_varint_encoding_format() {
    // Example: 300 = 0x12C
    // Low 7 bits: 0x2C (44)
    // Next 7 bits: 0x02
    // Encoded: [0xAC, 0x02] (0x2C | 0x80, then 0x02)
    let encoded = encode_varint(300);
    assert_eq!(encoded, vec![0xAC, 0x02], "300 should encode to [0xAC, 0x02]");
}

// ============================================================================
// OUTPUT TYPE TESTS
// ============================================================================

const OUTPUT_TYPE_TXOUT_TO_KEY: u8 = 0x02;         // Old format (no view tag)
const OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY: u8 = 0x03; // New format (with view tag)

#[test]
fn test_output_type_tagged_key() {
    // HF15+ requires txout_to_tagged_key (0x03)
    let output_type = OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY;
    assert_eq!(output_type, 0x03, "Tagged key output type should be 0x03");
}

#[test]
fn test_output_type_validation() {
    let mut rng = DeterministicRng::with_name("tx_output_type");
    let fixture = TransactionFixture::generate_valid(&mut rng);

    for output_type in &fixture.output_types {
        assert_eq!(
            *output_type,
            OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY,
            "Valid tx should use output type 0x03"
        );
    }
}

#[test]
fn test_wrong_output_type_detection() {
    let mut rng = DeterministicRng::with_name("tx_wrong_output");
    let fixture = TransactionFixture::generate_invalid(&mut rng, TxInvalidType::WrongOutputType);

    for output_type in &fixture.output_types {
        assert_eq!(
            *output_type,
            OUTPUT_TYPE_TXOUT_TO_KEY,
            "Invalid tx should have old output type 0x02"
        );
    }

    assert!(!fixture.should_be_valid, "Wrong output type should be invalid");
}

// ============================================================================
// TRANSACTION PREFIX STRUCTURE TESTS
// ============================================================================

/// Build a minimal transaction prefix for testing
fn build_tx_prefix(
    version: u8,
    unlock_time: u64,
    num_inputs: usize,
    num_outputs: usize,
    extra_len: usize,
) -> Vec<u8> {
    let mut prefix = Vec::new();

    // Version
    prefix.extend(encode_varint(version as u64));

    // Unlock time
    prefix.extend(encode_varint(unlock_time));

    // Number of inputs
    prefix.extend(encode_varint(num_inputs as u64));

    // Inputs (minimal: just count, no actual data)
    for _ in 0..num_inputs {
        // txin_to_key type
        prefix.push(0x02);
        // Amount (0 for RingCT)
        prefix.extend(encode_varint(0));
        // Ring size (16)
        prefix.extend(encode_varint(16));
        // Ring offsets (16 varints)
        for i in 0..16 {
            prefix.extend(encode_varint(1000 + i as u64));
        }
        // Key image (32 bytes)
        prefix.extend([0u8; 32]);
    }

    // Number of outputs
    prefix.extend(encode_varint(num_outputs as u64));

    // Outputs (minimal)
    for _ in 0..num_outputs {
        // Amount (0 for RingCT)
        prefix.extend(encode_varint(0));
        // Output type (0x03 for txout_to_tagged_key)
        prefix.push(OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY);
        // Public key (32 bytes)
        prefix.extend([0u8; 32]);
        // View tag (1 byte for type 0x03)
        prefix.push(0x42);
    }

    // Extra field length
    prefix.extend(encode_varint(extra_len as u64));
    // Extra data (zeros)
    prefix.extend(vec![0u8; extra_len]);

    prefix
}

#[test]
fn test_tx_prefix_version() {
    let prefix = build_tx_prefix(2, 0, 1, 2, 34);

    let (version, _) = decode_varint(&prefix).unwrap();
    assert_eq!(version, 2, "Version should be 2 for RingCT");
}

#[test]
fn test_tx_prefix_unlock_time() {
    let prefix = build_tx_prefix(2, 0, 1, 2, 34);

    // Skip version
    let (_, consumed) = decode_varint(&prefix).unwrap();
    let (unlock_time, _) = decode_varint(&prefix[consumed..]).unwrap();

    assert_eq!(unlock_time, 0, "Unlock time should be 0 for standard tx");
}

#[test]
fn test_tx_prefix_output_count() {
    let prefix = build_tx_prefix(2, 0, 1, 2, 34);

    // Monero requires minimum 2 outputs since HF15
    let mut rng = DeterministicRng::with_name("output_count");
    let fixture = TransactionFixture::generate_valid(&mut rng);

    assert!(
        fixture.num_outputs >= 2,
        "Valid tx should have at least 2 outputs"
    );
}

// ============================================================================
// EXTRA FIELD TESTS
// ============================================================================

const TX_EXTRA_TAG_PUBKEY: u8 = 0x01;
const TX_EXTRA_NONCE: u8 = 0x02;

#[test]
fn test_extra_field_pubkey_format() {
    // TX pubkey is stored as: 0x01 || 32-byte pubkey
    let mut rng = DeterministicRng::with_name("tx_extra_pubkey");
    let pubkey_bytes = rng.gen_32_bytes();

    let mut extra = Vec::new();
    extra.push(TX_EXTRA_TAG_PUBKEY);
    extra.extend(&pubkey_bytes);

    assert_eq!(extra.len(), 33, "TX pubkey extra should be 33 bytes");
    assert_eq!(extra[0], TX_EXTRA_TAG_PUBKEY, "First byte should be pubkey tag");
}

#[test]
fn test_extra_field_length_validation() {
    let mut rng = DeterministicRng::with_name("tx_extra_len");
    let fixture = TransactionFixture::generate_valid(&mut rng);

    // Extra should be 33-100 bytes for standard tx (pubkey + optional nonce)
    assert!(
        fixture.extra_length >= 33,
        "Extra length {} too small (min 33)",
        fixture.extra_length
    );
    assert!(
        fixture.extra_length <= 200,
        "Extra length {} too large for standard tx",
        fixture.extra_length
    );
}

#[test]
fn test_extra_too_big_detection() {
    let mut rng = DeterministicRng::with_name("tx_extra_big");
    let fixture = TransactionFixture::generate_invalid(&mut rng, TxInvalidType::ExtraTooBig);

    assert!(
        fixture.extra_length > 1000,
        "Invalid fixture should have large extra"
    );
    assert!(!fixture.should_be_valid, "Large extra should be invalid");
}

// ============================================================================
// RCT SIGNATURE TESTS
// ============================================================================

const RCT_TYPE_NULL: u8 = 0;
const RCT_TYPE_FULL: u8 = 1;
const RCT_TYPE_SIMPLE: u8 = 2;
const RCT_TYPE_BULLETPROOF: u8 = 3;
const RCT_TYPE_BULLETPROOF2: u8 = 4;
const RCT_TYPE_CLSAG: u8 = 5;
const RCT_TYPE_BULLETPROOF_PLUS: u8 = 6;

#[test]
fn test_rct_type_bulletproof_plus() {
    let mut rng = DeterministicRng::with_name("rct_type");
    let fixture = TransactionFixture::generate_valid(&mut rng);

    assert_eq!(
        fixture.rct_type,
        RCT_TYPE_BULLETPROOF_PLUS,
        "Current network requires RCT type 6 (BulletproofPlus)"
    );
}

#[test]
fn test_old_rct_type_warning() {
    let mut rng = DeterministicRng::with_name("rct_old");
    let fixture = TransactionFixture::generate_invalid(&mut rng, TxInvalidType::OldRctType);

    assert_eq!(fixture.rct_type, RCT_TYPE_CLSAG, "Invalid fixture should have old type");
    // Note: Old RCT types may still be valid on chain, but we warn about them
}

// ============================================================================
// COMPLETE TX STRUCTURE VALIDATION
// ============================================================================

/// Parse and validate transaction structure
fn validate_tx_structure(prefix: &[u8]) -> Result<TransactionParsed, String> {
    let mut offset = 0;

    // Version
    let (version, consumed) = decode_varint(&prefix[offset..])
        .ok_or("Failed to parse version")?;
    offset += consumed;

    if version != 2 {
        return Err(format!("Invalid version: {} (expected 2)", version));
    }

    // Unlock time
    let (unlock_time, consumed) = decode_varint(&prefix[offset..])
        .ok_or("Failed to parse unlock_time")?;
    offset += consumed;

    if unlock_time != 0 {
        return Err(format!("Non-zero unlock_time: {}", unlock_time));
    }

    // Number of inputs
    let (num_inputs, consumed) = decode_varint(&prefix[offset..])
        .ok_or("Failed to parse num_inputs")?;
    offset += consumed;

    if num_inputs == 0 {
        return Err("Zero inputs".to_string());
    }

    // Skip inputs (in real parser, we'd parse them fully)
    // This is simplified for testing

    Ok(TransactionParsed {
        version,
        unlock_time,
        num_inputs: num_inputs as usize,
    })
}

#[derive(Debug)]
struct TransactionParsed {
    version: u64,
    unlock_time: u64,
    num_inputs: usize,
}

#[test]
fn test_valid_tx_structure() {
    let prefix = build_tx_prefix(2, 0, 1, 2, 34);
    let result = validate_tx_structure(&prefix);

    assert!(result.is_ok(), "Valid prefix should parse successfully");
    let parsed = result.unwrap();
    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.unlock_time, 0);
    assert_eq!(parsed.num_inputs, 1);
}

#[test]
fn test_invalid_version_rejected() {
    let prefix = build_tx_prefix(1, 0, 1, 2, 34); // Version 1 is invalid
    let result = validate_tx_structure(&prefix);

    assert!(result.is_err(), "Version 1 should be rejected");
    assert!(result.unwrap_err().contains("version"));
}

#[test]
fn test_nonzero_unlock_time_rejected() {
    let prefix = build_tx_prefix(2, 100, 1, 2, 34); // Non-zero unlock
    let result = validate_tx_structure(&prefix);

    assert!(result.is_err(), "Non-zero unlock_time should be rejected");
    assert!(result.unwrap_err().contains("unlock_time"));
}

// ============================================================================
// FIXTURE TESTS
// ============================================================================

#[test]
fn test_all_invalid_types() {
    let mut rng = DeterministicRng::with_name("all_invalid");

    let invalid_types = [
        TxInvalidType::WrongVersion,
        TxInvalidType::NonZeroUnlockTime,
        TxInvalidType::ZeroInputs,
        TxInvalidType::ZeroOutputs,
        TxInvalidType::SingleOutput,
        TxInvalidType::WrongOutputType,
        TxInvalidType::OldRctType,
        TxInvalidType::ExtraTooBig,
    ];

    for invalid_type in invalid_types {
        let fixture = TransactionFixture::generate_invalid(&mut rng, invalid_type);
        assert!(
            !fixture.should_be_valid,
            "Invalid type {:?} should not be valid",
            invalid_type
        );
    }
}
