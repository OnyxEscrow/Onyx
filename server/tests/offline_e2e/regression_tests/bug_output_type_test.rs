//! Bug Regression: Wrong Output Type (Bug #2.11)
//!
//! ## Original Bug
//! Transaction outputs were created with type 0x02 (txout_to_key) instead of
//! type 0x03 (txout_to_tagged_key), causing transactions to be rejected
//! by the network after HF15.
//!
//! ## Root Cause
//! After Monero hard fork 15, all outputs must use type 0x03 which includes
//! a view tag for faster scanning. Using the old 0x02 type is invalid.
//!
//! ## Fix
//! Always use output type 0x03 (txout_to_tagged_key) for all outputs.
//!
//! ## Reference
//! - Monero HF15 specification
//! - server/src/services/transaction_builder.rs

// ============================================================================
// OUTPUT TYPE CONSTANTS
// ============================================================================

/// Old output type (pre-HF15, no view tag)
const OUTPUT_TYPE_TXOUT_TO_KEY: u8 = 0x02;

/// New output type (HF15+, with view tag)
const OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY: u8 = 0x03;

/// Current network output type requirement
const REQUIRED_OUTPUT_TYPE: u8 = OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY;

// ============================================================================
// OUTPUT STRUCTURE
// ============================================================================

#[derive(Debug, Clone)]
pub struct TransactionOutput {
    pub amount: u64,       // 0 for RingCT
    pub output_type: u8,
    pub public_key: [u8; 32],
    pub view_tag: Option<u8>, // Only for type 0x03
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputValidationError {
    WrongOutputType { got: u8, expected: u8 },
    MissingViewTag,
    UnexpectedViewTag,
    InvalidPublicKey,
}

// ============================================================================
// OUTPUT CREATION FUNCTIONS
// ============================================================================

/// BUG: Creates output with old type 0x02 (vulnerable)
fn create_output_buggy(public_key: [u8; 32]) -> TransactionOutput {
    TransactionOutput {
        amount: 0,
        output_type: OUTPUT_TYPE_TXOUT_TO_KEY, // BUG: Wrong type!
        public_key,
        view_tag: None, // No view tag for old type
    }
}

/// FIXED: Creates output with correct type 0x03
fn create_output_fixed(public_key: [u8; 32], view_tag: u8) -> TransactionOutput {
    TransactionOutput {
        amount: 0,
        output_type: OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY, // Correct type
        public_key,
        view_tag: Some(view_tag),
    }
}

// ============================================================================
// VALIDATION FUNCTIONS
// ============================================================================

/// Validate a single output
fn validate_output(output: &TransactionOutput) -> Result<(), OutputValidationError> {
    // Check output type
    if output.output_type != REQUIRED_OUTPUT_TYPE {
        return Err(OutputValidationError::WrongOutputType {
            got: output.output_type,
            expected: REQUIRED_OUTPUT_TYPE,
        });
    }

    // Type 0x03 requires view tag
    if output.output_type == OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY && output.view_tag.is_none() {
        return Err(OutputValidationError::MissingViewTag);
    }

    // Type 0x02 should NOT have view tag
    if output.output_type == OUTPUT_TYPE_TXOUT_TO_KEY && output.view_tag.is_some() {
        return Err(OutputValidationError::UnexpectedViewTag);
    }

    Ok(())
}

/// Validate all outputs in a transaction
fn validate_transaction_outputs(outputs: &[TransactionOutput]) -> Result<(), OutputValidationError> {
    for output in outputs {
        validate_output(output)?;
    }
    Ok(())
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

#[test]
fn test_buggy_output_type_rejected() {
    use crate::mock_infrastructure::DeterministicRng;
    let mut rng = DeterministicRng::with_name("buggy_output");

    let public_key = rng.gen_32_bytes();

    // Create output using buggy function
    let output = create_output_buggy(public_key);

    // Validate should fail
    let result = validate_output(&output);
    assert!(matches!(
        result,
        Err(OutputValidationError::WrongOutputType { .. })
    ));
}

#[test]
fn test_fixed_output_type_accepted() {
    use crate::mock_infrastructure::DeterministicRng;
    let mut rng = DeterministicRng::with_name("fixed_output");

    let public_key = rng.gen_32_bytes();
    let view_tag = 0x42u8;

    // Create output using fixed function
    let output = create_output_fixed(public_key, view_tag);

    // Validate should succeed
    let result = validate_output(&output);
    assert!(result.is_ok());
}

#[test]
fn test_output_type_bytes() {
    // Verify exact byte values
    assert_eq!(OUTPUT_TYPE_TXOUT_TO_KEY, 0x02);
    assert_eq!(OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY, 0x03);
    assert_eq!(REQUIRED_OUTPUT_TYPE, 0x03);
}

// ============================================================================
// OUTPUT TYPE DETECTION TESTS
// ============================================================================

#[test]
fn test_detect_wrong_output_type_0x02() {
    let output = TransactionOutput {
        amount: 0,
        output_type: 0x02,
        public_key: [0u8; 32],
        view_tag: None,
    };

    let result = validate_output(&output);
    assert_eq!(
        result,
        Err(OutputValidationError::WrongOutputType {
            got: 0x02,
            expected: 0x03,
        })
    );
}

#[test]
fn test_detect_wrong_output_type_0x01() {
    // Even older type (txout_to_script)
    let output = TransactionOutput {
        amount: 0,
        output_type: 0x01,
        public_key: [0u8; 32],
        view_tag: None,
    };

    let result = validate_output(&output);
    assert!(matches!(
        result,
        Err(OutputValidationError::WrongOutputType { .. })
    ));
}

#[test]
fn test_detect_unknown_output_type() {
    let output = TransactionOutput {
        amount: 0,
        output_type: 0xFF, // Unknown type
        public_key: [0u8; 32],
        view_tag: None,
    };

    let result = validate_output(&output);
    assert!(matches!(
        result,
        Err(OutputValidationError::WrongOutputType { .. })
    ));
}

// ============================================================================
// VIEW TAG TESTS
// ============================================================================

#[test]
fn test_type_0x03_requires_view_tag() {
    let output = TransactionOutput {
        amount: 0,
        output_type: 0x03,
        public_key: [0u8; 32],
        view_tag: None, // Missing!
    };

    let result = validate_output(&output);
    assert_eq!(result, Err(OutputValidationError::MissingViewTag));
}

#[test]
fn test_type_0x03_with_view_tag_valid() {
    let output = TransactionOutput {
        amount: 0,
        output_type: 0x03,
        public_key: [0u8; 32],
        view_tag: Some(0x42),
    };

    let result = validate_output(&output);
    assert!(result.is_ok());
}

#[test]
fn test_view_tag_all_values() {
    // All 256 possible view tag values should be valid
    for tag in 0u8..=255 {
        let output = TransactionOutput {
            amount: 0,
            output_type: 0x03,
            public_key: [0u8; 32],
            view_tag: Some(tag),
        };

        let result = validate_output(&output);
        assert!(result.is_ok(), "View tag {} should be valid", tag);
    }
}

// ============================================================================
// TRANSACTION VALIDATION TESTS
// ============================================================================

#[test]
fn test_tx_all_outputs_valid() {
    use crate::mock_infrastructure::DeterministicRng;
    let mut rng = DeterministicRng::with_name("tx_valid");

    let outputs: Vec<TransactionOutput> = (0..16)
        .map(|_| create_output_fixed(rng.gen_32_bytes(), rng.gen_range(256) as u8))
        .collect();

    let result = validate_transaction_outputs(&outputs);
    assert!(result.is_ok());
}

#[test]
fn test_tx_one_invalid_output_fails() {
    use crate::mock_infrastructure::DeterministicRng;
    let mut rng = DeterministicRng::with_name("tx_one_invalid");

    // Create 15 valid outputs and 1 invalid
    let mut outputs: Vec<TransactionOutput> = (0..15)
        .map(|_| create_output_fixed(rng.gen_32_bytes(), rng.gen_range(256) as u8))
        .collect();

    // Add one buggy output
    outputs.push(create_output_buggy(rng.gen_32_bytes()));

    let result = validate_transaction_outputs(&outputs);
    assert!(result.is_err());
}

#[test]
fn test_tx_empty_outputs_valid() {
    let outputs: Vec<TransactionOutput> = vec![];
    let result = validate_transaction_outputs(&outputs);
    assert!(result.is_ok()); // Empty is valid (though unrealistic)
}

// ============================================================================
// SERIALIZATION FORMAT TESTS
// ============================================================================

/// Serialize output to bytes (simplified)
fn serialize_output(output: &TransactionOutput) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Amount (varint, simplified as 0x00 for RingCT)
    bytes.push(0x00);

    // Output type
    bytes.push(output.output_type);

    // Public key (32 bytes)
    bytes.extend(&output.public_key);

    // View tag (1 byte, only for type 0x03)
    if output.output_type == OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY {
        if let Some(tag) = output.view_tag {
            bytes.push(tag);
        }
    }

    bytes
}

#[test]
fn test_serialized_output_type_0x02_length() {
    let output = create_output_buggy([0xAA; 32]);
    let bytes = serialize_output(&output);

    // 1 (amount) + 1 (type) + 32 (pubkey) = 34 bytes
    assert_eq!(bytes.len(), 34);
    assert_eq!(bytes[1], 0x02); // Type byte
}

#[test]
fn test_serialized_output_type_0x03_length() {
    let output = create_output_fixed([0xAA; 32], 0x42);
    let bytes = serialize_output(&output);

    // 1 (amount) + 1 (type) + 32 (pubkey) + 1 (view_tag) = 35 bytes
    assert_eq!(bytes.len(), 35);
    assert_eq!(bytes[1], 0x03); // Type byte
    assert_eq!(bytes[34], 0x42); // View tag
}

#[test]
fn test_type_byte_position() {
    use crate::mock_infrastructure::DeterministicRng;
    let mut rng = DeterministicRng::with_name("type_position");

    let output = create_output_fixed(rng.gen_32_bytes(), rng.gen_range(256) as u8);
    let bytes = serialize_output(&output);

    // Type byte is at position 1 (after amount varint)
    assert_eq!(bytes[1], OUTPUT_TYPE_TXOUT_TO_TAGGED_KEY);
}

// ============================================================================
// DETERMINISM TESTS
// ============================================================================

#[test]
fn test_output_creation_deterministic() {
    use crate::mock_infrastructure::DeterministicRng;
    let mut rng = DeterministicRng::with_name("output_det");

    let pk = rng.gen_32_bytes();
    let tag = rng.gen_range(256) as u8;

    let output1 = create_output_fixed(pk, tag);
    let output2 = create_output_fixed(pk, tag);

    assert_eq!(output1.output_type, output2.output_type);
    assert_eq!(output1.public_key, output2.public_key);
    assert_eq!(output1.view_tag, output2.view_tag);
}

// ============================================================================
// NETWORK COMPATIBILITY TESTS
// ============================================================================

#[test]
fn test_hf15_requirement() {
    // After HF15, only type 0x03 is accepted
    let valid_types = [0x03u8]; // Only one valid type now

    for t in 0u8..=0x10 {
        let output = TransactionOutput {
            amount: 0,
            output_type: t,
            public_key: [0u8; 32],
            view_tag: if t == 0x03 { Some(0) } else { None },
        };

        let result = validate_output(&output);
        if valid_types.contains(&t) {
            assert!(result.is_ok(), "Type 0x{:02X} should be valid post-HF15", t);
        } else {
            assert!(result.is_err(), "Type 0x{:02X} should be invalid post-HF15", t);
        }
    }
}
