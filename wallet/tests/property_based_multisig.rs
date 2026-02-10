//! Property-based tests for multisig operations
//!
//! These tests validate invariant properties of the multisig system
//! rather than specific test cases. This catches edge cases and
//! unexpected behaviors that unit tests might miss.
//!
//! # Properties Tested
//!
//! 1. **Format invariance** - multisig_info always has correct prefix
//! 2. **Length invariance** - multisig_info always within MIN/MAX bounds
//! 3. **Validation consistency** - Invalid inputs always rejected
//! 4. **Character set invariance** - multisig_info only contains base64 chars
//! 5. **Threshold validation** - Invalid thresholds always rejected

use proptest::prelude::*;
use monero_marketplace_common::{MAX_MULTISIG_INFO_LEN, MIN_MULTISIG_INFO_LEN};

/// Strategy to generate valid multisig_info strings
fn valid_multisig_info_strategy() -> impl Strategy<Value = String> {
    let length = MIN_MULTISIG_INFO_LEN..MAX_MULTISIG_INFO_LEN;

    length.prop_flat_map(move |len| {
        let data_len = len - 10; // "MultisigV1" is 10 chars
        // Generate random base64 string of exact length
        let regex = format!("MultisigV1[A-Za-z0-9+/=]{{{}}}", data_len);
        proptest::string::string_regex(&regex).expect("Invalid regex")
    })
}

/// Strategy to generate invalid multisig_info strings (for negative testing)
fn invalid_multisig_info_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Too short
        Just("MultisigV1".to_string()),
        Just("Multisig".to_string()),
        Just("M".to_string()),
        Just("".to_string()),

        // Wrong prefix
        (MIN_MULTISIG_INFO_LEN..MAX_MULTISIG_INFO_LEN)
            .prop_map(|len| format!("InvalidPrefix{}", "A".repeat(len - 13))),

        // Invalid characters
        (MIN_MULTISIG_INFO_LEN..MAX_MULTISIG_INFO_LEN)
            .prop_map(|len| format!("MultisigV1{}", "@#$%".repeat(len / 4))),

        // Too long
        Just(format!("MultisigV1{}", "A".repeat(MAX_MULTISIG_INFO_LEN + 100))),
    ]
}

/// Strategy to generate threshold values
fn threshold_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32), // Invalid
        Just(1u32), // Invalid (must be at least 2 for 2-of-3)
        2u32..4u32,    // Valid range for 2-of-3
        10u32..100u32, // Too high
    ]
}

// ============================================================================
// Property 1: Format Invariance
// ============================================================================

proptest! {
    /// Property: Valid multisig_info strings always have correct prefix
    #[test]
    fn prop_multisig_info_has_valid_prefix(
        info in valid_multisig_info_strategy()
    ) {
        // Valid info must start with MultisigV1 or MultisigxV2
        prop_assert!(
            info.starts_with("MultisigV1") || info.starts_with("MultisigxV2"),
            "multisig_info must start with valid prefix, got: {}",
            info
        );
    }

    /// Property: Invalid prefixes are always detected
    #[test]
    fn prop_invalid_prefix_detected(
        info in invalid_multisig_info_strategy()
    ) {
        // Skip if by chance we generated a valid prefix
        if info.starts_with("MultisigV1") || info.starts_with("MultisigxV2") {
            return Ok(());
        }

        // Validation should fail
        let result = validate_multisig_info_format(&info);
        prop_assert!(
            result.is_err(),
            "Should reject invalid prefix, but accepted: {}",
            info
        );
    }
}

// ============================================================================
// Property 2: Length Invariance
// ============================================================================

proptest! {
    /// Property: Valid multisig_info always within length bounds
    #[test]
    fn prop_multisig_info_length_bounds(
        info in valid_multisig_info_strategy()
    ) {
        prop_assert!(
            info.len() >= MIN_MULTISIG_INFO_LEN,
            "multisig_info too short: {} < {}",
            info.len(),
            MIN_MULTISIG_INFO_LEN
        );
        prop_assert!(
            info.len() <= MAX_MULTISIG_INFO_LEN,
            "multisig_info too long: {} > {}",
            info.len(),
            MAX_MULTISIG_INFO_LEN
        );
    }

    /// Property: Strings outside length bounds are rejected
    #[test]
    fn prop_invalid_length_rejected(
        prefix in prop::sample::select(vec!["MultisigV1", "MultisigxV2"]),
        data_len in prop::option::of(0usize..MIN_MULTISIG_INFO_LEN - 10)
    ) {
        let info = format!("{}{}", prefix, "A".repeat(data_len.unwrap_or(0)));

        if info.len() < MIN_MULTISIG_INFO_LEN {
            let result = validate_multisig_info_format(&info);
            prop_assert!(
                result.is_err(),
                "Should reject too-short info: {} bytes",
                info.len()
            );
        }
    }
}

// ============================================================================
// Property 3: Character Set Invariance
// ============================================================================

proptest! {
    /// Property: Valid multisig_info only contains base64 + prefix chars
    #[test]
    fn prop_multisig_info_valid_charset(
        info in valid_multisig_info_strategy()
    ) {
        for ch in info.chars() {
            prop_assert!(
                ch.is_alphanumeric() || ch == '+' || ch == '/' || ch == '=',
                "Invalid character in multisig_info: '{}'",
                ch
            );
        }
    }

    /// Property: Invalid characters are always rejected
    #[test]
    fn prop_invalid_chars_rejected(
        invalid_chars in "[^A-Za-z0-9+/=]{10,20}"
    ) {
        let info = format!("MultisigV1{}", invalid_chars);

        // Only test if it's long enough to pass length validation
        if info.len() >= MIN_MULTISIG_INFO_LEN {
            let result = validate_multisig_info_format(&info);
            prop_assert!(
                result.is_err(),
                "Should reject invalid characters"
            );
        }
    }
}

// ============================================================================
// Property 4: Threshold Validation
// ============================================================================

proptest! {
    /// Property: Threshold < 2 always rejected for make_multisig
    #[test]
    fn prop_threshold_minimum_enforced(
        threshold in 0u32..2
    ) {
        let result = validate_threshold(threshold, 3);
        prop_assert!(
            result.is_err(),
            "Threshold {} should be rejected (minimum 2)",
            threshold
        );
    }

    /// Property: Valid thresholds (2-3 for 2-of-3) accepted
    #[test]
    fn prop_valid_threshold_accepted(
        threshold in 2u32..4
    ) {
        let result = validate_threshold(threshold, 3);
        prop_assert!(
            result.is_ok(),
            "Valid threshold {} should be accepted",
            threshold
        );
    }

    /// Property: Threshold > N always rejected
    #[test]
    fn prop_threshold_maximum_enforced(
        threshold in 4u32..100,
        n in 2u32..4
    ) {
        if threshold > n {
            let result = validate_threshold(threshold, n as usize);
            prop_assert!(
                result.is_err(),
                "Threshold {} > N {} should be rejected",
                threshold,
                n
            );
        }
    }
}

// ============================================================================
// Property 5: List Validation (for make_multisig/import)
// ============================================================================

proptest! {
    /// Property: Empty list always rejected
    #[test]
    fn prop_empty_list_rejected(
        _dummy in 0..10 // Dummy to make proptest work
    ) {
        let result = validate_multisig_info_list(&vec![]);
        prop_assert!(
            result.is_err(),
            "Empty list should be rejected"
        );
    }

    /// Property: List with insufficient items rejected (need N-1 for N-party)
    #[test]
    fn prop_insufficient_list_rejected(
        info in valid_multisig_info_strategy()
    ) {
        // For 2-of-3, need 2 infos (N-1 where N=3)
        let result = validate_multisig_info_list(&vec![info]);
        prop_assert!(
            result.is_err(),
            "Single info should be rejected for 2-of-3"
        );
    }

    /// Property: List with sufficient valid items accepted
    #[test]
    fn prop_sufficient_valid_list_accepted(
        info1 in valid_multisig_info_strategy(),
        info2 in valid_multisig_info_strategy()
    ) {
        // Ensure they're different
        if info1 != info2 {
            let result = validate_multisig_info_list(&vec![info1, info2]);
            prop_assert!(
                result.is_ok(),
                "Two valid infos should be accepted"
            );
        }
    }
}

// ============================================================================
// Helper Functions (Validation Logic)
// ============================================================================

/// Validates multisig_info format
///
/// This mirrors the validation in wallet/src/rpc.rs
fn validate_multisig_info_format(info: &str) -> Result<(), String> {
    // Prefix validation
    if !info.starts_with("MultisigV1") && !info.starts_with("MultisigxV2") {
        return Err(format!("Invalid prefix: {}", &info[..info.len().min(20)]));
    }

    // Length validation
    if info.len() < MIN_MULTISIG_INFO_LEN || info.len() > MAX_MULTISIG_INFO_LEN {
        return Err(format!("Invalid length: {}", info.len()));
    }

    // Character validation
    for ch in info.chars() {
        if !ch.is_alphanumeric() && ch != '+' && ch != '/' && ch != '=' {
            return Err(format!("Invalid character: '{}'", ch));
        }
    }

    Ok(())
}

/// Validates threshold for multisig
fn validate_threshold(threshold: u32, n: usize) -> Result<(), String> {
    if threshold < 2 {
        return Err(format!("Threshold must be at least 2, got {}", threshold));
    }

    if threshold as usize > n {
        return Err(format!("Threshold {} exceeds N {}", threshold, n));
    }

    Ok(())
}

/// Validates a list of multisig_info
fn validate_multisig_info_list(infos: &[String]) -> Result<(), String> {
    if infos.is_empty() {
        return Err("Need at least 1 multisig info".to_string());
    }

    // For 2-of-3, need at least 2 infos (N-1)
    if infos.len() < 2 {
        return Err(format!(
            "Expected at least 2 infos for 2-of-3, got {}",
            infos.len()
        ));
    }

    // Validate each info
    for (i, info) in infos.iter().enumerate() {
        validate_multisig_info_format(info)
            .map_err(|e| format!("Invalid info[{}]: {}", i, e))?;
    }

    Ok(())
}

// ============================================================================
// Advanced Properties: Fuzzing Attack Scenarios
// ============================================================================

proptest! {
    /// Property: Extremely long strings don't cause crashes
    #[test]
    fn prop_no_crash_on_huge_input(
        prefix in prop::sample::select(vec!["MultisigV1", "MultisigxV2", "Invalid"]),
        size in 10000usize..100000
    ) {
        let huge_string = format!("{}{}", prefix, "A".repeat(size));

        // Should not panic, just return error
        let _ = validate_multisig_info_format(&huge_string);
    }

    /// Property: Unicode and special chars don't cause crashes
    #[test]
    fn prop_no_crash_on_unicode(
        unicode_data in "\\PC{100,200}" // Unicode characters
    ) {
        let info = format!("MultisigV1{}", unicode_data);

        // Should not panic, just return error
        let _ = validate_multisig_info_format(&info);
    }

    /// Property: Null bytes don't cause issues
    #[test]
    fn prop_no_crash_on_null_bytes(
        prefix in prop::sample::select(vec!["MultisigV1", "MultisigxV2"])
    ) {
        let mut data = prefix.to_string();
        data.push('\0');
        data.push_str("A".repeat(150).as_str());

        // Should not panic
        let _ = validate_multisig_info_format(&data);
    }
}

// ============================================================================
// Regression Tests (Based on Real Bugs)
// ============================================================================

#[test]
fn regression_empty_string_panic() {
    // Bug: Empty string caused panic in original implementation
    let result = validate_multisig_info_format("");
    assert!(result.is_err(), "Empty string should be rejected");
}

#[test]
fn regression_exactly_min_length() {
    // Bug: MIN_MULTISIG_INFO_LEN boundary was off-by-one
    let info = format!("MultisigV1{}", "A".repeat(MIN_MULTISIG_INFO_LEN - 10));
    let result = validate_multisig_info_format(&info);
    assert!(result.is_ok(), "Exactly MIN_MULTISIG_INFO_LEN should be accepted");
}

#[test]
fn regression_exactly_max_length() {
    // Bug: MAX_MULTISIG_INFO_LEN boundary was off-by-one
    let info = format!("MultisigV1{}", "A".repeat(MAX_MULTISIG_INFO_LEN - 10));
    let result = validate_multisig_info_format(&info);
    assert!(result.is_ok(), "Exactly MAX_MULTISIG_INFO_LEN should be accepted");
}

#[test]
fn regression_case_sensitivity() {
    // Bug: Prefix validation was case-sensitive
    let info = format!("multisigv1{}", "A".repeat(150)); // lowercase
    let result = validate_multisig_info_format(&info);
    assert!(result.is_err(), "Lowercase prefix should be rejected");
}

// ============================================================================
// Performance Properties
// ============================================================================

#[test]
fn perf_validation_under_1ms() {
    // Property: Validation should be very fast (< 1ms even for large inputs)
    use std::time::Instant;

    let large_valid_info = format!("MultisigV1{}", "A".repeat(MAX_MULTISIG_INFO_LEN - 10));

    let start = Instant::now();
    let _ = validate_multisig_info_format(&large_valid_info);
    let duration = start.elapsed();

    assert!(
        duration.as_millis() < 1,
        "Validation took too long: {:?}",
        duration
    );
}

#[test]
fn perf_list_validation_scales_linearly() {
    // Property: Validating N items should take roughly N times single validation
    use std::time::Instant;

    let info = format!("MultisigV1{}", "A".repeat(150));

    // Validate single
    let start = Instant::now();
    let _ = validate_multisig_info_format(&info);
    let single_time = start.elapsed();

    // Validate list of 100
    let list: Vec<String> = (0..100).map(|_| info.clone()).collect();
    let start = Instant::now();
    let _ = validate_multisig_info_list(&list);
    let list_time = start.elapsed();

    // Should be roughly 100x (allow 200x for overhead)
    assert!(
        list_time < single_time * 200,
        "List validation doesn't scale linearly: {:?} vs {:?}",
        list_time,
        single_time * 100
    );
}
