//! Amount Validation Tests
//!
//! Tests for Monero amount validation:
//! - Dust threshold
//! - Overflow prevention
//! - Atomic unit conversion
//! - Amount bounds
//!
//! Reference: Monero amount handling

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// AMOUNT CONSTANTS
// ============================================================================

/// Atomic units per XMR (1 XMR = 10^12 piconero)
const ATOMIC_UNITS_PER_XMR: u64 = 1_000_000_000_000;

/// Minimum dust threshold (below this is considered dust)
/// Current network value: 0.0001 XMR
const DUST_THRESHOLD: u64 = 100_000_000;

/// Maximum possible XMR supply (~18.4 million XMR)
const MAX_XMR_SUPPLY: u64 = 18_400_000 * ATOMIC_UNITS_PER_XMR;

/// Minimum transaction amount (1 piconero)
const MIN_AMOUNT: u64 = 1;

/// Maximum safe amount for single transaction
const MAX_SINGLE_TX_AMOUNT: u64 = 10_000 * ATOMIC_UNITS_PER_XMR;

// ============================================================================
// AMOUNT VALIDATION TYPES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ValidatedAmount {
    pub atomic_units: u64,
    pub xmr: f64,
    pub is_dust: bool,
    pub is_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AmountError {
    Zero,
    Negative,
    Overflow,
    ExceedsMaxSupply,
    BelowDust,
    InvalidString,
    TooManyDecimals,
}

// ============================================================================
// AMOUNT CONVERSION FUNCTIONS
// ============================================================================

/// Convert XMR to atomic units (piconero)
pub fn xmr_to_atomic(xmr: f64) -> Result<u64, AmountError> {
    if xmr < 0.0 {
        return Err(AmountError::Negative);
    }
    if xmr == 0.0 {
        return Err(AmountError::Zero);
    }

    let atomic = xmr * ATOMIC_UNITS_PER_XMR as f64;

    if atomic > u64::MAX as f64 {
        return Err(AmountError::Overflow);
    }

    let atomic_u64 = atomic.round() as u64;

    if atomic_u64 > MAX_XMR_SUPPLY {
        return Err(AmountError::ExceedsMaxSupply);
    }

    Ok(atomic_u64)
}

/// Convert atomic units to XMR
pub fn atomic_to_xmr(atomic: u64) -> f64 {
    atomic as f64 / ATOMIC_UNITS_PER_XMR as f64
}

/// Parse amount string to atomic units
/// Supports formats: "1.5", "1.500000000000", "1500000000000"
pub fn parse_amount(input: &str) -> Result<u64, AmountError> {
    let input = input.trim();

    if input.is_empty() {
        return Err(AmountError::InvalidString);
    }

    // Check if it's a decimal or integer
    if input.contains('.') {
        // Decimal format (XMR)
        let parts: Vec<&str> = input.split('.').collect();
        if parts.len() != 2 {
            return Err(AmountError::InvalidString);
        }

        let integer_part = parts[0];
        let decimal_part = parts[1];

        // Max 12 decimal places
        if decimal_part.len() > 12 {
            return Err(AmountError::TooManyDecimals);
        }

        // Parse as float
        let xmr: f64 = input.parse().map_err(|_| AmountError::InvalidString)?;
        xmr_to_atomic(xmr)
    } else {
        // Integer format (atomic units)
        let atomic: u64 = input.parse().map_err(|_| AmountError::InvalidString)?;

        if atomic == 0 {
            return Err(AmountError::Zero);
        }

        if atomic > MAX_XMR_SUPPLY {
            return Err(AmountError::ExceedsMaxSupply);
        }

        Ok(atomic)
    }
}

/// Validate an amount
pub fn validate_amount(atomic: u64) -> ValidatedAmount {
    let is_dust = atomic < DUST_THRESHOLD;
    let is_valid = atomic > 0 && atomic <= MAX_XMR_SUPPLY;

    ValidatedAmount {
        atomic_units: atomic,
        xmr: atomic_to_xmr(atomic),
        is_dust,
        is_valid,
    }
}

/// Check if amount is above dust threshold
pub fn is_above_dust(atomic: u64) -> bool {
    atomic >= DUST_THRESHOLD
}

/// Calculate sum with overflow protection
pub fn safe_sum(amounts: &[u64]) -> Option<u64> {
    let mut sum: u64 = 0;
    for &amount in amounts {
        sum = sum.checked_add(amount)?;
    }
    Some(sum)
}

/// Calculate difference with underflow protection
pub fn safe_subtract(a: u64, b: u64) -> Option<u64> {
    a.checked_sub(b)
}

// ============================================================================
// BASIC CONVERSION TESTS
// ============================================================================

#[test]
fn test_xmr_to_atomic_one_xmr() {
    let atomic = xmr_to_atomic(1.0).unwrap();
    assert_eq!(atomic, ATOMIC_UNITS_PER_XMR);
}

#[test]
fn test_xmr_to_atomic_fractional() {
    let atomic = xmr_to_atomic(0.5).unwrap();
    assert_eq!(atomic, 500_000_000_000);
}

#[test]
fn test_xmr_to_atomic_small() {
    let atomic = xmr_to_atomic(0.000000000001).unwrap();
    assert_eq!(atomic, 1); // 1 piconero
}

#[test]
fn test_atomic_to_xmr_roundtrip() {
    let original_xmr = 1.5;
    let atomic = xmr_to_atomic(original_xmr).unwrap();
    let back_to_xmr = atomic_to_xmr(atomic);

    assert!((back_to_xmr - original_xmr).abs() < 0.000000001);
}

#[test]
fn test_atomic_to_xmr_large() {
    let atomic = 18_400_000 * ATOMIC_UNITS_PER_XMR;
    let xmr = atomic_to_xmr(atomic);
    assert!((xmr - 18_400_000.0).abs() < 0.01);
}

// ============================================================================
// DUST THRESHOLD TESTS
// ============================================================================

#[test]
fn test_dust_below_threshold() {
    let amount = DUST_THRESHOLD - 1;
    let result = validate_amount(amount);

    assert!(result.is_dust);
    assert!(result.is_valid); // Still valid, just dusty
}

#[test]
fn test_dust_at_threshold() {
    let result = validate_amount(DUST_THRESHOLD);

    assert!(!result.is_dust);
    assert!(result.is_valid);
}

#[test]
fn test_dust_above_threshold() {
    let amount = DUST_THRESHOLD + 1;
    let result = validate_amount(amount);

    assert!(!result.is_dust);
    assert!(result.is_valid);
}

#[test]
fn test_is_above_dust_helper() {
    assert!(!is_above_dust(DUST_THRESHOLD - 1));
    assert!(is_above_dust(DUST_THRESHOLD));
    assert!(is_above_dust(DUST_THRESHOLD + 1));
}

#[test]
fn test_one_piconero_is_dust() {
    let result = validate_amount(1);
    assert!(result.is_dust);
}

// ============================================================================
// OVERFLOW TESTS
// ============================================================================

#[test]
fn test_overflow_xmr_conversion() {
    // u64::MAX / ATOMIC_UNITS_PER_XMR ≈ 18 billion XMR
    let result = xmr_to_atomic(f64::MAX);
    assert!(matches!(result, Err(AmountError::Overflow)));
}

#[test]
fn test_safe_sum_no_overflow() {
    let amounts = vec![1_000_000_000_000u64; 100]; // 100 XMR
    let sum = safe_sum(&amounts);

    assert!(sum.is_some());
    assert_eq!(sum.unwrap(), 100 * ATOMIC_UNITS_PER_XMR);
}

#[test]
fn test_safe_sum_overflow() {
    let amounts = vec![u64::MAX, 1];
    let sum = safe_sum(&amounts);

    assert!(sum.is_none());
}

#[test]
fn test_safe_subtract_no_underflow() {
    let result = safe_subtract(100, 50);
    assert_eq!(result, Some(50));
}

#[test]
fn test_safe_subtract_underflow() {
    let result = safe_subtract(50, 100);
    assert!(result.is_none());
}

#[test]
fn test_safe_subtract_exact() {
    let result = safe_subtract(100, 100);
    assert_eq!(result, Some(0));
}

// ============================================================================
// MAX SUPPLY TESTS
// ============================================================================

#[test]
fn test_at_max_supply() {
    let result = validate_amount(MAX_XMR_SUPPLY);
    assert!(result.is_valid);
}

#[test]
fn test_above_max_supply() {
    let result = validate_amount(MAX_XMR_SUPPLY + 1);
    assert!(!result.is_valid);
}

#[test]
fn test_xmr_to_atomic_exceeds_supply() {
    // 18.42 million XMR exceeds max supply (18.4 million) but doesn't overflow u64
    // MAX_XMR_SUPPLY = 18_400_000 XMR
    // u64::MAX ≈ 18_446_744 XMR in atomic units
    // So we use 18.42 million which is between these values
    let result = xmr_to_atomic(18_420_000.0);
    assert!(matches!(result, Err(AmountError::ExceedsMaxSupply)));
}

// ============================================================================
// PARSE AMOUNT TESTS
// ============================================================================

#[test]
fn test_parse_decimal_amount() {
    let result = parse_amount("1.5").unwrap();
    assert_eq!(result, 1_500_000_000_000);
}

#[test]
fn test_parse_integer_atomic() {
    let result = parse_amount("1000000000000").unwrap();
    assert_eq!(result, ATOMIC_UNITS_PER_XMR);
}

#[test]
fn test_parse_small_decimal() {
    let result = parse_amount("0.000001").unwrap();
    assert_eq!(result, 1_000_000); // 10^6 piconero = 0.000001 XMR
}

#[test]
fn test_parse_12_decimal_places() {
    let result = parse_amount("1.000000000001").unwrap();
    assert_eq!(result, 1_000_000_000_001); // 1 XMR + 1 piconero
}

#[test]
fn test_parse_too_many_decimals() {
    let result = parse_amount("1.0000000000001"); // 13 decimal places
    assert!(matches!(result, Err(AmountError::TooManyDecimals)));
}

#[test]
fn test_parse_zero() {
    let result = parse_amount("0");
    assert!(matches!(result, Err(AmountError::Zero)));
}

#[test]
fn test_parse_zero_decimal() {
    let result = parse_amount("0.0");
    assert!(matches!(result, Err(AmountError::Zero)));
}

#[test]
fn test_parse_empty() {
    let result = parse_amount("");
    assert!(matches!(result, Err(AmountError::InvalidString)));
}

#[test]
fn test_parse_invalid_string() {
    let result = parse_amount("abc");
    assert!(matches!(result, Err(AmountError::InvalidString)));
}

#[test]
fn test_parse_whitespace_trimmed() {
    let result = parse_amount("  1.5  ").unwrap();
    assert_eq!(result, 1_500_000_000_000);
}

// ============================================================================
// NEGATIVE AMOUNT TESTS
// ============================================================================

#[test]
fn test_negative_xmr_rejected() {
    let result = xmr_to_atomic(-1.0);
    assert!(matches!(result, Err(AmountError::Negative)));
}

#[test]
fn test_zero_xmr_rejected() {
    let result = xmr_to_atomic(0.0);
    assert!(matches!(result, Err(AmountError::Zero)));
}

// ============================================================================
// VALIDATED AMOUNT TESTS
// ============================================================================

#[test]
fn test_validated_amount_fields() {
    let result = validate_amount(1_500_000_000_000);

    assert_eq!(result.atomic_units, 1_500_000_000_000);
    assert!((result.xmr - 1.5).abs() < 0.0001);
    assert!(!result.is_dust);
    assert!(result.is_valid);
}

#[test]
fn test_validated_amount_zero() {
    let result = validate_amount(0);

    assert!(!result.is_valid);
    assert!(result.is_dust);
}

// ============================================================================
// PRECISION TESTS
// ============================================================================

#[test]
fn test_precision_not_lost() {
    // Test various precise amounts
    let test_amounts = [
        1u64,
        12,
        123,
        1234,
        12345,
        123456,
        1234567,
        12345678,
        123456789,
        1234567890,
        12345678901,
        123456789012,
    ];

    for &atomic in &test_amounts {
        let xmr = atomic_to_xmr(atomic);
        let back = xmr_to_atomic(xmr).unwrap();

        assert_eq!(
            atomic, back,
            "Precision lost for {} atomic units",
            atomic
        );
    }
}

#[test]
fn test_common_amounts_precision() {
    // Common amounts in marketplace
    let amounts_xmr = [
        0.001,   // Minimum practical
        0.01,    // 10 milliXMR
        0.1,     // 100 milliXMR
        1.0,     // 1 XMR
        10.0,    // 10 XMR
        100.0,   // 100 XMR
        1000.0,  // 1000 XMR
    ];

    for &xmr in &amounts_xmr {
        let atomic = xmr_to_atomic(xmr).unwrap();
        let back = atomic_to_xmr(atomic);

        assert!(
            (xmr - back).abs() < 0.000000000001,
            "Precision issue for {} XMR",
            xmr
        );
    }
}

// ============================================================================
// BOUNDARY TESTS
// ============================================================================

#[test]
fn test_boundary_dust_minus_one() {
    let amount = DUST_THRESHOLD - 1;
    assert!(validate_amount(amount).is_dust);
}

#[test]
fn test_boundary_exactly_dust() {
    let amount = DUST_THRESHOLD;
    assert!(!validate_amount(amount).is_dust);
}

#[test]
fn test_boundary_dust_plus_one() {
    let amount = DUST_THRESHOLD + 1;
    assert!(!validate_amount(amount).is_dust);
}

#[test]
fn test_boundary_max_supply_minus_one() {
    let amount = MAX_XMR_SUPPLY - 1;
    assert!(validate_amount(amount).is_valid);
}

#[test]
fn test_boundary_max_supply_plus_one() {
    let amount = MAX_XMR_SUPPLY + 1;
    assert!(!validate_amount(amount).is_valid);
}

// ============================================================================
// DETERMINISM TESTS
// ============================================================================

#[test]
fn test_conversion_deterministic() {
    let xmr = 1.234567890123;

    let atomic1 = xmr_to_atomic(xmr).unwrap();
    let atomic2 = xmr_to_atomic(xmr).unwrap();

    assert_eq!(atomic1, atomic2);
}

#[test]
fn test_validation_deterministic() {
    let amount = 1_500_000_000_000u64;

    let result1 = validate_amount(amount);
    let result2 = validate_amount(amount);

    assert_eq!(result1, result2);
}

#[test]
fn test_random_amounts_consistent() {
    let mut rng = DeterministicRng::with_name("amount_consistency");

    for _ in 0..100 {
        let amount = rng.gen_range(MAX_XMR_SUPPLY);

        let r1 = validate_amount(amount);
        let r2 = validate_amount(amount);

        assert_eq!(r1.is_valid, r2.is_valid);
        assert_eq!(r1.is_dust, r2.is_dust);
    }
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_one_piconero() {
    let result = validate_amount(1);

    assert!(result.is_valid);
    assert!(result.is_dust);
    assert_eq!(result.xmr, 0.000000000001);
}

#[test]
fn test_u64_max_invalid() {
    let result = validate_amount(u64::MAX);
    assert!(!result.is_valid); // Exceeds max supply
}

#[test]
fn test_safe_sum_empty() {
    let sum = safe_sum(&[]);
    assert_eq!(sum, Some(0));
}

#[test]
fn test_safe_sum_single() {
    let sum = safe_sum(&[100]);
    assert_eq!(sum, Some(100));
}
