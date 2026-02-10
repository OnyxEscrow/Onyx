//! Fee Calculation Tests
//!
//! Tests for Monero transaction fee calculations:
//! - Basis points calculation (amount * bps / 10000)
//! - Overflow protection on large amounts
//! - Underflow prevention with saturating_sub
//! - Property: fee < amount always
//!
//! Reference: Standard marketplace fee calculation

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// CONSTANTS
// ============================================================================

/// 1 XMR in atomic units (piconero)
const XMR_TO_ATOMIC: u64 = 1_000_000_000_000;

/// Minimum transaction fee (0.0001 XMR)
const MIN_NETWORK_FEE: u64 = 100_000_000;

/// Maximum amount that can be safely processed (10000 XMR)
const MAX_SAFE_AMOUNT: u64 = 10_000 * XMR_TO_ATOMIC;

/// Standard marketplace fee in basis points (3% = 300 bps)
const DEFAULT_FEE_BPS: u64 = 300;

/// Maximum fee cap (50% = 5000 bps)
const MAX_FEE_BPS: u64 = 5000;

// ============================================================================
// FEE CALCULATION FUNCTIONS
// ============================================================================

/// Calculate fee using basis points: fee = amount * bps / 10000
/// Returns None if overflow would occur
fn calculate_fee_bps(amount: u64, bps: u64) -> Option<u64> {
    // Use u128 to prevent overflow during multiplication
    let amount_128 = amount as u128;
    let bps_128 = bps as u128;

    let fee_128 = amount_128.checked_mul(bps_128)?;
    let fee_128 = fee_128.checked_div(10000)?;

    // Convert back to u64, checking for overflow
    if fee_128 > u64::MAX as u128 {
        return None;
    }

    Some(fee_128 as u64)
}

/// Calculate fee with minimum guarantee
fn calculate_fee_with_min(amount: u64, bps: u64, min_fee: u64) -> Option<u64> {
    let calculated_fee = calculate_fee_bps(amount, bps)?;
    Some(calculated_fee.max(min_fee))
}

/// Calculate amount after fee deduction using saturating subtraction
fn amount_after_fee(amount: u64, fee: u64) -> u64 {
    amount.saturating_sub(fee)
}

/// Calculate fee percentage as a decimal (for display)
fn fee_percentage(amount: u64, fee: u64) -> f64 {
    if amount == 0 {
        return 0.0;
    }
    (fee as f64 / amount as f64) * 100.0
}

// ============================================================================
// BASIC FEE CALCULATION TESTS
// ============================================================================

#[test]
fn test_fee_3_percent() {
    // 3% of 1 XMR = 0.03 XMR
    let amount = XMR_TO_ATOMIC; // 1 XMR
    let fee = calculate_fee_bps(amount, 300).unwrap();

    let expected = 30_000_000_000u64; // 0.03 XMR
    assert_eq!(fee, expected, "3% of 1 XMR should be 0.03 XMR");
}

#[test]
fn test_fee_1_percent() {
    // 1% of 10 XMR = 0.1 XMR
    let amount = 10 * XMR_TO_ATOMIC;
    let fee = calculate_fee_bps(amount, 100).unwrap();

    let expected = 100_000_000_000u64; // 0.1 XMR
    assert_eq!(fee, expected, "1% of 10 XMR should be 0.1 XMR");
}

#[test]
fn test_fee_0_5_percent() {
    // 0.5% = 50 bps of 2 XMR = 0.01 XMR
    let amount = 2 * XMR_TO_ATOMIC;
    let fee = calculate_fee_bps(amount, 50).unwrap();

    let expected = 10_000_000_000u64; // 0.01 XMR
    assert_eq!(fee, expected, "0.5% of 2 XMR should be 0.01 XMR");
}

#[test]
fn test_fee_zero_amount() {
    let fee = calculate_fee_bps(0, 300).unwrap();
    assert_eq!(fee, 0, "Fee of 0 amount should be 0");
}

#[test]
fn test_fee_zero_bps() {
    let fee = calculate_fee_bps(XMR_TO_ATOMIC, 0).unwrap();
    assert_eq!(fee, 0, "0% fee should be 0");
}

// ============================================================================
// OVERFLOW PROTECTION TESTS
// ============================================================================

#[test]
fn test_fee_large_amount_no_overflow() {
    // 10000 XMR at 3%
    let amount = MAX_SAFE_AMOUNT;
    let fee = calculate_fee_bps(amount, 300);

    assert!(fee.is_some(), "10000 XMR should not overflow");

    let fee = fee.unwrap();
    let expected = 300 * XMR_TO_ATOMIC; // 300 XMR
    assert_eq!(fee, expected, "3% of 10000 XMR should be 300 XMR");
}

#[test]
fn test_fee_u64_max_no_panic() {
    // u64::MAX * 10000 would overflow, but we use u128 internally
    let fee = calculate_fee_bps(u64::MAX, 10000);

    // This should succeed because we use u128 for intermediate calculation
    // u64::MAX * 10000 / 10000 = u64::MAX
    assert!(fee.is_some(), "u64::MAX with 100% fee should work");
    assert_eq!(fee.unwrap(), u64::MAX, "100% of u64::MAX should be u64::MAX");
}

#[test]
fn test_fee_extreme_bps_no_overflow() {
    // 50% of u64::MAX (within reasonable limits)
    let amount = u64::MAX / 2;
    let fee = calculate_fee_bps(amount, 5000);

    assert!(fee.is_some(), "50% of large amount should not overflow");
}

#[test]
fn test_fee_multiplication_overflow_prevented() {
    // Test that u128 intermediate prevents overflow
    // This would overflow in u64: MAX * 9999
    let amount = u64::MAX;
    let fee = calculate_fee_bps(amount, 9999);

    // Should succeed because we use u128
    assert!(fee.is_some(), "Should not overflow with u128 intermediate");
}

// ============================================================================
// UNDERFLOW PREVENTION TESTS
// ============================================================================

#[test]
fn test_amount_after_fee_normal() {
    let amount = XMR_TO_ATOMIC;
    let fee = 30_000_000_000u64; // 0.03 XMR

    let remaining = amount_after_fee(amount, fee);
    let expected = 970_000_000_000u64; // 0.97 XMR

    assert_eq!(remaining, expected, "Amount after fee should be correct");
}

#[test]
fn test_amount_after_fee_saturating() {
    // Fee larger than amount (should saturate to 0)
    let amount = XMR_TO_ATOMIC;
    let fee = 2 * XMR_TO_ATOMIC;

    let remaining = amount_after_fee(amount, fee);
    assert_eq!(remaining, 0, "Saturating sub should prevent underflow");
}

#[test]
fn test_amount_after_fee_equal() {
    // Fee equals amount
    let amount = XMR_TO_ATOMIC;
    let remaining = amount_after_fee(amount, amount);

    assert_eq!(remaining, 0, "100% fee should leave 0");
}

#[test]
fn test_amount_after_fee_zero_fee() {
    let amount = XMR_TO_ATOMIC;
    let remaining = amount_after_fee(amount, 0);

    assert_eq!(remaining, amount, "0 fee should leave full amount");
}

// ============================================================================
// FEE < AMOUNT PROPERTY TESTS
// ============================================================================

#[test]
fn test_fee_always_less_than_amount_standard() {
    let mut rng = DeterministicRng::with_name("fee_less_than");

    // Test 100 random amounts with standard fee
    for _ in 0..100 {
        let amount = rng.gen_range(1_000_000_000_000_000); // Up to 1000 XMR
        if amount == 0 {
            continue;
        }

        let fee = calculate_fee_bps(amount, DEFAULT_FEE_BPS).unwrap();
        assert!(
            fee < amount,
            "Fee {} should be less than amount {} at 3%",
            fee,
            amount
        );
    }
}

#[test]
fn test_fee_always_less_than_amount_max_bps() {
    let mut rng = DeterministicRng::with_name("fee_max_bps");

    // Test with max allowed fee (50%)
    for _ in 0..100 {
        let amount = rng.gen_range(1_000_000_000_000_000);
        if amount == 0 {
            continue;
        }

        let fee = calculate_fee_bps(amount, MAX_FEE_BPS).unwrap();
        assert!(
            fee <= amount / 2,
            "50% fee {} should be <= half of amount {}",
            fee,
            amount
        );
    }
}

#[test]
fn test_fee_percentage_bounds() {
    let amount = XMR_TO_ATOMIC;

    // 3% fee
    let fee = calculate_fee_bps(amount, 300).unwrap();
    let pct = fee_percentage(amount, fee);

    assert!(
        (pct - 3.0).abs() < 0.001,
        "Fee percentage should be ~3%, got {}",
        pct
    );
}

// ============================================================================
// MINIMUM FEE TESTS
// ============================================================================

#[test]
fn test_minimum_fee_applied() {
    // Very small amount where 3% < min fee
    let amount = 1_000_000_000u64; // 0.001 XMR
    let min_fee = MIN_NETWORK_FEE;  // 0.0001 XMR

    // 3% of 0.001 XMR = 0.00003 XMR < min
    let fee = calculate_fee_with_min(amount, 300, min_fee).unwrap();

    assert_eq!(
        fee, min_fee,
        "Fee should be at least minimum ({})",
        min_fee
    );
}

#[test]
fn test_calculated_fee_exceeds_minimum() {
    // Large amount where 3% > min fee
    let amount = 10 * XMR_TO_ATOMIC;
    let min_fee = MIN_NETWORK_FEE;

    // 3% of 10 XMR = 0.3 XMR > min
    let fee = calculate_fee_with_min(amount, 300, min_fee).unwrap();

    let expected = 300_000_000_000u64; // 0.3 XMR
    assert_eq!(fee, expected, "Calculated fee should be used when > min");
}

#[test]
fn test_minimum_fee_edge_case() {
    // Amount where 3% exactly equals min
    // 3% * X = min_fee => X = min_fee * 10000 / 300
    let amount = MIN_NETWORK_FEE * 10000 / 300;
    let min_fee = MIN_NETWORK_FEE;

    let fee = calculate_fee_with_min(amount, 300, min_fee).unwrap();

    // Should be approximately min_fee (rounding may differ slightly)
    assert!(
        fee >= min_fee,
        "Fee {} should be >= min {}",
        fee,
        min_fee
    );
}

// ============================================================================
// PRECISION TESTS
// ============================================================================

#[test]
fn test_fee_precision_small_bps() {
    // 0.01% = 1 bps
    let amount = 100 * XMR_TO_ATOMIC; // 100 XMR
    let fee = calculate_fee_bps(amount, 1).unwrap();

    let expected = 10_000_000_000u64; // 0.01 XMR
    assert_eq!(fee, expected, "0.01% of 100 XMR should be 0.01 XMR");
}

#[test]
fn test_fee_rounding_down() {
    // Fee calculation truncates (rounds down)
    // 3% of 1 piconero = 0.03 piconero -> truncates to 0
    let fee = calculate_fee_bps(1, 300).unwrap();
    assert_eq!(fee, 0, "Sub-piconero fees should truncate to 0");
}

#[test]
fn test_fee_no_rounding_error_accumulation() {
    // Multiple small transactions vs one large
    let small_amount = XMR_TO_ATOMIC / 10; // 0.1 XMR
    let num_txs = 10;

    let mut total_small_fees = 0u64;
    for _ in 0..num_txs {
        total_small_fees += calculate_fee_bps(small_amount, 300).unwrap();
    }

    let large_amount = XMR_TO_ATOMIC; // 1 XMR
    let large_fee = calculate_fee_bps(large_amount, 300).unwrap();

    // May differ slightly due to truncation
    assert!(
        (total_small_fees as i64 - large_fee as i64).abs() < 10,
        "Rounding error should be minimal: {} vs {}",
        total_small_fees,
        large_fee
    );
}

// ============================================================================
// MARKETPLACE-SPECIFIC TESTS
// ============================================================================

/// Simulate complete escrow fee calculation
fn calculate_escrow_fees(order_amount: u64, marketplace_bps: u64) -> EscrowFees {
    let marketplace_fee = calculate_fee_bps(order_amount, marketplace_bps)
        .unwrap_or(0)
        .max(MIN_NETWORK_FEE);

    let network_fee = MIN_NETWORK_FEE;

    let total_fees = marketplace_fee.saturating_add(network_fee);
    let vendor_receives = order_amount.saturating_sub(total_fees);

    EscrowFees {
        order_amount,
        marketplace_fee,
        network_fee,
        total_fees,
        vendor_receives,
    }
}

#[derive(Debug, PartialEq)]
struct EscrowFees {
    order_amount: u64,
    marketplace_fee: u64,
    network_fee: u64,
    total_fees: u64,
    vendor_receives: u64,
}

#[test]
fn test_escrow_fees_1_xmr() {
    let fees = calculate_escrow_fees(XMR_TO_ATOMIC, 300);

    // 3% of 1 XMR = 0.03 XMR
    assert_eq!(fees.marketplace_fee, 30_000_000_000);

    // Network fee = 0.0001 XMR
    assert_eq!(fees.network_fee, MIN_NETWORK_FEE);

    // Total = 0.0301 XMR
    assert_eq!(fees.total_fees, 30_000_000_000 + MIN_NETWORK_FEE);

    // Vendor gets 0.9699 XMR
    let expected_vendor = XMR_TO_ATOMIC - fees.total_fees;
    assert_eq!(fees.vendor_receives, expected_vendor);
}

#[test]
fn test_escrow_fees_100_xmr() {
    let fees = calculate_escrow_fees(100 * XMR_TO_ATOMIC, 300);

    // 3% of 100 XMR = 3 XMR
    assert_eq!(fees.marketplace_fee, 3 * XMR_TO_ATOMIC);

    // Vendor gets 96.9999 XMR
    let expected = 100 * XMR_TO_ATOMIC - 3 * XMR_TO_ATOMIC - MIN_NETWORK_FEE;
    assert_eq!(fees.vendor_receives, expected);
}

#[test]
fn test_escrow_fees_dust_amount() {
    // Very small order (dust)
    let dust = 1000u64; // 0.000000001 XMR

    let fees = calculate_escrow_fees(dust, 300);

    // Marketplace fee should be at least min
    assert_eq!(fees.marketplace_fee, MIN_NETWORK_FEE);

    // Vendor receives 0 (fees > amount)
    assert_eq!(fees.vendor_receives, 0);
}

#[test]
fn test_escrow_fee_consistency() {
    let mut rng = DeterministicRng::with_name("escrow_consistency");

    for _ in 0..100 {
        let amount = rng.gen_range(1000 * XMR_TO_ATOMIC).max(1);
        let fees = calculate_escrow_fees(amount, 300);

        // Invariant: amount = vendor_receives + total_fees OR
        //           vendor_receives = 0 if fees > amount
        if fees.total_fees <= amount {
            assert_eq!(
                fees.vendor_receives + fees.total_fees,
                amount,
                "Fee accounting must balance for amount {}",
                amount
            );
        } else {
            assert_eq!(
                fees.vendor_receives, 0,
                "Vendor should receive 0 when fees exceed amount"
            );
        }
    }
}

// ============================================================================
// TIERED FEE TESTS
// ============================================================================

/// Calculate tiered fees (lower % for larger amounts)
fn calculate_tiered_fee(amount: u64) -> u64 {
    let bps = if amount >= 100 * XMR_TO_ATOMIC {
        150 // 1.5% for 100+ XMR
    } else if amount >= 10 * XMR_TO_ATOMIC {
        200 // 2% for 10-100 XMR
    } else {
        300 // 3% for < 10 XMR
    };

    calculate_fee_bps(amount, bps).unwrap_or(0)
}

#[test]
fn test_tiered_fee_small() {
    let fee = calculate_tiered_fee(XMR_TO_ATOMIC);
    let expected = calculate_fee_bps(XMR_TO_ATOMIC, 300).unwrap();

    assert_eq!(fee, expected, "Small amount should use 3% tier");
}

#[test]
fn test_tiered_fee_medium() {
    let fee = calculate_tiered_fee(50 * XMR_TO_ATOMIC);
    let expected = calculate_fee_bps(50 * XMR_TO_ATOMIC, 200).unwrap();

    assert_eq!(fee, expected, "Medium amount should use 2% tier");
}

#[test]
fn test_tiered_fee_large() {
    let fee = calculate_tiered_fee(200 * XMR_TO_ATOMIC);
    let expected = calculate_fee_bps(200 * XMR_TO_ATOMIC, 150).unwrap();

    assert_eq!(fee, expected, "Large amount should use 1.5% tier");
}

#[test]
fn test_tiered_fee_boundary() {
    // Exactly at 10 XMR boundary
    let fee_below = calculate_tiered_fee(10 * XMR_TO_ATOMIC - 1);
    let fee_at = calculate_tiered_fee(10 * XMR_TO_ATOMIC);

    // Below boundary: 3%
    let expected_below = calculate_fee_bps(10 * XMR_TO_ATOMIC - 1, 300).unwrap();
    assert_eq!(fee_below, expected_below);

    // At boundary: 2%
    let expected_at = calculate_fee_bps(10 * XMR_TO_ATOMIC, 200).unwrap();
    assert_eq!(fee_at, expected_at);
}

// ============================================================================
// SPLIT PAYMENT FEE TESTS
// ============================================================================

/// Calculate fees for split payment (buyer pays fee + amount)
fn calculate_buyer_total(order_amount: u64, fee_bps: u64) -> Option<u64> {
    let fee = calculate_fee_bps(order_amount, fee_bps)?;
    order_amount.checked_add(fee)
}

#[test]
fn test_split_payment_buyer_total() {
    // Buyer pays: order_amount + fee
    let order = XMR_TO_ATOMIC; // 1 XMR
    let buyer_total = calculate_buyer_total(order, 300).unwrap();

    // 1 XMR + 0.03 XMR = 1.03 XMR
    let expected = XMR_TO_ATOMIC + 30_000_000_000;
    assert_eq!(buyer_total, expected);
}

#[test]
fn test_split_payment_large_amount() {
    // Verify no overflow on large amounts
    let order = MAX_SAFE_AMOUNT;
    let buyer_total = calculate_buyer_total(order, 300);

    assert!(buyer_total.is_some(), "Large split payment should not overflow");
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_fee_one_piconero() {
    // Smallest possible amount
    let fee = calculate_fee_bps(1, 10000).unwrap(); // 100%
    assert_eq!(fee, 1, "100% of 1 piconero should be 1");
}

#[test]
fn test_fee_basis_point_precision() {
    // Test each basis point from 1-100
    let amount = 10000 * XMR_TO_ATOMIC; // Large enough for precision

    for bps in 1..=100 {
        let fee = calculate_fee_bps(amount, bps).unwrap();
        let expected = amount * bps / 10000;
        assert_eq!(
            fee, expected,
            "Fee at {} bps should be precise",
            bps
        );
    }
}

#[test]
fn test_deterministic_fee_calculation() {
    // Same inputs should always produce same outputs
    let amount = 12_345_678_901_234u64;
    let bps = 299;

    let fee1 = calculate_fee_bps(amount, bps);
    let fee2 = calculate_fee_bps(amount, bps);

    assert_eq!(fee1, fee2, "Fee calculation must be deterministic");
}
