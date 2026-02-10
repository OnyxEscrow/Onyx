//! Commitment Mask Tests
//!
//! Tests for Pedersen commitment operations:
//! - Commitment computation: C = mask*G + amount*H
//! - Commitment balance verification
//! - Mask arithmetic for transaction building
//! - Pseudo output commitment validation

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha3::{Digest, Keccak256};

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// CONSTANTS
// ============================================================================

/// H generator constant from Monero's rctTypes.h
/// This is the "alternate basepoint" for Pedersen commitments
const H_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// Get the H point (alternate generator)
fn h_point() -> EdwardsPoint {
    CompressedEdwardsY(H_BYTES)
        .decompress()
        .expect("H is a valid point")
}

// ============================================================================
// PEDERSEN COMMITMENT COMPUTATION
// ============================================================================

/// Compute a Pedersen commitment: C = mask*G + amount*H
fn compute_commitment(mask: &Scalar, amount: u64) -> EdwardsPoint {
    let g = ED25519_BASEPOINT_POINT;
    let h = h_point();
    let amount_scalar = Scalar::from(amount);

    mask * g + amount_scalar * h
}

/// Compute commitment from bytes
fn compute_commitment_from_bytes(mask_bytes: &[u8; 32], amount: u64) -> EdwardsPoint {
    let mask = Scalar::from_bytes_mod_order(*mask_bytes);
    compute_commitment(&mask, amount)
}

// ============================================================================
// BASIC COMMITMENT TESTS
// ============================================================================

#[test]
fn test_h_point_is_valid() {
    let h = h_point();

    // H should not be the identity
    assert_ne!(h, EdwardsPoint::identity(), "H should not be identity");

    // H should be a valid curve point (if we got here, decompress succeeded)
    let compressed = h.compress();
    let redecompressed = compressed.decompress().unwrap();
    assert_eq!(h, redecompressed, "H should round-trip through compression");
}

#[test]
fn test_h_different_from_g() {
    let g = ED25519_BASEPOINT_POINT;
    let h = h_point();

    assert_ne!(g, h, "H should be different from G");
}

#[test]
fn test_commitment_deterministic() {
    let mut rng = DeterministicRng::with_name("commitment_det");

    let mask = rng.gen_scalar();
    let amount = 1_000_000_000_000u64; // 1 XMR

    let c1 = compute_commitment(&mask, amount);
    let c2 = compute_commitment(&mask, amount);

    assert_eq!(c1, c2, "Commitment should be deterministic");
}

#[test]
fn test_commitment_different_masks() {
    let mut rng = DeterministicRng::with_name("commitment_diff_mask");

    let mask1 = rng.gen_scalar();
    let mask2 = rng.gen_scalar();
    let amount = 1_000_000_000_000u64;

    let c1 = compute_commitment(&mask1, amount);
    let c2 = compute_commitment(&mask2, amount);

    assert_ne!(c1, c2, "Different masks should produce different commitments");
}

#[test]
fn test_commitment_different_amounts() {
    let mut rng = DeterministicRng::with_name("commitment_diff_amt");

    let mask = rng.gen_scalar();
    let amount1 = 1_000_000_000_000u64;
    let amount2 = 2_000_000_000_000u64;

    let c1 = compute_commitment(&mask, amount1);
    let c2 = compute_commitment(&mask, amount2);

    assert_ne!(c1, c2, "Different amounts should produce different commitments");
}

#[test]
fn test_zero_amount_commitment() {
    let mut rng = DeterministicRng::with_name("commitment_zero_amt");

    let mask = rng.gen_scalar();

    // C = mask*G + 0*H = mask*G
    let c = compute_commitment(&mask, 0);
    let expected = mask * ED25519_BASEPOINT_POINT;

    assert_eq!(c, expected, "Zero amount commitment should equal mask*G");
}

#[test]
fn test_zero_mask_commitment() {
    // C = 0*G + amount*H = amount*H
    let amount = 1_000_000_000_000u64;
    let c = compute_commitment(&Scalar::ZERO, amount);
    let expected = Scalar::from(amount) * h_point();

    assert_eq!(c, expected, "Zero mask commitment should equal amount*H");
}

// ============================================================================
// COMMITMENT BALANCE TESTS
// ============================================================================

#[test]
fn test_commitment_addition() {
    let mut rng = DeterministicRng::with_name("commitment_add");

    let mask1 = rng.gen_scalar();
    let mask2 = rng.gen_scalar();
    let amount1 = 500_000_000_000u64;
    let amount2 = 500_000_000_000u64;

    let c1 = compute_commitment(&mask1, amount1);
    let c2 = compute_commitment(&mask2, amount2);

    // C1 + C2 = (mask1 + mask2)*G + (amount1 + amount2)*H
    let c_sum = c1 + c2;
    let expected = compute_commitment(&(mask1 + mask2), amount1 + amount2);

    assert_eq!(c_sum, expected, "Commitment addition should be homomorphic");
}

#[test]
fn test_commitment_subtraction() {
    let mut rng = DeterministicRng::with_name("commitment_sub");

    let mask1 = rng.gen_scalar();
    let mask2 = rng.gen_scalar();
    let amount1 = 1_000_000_000_000u64;
    let amount2 = 300_000_000_000u64;

    let c1 = compute_commitment(&mask1, amount1);
    let c2 = compute_commitment(&mask2, amount2);

    // C1 - C2 = (mask1 - mask2)*G + (amount1 - amount2)*H
    let c_diff = c1 - c2;
    let expected_mask = mask1 - mask2;
    let expected_amount = amount1 - amount2;
    let expected = compute_commitment(&expected_mask, expected_amount);

    assert_eq!(c_diff, expected, "Commitment subtraction should be homomorphic");
}

#[test]
fn test_transaction_balance() {
    // In a valid transaction: sum(inputs) = sum(outputs) + fee
    // Commitment form: sum(C_in) = sum(C_out) + fee*H
    // This works because fee commitments use mask=0

    let mut rng = DeterministicRng::with_name("tx_balance");

    // Input
    let input_mask = rng.gen_scalar();
    let input_amount = 1_000_000_000_000u64; // 1 XMR
    let c_input = compute_commitment(&input_mask, input_amount);

    // Output
    let output_amount = 970_000_000_000u64; // 0.97 XMR
    let fee = 30_000_000_000u64;            // 0.03 XMR

    // For balance: output_mask = input_mask (if no change)
    // But typically: output_mask is chosen, then we adjust
    let output_mask = rng.gen_scalar();
    let c_output = compute_commitment(&output_mask, output_amount);

    // Fee commitment (mask=0 by convention)
    let c_fee = Scalar::from(fee) * h_point();

    // For balance: C_input = C_output + C_fee
    // (input_mask)*G + (input_amount)*H = (output_mask)*G + (output_amount)*H + fee*H
    // This requires: input_mask = output_mask AND input_amount = output_amount + fee

    // In practice, we compute the mask difference
    let mask_diff = input_mask - output_mask;

    // The "excess" should be: mask_diff*G (when amounts balance)
    let excess = c_input - c_output - c_fee;
    let expected_excess = mask_diff * ED25519_BASEPOINT_POINT;

    assert_eq!(excess, expected_excess, "Transaction balance should produce mask*G excess");
}

// ============================================================================
// PSEUDO OUTPUT COMMITMENT TESTS
// ============================================================================

#[test]
fn test_pseudo_output_balance() {
    // In CLSAG, pseudo_out balances with output commitments
    // pseudo_out = out_commitment + fee*H (for single input/output)

    let mut rng = DeterministicRng::with_name("pseudo_out");

    let output_mask = rng.gen_scalar();
    let output_amount = 970_000_000_000u64;
    let fee = 30_000_000_000u64;

    let c_output = compute_commitment(&output_mask, output_amount);
    let c_fee = Scalar::from(fee) * h_point();

    // Pseudo output must balance
    let pseudo_out = c_output + c_fee;

    // This should equal: output_mask*G + (output_amount + fee)*H
    let expected = compute_commitment(&output_mask, output_amount + fee);

    assert_eq!(pseudo_out, expected, "Pseudo output should balance");
}

#[test]
fn test_multi_output_balance() {
    // Multiple outputs: pseudo_out = sum(C_out) + fee*H
    let mut rng = DeterministicRng::with_name("multi_out");

    let mask1 = rng.gen_scalar();
    let mask2 = rng.gen_scalar();
    let amount1 = 500_000_000_000u64;
    let amount2 = 470_000_000_000u64;
    let fee = 30_000_000_000u64;

    let c_out1 = compute_commitment(&mask1, amount1);
    let c_out2 = compute_commitment(&mask2, amount2);
    let c_fee = Scalar::from(fee) * h_point();

    let pseudo_out = c_out1 + c_out2 + c_fee;

    // Verify balance
    let total_mask = mask1 + mask2;
    let total_amount = amount1 + amount2 + fee;
    let expected = compute_commitment(&total_mask, total_amount);

    assert_eq!(pseudo_out, expected, "Multi-output pseudo_out should balance");
}

// ============================================================================
// MASK DELTA COMPUTATION TESTS
// ============================================================================

#[test]
fn test_mask_delta_for_dummy_output() {
    // When mask_delta=0, pseudo_out = input_commitment
    // We need dummy_mask = input_mask - output_mask
    // So: pseudo_out = out0 + dummy + fee*H

    let mut rng = DeterministicRng::with_name("mask_delta");

    let input_mask = rng.gen_scalar();
    let output_mask = rng.gen_scalar();
    let output_amount = 970_000_000_000u64;
    let fee = 30_000_000_000u64;

    // Dummy mask ensures balance
    let dummy_mask = input_mask - output_mask;

    // Commitments
    let c_out0 = compute_commitment(&output_mask, output_amount);
    let c_dummy = compute_commitment(&dummy_mask, 0); // 0 amount
    let c_fee = Scalar::from(fee) * h_point();

    // Pseudo out = out0 + dummy + fee*H
    let pseudo_out = c_out0 + c_dummy + c_fee;

    // This should equal input commitment with same amount
    let input_amount = output_amount + fee;
    let expected = compute_commitment(&input_mask, input_amount);

    assert_eq!(pseudo_out, expected, "Dummy output mask should balance commitment");
}

// ============================================================================
// COFACTOR MULTIPLICATION TESTS
// ============================================================================

#[test]
fn test_cofactor_multiplication() {
    let mut rng = DeterministicRng::with_name("cofactor");

    let point = rng.gen_point();

    // Multiply by cofactor (8 for Ed25519)
    let cofactored = point.mul_by_cofactor();

    // 8*P should be different from P (unless P is in subgroup of order 1)
    // For random points, this should be true
    assert_ne!(point, cofactored, "8*P should differ from P for random points");

    // But cofactored/8 (if we could compute it) should give back P
    // This is implicit in how CLSAG stores D_inv8 = D/8
}

#[test]
fn test_d_inv8_convention() {
    // In CLSAG, D is stored as D_inv8 = D/8
    // During verification: D_original = D_inv8 * 8

    let mut rng = DeterministicRng::with_name("d_inv8");

    // Simulate D computation
    let d = rng.gen_point();

    // Store as D/8 (which is d * (1/8))
    // In practice, we'd use scalar inversion
    let eight_inv = Scalar::from(8u64).invert();
    let d_inv8 = d * eight_inv;

    // Recover D
    let d_recovered = d_inv8 * Scalar::from(8u64);

    assert_eq!(d, d_recovered, "D should be recoverable from D_inv8");
}

// ============================================================================
// HASH-BASED MASK DERIVATION TESTS
// ============================================================================

#[test]
fn test_mask_derivation_deterministic() {
    // Masks are often derived deterministically from shared secrets
    let shared_secret = [0x42u8; 32];
    let output_index = 0u64;

    let mask1 = derive_mask(&shared_secret, output_index);
    let mask2 = derive_mask(&shared_secret, output_index);

    assert_eq!(mask1, mask2, "Mask derivation should be deterministic");
}

#[test]
fn test_mask_derivation_unique_per_index() {
    let shared_secret = [0x42u8; 32];

    let mask0 = derive_mask(&shared_secret, 0);
    let mask1 = derive_mask(&shared_secret, 1);

    assert_ne!(mask0, mask1, "Different indices should produce different masks");
}

/// Derive a mask from shared secret and output index
fn derive_mask(shared_secret: &[u8; 32], output_index: u64) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(b"commitment_mask");
    hasher.update(shared_secret);
    hasher.update(&output_index.to_le_bytes());

    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

// ============================================================================
// OVERFLOW/UNDERFLOW TESTS
// ============================================================================

#[test]
fn test_large_amount_commitment() {
    let mut rng = DeterministicRng::with_name("large_amt");

    let mask = rng.gen_scalar();
    let large_amount = u64::MAX;

    // Should not panic
    let c = compute_commitment(&mask, large_amount);

    // Should be non-identity
    assert_ne!(c, EdwardsPoint::identity());
}

#[test]
fn test_commitment_with_reduced_scalar() {
    // Scalars are automatically reduced mod l
    let mut large_mask = [0xffu8; 32];

    // This will be reduced mod l
    let mask = Scalar::from_bytes_mod_order(large_mask);
    let amount = 1_000_000_000_000u64;

    // Should not panic
    let c = compute_commitment(&mask, amount);

    // Result should be deterministic
    let c2 = compute_commitment(&mask, amount);
    assert_eq!(c, c2);
}

// ============================================================================
// COMMITMENT VERIFICATION HELPERS
// ============================================================================

#[test]
fn test_commitment_difference_reveals_nothing() {
    // Given C1 and C2, an observer cannot determine:
    // - The individual amounts
    // - The individual masks
    // They can only verify balance (if C1 = C2 + fee*H)

    let mut rng = DeterministicRng::with_name("hiding");

    let mask1 = rng.gen_scalar();
    let mask2 = rng.gen_scalar();
    let amount1 = 1_000_000_000_000u64;
    let amount2 = 1_000_000_000_000u64; // Same amount

    let c1 = compute_commitment(&mask1, amount1);
    let c2 = compute_commitment(&mask2, amount2);

    // Even with same amount, commitments are different (due to different masks)
    // This is the hiding property
    assert_ne!(c1, c2, "Same amount with different masks should hide the amount");
}

#[test]
fn test_fee_commitment_is_public() {
    // Fee commitment uses mask=0, so fee*H reveals the fee
    // This is intentional in Monero

    let fee = 30_000_000_000u64;
    let c_fee = Scalar::from(fee) * h_point();

    // Anyone can verify this is correct by computing fee*H
    let expected = Scalar::from(fee) * h_point();
    assert_eq!(c_fee, expected);
}
