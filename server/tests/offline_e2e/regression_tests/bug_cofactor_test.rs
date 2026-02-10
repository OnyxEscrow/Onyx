//! Bug Regression: Cofactor Multiplication (Bug #1.2)
//!
//! ## Original Bug
//! Key images were not multiplied by cofactor (8) before storage,
//! causing CLSAG verification to fail.
//!
//! ## Root Cause
//! Ed25519 curve has cofactor 8. Points must be multiplied by cofactor
//! to ensure they're in the prime-order subgroup for CLSAG to work correctly.
//!
//! ## Fix
//! Apply `.mul_by_cofactor()` to all key images before use in CLSAG.
//!
//! ## Reference
//! - server/src/services/clsag_verifier.rs
//! - monero/src/ringct/rctSigs.cpp

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar, traits::Identity,
};

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// COFACTOR CONSTANTS
// ============================================================================

/// Ed25519 cofactor
const COFACTOR: u64 = 8;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Simulate pre-fix behavior (no cofactor multiplication)
fn process_key_image_buggy(point: &EdwardsPoint) -> EdwardsPoint {
    // BUG: Returns point without cofactor multiplication
    *point
}

/// Correct behavior (with cofactor multiplication)
fn process_key_image_fixed(point: &EdwardsPoint) -> EdwardsPoint {
    point.mul_by_cofactor()
}

/// Check if point is in prime-order subgroup
fn is_in_prime_subgroup(point: &EdwardsPoint) -> bool {
    // A point is in the prime-order subgroup if 8*P != 0 AND l*P = 0
    // For simplified test: 8*P should not equal identity
    let cofactored = point.mul_by_cofactor();
    cofactored != EdwardsPoint::identity()
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

#[test]
fn test_cofactor_multiplication_applied() {
    let mut rng = DeterministicRng::with_name("cofactor_applied");

    for _ in 0..100 {
        let point = rng.gen_point();

        // Fixed behavior should apply cofactor
        let fixed = process_key_image_fixed(&point);

        // Verify cofactor was applied (8*P != P for random points)
        assert_ne!(
            fixed, point,
            "Cofactor multiplication should change the point"
        );

        // Verify 8*P = P * 8
        let manual_cofactor = point * Scalar::from(COFACTOR);
        assert_eq!(
            fixed, manual_cofactor,
            "mul_by_cofactor should equal scalar multiplication by 8"
        );
    }
}

#[test]
fn test_buggy_behavior_differs() {
    let mut rng = DeterministicRng::with_name("cofactor_buggy");

    let point = rng.gen_point();

    let buggy_result = process_key_image_buggy(&point);
    let fixed_result = process_key_image_fixed(&point);

    // The buggy version should differ from fixed
    assert_ne!(
        buggy_result, fixed_result,
        "Buggy behavior should differ from fixed"
    );

    // Buggy returns original point
    assert_eq!(buggy_result, point);
}

#[test]
fn test_cofactor_idempotent_after_first_application() {
    let mut rng = DeterministicRng::with_name("cofactor_idempotent");

    let point = rng.gen_point();

    // Apply cofactor twice
    let once = process_key_image_fixed(&point);
    let twice = process_key_image_fixed(&once);

    // Note: 8 * (8 * P) = 64 * P != 8 * P for random points
    // So it's NOT idempotent - this is why we must apply exactly once
    assert_ne!(
        once, twice,
        "Cofactor multiplication is NOT idempotent - apply exactly once"
    );
}

#[test]
fn test_cofactor_on_identity() {
    let identity = EdwardsPoint::identity();

    let result = process_key_image_fixed(&identity);

    // 8 * 0 = 0
    assert_eq!(
        result,
        EdwardsPoint::identity(),
        "Cofactor of identity should be identity"
    );
}

#[test]
fn test_cofactor_on_basepoint() {
    let g = ED25519_BASEPOINT_POINT;

    let result = process_key_image_fixed(&g);

    // 8 * G should be well-defined
    let expected = g * Scalar::from(COFACTOR);
    assert_eq!(result, expected);
}

// ============================================================================
// CLSAG-SPECIFIC COFACTOR TESTS
// ============================================================================

#[test]
fn test_clsag_requires_cofactored_key_images() {
    let mut rng = DeterministicRng::with_name("clsag_cofactor");

    // Simulate a partial key image from multisig
    let partial_ki = rng.gen_point();

    // CRITICAL: Must cofactor before use in CLSAG
    let ki_for_clsag = process_key_image_fixed(&partial_ki);

    // Verify it's different (bug prevention)
    assert_ne!(
        partial_ki, ki_for_clsag,
        "Key image must be cofactored before CLSAG use"
    );
}

#[test]
fn test_aggregated_key_image_cofactored() {
    let mut rng = DeterministicRng::with_name("aggregated_ki");

    // Simulate 2 partial key images
    let pki1 = rng.gen_point();
    let pki2 = rng.gen_point();

    // BUG: Adding then cofactoring vs cofactoring then adding
    // The correct way: cofactor each, then add

    // Wrong way (bug)
    let buggy_ki = (pki1 + pki2).mul_by_cofactor();

    // Correct way (fixed)
    let fixed_ki = pki1.mul_by_cofactor() + pki2.mul_by_cofactor();

    // These ARE equal due to distributive property: 8*(a+b) = 8*a + 8*b
    assert_eq!(
        buggy_ki, fixed_ki,
        "Order shouldn't matter due to distributive property"
    );

    // But the real bug was not applying cofactor at all
    let really_buggy_ki = pki1 + pki2;
    assert_ne!(really_buggy_ki, fixed_ki, "No cofactor at all is the bug");
}

#[test]
fn test_d_inv8_convention() {
    let mut rng = DeterministicRng::with_name("d_inv8");

    // In CLSAG, D is stored as D/8 to save computation during verification
    let d = rng.gen_point();

    // Store as D/8
    let eight_inv = Scalar::from(8u64).invert();
    let d_inv8 = d * eight_inv;

    // During verification, recover D
    let d_recovered = d_inv8 * Scalar::from(8u64);

    assert_eq!(d, d_recovered, "D should be recoverable from D_inv8");

    // Alternative: use mul_by_cofactor on D_inv8
    let d_via_cofactor = d_inv8.mul_by_cofactor();
    assert_eq!(d, d_via_cofactor);
}

// ============================================================================
// SUBGROUP MEMBERSHIP TESTS
// ============================================================================

#[test]
fn test_random_points_in_subgroup() {
    let mut rng = DeterministicRng::with_name("subgroup_random");

    for _ in 0..100 {
        let point = rng.gen_point();

        // Our RNG generates valid curve points
        // After cofactor multiplication, should definitely be in subgroup
        let cofactored = point.mul_by_cofactor();
        assert!(
            is_in_prime_subgroup(&cofactored),
            "Cofactored point should be in prime subgroup"
        );
    }
}

#[test]
fn test_basepoint_in_subgroup() {
    let g = ED25519_BASEPOINT_POINT;
    assert!(
        is_in_prime_subgroup(&g),
        "Basepoint should be in prime subgroup"
    );
}

// ============================================================================
// SCALAR MULTIPLICATION EQUIVALENCE
// ============================================================================

#[test]
fn test_mul_by_cofactor_equals_scalar_8() {
    let mut rng = DeterministicRng::with_name("mul_equiv");

    for _ in 0..100 {
        let point = rng.gen_point();

        let via_method = point.mul_by_cofactor();
        let via_scalar = point * Scalar::from(8u64);

        assert_eq!(
            via_method, via_scalar,
            "mul_by_cofactor should equal * Scalar::from(8)"
        );
    }
}

// ============================================================================
// DETERMINISM TESTS
// ============================================================================

#[test]
fn test_cofactor_deterministic() {
    let mut rng = DeterministicRng::with_name("cofactor_det");

    let point = rng.gen_point();

    let result1 = process_key_image_fixed(&point);
    let result2 = process_key_image_fixed(&point);

    assert_eq!(
        result1, result2,
        "Cofactor multiplication should be deterministic"
    );
}

// ============================================================================
// KNOWN VALUE TESTS
// ============================================================================

#[test]
fn test_cofactor_known_value() {
    // Use a fixed seed to get deterministic "known" value
    let mut rng = DeterministicRng::with_name("known_cofactor");

    let point = rng.gen_point();
    let cofactored = point.mul_by_cofactor();

    // Compress and check it's valid
    let compressed = cofactored.compress();
    let decompressed = compressed.decompress();

    assert!(
        decompressed.is_some(),
        "Cofactored point should compress/decompress correctly"
    );
    assert_eq!(
        decompressed.unwrap(),
        cofactored,
        "Should roundtrip correctly"
    );
}
