//! Lagrange Coefficient Tests
//!
//! Tests for Lagrange interpolation coefficients used in threshold signatures:
//! - Coefficient computation for all signer pairs
//! - Sum property (λ₁ + λ₂ = 1)
//! - Scalar field arithmetic
//! - Edge cases

use curve25519_dalek::scalar::Scalar;

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// LAGRANGE COEFFICIENT COMPUTATION
// ============================================================================

/// Compute Lagrange coefficient for signer i given other signer j
/// λ_i = j / (j - i)
fn lagrange_coefficient(signer_idx: u16, other_idx: u16) -> Scalar {
    let i = Scalar::from(signer_idx);
    let j = Scalar::from(other_idx);

    // λ_i = j / (j - i)
    j * (j - i).invert()
}

/// Compute both Lagrange coefficients for a 2-of-3 signer pair
fn compute_lagrange_pair(idx1: u16, idx2: u16) -> (Scalar, Scalar) {
    // λ₁ = idx2 / (idx2 - idx1)
    let lambda1 = lagrange_coefficient(idx1, idx2);
    // λ₂ = idx1 / (idx1 - idx2)
    let lambda2 = lagrange_coefficient(idx2, idx1);

    (lambda1, lambda2)
}

// ============================================================================
// BUYER + VENDOR PAIR (indices 1, 2)
// ============================================================================

#[test]
fn test_lagrange_buyer_vendor_coefficients() {
    let (lambda_buyer, lambda_vendor) = compute_lagrange_pair(1, 2);

    // λ_buyer = 2 / (2 - 1) = 2
    assert_eq!(
        lambda_buyer,
        Scalar::from(2u64),
        "λ_buyer should be 2 for buyer+vendor pair"
    );

    // λ_vendor = 1 / (1 - 2) = -1
    assert_eq!(
        lambda_vendor,
        -Scalar::ONE,
        "λ_vendor should be -1 for buyer+vendor pair"
    );
}

#[test]
fn test_buyer_vendor_sum_is_one() {
    let (lambda_buyer, lambda_vendor) = compute_lagrange_pair(1, 2);

    // λ₁ + λ₂ = 1 (fundamental Lagrange property)
    let sum = lambda_buyer + lambda_vendor;
    assert_eq!(
        sum,
        Scalar::ONE,
        "Sum of Lagrange coefficients should be 1"
    );
}

// ============================================================================
// BUYER + ARBITER PAIR (indices 1, 3)
// ============================================================================

#[test]
fn test_lagrange_buyer_arbiter_coefficients() {
    let (lambda_buyer, lambda_arbiter) = compute_lagrange_pair(1, 3);

    // λ_buyer = 3 / (3 - 1) = 3/2
    // Verify by checking 2 * λ_buyer = 3
    let two_lambda_buyer = lambda_buyer * Scalar::from(2u64);
    assert_eq!(
        two_lambda_buyer,
        Scalar::from(3u64),
        "2 * λ_buyer should be 3 (i.e., λ_buyer = 3/2)"
    );

    // λ_arbiter = 1 / (1 - 3) = -1/2
    // Verify by checking 2 * λ_arbiter = -1
    let two_lambda_arbiter = lambda_arbiter * Scalar::from(2u64);
    assert_eq!(
        two_lambda_arbiter,
        -Scalar::ONE,
        "2 * λ_arbiter should be -1 (i.e., λ_arbiter = -1/2)"
    );
}

#[test]
fn test_buyer_arbiter_sum_is_one() {
    let (lambda_buyer, lambda_arbiter) = compute_lagrange_pair(1, 3);

    // λ₁ + λ₂ = 1
    let sum = lambda_buyer + lambda_arbiter;
    assert_eq!(
        sum,
        Scalar::ONE,
        "Sum of Lagrange coefficients should be 1"
    );
}

// ============================================================================
// VENDOR + ARBITER PAIR (indices 2, 3)
// ============================================================================

#[test]
fn test_lagrange_vendor_arbiter_coefficients() {
    let (lambda_vendor, lambda_arbiter) = compute_lagrange_pair(2, 3);

    // λ_vendor = 3 / (3 - 2) = 3
    assert_eq!(
        lambda_vendor,
        Scalar::from(3u64),
        "λ_vendor should be 3 for vendor+arbiter pair"
    );

    // λ_arbiter = 2 / (2 - 3) = -2
    assert_eq!(
        lambda_arbiter,
        -Scalar::from(2u64),
        "λ_arbiter should be -2 for vendor+arbiter pair"
    );
}

#[test]
fn test_vendor_arbiter_sum_is_one() {
    let (lambda_vendor, lambda_arbiter) = compute_lagrange_pair(2, 3);

    // λ₁ + λ₂ = 1
    let sum = lambda_vendor + lambda_arbiter;
    assert_eq!(
        sum,
        Scalar::ONE,
        "Sum of Lagrange coefficients should be 1"
    );
}

// ============================================================================
// SCALAR FIELD ARITHMETIC TESTS
// ============================================================================

#[test]
fn test_scalar_negation() {
    // -1 in scalar field is l - 1 (where l is the group order)
    let neg_one = -Scalar::ONE;
    let one = Scalar::ONE;

    // -1 + 1 = 0
    assert_eq!(
        neg_one + one,
        Scalar::ZERO,
        "(-1) + 1 should equal 0 in scalar field"
    );
}

#[test]
fn test_scalar_inverse() {
    // 2 * (1/2) = 1
    let two = Scalar::from(2u64);
    let half = two.invert();
    assert_eq!(
        two * half,
        Scalar::ONE,
        "2 * (1/2) should equal 1"
    );

    // 3 * (1/3) = 1
    let three = Scalar::from(3u64);
    let third = three.invert();
    assert_eq!(
        three * third,
        Scalar::ONE,
        "3 * (1/3) should equal 1"
    );
}

#[test]
fn test_scalar_division() {
    // a / b = a * (1/b)
    let a = Scalar::from(6u64);
    let b = Scalar::from(2u64);

    let result = a * b.invert();
    assert_eq!(
        result,
        Scalar::from(3u64),
        "6 / 2 should equal 3"
    );
}

#[test]
fn test_negative_scalar_division() {
    // 1 / (-1) = -1
    let one = Scalar::ONE;
    let neg_one = -Scalar::ONE;

    let result = one * neg_one.invert();
    assert_eq!(
        result,
        neg_one,
        "1 / (-1) should equal -1"
    );
}

// ============================================================================
// KEY RECONSTRUCTION VERIFICATION
// ============================================================================

#[test]
fn test_key_reconstruction_buyer_vendor() {
    let mut rng = DeterministicRng::with_name("lagrange_recon_bv");

    // Secret shares (in a real system, these come from DKG)
    let share1 = rng.gen_scalar(); // Buyer's share at x=1
    let share2 = rng.gen_scalar(); // Vendor's share at x=2

    // Compute Lagrange coefficients
    let (lambda1, lambda2) = compute_lagrange_pair(1, 2);

    // Reconstruct secret at x=0
    let reconstructed = lambda1 * share1 + lambda2 * share2;

    // Verify the shares are at the correct points
    // f(1) = share1, f(2) = share2, f(0) = reconstructed
    // For linear interpolation through (1, s1) and (2, s2):
    // f(x) = λ₁(x)*s1 + λ₂(x)*s2

    // At x=0: f(0) = (2/(2-1))*s1 + (1/(1-2))*s2 = 2*s1 - s2
    let expected = Scalar::from(2u64) * share1 - share2;
    assert_eq!(
        reconstructed, expected,
        "Lagrange reconstruction should match linear interpolation"
    );
}

#[test]
fn test_key_reconstruction_all_pairs_consistent() {
    let mut rng = DeterministicRng::with_name("lagrange_all_pairs");

    // Generate a "true" secret and shares on a line through it
    let true_secret = rng.gen_scalar(); // f(0) = s
    let slope = rng.gen_scalar();       // random slope

    // Shares: f(x) = s + slope * x
    let share1 = true_secret + slope;              // f(1)
    let share2 = true_secret + Scalar::from(2u64) * slope; // f(2)
    let share3 = true_secret + Scalar::from(3u64) * slope; // f(3)

    // Reconstruct from buyer+vendor (1, 2)
    let (l1_bv, l2_bv) = compute_lagrange_pair(1, 2);
    let recon_bv = l1_bv * share1 + l2_bv * share2;

    // Reconstruct from buyer+arbiter (1, 3)
    let (l1_ba, l3_ba) = compute_lagrange_pair(1, 3);
    let recon_ba = l1_ba * share1 + l3_ba * share3;

    // Reconstruct from vendor+arbiter (2, 3)
    let (l2_va, l3_va) = compute_lagrange_pair(2, 3);
    let recon_va = l2_va * share2 + l3_va * share3;

    // All reconstructions should equal the true secret
    assert_eq!(recon_bv, true_secret, "Buyer+Vendor should reconstruct secret");
    assert_eq!(recon_ba, true_secret, "Buyer+Arbiter should reconstruct secret");
    assert_eq!(recon_va, true_secret, "Vendor+Arbiter should reconstruct secret");
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_lagrange_zero_invert_panic() {
    // This should NOT panic - j - i != 0 when j != i
    // But let's verify division by zero is avoided

    // Same index would cause j - i = 0, which is undefined
    // Our implementation should never be called with same indices
    // This is a documentation test - the actual panic would occur
    // if we computed lagrange_coefficient(1, 1)
}

#[test]
fn test_large_indices() {
    // Verify large indices still work
    let (l1, l2) = compute_lagrange_pair(1000, 2000);

    // Sum should still be 1
    assert_eq!(l1 + l2, Scalar::ONE, "Sum should be 1 even for large indices");
}

#[test]
fn test_coefficient_determinism() {
    // Coefficients should be deterministic (no randomness)
    let (l1a, l2a) = compute_lagrange_pair(1, 2);
    let (l1b, l2b) = compute_lagrange_pair(1, 2);

    assert_eq!(l1a, l1b, "Lambda1 should be deterministic");
    assert_eq!(l2a, l2b, "Lambda2 should be deterministic");
}

// ============================================================================
// CLSAG COMPATIBILITY TESTS
// ============================================================================

#[test]
fn test_lagrange_applied_to_points() {
    let mut rng = DeterministicRng::with_name("lagrange_points");

    // In CLSAG, we apply Lagrange to key images:
    // KI = λ₁*PKI₁ + λ₂*PKI₂

    let pki1 = rng.gen_point();
    let pki2 = rng.gen_point();

    let (lambda1, lambda2) = compute_lagrange_pair(1, 2);

    // Apply Lagrange (point * scalar, not scalar * point)
    let ki = (pki1 * lambda1) + (pki2 * lambda2);

    // Verify computation is valid (non-identity for random points)
    use curve25519_dalek::traits::Identity;
    use curve25519_dalek::edwards::EdwardsPoint;
    assert_ne!(
        ki,
        EdwardsPoint::identity(),
        "Lagrange-weighted sum should be non-identity"
    );
}

#[test]
fn test_scalar_multiplication_distribution() {
    let mut rng = DeterministicRng::with_name("lagrange_dist");

    let p = rng.gen_point();
    let lambda1 = Scalar::from(2u64);
    let lambda2 = -Scalar::ONE;

    // (λ₁ + λ₂) * P = λ₁*P + λ₂*P
    let left = (lambda1 + lambda2) * p;
    let right = (lambda1 * p) + (lambda2 * p);

    assert_eq!(left, right, "Scalar multiplication should distribute");

    // Since λ₁ + λ₂ = 1, this equals P
    assert_eq!(left, p, "(λ₁ + λ₂)*P should equal P when sum is 1");
}
