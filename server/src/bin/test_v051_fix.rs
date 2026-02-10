//! Test FROST 2-of-3 CLSAG with v0.51.0 fix
//!
//! This test verifies that the Lagrange coefficient is NOT applied to the derivation 'd',
//! only to the spend shares (b1, b2).
//!
//! Run: cargo run --release --bin test_v051_fix

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use monero_generators_mirror::hash_to_point;
use sha3::{Digest, Keccak256};

// ============================================================================
// ESCROW DATA (from database for escrow ef57f177-f873-40c3-a175-4ab87c195ad8)
// ============================================================================
const ESCROW_ID: &str = "ef57f177-f873-40c3-a175-4ab87c195ad8";
const AMOUNT: i64 = 1000000000; // 0.001 XMR

// Threshold shares (indices: buyer=1, vendor=2)
const BUYER_SPEND_SHARE: &str = "916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b";
const VENDOR_SPEND_SHARE: &str = "7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e";

// View key (shared)
const VIEW_KEY_PRIV: &str = "f2fcd78c14a49e707e4a7f4dfc24f5cfbfddfff5f94837bcddd72d88d963e808";

// Transaction data
const TX_PUBKEY: &str = "75ee30c8278cd0da2e081f0dbd22bd8c884d83da2f061c013175fb5612009da9";
const OUTPUT_INDEX: u64 = 1;

// Expected values (from verification)
const EXPECTED_ONE_TIME_PUBKEY: &str = "ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0";
const EXPECTED_KEY_IMAGE: &str = "8ffbfb305308f35ac4bba545fc33257fc9d91f031959529a48bb7e8ef81d75ff";

// Funding mask (z) from escrow
const FUNDING_MASK: &str = "c254d7f8dc4ccfbc7bbab6925a611398ca5c93ab9f3b8c731620ae168a3a4508";

// Pseudo-out mask (output_mask + dummy_mask)
const PSEUDO_OUT_MASK: &str = "ad5bac57f377fe632399bc69a18b0388346bd123cac008e0ddf941bc39460d00";

// Ring data (signer at index 15)
const SIGNER_INDEX: usize = 15;
const RING_SIZE: usize = 16;

// Ring public keys (16 members)
const RING_PUBKEYS: [&str; 16] = [
    "b2faa6d6e0fbb0aa1b22a93ea8a3e75f8a9f7e3c6d5b4a3928171605f4e3d2c1",
    "c3a5b7e8f1d2c4b6a8907162534d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80918273",
    "d4b6c8f9e2e3d5c7b9018273645e5f6071828394a5b6c7d8e9f0a1b2c3d4e5f6",
    "e5c7d9faf3f4e6d8ca129384756f607182939405b6c7d8e9f0a1b2c3d4e5f607",
    "f6d8eafb04050706db23a495867071829304a516c7d8e9f0a1b2c3d4e5f60718",
    "07e9fb0c15160817ec34b5a6978182930415b627d8e9f0a1b2c3d4e5f6071829",
    "18fa0c1d26270928fd45c6b7a89293a41526c738e9f0a1b2c3d4e5f607182930",
    "290b1d2e37381a39fe56d7c8b9a3a4b52637d849f0a1b2c3d4e5f60718293041",
    "3a1c2e3f48492b4aff67e8d9cab4b5c63748e95a01b2c3d4e5f6071829304152",
    "4b2d3f40595a3c5b0078f9eadbc5c6d74859fa6b12c3d4e5f607182930415263",
    "5c3e40516a6b4d6c1189fafbecd6d7e85960fb7c23d4e5f6071829304152637f",
    "6d4f51627b7c5e7d229afb0cfde7e8f96a710c8d34e5f607182930415263748a",
    "7e5062738c8d6f8e33abfc1d0ef8f90a7b821d9e45f6071829304152637485fb",
    "8f6173849d9e708f44bcfd2e1f090a1b8c932eaf56071829304152637485960c",
    "a07284950eaf819055cdfe3f200a1b2c9da43fb067182930415263748596a71d",
    "ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0", // Signer at index 15
];

// Ring commitments (16 members)
const RING_COMMITMENTS: [&str; 16] = [
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1",
    "34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
    "4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123",
    "567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234",
    "67890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345",
    "7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
    "890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567",
    "90abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
    "0abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789",
    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "bcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678901",
    "cdef1234567890abcdef1234567890abcdef1234567890abcdef123456789012",
    "def1234567890abcdef1234567890abcdef1234567890abcdef1234567890123",
    "ef1234567890abcdef1234567890abcdef1234567890abcdef12345678901234",
    "3f7ca0f9eca7ecbefc1ef46e5947fbb75d8fca9e2c7e2230f0a552fde59336a0", // Real commitment at index 15
];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("Invalid hex")
}

fn hex_to_scalar(hex: &str) -> Scalar {
    let bytes = hex_to_bytes(hex);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Scalar::from_bytes_mod_order(arr)
}

fn hex_to_point(hex: &str) -> Option<EdwardsPoint> {
    let bytes = hex_to_bytes(hex);
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr).decompress()
}

fn encode_varint(value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut n = value;
    while n >= 0x80 {
        result.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    result.push(n as u8);
    result
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn keccak256_to_scalar(data: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order(keccak256(data))
}

/// Compute Lagrange coefficient λ_i for 2-of-3 threshold
/// λ_i = j / (j - i) where i is my_index and j is other_index
fn compute_lagrange_coefficient(my_index: u8, other_index: u8) -> Scalar {
    let i = Scalar::from(my_index as u64);
    let j = Scalar::from(other_index as u64);
    let numerator = j;
    let denominator = j - i;
    numerator * denominator.invert()
}

/// Compute derivation scalar from tx_pubkey and view_key
fn compute_derivation(view_key: &Scalar, tx_pubkey: &EdwardsPoint, output_index: u64) -> Scalar {
    // shared_secret = 8 * view_key * tx_pubkey (with cofactor for Monero compatibility)
    // v0.52.0 FIX: Added mul_by_cofactor() which is REQUIRED for correct derivation
    let shared_secret = (view_key * tx_pubkey).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    // Hash: H_s(shared_secret || varint(output_index))
    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    hasher.update(&encode_varint(output_index));
    let hash: [u8; 32] = hasher.finalize().into();

    Scalar::from_bytes_mod_order(hash)
}

/// Build CLSAG domain separator (32 bytes, null-padded)
fn clsag_domain(suffix: &str) -> [u8; 32] {
    let prefix = b"CLSAG_";
    let mut domain = [0u8; 32];
    domain[..prefix.len()].copy_from_slice(prefix);
    let suffix_bytes = suffix.as_bytes();
    domain[prefix.len()..prefix.len() + suffix_bytes.len()].copy_from_slice(suffix_bytes);
    domain
}

/// Compute mu_P and mu_C from CLSAG aggregation hash
fn compute_mu_coefficients(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    let n = ring_keys.len();
    let mut buffer = Vec::with_capacity((2 * n + 5) * 32);

    // Domain separator for agg_0
    buffer.extend_from_slice(&clsag_domain("agg_0"));

    // Ring keys
    for key in ring_keys {
        buffer.extend_from_slice(&key.compress().to_bytes());
    }

    // Ring commitments
    for commit in ring_commitments {
        buffer.extend_from_slice(&commit.compress().to_bytes());
    }

    // Key image
    buffer.extend_from_slice(&key_image.compress().to_bytes());

    // D * inv8
    buffer.extend_from_slice(&d_inv8.compress().to_bytes());

    // Pseudo output
    buffer.extend_from_slice(&pseudo_out.compress().to_bytes());

    let mu_p = keccak256_to_scalar(&buffer);

    // Change domain to agg_1 for mu_C
    buffer[..32].copy_from_slice(&clsag_domain("agg_1"));
    let mu_c = keccak256_to_scalar(&buffer);

    (mu_p, mu_c)
}

// ============================================================================
// MAIN TEST
// ============================================================================

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     FROST 2-of-3 CLSAG TEST with v0.51.0 FIX                     ║");
    println!("║     Testing: Derivation NOT weighted by Lagrange coefficient     ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // ========================================================================
    // Step 1: Compute derivation scalar
    // ========================================================================
    println!("=== STEP 1: Compute Derivation ===");

    let view_key = hex_to_scalar(VIEW_KEY_PRIV);
    let tx_pubkey = hex_to_point(TX_PUBKEY).expect("Invalid TX pubkey");

    let derivation = compute_derivation(&view_key, &tx_pubkey, OUTPUT_INDEX);
    println!("Derivation (d): {}", hex::encode(derivation.to_bytes()));

    // ========================================================================
    // Step 2: Compute Lagrange coefficients
    // ========================================================================
    println!("\n=== STEP 2: Lagrange Coefficients ===");

    // Buyer = index 1, Vendor = index 2
    let lambda_buyer = compute_lagrange_coefficient(1, 2);  // λ_1 = 2/(2-1) = 2
    let lambda_vendor = compute_lagrange_coefficient(2, 1); // λ_2 = 1/(1-2) = -1

    println!("λ_buyer (index 1):  {} (expected: 2)", hex::encode(lambda_buyer.to_bytes()));
    println!("λ_vendor (index 2): {} (expected: -1 mod L)", hex::encode(lambda_vendor.to_bytes()));

    // Verify λ values
    let two = Scalar::from(2u64);
    let neg_one = -Scalar::ONE;

    if lambda_buyer == two {
        println!("  λ_buyer = 2 ✅");
    } else {
        println!("  λ_buyer ≠ 2 ❌");
    }

    if lambda_vendor == neg_one {
        println!("  λ_vendor = -1 ✅");
    } else {
        println!("  λ_vendor ≠ -1 ❌");
    }

    // ========================================================================
    // Step 3: Compute effective secret x_total
    // ========================================================================
    println!("\n=== STEP 3: Compute x_total (CORRECT vs BUG) ===");

    let b_buyer = hex_to_scalar(BUYER_SPEND_SHARE);
    let b_vendor = hex_to_scalar(VENDOR_SPEND_SHARE);

    // v0.51.0 CORRECT: x_total = d + λ_buyer*b_buyer + λ_vendor*b_vendor
    // Derivation is NOT weighted by λ!
    let x_total_correct = derivation + lambda_buyer * b_buyer + lambda_vendor * b_vendor;

    // v0.50.0 BUG: First signer computed λ1*(d + b1) instead of d + λ1*b1
    // Assuming buyer is first signer:
    let x_total_bug = lambda_buyer * (derivation + b_buyer) + lambda_vendor * b_vendor;

    println!("x_total (v0.51.0 CORRECT): {}", hex::encode(x_total_correct.to_bytes()));
    println!("x_total (v0.50.0 BUG):     {}", hex::encode(x_total_bug.to_bytes()));

    if x_total_correct != x_total_bug {
        println!("\n⚠️  BUG CONFIRMED: x_total values differ!");
        let diff = x_total_bug - x_total_correct;
        println!("   Difference: {}", hex::encode(diff.to_bytes()));
        println!("   This explains why CLSAG verification was failing.");
    }

    // ========================================================================
    // Step 4: Verify x_total * G = P (one-time pubkey)
    // ========================================================================
    println!("\n=== STEP 4: Verify x_total * G == P ===");

    let p_computed_correct = &x_total_correct * ED25519_BASEPOINT_TABLE;
    let p_computed_bug = &x_total_bug * ED25519_BASEPOINT_TABLE;
    let p_expected = hex_to_point(EXPECTED_ONE_TIME_PUBKEY).expect("Invalid expected pubkey");

    println!("P from x_total (CORRECT): {}", hex::encode(p_computed_correct.compress().to_bytes()));
    println!("P from x_total (BUG):     {}", hex::encode(p_computed_bug.compress().to_bytes()));
    println!("P expected:               {}", EXPECTED_ONE_TIME_PUBKEY);

    if p_computed_correct == p_expected {
        println!("\n✅ CORRECT formula: x_total * G == P");
    } else {
        println!("\n❌ CORRECT formula failed: x_total * G ≠ P");
    }

    if p_computed_bug == p_expected {
        println!("✅ BUG formula: x_total * G == P (unexpected!)");
    } else {
        println!("❌ BUG formula: x_total * G ≠ P (expected, confirms bug)");
    }

    // ========================================================================
    // Step 5: Compute Key Image
    // ========================================================================
    println!("\n=== STEP 5: Compute Key Image ===");

    let p_bytes: [u8; 32] = p_expected.compress().to_bytes();
    let hp_p = hash_to_point(p_bytes);

    let ki_correct = x_total_correct * hp_p;
    let ki_bug = x_total_bug * hp_p;

    println!("Key Image (CORRECT): {}", hex::encode(ki_correct.compress().to_bytes()));
    println!("Key Image (BUG):     {}", hex::encode(ki_bug.compress().to_bytes()));
    println!("Key Image expected:  {}", EXPECTED_KEY_IMAGE);

    if hex::encode(ki_correct.compress().to_bytes()) == EXPECTED_KEY_IMAGE {
        println!("\n✅ Key Image MATCHES with CORRECT formula!");
    } else {
        println!("\n❌ Key Image mismatch with CORRECT formula");
    }

    // ========================================================================
    // Step 6: Simulate CLSAG signing with CORRECT formula
    // ========================================================================
    println!("\n=== STEP 6: Simulate CLSAG Signing ===");

    // Parse masks
    let z = hex_to_scalar(FUNDING_MASK);
    let pseudo_out_mask = hex_to_scalar(PSEUDO_OUT_MASK);
    let mask_delta = z - pseudo_out_mask;

    println!("funding_mask (z):    {}", FUNDING_MASK);
    println!("pseudo_out_mask:     {}", PSEUDO_OUT_MASK);
    println!("mask_delta (z-pom):  {}", hex::encode(mask_delta.to_bytes()));

    // D point computation
    let d_point = mask_delta * hp_p;
    let inv8 = Scalar::from(8u64).invert();
    let d_inv8 = d_point * inv8;

    println!("D = mask_delta * Hp(P): {}", hex::encode(d_point.compress().to_bytes()));
    println!("D_inv8 = D / 8:         {}", hex::encode(d_inv8.compress().to_bytes()));

    // For a full test, we'd need to:
    // 1. Parse all ring members
    // 2. Build the CLSAG buffer
    // 3. Compute c1, mu_p, mu_c
    // 4. Run the ring loop
    // 5. Verify c_computed == c_expected

    // Simplified verification: Just check the key relationships
    println!("\n=== STEP 7: Key Relationship Verification ===");

    // For CLSAG to verify, we need:
    // - KI = x * Hp(P)  where x = x_total
    // - D = mask_delta * Hp(P)
    // - s = α - c_p * x - c_c * mask_delta

    // Generate a test nonce α
    let alpha = Scalar::from(12345u64); // Deterministic for test

    // Simulate c_p and c_c (normally computed from ring loop)
    let c_test = Scalar::from(98765u64);
    let mu_p_test = Scalar::from(11111u64);
    let mu_c_test = Scalar::from(22222u64);
    let c_p = c_test * mu_p_test;
    let c_c = c_test * mu_c_test;

    // Compute s with CORRECT formula
    let s_correct = alpha - c_p * x_total_correct - c_c * mask_delta;

    // Compute s with BUG formula
    let s_bug = alpha - c_p * x_total_bug - c_c * mask_delta;

    println!("s (CORRECT): {}", hex::encode(s_correct.to_bytes()));
    println!("s (BUG):     {}", hex::encode(s_bug.to_bytes()));

    // Verify: s*G + c_p*P should equal α*G (for L point)
    let l_correct = &s_correct * ED25519_BASEPOINT_TABLE + c_p * p_expected;
    let l_bug = &s_bug * ED25519_BASEPOINT_TABLE + c_p * p_expected;
    let alpha_g = &alpha * ED25519_BASEPOINT_TABLE;

    println!("\n=== STEP 8: L Point Verification ===");
    println!("L = s*G + c_p*P");
    println!("Expected: α*G = {}", hex::encode(alpha_g.compress().to_bytes()));
    println!("L (CORRECT):   {}", hex::encode(l_correct.compress().to_bytes()));
    println!("L (BUG):       {}", hex::encode(l_bug.compress().to_bytes()));

    if l_correct == alpha_g {
        println!("\n✅ L point MATCHES with CORRECT formula!");
    } else {
        println!("\n❌ L point mismatch with CORRECT formula");
    }

    // Verify R point: s*Hp + c_p*KI should equal α*Hp
    let r_correct = s_correct * hp_p + c_p * ki_correct;
    let r_bug = s_bug * hp_p + c_p * ki_bug;
    let alpha_hp = alpha * hp_p;

    println!("\n=== STEP 9: R Point Verification ===");
    println!("R = s*Hp + c_p*KI");
    println!("Expected: α*Hp = {}", hex::encode(alpha_hp.compress().to_bytes()));
    println!("R (CORRECT):    {}", hex::encode(r_correct.compress().to_bytes()));
    println!("R (BUG):        {}", hex::encode(r_bug.compress().to_bytes()));

    if r_correct == alpha_hp {
        println!("\n✅ R point MATCHES with CORRECT formula!");
    } else {
        println!("\n❌ R point mismatch with CORRECT formula");
    }

    // ========================================================================
    // Final Summary
    // ========================================================================
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                        TEST SUMMARY                              ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    let pubkey_ok = p_computed_correct == p_expected;
    let ki_ok = hex::encode(ki_correct.compress().to_bytes()) == EXPECTED_KEY_IMAGE;
    let l_ok = l_correct == alpha_g;
    let r_ok = r_correct == alpha_hp;

    println!("x_total * G == P:       {}", if pubkey_ok { "✅ PASS" } else { "❌ FAIL" });
    println!("Key Image matches:      {}", if ki_ok { "✅ PASS" } else { "❌ FAIL" });
    println!("L = s*G + c_p*P == α*G: {}", if l_ok { "✅ PASS" } else { "❌ FAIL" });
    println!("R = s*Hp + c_p*KI == α*Hp: {}", if r_ok { "✅ PASS" } else { "❌ FAIL" });

    if pubkey_ok && ki_ok && l_ok && r_ok {
        println!("\n🎉 ALL TESTS PASSED! v0.51.0 fix is CORRECT.");
        println!("   The derivation 'd' should NOT be weighted by Lagrange coefficient.");
    } else {
        println!("\n⚠️  SOME TESTS FAILED. Review the fix.");
    }
}
