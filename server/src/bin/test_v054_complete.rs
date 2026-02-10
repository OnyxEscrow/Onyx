//! Complete v0.54.0 FROST CLSAG Flow Test
//!
//! This test simulates the ENTIRE signing flow including:
//! 1. PKI computation WITHOUT derivation (as WASM does)
//! 2. PKI aggregation on server (simple sum)
//! 3. Adding derivation to aggregated KI (v0.54.0 fix in prepare_sign)
//! 4. CLSAG partial signature computation
//! 5. Signature aggregation
//! 6. CLSAG verification
//!
//! Run: cargo run --release --bin test_v054_complete

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use monero_generators_mirror::hash_to_point;
use sha3::{Digest, Keccak256};

// ============================================================================
// ESCROW DATA (from database for escrow ef57f177-f873-40c3-a175-4ab87c195ad8)
// These are VERIFIED constants from FROST_CLSAG_VERIFICATION_STATUS.md
// ============================================================================
const BUYER_SPEND_SHARE: &str = "916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b";
const VENDOR_SPEND_SHARE: &str = "7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e";
const VIEW_KEY_PRIV: &str = "f2fcd78c14a49e707e4a7f4dfc24f5cfbfddfff5f94837bcddd72d88d963e808";
const TX_PUBKEY: &str = "75ee30c8278cd0da2e081f0dbd22bd8c884d83da2f061c013175fb5612009da9";
const OUTPUT_INDEX: u64 = 1;
const EXPECTED_ONE_TIME_PUBKEY: &str =
    "ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0";
const EXPECTED_KEY_IMAGE: &str = "8ffbfb305308f35ac4bba545fc33257fc9d91f031959529a48bb7e8ef81d75ff";

fn hex_to_scalar(hex: &str) -> Scalar {
    let bytes = hex::decode(hex).expect("Invalid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Scalar::from_bytes_mod_order(arr)
}

fn hex_to_point(hex: &str) -> Option<EdwardsPoint> {
    let bytes = hex::decode(hex).ok()?;
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

/// Lagrange coefficient λ_i for 2-of-3 threshold
fn compute_lagrange_coefficient(my_index: u8, other_index: u8) -> Scalar {
    let i = Scalar::from(my_index as u64);
    let j = Scalar::from(other_index as u64);
    j * (j - i).invert()
}

/// Compute derivation scalar with cofactor (v0.52.0 CORRECT)
fn compute_derivation(view_key: &Scalar, tx_pubkey: &EdwardsPoint, output_index: u64) -> Scalar {
    // shared_secret = 8 * view_key * tx_pubkey (WITH COFACTOR)
    let shared_secret = (view_key * tx_pubkey).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    hasher.update(&encode_varint(output_index));
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║     FROST 2-of-3 CLSAG v0.54.0 COMPLETE FLOW TEST                        ║");
    println!("║     Simulating: PKI → Aggregation → Derivation Fix → Signing             ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝\n");

    // Parse inputs
    let view_key = hex_to_scalar(VIEW_KEY_PRIV);
    let tx_pubkey = hex_to_point(TX_PUBKEY).expect("Invalid TX pubkey");
    let b_buyer = hex_to_scalar(BUYER_SPEND_SHARE);
    let b_vendor = hex_to_scalar(VENDOR_SPEND_SHARE);
    let p_expected = hex_to_point(EXPECTED_ONE_TIME_PUBKEY).expect("Invalid expected pubkey");
    let p_bytes: [u8; 32] = p_expected.compress().to_bytes();

    // Compute Hp(P) for key image
    let hp_p = hash_to_point(p_bytes);

    // Lagrange coefficients for buyer(1) + vendor(2)
    let lambda_buyer = compute_lagrange_coefficient(1, 2); // λ₁ = 2
    let lambda_vendor = compute_lagrange_coefficient(2, 1); // λ₂ = -1

    println!("=== STEP 1: Compute Partial Key Images (WASM behavior) ===\n");
    println!("In WASM, PKIs are computed WITHOUT derivation:");
    println!("  pKI = λ * b * Hp(P)    (spend share only, no derivation)\n");

    // WASM computes: pKI_buyer = λ_buyer * b_buyer * Hp(P)
    let pki_buyer_point = (lambda_buyer * b_buyer) * hp_p;
    let pki_buyer_hex = hex::encode(pki_buyer_point.compress().to_bytes());

    // WASM computes: pKI_vendor = λ_vendor * b_vendor * Hp(P)
    let pki_vendor_point = (lambda_vendor * b_vendor) * hp_p;
    let pki_vendor_hex = hex::encode(pki_vendor_point.compress().to_bytes());

    println!("pKI_buyer  (λ₁*b₁*Hp(P)): {}", &pki_buyer_hex[..32]);
    println!("pKI_vendor (λ₂*b₂*Hp(P)): {}", &pki_vendor_hex[..32]);

    println!("\n=== STEP 2: Server Aggregates PKIs (simple sum) ===\n");

    // Server does: KI_partial = pKI_buyer + pKI_vendor
    let ki_partial = pki_buyer_point + pki_vendor_point;
    let ki_partial_hex = hex::encode(ki_partial.compress().to_bytes());

    println!("KI_partial = pKI_buyer + pKI_vendor");
    println!("KI_partial: {}", &ki_partial_hex[..32]);

    // This is (λ_buyer*b_buyer + λ_vendor*b_vendor) * Hp(P)
    // Missing the derivation d!

    println!("\n=== STEP 3: v0.54.0 Fix - Add Derivation in prepare_sign ===\n");

    // Compute derivation scalar d
    let d = compute_derivation(&view_key, &tx_pubkey, OUTPUT_INDEX);
    println!(
        "Derivation scalar d = Hs(8*a*R || idx): {}",
        hex::encode(d.to_bytes())
    );

    // Compute d * Hp(P)
    let derivation_contribution = d * hp_p;
    println!(
        "d * Hp(P): {}",
        hex::encode(derivation_contribution.compress().to_bytes())
    );

    // CORRECT key image: KI = KI_partial + d * Hp(P)
    let ki_corrected = ki_partial + derivation_contribution;
    let ki_corrected_hex = hex::encode(ki_corrected.compress().to_bytes());

    println!("\nKI_corrected = KI_partial + d*Hp(P)");
    println!("KI_corrected: {}", ki_corrected_hex);
    println!("KI_expected:  {}", EXPECTED_KEY_IMAGE);

    let ki_matches = ki_corrected_hex == EXPECTED_KEY_IMAGE;
    println!(
        "\nKey Image Match: {}",
        if ki_matches { "✅ PASS" } else { "❌ FAIL" }
    );

    println!("\n=== STEP 4: Verify x_total * G = P ===\n");

    // The correct private key is: x_total = d + λ_buyer*b_buyer + λ_vendor*b_vendor
    let x_total = d + lambda_buyer * b_buyer + lambda_vendor * b_vendor;
    let p_computed = &x_total * ED25519_BASEPOINT_TABLE;

    println!(
        "x_total = d + λ₁*b₁ + λ₂*b₂: {}",
        hex::encode(x_total.to_bytes())
    );
    println!(
        "x_total * G: {}",
        hex::encode(p_computed.compress().to_bytes())
    );
    println!("P expected:  {}", EXPECTED_ONE_TIME_PUBKEY);

    let p_matches = p_computed == p_expected;
    println!(
        "\nx_total * G = P: {}",
        if p_matches { "✅ PASS" } else { "❌ FAIL" }
    );

    println!("\n=== STEP 5: Simulate CLSAG Partial Signing ===\n");

    // Generate test nonces
    let alpha = Scalar::from(12345u64); // Test nonce
    let c_p = Scalar::from(98765u64); // Test challenge (would come from hash in real flow)

    println!("Using test values:");
    println!("  alpha (nonce): {}", hex::encode(alpha.to_bytes()));
    println!("  c_p (challenge): {}", hex::encode(c_p.to_bytes()));

    // v0.54.0 CORRECT formula for first signer (buyer):
    // s_partial_buyer = α - c_p*d - c_p*λ_buyer*b_buyer
    // (derivation is separate, not weighted by Lagrange!)
    let s_partial_buyer = alpha - c_p * d - c_p * (lambda_buyer * b_buyer);

    // Second signer (vendor) contribution:
    // s_partial_vendor = -c_p * λ_vendor * b_vendor (contribution only)
    let s_partial_vendor = -c_p * (lambda_vendor * b_vendor);

    println!("\nFirst signer (buyer):");
    println!("  s_partial = α - c_p*d - c_p*λ₁*b₁");
    println!(
        "  s_partial_buyer: {}",
        hex::encode(s_partial_buyer.to_bytes())
    );

    println!("\nSecond signer (vendor) contribution:");
    println!("  s_contrib = -c_p*λ₂*b₂");
    println!(
        "  s_partial_vendor: {}",
        hex::encode(s_partial_vendor.to_bytes())
    );

    // Aggregate signatures
    let s_final = s_partial_buyer + s_partial_vendor;
    println!("\nAggregated signature:");
    println!("  s_final = s_partial_buyer + s_partial_vendor");
    println!("  s_final: {}", hex::encode(s_final.to_bytes()));

    println!("\n=== STEP 6: Verify CLSAG Equation ===\n");

    // The CLSAG verification equation for L point:
    // L = s*G + c_p*P
    // Should equal: α*G (the original nonce commitment)

    let l_computed = &s_final * ED25519_BASEPOINT_TABLE + c_p * p_expected;
    let alpha_g = &alpha * ED25519_BASEPOINT_TABLE;

    println!("L = s*G + c_p*P");
    println!(
        "L computed: {}",
        hex::encode(l_computed.compress().to_bytes())
    );
    println!("α*G:        {}", hex::encode(alpha_g.compress().to_bytes()));

    let l_matches = l_computed == alpha_g;
    println!(
        "\nL = α*G: {}",
        if l_matches { "✅ PASS" } else { "❌ FAIL" }
    );

    // Also verify R point equation for key image
    // R = s*Hp(P) + c_p*KI
    // Should equal: α*Hp(P)

    let r_computed = s_final * hp_p + c_p * ki_corrected;
    let alpha_hp = alpha * hp_p;

    println!("\nR = s*Hp(P) + c_p*KI");
    println!(
        "R computed: {}",
        hex::encode(r_computed.compress().to_bytes())
    );
    println!(
        "α*Hp(P):    {}",
        hex::encode(alpha_hp.compress().to_bytes())
    );

    let r_matches = r_computed == alpha_hp;
    println!(
        "\nR = α*Hp(P): {}",
        if r_matches { "✅ PASS" } else { "❌ FAIL" }
    );

    println!("\n╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║                         TEST SUMMARY                                      ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝\n");

    println!("Step 1 - PKI computation (no derivation):     ✅ Simulated");
    println!("Step 2 - PKI aggregation (simple sum):        ✅ Simulated");
    println!(
        "Step 3 - v0.54.0 derivation fix:              {}",
        if ki_matches { "✅ PASS" } else { "❌ FAIL" }
    );
    println!(
        "Step 4 - x_total * G = P:                     {}",
        if p_matches { "✅ PASS" } else { "❌ FAIL" }
    );
    println!("Step 5 - Partial signing:                     ✅ Simulated");
    println!(
        "Step 6a - L = s*G + c_p*P = α*G:             {}",
        if l_matches { "✅ PASS" } else { "❌ FAIL" }
    );
    println!(
        "Step 6b - R = s*Hp(P) + c_p*KI = α*Hp(P):    {}",
        if r_matches { "✅ PASS" } else { "❌ FAIL" }
    );

    let all_pass = ki_matches && p_matches && l_matches && r_matches;

    if all_pass {
        println!("\n🎉 ALL TESTS PASS!");
        println!("\n   The v0.54.0 flow is mathematically correct:");
        println!("   1. PKIs computed without derivation: pKI = λ*b*Hp(P)");
        println!("   2. Server aggregates: KI_partial = Σ pKI_i");
        println!("   3. v0.54.0 adds derivation in prepare_sign: KI = KI_partial + d*Hp(P)");
        println!("   4. Browser uses corrected KI for tx_prefix_hash");
        println!("   5. CLSAG signatures verify correctly");
        println!("\n   Ready for browser test!");
        std::process::exit(0);
    } else {
        println!("\n❌ SOME TESTS FAILED - Review the implementation.");
        std::process::exit(1);
    }
}
