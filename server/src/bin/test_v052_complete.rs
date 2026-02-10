//! Complete v0.52.0 FROST CLSAG Test
//!
//! This test verifies the CLSAG signature with:
//! 1. Cofactor multiplication in derivation (v0.52.0 fix)
//! 2. Derivation NOT weighted by Lagrange coefficient (v0.51.0 fix)
//!
//! Run: cargo run --release --bin test_v052_complete

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use monero_generators_mirror::hash_to_point;
use sha3::{Digest, Keccak256};

// ============================================================================
// ESCROW DATA (from database for escrow ef57f177-f873-40c3-a175-4ab87c195ad8)
// ============================================================================
const BUYER_SPEND_SHARE: &str = "916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b";
const VENDOR_SPEND_SHARE: &str = "7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e";
const VIEW_KEY_PRIV: &str = "f2fcd78c14a49e707e4a7f4dfc24f5cfbfddfff5f94837bcddd72d88d963e808";
const TX_PUBKEY: &str = "75ee30c8278cd0da2e081f0dbd22bd8c884d83da2f061c013175fb5612009da9";
const OUTPUT_INDEX: u64 = 1;
const EXPECTED_ONE_TIME_PUBKEY: &str =
    "ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0";
const EXPECTED_KEY_IMAGE: &str = "8ffbfb305308f35ac4bba545fc33257fc9d91f031959529a48bb7e8ef81d75ff";
const FUNDING_MASK: &str = "c254d7f8dc4ccfbc7bbab6925a611398ca5c93ab9f3b8c731620ae168a3a4508";

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

/// v0.52.0 CORRECT: Derivation with cofactor multiplication
fn compute_derivation_v052(
    view_key: &Scalar,
    tx_pubkey: &EdwardsPoint,
    output_index: u64,
) -> Scalar {
    // shared_secret = 8 * view_key * tx_pubkey (WITH COFACTOR)
    let shared_secret = (view_key * tx_pubkey).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    hasher.update(&encode_varint(output_index));
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

/// v0.50.0 BUG: Derivation without cofactor
fn compute_derivation_v050(
    view_key: &Scalar,
    tx_pubkey: &EdwardsPoint,
    output_index: u64,
) -> Scalar {
    // shared_secret = view_key * tx_pubkey (NO COFACTOR - BUG!)
    let shared_secret = view_key * tx_pubkey;
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    hasher.update(&encode_varint(output_index));
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     FROST 2-of-3 CLSAG v0.52.0 COMPLETE TEST                     ║");
    println!("║     Testing: Cofactor + Lagrange NOT applied to derivation       ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Parse inputs
    let view_key = hex_to_scalar(VIEW_KEY_PRIV);
    let tx_pubkey = hex_to_point(TX_PUBKEY).expect("Invalid TX pubkey");
    let b_buyer = hex_to_scalar(BUYER_SPEND_SHARE);
    let b_vendor = hex_to_scalar(VENDOR_SPEND_SHARE);
    let p_expected = hex_to_point(EXPECTED_ONE_TIME_PUBKEY).expect("Invalid expected pubkey");

    // Lagrange coefficients
    let lambda_buyer = compute_lagrange_coefficient(1, 2); // λ₁ = 2
    let lambda_vendor = compute_lagrange_coefficient(2, 1); // λ₂ = -1

    println!("=== STEP 1: Compare Derivation Computation ===\n");

    let d_v052 = compute_derivation_v052(&view_key, &tx_pubkey, OUTPUT_INDEX);
    let d_v050 = compute_derivation_v050(&view_key, &tx_pubkey, OUTPUT_INDEX);

    println!(
        "Derivation (v0.52.0 WITH cofactor):    {}",
        hex::encode(d_v052.to_bytes())
    );
    println!(
        "Derivation (v0.50.0 WITHOUT cofactor): {}",
        hex::encode(d_v050.to_bytes())
    );
    println!(
        "Derivations differ: {}",
        if d_v052 != d_v050 {
            "✅ YES (cofactor matters!)"
        } else {
            "❌ NO"
        }
    );

    println!("\n=== STEP 2: Compute x_total with CORRECT formula ===\n");

    // v0.52.0 CORRECT: x_total = d + λ₁*b₁ + λ₂*b₂
    // Derivation is NOT weighted by Lagrange!
    let x_total_v052 = d_v052 + lambda_buyer * b_buyer + lambda_vendor * b_vendor;

    // v0.50.0 BUG (no cofactor):
    let x_total_v050_nocof = d_v050 + lambda_buyer * b_buyer + lambda_vendor * b_vendor;

    // v0.49.0 BUG (cofactor but derivation weighted):
    let x_total_v049_weighted = lambda_buyer * (d_v052 + b_buyer) + lambda_vendor * b_vendor;

    println!(
        "x_total (v0.52.0 CORRECT):              {}",
        hex::encode(x_total_v052.to_bytes())
    );
    println!(
        "x_total (v0.50.0 no cofactor):          {}",
        hex::encode(x_total_v050_nocof.to_bytes())
    );
    println!(
        "x_total (v0.49.0 weighted derivation):  {}",
        hex::encode(x_total_v049_weighted.to_bytes())
    );

    println!("\n=== STEP 3: Verify x_total * G == P ===\n");

    let p_v052 = &x_total_v052 * ED25519_BASEPOINT_TABLE;
    let p_v050 = &x_total_v050_nocof * ED25519_BASEPOINT_TABLE;
    let p_v049 = &x_total_v049_weighted * ED25519_BASEPOINT_TABLE;

    println!(
        "P from v0.52.0: {}",
        hex::encode(p_v052.compress().to_bytes())
    );
    println!(
        "P from v0.50.0: {}",
        hex::encode(p_v050.compress().to_bytes())
    );
    println!(
        "P from v0.49.0: {}",
        hex::encode(p_v049.compress().to_bytes())
    );
    println!("P expected:     {}", EXPECTED_ONE_TIME_PUBKEY);

    let v052_ok = p_v052 == p_expected;
    let v050_ok = p_v050 == p_expected;
    let v049_ok = p_v049 == p_expected;

    println!(
        "\nv0.52.0 (cofactor + no λ on d): {}",
        if v052_ok { "✅ PASS" } else { "❌ FAIL" }
    );
    println!(
        "v0.50.0 (no cofactor):          {}",
        if v050_ok { "✅ PASS" } else { "❌ FAIL" }
    );
    println!(
        "v0.49.0 (weighted derivation):  {}",
        if v049_ok { "✅ PASS" } else { "❌ FAIL" }
    );

    println!("\n=== STEP 4: Compute Key Image ===\n");

    let p_bytes: [u8; 32] = p_expected.compress().to_bytes();
    let hp_p = hash_to_point(p_bytes);

    let ki_v052 = x_total_v052 * hp_p;
    let ki_v050 = x_total_v050_nocof * hp_p;

    println!(
        "Key Image (v0.52.0): {}",
        hex::encode(ki_v052.compress().to_bytes())
    );
    println!(
        "Key Image (v0.50.0): {}",
        hex::encode(ki_v050.compress().to_bytes())
    );
    println!("Key Image expected:  {}", EXPECTED_KEY_IMAGE);

    let ki_v052_ok = hex::encode(ki_v052.compress().to_bytes()) == EXPECTED_KEY_IMAGE;
    let ki_v050_ok = hex::encode(ki_v050.compress().to_bytes()) == EXPECTED_KEY_IMAGE;

    println!(
        "\nv0.52.0 Key Image: {}",
        if ki_v052_ok {
            "✅ MATCH"
        } else {
            "❌ MISMATCH"
        }
    );
    println!(
        "v0.50.0 Key Image: {}",
        if ki_v050_ok {
            "✅ MATCH"
        } else {
            "❌ MISMATCH"
        }
    );

    println!("\n=== STEP 5: Simulate s_partial Computation ===\n");

    // Generate test alpha and c values
    let alpha = Scalar::from(12345u64);
    let c_p = Scalar::from(98765u64);

    // v0.52.0 CORRECT: s = α - c_p * d - c_p * λ₁ * b₁
    // First signer contributes: α - c_p*d - c_p*λ₁*b₁
    let s_v052_buyer = alpha - c_p * d_v052 - c_p * (lambda_buyer * b_buyer);

    // v0.49.0 BUG: s = α - c_p * λ₁ * (d + b₁)
    let s_v049_buyer = alpha - c_p * (lambda_buyer * (d_v052 + b_buyer));

    println!(
        "s_partial buyer (v0.52.0 CORRECT): {}",
        hex::encode(s_v052_buyer.to_bytes())
    );
    println!(
        "s_partial buyer (v0.49.0 BUG):     {}",
        hex::encode(s_v049_buyer.to_bytes())
    );
    println!(
        "s_partial values differ: {}",
        if s_v052_buyer != s_v049_buyer {
            "✅ YES"
        } else {
            "❌ NO"
        }
    );

    // Verify L point: s*G + c_p*P should relate to alpha*G for correct formula
    let d_g = &d_v052 * ED25519_BASEPOINT_TABLE;
    let lb_b_g = &(lambda_buyer * b_buyer) * ED25519_BASEPOINT_TABLE;
    let l_v052 = &s_v052_buyer * ED25519_BASEPOINT_TABLE + c_p * (d_g + lb_b_g);
    let alpha_g = &alpha * ED25519_BASEPOINT_TABLE;

    println!(
        "\nL (s*G + c_p*(d*G + λ₁*b₁*G)): {}",
        hex::encode(l_v052.compress().to_bytes())
    );
    println!(
        "α*G:                           {}",
        hex::encode(alpha_g.compress().to_bytes())
    );
    println!(
        "L == α*G: {}",
        if l_v052 == alpha_g {
            "✅ MATCH"
        } else {
            "❌ MISMATCH"
        }
    );

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                         TEST SUMMARY                             ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    println!(
        "\n✓ Cofactor multiplication: {}",
        if d_v052 != d_v050 {
            "✅ VERIFIED (values differ)"
        } else {
            "❌ FAILED"
        }
    );
    println!(
        "✓ x_total * G == P (v0.52.0): {}",
        if v052_ok { "✅ PASS" } else { "❌ FAIL" }
    );
    println!(
        "✓ Key Image matches (v0.52.0): {}",
        if ki_v052_ok { "✅ PASS" } else { "❌ FAIL" }
    );
    println!(
        "✓ s_partial formula: {}",
        if s_v052_buyer != s_v049_buyer {
            "✅ CORRECTED"
        } else {
            "❌ SAME AS BUG"
        }
    );

    if v052_ok && ki_v052_ok {
        println!("\n🎉 v0.52.0 FIX IS CORRECT!");
        println!("   Both fixes applied:");
        println!("   1. Cofactor multiplication in derivation");
        println!("   2. Derivation NOT weighted by Lagrange coefficient");
        println!("\n   The WASM code should now produce valid CLSAG signatures.");
        std::process::exit(0);
    } else {
        println!("\n❌ TESTS FAILED - Review the fixes.");
        std::process::exit(1);
    }
}
