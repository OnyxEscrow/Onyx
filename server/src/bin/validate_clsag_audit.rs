//! CLSAG Audit Validator - v0.50.0
//!
//! Validates CLSAG signing against known funding TX values
//!
//! Usage: cargo run --bin validate_clsag_audit
//!
//! This script computes all intermediate CLSAG values from known escrow data
//! and validates each step against expected formulas.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use monero_generators::hash_to_point;
use sha3::{Digest, Keccak256};

/// =============================================================================
/// ESCROW DATA (from database: 8dfe6cd8-4ce8-4754-9c2e-9fcef175b05e)
/// =============================================================================
const ESCROW_ID: &str = "8dfe6cd8-4ce8-4754-9c2e-9fcef175b05e";
const FUNDING_TX_HASH: &str = "4963ebb1a74c93259864a15cae1364f0638b0dcec43677415f9541c43d221796";

/// TX Public Key (R) - from funding transaction extra field
const TX_PUB_KEY_R: &str = "f328e5ae72ba19d163b5cbea369cfeb67f1290dc34271acb28425203a20e62b7";

/// Shared View Key (a_shared) - from FROST DKG, stored in escrow
const SHARED_VIEW_KEY: &str = "d4f2f1cc764d4acc97a849ed525cf56e66de9657812920f1e001197a166d5909";

/// Funding Commitment Mask (z) - the blinding factor for the output commitment
const FUNDING_COMMITMENT_MASK: &str =
    "689d9955dcd9b994bccb690d42477ae2ec2cb8634f5fab62e08641fa01f57f09";

/// Output 0 (the escrow output being spent)
const OUTPUT_0_PUBKEY: &str = "8cd680c84b7f2e999fbf6b29c832df99ceae81ee0104718cad5d0fc1457f8bd3";
const OUTPUT_0_COMMITMENT: &str =
    "85046c4a1e7b7d6a1ebaef7dd36a62d36378e56b7c1d4c118613892cb086885b";
const OUTPUT_INDEX: u64 = 0;

/// Output 1 (change output - not used in escrow)
const OUTPUT_1_PUBKEY: &str = "c446e94d12ff95bcc20abc43821b67fa26e5832c9fadc1a91e5fb714ba0f4367";
const OUTPUT_1_COMMITMENT: &str =
    "d5e62020fd7418758719856154bd22ebdfb716d920685d1630e418393e987a35";

fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn hex_to_point(hex: &str) -> Result<EdwardsPoint, String> {
    let bytes = hex_to_bytes32(hex)?;
    CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| "Point decompression failed".to_string())
}

fn hex_to_scalar(hex: &str) -> Result<Scalar, String> {
    let bytes = hex_to_bytes32(hex)?;
    Ok(Scalar::from_bytes_mod_order(bytes))
}

/// Encode u64 as varint (Monero-compatible)
fn encode_varint(n: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut val = n;
    while val >= 0x80 {
        result.push((val as u8) | 0x80);
        val >>= 7;
    }
    result.push(val as u8);
    result
}

/// Compute Lagrange coefficient for index i given set of indices
fn lagrange_coefficient(i: u32, indices: &[u32]) -> Scalar {
    let mut result = Scalar::ONE;
    let i_scalar = Scalar::from(i);
    for &j in indices {
        if j != i {
            let j_scalar = Scalar::from(j);
            let numerator = j_scalar;
            let denominator = j_scalar - i_scalar;
            result *= numerator * denominator.invert();
        }
    }
    result
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║         CLSAG AUDIT VALIDATOR v0.50.0                            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    println!("📋 Escrow ID: {}", ESCROW_ID);
    println!("📋 Funding TX: {}", FUNDING_TX_HASH);
    println!("📋 TX Public Key (R): {}", TX_PUB_KEY_R);
    println!("📋 Shared View Key: {}...", &SHARED_VIEW_KEY[..16]);
    println!("📋 Funding Mask (z): {}...", &FUNDING_COMMITMENT_MASK[..16]);
    println!("📋 Output Index: {}", OUTPUT_INDEX);
    println!();

    // Parse all inputs
    let tx_pub_r = match hex_to_point(TX_PUB_KEY_R) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ Failed to parse TX pub key: {}", e);
            return;
        }
    };

    let view_key_shared = match hex_to_scalar(SHARED_VIEW_KEY) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to parse shared view key: {}", e);
            return;
        }
    };

    let funding_mask_z = match hex_to_scalar(FUNDING_COMMITMENT_MASK) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to parse funding mask: {}", e);
            return;
        }
    };

    let output_0_p = match hex_to_point(OUTPUT_0_PUBKEY) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ Failed to parse output 0 pubkey: {}", e);
            return;
        }
    };

    println!("═══════════════════════════════════════════════════════════════════");
    println!("STEP 1: Compute Hp(P) - Hash-to-Point of Output Public Key");
    println!("═══════════════════════════════════════════════════════════════════\n");

    let hp_p = hash_to_point(hex_to_bytes32(OUTPUT_0_PUBKEY).unwrap());
    println!("Output Public Key (P): {}", OUTPUT_0_PUBKEY);
    println!(
        "Hp(P):                 {}",
        hex::encode(hp_p.compress().to_bytes())
    );

    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("STEP 2: Lagrange Coefficients for Buyer(1) + Vendor(2)");
    println!("═══════════════════════════════════════════════════════════════════\n");

    let indices = [1u32, 2u32];
    let lambda_buyer = lagrange_coefficient(1, &indices); // λ₁ = 2
    let lambda_vendor = lagrange_coefficient(2, &indices); // λ₂ = -1

    println!(
        "λ_buyer (index 1):  {}",
        hex::encode(lambda_buyer.as_bytes())
    );
    println!(
        "λ_vendor (index 2): {}",
        hex::encode(lambda_vendor.as_bytes())
    );
    println!(
        "λ_buyer + λ_vendor: {}",
        hex::encode((lambda_buyer + lambda_vendor).as_bytes())
    );

    let expected_lambda_buyer = Scalar::from(2u64);
    let expected_lambda_vendor = -Scalar::ONE;

    if lambda_buyer == expected_lambda_buyer && lambda_vendor == expected_lambda_vendor {
        println!("✅ Lagrange coefficients CORRECT (λ₁=2, λ₂=-1, sum=1)");
    } else {
        println!("❌ Lagrange coefficients MISMATCH!");
        return;
    }

    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("STEP 3: Derivation Scalar Computation");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // Compute shared secret: 8 * a_shared * R (with cofactor)
    // This matches Monero's key derivation
    let shared_secret_point = (view_key_shared * tx_pub_r).mul_by_cofactor();
    let shared_secret_bytes = shared_secret_point.compress().to_bytes();
    println!(
        "Shared secret (8*a*R): {}",
        hex::encode(&shared_secret_bytes)
    );

    // Compute derivation scalar: H_s(shared_secret || varint(output_index))
    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    hasher.update(&encode_varint(OUTPUT_INDEX));
    let derivation_hash: [u8; 32] = hasher.finalize().into();
    let derivation_scalar = Scalar::from_bytes_mod_order(derivation_hash);

    println!("Derivation scalar (d): {}", hex::encode(&derivation_hash));
    println!();
    println!(
        "Formula: d = H_s(8 * a_shared * R || varint({}))",
        OUTPUT_INDEX
    );

    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("STEP 4: Verify Output Public Key Matches Derivation");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // For a standard output: P = H_s(8aR||i)*G + B
    // where B is the spend public key
    // We can't verify this directly without the spend public key,
    // but we can compute d*G and see if P - d*G is a valid point
    let d_g = derivation_scalar * G;
    println!("d * G = {}", hex::encode(d_g.compress().to_bytes()));

    // P - d*G should equal the spend public key B if derivation is correct
    let spend_pub_derived = output_0_p - d_g;
    println!(
        "P - d*G (should be B): {}",
        hex::encode(spend_pub_derived.compress().to_bytes())
    );
    println!();
    println!("This should match the FROST group public key from DKG.");

    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("STEP 5: Key Image Formula (with Derivation)");
    println!("═══════════════════════════════════════════════════════════════════\n");

    println!("For 2-of-3 multisig with FROST and output derivation:");
    println!();
    println!("Full secret key:  x = d + b  (derivation + spend_share)");
    println!("Key Image:        I = x * Hp(P)");
    println!();
    println!("With Lagrange aggregation (buyer+vendor):");
    println!("  x_total = d + λ₁*b₁ + λ₂*b₂");
    println!("  I = (d + λ₁*b₁ + λ₂*b₂) * Hp(P)");
    println!();
    println!("PKI Aggregation (v0.50.0 - simple sum):");
    println!("  PKI_first  = (d + λ₁*b₁) * Hp(P)  (first signer includes derivation)");
    println!("  PKI_second = λ₂*b₂ * Hp(P)        (second signer: spend share only)");
    println!("  I = PKI_first + PKI_second");
    println!("    = (d + λ₁*b₁ + λ₂*b₂) * Hp(P) ✓");

    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("STEP 6: Expected D Point (for mask_delta)");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // For release, pseudo_out_mask is typically 0 or a fresh random value
    // D = (z - pseudo_out_mask) * Hp(P)
    // If pseudo_out_mask = 0, then D = z * Hp(P)
    let d_point_with_z = funding_mask_z * hp_p;
    println!("Funding mask (z):      {}", FUNDING_COMMITMENT_MASK);
    println!(
        "D = z * Hp(P):         {}",
        hex::encode(d_point_with_z.compress().to_bytes())
    );
    println!();
    println!("Note: If pseudo_out_mask ≠ 0, D = (z - pseudo_out_mask) * Hp(P)");

    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("STEP 7: S-Value Aggregation Formula");
    println!("═══════════════════════════════════════════════════════════════════\n");

    println!("First signer (FROST mode, includes derivation):");
    println!("  s₁ = α₁ - c_p*λ₁*(d+b₁) - c_c*λ₁*mask_delta");
    println!();
    println!("Second signer (FROST mode, includes derivation):");
    println!("  s₂ = α₂ - c_p*λ₂*(d+b₂) - c_c*λ₂*mask_delta");
    println!();
    println!("Aggregated (simple sum):");
    println!("  s = s₁ + s₂");
    println!("    = (α₁+α₂) - c_p*(λ₁*(d+b₁) + λ₂*(d+b₂)) - c_c*(λ₁+λ₂)*mask_delta");
    println!("    = α_total - c_p*(d*(λ₁+λ₂) + λ₁*b₁ + λ₂*b₂) - c_c*mask_delta");
    println!("    = α_total - c_p*(d + λ₁*b₁ + λ₂*b₂) - c_c*mask_delta  ✓");
    println!();
    println!("This uses x_total = d + λ₁*b₁ + λ₂*b₂, matching the key image formula!");

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    AUDIT SUMMARY                                 ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    println!("✅ Lagrange coefficients: VERIFIED (λ₁=2, λ₂=-1, sum=1)");
    println!("✅ hash_to_point(P): COMPUTED");
    println!("✅ Derivation scalar: COMPUTED from shared view key");
    println!("✅ D point (mask contribution): COMPUTED");
    println!();
    println!("REFERENCE VALUES FOR TESTING:");
    println!("────────────────────────────────────────────────────────────────────");
    println!(
        "Hp(P):              {}",
        hex::encode(hp_p.compress().to_bytes())
    );
    println!("Derivation (d):     {}", hex::encode(&derivation_hash));
    println!(
        "D = z*Hp(P):        {}",
        hex::encode(d_point_with_z.compress().to_bytes())
    );
    println!(
        "P - d*G (group B):  {}",
        hex::encode(spend_pub_derived.compress().to_bytes())
    );
    println!();
    println!("Use these values to validate WASM/JavaScript signing:");
    println!("1. Verify WASM computes same Hp(P)");
    println!("2. Verify WASM computes same derivation scalar");
    println!("3. Verify first signer PKI = (d + λ*b) * Hp(P)");
    println!("4. Verify second signer PKI = λ*b * Hp(P)");
    println!("5. Verify server aggregates with SIMPLE SUM (v0.50.0 fix)");
}
