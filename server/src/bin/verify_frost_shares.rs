#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case
)]
//! Verify FROST share reconstruction
//!
//! Validates that λ_buyer * buyer_share + λ_vendor * vendor_share = group_secret
//! and group_secret * G = group_pubkey

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

fn main() {
    println!("=== FROST Share Verification ===\n");

    // Known values from escrow ef57f177-f873-40c3-a175-4ab87c195ad8
    let vendor_share_hex = "7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e";
    let buyer_share_hex = "916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b";
    let group_pubkey_hex = "8fe544aed04ac3a92dff7d2fb076689b83db5d8eba175bf8853e123b2f0e0fef";

    // Parse shares
    let vendor_bytes = hex::decode(vendor_share_hex).expect("vendor hex");
    let buyer_bytes = hex::decode(buyer_share_hex).expect("buyer hex");
    let group_pubkey_bytes = hex::decode(group_pubkey_hex).expect("group_pubkey hex");

    let vendor_share =
        Scalar::from_canonical_bytes(vendor_bytes.try_into().unwrap()).expect("vendor scalar");
    let buyer_share =
        Scalar::from_canonical_bytes(buyer_bytes.try_into().unwrap()).expect("buyer scalar");

    println!("Vendor share: {vendor_share_hex}");
    println!("Buyer share:  {buyer_share_hex}");
    println!("Group pubkey: {group_pubkey_hex}");

    // Lagrange coefficients for buyer(1) + vendor(2):
    // λ_buyer = 2/(2-1) = 2
    // λ_vendor = 1/(1-2) = -1
    let lambda_buyer = Scalar::from(2u64);
    let lambda_vendor = -Scalar::ONE; // -1 mod L

    println!("\nLagrange coefficients:");
    println!("  λ_buyer = 2");
    println!("  λ_vendor = -1 (mod L)");
    println!("  λ_vendor hex: {}", hex::encode(lambda_vendor.as_bytes()));

    // Reconstruct group secret
    let buyer_contrib = lambda_buyer * buyer_share;
    let vendor_contrib = lambda_vendor * vendor_share;
    let group_secret = buyer_contrib + vendor_contrib;

    println!("\nReconstruction:");
    println!(
        "  λ_buyer * buyer_share   = {}",
        hex::encode(buyer_contrib.as_bytes())
    );
    println!(
        "  λ_vendor * vendor_share = {}",
        hex::encode(vendor_contrib.as_bytes())
    );
    println!(
        "  group_secret (sum)      = {}",
        hex::encode(group_secret.as_bytes())
    );

    // Compute group_secret * G
    let computed_pubkey = &group_secret * ED25519_BASEPOINT_TABLE;
    let computed_pubkey_compressed = computed_pubkey.compress();
    let computed_pubkey_hex = hex::encode(computed_pubkey_compressed.as_bytes());

    println!("\nVerification:");
    println!("  group_secret * G = {computed_pubkey_hex}");
    println!("  Expected pubkey  = {group_pubkey_hex}");

    if computed_pubkey_hex == group_pubkey_hex {
        println!("\n✅ VERIFICATION PASSED: Lagrange reconstruction is correct!");
        println!("   The FROST shares will correctly reconstruct the group secret.");
    } else {
        println!("\n❌ VERIFICATION FAILED: group_secret * G != group_pubkey");
        println!("   The shares do NOT correctly reconstruct the group secret!");
    }
}
