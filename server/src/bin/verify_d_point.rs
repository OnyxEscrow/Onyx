//! Verify D point computation for FROST 2-of-3 CLSAG
//! Run: cargo run --release --bin verify_d_point

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use monero_generators_mirror::hash_to_point;
use sha3::{Digest, Keccak256};

// From server logs and verify_ki.rs
const SIGNER_PUBKEY: &str = "ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0";
const D_INV8_IN_TX: &str = "1d6a4b5f7433965a4f583ba627d99ad2dcc314d71da894688552495896c30894";

// From server logs (first 8 bytes shown, need full 32)
// pseudo_out_mask (commitment_mask): 9a8fa101e9dad0bc... (first 8 bytes)
// funding_mask (z): c254d7f8dc4ccfbc... (first 8 bytes)
// mask_delta: 15992b540ed51058... (first 8 bytes)

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("Invalid hex")
}

fn hex_to_scalar(hex: &str) -> Scalar {
    let bytes = hex_to_bytes(hex);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Scalar::from_bytes_mod_order(arr)
}

fn hex_to_point(hex: &str) -> EdwardsPoint {
    let bytes = hex_to_bytes(hex);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .unwrap_or_else(|| panic!("Invalid point: {}", hex))
}

fn main() {
    println!("=== D POINT VERIFICATION ===\n");

    // Parse signer pubkey
    let signer_pubkey_bytes: [u8; 32] = {
        let bytes = hex_to_bytes(SIGNER_PUBKEY);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };

    println!("Signer pubkey (P): {}", SIGNER_PUBKEY);

    // Compute Hp(P) using monero's hash_to_point
    let hp_signer = hash_to_point(signer_pubkey_bytes);
    println!("Hp(P): {}", hex::encode(hp_signer.compress().as_bytes()));

    // Parse D_inv8 from TX
    let d_inv8_tx = hex_to_point(D_INV8_IN_TX);
    println!("\nD_inv8 in TX: {}", D_INV8_IN_TX);

    // Compute D from D_inv8: D = D_inv8 * 8
    let eight = Scalar::from(8u64);
    let d_computed = d_inv8_tx * eight;
    println!("D computed (D_inv8 * 8): {}", hex::encode(d_computed.compress().as_bytes()));

    // Now we need to find mask_delta such that D = mask_delta * Hp(P)
    // We can verify this by checking if D / Hp(P) gives a valid scalar

    // Try to extract mask_delta from the known values
    // We have: funding_mask (z) and pseudo_out_mask, and mask_delta = z - pseudo_out_mask

    // Let's try some known mask values from the escrow
    println!("\n=== TESTING WITH KNOWN MASK VALUES ===");

    // The server logs show partial hex values. Let me try to construct full scalars.
    // From test_frost_flow.rs, we have the funding output commitment mask

    // Actually, let me try a different approach:
    // If D = mask_delta * Hp(P), and we know D and Hp(P),
    // we can verify by computing D / Hp(P) and checking if the result is the mask_delta

    // For verification, let's check if D is on the curve correctly
    println!("\n=== D POINT ANALYSIS ===");
    println!("D_inv8 * 8 = D = {}", hex::encode(d_computed.compress().as_bytes()));

    // Verify D_inv8 * 8 * inv8 = D_inv8
    let inv8 = Scalar::from(8u64).invert();
    let d_inv8_verify = d_computed * inv8;
    println!("D * inv8 = {}", hex::encode(d_inv8_verify.compress().as_bytes()));
    println!("Matches D_inv8 in TX: {}",
        if hex::encode(d_inv8_verify.compress().as_bytes()) == D_INV8_IN_TX { "✅" } else { "❌" });

    // Now let's try to verify with actual mask values from the database
    // We need to get the full 32-byte mask values

    println!("\n=== MASK VALUE INVESTIGATION ===");
    println!("From server logs (partial values):");
    println!("  pseudo_out_mask: 9a8fa101e9dad0bc... (need full 32 bytes)");
    println!("  funding_mask:    c254d7f8dc4ccfbc... (need full 32 bytes)");
    println!("  mask_delta:      15992b540ed51058... (need full 32 bytes)");

    // To get full mask values, we need to read them from:
    // 1. The escrow's frost_dkg_sessions table (funding_mask_hex column)
    // 2. Or compute from the commitment derivation

    println!("\n=== CHECKING D COMPUTATION MATH ===");
    println!("D = mask_delta * Hp(P)");
    println!("D_inv8 = D / 8 = mask_delta * Hp(P) / 8");
    println!("");
    println!("If mask_delta is WRONG, then D is WRONG, and:");
    println!("  - mu_p and mu_c computed by verifier use WRONG D_inv8");
    println!("  - OR the signature's s_π was computed with DIFFERENT mask_delta");
    println!("  - Either way, verification fails");

    // Let me also compute what mu values should be
    println!("\n=== CHECKING IF D IS IDENTITY ===");
    let identity_bytes = [
        1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let d_bytes = d_computed.compress().to_bytes();
    let d_inv8_bytes = d_inv8_tx.compress().to_bytes();

    println!("D is identity: {}", if d_bytes == identity_bytes { "YES ⚠️" } else { "NO ✅" });
    println!("D_inv8 is identity: {}", if d_inv8_bytes == identity_bytes { "YES ⚠️" } else { "NO ✅" });

    // Check if D_inv8 * 8 = 0 (which would indicate mask_delta = 0)
    let zero_point = EdwardsPoint::default();
    println!("D is zero point: {}", if d_computed == zero_point { "YES ⚠️" } else { "NO ✅" });

    // Now let's try to compute what D SHOULD be with different mask_delta values
    println!("\n=== COMPUTING D WITH TEST MASK VALUES ===");

    // If mask_delta = 0, D should be identity
    let mask_zero = Scalar::ZERO;
    let d_from_zero = hp_signer * mask_zero;
    println!("D with mask_delta=0: {}", hex::encode(d_from_zero.compress().as_bytes()));

    // If mask_delta = 1, D should be Hp(P)
    let mask_one = Scalar::ONE;
    let d_from_one = hp_signer * mask_one;
    println!("D with mask_delta=1: {}...", &hex::encode(d_from_one.compress().as_bytes())[..32]);

    // Try to reverse-engineer the mask_delta from D
    // This is discrete log problem - we can't solve it directly
    // But we can check if D/Hp(P) works as expected

    println!("\n=== SUMMARY ===");
    println!("The D_inv8 in TX is: {}", D_INV8_IN_TX);
    println!("This corresponds to D = {}", hex::encode(d_computed.compress().as_bytes()));
    println!("");
    println!("For CLSAG verification to pass:");
    println!("1. D_inv8 must be correctly computed: D_inv8 = mask_delta * Hp(P) / 8");
    println!("2. mask_delta must be: z - pseudo_out_mask");
    println!("3. pseudo_out must be: pseudo_out_mask * G + amount * H");
    println!("");
    println!("To verify D is correct, we need the full 32-byte mask values.");
    println!("Run: cargo run --bin read_escrow to extract them from the database.");
}
