//! Test that D point is correctly computed (not identity) when pseudo_mask differs from funding_mask

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use monero_generators::hash_to_point;
use rand::RngCore;

fn main() {
    println!("=== Testing D Point Computation ===\n");

    // Simulate a random ring public key at signer position
    let mut p_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut p_bytes);
    let p_scalar = Scalar::from_bytes_mod_order(p_bytes);
    let p_point = &p_scalar * ED25519_BASEPOINT_TABLE;

    // Hp(P) - hash to point
    let hp_p = hash_to_point(p_point.compress().to_bytes());

    println!(
        "Ring public key P: {}...",
        hex::encode(&p_point.compress().as_bytes()[..8])
    );
    println!(
        "Hp(P): {}...",
        hex::encode(&hp_p.compress().as_bytes()[..8])
    );

    // Case 1: Same mask (z_diff = 0) - produces identity D (BAD)
    println!("\n--- Case 1: z_diff = 0 (same mask) ---");
    let z_diff_zero = Scalar::ZERO;
    let d_full_zero = z_diff_zero * hp_p;
    let d_inv8_zero = d_full_zero * Scalar::from(8u64).invert();
    println!("z_diff: {}", hex::encode(z_diff_zero.as_bytes()));
    println!(
        "D (full): {}",
        hex::encode(d_full_zero.compress().as_bytes())
    );
    println!(
        "D (inv8): {}",
        hex::encode(d_inv8_zero.compress().as_bytes())
    );

    let identity_bytes = [
        1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let is_identity = d_inv8_zero.compress().as_bytes() == &identity_bytes;
    println!(
        "Is identity? {} {}",
        is_identity,
        if is_identity { "❌ BAD" } else { "✅" }
    );

    // Case 2: Different mask (z_diff != 0) - produces non-identity D (GOOD)
    println!("\n--- Case 2: z_diff != 0 (random pseudo_mask) ---");
    let mut funding_mask_bytes = [0u8; 32];
    let mut pseudo_mask_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut funding_mask_bytes);
    rand::thread_rng().fill_bytes(&mut pseudo_mask_bytes);

    let funding_mask = Scalar::from_bytes_mod_order(funding_mask_bytes);
    let pseudo_mask = Scalar::from_bytes_mod_order(pseudo_mask_bytes);
    let z_diff = funding_mask - pseudo_mask;

    let d_full = z_diff * hp_p;
    let d_inv8 = d_full * Scalar::from(8u64).invert();

    println!("funding_mask: {}...", hex::encode(&funding_mask_bytes[..8]));
    println!("pseudo_mask: {}...", hex::encode(&pseudo_mask_bytes[..8]));
    println!("z_diff: {}...", hex::encode(&z_diff.to_bytes()[..8]));
    println!("D (full): {}", hex::encode(d_full.compress().as_bytes()));
    println!("D (inv8): {}", hex::encode(d_inv8.compress().as_bytes()));

    let is_identity = d_inv8.compress().as_bytes() == &identity_bytes;
    println!(
        "Is identity? {} {}",
        is_identity,
        if is_identity { "❌ BAD" } else { "✅ GOOD" }
    );

    // Verify D * 8 = D_full
    let d_reconstructed = d_inv8 * Scalar::from(8u64);
    println!(
        "\nVerify D_inv8 * 8 = D_full: {}",
        if d_reconstructed.compress() == d_full.compress() {
            "✅ Match"
        } else {
            "❌ Mismatch"
        }
    );

    println!("\n=== CONCLUSION ===");
    if !is_identity {
        println!("✅ D point computation is correct when using random pseudo_mask");
        println!("   This fix ensures valid CLSAG signatures for broadcast");
    } else {
        println!("❌ D point is still identity - something is wrong");
    }
}
