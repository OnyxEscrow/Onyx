//! Verify hash_to_point matches Monero's implementation
//! Test vector: Hp(G) where G is the basepoint

use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
use curve25519_dalek::edwards::CompressedEdwardsY;
use monero_generators_mirror::hash_to_point;

fn main() {
    println!("=== Verifying hash_to_point (Hp) Implementation ===\n");

    // Test 1: Hp(G) - hash of basepoint
    let g_bytes = ED25519_BASEPOINT_COMPRESSED.to_bytes();
    println!("G (basepoint compressed): {}", hex::encode(&g_bytes));

    let hp_g = hash_to_point(g_bytes);
    println!(
        "Hp(G) from our impl:      {}",
        hex::encode(hp_g.compress().to_bytes())
    );

    // Monero's expected Hp(G) - from monero-project test vectors
    // This is 8*hash_to_ec(G)
    // Reference: monero/tests/crypto/main.cpp
    println!("\n--- Known Monero Test Vectors ---");

    // Test with a specific public key from our TX
    // Ring member at index 15 (real input position)
    let ring_key_hex = "17fc398f8ff41d5f80fd4abb5e5702e6c97ec8b8e75b2d79cdcce1a17bcdc9c8";
    let ring_key_bytes = hex::decode(ring_key_hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&ring_key_bytes);

    println!("\nRing key P[15]: {}", ring_key_hex);
    let hp_ring = hash_to_point(arr);
    println!(
        "Hp(P[15]):      {}",
        hex::encode(hp_ring.compress().to_bytes())
    );

    // The key image should be I = x * Hp(P)
    // For multisig: I = (lambda1*x1 + lambda2*x2) * Hp(P_multisig)

    // Let's also test with identity and zero
    println!("\n--- Additional Test Points ---");

    // All zeros
    let zeros = [0u8; 32];
    let hp_zeros = hash_to_point(zeros);
    println!(
        "Hp([0;32]):     {}",
        hex::encode(hp_zeros.compress().to_bytes())
    );

    // Test with our multisig public key from escrow
    let multisig_key_hex = "17fc398f8ff41d5f80fd4abb5e5702e6c97ec8b8e75b2d79cdcce1a17bcdc9c8";
    // This is P[15] - the real output we're spending

    // Now let's verify with monerod's get_output_distribution or get_outs
    println!("\n--- Fetch actual ring key from daemon ---");
}
