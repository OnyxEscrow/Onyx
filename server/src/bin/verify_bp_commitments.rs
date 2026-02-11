//! Verify that BP+ commitments match what we serialize in outPk
//!
//! This checks if the commitments computed by monero-bulletproofs-mirror
//! match our compute_pedersen_commitment function

use anyhow::Result;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use monero_generators::H;
use monero_primitives_mirror::Commitment;

/// Our H_BYTES constant (same as in transaction_builder.rs)
const H_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// Compute commitment point from Commitment struct (same as BP+ internal)
fn commitment_to_point(c: &Commitment) -> EdwardsPoint {
    &c.mask * ED25519_BASEPOINT_TABLE + Scalar::from(c.amount) * *H
}

fn main() -> Result<()> {
    println!("=== Bulletproof+ Commitment Verification ===\n");

    // Test values
    let mask = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08,
    ];
    let amount: u64 = 1_000_000_000_000; // 1 XMR

    println!("Test mask: {}", hex::encode(mask));
    println!(
        "Test amount: {} piconero ({:.12} XMR)\n",
        amount,
        amount as f64 / 1e12
    );

    // Method 1: Our compute_pedersen_commitment
    println!("=== Method 1: Our compute_pedersen_commitment ===");
    let h_point = CompressedEdwardsY(H_BYTES)
        .decompress()
        .expect("Invalid H point");
    let mask_scalar = Scalar::from_bytes_mod_order(mask);
    let mask_g = &mask_scalar * ED25519_BASEPOINT_TABLE;
    let amount_scalar = Scalar::from(amount);
    let amount_h = amount_scalar * h_point;
    let commitment_ours = mask_g + amount_h;
    let commitment_ours_bytes = commitment_ours.compress().to_bytes();
    println!("Commitment (ours): {}", hex::encode(commitment_ours_bytes));

    // Method 2: monero-generators H
    println!("\n=== Method 2: monero-generators H ===");
    let h_from_lib: &EdwardsPoint = &H; // Dereference LazyLock
    let mask_scalar = Scalar::from_bytes_mod_order(mask);
    let mask_g = &mask_scalar * ED25519_BASEPOINT_TABLE;
    let amount_scalar = Scalar::from(amount);
    let amount_h = amount_scalar * h_from_lib;
    let commitment_lib = mask_g + amount_h;
    let commitment_lib_bytes = commitment_lib.compress().to_bytes();
    println!("Commitment (lib H): {}", hex::encode(commitment_lib_bytes));

    // Method 3: monero-primitives-mirror Commitment struct
    println!("\n=== Method 3: monero-primitives-mirror Commitment ===");
    let commitment_struct = Commitment {
        mask: Scalar::from_bytes_mod_order(mask),
        amount,
    };
    let commitment_from_struct = commitment_to_point(&commitment_struct);
    let commitment_struct_bytes = commitment_from_struct.compress().to_bytes();
    println!(
        "Commitment (struct): {}",
        hex::encode(commitment_struct_bytes)
    );

    // Compare H points first
    println!("\n=== H Generator Comparison ===");
    let h_ours_bytes = H_BYTES;
    let h_lib_bytes = h_from_lib.compress().to_bytes();
    println!("H (ours):          {}", hex::encode(h_ours_bytes));
    println!("H (generators lib): {}", hex::encode(h_lib_bytes));

    if h_ours_bytes == h_lib_bytes {
        println!("✅ H generators MATCH");
    } else {
        println!("❌ H generators DON'T MATCH - this is the bug!");
    }

    // Compare commitments
    println!("\n=== Commitment Comparison ===");
    if commitment_ours_bytes == commitment_lib_bytes
        && commitment_ours_bytes == commitment_struct_bytes
    {
        println!("✅ All commitments MATCH");
    } else {
        println!("❌ Commitments DON'T MATCH!");
        println!("  Ours:   {}", hex::encode(commitment_ours_bytes));
        println!("  Lib:    {}", hex::encode(commitment_lib_bytes));
        println!("  Struct: {}", hex::encode(commitment_struct_bytes));
    }

    // Now let's check what BP+ actually generates for its proof
    println!("\n=== Bulletproof+ Proof Test ===");
    use monero_bulletproofs_mirror::Bulletproof;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let commitments = vec![commitment_struct];

    match Bulletproof::prove_plus(&mut rng, commitments) {
        Ok(bp) => {
            println!("✅ Bulletproof+ generated successfully");

            // Verify the proof using EdwardsPoint commitments
            let verification_commitment = commitment_to_point(&Commitment {
                mask: Scalar::from_bytes_mod_order(mask),
                amount,
            });

            if bp.verify(&mut rng, &[verification_commitment]) {
                println!("✅ Bulletproof+ verification PASSED");
            } else {
                println!("❌ Bulletproof+ verification FAILED");
            }
        }
        Err(e) => {
            println!("❌ Bulletproof+ generation failed: {e:?}");
        }
    }

    // Test with 2 outputs (like our transaction)
    println!("\n=== Two-Output Test (Real + Dummy) ===");
    let output_0_amount: u64 = 999956000000; // ~0.999956 XMR (input - fee)
    let output_1_amount: u64 = 0; // 0 XMR dummy

    // Use funding_mask-like scenario
    let funding_mask_bytes: [u8; 32] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x00,
    ];
    let mask_0_bytes: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00,
    ];

    let funding_mask = Scalar::from_bytes_mod_order(funding_mask_bytes);
    let mask_0 = Scalar::from_bytes_mod_order(mask_0_bytes);
    let mask_1 = funding_mask - mask_0; // Balance: funding_mask = mask_0 + mask_1

    println!("mask_0: {}...", hex::encode(&mask_0.to_bytes()[..8]));
    println!("mask_1: {}...", hex::encode(&mask_1.to_bytes()[..8]));

    // Compute commitments using monero-generators H
    let commitment_0 =
        &mask_0 * ED25519_BASEPOINT_TABLE + Scalar::from(output_0_amount) * h_from_lib;
    let commitment_1 =
        &mask_1 * ED25519_BASEPOINT_TABLE + Scalar::from(output_1_amount) * h_from_lib;

    println!(
        "commitment_0: {}",
        hex::encode(commitment_0.compress().to_bytes())
    );
    println!(
        "commitment_1: {}",
        hex::encode(commitment_1.compress().to_bytes())
    );

    // Generate BP+ for both outputs
    let commitments_2out = vec![
        Commitment {
            mask: mask_0,
            amount: output_0_amount,
        },
        Commitment {
            mask: mask_1,
            amount: output_1_amount,
        },
    ];

    match Bulletproof::prove_plus(&mut rng, commitments_2out.clone()) {
        Ok(bp) => {
            println!("✅ Two-output Bulletproof+ generated");

            // Verify using EdwardsPoint commitments
            let verify_points: Vec<EdwardsPoint> =
                commitments_2out.iter().map(commitment_to_point).collect();

            if bp.verify(&mut rng, &verify_points) {
                println!("✅ Two-output Bulletproof+ verification PASSED");
            } else {
                println!("❌ Two-output Bulletproof+ verification FAILED");
            }
        }
        Err(e) => {
            println!("❌ Two-output Bulletproof+ generation failed: {e:?}");
        }
    }

    // Verify commitment balance
    println!("\n=== Commitment Balance Verification ===");
    let fee: u64 = 44000000;
    let input_amount = output_0_amount + fee;

    let input_commitment =
        &funding_mask * ED25519_BASEPOINT_TABLE + Scalar::from(input_amount) * h_from_lib;
    let sum_outputs = commitment_0 + commitment_1;
    let fee_commitment = Scalar::from(fee) * h_from_lib;
    let expected_input = sum_outputs + fee_commitment;

    println!(
        "input_commitment:  {}",
        hex::encode(input_commitment.compress().to_bytes())
    );
    println!(
        "sum_outputs + fee: {}",
        hex::encode(expected_input.compress().to_bytes())
    );

    if input_commitment.compress() == expected_input.compress() {
        println!("✅ Commitment balance VERIFIED");
    } else {
        println!("❌ Commitment balance FAILED");
    }

    Ok(())
}
