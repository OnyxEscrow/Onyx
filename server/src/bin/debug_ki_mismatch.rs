//! Debug key image mismatch between browser PKI aggregation and CLI computation

use anyhow::{bail, Context, Result};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use monero_generators::hash_to_point;
use sha3::{Digest, Keccak256};

fn main() -> Result<()> {
    // Data from DB
    let buyer_share_hex = "eb8f208a08a10da77a2c14cf2a50ddd3f05ec3e18ae3ef9e1a86ff2d935c440c";
    let vendor_share_hex = "203e5b423c98a90f913e339d4532154d49515c519ec6c7a0eeebd943dcfd810a";
    let group_pubkey_hex = "eefa44eed676819ccd740ffd7f82f82b30a4369a6a70b3b45eec1b159432df4d";
    let one_time_pubkey_hex = "0c5c4fcf82b7cb8cd0f91515ab4ce99c7fb482c4aeba321735e570fd39a59bed";
    let funding_tx_pubkey_hex = "257c94d3e9ebf3664fcaeb806f8077ac09c14c030ff652195ebe811fcd814cc5";
    let view_key_hex = "938d10efc3bbaa641575cb5114189428f4e46398e46df1834eb323ef20c8906"; // 63 chars, need padding
    let output_index = 1u64;

    // PKIs from DB
    let buyer_pki_hex = "5512f5c3efeec08218207594ca974b659839f2da6a490d43cb3cbea8c63c7be4";
    let vendor_pki_hex = "0eaf0fc0292ad793bf93e596996033eedff367ff4da0a0d58b0cea4a8288e5ef";
    let aggregated_ki_hex = "3b5c8ae153bc1ce524d308a79f8a75e0de5b4b8fd07637e9625bc6b5e4ebe7a8";

    println!("=== KEY IMAGE MISMATCH DEBUG ===\n");

    // Parse all values
    let b_buyer = hex_to_scalar(buyer_share_hex)?;
    let b_vendor = hex_to_scalar(vendor_share_hex)?;
    let group_pubkey = hex_to_point(group_pubkey_hex)?;
    let one_time_pubkey = hex_to_point(one_time_pubkey_hex)?;
    let tx_pubkey = hex_to_point(funding_tx_pubkey_hex)?;

    // Pad view key to 64 chars if needed
    let view_key_padded = if view_key_hex.len() == 63 {
        format!("0{}", view_key_hex)
    } else {
        view_key_hex.to_string()
    };
    let view_key = hex_to_scalar(&view_key_padded)?;

    // Lagrange coefficients for 2-of-3 (signers 1 and 2)
    let lambda_buyer = compute_lagrange_coefficient(1, 2);
    let lambda_vendor = compute_lagrange_coefficient(2, 1);

    println!(
        "λ_buyer (signer 1) = 2 mod L: {}",
        hex::encode(&lambda_buyer.to_bytes()[..8])
    );
    println!(
        "λ_vendor (signer 2) = -1 mod L: {}",
        hex::encode(&lambda_vendor.to_bytes()[..8])
    );

    // Compute derivation d = H_s(a * R || output_index)
    let d = compute_derivation(&view_key, &tx_pubkey, output_index);
    println!("\nDerivation d: {}...", hex::encode(&d.to_bytes()[..8]));

    // Compute x_total = d + λ_buyer * b_buyer + λ_vendor * b_vendor
    let x_total = d + lambda_buyer * b_buyer + lambda_vendor * b_vendor;
    println!(
        "x_total = d + λ₁*b₁ + λ₂*b₂: {}...",
        hex::encode(&x_total.to_bytes()[..8])
    );

    // Verify P = d*G + B
    let d_g = &d * ED25519_BASEPOINT_TABLE;
    let p_expected = d_g + group_pubkey;
    println!(
        "\nP_expected = d*G + B: {}",
        hex::encode(p_expected.compress().as_bytes())
    );
    println!("P_actual (from DB):   {}", one_time_pubkey_hex);
    println!("P match: {}", p_expected == one_time_pubkey);

    // Verify x_total * G = P
    let p_from_x = &x_total * ED25519_BASEPOINT_TABLE;
    println!(
        "\nx_total * G:          {}",
        hex::encode(p_from_x.compress().as_bytes())
    );
    println!("x_total * G = P: {}", p_from_x == p_expected);

    // Compute Hp(P) using CORRECT one-time pubkey
    let hp_correct = hash_to_point(one_time_pubkey.compress().to_bytes());
    println!(
        "\nHp(P_actual):    {}...",
        hex::encode(&hp_correct.compress().as_bytes()[..8])
    );

    // What if browser used group_pubkey instead?
    let hp_wrong = hash_to_point(group_pubkey.compress().to_bytes());
    println!(
        "Hp(B_group):     {}...",
        hex::encode(&hp_wrong.compress().as_bytes()[..8])
    );

    // CLI computes: KI = x_total * Hp(P)
    let ki_cli = x_total * hp_correct;
    println!("\n=== KEY IMAGES ===");
    println!(
        "CLI computes (x_total * Hp(P)):  {}",
        hex::encode(ki_cli.compress().as_bytes())
    );
    println!("Aggregated from browser (DB):    {}", aggregated_ki_hex);

    // What would happen with wrong Hp?
    let ki_wrong = x_total * hp_wrong;
    println!(
        "If using Hp(B) instead:          {}",
        hex::encode(ki_wrong.compress().as_bytes())
    );

    // Parse browser PKIs and verify aggregation
    let buyer_pki = hex_to_point(buyer_pki_hex)?;
    let vendor_pki = hex_to_point(vendor_pki_hex)?;
    let aggregated_ki = hex_to_point(aggregated_ki_hex)?;

    let sum_pki = buyer_pki + vendor_pki;
    println!("\n=== PKI AGGREGATION ===");
    println!(
        "buyer_pki + vendor_pki:  {}",
        hex::encode(sum_pki.compress().as_bytes())
    );
    println!("aggregated_ki (DB):      {}", aggregated_ki_hex);
    println!("Sum matches aggregated: {}", sum_pki == aggregated_ki);

    // Check what browser computed for each PKI
    // Buyer PKI should be: (d + λ_buyer * b_buyer) * Hp(P)
    let buyer_x = d + lambda_buyer * b_buyer;
    let expected_buyer_pki = buyer_x * hp_correct;
    println!("\n=== EXPECTED PKIs (if using correct Hp(P)) ===");
    println!(
        "Expected buyer_pki  ((d + λ₁*b₁) * Hp(P)): {}",
        hex::encode(expected_buyer_pki.compress().as_bytes())
    );
    println!(
        "Actual buyer_pki (from DB):                {}",
        buyer_pki_hex
    );
    println!("Match: {}", expected_buyer_pki == buyer_pki);

    // Vendor PKI should be: λ_vendor * b_vendor * Hp(P)
    let vendor_x = lambda_vendor * b_vendor;
    let expected_vendor_pki = vendor_x * hp_correct;
    println!(
        "\nExpected vendor_pki (λ₂*b₂ * Hp(P)):       {}",
        hex::encode(expected_vendor_pki.compress().as_bytes())
    );
    println!(
        "Actual vendor_pki (from DB):               {}",
        vendor_pki_hex
    );
    println!("Match: {}", expected_vendor_pki == vendor_pki);

    // Check with wrong Hp (group pubkey)
    let expected_buyer_pki_wrong = buyer_x * hp_wrong;
    let expected_vendor_pki_wrong = vendor_x * hp_wrong;
    println!("\n=== IF BROWSER USED Hp(B_group) INSTEAD ===");
    println!(
        "Expected buyer_pki  ((d + λ₁*b₁) * Hp(B)): {}",
        hex::encode(expected_buyer_pki_wrong.compress().as_bytes())
    );
    println!(
        "Match actual buyer_pki: {}",
        expected_buyer_pki_wrong == buyer_pki
    );
    println!(
        "\nExpected vendor_pki (λ₂*b₂ * Hp(B)):       {}",
        hex::encode(expected_vendor_pki_wrong.compress().as_bytes())
    );
    println!(
        "Match actual vendor_pki: {}",
        expected_vendor_pki_wrong == vendor_pki
    );

    Ok(())
}

fn hex_to_scalar(hex: &str) -> Result<Scalar> {
    let bytes = hex::decode(hex).context("Invalid hex for scalar")?;
    if bytes.len() != 32 {
        bail!("Scalar must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Scalar::from_bytes_mod_order(arr))
}

fn hex_to_point(hex: &str) -> Result<EdwardsPoint> {
    let bytes = hex::decode(hex).context("Invalid hex for point")?;
    if bytes.len() != 32 {
        bail!("Point must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid Edwards point"))
}

fn compute_lagrange_coefficient(i: u64, j: u64) -> Scalar {
    let i_scalar = Scalar::from(i);
    let j_scalar = Scalar::from(j);
    j_scalar * (j_scalar - i_scalar).invert()
}

fn compute_derivation(view_key: &Scalar, tx_pubkey: &EdwardsPoint, output_index: u64) -> Scalar {
    let shared_secret = (view_key * tx_pubkey).mul_by_cofactor();
    let mut hasher = Keccak256::new();
    hasher.update(b"derivation");
    hasher.update(shared_secret.compress().as_bytes());
    hasher.update(output_index.to_le_bytes());
    let hash_result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_result);
    Scalar::from_bytes_mod_order(arr)
}
