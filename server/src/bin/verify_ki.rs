//! Verify Key Image computation for FROST 2-of-3
//! Run: cargo run --release --bin verify_ki

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use monero_generators::hash_to_point;
use sha3::{Digest, Keccak256};

// From test_frost_flow.rs
const TX_SECRET_KEY: &str = "54d48a7b6f680a88fd04b4cf56b18f09e01c66ab3aa5ec9aabb33a258de43704";
const VIEW_KEY_PRIV: &str = "f2fcd78c14a49e707e4a7f4dfc24f5cfbfddfff5f94837bcddd72d88d963e808";
const GROUP_PUBKEY: &str = "8fe544aed04ac3a92dff7d2fb076689b83db5d8eba175bf8853e123b2f0e0fef";
const VENDOR_SHARE: &str = "7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e";
const BUYER_SHARE: &str = "916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b";
const OUTPUT_INDEX: u32 = 1; // FROST test uses index 1
const EXPECTED_TX_PUBKEY: &str = "75ee30c8278cd0da2e081f0dbd22bd8c884d83da2f061c013175fb5612009da9";
const EXPECTED_ONE_TIME_PUBKEY: &str =
    "ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0";

// From last test run
const TX_KEY_IMAGE: &str = "8ffbfb305308f35ac4bba545fc33257fc9d91f031959529a48bb7e8ef81d75ff";

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
    if bytes.len() != 32 {
        panic!("Point hex must be 32 bytes, got {}: {}", bytes.len(), hex);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    curve25519_dalek::edwards::CompressedEdwardsY(arr)
        .decompress()
        .unwrap_or_else(|| panic!("Invalid point: {hex}"))
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

fn compute_derivation(view_key: &Scalar, tx_pubkey: &EdwardsPoint, output_index: u32) -> Scalar {
    // shared_secret = 8 * view_key * R (with cofactor)
    let shared_secret = (view_key * tx_pubkey).mul_by_cofactor();

    // Hash shared_secret || varint(output_index) to derivation scalar
    let mut hasher = Keccak256::new();
    hasher.update(shared_secret.compress().as_bytes());
    hasher.update(encode_varint(output_index as u64));
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

fn main() {
    println!("=== KEY IMAGE VERIFICATION ===\n");

    println!("Checking constants...");
    println!("TX_SECRET_KEY (32 bytes?): {} chars", TX_SECRET_KEY.len());
    println!("VIEW_KEY_PRIV (32 bytes?): {} chars", VIEW_KEY_PRIV.len());
    println!("GROUP_PUBKEY (32 bytes?): {} chars", GROUP_PUBKEY.len());
    println!(
        "EXPECTED_TX_PUBKEY (32 bytes?): {} chars",
        EXPECTED_TX_PUBKEY.len()
    );
    println!(
        "EXPECTED_ONE_TIME_PUBKEY (32 bytes?): {} chars",
        EXPECTED_ONE_TIME_PUBKEY.len()
    );
    println!();

    // Step 1: Compute derivation
    let view_key = hex_to_scalar(VIEW_KEY_PRIV);
    println!("Parsing tx_pubkey: {EXPECTED_TX_PUBKEY}");
    let tx_pubkey = hex_to_point(EXPECTED_TX_PUBKEY);
    println!("Parsed tx_pubkey OK");
    let derivation = compute_derivation(&view_key, &tx_pubkey, OUTPUT_INDEX);
    println!("Derivation (d): {}", hex::encode(derivation.as_bytes()));

    // Step 2: Verify one-time pubkey
    println!("Parsing group_pubkey: {GROUP_PUBKEY}");
    let group_pubkey = hex_to_point(GROUP_PUBKEY);
    println!("Parsed group_pubkey OK");
    let d_point = &derivation * ED25519_BASEPOINT_TABLE;
    let one_time_pubkey = d_point + group_pubkey;
    let one_time_pubkey_hex = hex::encode(one_time_pubkey.compress().as_bytes());
    println!("Computed one-time pubkey: {one_time_pubkey_hex}");
    println!("Expected one-time pubkey: {EXPECTED_ONE_TIME_PUBKEY}");
    println!(
        "Match: {}",
        if one_time_pubkey_hex == EXPECTED_ONE_TIME_PUBKEY {
            "✅"
        } else {
            "❌"
        }
    );
    println!();

    // Step 3: Compute Hp(P) using monero_generators
    let p_bytes = hex_to_bytes(EXPECTED_ONE_TIME_PUBKEY);
    let mut p_arr = [0u8; 32];
    p_arr.copy_from_slice(&p_bytes);
    let hp_p = hash_to_point(p_arr);
    println!("Hp(P): {}", hex::encode(hp_p.compress().as_bytes()));

    // Step 4: Compute x_total = d + λ_vendor*s_vendor + λ_buyer*s_buyer
    // λ_vendor = -1, λ_buyer = 2
    let vendor_share = hex_to_scalar(VENDOR_SHARE);
    let buyer_share = hex_to_scalar(BUYER_SHARE);
    let lambda_vendor = -Scalar::ONE;
    let lambda_buyer = Scalar::from(2u64);

    let x_vendor_weighted = lambda_vendor * vendor_share; // -1 * s_vendor
    let x_buyer_weighted = lambda_buyer * buyer_share; // 2 * s_buyer

    // VENDOR includes derivation, BUYER does not
    let x_eff_vendor = derivation + x_vendor_weighted;
    let x_eff_buyer = x_buyer_weighted;

    let x_total = x_eff_vendor + x_eff_buyer;
    println!(
        "x_total (d + 2*buyer - vendor): {}",
        hex::encode(x_total.as_bytes())
    );

    // Step 5: Compute expected KI = x_total * Hp(P)
    let expected_ki = x_total * hp_p;
    let expected_ki_hex = hex::encode(expected_ki.compress().as_bytes());
    println!("\nExpected Key Image: {expected_ki_hex}");
    println!("TX Key Image:       {TX_KEY_IMAGE}");
    println!(
        "Match: {}",
        if expected_ki_hex == TX_KEY_IMAGE {
            "✅"
        } else {
            "❌"
        }
    );

    // Step 6: Also verify by computing x from the tx_secret_key
    // In Monero, one-time output secret = d + b where b is spend key
    // For multisig: b = b1 + b2 + b3 (but we only have shares)
    let tx_secret = hex_to_scalar(TX_SECRET_KEY);
    println!("\n=== VERIFICATION WITH TX_SECRET_KEY ===");
    println!("tx_secret_key: {TX_SECRET_KEY}");

    // The full output secret should be: x = d + tx_secret_key
    let full_secret = derivation + tx_secret;
    println!(
        "Full secret (d + tx_secret): {}",
        hex::encode(full_secret.as_bytes())
    );

    // Key image from full secret
    let ki_from_full = full_secret * hp_p;
    let ki_from_full_hex = hex::encode(ki_from_full.compress().as_bytes());
    println!("KI from full secret: {ki_from_full_hex}");

    // Compare x_total to full_secret
    println!("\n=== COMPARING RECONSTRUCTED VS FULL SECRET ===");
    println!(
        "x_total (reconstructed):     {}",
        hex::encode(x_total.as_bytes())
    );
    println!(
        "full_secret (d+tx_secret):   {}",
        hex::encode(full_secret.as_bytes())
    );

    if x_total == full_secret {
        println!("Match: ✅ Lagrange reconstruction is CORRECT");
    } else {
        println!("Match: ❌ Lagrange reconstruction is WRONG");
        // Check what the difference is
        let diff = full_secret - x_total;
        println!("Difference: {}", hex::encode(diff.as_bytes()));

        // Check if tx_secret_key = 2*buyer - vendor (should be the reconstructed group secret)
        let reconstructed_group_secret = x_buyer_weighted + x_vendor_weighted;
        println!(
            "\nReconstructed group secret (2*buyer - vendor): {}",
            hex::encode(reconstructed_group_secret.as_bytes())
        );
        println!("TX_SECRET_KEY:                                  {TX_SECRET_KEY}");
        if hex::encode(reconstructed_group_secret.as_bytes()) == TX_SECRET_KEY.to_lowercase() {
            println!("Match: ✅ Group secret reconstruction is CORRECT");
        } else {
            println!("Match: ❌ Group secret reconstruction is WRONG");
        }
    }

    // ========================================================================
    // CRITICAL CHECK: x_total * G should equal P (the one-time pubkey)
    // ========================================================================
    println!("\n=== VERIFYING x_total * G == P ===");
    let x_total_pubkey = &x_total * ED25519_BASEPOINT_TABLE;
    let x_total_pubkey_hex = hex::encode(x_total_pubkey.compress().as_bytes());
    println!("x_total * G:        {x_total_pubkey_hex}");
    println!("Expected P:         {EXPECTED_ONE_TIME_PUBKEY}");

    if x_total_pubkey_hex == EXPECTED_ONE_TIME_PUBKEY.to_lowercase() {
        println!("Match: ✅ Secret correctly opens to one-time pubkey!");
        println!("\nCONCLUSION: The key image is CRYPTOGRAPHICALLY CORRECT.");
        println!("If daemon rejects, the issue is elsewhere (ring, RCT, serialization).");
    } else {
        println!("Match: ❌ SECRET DOES NOT OPEN TO ONE-TIME PUBKEY!");
        println!("\n⚠️ THIS IS THE ROOT CAUSE: Key image verification will fail");
        println!("   because x_total does not correspond to the public key P.");
    }
}
