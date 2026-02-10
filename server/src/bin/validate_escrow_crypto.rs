//! Complete cryptographic validation for escrow #ef57f177
//!
//! Tests EVERY step of the signing flow with known values.
//!
//! Usage: cargo run --release --bin validate_escrow_crypto

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

// ============================================================================
// KNOWN VALUES FROM ESCROW #ef57f177-f873-40c3-a175-4ab87c195ad8
// ============================================================================

const ESCROW_ID: &str = "ef57f177-f873-40c3-a175-4ab87c195ad8";

// Transaction data
const TX_ID: &str = "2cfe655d56c881908a883a8bb8f0f85bc09310cf7f43816bc2fd3801088ba665";
// NOTE: This is the TX PRIVATE KEY (r), not the public key R!
// R = r * G must be computed
const TX_SECRET_KEY: &str = "54d48a7b6f680a88fd04b4cf56b18f09e01c66ab3aa5ec9aabb33a258de43704";

// FROST keys
const GROUP_PUBKEY: &str = "8fe544aed04ac3a92dff7d2fb076689b83db5d8eba175bf8853e123b2f0e0fef";
const VIEW_KEY_PRIV: &str = "f2fcd78c14a49e707e4a7f4dfc24f5cfbfddfff5f94837bcddd72d88d963e808";
const VENDOR_SHARE: &str = "7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e";
const BUYER_SHARE: &str = "916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b";

// Escrow address (destination of funding TX)
const ESCROW_ADDRESS: &str = "57HRDdV2XrAVJFnChTRsbDT1h5Lv2fxpSiZxgGhxKCP8h1gGfrS6YJvgeGpLixGsruAZphkpZc5mPNHh94w1QVRxTjRZ4tu";

// Output index - FROM DB: funding_output_index = 1
const OUTPUT_INDEX: u64 = 1;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn hex_to_bytes(h: &str) -> Vec<u8> {
    hex::decode(h).expect("Invalid hex")
}

fn hex_to_scalar(h: &str) -> Scalar {
    let bytes = hex_to_bytes(h);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Scalar::from_bytes_mod_order(arr)
}

fn hex_to_point(h: &str) -> EdwardsPoint {
    let bytes = hex_to_bytes(h);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .expect("Invalid Edwards point")
}

/// Encode a u64 as a varint (Monero-style)
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

/// Hash to point (Monero's hash_to_ec)
fn hash_to_point(data: [u8; 32]) -> EdwardsPoint {
    let mut counter = 0u8;
    loop {
        let mut hasher = Keccak256::new();
        hasher.update(&data);
        hasher.update(&[counter]);
        let hash: [u8; 32] = hasher.finalize().into();

        // Try to decompress as Edwards point
        if let Some(point) = CompressedEdwardsY(hash).decompress() {
            // Multiply by cofactor to get point in prime-order subgroup
            return point.mul_by_cofactor();
        }
        counter += 1;
        if counter > 255 {
            panic!("hash_to_point failed after 256 attempts");
        }
    }
}

fn main() {
    println!("=== ESCROW #{} CRYPTOGRAPHIC VALIDATION ===\n", &ESCROW_ID[..8]);

    // ========================================================================
    // STEP 1: Verify Lagrange reconstruction (already verified, but confirm)
    // ========================================================================
    println!("STEP 1: Lagrange Reconstruction");
    println!("--------------------------------");

    let vendor_share = hex_to_scalar(VENDOR_SHARE);
    let buyer_share = hex_to_scalar(BUYER_SHARE);
    let group_pubkey = hex_to_point(GROUP_PUBKEY);

    // Lagrange coefficients for buyer(1) + vendor(2)
    let lambda_buyer = Scalar::from(2u64);
    let lambda_vendor = -Scalar::ONE;

    let group_secret = lambda_buyer * buyer_share + lambda_vendor * vendor_share;
    let computed_pubkey = &group_secret * ED25519_BASEPOINT_TABLE;

    println!("  group_secret = {}", hex::encode(group_secret.as_bytes()));
    println!("  computed_pubkey = {}", hex::encode(computed_pubkey.compress().as_bytes()));
    println!("  expected_pubkey = {}", GROUP_PUBKEY);

    if computed_pubkey.compress().as_bytes() == &hex_to_bytes(GROUP_PUBKEY)[..] {
        println!("  ✅ Lagrange reconstruction CORRECT\n");
    } else {
        println!("  ❌ Lagrange reconstruction FAILED!\n");
        return;
    }

    // ========================================================================
    // STEP 2: Compute derivation scalar (d = H_s(8 * a * R || varint(idx)))
    // ========================================================================
    println!("STEP 2: Derivation Scalar");
    println!("-------------------------");

    let view_key = hex_to_scalar(VIEW_KEY_PRIV);

    // TX_SECRET_KEY is the private key r, we need R = r * G
    let tx_secret_key = hex_to_scalar(TX_SECRET_KEY);
    let tx_pub_key = &tx_secret_key * ED25519_BASEPOINT_TABLE;
    let tx_pub_key_hex = hex::encode(tx_pub_key.compress().as_bytes());
    println!("  tx_secret_key (r) = {}", TX_SECRET_KEY);
    println!("  tx_pub_key (R = r*G) = {}", tx_pub_key_hex);

    // Compute shared secret: 8 * a * R (with cofactor)
    let shared_secret = (view_key * tx_pub_key).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    println!("  view_key = {}...", &VIEW_KEY_PRIV[..16]);
    println!("  shared_secret (8*a*R) = {}", hex::encode(&shared_secret_bytes));

    // Hash to derivation scalar
    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    hasher.update(&encode_varint(OUTPUT_INDEX));
    let derivation_hash: [u8; 32] = hasher.finalize().into();
    let derivation = Scalar::from_bytes_mod_order(derivation_hash);

    println!("  output_index = {} (varint: {:02x?})", OUTPUT_INDEX, encode_varint(OUTPUT_INDEX));
    println!("  derivation (d) = {}", hex::encode(derivation.as_bytes()));

    // ========================================================================
    // STEP 3: Compute one-time output public key P = d*G + B
    // ========================================================================
    println!("\nSTEP 3: One-Time Output Public Key (P)");
    println!("---------------------------------------");

    // P = d*G + B where B = group_pubkey (spend public key)
    let d_point = &derivation * ED25519_BASEPOINT_TABLE;
    let one_time_pubkey = d_point + group_pubkey;
    let one_time_pubkey_hex = hex::encode(one_time_pubkey.compress().as_bytes());

    println!("  d*G = {}", hex::encode(d_point.compress().as_bytes()));
    println!("  B (group_pubkey) = {}", GROUP_PUBKEY);
    println!("  P = d*G + B = {}", one_time_pubkey_hex);
    println!("  (This is the one_time_pubkey that should be used for signing)");

    // ========================================================================
    // STEP 4: Compute Hp(P) - hash to point
    // ========================================================================
    println!("\nSTEP 4: Hash-to-Point Hp(P)");
    println!("---------------------------");

    let hp = hash_to_point(one_time_pubkey.compress().to_bytes());
    println!("  Hp(P) = {}", hex::encode(hp.compress().as_bytes()));

    // ========================================================================
    // STEP 5: Compute full output secret x = d + group_secret
    // ========================================================================
    println!("\nSTEP 5: Full Output Secret");
    println!("--------------------------");

    let output_secret = derivation + group_secret;
    println!("  x = d + group_secret = {}", hex::encode(output_secret.as_bytes()));

    // Verify: x * G should equal P
    let x_times_g = &output_secret * ED25519_BASEPOINT_TABLE;
    if x_times_g == one_time_pubkey {
        println!("  ✅ Verification: x * G = P (CORRECT)");
    } else {
        println!("  ❌ Verification FAILED: x * G ≠ P");
        println!("     x * G = {}", hex::encode(x_times_g.compress().as_bytes()));
    }

    // ========================================================================
    // STEP 6: Compute correct Key Image KI = x * Hp(P)
    // ========================================================================
    println!("\nSTEP 6: Key Image");
    println!("-----------------");

    let key_image = output_secret * hp;
    let key_image_hex = hex::encode(key_image.compress().as_bytes());
    println!("  KI = x * Hp(P) = {}", key_image_hex);

    // ========================================================================
    // STEP 7: Compute PKIs with Lagrange (as WASM should compute them)
    // ========================================================================
    println!("\nSTEP 7: Partial Key Images (PKI)");
    println!("--------------------------------");

    // For FROST with buyer+vendor:
    // First signer (vendor): PKI_v = (d + λ_v * s_v) * Hp(P)
    // Second signer (buyer): PKI_b = (λ_b * s_b) * Hp(P)

    let weighted_vendor = lambda_vendor * vendor_share;
    let weighted_buyer = lambda_buyer * buyer_share;

    println!("  λ_vendor * s_vendor = {}", hex::encode(weighted_vendor.as_bytes()));
    println!("  λ_buyer * s_buyer = {}", hex::encode(weighted_buyer.as_bytes()));

    // First signer includes derivation
    let x_eff_first = derivation + weighted_vendor;
    let pki_first = x_eff_first * hp;

    // Second signer does NOT include derivation
    let x_eff_second = weighted_buyer;
    let pki_second = x_eff_second * hp;

    println!("\n  First signer (vendor with derivation):");
    println!("    x_eff = d + λ_v*s_v = {}", hex::encode(x_eff_first.as_bytes()));
    println!("    PKI_first = {}", hex::encode(pki_first.compress().as_bytes()));

    println!("\n  Second signer (buyer without derivation):");
    println!("    x_eff = λ_b*s_b = {}", hex::encode(x_eff_second.as_bytes()));
    println!("    PKI_second = {}", hex::encode(pki_second.compress().as_bytes()));

    // ========================================================================
    // STEP 8: Verify aggregation
    // ========================================================================
    println!("\nSTEP 8: PKI Aggregation");
    println!("-----------------------");

    let aggregated_ki = pki_first + pki_second;
    let aggregated_hex = hex::encode(aggregated_ki.compress().as_bytes());

    println!("  KI_agg = PKI_first + PKI_second = {}", aggregated_hex);
    println!("  Expected KI = {}", key_image_hex);

    if aggregated_ki == key_image {
        println!("\n  ✅ AGGREGATION CORRECT: KI_agg = KI");
    } else {
        println!("\n  ❌ AGGREGATION MISMATCH!");
        println!("     This means the PKI computation has a bug.");
    }

    // ========================================================================
    // SUMMARY
    // ========================================================================
    println!("\n========================================");
    println!("SUMMARY - VALUES TO USE FOR SIGNING");
    println!("========================================");
    println!("escrow_id:       {}", ESCROW_ID);
    println!("one_time_pubkey: {}", one_time_pubkey_hex);
    println!("key_image:       {}", key_image_hex);
    println!("derivation:      {}", hex::encode(derivation.as_bytes()));
    println!("group_secret:    {}", hex::encode(group_secret.as_bytes()));
    println!("output_secret:   {}", hex::encode(output_secret.as_bytes()));
    println!("\nPKI values (for server verification):");
    println!("  PKI_vendor (first):  {}", hex::encode(pki_first.compress().as_bytes()));
    println!("  PKI_buyer (second):  {}", hex::encode(pki_second.compress().as_bytes()));

    // ========================================================================
    // STEP 9: Compare with DB values
    // ========================================================================
    println!("\n========================================");
    println!("COMPARISON WITH DATABASE VALUES");
    println!("========================================");

    // Values from read_escrow output
    const DB_BUYER_PKI: &str = "41ec4f7f9c9e5c995e80d387ea785c04a6a1c97ecf4b3d9fb725d513b5512a36";
    const DB_VENDOR_PKI: &str = "bf9e270c02dc7ca3dca6409924f62fac8fea0dc68dc42d484decf90303648a92";
    const DB_AGGREGATED_KI: &str = "3d7828c8b4aec911a19ecd916894d95a56cfc9ee14705be7d6cba7154cc4c733";
    const DB_TX_PUBKEY: &str = "75ee30c8278cd0da2e081f0dbd22bd8c884d83da2f061c013175fb5612009da9";

    println!("\n  TX Public Key (R):");
    println!("    Expected:  {}", tx_pub_key_hex);
    println!("    DB:        {}", DB_TX_PUBKEY);
    if tx_pub_key_hex == DB_TX_PUBKEY {
        println!("    ✅ MATCH");
    } else {
        println!("    ❌ MISMATCH!");
    }

    println!("\n  Buyer PKI:");
    let expected_buyer_pki = hex::encode(pki_second.compress().as_bytes());
    println!("    Expected:  {}", expected_buyer_pki);
    println!("    DB:        {}", DB_BUYER_PKI);
    if expected_buyer_pki == DB_BUYER_PKI {
        println!("    ✅ MATCH");
    } else {
        println!("    ❌ MISMATCH!");
    }

    println!("\n  Vendor PKI:");
    let expected_vendor_pki = hex::encode(pki_first.compress().as_bytes());
    println!("    Expected:  {}", expected_vendor_pki);
    println!("    DB:        {}", DB_VENDOR_PKI);
    if expected_vendor_pki == DB_VENDOR_PKI {
        println!("    ✅ MATCH");
    } else {
        println!("    ❌ MISMATCH!");
    }

    println!("\n  Aggregated Key Image:");
    println!("    Expected:  {}", aggregated_hex);
    println!("    DB:        {}", DB_AGGREGATED_KI);
    if aggregated_hex == DB_AGGREGATED_KI {
        println!("    ✅ MATCH");
    } else {
        println!("    ❌ MISMATCH!");
    }
}
