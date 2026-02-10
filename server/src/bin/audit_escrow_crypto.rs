//! Audit Escrow Cryptographic Values
//!
//! This script verifies all cryptographic computations for a specific escrow
//! using known values from the funding transaction.
//!
//! Usage: cargo run --bin audit_escrow_crypto

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

// ============================================================
// KNOWN VALUES FROM ESCROW 8dfe6cd8-4ce8-4754-9c2e-9fcef175b05e
// Funded by TX: 4963ebb1a74c93259864a15cae1364f0638b0dcec43677415f9541c43d221796
// ============================================================

const TX_PUBKEY_HEX: &str = "f328e5ae72ba19d163b5cbea369cfeb67f1290dc34271acb28425203a20e62b7";
const TX_SECRET_KEY_HEX: &str = "43c788f9729df6d15b8ba4584816facecef04dd823b7be39af7ae777b3a2f509";
const VIEW_KEY_HEX: &str = "d4f2f1cc764d4acc97a849ed525cf56e66de9657812920f1e001197a166d5909";

// Outputs from funding TX
const OUTPUT_0_KEY_HEX: &str = "8cd680c84b7f2e999fbf6b29c832df99ceae81ee0104718cad5d0fc1457f8bd3";
const OUTPUT_0_VIEW_TAG: u8 = 0x1d;
const OUTPUT_1_KEY_HEX: &str = "c446e94d12ff95bcc20abc43821b67fa26e5832c9fadc1a91e5fb714ba0f4367";
const OUTPUT_1_VIEW_TAG: u8 = 0x85;

// Stored PKI values from database
const BUYER_PKI_HEX: &str = "65efa8df2b3429526cd8c32f4b9a5a14cfd37616da0d628ae5c66d7855419b7f";
const VENDOR_PKI_HEX: &str = "60f32ac3d17c2fac2c582cd96ee549fb59e8a974cd57785829901bd11104135a";
const AGG_KEY_IMAGE_HEX: &str = "7ac0e3fefc81d119edb94a2f009980d3e9c6a33f406e5f210d9b37c6c130b883";

// Lagrange coefficients for buyer(1) + vendor(2)
// λ_buyer = 2, λ_vendor = -1 mod L
const LAMBDA_BUYER: u64 = 2;
// λ_vendor = -1 mod L = L - 1

fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).expect("Invalid hex");
    bytes.try_into().expect("Wrong length")
}

fn hex_to_point(hex: &str) -> Option<EdwardsPoint> {
    CompressedEdwardsY(hex_to_bytes32(hex)).decompress()
}

fn hex_to_scalar(hex: &str) -> Scalar {
    Scalar::from_bytes_mod_order(hex_to_bytes32(hex))
}

/// Monero's hash_to_point (Keccak256 + multiply by cofactor)
fn hash_to_point(data: &[u8]) -> EdwardsPoint {
    let mut hash = Keccak256::new();
    hash.update(data);
    let hash_bytes: [u8; 32] = hash.finalize().into();

    // Try to decompress, if fails, hash again
    let mut attempt = hash_bytes;
    loop {
        if let Some(point) = CompressedEdwardsY(attempt).decompress() {
            // Multiply by cofactor (8) to get point in prime-order subgroup
            return point.mul_by_cofactor();
        }
        // Hash again if point is not on curve
        let mut hasher = Keccak256::new();
        hasher.update(&attempt);
        attempt = hasher.finalize().into();
    }
}

/// Compute Hs = H(8*a*R || output_index) - the key derivation scalar
fn compute_derivation_scalar(view_key: &Scalar, tx_pubkey: &EdwardsPoint, output_index: u64) -> Scalar {
    // 8*a*R (ECDH with cofactor)
    let shared_secret = (view_key * tx_pubkey).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    // H("derivation" || 8aR || varint(output_index))
    let mut data = Vec::new();
    data.extend_from_slice(&shared_secret_bytes);

    // Encode output_index as varint
    let mut idx = output_index;
    loop {
        let byte = (idx & 0x7f) as u8;
        idx >>= 7;
        if idx == 0 {
            data.push(byte);
            break;
        } else {
            data.push(byte | 0x80);
        }
    }

    // Hs = H(data) reduced to scalar
    let mut hasher = Keccak256::new();
    hasher.update(b"derivation");
    hasher.update(&data);
    let hash: [u8; 32] = hasher.finalize().into();

    Scalar::from_bytes_mod_order(hash)
}

/// Compute view tag (first byte of H(8aR || output_index))
fn compute_view_tag(view_key: &Scalar, tx_pubkey: &EdwardsPoint, output_index: u64) -> u8 {
    let shared_secret = (view_key * tx_pubkey).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    let mut data = Vec::new();
    data.extend_from_slice(b"view_tag");
    data.extend_from_slice(&shared_secret_bytes);

    // Encode output_index as varint
    let mut idx = output_index;
    loop {
        let byte = (idx & 0x7f) as u8;
        idx >>= 7;
        if idx == 0 {
            data.push(byte);
            break;
        } else {
            data.push(byte | 0x80);
        }
    }

    let mut hasher = Keccak256::new();
    hasher.update(&data);
    let hash: [u8; 32] = hasher.finalize().into();

    hash[0]
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     ESCROW CRYPTO AUDIT - 8dfe6cd8-4ce8-4754-9c2e-9fcef175   ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Parse all known values
    let tx_pubkey = hex_to_point(TX_PUBKEY_HEX).expect("Invalid TX pubkey");
    let view_key = hex_to_scalar(VIEW_KEY_HEX);
    let output_0_key = hex_to_point(OUTPUT_0_KEY_HEX).expect("Invalid output 0 key");
    let output_1_key = hex_to_point(OUTPUT_1_KEY_HEX).expect("Invalid output 1 key");
    let buyer_pki = hex_to_point(BUYER_PKI_HEX).expect("Invalid buyer PKI");
    let vendor_pki = hex_to_point(VENDOR_PKI_HEX).expect("Invalid vendor PKI");
    let agg_ki = hex_to_point(AGG_KEY_IMAGE_HEX).expect("Invalid agg key image");

    println!("=== STEP 1: Identify which output belongs to escrow ===");
    println!();

    // Compute view tags for both outputs
    let computed_tag_0 = compute_view_tag(&view_key, &tx_pubkey, 0);
    let computed_tag_1 = compute_view_tag(&view_key, &tx_pubkey, 1);

    println!("Output 0: stored_tag=0x{:02x}, computed_tag=0x{:02x} {}",
        OUTPUT_0_VIEW_TAG, computed_tag_0,
        if OUTPUT_0_VIEW_TAG == computed_tag_0 { "✅ MATCH" } else { "❌ NO MATCH" });
    println!("Output 1: stored_tag=0x{:02x}, computed_tag=0x{:02x} {}",
        OUTPUT_1_VIEW_TAG, computed_tag_1,
        if OUTPUT_1_VIEW_TAG == computed_tag_1 { "✅ MATCH" } else { "❌ NO MATCH" });

    // Determine which output is ours
    let (our_output_index, our_output_key) = if OUTPUT_0_VIEW_TAG == computed_tag_0 {
        (0u64, output_0_key)
    } else if OUTPUT_1_VIEW_TAG == computed_tag_1 {
        (1u64, output_1_key)
    } else {
        println!("❌ ERROR: Neither output matches our view key!");
        return;
    };

    println!();
    println!("→ Our output is OUTPUT {} (P = {}...)",
        our_output_index,
        &hex::encode(our_output_key.compress().to_bytes())[..16]);

    println!();
    println!("=== STEP 2: Compute derivation scalar Hs ===");
    println!();

    let hs = compute_derivation_scalar(&view_key, &tx_pubkey, our_output_index);
    println!("Hs = H(8aR || {}) = {}...",
        our_output_index,
        &hex::encode(hs.to_bytes())[..16]);

    // Verify: P = Hs*G + B (we don't have B, but we can check Hs*G)
    let hs_point = &hs * ED25519_BASEPOINT_TABLE;
    println!("Hs*G = {}...", &hex::encode(hs_point.compress().to_bytes())[..16]);

    println!();
    println!("=== STEP 3: Compute Hp(P) - hash to point of output key ===");
    println!();

    let output_key_bytes = our_output_key.compress().to_bytes();
    let hp_p = hash_to_point(&output_key_bytes);
    println!("Hp(P) = {}...", &hex::encode(hp_p.compress().to_bytes())[..16]);

    println!();
    println!("=== STEP 4: Verify PKI computation ===");
    println!();
    println!("PKI should be: (Hs + spend_share) * Hp(P)");
    println!();
    println!("Stored PKIs:");
    println!("  Buyer PKI:  {}", BUYER_PKI_HEX);
    println!("  Vendor PKI: {}", VENDOR_PKI_HEX);
    println!();

    // We can't verify individual PKIs without the spend shares,
    // but we CAN verify the Lagrange aggregation

    println!("=== STEP 5: Verify Lagrange aggregation of Key Image ===");
    println!();
    println!("For signer pair {{buyer=1, vendor=2}}:");
    println!("  λ_buyer  = 2");
    println!("  λ_vendor = -1 (mod L)");
    println!();
    println!("Expected: KI = λ_buyer * PKI_buyer + λ_vendor * PKI_vendor");
    println!("             = 2 * PKI_buyer - PKI_vendor");
    println!();

    // Compute: 2 * buyer_pki - vendor_pki
    let lambda_buyer = Scalar::from(LAMBDA_BUYER);
    let lambda_vendor = -Scalar::ONE; // -1 mod L

    let computed_ki = (lambda_buyer * buyer_pki) + (lambda_vendor * vendor_pki);
    let computed_ki_hex = hex::encode(computed_ki.compress().to_bytes());

    println!("Computed KI: {}", computed_ki_hex);
    println!("Stored KI:   {}", AGG_KEY_IMAGE_HEX);
    println!();

    if computed_ki_hex == AGG_KEY_IMAGE_HEX {
        println!("✅ KEY IMAGE AGGREGATION CORRECT!");
        println!("   The Lagrange-weighted sum of PKIs matches the stored key image.");
    } else {
        println!("❌ KEY IMAGE MISMATCH!");
        println!("   Computed: {}", &computed_ki_hex[..32]);
        println!("   Stored:   {}", &AGG_KEY_IMAGE_HEX[..32]);
        println!();
        println!("   Possible causes:");
        println!("   1. Wrong Lagrange coefficients");
        println!("   2. PKI values were computed incorrectly");
        println!("   3. Different signer pair was used");
    }

    println!();
    println!("=== STEP 6: Verify λ_buyer + λ_vendor = 1 ===");
    println!();

    let sum = lambda_buyer + lambda_vendor;
    let sum_is_one = sum == Scalar::ONE;
    println!("λ_buyer + λ_vendor = {} {}",
        hex::encode(sum.to_bytes()),
        if sum_is_one { "= 1 ✅" } else { "≠ 1 ❌" });

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                      AUDIT COMPLETE                          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
