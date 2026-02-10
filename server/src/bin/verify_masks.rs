//! Verify mask computation for FROST 2-of-3
//! Run: cargo run --release --bin verify_masks

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

// From escrow data
const ESCROW_ID: &str = "ef57f177-f873-40c3-a175-4ab87c195ad8";
const AMOUNT: i64 = 1000000000; // 0.001 XMR in atomic units
const FUNDING_MASK: &str = "c254d7f8dc4ccfbc7bbab6925a611398ca5c93ab9f3b8c731620ae168a3a4508";
const DUMMY_MASK_LOGGED: &str = "a206991f258a777ee221ac28587e10a6956fd087d57bef0838266d9750e34a0d";
// Correctly decoded from base58
const VENDOR_VIEW_PUB: &str = "edf700b8a06ade3479c82be305e626514006fda507104af42fe6f46aabc4d5da";

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("Invalid hex")
}

fn hex_to_32(hex: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(hex);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
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

fn derive_tx_secret_key(escrow_id: &str, amount: i64) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"NEXUS_TX_SECRET_V1");
    hasher.update(escrow_id.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.finalize().into()
}

fn derive_output_mask(tx_secret_key: &[u8; 32], recipient_view_pub: &[u8; 32], output_index: u64) -> [u8; 32] {
    let r = Scalar::from_bytes_mod_order(*tx_secret_key);
    
    let view_pub_point = CompressedEdwardsY(*recipient_view_pub)
        .decompress()
        .expect("Invalid recipient view key");
    
    // Shared secret with cofactor: 8 * r * V
    let shared_secret = (r * view_pub_point).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();
    
    // Hs(derivation || varint(output_index))
    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    hasher.update(&encode_varint(output_index));
    let derivation_hash: [u8; 32] = hasher.finalize().into();
    
    let derivation_scalar = Scalar::from_bytes_mod_order(derivation_hash);
    
    // mask = Hs("commitment_mask" || derivation_scalar)
    let mut mask_hasher = Keccak256::new();
    mask_hasher.update(b"commitment_mask");
    mask_hasher.update(derivation_scalar.as_bytes());
    let mask_bytes: [u8; 32] = mask_hasher.finalize().into();
    
    Scalar::from_bytes_mod_order(mask_bytes).to_bytes()
}

fn main() {
    println!("=== FULL MASK COMPUTATION VERIFICATION ===\n");
    
    // Compute tx_secret_key like the server does
    let tx_secret_key = derive_tx_secret_key(ESCROW_ID, AMOUNT);
    println!("Computed tx_secret_key: {}", hex::encode(&tx_secret_key));
    println!("Expected (from FROST test): 54d48a7b6f680a88fd04b4cf56b18f09e01c66ab3aa5ec9aabb33a258de43704");
    println!("Match: {}\n", if hex::encode(&tx_secret_key) == "54d48a7b6f680a88fd04b4cf56b18f09e01c66ab3aa5ec9aabb33a258de43704" { "✅" } else { "❌" });
    
    let vendor_view_pub = hex_to_32(VENDOR_VIEW_PUB);
    let funding_mask = hex_to_32(FUNDING_MASK);
    let dummy_mask_logged = hex_to_32(DUMMY_MASK_LOGGED);
    
    println!("vendor_view_pub: {}", VENDOR_VIEW_PUB);
    
    // Compute output_mask (index 0)
    let output_mask = derive_output_mask(&tx_secret_key, &vendor_view_pub, 0);
    println!("\nComputed output_mask (index 0): {}", hex::encode(&output_mask));
    println!("Expected (first 8 from logs):   e55cfe3edeb36b96...");
    println!("Match first 8: {}", if hex::encode(&output_mask[..8]) == "e55cfe3edeb36b96" { "✅" } else { "❌" });
    
    // Compute dummy_mask (index 1)
    let dummy_mask = derive_output_mask(&tx_secret_key, &vendor_view_pub, 1);
    println!("\nComputed dummy_mask (index 1): {}", hex::encode(&dummy_mask));
    println!("Logged dummy_mask:             {}", DUMMY_MASK_LOGGED);
    println!("Match: {}", if dummy_mask == dummy_mask_logged { "✅" } else { "❌" });
    
    // Compute pseudo_out_mask = output_mask + dummy_mask
    let out_scalar = Scalar::from_bytes_mod_order(output_mask);
    let dummy_scalar = Scalar::from_bytes_mod_order(dummy_mask);
    let pseudo_out_mask = (out_scalar + dummy_scalar).to_bytes();
    println!("\nComputed pseudo_out_mask: {}", hex::encode(&pseudo_out_mask));
    println!("Expected (first 8 from logs): 9a8fa101e9dad0bc...");
    println!("Match first 8: {}", if hex::encode(&pseudo_out_mask[..8]) == "9a8fa101e9dad0bc" { "✅" } else { "❌" });
    
    // Compute mask_delta = funding_mask - pseudo_out_mask
    let z_scalar = Scalar::from_bytes_mod_order(funding_mask);
    let pseudo_scalar = Scalar::from_bytes_mod_order(pseudo_out_mask);
    let mask_delta = (z_scalar - pseudo_scalar).to_bytes();
    println!("\nComputed mask_delta (z - pseudo_out_mask): {}", hex::encode(&mask_delta));
    println!("Expected (first 8 from logs): 15992b540ed51058...");
    println!("Match first 8: {}", if hex::encode(&mask_delta[..8]) == "15992b540ed51058" { "✅" } else { "❌" });
    
    // Verify mask_delta is NOT zero (important for CLSAG)
    let zero = [0u8; 32];
    println!("\nmask_delta is zero: {}", if mask_delta == zero { "⚠️ YES - THIS IS A BUG!" } else { "✅ NO (good)" });
    
    // Now compute D = mask_delta * Hp(P_signer)
    let signer_pubkey = hex_to_32("ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0");
    let hp_signer = monero_generators_mirror::hash_to_point(signer_pubkey);
    let mask_delta_scalar = Scalar::from_bytes_mod_order(mask_delta);
    let d_point = mask_delta_scalar * hp_signer;
    let d_bytes = d_point.compress().to_bytes();
    
    println!("\n=== D POINT COMPUTATION ===");
    println!("D = mask_delta * Hp(P_signer): {}", hex::encode(&d_bytes));
    
    // D_inv8 = D / 8
    let inv8 = Scalar::from(8u64).invert();
    let d_inv8 = d_point * inv8;
    let d_inv8_bytes = d_inv8.compress().to_bytes();
    println!("D_inv8 = D / 8: {}", hex::encode(&d_inv8_bytes));
    
    // Compare with TX value
    let d_inv8_tx = "1d6a4b5f7433965a4f583ba627d99ad2dcc314d71da894688552495896c30894";
    println!("\nD_inv8 from TX: {}", d_inv8_tx);
    println!("D_inv8 computed: {}", hex::encode(&d_inv8_bytes));
    println!("Match: {}", if hex::encode(&d_inv8_bytes) == d_inv8_tx { "✅" } else { "❌" });
    
    // Summary
    println!("\n=== SUMMARY ===");
    let out_match = hex::encode(&output_mask[..8]) == "e55cfe3edeb36b96";
    let dummy_match = dummy_mask == dummy_mask_logged;
    let pseudo_match = hex::encode(&pseudo_out_mask[..8]) == "9a8fa101e9dad0bc";
    let delta_match = hex::encode(&mask_delta[..8]) == "15992b540ed51058";
    let d_match = hex::encode(&d_inv8_bytes) == d_inv8_tx;
    
    println!("output_mask derivation: {}", if out_match { "✅" } else { "❌" });
    println!("dummy_mask derivation: {}", if dummy_match { "✅" } else { "❌" });
    println!("pseudo_out_mask sum: {}", if pseudo_match { "✅" } else { "❌" });
    println!("mask_delta computation: {}", if delta_match { "✅" } else { "❌" });
    println!("D_inv8 computation: {}", if d_match { "✅" } else { "❌" });
    
    if out_match && dummy_match && pseudo_match && delta_match && d_match {
        println!("\n✅ ALL MASK COMPUTATIONS ARE CORRECT!");
        println!("The issue must be elsewhere (CLSAG challenge, s values, etc.)");
    } else {
        println!("\n❌ MASK COMPUTATION MISMATCH DETECTED!");
        println!("This could be the root cause of CLSAG verification failure.");
    }
}
