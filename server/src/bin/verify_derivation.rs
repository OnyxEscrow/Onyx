// Verify derivation from BOTH sides:
// 1. Sender: derivation = 8 * r * V (tx_secret * view_pub)
// 2. Recipient: derivation = 8 * v * R (view_secret * tx_pubkey)
// These MUST match for the wallet to detect the output

use sha3::{Digest, Keccak256};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;

fn main() {
    println!("=== DERIVATION VERIFICATION ===\n");

    // Known values
    let escrow_id = "148c8bcd-205d-4f83-8b40-dbfacfcf515e";
    let amount: u64 = 1000000000;

    // Wallet's SECRET view key (from user)
    let view_secret_hex = "4780bc9bed77502d2f5a6cea05b24edfeb7a115118c1f58d9e98b10bf2f15505";
    let view_secret_bytes: [u8; 32] = hex::decode(view_secret_hex)
        .expect("Invalid view_secret hex")
        .try_into()
        .expect("Invalid length");

    // Wallet's PUBLIC view key
    let view_pub_hex = "88141fed8ba6befc00a338fa0d7080fadd8576626b7d2f5dc1a5627b762a40f2";
    let view_pub_bytes: [u8; 32] = hex::decode(view_pub_hex)
        .expect("Invalid view_pub hex")
        .try_into()
        .expect("Invalid length");

    // Wallet's spend pubkey
    let spend_pub_hex = "b043065c783612cec9a14d2227b7e949fc41188e6c959bf37dd8e160f38192bb";
    let spend_pub_bytes: [u8; 32] = hex::decode(spend_pub_hex)
        .expect("Invalid spend_pub hex")
        .try_into()
        .expect("Invalid length");

    // === SENDER SIDE ===
    println!("--- SENDER SIDE (our code) ---");

    // Compute tx_secret_key (deterministic)
    let tx_secret_key: [u8; 32] = {
        let mut hasher = Keccak256::new();
        hasher.update(b"NEXUS_TX_SECRET_V1");
        hasher.update(escrow_id.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.finalize().into()
    };
    println!("tx_secret_key (r): {}", hex::encode(&tx_secret_key));

    let r = Scalar::from_bytes_mod_order(tx_secret_key);

    // tx_pubkey = r * G
    let tx_pubkey = (&*ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();
    println!("tx_pubkey (R = r*G): {}", hex::encode(&tx_pubkey));

    // Parse view_pub as point
    let view_pub_point = CompressedEdwardsY(view_pub_bytes)
        .decompress()
        .expect("Failed to decompress view_pub");

    // Sender's derivation = 8 * r * V
    let sender_derivation = (r * view_pub_point).mul_by_cofactor();
    let sender_derivation_bytes = sender_derivation.compress().to_bytes();
    println!("sender derivation (8*r*V): {}", hex::encode(&sender_derivation_bytes));

    // === RECIPIENT SIDE ===
    println!("\n--- RECIPIENT SIDE (wallet) ---");

    let v = Scalar::from_bytes_mod_order(view_secret_bytes);
    println!("view_secret (v): {}", hex::encode(&view_secret_bytes));

    // Verify: v * G should equal view_pub
    let computed_view_pub = (&*ED25519_BASEPOINT_TABLE * &v).compress().to_bytes();
    println!("computed view_pub (v*G): {}", hex::encode(&computed_view_pub));
    if computed_view_pub == view_pub_bytes {
        println!("✅ v*G matches view_pub");
    } else {
        println!("❌ v*G does NOT match view_pub - KEY MISMATCH!");
    }

    // Parse tx_pubkey as point
    let tx_pubkey_point = CompressedEdwardsY(tx_pubkey)
        .decompress()
        .expect("Failed to decompress tx_pubkey");

    // Recipient's derivation = 8 * v * R
    let recipient_derivation = (v * tx_pubkey_point).mul_by_cofactor();
    let recipient_derivation_bytes = recipient_derivation.compress().to_bytes();
    println!("recipient derivation (8*v*R): {}", hex::encode(&recipient_derivation_bytes));

    // === COMPARE ===
    println!("\n--- COMPARISON ---");
    if sender_derivation_bytes == recipient_derivation_bytes {
        println!("✅ DERIVATIONS MATCH!");
    } else {
        println!("❌ DERIVATIONS DO NOT MATCH!");
        println!("   sender:    {}", hex::encode(&sender_derivation_bytes));
        println!("   recipient: {}", hex::encode(&recipient_derivation_bytes));
    }

    // === COMPUTE STEALTH ADDRESS ===
    println!("\n--- STEALTH ADDRESS (output index 1) ---");
    let output_index: u64 = 1;

    // Varint encode output_index
    let mut output_index_varint = Vec::new();
    let mut val = output_index;
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 { byte |= 0x80; }
        output_index_varint.push(byte);
        if val == 0 { break; }
    }

    // H_s(derivation || output_index)
    let mut hasher = Keccak256::new();
    hasher.update(&sender_derivation_bytes);
    hasher.update(&output_index_varint);
    let hash: [u8; 32] = hasher.finalize().into();
    let h_s = Scalar::from_bytes_mod_order(hash);
    println!("H_s(derivation || 1): {}", hex::encode(&hash));

    // Stealth address = H_s * G + S
    let spend_pub_point = CompressedEdwardsY(spend_pub_bytes)
        .decompress()
        .expect("Failed to decompress spend_pub");
    let h_s_g = &*ED25519_BASEPOINT_TABLE * &h_s;
    let stealth_address = (h_s_g + spend_pub_point).compress().to_bytes();
    println!("computed stealth_address: {}", hex::encode(&stealth_address));

    // Expected from blockchain
    let expected_stealth = "dec8d25c25767255031d74ff8c926e91797bd65667f7817478128513fb5a1543";
    println!("expected (from blockchain): {}", expected_stealth);

    if hex::encode(&stealth_address) == expected_stealth {
        println!("✅ STEALTH ADDRESS MATCHES BLOCKCHAIN!");
    } else {
        println!("❌ STEALTH ADDRESS DOES NOT MATCH!");
    }

    // === VIEW TAG ===
    println!("\n--- VIEW TAG ---");
    let mut vt_hasher = Keccak256::new();
    vt_hasher.update(b"view_tag");
    vt_hasher.update(&sender_derivation_bytes);
    vt_hasher.update(&output_index_varint);
    let vt_hash: [u8; 32] = vt_hasher.finalize().into();
    let view_tag = vt_hash[0];
    println!("computed view_tag: 0x{:02x}", view_tag);
    println!("expected (from blockchain): 0x54");

    if view_tag == 0x54 {
        println!("✅ VIEW TAG MATCHES!");
    } else {
        println!("❌ VIEW TAG DOES NOT MATCH!");
    }
}
