// Check if output[1] was generated with the OLD platform address (subaddress 75wC...)
// instead of the NEW primary address (58WZH...)

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

// OLD platform address (subaddress)
const OLD_PLATFORM_ADDRESS: &str = "75wCKnwCxc3ZMLKdupfe8KKXDV6nGik3tRorFffyic8QLy7gqLUeRfeGFzf2seD4kSiY9mSzQFvzd5JyaAuxc8iqJbD1tcs";

// NEW platform address (primary)
const NEW_PLATFORM_ADDRESS: &str = "58WZHPMi4UZbb6jmyphVHiDNkYXNf8wLWhjB4SxHBvG9YNHsyZmntHjj9junfWQJjqixi48rWpoWWGgZBPjrE6HMUKNfmZx";

// Actual output[1] from blockchain
const BLOCKCHAIN_OUTPUT_1_KEY: &str =
    "dec8d25c25767255031d74ff8c926e91797bd65667f7817478128513fb5a1543";
const BLOCKCHAIN_OUTPUT_1_VIEWTAG: u8 = 0x54;

fn parse_address(address: &str) -> ([u8; 32], [u8; 32]) {
    let decoded = base58_monero::decode_check(address).expect("Failed to decode address");

    let mut spend_pub = [0u8; 32];
    let mut view_pub = [0u8; 32];

    if decoded.len() == 65 {
        // Primary address: network(1) + spend(32) + view(32)
        spend_pub.copy_from_slice(&decoded[1..33]);
        view_pub.copy_from_slice(&decoded[33..65]);
    } else if decoded.len() == 69 {
        // Subaddress: network(1) + spend(32) + view(32) + checksum
        // Actually subaddresses are also 65 bytes after decode_check removes checksum
        spend_pub.copy_from_slice(&decoded[1..33]);
        view_pub.copy_from_slice(&decoded[33..65]);
    } else {
        panic!("Unexpected address length: {}", decoded.len());
    }

    (spend_pub, view_pub)
}

fn compute_stealth_address(
    tx_secret_key: &[u8; 32],
    spend_pub: &[u8; 32],
    view_pub: &[u8; 32],
    output_index: u64,
) -> ([u8; 32], u8) {
    let r = Scalar::from_bytes_mod_order(*tx_secret_key);

    let view_pub_point = CompressedEdwardsY(*view_pub)
        .decompress()
        .expect("Failed to decompress view_pub");

    let spend_pub_point = CompressedEdwardsY(*spend_pub)
        .decompress()
        .expect("Failed to decompress spend_pub");

    // derivation = 8 * r * V
    let derivation = (r * view_pub_point).mul_by_cofactor();
    let derivation_bytes = derivation.compress().to_bytes();

    // Varint encode output_index
    let mut output_index_varint = Vec::new();
    let mut val = output_index;
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        output_index_varint.push(byte);
        if val == 0 {
            break;
        }
    }

    // H_s(derivation || output_index)
    let mut hasher = Keccak256::new();
    hasher.update(&derivation_bytes);
    hasher.update(&output_index_varint);
    let hash: [u8; 32] = hasher.finalize().into();
    let h_s = Scalar::from_bytes_mod_order(hash);

    // stealth_address = H_s * G + S
    let h_s_g = &*ED25519_BASEPOINT_TABLE * &h_s;
    let stealth_address = (h_s_g + spend_pub_point).compress().to_bytes();

    // view_tag = H("view_tag" || derivation || output_index)[0]
    let mut vt_hasher = Keccak256::new();
    vt_hasher.update(b"view_tag");
    vt_hasher.update(&derivation_bytes);
    vt_hasher.update(&output_index_varint);
    let vt_hash: [u8; 32] = vt_hasher.finalize().into();
    let view_tag = vt_hash[0];

    (stealth_address, view_tag)
}

fn main() {
    println!("=== CHECKING OLD vs NEW PLATFORM ADDRESS ===\n");

    let escrow_id = "148c8bcd-205d-4f83-8b40-dbfacfcf515e";
    let amount: u64 = 1000000000;

    // Compute tx_secret_key
    let tx_secret_key: [u8; 32] = {
        let mut hasher = Keccak256::new();
        hasher.update(b"NEXUS_TX_SECRET_V1");
        hasher.update(escrow_id.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.finalize().into()
    };

    println!("tx_secret_key: {}", hex::encode(&tx_secret_key));
    println!("Blockchain output[1] key: {}", BLOCKCHAIN_OUTPUT_1_KEY);
    println!(
        "Blockchain output[1] view_tag: 0x{:02x}\n",
        BLOCKCHAIN_OUTPUT_1_VIEWTAG
    );

    // Parse OLD address
    println!("--- OLD Platform Address (subaddress 75wC...) ---");
    let (old_spend_pub, old_view_pub) = parse_address(OLD_PLATFORM_ADDRESS);
    println!("spend_pub: {}", hex::encode(&old_spend_pub));
    println!("view_pub:  {}", hex::encode(&old_view_pub));

    let (old_stealth, old_vt) =
        compute_stealth_address(&tx_secret_key, &old_spend_pub, &old_view_pub, 1);
    println!("Computed stealth_address: {}", hex::encode(&old_stealth));
    println!("Computed view_tag: 0x{:02x}", old_vt);

    if hex::encode(&old_stealth) == BLOCKCHAIN_OUTPUT_1_KEY {
        println!("🔴 MATCH! Output[1] was generated with OLD address!");
    } else {
        println!("No match with OLD address");
    }

    // Parse NEW address
    println!("\n--- NEW Platform Address (primary 58WZH...) ---");
    let (new_spend_pub, new_view_pub) = parse_address(NEW_PLATFORM_ADDRESS);
    println!("spend_pub: {}", hex::encode(&new_spend_pub));
    println!("view_pub:  {}", hex::encode(&new_view_pub));

    let (new_stealth, new_vt) =
        compute_stealth_address(&tx_secret_key, &new_spend_pub, &new_view_pub, 1);
    println!("Computed stealth_address: {}", hex::encode(&new_stealth));
    println!("Computed view_tag: 0x{:02x}", new_vt);

    if hex::encode(&new_stealth) == BLOCKCHAIN_OUTPUT_1_KEY {
        println!("🟢 MATCH! Output[1] was generated with NEW address!");
    } else {
        println!("No match with NEW address");
    }

    println!("\n=== CONCLUSION ===");
    if hex::encode(&old_stealth) == BLOCKCHAIN_OUTPUT_1_KEY {
        println!("❌ BUG CONFIRMED: The transaction used the OLD platform address (75wC...)");
        println!("   The 5% fee went to the SUBADDRESS, not the primary address!");
        println!("   Check if the OLD wallet (with subaddress 75wC...) received the funds.");
    } else if hex::encode(&new_stealth) == BLOCKCHAIN_OUTPUT_1_KEY {
        println!("✅ Transaction used the NEW platform address correctly.");
        println!("   The issue is elsewhere...");
    } else {
        println!("⚠️  Neither address matches! Something else is wrong.");
    }
}
