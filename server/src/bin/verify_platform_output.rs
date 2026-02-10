// Diagnostic tool to verify platform fee output in a transaction
// Run: cargo run --bin verify_platform_output -- <tx_hash> <escrow_id> <amount_atomic>

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};
use std::env;

const PLATFORM_ADDRESS: &str = "58WZHPMi4UZbb6jmyphVHiDNkYXNf8wLWhjB4SxHBvG9YNHsyZmntHjj9junfWQJjqixi48rWpoWWGgZBPjrE6HMUKNfmZx";

fn main() {
    let args: Vec<String> = env::args().collect();

    let (tx_hash, escrow_id, amount) = if args.len() >= 4 {
        (
            args[1].clone(),
            args[2].clone(),
            args[3].parse::<u64>().expect("Invalid amount"),
        )
    } else {
        // Default values from the test case
        (
            "2d3291ad0226f40f4d6f5b9349165e3011bf6a29139e5d52303763ff792ed46e".to_string(),
            "148c8bcd-205d-4f83-8b40-dbfacfcf515e".to_string(),
            1000000000u64, // 1 XMR in atomic
        )
    };

    println!("=== PLATFORM OUTPUT VERIFICATION ===\n");
    println!("TX Hash: {}", tx_hash);
    println!("Escrow ID: {}", escrow_id);
    println!("Amount: {} atomic", amount);
    println!(
        "Platform Address: {}...{}",
        &PLATFORM_ADDRESS[..12],
        &PLATFORM_ADDRESS[PLATFORM_ADDRESS.len() - 8..]
    );
    println!();

    // Step 1: Parse platform address
    println!("--- Step 1: Parse Platform Address ---");
    let decoded =
        base58_monero::decode_check(PLATFORM_ADDRESS).expect("Failed to decode platform address");

    if decoded.len() != 65 {
        panic!("Invalid address length: {} (expected 65)", decoded.len());
    }

    let network_byte = decoded[0];
    let mut platform_spend_pub = [0u8; 32];
    let mut platform_view_pub = [0u8; 32];
    platform_spend_pub.copy_from_slice(&decoded[1..33]);
    platform_view_pub.copy_from_slice(&decoded[33..65]);

    println!("Network byte: {} (24=stagenet, 18=mainnet)", network_byte);
    println!("Platform spend_pub: {}", hex::encode(&platform_spend_pub));
    println!("Platform view_pub:  {}", hex::encode(&platform_view_pub));
    println!();

    // Step 2: Compute deterministic tx_secret_key
    println!("--- Step 2: Compute TX Secret Key ---");
    let tx_secret_key: [u8; 32] = {
        let mut hasher = Keccak256::new();
        hasher.update(b"NEXUS_TX_SECRET_V1");
        hasher.update(escrow_id.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.finalize().into()
    };
    println!("tx_secret_key: {}", hex::encode(&tx_secret_key));

    // Step 3: Compute tx_pubkey (R = r*G)
    println!("\n--- Step 3: Compute TX Pubkey ---");
    let r = Scalar::from_bytes_mod_order(tx_secret_key);
    let tx_pubkey = (&*ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();
    println!("tx_pubkey (R = r*G): {}", hex::encode(&tx_pubkey));
    println!();

    // Step 4: Compute derivation for platform (output index 1)
    println!("--- Step 4: Compute Derivation for Platform (index=1) ---");

    let view_pub_point = CompressedEdwardsY(platform_view_pub)
        .decompress()
        .expect("Failed to decompress platform view pubkey");

    let spend_pub_point = CompressedEdwardsY(platform_spend_pub)
        .decompress()
        .expect("Failed to decompress platform spend pubkey");

    // derivation = 8 * r * V (cofactor multiplication)
    let derivation = (r * view_pub_point).mul_by_cofactor();
    let derivation_bytes = derivation.compress().to_bytes();
    println!("derivation (8*r*V): {}", hex::encode(&derivation_bytes));

    // Step 5: Compute H_s(derivation || output_index)
    println!("\n--- Step 5: Compute H_s for Stealth Address ---");
    let output_index: u64 = 1; // Platform is output 1

    // Varint encoding for output_index
    let mut output_index_varint = Vec::new();
    encode_varint(&mut output_index_varint, output_index);
    println!("output_index varint: {:?}", output_index_varint);

    let mut hasher = Keccak256::new();
    hasher.update(&derivation_bytes);
    hasher.update(&output_index_varint);
    let hash: [u8; 32] = hasher.finalize().into();
    let h_s = Scalar::from_bytes_mod_order(hash);
    println!("H_s(derivation || 1): {}", hex::encode(&hash));

    // Step 6: Compute stealth address P = H_s*G + S
    println!("\n--- Step 6: Compute Stealth Address ---");
    let h_s_g = &*ED25519_BASEPOINT_TABLE * &h_s;
    let stealth_address = (h_s_g + spend_pub_point).compress().to_bytes();
    println!(
        "EXPECTED stealth_address: {}",
        hex::encode(&stealth_address)
    );

    // Step 7: Compute view_tag
    println!("\n--- Step 7: Compute View Tag ---");
    let mut vt_hasher = Keccak256::new();
    vt_hasher.update(b"view_tag"); // 8 bytes, no null
    vt_hasher.update(&derivation_bytes);
    vt_hasher.update(&output_index_varint);
    let vt_hash: [u8; 32] = vt_hasher.finalize().into();
    let view_tag = vt_hash[0];
    println!("EXPECTED view_tag: 0x{:02x} ({})", view_tag, view_tag);

    println!("\n=== SUMMARY ===");
    println!("To verify, check the blockchain TX and compare:");
    println!(
        "  1. TX extra field should contain tx_pubkey: {}",
        hex::encode(&tx_pubkey)
    );
    println!(
        "  2. Output[1] target key should be: {}",
        hex::encode(&stealth_address)
    );
    println!("  3. Output[1] view_tag should be: 0x{:02x}", view_tag);

    println!("\n=== CURL COMMAND TO FETCH TX ===");
    println!(
        r#"curl -s -X POST http://stagenet.xmr-tw.org:38081/get_transactions -d '{{"txs_hashes":["{}"],"decode_as_json":true}}' -H "Content-Type: application/json" | jq '.txs[0].as_json' -r | jq ."#,
        tx_hash
    );

    println!("\n=== MANUAL VERIFICATION ===");
    println!("In the TX JSON, look for:");
    println!("  - \"extra\": should start with [1, ...] where bytes 1-32 are tx_pubkey");
    println!("  - \"vout[1].target.tagged_key.key\": should match our stealth_address");
    println!("  - \"vout[1].target.tagged_key.view_tag\": should match our view_tag");
}

fn encode_varint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}
