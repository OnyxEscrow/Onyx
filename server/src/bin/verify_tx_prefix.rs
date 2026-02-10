//! Verify tx_prefix_hash from TX hex file

use sha3::{Digest, Keccak256};
use std::fs;

fn main() {
    // Read TX hex
    let hex_data = fs::read_to_string("/tmp/tx_debug_ef57f177-f873-40c3-a175-4ab87c195ad8.hex")
        .expect("Failed to read TX hex file");
    let hex_data = hex_data.trim();

    let data = hex::decode(hex_data).expect("Invalid hex");

    // TX prefix is bytes 0-178
    let tx_prefix = &data[..178];

    // Compute Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(tx_prefix);
    let hash = hasher.finalize();

    let computed_hash = hex::encode(&hash);

    println!("TX prefix length: {} bytes", tx_prefix.len());
    println!(
        "TX prefix (first 32 bytes): {}",
        hex::encode(&tx_prefix[..32])
    );
    println!("\nComputed tx_prefix_hash: {}", computed_hash);

    // Expected from test
    let expected = "405ec21109897ce30308066caf44040822762ecae1dddb6f585d4ee15fe57431";
    println!("Expected tx_prefix_hash: {}", expected);
    println!("Match: {}", computed_hash == expected);

    if computed_hash != expected {
        println!("\n⚠️  TX PREFIX HASH MISMATCH!");
        println!("This means the signature was computed for a different tx_prefix!");
    }
}
