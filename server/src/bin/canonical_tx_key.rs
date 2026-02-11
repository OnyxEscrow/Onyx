// Compute the CANONICAL tx_secret_key (reduced mod l)
// This is what Monero's check_tx_key expects

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

fn main() {
    let escrow_id = "148c8bcd-205d-4f83-8b40-dbfacfcf515e";
    let amount: u64 = 1000000000;

    // Step 1: Compute raw hash
    let raw_hash: [u8; 32] = {
        let mut hasher = Keccak256::new();
        hasher.update(b"NEXUS_TX_SECRET_V1");
        hasher.update(escrow_id.as_bytes());
        hasher.update(amount.to_le_bytes());
        hasher.finalize().into()
    };

    println!("=== TX KEY DERIVATION DEBUG ===\n");
    println!("Escrow ID: {escrow_id}");
    println!("Amount: {amount} atomic\n");

    println!("--- Step 1: Raw Keccak256 hash ---");
    println!("raw_hash: {}", hex::encode(raw_hash));

    // Step 2: Reduce mod l (curve order)
    let r = Scalar::from_bytes_mod_order(raw_hash);
    let canonical_tx_key = r.to_bytes();

    println!("\n--- Step 2: Scalar reduction (mod l) ---");
    println!("canonical_tx_key: {}", hex::encode(canonical_tx_key));

    // Check if they're different
    if raw_hash == canonical_tx_key {
        println!("\n✅ raw_hash == canonical_tx_key (no reduction occurred)");
    } else {
        println!("\n⚠️  raw_hash != canonical_tx_key (REDUCTION OCCURRED!)");
        println!("   This is the KEY that Monero expects for check_tx_key");
    }

    // Step 3: Compute R = r * G
    let tx_pubkey = (ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();

    println!("\n--- Step 3: TX Pubkey (R = r*G) ---");
    println!("tx_pubkey: {}", hex::encode(tx_pubkey));

    // Step 4: Print the check_tx_key command
    println!("\n=== MONERO CLI COMMAND ===");
    println!("check_tx_key 2d3291ad0226f40f4d6f5b9349165e3011bf6a29139e5d52303763ff792ed46e {} 58WZHPMi4UZbb6jmyphVHiDNkYXNf8wLWhjB4SxHBvG9YNHsyZmntHjj9junfWQJjqixi48rWpoWWGgZBPjrE6HMUKNfmZx",
        hex::encode(canonical_tx_key));
}
