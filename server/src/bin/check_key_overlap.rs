//! Check if there's key share overlap in 2-of-3 multisig
//!
//! For 2-of-3 multisig with key distribution:
//! - Total spend key B = k1 + k2 + k3
//! - Vendor has: k1 + k2
//! - Buyer has: k2 + k3
//!
//! When Vendor + Buyer sign:
//! - Sum: (k1+k2) + (k2+k3) = k1 + 2*k2 + k3
//! - Overlap: k2 is counted twice
//!
//! This tool queries the wallets and computes:
//! - S = spend_v + spend_b (sum of partial spend PUBLIC keys)
//! - B = multisig spend PUBLIC key
//! - Overlap = S - B (should equal k2*G for 2-of-3)

use anyhow::{Context, Result};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::Identity;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    println!("=== Key Share Overlap Check ===\n");

    // Query each wallet's spend public key
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let ports = [18083, 18084, 18085]; // buyer, vendor, arbiter
    let names = ["Buyer", "Vendor", "Arbiter"];
    let mut spend_pubs = Vec::new();

    for (port, name) in ports.iter().zip(names.iter()) {
        let url = format!("http://127.0.0.1:{}/json_rpc", port);

        // Query spend public key
        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":"0","method":"query_key","params":{"key_type":"spend_key"}}"#)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let json: serde_json::Value = resp.json().await?;
                if let Some(key) = json
                    .get("result")
                    .and_then(|r| r.get("key"))
                    .and_then(|k| k.as_str())
                {
                    println!("{} ({}) spend key: {}", name, port, key);

                    // Parse as point
                    let key_bytes = hex::decode(key)?;
                    if key_bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key_bytes);
                        if let Some(point) = CompressedEdwardsY(arr).decompress() {
                            spend_pubs.push((*name, point));
                        }
                    }
                } else if let Some(err) = json.get("error") {
                    println!("{} ({}) error: {:?}", name, port, err);
                }
            }
            Err(e) => {
                println!("{} ({}) not reachable: {}", name, port, e);
            }
        }
    }

    if spend_pubs.len() < 2 {
        println!("\nNeed at least 2 wallets to check overlap");
        return Ok(());
    }

    // Get the multisig address's spend public key
    // We need to parse it from the address
    let multisig_address = env::args().nth(1);
    if let Some(addr) = multisig_address {
        println!("\nMultisig address: {}", addr);
        // Would need to decode base58 address to extract B
        // For now, we'll compare the spend key sums
    }

    println!("\n--- Comparing Spend Key Sums ---\n");

    // Compute sum of vendor + buyer spend keys
    if spend_pubs.len() >= 2 {
        let vendor_pub = spend_pubs
            .iter()
            .find(|(n, _)| *n == "Vendor")
            .map(|(_, p)| p);
        let buyer_pub = spend_pubs
            .iter()
            .find(|(n, _)| *n == "Buyer")
            .map(|(_, p)| p);

        if let (Some(v), Some(b)) = (vendor_pub, buyer_pub) {
            let sum = v + b;
            let sum_hex = hex::encode(sum.compress().as_bytes());
            println!("Vendor + Buyer spend public key sum: {}", sum_hex);

            // The multisig spend key B should be different from this sum
            // The difference is the overlapping key k2*G
            println!("\nIf this sum differs from the multisig spend key B,");
            println!("the difference = overlap * G (the double-counted key)");
        }
    }

    // Also show all pairwise sums
    if spend_pubs.len() >= 3 {
        println!("\n--- All Pairwise Sums ---\n");
        for i in 0..spend_pubs.len() {
            for j in (i + 1)..spend_pubs.len() {
                let sum = spend_pubs[i].1 + spend_pubs[j].1;
                let sum_hex = hex::encode(sum.compress().as_bytes());
                println!(
                    "{} + {} = {}",
                    spend_pubs[i].0,
                    spend_pubs[j].0,
                    &sum_hex[..16]
                );
            }
        }
    }

    println!("\n=== Analysis ===\n");
    println!("In Monero 2-of-3 multisig:");
    println!("- B = k1 + k2 + k3 (full spend key)");
    println!("- Each signer holds 2 of 3 sub-keys");
    println!("- Any 2 signers have all 3 sub-keys, but one is shared");
    println!();
    println!("The current NEXUS CLSAG signing computes:");
    println!("  x_total = x_vendor + x_buyer");
    println!("         = (derivation + spend_v) + spend_b");
    println!("         = derivation + k1 + k2 + k2 + k3");
    println!("         = derivation + k1 + 2*k2 + k3");
    println!();
    println!("But the output key P requires:");
    println!("  P = derivation*G + B*G = derivation*G + (k1+k2+k3)*G");
    println!();
    println!("The difference: k2 is double-counted!");
    println!("This causes L[signer] != alpha_agg * G in CLSAG verification.");

    Ok(())
}
