//! Reverse engineer a VALID stagenet TX to understand exact CLSAG format
//!
//! 1. Fetch a recent valid TX from stagenet
//! 2. Parse its CLSAG signature
//! 3. Verify the signature using Monero's exact algorithm
//! 4. Compare with our implementation

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use monero_generators_mirror::hash_to_point;
use serde::Deserialize;
use sha3::{Digest, Keccak256};

/// Get daemon URL from environment or use default based on network
fn get_daemon_url() -> String {
    std::env::var("MONERO_DAEMON_URL").unwrap_or_else(|_| {
        let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        match network.as_str() {
            "mainnet" => "http://127.0.0.1:18081".to_string(),
            "testnet" => "http://127.0.0.1:28081".to_string(),
            _ => "http://stagenet.xmr-tw.org:38081".to_string(), // Public stagenet node
        }
    })
}

#[derive(Deserialize, Debug)]
struct TxPoolResponse {
    transactions: Option<Vec<TxInfo>>,
    status: String,
}

#[derive(Deserialize, Debug)]
struct TxInfo {
    tx_hash: String,
}

#[derive(Deserialize, Debug)]
struct GetTxResponse {
    txs: Option<Vec<TxData>>,
    status: String,
}

#[derive(Deserialize, Debug)]
struct TxData {
    tx_hash: String,
    as_hex: String,
    pruned_as_hex: Option<String>,
}

fn read_varint(data: &[u8], pos: &mut usize) -> u64 {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        if *pos >= data.len() {
            break;
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    result
}

fn read_point(data: &[u8], pos: &mut usize) -> EdwardsPoint {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    CompressedEdwardsY(arr).decompress().expect("Invalid point")
}

fn read_scalar(data: &[u8], pos: &mut usize) -> Scalar {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    Scalar::from_canonical_bytes(arr).unwrap_or(Scalar::from_bytes_mod_order(arr))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== REVERSE ENGINEERING VALID STAGENET TX ===\n");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    // Get a recent confirmed TX from stagenet (not from pool, from blockchain)
    // Use get_transactions with a known recent TX hash
    println!("Fetching recent block to get a valid TX...");

    // Get current height
    let daemon_url = get_daemon_url();
    let height_resp: serde_json::Value = client
        .post(format!("{}/json_rpc", daemon_url))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_block_count"
        }))
        .send()
        .await?
        .json()
        .await?;

    let height = height_resp["result"]["count"].as_u64().unwrap_or(0);
    println!("Current height: {}", height);

    // Get a recent block with transactions
    let mut tx_hash = String::new();
    for h in (height - 100..height).rev() {
        let block_resp: serde_json::Value = client
            .post(format!("{}/json_rpc", daemon_url))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_block",
                "params": {"height": h}
            }))
            .send()
            .await?
            .json()
            .await?;

        if let Some(txs) = block_resp["result"]["tx_hashes"].as_array() {
            if !txs.is_empty() {
                tx_hash = txs[0].as_str().unwrap_or("").to_string();
                println!("Found TX at height {}: {}", h, &tx_hash[..16]);
                break;
            }
        }
    }

    if tx_hash.is_empty() {
        println!("No transactions found in recent blocks");
        return Ok(());
    }

    // Fetch the full transaction
    println!("\nFetching full TX data...");
    let tx_resp: serde_json::Value = client
        .post(format!("{}/get_transactions", daemon_url))
        .json(&serde_json::json!({
            "txs_hashes": [&tx_hash],
            "decode_as_json": false
        }))
        .send()
        .await?
        .json()
        .await?;

    let tx_hex = tx_resp["txs"][0]["as_hex"].as_str().unwrap_or("");
    if tx_hex.is_empty() {
        println!("Failed to get TX hex");
        return Ok(());
    }

    println!(
        "TX hex length: {} chars ({} bytes)",
        tx_hex.len(),
        tx_hex.len() / 2
    );

    let tx = hex::decode(tx_hex)?;

    // Parse the transaction
    println!("\n=== PARSING TRANSACTION ===\n");
    let mut pos = 0;

    let version = read_varint(&tx, &mut pos);
    println!("Version: {}", version);

    let unlock_time = read_varint(&tx, &mut pos);
    println!("Unlock time: {}", unlock_time);

    // Inputs
    let input_count = read_varint(&tx, &mut pos);
    println!("Input count: {}", input_count);

    let mut key_images: Vec<[u8; 32]> = Vec::new();
    let mut ring_indices: Vec<Vec<u64>> = Vec::new();

    for i in 0..input_count {
        let input_type = tx[pos];
        pos += 1;
        if input_type == 0x02 {
            let amount = read_varint(&tx, &mut pos);
            let key_offset_count = read_varint(&tx, &mut pos);

            let mut offsets = Vec::new();
            let mut abs_offset = 0u64;
            for _ in 0..key_offset_count {
                let delta = read_varint(&tx, &mut pos);
                abs_offset += delta;
                offsets.push(abs_offset);
            }
            ring_indices.push(offsets.clone());

            let mut ki = [0u8; 32];
            ki.copy_from_slice(&tx[pos..pos + 32]);
            key_images.push(ki);
            pos += 32;

            println!(
                "Input {}: ring_size={}, key_image={}...",
                i,
                key_offset_count,
                hex::encode(&ki[..8])
            );
        }
    }

    // Outputs
    let output_count = read_varint(&tx, &mut pos);
    println!("Output count: {}", output_count);

    for i in 0..output_count {
        let amount = read_varint(&tx, &mut pos);
        let output_type = tx[pos];
        pos += 1;
        if output_type == 0x03 {
            // tagged key
            pos += 33; // pubkey + view_tag
        } else if output_type == 0x02 {
            pos += 32; // just pubkey
        }
    }

    // Extra
    let extra_len = read_varint(&tx, &mut pos);
    let extra_end = pos + extra_len as usize;
    pos = extra_end;
    println!("Extra length: {}", extra_len);

    // RCT base
    let rct_type = tx[pos];
    pos += 1;
    println!("RCT type: {} (6=BulletproofPlus)", rct_type);

    if rct_type == 0 {
        println!("No RCT data");
        return Ok(());
    }

    let fee = read_varint(&tx, &mut pos);
    println!("Fee: {} atomic", fee);

    // ecdhInfo
    for _ in 0..output_count {
        pos += 8; // encrypted amount
    }

    // outPk (commitments)
    let mut output_commitments: Vec<EdwardsPoint> = Vec::new();
    for i in 0..output_count {
        let point = read_point(&tx, &mut pos);
        output_commitments.push(point);
        println!("outPk[{}]: {}", i, hex::encode(point.compress().as_bytes()));
    }

    // RCT prunable
    println!("\n=== RCT PRUNABLE (CLSAG) ===\n");

    // BP+ count
    let bp_count = read_varint(&tx, &mut pos);
    println!("BP+ count: {}", bp_count);

    // Skip BP+ data (A, A1, B, r1, s1, d1, L[], R[])
    pos += 32 * 6; // A, A1, B, r1, s1, d1
    let l_count = read_varint(&tx, &mut pos);
    pos += 32 * l_count as usize;
    let r_count = read_varint(&tx, &mut pos);
    pos += 32 * r_count as usize;
    println!("BP+ L/R counts: {}/{}", l_count, r_count);

    // CLSAG signatures (one per input)
    println!("\n=== CLSAG SIGNATURES ===");
    for i in 0..input_count as usize {
        let ring_size = ring_indices[i].len();
        println!("\nCLSAG[{}] (ring_size={}):", i, ring_size);

        // s values
        let mut s_values: Vec<Scalar> = Vec::new();
        for j in 0..ring_size {
            let s = read_scalar(&tx, &mut pos);
            s_values.push(s);
            if j < 2 || j == ring_size - 1 {
                println!("  s[{}]: {}", j, hex::encode(s.as_bytes()));
            }
        }

        // c1
        let c1 = read_scalar(&tx, &mut pos);
        println!("  c1: {}", hex::encode(c1.as_bytes()));

        // D
        let d_bytes: [u8; 32] = tx[pos..pos + 32].try_into().unwrap();
        pos += 32;
        let d_point = CompressedEdwardsY(d_bytes).decompress();
        println!(
            "  D: {} (valid: {})",
            hex::encode(&d_bytes),
            d_point.is_some()
        );

        // Now verify this CLSAG!
        println!("\n  === VERIFYING CLSAG[{}] ===", i);

        // Fetch ring members
        let indices = &ring_indices[i];
        let ring_resp: serde_json::Value = client
            .post(format!("{}/get_outs", daemon_url))
            .json(&serde_json::json!({
                "outputs": indices.iter().map(|idx| {
                    serde_json::json!({"amount": 0, "index": idx})
                }).collect::<Vec<_>>(),
                "get_txid": false
            }))
            .send()
            .await?
            .json()
            .await?;

        let mut ring_keys: Vec<EdwardsPoint> = Vec::new();
        let mut ring_commitments: Vec<EdwardsPoint> = Vec::new();

        if let Some(outs) = ring_resp["outs"].as_array() {
            for (j, out) in outs.iter().enumerate() {
                let key_hex = out["key"].as_str().unwrap_or("");
                let mask_hex = out["mask"].as_str().unwrap_or("");

                let key_bytes: [u8; 32] = hex::decode(key_hex)?.try_into().unwrap();
                let mask_bytes: [u8; 32] = hex::decode(mask_hex)?.try_into().unwrap();

                ring_keys.push(CompressedEdwardsY(key_bytes).decompress().unwrap());
                ring_commitments.push(CompressedEdwardsY(mask_bytes).decompress().unwrap());

                if j < 2 {
                    println!("  P[{}]: {}", j, &key_hex[..16]);
                }
            }
            println!("  ... {} ring members loaded", ring_keys.len());
        }

        // Key image
        let ki_bytes = key_images[i];
        let key_image = CompressedEdwardsY(ki_bytes).decompress().unwrap();
        println!("  Key Image: {}", hex::encode(&ki_bytes[..16]));

        // We need pseudo_out and message - skip verification for now, just show structure
        println!("  ✅ CLSAG structure parsed successfully");
    }

    // pseudo_outs
    println!("\n=== PSEUDO OUTPUTS ===");
    for i in 0..input_count as usize {
        let pseudo = read_point(&tx, &mut pos);
        println!(
            "pseudo_out[{}]: {}",
            i,
            hex::encode(pseudo.compress().as_bytes())
        );
    }

    println!("\n=== PARSE COMPLETE ===");
    println!("Remaining bytes: {}", tx.len() - pos);

    Ok(())
}
