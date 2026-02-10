#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case
)]
//! Verify a REAL stagenet CLSAG - EXACT Monero format

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use monero_generators::hash_to_point;
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

// Domain separators - 32 bytes total (text + zero padding)
fn domain_round() -> [u8; 32] {
    let mut d = [0u8; 32];
    d[..11].copy_from_slice(b"CLSAG_round");
    d
}

fn domain_agg_0() -> [u8; 32] {
    let mut d = [0u8; 32];
    d[..11].copy_from_slice(b"CLSAG_agg_0");
    d
}

fn domain_agg_1() -> [u8; 32] {
    let mut d = [0u8; 32];
    d[..11].copy_from_slice(b"CLSAG_agg_1");
    d
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

fn read_bytes32(data: &[u8], pos: &mut usize) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    arr
}

fn read_point(data: &[u8], pos: &mut usize) -> EdwardsPoint {
    let arr = read_bytes32(data, pos);
    CompressedEdwardsY(arr).decompress().expect("Invalid point")
}

fn read_scalar(data: &[u8], pos: &mut usize) -> Scalar {
    let arr = read_bytes32(data, pos);
    Scalar::from_canonical_bytes(arr).unwrap_or(Scalar::from_bytes_mod_order(arr))
}

fn compute_aggregation_coefficients(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_point: &EdwardsPoint,
    c_offset: &EdwardsPoint, // pseudo_out (C_offset), NOT message!
) -> (Scalar, Scalar) {
    // mu_P = H_s(str_agg0 || P || C_nonzero || I || D || C_offset)
    let mut hasher_p = Keccak256::new();
    hasher_p.update(&domain_agg_0()); // 32 bytes with zero padding
    for key in ring_keys {
        hasher_p.update(key.compress().as_bytes());
    }
    for c in ring_commitments {
        hasher_p.update(c.compress().as_bytes());
    }
    hasher_p.update(key_image.compress().as_bytes());
    hasher_p.update(d_point.compress().as_bytes());
    hasher_p.update(c_offset.compress().as_bytes()); // pseudo_out point!
    let mu_p = Scalar::from_bytes_mod_order(hasher_p.finalize().into());

    // mu_C = H_s(str_agg1 || P || C_nonzero || I || D || C_offset)
    let mut hasher_c = Keccak256::new();
    hasher_c.update(&domain_agg_1()); // 32 bytes with zero padding
    for key in ring_keys {
        hasher_c.update(key.compress().as_bytes());
    }
    for c in ring_commitments {
        hasher_c.update(c.compress().as_bytes());
    }
    hasher_c.update(key_image.compress().as_bytes());
    hasher_c.update(d_point.compress().as_bytes());
    hasher_c.update(c_offset.compress().as_bytes()); // pseudo_out point!
    let mu_c = Scalar::from_bytes_mod_order(hasher_c.finalize().into());

    (mu_p, mu_c)
}

fn compute_round_hash(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    pseudo_out: &EdwardsPoint,
    message: &[u8; 32],
    l_point: &EdwardsPoint,
    r_point: &EdwardsPoint,
) -> Scalar {
    // c = H_s(str_round || P || C_nonzero || C_offset || m || L || R)
    let mut hasher = Keccak256::new();
    hasher.update(&domain_round()); // 32 bytes with zero padding
    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }
    for c in ring_commitments {
        hasher.update(c.compress().as_bytes());
    }
    hasher.update(pseudo_out.compress().as_bytes());
    hasher.update(message);
    hasher.update(l_point.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());
    Scalar::from_bytes_mod_order(hasher.finalize().into())
}

fn verify_clsag(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
    message: &[u8; 32],
    c1: &Scalar,
    s_values: &[Scalar],
    d_inv8: &EdwardsPoint,
) -> bool {
    let ring_size = ring_keys.len();
    let d_full = d_inv8 * Scalar::from(8u64);

    // CRITICAL: Aggregation coefficients use D/8 (as stored), NOT D*8!
    let (mu_p, mu_c) = compute_aggregation_coefficients(
        ring_keys,
        ring_commitments,
        key_image,
        d_inv8,
        pseudo_out, // Use d_inv8 (D/8)!
    );

    println!("    mu_P: {}", hex::encode(mu_p.as_bytes()));
    println!("    mu_C: {}", hex::encode(mu_c.as_bytes()));

    let hp_values: Vec<EdwardsPoint> = ring_keys
        .iter()
        .map(|key| hash_to_point(key.compress().to_bytes()))
        .collect();

    let mut c = *c1;

    for i in 0..ring_size {
        let c_p = mu_p * c;
        let c_c = mu_c * c;
        let c_adjusted = &ring_commitments[i] - pseudo_out;
        let l_i = &s_values[i] * ED25519_BASEPOINT_TABLE + c_p * &ring_keys[i] + c_c * c_adjusted;
        let r_i = &s_values[i] * &hp_values[i] + c_p * key_image + c_c * d_full;
        c = compute_round_hash(ring_keys, ring_commitments, pseudo_out, message, &l_i, &r_i);
        if i < 2 || i == ring_size - 1 {
            println!(
                "    c[{}→{}]: {}",
                i,
                (i + 1) % ring_size,
                hex::encode(c.as_bytes())
            );
        }
    }

    println!("    c_final: {}", hex::encode(c.as_bytes()));
    println!("    c1:      {}", hex::encode(c1.as_bytes()));
    c == *c1
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== VERIFYING REAL STAGENET CLSAG ===\n");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let height_resp: serde_json::Value = client
        .post(format!("{}/json_rpc", &get_daemon_url()))
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": "0", "method": "get_block_count"}))
        .send()
        .await?
        .json()
        .await?;
    let height = height_resp["result"]["count"].as_u64().unwrap_or(0);

    let mut full_tx_hash = String::new();
    for h in (height - 100..height).rev() {
        let block_resp: serde_json::Value = client.post(format!("{}/json_rpc", &get_daemon_url()))
            .json(&serde_json::json!({"jsonrpc": "2.0", "id": "0", "method": "get_block", "params": {"height": h}}))
            .send().await?.json().await?;
        if let Some(txs) = block_resp["result"]["tx_hashes"].as_array() {
            if !txs.is_empty() {
                full_tx_hash = txs[0].as_str().unwrap_or("").to_string();
                println!("TX from height {}: {}", h, &full_tx_hash);
                break;
            }
        }
    }

    let tx_resp: serde_json::Value = client
        .post(format!("{}/get_transactions", &get_daemon_url()))
        .json(&serde_json::json!({"txs_hashes": [&full_tx_hash], "decode_as_json": false}))
        .send()
        .await?
        .json()
        .await?;
    let tx_hex = tx_resp["txs"][0]["as_hex"].as_str().unwrap_or("");
    let tx = hex::decode(tx_hex)?;

    // Parse TX
    let mut pos = 0;
    let _version = read_varint(&tx, &mut pos);
    let _unlock_time = read_varint(&tx, &mut pos);

    let input_count = read_varint(&tx, &mut pos);
    let mut key_images: Vec<EdwardsPoint> = Vec::new();
    let mut ring_indices: Vec<Vec<u64>> = Vec::new();

    for _ in 0..input_count {
        let input_type = tx[pos];
        pos += 1;
        if input_type == 0x02 {
            let _ = read_varint(&tx, &mut pos);
            let key_offset_count = read_varint(&tx, &mut pos);
            let mut offsets = Vec::new();
            let mut abs = 0u64;
            for _ in 0..key_offset_count {
                abs += read_varint(&tx, &mut pos);
                offsets.push(abs);
            }
            ring_indices.push(offsets);
            key_images.push(read_point(&tx, &mut pos));
        }
    }

    let output_count = read_varint(&tx, &mut pos);
    for _ in 0..output_count {
        let _ = read_varint(&tx, &mut pos);
        let t = tx[pos];
        pos += 1;
        if t == 0x03 {
            pos += 33;
        } else if t == 0x02 {
            pos += 32;
        }
    }

    let extra_len = read_varint(&tx, &mut pos);
    pos += extra_len as usize;
    let prefix_end = pos;

    // hashes[0] = tx_prefix_hash
    let tx_prefix_hash: [u8; 32] = Keccak256::digest(&tx[..prefix_end]).into();
    println!("hashes[0] prefix: {}", hex::encode(&tx_prefix_hash));

    // RCT base
    let rct_base_start = pos;
    let rct_type = tx[pos];
    pos += 1;
    let _fee = read_varint(&tx, &mut pos);
    for _ in 0..output_count {
        pos += 8;
    } // ecdhInfo
    let mut output_commitments: Vec<EdwardsPoint> = Vec::new();
    for _ in 0..output_count {
        output_commitments.push(read_point(&tx, &mut pos));
    }
    let rct_base_end = pos;

    // hashes[1] = hash(rctSigBase)
    let rct_base_hash: [u8; 32] = Keccak256::digest(&tx[rct_base_start..rct_base_end]).into();
    println!("hashes[1] rctBase: {}", hex::encode(&rct_base_hash));

    // BP+ - extract just the keys (no varints)
    let _bp_count = read_varint(&tx, &mut pos);

    // BP+ components as keyV (just 32-byte keys concatenated)
    let mut bp_kv: Vec<u8> = Vec::new();

    // A, A1, B, r1, s1, d1 (6 x 32 bytes)
    for _ in 0..6 {
        bp_kv.extend_from_slice(&read_bytes32(&tx, &mut pos));
    }

    // L vector
    let l_count = read_varint(&tx, &mut pos);
    for _ in 0..l_count {
        bp_kv.extend_from_slice(&read_bytes32(&tx, &mut pos));
    }

    // R vector
    let r_count = read_varint(&tx, &mut pos);
    for _ in 0..r_count {
        bp_kv.extend_from_slice(&read_bytes32(&tx, &mut pos));
    }

    // hashes[2] = cn_fast_hash(kv) where kv = concatenation of BP+ keys
    let bp_hash: [u8; 32] = Keccak256::digest(&bp_kv).into();
    println!(
        "hashes[2] BP+ kv: {} ({} keys)",
        hex::encode(&bp_hash),
        bp_kv.len() / 32
    );

    // get_pre_mlsag_hash - CRITICAL: NO sc_reduce32 on input hashes!
    // cn_fast_hash(tx_prefix_hash || rctSigBase_hash || bp_kv_hash)
    // All three are raw 32-byte hashes, concatenated directly
    let clsag_message: [u8; 32] = Keccak256::new()
        .chain_update(&tx_prefix_hash) // raw 32 bytes
        .chain_update(&rct_base_hash) // raw 32 bytes
        .chain_update(&bp_hash) // raw 32 bytes
        .finalize()
        .into();
    println!("CLSAG msg: {}", hex::encode(&clsag_message));

    // Read CLSAGs
    let mut clsag_data: Vec<(Vec<Scalar>, Scalar, EdwardsPoint)> = Vec::new();
    for i in 0..input_count as usize {
        let ring_size = ring_indices[i].len();
        let mut s_values = Vec::new();
        for _ in 0..ring_size {
            s_values.push(read_scalar(&tx, &mut pos));
        }
        let c1 = read_scalar(&tx, &mut pos);
        let d_inv8 = read_point(&tx, &mut pos);
        clsag_data.push((s_values, c1, d_inv8));
    }

    // pseudo_outs
    let mut pseudo_outs: Vec<EdwardsPoint> = Vec::new();
    for _ in 0..input_count {
        pseudo_outs.push(read_point(&tx, &mut pos));
    }

    // Verify
    for i in 0..input_count as usize {
        println!("\n=== CLSAG[{}] ===", i);

        let ring_resp: serde_json::Value = client.post(format!("{}/get_outs", &get_daemon_url()))
            .json(&serde_json::json!({
                "outputs": ring_indices[i].iter().map(|idx| serde_json::json!({"amount": 0, "index": idx})).collect::<Vec<_>>(),
                "get_txid": false
            }))
            .send().await?.json().await?;

        let mut ring_keys: Vec<EdwardsPoint> = Vec::new();
        let mut ring_commitments: Vec<EdwardsPoint> = Vec::new();

        for out in ring_resp["outs"].as_array().unwrap_or(&vec![]) {
            let k: [u8; 32] = hex::decode(out["key"].as_str().unwrap_or(""))?
                .try_into()
                .unwrap();
            let m: [u8; 32] = hex::decode(out["mask"].as_str().unwrap_or(""))?
                .try_into()
                .unwrap();
            ring_keys.push(CompressedEdwardsY(k).decompress().unwrap());
            ring_commitments.push(CompressedEdwardsY(m).decompress().unwrap());
        }

        let (s, c1, d) = &clsag_data[i];
        println!("    D (inv8): {}", hex::encode(d.compress().as_bytes()));
        println!(
            "    pseudo_out: {}",
            hex::encode(pseudo_outs[i].compress().as_bytes())
        );
        println!(
            "    ring_commitment[15]: {}",
            hex::encode(ring_commitments[15].compress().as_bytes())
        );
        let valid = verify_clsag(
            &ring_keys,
            &ring_commitments,
            &key_images[i],
            &pseudo_outs[i],
            &clsag_message,
            c1,
            s,
            d,
        );
        println!("  {}", if valid { "✅ VERIFIED" } else { "❌ FAILED" });
    }

    Ok(())
}
