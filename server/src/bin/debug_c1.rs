#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case
)]
//! Debug c1 computation by tracing the exact challenge chain

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use monero_generators::hash_to_point;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use std::fs;

const CLSAG_DOMAIN: &[u8] = b"CLSAG_round";
const CLSAG_AGG_0: &[u8] = b"CLSAG_agg_0";
const CLSAG_AGG_1: &[u8] = b"CLSAG_agg_1";

fn read_varint(data: &[u8], pos: &mut usize) -> u64 {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
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

fn hex_to_point(hex: &str) -> Option<EdwardsPoint> {
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr).decompress()
}

fn bytes_to_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    CompressedEdwardsY(arr).decompress()
}

fn bytes_to_scalar(bytes: &[u8]) -> Scalar {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Scalar::from_bytes_mod_order(arr)
}

#[derive(Deserialize)]
struct GetOutsResult {
    outs: Vec<OutEntry>,
}

#[derive(Deserialize, Clone)]
struct OutEntry {
    key: String,
    mask: String,
}

fn compute_mu(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    let mut domain_agg_0 = [0u8; 32];
    domain_agg_0[..CLSAG_AGG_0.len()].copy_from_slice(CLSAG_AGG_0);

    let mut hasher = Keccak256::new();
    hasher.update(domain_agg_0);
    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher.update(commitment.compress().as_bytes());
    }
    hasher.update(key_image.compress().as_bytes());
    hasher.update(d_inv8.compress().as_bytes());
    hasher.update(pseudo_out.compress().as_bytes());
    let mu_p = Scalar::from_bytes_mod_order(hasher.finalize().into());

    let mut domain_agg_1 = [0u8; 32];
    domain_agg_1[..CLSAG_AGG_1.len()].copy_from_slice(CLSAG_AGG_1);

    let mut hasher = Keccak256::new();
    hasher.update(domain_agg_1);
    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher.update(commitment.compress().as_bytes());
    }
    hasher.update(key_image.compress().as_bytes());
    hasher.update(d_inv8.compress().as_bytes());
    hasher.update(pseudo_out.compress().as_bytes());
    let mu_c = Scalar::from_bytes_mod_order(hasher.finalize().into());

    (mu_p, mu_c)
}

fn compute_challenge(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    pseudo_out: &EdwardsPoint,
    tx_prefix_hash: &[u8; 32],
    l_point: &EdwardsPoint,
    r_point: &EdwardsPoint,
) -> Scalar {
    let mut domain = [0u8; 32];
    domain[..CLSAG_DOMAIN.len()].copy_from_slice(CLSAG_DOMAIN);

    let mut hasher = Keccak256::new();
    hasher.update(domain);
    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher.update(commitment.compress().as_bytes());
    }
    hasher.update(pseudo_out.compress().as_bytes());
    hasher.update(tx_prefix_hash);
    // NOTE: I and D are NOT in round hash
    hasher.update(l_point.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());

    Scalar::from_bytes_mod_order(hasher.finalize().into())
}

#[tokio::main]
async fn main() {
    println!("=== Debug c1 Computation ===\n");

    // Read TX
    let tx_hex = fs::read_to_string("/tmp/frost_tx_01ffabd0.hex").expect("Read TX");
    let tx = hex::decode(tx_hex.trim()).expect("Decode TX");

    // Parse prefix
    let mut pos = 0;
    let _version = read_varint(&tx, &mut pos);
    let _unlock_time = read_varint(&tx, &mut pos);
    let input_count = read_varint(&tx, &mut pos);

    let mut ring_indices = Vec::new();
    for _ in 0..input_count {
        let input_type = tx[pos];
        pos += 1;
        if input_type == 0x02 {
            let _amount = read_varint(&tx, &mut pos);
            let key_offset_count = read_varint(&tx, &mut pos);
            let mut absolute_idx = 0u64;
            for _ in 0..key_offset_count {
                let offset = read_varint(&tx, &mut pos);
                absolute_idx += offset;
                ring_indices.push(absolute_idx);
            }
            pos += 32;
        }
    }

    let output_count = read_varint(&tx, &mut pos);
    for _ in 0..output_count {
        let _amount = read_varint(&tx, &mut pos);
        let output_type = tx[pos];
        pos += 1;
        if output_type == 0x03 {
            pos += 33;
        }
    }

    let extra_len = read_varint(&tx, &mut pos);
    pos += extra_len as usize;
    let prefix_end = pos;

    let mut hasher = Keccak256::new();
    hasher.update(&tx[..prefix_end]);
    let mut tx_prefix_hash = [0u8; 32];
    tx_prefix_hash.copy_from_slice(&hasher.finalize());
    println!("tx_prefix_hash: {}", hex::encode(tx_prefix_hash));

    // Skip RCT base
    let _rct_type = tx[pos];
    pos += 1;
    let _fee = read_varint(&tx, &mut pos);
    pos += (output_count * 8) as usize;
    pos += (output_count * 32) as usize;

    // Skip BP+
    let bp_count = read_varint(&tx, &mut pos);
    for _ in 0..bp_count {
        pos += 192;
        let l_count = read_varint(&tx, &mut pos);
        pos += (l_count * 32) as usize;
        let r_count = read_varint(&tx, &mut pos);
        pos += (r_count * 32) as usize;
    }

    // Parse CLSAG
    let ring_size = 16usize;
    let mut s_values = Vec::new();
    for _ in 0..ring_size {
        s_values.push(bytes_to_scalar(&tx[pos..pos + 32]));
        pos += 32;
    }

    let c1 = bytes_to_scalar(&tx[pos..pos + 32]);
    println!("c1 from TX: {}", hex::encode(&tx[pos..pos + 32]));
    pos += 32;

    let d_inv8 = bytes_to_point(&tx[pos..pos + 32]).expect("D");
    pos += 32;

    let pseudo_out = bytes_to_point(&tx[pos..pos + 32]).expect("pseudo_out");

    let key_image_hex = "519fb41ca66e83829266552db6d7d57f421282611a3fe643bcc82d435275b18a";
    let key_image = hex_to_point(key_image_hex).expect("key image");

    // Fetch ring
    let client = reqwest::Client::new();
    let params = serde_json::json!({
        "outputs": ring_indices.iter().map(|&i| serde_json::json!({"amount": 0, "index": i})).collect::<Vec<_>>(),
        "get_txid": false
    });

    let resp: GetOutsResult = client
        .post("http://stagenet.xmr-tw.org:38081/get_outs")
        .json(&params)
        .send()
        .await
        .expect("RPC")
        .json()
        .await
        .expect("JSON");

    let ring_keys: Vec<EdwardsPoint> = resp
        .outs
        .iter()
        .map(|o| hex_to_point(&o.key).unwrap())
        .collect();
    let ring_commitments: Vec<EdwardsPoint> = resp
        .outs
        .iter()
        .map(|o| hex_to_point(&o.mask).unwrap())
        .collect();

    let (mu_p, mu_c) = compute_mu(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );
    println!("mu_P: {}", hex::encode(mu_p.to_bytes()));
    println!("mu_C: {}", hex::encode(mu_c.to_bytes()));

    let d_original = Scalar::from(8u64) * d_inv8;

    let hp_values: Vec<EdwardsPoint> = ring_keys
        .iter()
        .map(|k| hash_to_point(k.compress().to_bytes()))
        .collect();

    let g = ED25519_BASEPOINT_POINT;

    // Verify starting from c1 at index 1
    println!("\n=== Verification Loop ===");
    let real_index = 15usize;

    let mut c_current = c1;
    for step in 0..ring_size {
        let i = (1 + step) % ring_size;
        let next_i = (i + 1) % ring_size;

        let c_p = mu_p * c_current;
        let c_c = mu_c * c_current;

        let commitment_diff = ring_commitments[i] - pseudo_out;
        let l_point = EdwardsPoint::multiscalar_mul(
            &[s_values[i], c_p, c_c],
            &[g, ring_keys[i], commitment_diff],
        );
        let r_point = EdwardsPoint::multiscalar_mul(
            &[s_values[i], c_p, c_c],
            &[hp_values[i], key_image, d_original],
        );

        let c_next = compute_challenge(
            &ring_keys,
            &ring_commitments,
            &pseudo_out,
            &tx_prefix_hash,
            &l_point,
            &r_point,
        );

        if i == real_index || i == 0 || i == 1 {
            println!(
                "i={:2}: c_in={:.16}... L={:.16}... R={:.16}... c_out={:.16}...",
                i,
                hex::encode(c_current.to_bytes())[..16].to_string(),
                hex::encode(l_point.compress().as_bytes())[..16].to_string(),
                hex::encode(r_point.compress().as_bytes())[..16].to_string(),
                hex::encode(c_next.to_bytes())[..16].to_string()
            );
        }

        c_current = c_next;
    }

    println!("\nAfter full loop:");
    println!("  Expected c1: {}", hex::encode(c1.to_bytes()));
    println!("  Computed:    {}", hex::encode(c_current.to_bytes()));

    if c1.to_bytes() == c_current.to_bytes() {
        println!("✅ Ring closed!");
    } else {
        println!("❌ Ring FAILED!");
    }
}
