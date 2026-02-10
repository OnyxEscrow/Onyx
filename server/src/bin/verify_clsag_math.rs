#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case
)]
//! Verify CLSAG signature mathematically by recomputing the ring

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use monero_generators::hash_to_point;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use std::fs;
use tokio;

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
    // mu_P from CLSAG_agg_0
    let mut domain_agg_0 = [0u8; 32];
    domain_agg_0[..CLSAG_AGG_0.len()].copy_from_slice(CLSAG_AGG_0);

    let mut hasher = Keccak256::new();
    hasher.update(&domain_agg_0);
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

    // mu_C from CLSAG_agg_1
    let mut domain_agg_1 = [0u8; 32];
    domain_agg_1[..CLSAG_AGG_1.len()].copy_from_slice(CLSAG_AGG_1);

    let mut hasher = Keccak256::new();
    hasher.update(&domain_agg_1);
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
    _key_image: &EdwardsPoint, // NOT included in round hash
    _d_inv8: &EdwardsPoint,    // NOT included in round hash
    l_point: &EdwardsPoint,
    r_point: &EdwardsPoint,
) -> Scalar {
    let mut domain = [0u8; 32];
    domain[..CLSAG_DOMAIN.len()].copy_from_slice(CLSAG_DOMAIN);

    let mut hasher = Keccak256::new();
    hasher.update(&domain);
    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher.update(commitment.compress().as_bytes());
    }
    hasher.update(pseudo_out.compress().as_bytes());
    hasher.update(tx_prefix_hash);
    // NOTE: I and D are NOT in round hash (only in mu computation)
    hasher.update(l_point.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());

    Scalar::from_bytes_mod_order(hasher.finalize().into())
}

#[tokio::main]
async fn main() {
    println!("=== CLSAG Mathematical Verification ===\n");

    // Read and parse TX
    let tx_hex = fs::read_to_string("/tmp/frost_tx_01ffabd0.hex").expect("Failed to read TX");
    let tx = hex::decode(tx_hex.trim()).expect("Invalid hex");

    // Parse prefix to get tx_prefix_hash
    let mut pos = 0;
    let _version = read_varint(&tx, &mut pos);
    let _unlock_time = read_varint(&tx, &mut pos);
    let input_count = read_varint(&tx, &mut pos);

    let mut ring_indices = Vec::new();
    let mut key_image_pos = 0usize;
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
            key_image_pos = pos; // Save key image position
            pos += 32; // key image
        }
    }

    let output_count = read_varint(&tx, &mut pos);
    for _ in 0..output_count {
        let _amount = read_varint(&tx, &mut pos);
        let output_type = tx[pos];
        pos += 1;
        if output_type == 0x03 {
            pos += 33; // key + view_tag
        }
    }

    let extra_len = read_varint(&tx, &mut pos);
    pos += extra_len as usize;

    let prefix_end = pos;
    let mut hasher = Keccak256::new();
    hasher.update(&tx[..prefix_end]);
    let mut tx_prefix_hash = [0u8; 32];
    tx_prefix_hash.copy_from_slice(&hasher.finalize());

    println!("TX prefix hash: {}", hex::encode(&tx_prefix_hash));
    println!("Ring indices: {:?}", ring_indices);

    // Save rct_base start for CLSAG message computation
    let rct_base_start = pos;

    // Skip RCT base
    let _rct_type = tx[pos];
    pos += 1;
    let _fee = read_varint(&tx, &mut pos);
    pos += (output_count * 8) as usize; // ecdhInfo
    pos += (output_count * 32) as usize; // outPk

    // Parse BP+ and compute ss blob
    let prunable_start = pos;
    let bp_count = read_varint(&tx, &mut pos);
    for _ in 0..bp_count {
        pos += 192; // A, A1, B, r1, s1, d1
        let l_count = read_varint(&tx, &mut pos);
        pos += (l_count * 32) as usize;
        let r_count = read_varint(&tx, &mut pos);
        pos += (r_count * 32) as usize;
    }
    let bp_end = pos;

    println!("\nCLSAG starts at pos {}", pos);

    // Compute ss blob hash (BP+ data only, not CLSAGs)
    let ss_blob = &tx[prunable_start..bp_end];
    let mut ss_hasher = Keccak256::new();
    ss_hasher.update(ss_blob);
    let ss_hash: [u8; 32] = ss_hasher.finalize().into();

    // Parse CLSAG
    let ring_size = 16usize;
    let mut s_values = Vec::new();
    for i in 0..ring_size {
        let s = bytes_to_scalar(&tx[pos..pos + 32]);
        s_values.push(s);
        if i < 3 || i == ring_size - 1 {
            println!("s[{}]: {}...", i, &hex::encode(&tx[pos..pos + 32])[..16]);
        } else if i == 3 {
            println!("...");
        }
        pos += 32;
    }

    let c1 = bytes_to_scalar(&tx[pos..pos + 32]);
    println!("c1: {}", hex::encode(&tx[pos..pos + 32]));
    pos += 32;

    let d_inv8 = bytes_to_point(&tx[pos..pos + 32]).expect("Invalid D");
    println!("D (inv8): {}", hex::encode(&tx[pos..pos + 32]));
    pos += 32;

    // pseudo_out
    let pseudo_out_bytes = &tx[pos..pos + 32];
    let pseudo_out = bytes_to_point(pseudo_out_bytes).expect("Invalid pseudo_out");
    println!("pseudo_out: {}", hex::encode(pseudo_out_bytes));
    pos += 32;

    // Compute full CLSAG message (get_pre_mlsag_hash)
    // = cn_fast_hash(sc_reduce32(tx_prefix_hash) || sc_reduce32(cn_fast_hash(ss_blob)) || sc_reduce32(cn_fast_hash(pseudo_outs)))
    let mut po_hasher = Keccak256::new();
    po_hasher.update(pseudo_out_bytes);
    let pseudo_outs_hash: [u8; 32] = po_hasher.finalize().into();

    let hash0 = Scalar::from_bytes_mod_order(tx_prefix_hash).to_bytes(); // sc_reduce32(prefix)
    let hash1 = Scalar::from_bytes_mod_order(ss_hash).to_bytes(); // sc_reduce32(ss_hash)
    let hash2 = Scalar::from_bytes_mod_order(pseudo_outs_hash).to_bytes(); // sc_reduce32(pseudo_hash)

    let mut final_hasher = Keccak256::new();
    final_hasher.update(&hash0);
    final_hasher.update(&hash1);
    final_hasher.update(&hash2);
    let clsag_message: [u8; 32] = final_hasher.finalize().into();

    println!(
        "\nFull CLSAG message (get_pre_mlsag_hash): {}",
        hex::encode(&clsag_message)
    );

    // Key image from prefix (parsed dynamically earlier)
    let key_image =
        bytes_to_point(&tx[key_image_pos..key_image_pos + 32]).expect("Invalid key image");
    println!(
        "key_image (from TX at pos {}): {}",
        key_image_pos,
        hex::encode(&tx[key_image_pos..key_image_pos + 32])
    );

    // Fetch ring members
    println!("\nFetching ring members from daemon...");
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
        .expect("RPC failed")
        .json()
        .await
        .expect("JSON parse failed");

    let ring_keys: Vec<EdwardsPoint> = resp
        .outs
        .iter()
        .map(|o| hex_to_point(&o.key).expect("Invalid ring key"))
        .collect();
    let ring_commitments: Vec<EdwardsPoint> = resp
        .outs
        .iter()
        .map(|o| hex_to_point(&o.mask).expect("Invalid ring commitment"))
        .collect();

    println!("Ring size: {}", ring_keys.len());
    println!("Real position: 15 (known from TX creation)");

    // Compute mu_P and mu_C
    let (mu_p, mu_c) = compute_mu(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );
    println!("\nmu_P: {}...", &hex::encode(mu_p.to_bytes())[..16]);
    println!("mu_C: {}...", &hex::encode(mu_c.to_bytes())[..16]);

    // D = d_inv8 * 8 (recovering original D)
    let d_original = Scalar::from(8u64) * d_inv8;
    println!(
        "D_original: {}...",
        &hex::encode(d_original.compress().to_bytes())[..16]
    );

    // HP values
    let hp_values: Vec<EdwardsPoint> = ring_keys
        .iter()
        .map(|k| hash_to_point(k.compress().to_bytes()))
        .collect();

    // Verify ring starting from c1 at index 1
    // c[1] is the challenge going INTO index 1
    // We verify: compute L[1], R[1], then c[2] = H(..., L[1], R[1])
    // Continue around the ring until we get back to c[1]

    println!("\n=== Ring Verification ===");
    println!("Starting with c[1] = c1 from signature");

    let g = ED25519_BASEPOINT_POINT;

    let mut c_current = c1;
    for step in 0..ring_size {
        let i = (1 + step) % ring_size;

        let c_p = mu_p * c_current;
        let c_c = mu_c * c_current;

        // L[i] = s[i]*G + c_p*P[i] + c_c*(C[i] - pseudo_out)
        let commitment_diff = ring_commitments[i] - pseudo_out;
        let l_point = EdwardsPoint::multiscalar_mul(
            &[s_values[i], c_p, c_c],
            &[g, ring_keys[i], commitment_diff],
        );

        // R[i] = s[i]*Hp(P[i]) + c_p*I + c_c*D
        let r_point = EdwardsPoint::multiscalar_mul(
            &[s_values[i], c_p, c_c],
            &[hp_values[i], key_image, d_original],
        );

        // Compute c_next = H(..., L, R) using FULL CLSAG message
        let c_next = compute_challenge(
            &ring_keys,
            &ring_commitments,
            &pseudo_out,
            &clsag_message, // CRITICAL: Use full CLSAG message, not just tx_prefix_hash!
            &key_image,
            &d_inv8,
            &l_point,
            &r_point,
        );

        if step < 2 || step == ring_size - 1 {
            let next_idx = (i + 1) % ring_size;
            println!(
                "Step {}: i={}, compute c[{}] = {}...",
                step,
                i,
                next_idx,
                &hex::encode(c_next.to_bytes())[..16]
            );
        } else if step == 2 {
            println!("...");
        }

        c_current = c_next;
    }

    // After 16 steps, c_current should be c1 again
    let expected_c1_bytes = c1.to_bytes();
    let computed_c1_bytes = c_current.to_bytes();

    println!("\nRing closure check:");
    println!(
        "  Expected c1: {}...",
        &hex::encode(&expected_c1_bytes)[..16]
    );
    println!(
        "  Computed c1: {}...",
        &hex::encode(&computed_c1_bytes)[..16]
    );

    if expected_c1_bytes == computed_c1_bytes {
        println!("✅ CLSAG RING CLOSED SUCCESSFULLY!");
    } else {
        println!("❌ RING CLOSURE FAILED!");
        println!("  Full expected: {}", hex::encode(&expected_c1_bytes));
        println!("  Full computed: {}", hex::encode(&computed_c1_bytes));
    }
}
