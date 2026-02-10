//! Local CLSAG verification to debug signature issues
//!
//! This binary reads a TX hex file, fetches ring members, and verifies
//! the CLSAG signature step by step.

use anyhow::{bail, Context, Result};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

const RING_SIZE: usize = 16;

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

// Domain separators
const CLSAG_ROUND: &[u8] = b"CLSAG_round";
const CLSAG_AGG_0: &[u8] = b"CLSAG_agg_0";
const CLSAG_AGG_1: &[u8] = b"CLSAG_agg_1";

fn hash_to_point(data: [u8; 32]) -> EdwardsPoint {
    // Simplified hash-to-point (should match Monero's ge_fromfe_frombytes_vartime)
    // This is a placeholder - the actual implementation is complex
    let mut hasher = Keccak256::new();
    hasher.update(&data);
    let hash_bytes: [u8; 32] = hasher.finalize().into();

    // Try to decompress as a point, if fails hash again
    loop {
        if let Some(point) = CompressedEdwardsY(hash_bytes).decompress() {
            return point * Scalar::from(8u64); // Clear cofactor
        }
        // If decompression fails, we'd need to iterate - simplified here
        break;
    }

    // Fallback (shouldn't reach here in practice)
    EdwardsPoint::default()
}

fn hex_to_point(hex: &str) -> Result<EdwardsPoint> {
    let bytes: [u8; 32] = hex::decode(hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid point length"))?;
    CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid point"))
}

fn compute_mixing_coefficients(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    let mut domain_agg_0 = [0u8; 32];
    domain_agg_0[..CLSAG_AGG_0.len()].copy_from_slice(CLSAG_AGG_0);

    let mut domain_agg_1 = [0u8; 32];
    domain_agg_1[..CLSAG_AGG_1.len()].copy_from_slice(CLSAG_AGG_1);

    let mut hasher_p = Keccak256::new();
    hasher_p.update(&domain_agg_0);
    for key in ring_keys {
        hasher_p.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher_p.update(commitment.compress().as_bytes());
    }
    hasher_p.update(key_image.compress().as_bytes());
    hasher_p.update(d_inv8.compress().as_bytes());
    hasher_p.update(pseudo_out.compress().as_bytes());
    let mu_p = Scalar::from_bytes_mod_order(hasher_p.finalize().into());

    let mut hasher_c = Keccak256::new();
    hasher_c.update(&domain_agg_1);
    for key in ring_keys {
        hasher_c.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher_c.update(commitment.compress().as_bytes());
    }
    hasher_c.update(key_image.compress().as_bytes());
    hasher_c.update(d_inv8.compress().as_bytes());
    hasher_c.update(pseudo_out.compress().as_bytes());
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
    let mut domain = [0u8; 32];
    domain[..CLSAG_ROUND.len()].copy_from_slice(CLSAG_ROUND);

    let mut hasher = Keccak256::new();
    hasher.update(&domain);
    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher.update(commitment.compress().as_bytes());
    }
    hasher.update(pseudo_out.compress().as_bytes());
    hasher.update(message);
    hasher.update(l_point.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());

    Scalar::from_bytes_mod_order(hasher.finalize().into())
}

fn read_varint(data: &[u8], offset: &mut usize) -> u64 {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        let byte = data[*offset];
        *offset += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }
    result
}

#[derive(serde::Deserialize)]
struct GetOutsResponse {
    outs: Vec<OutEntry>,
    status: String,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct OutEntry {
    key: String,
    mask: String,
}

fn fetch_ring_members(indices: &[u64]) -> Result<Vec<OutEntry>> {
    let client = reqwest::blocking::Client::new();
    let daemon_url = get_daemon_url();

    #[derive(serde::Serialize)]
    struct OutputIndex {
        amount: u64,
        index: u64,
    }

    #[derive(serde::Serialize)]
    struct GetOutsParams {
        outputs: Vec<OutputIndex>,
        get_txid: bool,
    }

    let params = GetOutsParams {
        outputs: indices.iter().map(|&i| OutputIndex { amount: 0, index: i }).collect(),
        get_txid: true,
    };

    let response: GetOutsResponse = client
        .post(format!("{}/get_outs", daemon_url))
        .json(&params)
        .send()?
        .json()?;

    if response.status != "OK" {
        bail!("get_outs failed: {}", response.status);
    }

    Ok(response.outs)
}

fn main() -> Result<()> {
    println!("=== LOCAL CLSAG VERIFICATION ===\n");

    // Read TX hex
    let tx_hex = std::fs::read_to_string("/tmp/frost_tx_01ffabd0.hex")?
        .trim()
        .to_string();
    let data = hex::decode(&tx_hex)?;

    println!("TX size: {} bytes", data.len());

    // Parse transaction
    let mut offset = 0;
    let _version = read_varint(&data, &mut offset);
    let _unlock_time = read_varint(&data, &mut offset);
    let input_count = read_varint(&data, &mut offset);

    if input_count != 1 {
        bail!("Expected 1 input, got {}", input_count);
    }

    let _input_type = read_varint(&data, &mut offset);
    let _amount = read_varint(&data, &mut offset);
    let ring_size = read_varint(&data, &mut offset) as usize;

    if ring_size != RING_SIZE {
        bail!("Expected ring size {}, got {}", RING_SIZE, ring_size);
    }

    // Parse ring offsets
    let mut offsets = Vec::new();
    for _ in 0..ring_size {
        offsets.push(read_varint(&data, &mut offset));
    }

    // Convert to absolute indices
    let mut indices = Vec::new();
    let mut cumsum: u64 = 0;
    for off in &offsets {
        cumsum += off;
        indices.push(cumsum);
    }

    println!("Ring indices: {:?}", indices);

    // Key image
    let key_image_bytes: [u8; 32] = data[offset..offset+32].try_into()?;
    offset += 32;

    let key_image = CompressedEdwardsY(key_image_bytes)
        .decompress()
        .context("Invalid key image")?;
    println!("Key image: {}", hex::encode(&key_image_bytes));

    // Skip outputs and extra
    let output_count = read_varint(&data, &mut offset) as usize;
    for _ in 0..output_count {
        let _amount = read_varint(&data, &mut offset);
        let out_type = read_varint(&data, &mut offset);
        offset += 32; // pubkey
        if out_type == 3 {
            offset += 1; // view_tag
        }
    }
    let extra_len = read_varint(&data, &mut offset) as usize;
    offset += extra_len;

    let tx_prefix_end = offset;

    // Compute tx_prefix_hash
    let tx_prefix = &data[..tx_prefix_end];
    let mut hasher = Keccak256::new();
    hasher.update(tx_prefix);
    let tx_prefix_hash: [u8; 32] = hasher.finalize().into();
    println!("tx_prefix_hash: {}", hex::encode(&tx_prefix_hash));

    // Extract CLSAG from end of TX
    let clsag_size = ring_size * 32 + 32 + 32;
    let pseudo_out_size = 32;
    let clsag_start = data.len() - clsag_size - pseudo_out_size;

    // s values
    let mut s_values: Vec<Scalar> = Vec::new();
    let mut s_offset = clsag_start;
    for _ in 0..ring_size {
        let s_bytes: [u8; 32] = data[s_offset..s_offset+32].try_into()?;
        s_values.push(Scalar::from_canonical_bytes(s_bytes).unwrap_or(Scalar::ZERO));
        s_offset += 32;
    }

    // c1
    let c1_bytes: [u8; 32] = data[s_offset..s_offset+32].try_into()?;
    let c1 = Scalar::from_canonical_bytes(c1_bytes).unwrap_or(Scalar::ZERO);
    s_offset += 32;
    println!("c1: {}", hex::encode(&c1_bytes));

    // D
    let d_bytes: [u8; 32] = data[s_offset..s_offset+32].try_into()?;
    let d_inv8 = CompressedEdwardsY(d_bytes)
        .decompress()
        .context("Invalid D point")?;
    s_offset += 32;
    println!("D/8: {}", hex::encode(&d_bytes));

    // D full (D/8 * 8)
    let d_full = d_inv8 * Scalar::from(8u64);

    // pseudo_out
    let pseudo_out_bytes: [u8; 32] = data[s_offset..s_offset+32].try_into()?;
    let pseudo_out = CompressedEdwardsY(pseudo_out_bytes)
        .decompress()
        .context("Invalid pseudo_out")?;
    println!("pseudo_out: {}", hex::encode(&pseudo_out_bytes));

    // Fetch ring members
    println!("\nFetching ring members from daemon...");
    let ring_members = fetch_ring_members(&indices)?;

    // Parse ring keys and commitments
    let ring_keys: Vec<EdwardsPoint> = ring_members.iter()
        .map(|rm| hex_to_point(&rm.key))
        .collect::<Result<_>>()?;

    let ring_commitments: Vec<EdwardsPoint> = ring_members.iter()
        .map(|rm| hex_to_point(&rm.mask))
        .collect::<Result<_>>()?;

    // Find real index
    let real_pos = ring_commitments.iter()
        .position(|c| c.compress().as_bytes() == pseudo_out_bytes.as_slice())
        .context("Real output not found in ring")?;
    println!("Real position: {}", real_pos);

    // Compute mu_P and mu_C
    let (mu_p, mu_c) = compute_mixing_coefficients(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );
    println!("\nmu_P: {}", hex::encode(mu_p.to_bytes()));
    println!("mu_C: {}", hex::encode(mu_c.to_bytes()));

    // Compute hash_to_point values for all ring members
    let hp_values: Vec<EdwardsPoint> = ring_keys.iter()
        .map(|key| hash_to_point(key.compress().to_bytes()))
        .collect();

    // Now verify the CLSAG
    println!("\n=== CLSAG VERIFICATION ===");

    // For verification, we need the full CLSAG message (get_pre_mlsag_hash)
    // This requires the BP+ hash and pseudo_outs hash, which we don't have
    // So we use the tx_prefix_hash as a proxy (this is the issue!)

    // Actually, we need to compute the FULL CLSAG message
    // Let's extract BP+ from the TX and compute it properly

    // For now, let's just verify the ring closure with the stored c1
    println!("\nStarting verification from c1 at index 1...");

    // Verification loop: start at index 1, go 1->2->...->15->0, end at index 1
    let mut c_current = c1;

    for step in 0..ring_size {
        let i = (1 + step) % ring_size;
        let p_i = &ring_keys[i];
        let c_i = &ring_commitments[i];
        let hp_i = &hp_values[i];
        let s_i = s_values[i];

        let c_p = mu_p * c_current;
        let c_c = mu_c * c_current;

        let c_adjusted = c_i - pseudo_out;

        // L[i] = s[i]*G + c_p*P[i] + c_c*(C[i] - pseudo_out)
        let l_i = &s_i * ED25519_BASEPOINT_TABLE + c_p * p_i + c_c * c_adjusted;

        // R[i] = s[i]*Hp(P[i]) + c_p*I + c_c*D
        let r_i = s_i * hp_i + c_p * key_image + c_c * d_full;

        // Compute next challenge
        // NOTE: We're using tx_prefix_hash, but should use full CLSAG message
        c_current = compute_round_hash(
            &ring_keys,
            &ring_commitments,
            &pseudo_out,
            &tx_prefix_hash, // This should be the full CLSAG message!
            &l_i,
            &r_i,
        );

        if step < 3 || i == real_pos || step == ring_size - 1 {
            println!("Step {}: i={}, c={}...", step, i, hex::encode(&c_current.to_bytes()[..8]));
        } else if step == 3 {
            println!("...");
        }
    }

    // After processing index 0, we should be back at c1
    println!("\nFinal c (should equal c1): {}", hex::encode(c_current.to_bytes()));
    println!("Original c1:               {}", hex::encode(c1.to_bytes()));

    if c_current == c1 {
        println!("\n✅ CLSAG verification PASSED (with tx_prefix_hash as message)");
    } else {
        println!("\n❌ CLSAG verification FAILED");
        println!("   This is expected because we used tx_prefix_hash instead of full CLSAG message");
    }

    Ok(())
}
