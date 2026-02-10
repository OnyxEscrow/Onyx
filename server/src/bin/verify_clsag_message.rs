#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case
)]
//! Verify CLSAG message computation (get_pre_mlsag_hash)
//!
//! Monero CLSAG signs a 32-byte message computed from:
//! 1. tx_prefix_hash
//! 2. Hash of range proofs (ss)
//! 3. Hash of pseudo_outs
//!
//! Reference: monero/src/ringct/rctSigs.cpp::get_pre_mlsag_hash

use sha3::{Digest, Keccak256};
use std::fs;

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

fn main() {
    println!("=== CLSAG Message Verification (get_pre_mlsag_hash) ===\n");

    // Read TX
    let tx_hex = fs::read_to_string("/tmp/frost_tx_01ffabd0.hex").expect("Failed to read TX");
    let tx = hex::decode(tx_hex.trim()).expect("Invalid hex");
    println!("TX size: {} bytes", tx.len());

    // Parse prefix to get tx_prefix_hash
    let mut pos = 0;
    let version = read_varint(&tx, &mut pos);
    let unlock_time = read_varint(&tx, &mut pos);
    let input_count = read_varint(&tx, &mut pos);

    println!("Version: {}", version);
    println!("Unlock time: {}", unlock_time);
    println!("Input count: {}", input_count);

    for _ in 0..input_count {
        let input_type = tx[pos];
        pos += 1;
        if input_type == 0x02 {
            let _amount = read_varint(&tx, &mut pos);
            let key_offset_count = read_varint(&tx, &mut pos);
            for _ in 0..key_offset_count {
                let _offset = read_varint(&tx, &mut pos);
            }
            pos += 32; // key image
        }
    }

    let output_count = read_varint(&tx, &mut pos);
    println!("Output count: {}", output_count);

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

    // Compute tx_prefix_hash
    let mut hasher = Keccak256::new();
    hasher.update(&tx[..prefix_end]);
    let tx_prefix_hash: [u8; 32] = hasher.finalize().into();
    println!("\n=== Component 1: tx_prefix_hash ===");
    println!("  {}", hex::encode(&tx_prefix_hash));

    // Parse RCT base
    let rct_type = tx[pos];
    pos += 1;
    let fee = read_varint(&tx, &mut pos);
    println!("\nRCT type: {} (should be 6 for BulletproofPlus)", rct_type);
    println!("Fee: {} atomic units", fee);

    // ecdhInfo (8 bytes per output for type 6)
    let ecdh_start = pos;
    pos += (output_count * 8) as usize;
    let ecdh_end = pos;
    println!("ecdhInfo: {} bytes", ecdh_end - ecdh_start);

    // outPk (32 bytes per output)
    let outpk_start = pos;
    pos += (output_count * 32) as usize;
    let outpk_end = pos;
    println!("outPk: {} bytes", outpk_end - outpk_start);

    let rct_base_end = pos;
    let prunable_start = pos;

    // Parse Bulletproof+
    let bp_count = read_varint(&tx, &mut pos);
    println!("\nBP+ count: {}", bp_count);

    let bp_start = pos - 1; // include the count varint
    for _ in 0..bp_count {
        pos += 192; // A, A1, B, r1, s1, d1
        let l_count = read_varint(&tx, &mut pos);
        pos += (l_count * 32) as usize;
        let r_count = read_varint(&tx, &mut pos);
        pos += (r_count * 32) as usize;
    }
    let bp_end = pos;
    println!("BP+ data: {} bytes", bp_end - bp_start);

    // CLSAG (16 * 32 for s-values + 32 for c1 + 32 for D)
    let clsag_start = pos;
    let ring_size = 16usize;
    pos += ring_size * 32; // s-values
    pos += 32; // c1
    pos += 32; // D
    let clsag_end = pos;
    println!("CLSAG data: {} bytes", clsag_end - clsag_start);

    // pseudo_outs (32 bytes per input)
    let pseudo_outs_start = pos;
    pos += (input_count * 32) as usize;
    let pseudo_outs_end = pos;
    println!("pseudo_outs: {} bytes", pseudo_outs_end - pseudo_outs_start);

    // === Compute get_pre_mlsag_hash ===
    // This is the actual message signed by CLSAG
    //
    // From Monero source (rctSigs.cpp::get_pre_mlsag_hash):
    // 1. Start with empty blob
    // 2. Hash tx_prefix_hash
    // 3. Hash ss (rctSigPrunable without clsag_ss - for RCT type 6, this is the BP+ data)
    // 4. Hash pseudo_outs

    println!("\n=== Computing get_pre_mlsag_hash ===");

    // ss = hash of rctSigPrunable EXCLUDING CLSAGs
    // For RCT type 6, this is just the BP+ data
    let ss_blob = &tx[prunable_start..clsag_start];
    println!("ss blob: {} bytes (BP+ only)", ss_blob.len());

    let mut ss_hasher = Keccak256::new();
    ss_hasher.update(ss_blob);
    let ss_hash: [u8; 32] = ss_hasher.finalize().into();
    println!("ss hash: {}", hex::encode(&ss_hash));

    // pseudo_outs hash
    let pseudo_outs_blob = &tx[pseudo_outs_start..pseudo_outs_end];
    let mut po_hasher = Keccak256::new();
    po_hasher.update(pseudo_outs_blob);
    let pseudo_outs_hash: [u8; 32] = po_hasher.finalize().into();
    println!("pseudo_outs hash: {}", hex::encode(&pseudo_outs_hash));

    // Final message = hash(sc_reduce(tx_prefix_hash) || hash_to_scalar(ss) || hash_to_scalar(pseudo_outs))
    // CRITICAL: Monero applies sc_reduce32 to each component before concatenating!
    use curve25519_dalek::scalar::Scalar;

    // hash0 = sc_reduce32(tx_prefix_hash) - NOT hash again, just reduce!
    let hash0 = Scalar::from_bytes_mod_order(tx_prefix_hash).to_bytes();
    // hash1 = hash_to_scalar(ss_blob) = sc_reduce32(cn_fast_hash(ss_blob))
    let hash1 = Scalar::from_bytes_mod_order(ss_hash).to_bytes();
    // hash2 = hash_to_scalar(pseudo_outs_blob) = sc_reduce32(cn_fast_hash(pseudo_outs_blob))
    let hash2 = Scalar::from_bytes_mod_order(pseudo_outs_hash).to_bytes();

    println!("\nhash0 (sc_reduce32(prefix)):     {}", hex::encode(&hash0));
    println!("hash1 (h2s(ss)):                 {}", hex::encode(&hash1));
    println!("hash2 (h2s(pseudo)):             {}", hex::encode(&hash2));

    let mut final_hasher = Keccak256::new();
    final_hasher.update(&hash0);
    final_hasher.update(&hash1);
    final_hasher.update(&hash2);
    let mlsag_message: [u8; 32] = final_hasher.finalize().into();

    println!("\n=== CLSAG Message (get_pre_mlsag_hash) ===");
    println!("  {}", hex::encode(&mlsag_message));

    println!("\n=== Comparison ===");
    println!(
        "tx_prefix_hash used in signing: {}",
        hex::encode(&tx_prefix_hash)
    );
    println!(
        "Full CLSAG message should be:   {}",
        hex::encode(&mlsag_message)
    );

    if tx_prefix_hash == mlsag_message {
        println!("\n⚠️  They are the SAME - this is suspicious!");
    } else {
        println!("\n❌ They are DIFFERENT!");
        println!("   If signing was done with tx_prefix_hash instead of full message,");
        println!("   the signature will be valid internally but rejected by daemon.");
    }

    // Save the correct message for use in signing
    fs::write("/tmp/clsag_message.hex", hex::encode(&mlsag_message)).expect("Failed to write");
    println!("\nSaved correct CLSAG message to /tmp/clsag_message.hex");
}
