//! Verify TX prefix hash from saved TX file

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
    let tx_hex = fs::read_to_string("/tmp/frost_tx_01ffabd0.hex").expect("Failed to read TX file");
    let tx = hex::decode(tx_hex.trim()).expect("Invalid hex");

    println!("Total TX size: {} bytes", tx.len());

    // Parse TX prefix to find exact end position
    let mut pos = 0;

    // Version (varint)
    let version = read_varint(&tx, &mut pos);
    println!("Version: {version} (at pos {pos})");

    // Unlock time (varint)
    let unlock_time = read_varint(&tx, &mut pos);
    println!("Unlock time: {unlock_time} (at pos {pos})");

    // Input count (varint)
    let input_count = read_varint(&tx, &mut pos);
    println!("Input count: {input_count} (at pos {pos})");

    for i in 0..input_count {
        // Input type byte
        let input_type = tx[pos];
        pos += 1;
        println!("  Input {i} type: 0x{input_type:02x}");

        if input_type == 0x02 {
            // txin_to_key
            let amount = read_varint(&tx, &mut pos);
            println!("    Amount: {amount}");

            let key_offset_count = read_varint(&tx, &mut pos);
            println!("    Key offset count: {key_offset_count}");

            for j in 0..key_offset_count {
                let offset = read_varint(&tx, &mut pos);
                if j < 3 || j == key_offset_count - 1 {
                    println!("      Offset[{j}]: {offset}");
                } else if j == 3 {
                    println!("      ...");
                }
            }

            // Key image (32 bytes)
            let ki = &tx[pos..pos + 32];
            pos += 32;
            println!("    Key image: {}", hex::encode(ki));
        }
    }

    // Output count (varint)
    let output_count = read_varint(&tx, &mut pos);
    println!("Output count: {output_count} (at pos {pos})");

    for i in 0..output_count {
        let amount = read_varint(&tx, &mut pos);
        println!("  Output {i} amount: {amount}");

        let output_type = tx[pos];
        pos += 1;
        println!("    Type: 0x{output_type:02x}");

        if output_type == 0x03 {
            // txout_to_tagged_key: 32 byte key + 1 byte view_tag
            let key = &tx[pos..pos + 32];
            pos += 32;
            let view_tag = tx[pos];
            pos += 1;
            println!("    Key: {}...", &hex::encode(key)[..16]);
            println!("    View tag: 0x{view_tag:02x}");
        }
    }

    // Extra length (varint)
    let extra_len = read_varint(&tx, &mut pos);
    println!("Extra length: {extra_len} (at pos {pos})");

    // Extra bytes
    let extra = &tx[pos..pos + extra_len as usize];
    pos += extra_len as usize;
    println!("Extra: {}", hex::encode(extra));

    println!("\n=== TX PREFIX ENDS AT POSITION {pos} ===");

    // Hash the prefix
    let prefix = &tx[..pos];
    let mut hasher = Keccak256::new();
    hasher.update(prefix);
    let hash: [u8; 32] = hasher.finalize().into();

    println!("TX prefix hash: {}", hex::encode(hash));

    // Parse TX pubkey from extra
    if extra.len() >= 33 && extra[0] == 0x01 {
        println!("TX pubkey: {}", hex::encode(&extra[1..33]));
    }
}
