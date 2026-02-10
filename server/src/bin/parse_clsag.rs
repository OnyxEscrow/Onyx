//! Parse complete TX structure including CLSAG

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

    println!("=== FULL TX PARSE ===\n");
    println!("Total TX size: {} bytes\n", tx.len());

    // === TX PREFIX ===
    let mut pos = 0;

    let version = read_varint(&tx, &mut pos);
    let unlock_time = read_varint(&tx, &mut pos);
    let input_count = read_varint(&tx, &mut pos);

    println!("TX PREFIX:");
    println!("  Version: {}", version);
    println!("  Unlock time: {}", unlock_time);
    println!("  Input count: {}", input_count);

    for _ in 0..input_count {
        let input_type = tx[pos];
        pos += 1;

        if input_type == 0x02 {
            let _amount = read_varint(&tx, &mut pos);
            let key_offset_count = read_varint(&tx, &mut pos);

            for _ in 0..key_offset_count {
                let _offset = read_varint(&tx, &mut pos);
            }

            let ki = &tx[pos..pos+32];
            pos += 32;
            println!("  Key image: {}", hex::encode(ki));
        }
    }

    let output_count = read_varint(&tx, &mut pos);
    println!("  Output count: {}", output_count);

    for i in 0..output_count {
        let _amount = read_varint(&tx, &mut pos);
        let output_type = tx[pos];
        pos += 1;

        if output_type == 0x03 {
            let key = &tx[pos..pos+32];
            pos += 32;
            let view_tag = tx[pos];
            pos += 1;
            println!("    Output {}: key={}..., view_tag=0x{:02x}", i, &hex::encode(key)[..16], view_tag);
        }
    }

    let extra_len = read_varint(&tx, &mut pos);
    let extra = &tx[pos..pos + extra_len as usize];
    pos += extra_len as usize;

    let prefix_end = pos;
    println!("  Extra ({} bytes): {}", extra_len, hex::encode(extra));

    // Hash prefix
    let prefix = &tx[..prefix_end];
    let mut hasher = Keccak256::new();
    hasher.update(prefix);
    let prefix_hash: [u8; 32] = hasher.finalize().into();
    println!("\n  TX PREFIX HASH: {}", hex::encode(&prefix_hash));

    // === RCT BASE ===
    println!("\nRCT BASE:");

    let rct_type = tx[pos];
    pos += 1;
    println!("  RCT type: {} (BulletproofPlus)", rct_type);

    let fee = read_varint(&tx, &mut pos);
    println!("  Fee: {} atomic units ({:.12} XMR)", fee, fee as f64 / 1e12);

    // ecdhInfo (2 outputs = 2 * 8 bytes = 16 bytes)
    println!("  ecdhInfo:");
    for i in 0..output_count {
        let ecdh = &tx[pos..pos+8];
        pos += 8;
        println!("    [{}]: {}", i, hex::encode(ecdh));
    }

    // outPk (2 outputs = 2 * 32 bytes = 64 bytes)
    println!("  outPk:");
    for i in 0..output_count {
        let outpk = &tx[pos..pos+32];
        pos += 32;
        println!("    [{}]: {}", i, hex::encode(outpk));
    }

    println!("\n  RCT BASE ends at pos {} (expected around 178+1+varints+16+64=262)", pos);

    // === RCT PRUNABLE ===
    println!("\nRCT PRUNABLE (starts at pos {}):", pos);

    // Bulletproof Plus count
    let bp_count = read_varint(&tx, &mut pos);
    println!("  BP+ count: {} (pos={})", bp_count, pos);

    for bp_idx in 0..bp_count {
        let bp_start = pos;
        println!("  BP+[{}] starts at pos {}:", bp_idx, bp_start);

        // A (32 bytes)
        let a = &tx[pos..pos+32];
        pos += 32;
        println!("    A: {}... (pos={})", &hex::encode(a)[..16], pos);

        // A1 (32 bytes)
        let a1 = &tx[pos..pos+32];
        pos += 32;
        println!("    A1: {}... (pos={})", &hex::encode(a1)[..16], pos);

        // B (32 bytes)
        let b = &tx[pos..pos+32];
        pos += 32;
        println!("    B: {}... (pos={})", &hex::encode(b)[..16], pos);

        // r1 (32 bytes)
        let r1 = &tx[pos..pos+32];
        pos += 32;
        println!("    r1: {}... (pos={})", &hex::encode(r1)[..16], pos);

        // s1 (32 bytes)
        let s1 = &tx[pos..pos+32];
        pos += 32;
        println!("    s1: {}... (pos={})", &hex::encode(s1)[..16], pos);

        // d1 (32 bytes)
        let d1 = &tx[pos..pos+32];
        pos += 32;
        println!("    d1: {}... (pos={})", &hex::encode(d1)[..16], pos);

        // L array - count then points
        let l_count = read_varint(&tx, &mut pos);
        println!("    L count: {} (pos={})", l_count, pos);
        for i in 0..l_count {
            let l = &tx[pos..pos+32];
            pos += 32;
            if i < 2 {
                println!("      L[{}]: {}...", i, &hex::encode(l)[..16]);
            }
        }
        println!("    After L: pos={}", pos);

        // R array - count then points
        let r_count = read_varint(&tx, &mut pos);
        println!("    R count: {} (pos={})", r_count, pos);
        for i in 0..r_count {
            let r = &tx[pos..pos+32];
            pos += 32;
            if i < 2 {
                println!("      R[{}]: {}...", i, &hex::encode(r)[..16]);
            }
        }
        println!("    After R: pos={}", pos);
        println!("    BP+[{}] size: {} bytes", bp_idx, pos - bp_start);
    }

    // For RCT type 6: NO CLSAG count varint - number of CLSAGs = number of BP+ = number of inputs
    // CLSAGs follow directly after BP+ section
    let clsag_count = input_count;
    println!("\n  CLSAGs (count=inputs={}): at pos {}", clsag_count, pos);

    for clsag_idx in 0..clsag_count {
        println!("  CLSAG[{}]:", clsag_idx);

        // s values - ring_size * 32 bytes (ring_size = key_offset_count from input = 16)
        let ring_size = 16u64; // We know this from parsing input
        println!("    s values ({} scalars):", ring_size);

        let mut s_values = Vec::new();
        for i in 0..ring_size {
            let s = &tx[pos..pos+32];
            pos += 32;
            s_values.push(hex::encode(s));
            if i < 3 || i == ring_size - 1 {
                println!("      s[{}]: {}", i, hex::encode(s));
            } else if i == 3 {
                println!("      ...");
            }
        }

        // c1 (32 bytes)
        let c1 = &tx[pos..pos+32];
        pos += 32;
        println!("    c1: {}", hex::encode(c1));

        // D (32 bytes)
        let d = &tx[pos..pos+32];
        pos += 32;
        println!("    D: {}", hex::encode(d));

        println!("    CLSAG ends at pos {}", pos);
    }

    // pseudo_outs (input_count * 32 bytes)
    println!("\n  pseudo_outs:");
    for i in 0..input_count {
        let pseudo_out = &tx[pos..pos+32];
        pos += 32;
        println!("    [{}]: {}", i, hex::encode(pseudo_out));
    }

    println!("\n=== PARSE COMPLETE ===");
    println!("Parsed {} of {} bytes", pos, tx.len());

    if pos != tx.len() {
        println!("⚠️  {} unparsed bytes remaining!", tx.len() - pos);
        println!("Remaining: {}", hex::encode(&tx[pos..]));
    } else {
        println!("✅ All bytes parsed correctly");
    }
}
