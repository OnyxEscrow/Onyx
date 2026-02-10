//! Verify TX commitment balance from the serialized TX hex
//! Checks: pseudo_out = sum(outPk) + fee * H

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
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

fn bytes_to_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    CompressedEdwardsY(arr).decompress()
}

fn main() {
    println!("=== TX Commitment Balance Verification ===\n");

    // Read TX
    let tx_hex = fs::read_to_string("/tmp/frost_tx_01ffabd0.hex").expect("Read TX");
    let tx = hex::decode(tx_hex.trim()).expect("Decode");
    println!("TX size: {} bytes", tx.len());

    // Parse prefix
    let mut pos = 0;
    let _version = read_varint(&tx, &mut pos);
    let _unlock_time = read_varint(&tx, &mut pos);
    let input_count = read_varint(&tx, &mut pos);
    println!("Input count: {}", input_count);

    // Skip inputs
    for _ in 0..input_count {
        let input_type = tx[pos]; pos += 1;
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

    // Skip outputs
    for _ in 0..output_count {
        let _amount = read_varint(&tx, &mut pos);
        let output_type = tx[pos]; pos += 1;
        if output_type == 0x03 {
            pos += 33; // key + view_tag
        } else if output_type == 0x02 {
            pos += 32; // key only
        }
    }

    // Skip extra
    let extra_len = read_varint(&tx, &mut pos);
    pos += extra_len as usize;
    let prefix_end = pos;
    println!("Prefix ends at: {}", prefix_end);

    // Parse RCT base
    let rct_type = tx[pos]; pos += 1;
    println!("RCT type: {}", rct_type);

    let fee = read_varint(&tx, &mut pos);
    println!("Fee: {} atomic units ({:.12} XMR)", fee, fee as f64 / 1e12);

    // ecdhInfo (8 bytes per output for RCT type 6)
    let ecdh_start = pos;
    pos += (output_count as usize) * 8;
    let ecdh_end = pos;
    println!("ecdhInfo: {} bytes at positions {}-{}", ecdh_end - ecdh_start, ecdh_start, ecdh_end);

    // outPk (32 bytes per output)
    let outpk_start = pos;
    let mut out_pk: Vec<EdwardsPoint> = Vec::new();
    for i in 0..output_count {
        let pk_bytes = &tx[pos..pos+32];
        let pk = bytes_to_point(pk_bytes).expect(&format!("Invalid outPk[{}]", i));
        out_pk.push(pk);
        println!("outPk[{}] at {}: {}", i, pos, hex::encode(pk_bytes));
        pos += 32;
    }
    let outpk_end = pos;
    println!("outPk: {} bytes at positions {}-{}", outpk_end - outpk_start, outpk_start, outpk_end);

    // Skip to pseudo_out (at end of TX)
    let pseudo_out_pos = tx.len() - 32;
    let pseudo_out_bytes = &tx[pseudo_out_pos..pseudo_out_pos+32];
    let pseudo_out = bytes_to_point(pseudo_out_bytes).expect("Invalid pseudo_out");
    println!("\npseudo_out at {}: {}", pseudo_out_pos, hex::encode(pseudo_out_bytes));

    // H generator (from Monero)
    let h_bytes: [u8; 32] = [
        0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
        0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
        0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
        0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
    ];
    let h_point = CompressedEdwardsY(h_bytes).decompress()
        .expect("Invalid H point");

    // Compute: expected_pseudo = sum(outPk) + fee * H
    let mut sum_outpk = out_pk[0];
    for i in 1..out_pk.len() {
        sum_outpk = sum_outpk + out_pk[i];
    }

    let fee_h = Scalar::from(fee) * h_point;
    let expected_pseudo = sum_outpk + fee_h;

    println!("\n=== Balance Check ===");
    println!("sum(outPk):        {}", hex::encode(sum_outpk.compress().as_bytes()));
    println!("fee * H:           {}", hex::encode(fee_h.compress().as_bytes()));
    println!("Expected pseudo:   {}", hex::encode(expected_pseudo.compress().as_bytes()));
    println!("Actual pseudo_out: {}", hex::encode(pseudo_out.compress().as_bytes()));

    if expected_pseudo.compress() == pseudo_out.compress() {
        println!("\n✅ Commitment balance VERIFIED!");
    } else {
        println!("\n❌ Commitment balance FAILED!");
        let diff = pseudo_out - expected_pseudo;
        println!("Difference: {}", hex::encode(diff.compress().as_bytes()));
    }

    // Also check that outPk matches expected (from the build output)
    println!("\n=== Sanity Checks ===");

    // Check if outPk are valid points (not identity)
    for (i, pk) in out_pk.iter().enumerate() {
        let is_identity = pk.compress().as_bytes() == &[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        if is_identity {
            println!("⚠️  outPk[{}] is identity point!", i);
        } else {
            println!("✅ outPk[{}] is valid non-identity point", i);
        }
    }

    // Check if pseudo_out is valid
    let pseudo_is_identity = pseudo_out.compress().as_bytes() == &[
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    if pseudo_is_identity {
        println!("⚠️  pseudo_out is identity point!");
    } else {
        println!("✅ pseudo_out is valid non-identity point");
    }
}
