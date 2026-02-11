use sha3::{Digest, Keccak256};
use std::fs;

fn read_varint(data: &[u8], pos: &mut usize) -> u64 {
    let mut result: u64 = 0;
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
    let hex = fs::read_to_string("/tmp/tx_debug_ef57f177-f873-40c3-a175-4ab87c195ad8.hex")
        .unwrap()
        .trim()
        .to_string();
    let data = hex::decode(&hex).unwrap();

    let mut pos = 0;
    let start = pos;

    // version + unlock_time
    let version = read_varint(&data, &mut pos);
    let unlock = read_varint(&data, &mut pos);
    println!("Version: {version}, Unlock: {unlock}");

    // vin
    let vin_count = read_varint(&data, &mut pos);
    println!("Vin count: {vin_count}");
    for _ in 0..vin_count {
        let in_type = data[pos];
        pos += 1;
        if in_type == 0x02 {
            let _amount = read_varint(&data, &mut pos);
            let offset_count = read_varint(&data, &mut pos);
            for _ in 0..offset_count {
                let _ = read_varint(&data, &mut pos);
            }
            pos += 32; // key_image
        }
    }

    // vout
    let vout_count = read_varint(&data, &mut pos);
    println!("Vout count: {vout_count}");
    for _ in 0..vout_count {
        let _amount = read_varint(&data, &mut pos);
        let out_type = data[pos];
        pos += 1;
        println!("  Output type: 0x{out_type:02x}");
        if out_type == 0x02 {
            pos += 32;
        } else if out_type == 0x03 {
            pos += 33;
        }
    }

    // extra
    let extra_len = read_varint(&data, &mut pos) as usize;
    println!("Extra len: {extra_len}");
    pos += extra_len;

    let tx_prefix = &data[start..pos];
    println!("TX prefix length: {} bytes", tx_prefix.len());
    println!(
        "TX prefix (first 50 bytes): {}",
        hex::encode(&tx_prefix[..50.min(tx_prefix.len())])
    );

    let mut hasher = Keccak256::new();
    hasher.update(tx_prefix);
    let hash: [u8; 32] = hasher.finalize().into();

    println!("\nComputed tx_prefix_hash: {}", hex::encode(hash));
    println!(
        "Expected:                f09c87e8e7d938bc8fbe8dd6b9c4464617708b3cd04945e0412623ab2bb60763"
    );
    println!(
        "Match: {}",
        if hex::encode(hash) == "f09c87e8e7d938bc8fbe8dd6b9c4464617708b3cd04945e0412623ab2bb60763" {
            "✅"
        } else {
            "❌"
        }
    );
}
