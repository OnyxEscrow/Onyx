//! Verify ring offset encoding matches expected absolute indices

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
    let tx_hex = fs::read_to_string("/tmp/frost_tx_01ffabd0.hex").expect("Failed to read TX");
    let tx = hex::decode(tx_hex.trim()).expect("Invalid hex");

    // Parse to get ring offsets
    let mut pos = 0;
    let _version = read_varint(&tx, &mut pos);
    let _unlock_time = read_varint(&tx, &mut pos);
    let input_count = read_varint(&tx, &mut pos);

    for input_idx in 0..input_count {
        let input_type = tx[pos];
        pos += 1;

        if input_type == 0x02 {
            let _amount = read_varint(&tx, &mut pos);
            let key_offset_count = read_varint(&tx, &mut pos);

            println!("Input {}: {} key offsets", input_idx, key_offset_count);

            let mut absolute_idx = 0u64;
            let mut offsets = Vec::new();
            let mut absolutes = Vec::new();

            for i in 0..key_offset_count {
                let offset = read_varint(&tx, &mut pos);
                offsets.push(offset);
                absolute_idx += offset;
                absolutes.push(absolute_idx);
                println!("  [{}] offset={:8} -> absolute={}", i, offset, absolute_idx);
            }

            pos += 32; // skip key image

            // Expected absolute indices from our escrow
            let expected: Vec<u64> = vec![
                9610827, 9630869, 9636385, 9638860, 9641094, 9645904, 9647165, 9648564, 9650921,
                9652186, 9653759, 9655459, 9655591, 9661294, 9661666, 9672434,
            ];

            println!("\nVerification:");
            let mut all_match = true;
            for (i, (actual, expected)) in absolutes.iter().zip(expected.iter()).enumerate() {
                let status = if actual == expected { "✓" } else { "✗" };
                if actual != expected {
                    println!(
                        "  [{}] {} actual={} expected={}",
                        i, status, actual, expected
                    );
                    all_match = false;
                }
            }

            if all_match {
                println!(
                    "  ✅ All {} ring indices match expected values!",
                    absolutes.len()
                );
            } else {
                println!("  ❌ Ring index mismatch detected!");
            }
        }
    }
}
