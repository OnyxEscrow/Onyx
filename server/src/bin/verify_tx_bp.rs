//! Verify Bulletproof+ range proof from TX

use curve25519_dalek::edwards::CompressedEdwardsY;
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
    println!("=== Bulletproof+ Verification ===\n");

    let tx_hex = fs::read_to_string("/tmp/frost_tx_01ffabd0.hex").expect("Failed to read TX");
    let tx = hex::decode(tx_hex.trim()).expect("Invalid hex");

    // Parse to find BP+ data and output commitments
    let mut pos = 0;
    let _version = read_varint(&tx, &mut pos);
    let _unlock_time = read_varint(&tx, &mut pos);
    let input_count = read_varint(&tx, &mut pos);

    for _ in 0..input_count {
        let input_type = tx[pos];
        pos += 1;
        if input_type == 0x02 {
            let _ = read_varint(&tx, &mut pos);
            let key_offset_count = read_varint(&tx, &mut pos);
            for _ in 0..key_offset_count {
                let _ = read_varint(&tx, &mut pos);
            }
            pos += 32; // key image
        }
    }

    let output_count = read_varint(&tx, &mut pos);
    println!("Output count: {}", output_count);

    for _ in 0..output_count {
        let _ = read_varint(&tx, &mut pos);
        let output_type = tx[pos];
        pos += 1;
        if output_type == 0x03 {
            pos += 33;
        }
    }

    let extra_len = read_varint(&tx, &mut pos);
    pos += extra_len as usize;

    // RCT base
    let rct_type = tx[pos];
    pos += 1;
    let _fee = read_varint(&tx, &mut pos);
    pos += (output_count * 8) as usize; // ecdhInfo

    // Extract output commitments
    println!("\n=== Output Commitments (outPk) ===");
    let mut output_commitments = Vec::new();
    for i in 0..output_count {
        let commitment = &tx[pos..pos + 32];
        output_commitments.push(commitment.to_vec());

        // Verify point is valid
        let mut arr = [0u8; 32];
        arr.copy_from_slice(commitment);
        match CompressedEdwardsY(arr).decompress() {
            Some(_) => println!("outPk[{}]: {} ✅ valid point", i, hex::encode(commitment)),
            None => println!(
                "outPk[{}]: {} ❌ INVALID POINT!",
                i,
                hex::encode(commitment)
            ),
        }
        pos += 32;
    }

    // BP+ starts here
    let bp_count = read_varint(&tx, &mut pos);
    println!("\n=== Bulletproof+ Data ===");
    println!("BP+ count: {}", bp_count);

    let bp_start = pos;

    // Parse BP+ structure
    // A (32), A1 (32), B (32), r1 (32), s1 (32), d1 (32) = 192 bytes
    let a_point = &tx[pos..pos + 32];
    pos += 32;
    let a1_point = &tx[pos..pos + 32];
    pos += 32;
    let b_point = &tx[pos..pos + 32];
    pos += 32;
    let r1_scalar = &tx[pos..pos + 32];
    pos += 32;
    let s1_scalar = &tx[pos..pos + 32];
    pos += 32;
    let d1_scalar = &tx[pos..pos + 32];
    pos += 32;

    println!("A:  {}", hex::encode(a_point));
    println!("A1: {}", hex::encode(a1_point));
    println!("B:  {}", hex::encode(b_point));
    println!("r1: {}", hex::encode(r1_scalar));
    println!("s1: {}", hex::encode(s1_scalar));
    println!("d1: {}", hex::encode(d1_scalar));

    // L and R vectors
    let l_count = read_varint(&tx, &mut pos);
    println!("L vector count: {}", l_count);
    for i in 0..l_count {
        let l = &tx[pos..pos + 32];
        if i < 2 {
            println!("  L[{}]: {}", i, hex::encode(l));
        }
        pos += 32;
    }

    let r_count = read_varint(&tx, &mut pos);
    println!("R vector count: {}", r_count);
    for i in 0..r_count {
        let r = &tx[pos..pos + 32];
        if i < 2 {
            println!("  R[{}]: {}", i, hex::encode(r));
        }
        pos += 32;
    }

    let bp_end = pos;
    println!(
        "\nBP+ total size: {} bytes (pos {} to {})",
        bp_end - bp_start,
        bp_start,
        bp_end
    );

    // Validate all BP+ points are on curve
    println!("\n=== Validating BP+ Points ===");
    for (name, bytes) in [("A", a_point), ("A1", a1_point), ("B", b_point)] {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        match CompressedEdwardsY(arr).decompress() {
            Some(_) => println!("{}: valid curve point ✅", name),
            None => println!("{}: INVALID POINT ❌", name),
        }
    }

    // Check if this looks like a valid BP+ (should have L/R counts matching)
    println!("\n=== Structure Check ===");
    if l_count == r_count {
        println!("L/R vector counts match: {} ✅", l_count);
    } else {
        println!("L/R vector count mismatch: L={}, R={} ❌", l_count, r_count);
    }

    // For 2 outputs, we expect log2(64) = 6 rounds of inner product proof
    // Actually for BP+, it's log2(n*64) where n is number of outputs
    let expected_rounds = ((output_count as f64 * 64.0).log2()).ceil() as u64;
    println!(
        "Expected rounds for {} outputs: ~{}",
        output_count, expected_rounds
    );
    println!("Actual L/R count: {}", l_count);

    if l_count == expected_rounds {
        println!("Round count matches expected ✅");
    } else if l_count == 7 && output_count == 2 {
        // 2 outputs * 64 bits = 128, log2(128) = 7
        println!("Round count correct for 2 outputs (7 rounds for 128 bits) ✅");
    }
}
