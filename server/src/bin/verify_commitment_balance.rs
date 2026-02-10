//! Verify commitment balance: pseudo_out = sum(outPk) + fee * H

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

const H_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

fn hex_to_point(hex: &str) -> Option<EdwardsPoint> {
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 32 { return None; }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr).decompress()
}

fn main() {
    let pseudo_out_hex = "77cbf0f49d199728f0e23292eabaa45404b9a62e8272cb93d86965f88fd14365";
    let outpk0_hex = "6a607de0f35cdffe87a28f53f2cdddc6ad208aff5dd32d78556b64eb2e1f822c";
    let outpk1_hex = "7b2b45698c8866e994698af0348d70a63425b70dc4d79850b9151c461ecd001f";
    let fee: u64 = 44000000;

    println!("=== Commitment Balance Verification ===\n");

    let pseudo_out = hex_to_point(pseudo_out_hex).expect("Invalid pseudo_out");
    let outpk0 = hex_to_point(outpk0_hex).expect("Invalid outPk0");
    let outpk1 = hex_to_point(outpk1_hex).expect("Invalid outPk1");
    let h_point = CompressedEdwardsY(H_BYTES).decompress().expect("Invalid H");

    println!("pseudo_out: {}", pseudo_out_hex);
    println!("outPk[0]:   {}", outpk0_hex);
    println!("outPk[1]:   {}", outpk1_hex);
    println!("fee:        {} piconero\n", fee);

    // Compute: sum(outPk) + fee * H
    let fee_scalar = Scalar::from(fee);
    let fee_h = fee_scalar * h_point;
    let sum_out = outpk0 + outpk1;
    let expected = sum_out + fee_h;

    println!("fee * H:             {}", hex::encode(fee_h.compress().to_bytes()));
    println!("sum(outPk):          {}", hex::encode(sum_out.compress().to_bytes()));
    println!("sum(outPk) + fee*H:  {}", hex::encode(expected.compress().to_bytes()));
    println!("pseudo_out:          {}", pseudo_out_hex);

    let balance_ok = expected.compress() == pseudo_out.compress();
    println!("\nBalance check: {}", if balance_ok { "✅ BALANCED" } else { "❌ NOT BALANCED" });

    if !balance_ok {
        // Check what the difference is
        let diff = pseudo_out - expected;
        println!("Difference:          {}", hex::encode(diff.compress().to_bytes()));

        // Check negative difference
        let neg_diff = expected - pseudo_out;
        println!("Neg Difference:      {}", hex::encode(neg_diff.compress().to_bytes()));

        // Also check if maybe it's just outPk[0] + fee*H (single output case)
        let single_expected = outpk0 + fee_h;
        if single_expected.compress() == pseudo_out.compress() {
            println!("\nNOTE: pseudo_out = outPk[0] + fee*H (ignoring outPk[1])");
        }

        // Check what pseudo_out - outPk[0] - fee*H equals (should be outPk[1] if balanced)
        let remainder = pseudo_out - outpk0 - fee_h;
        println!("\npseudo - outPk[0] - fee*H = {}", hex::encode(remainder.compress().to_bytes()));
        println!("Expected outPk[1]:          {}", outpk1_hex);

        if remainder.compress() == outpk1.compress() {
            println!("✅ Actually balanced! (remainder matches outPk[1])");
        }
    }
}
