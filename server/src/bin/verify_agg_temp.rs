use curve25519_dalek::edwards::CompressedEdwardsY;

fn main() {
    let buyer_pki = "7a3b937d06dceca37df6cf98ae035ac2139b404c99893fa6fe2e17079fb18216";
    let vendor_pki = "0cf5f88e1c2c24f1ae6e5a2e0c5eb0cd04ba20408547f3d95188f7b41f922b90";
    let arbiter_pki = "b04296cb65b219ca179b7838edf21d05cdb69d0742d0fb642a20d331531401fc";
    let stored_agg = "fdd5704caea535552eb58edf1565e7402db639c2b92dc7cf05f92b05449e6902";

    // Decode all PKIs
    let buyer_bytes: [u8; 32] = hex::decode(buyer_pki).unwrap().try_into().unwrap();
    let vendor_bytes: [u8; 32] = hex::decode(vendor_pki).unwrap().try_into().unwrap();
    let arbiter_bytes: [u8; 32] = hex::decode(arbiter_pki).unwrap().try_into().unwrap();

    // Decompress to points
    let buyer_point = CompressedEdwardsY(buyer_bytes)
        .decompress()
        .expect("buyer decompress");
    let vendor_point = CompressedEdwardsY(vendor_bytes)
        .decompress()
        .expect("vendor decompress");
    let arbiter_point = CompressedEdwardsY(arbiter_bytes)
        .decompress()
        .expect("arbiter decompress");

    // Test different combinations
    let buyer_vendor = buyer_point + vendor_point;
    let vendor_arbiter = vendor_point + arbiter_point;
    let buyer_arbiter = buyer_point + arbiter_point;
    let all_three = buyer_point + vendor_point + arbiter_point;

    let buyer_vendor_hex = hex::encode(buyer_vendor.compress().as_bytes());
    let vendor_arbiter_hex = hex::encode(vendor_arbiter.compress().as_bytes());
    let buyer_arbiter_hex = hex::encode(buyer_arbiter.compress().as_bytes());
    let all_three_hex = hex::encode(all_three.compress().as_bytes());

    println!("=== PKI AGGREGATION VERIFICATION ===");
    println!("Stored Aggregated: {}", stored_agg);
    println!();
    println!("buyer + vendor:   {}", buyer_vendor_hex);
    println!(
        "  MATCH? {}",
        if buyer_vendor_hex == stored_agg {
            "✅ YES"
        } else {
            "❌ NO"
        }
    );
    println!();
    println!("vendor + arbiter: {}", vendor_arbiter_hex);
    println!(
        "  MATCH? {}",
        if vendor_arbiter_hex == stored_agg {
            "✅ YES (BUG!)"
        } else {
            "❌ NO"
        }
    );
    println!();
    println!("buyer + arbiter:  {}", buyer_arbiter_hex);
    println!(
        "  MATCH? {}",
        if buyer_arbiter_hex == stored_agg {
            "✅ YES (BUG!)"
        } else {
            "❌ NO"
        }
    );
    println!();
    println!("all three:        {}", all_three_hex);
    println!(
        "  MATCH? {}",
        if all_three_hex == stored_agg {
            "✅ YES (BUG! All 3 included!)"
        } else {
            "❌ NO"
        }
    );
}
