//! Verify key image derivation step by step

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use monero_generators_mirror::hash_to_point;

fn main() {
    println!("=== Key Image Derivation Verification ===\n");

    // From the escrow data:
    // buyer_share = 285f8c87f4e6f31a1ec5b02ba5458e2f7c27c41409c14c396acdbefdd0407e00
    // vendor_share = 56a3f4d573cfe58fd1e9fe656861dad243263c3b7338acb340493e6ffd4dd109
    // λ_buyer = 2, λ_vendor = -1

    let buyer_share_hex = "285f8c87f4e6f31a1ec5b02ba5458e2f7c27c41409c14c396acdbefdd0407e00";
    let vendor_share_hex = "56a3f4d573cfe58fd1e9fe656861dad243263c3b7338acb340493e6ffd4dd109";

    let buyer_share_bytes: [u8; 32] = hex::decode(buyer_share_hex).unwrap().try_into().unwrap();
    let vendor_share_bytes: [u8; 32] = hex::decode(vendor_share_hex).unwrap().try_into().unwrap();

    let s_buyer = Scalar::from_canonical_bytes(buyer_share_bytes).expect("Invalid buyer scalar");
    let s_vendor = Scalar::from_canonical_bytes(vendor_share_bytes).expect("Invalid vendor scalar");

    // λ_buyer = 2 (for participant index 1)
    // λ_vendor = -1 (for participant index 2)
    let two = Scalar::from(2u64);
    let minus_one = -Scalar::ONE;

    // x_total = λ_buyer * s_buyer + λ_vendor * s_vendor
    let x_total = two * s_buyer + minus_one * s_vendor;

    println!("s_buyer:  {}", buyer_share_hex);
    println!("s_vendor: {}", vendor_share_hex);
    println!("x_total:  {}", hex::encode(x_total.as_bytes()));

    // Verify P = x * G
    let p_computed = x_total * G;
    let p_expected_hex = "6c63c3deb753ca0b2059ffa634ad607247835a2e6c2e511639e893cc8f2b004b";

    println!(
        "\nP_computed: {}",
        hex::encode(p_computed.compress().as_bytes())
    );
    println!("P_expected: {}", p_expected_hex);

    let p_expected_bytes: [u8; 32] = hex::decode(p_expected_hex).unwrap().try_into().unwrap();
    let p_expected = CompressedEdwardsY(p_expected_bytes)
        .decompress()
        .expect("Invalid P");

    if p_computed.compress().as_bytes() == p_expected.compress().as_bytes() {
        println!("✅ x_total * G == P_expected");
    } else {
        println!("❌ x_total * G != P_expected");
        return;
    }

    // Key image = x * Hp(P)
    println!("\n=== Key Image Computation ===");
    let hp_p = hash_to_point(p_expected.compress().to_bytes());
    println!("Hp(P): {}", hex::encode(hp_p.compress().as_bytes()));

    let key_image = x_total * hp_p;
    println!(
        "KI = x * Hp(P): {}",
        hex::encode(key_image.compress().as_bytes())
    );

    let expected_ki_hex = "519fb41ca66e83829266552db6d7d57f421282611a3fe643bcc82d435275b18a";
    println!("Expected KI:    {}", expected_ki_hex);

    if hex::encode(key_image.compress().as_bytes()) == expected_ki_hex {
        println!("✅ Key image matches!");
    } else {
        println!("❌ Key image MISMATCH!");
    }

    // Also check using input point directly
    println!("\n=== Using Input P Directly ===");
    let hp_direct = hash_to_point(p_expected_bytes);
    println!(
        "Hp(P_bytes): {}",
        hex::encode(hp_direct.compress().as_bytes())
    );
    let ki_direct = x_total * hp_direct;
    println!(
        "KI direct:   {}",
        hex::encode(ki_direct.compress().as_bytes())
    );
}
