//! Check if H generators match between our code and monero-generators

use monero_generators::H;

fn main() {
    println!("=== H Generator Comparison ===\n");

    // H from monero-generators
    let h_from_lib = H.compress().to_bytes();
    println!(
        "H from monero-generators: {}",
        hex::encode(&h_from_lib)
    );

    // H from our code
    let h_our: [u8; 32] = [
        0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0,
        0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c,
        0x1f, 0x94,
    ];
    println!("H from our code:                  {}", hex::encode(&h_our));

    if h_from_lib == h_our {
        println!("\n✅ H generators MATCH!");
    } else {
        println!("\n❌ H generators DON'T MATCH!");
        println!("This could cause commitment verification failures.");
    }
}
