//! Quick utility to validate view key matches address
//! Usage: cargo run --bin validate_view_key -- <view_key> <address>

use server::crypto::view_key::validate_view_key_matches_address;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <view_key_hex> <monero_address>", args[0]);
        eprintln!(
            "Example: {} 4b3bc2178a190ac1062b99f2326f27d561f6ace301cf4c6df0827b8580456c03 5664Q...",
            args[0]
        );
        std::process::exit(1);
    }

    let view_key = &args[1];
    let address = &args[2];

    println!("Validating view key matches address...");
    println!("View key: {}...", &view_key[..16]);
    println!("Address:  {}...", &address[..20]);

    match validate_view_key_matches_address(view_key, address) {
        Ok(true) => {
            println!("\n✅ VALID: View key matches address cryptographically");
        }
        Ok(false) => {
            println!("\n❌ INVALID: View key does NOT match address!");
            println!("The stored view key will not work for balance monitoring.");
            std::process::exit(1);
        }
        Err(e) => {
            println!("\n❌ ERROR: {e}");
            std::process::exit(2);
        }
    }
}
