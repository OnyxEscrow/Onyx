//! Split DB encryption key into Shamir shares (3-of-5)
//!
//! This tool implements the key splitting phase of TM-002 mitigation.
//! It takes a 256-bit (32-byte) encryption key and splits it into 5 shares
//! where any 3 shares can reconstruct the original key.
//!
//! # Usage
//!
//! ```bash
//! # Interactive mode (recommended for security)
//! cargo run --bin split_key
//!
//! # Or with key from stdin
//! echo "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456" | cargo run --bin split_key
//!
//! # Or with key from file
//! cargo run --bin split_key < db_key.txt
//! ```
//!
//! # Security Notes
//!
//! - Key must be EXACTLY 32 bytes (256 bits)
//! - Shares are output to stdout in base64 format
//! - Original key should be securely deleted after splitting
//! - Store each share in a separate secure location
//!
//! # Example Output
//!
//! ```text
//! Shamir Secret Sharing - Key Split Tool
//! ======================================
//!
//! Enter 256-bit key (32 bytes, hex or base64):
//! [user input]
//!
//! ✅ Successfully split key into 5 shares (threshold: 3)
//!
//! Share 1 (store in location A):
//! AQHvR2xhc3Ntb3JwaGlzbV9kYXJrX2RlczE2ODJfMjAyNQ==
//!
//! Share 2 (store in location B):
//! AgL8UmVjb3Zlcnlfc3lzdGVtX3YxLjBfYnVpbHRfMjAyNQ==
//!
//! [... shares 3-5 ...]
//!
//! ⚠️  IMPORTANT:
//! - Store each share in a SEPARATE secure location
//! - Any 3 shares can reconstruct the key
//! - Losing >2 shares = permanent key loss
//! - Securely DELETE the original key file
//! ```

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use server::crypto::shamir::split_key;
use std::io::{self, Write};

fn main() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  Shamir Secret Sharing - Key Split Tool (TM-002)          ║");
    println!("║  Split DB encryption key into 5 shares (3 required)       ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Read key from user
    print!("Enter 256-bit key (32 bytes, hex or base64): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;
    let input = input.trim();

    // Try to decode as hex first, then base64, then raw bytes
    let key_bytes = decode_key(input).context("Failed to decode key")?;

    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Key must be exactly 32 bytes (256 bits), got {} bytes",
            key_bytes.len()
        );
    }

    // Split into 5 shares, require 3
    let shares = split_key(&key_bytes, 5, 3).context("Failed to split key")?;

    println!("\n✅ Successfully split key into 5 shares (threshold: 3)\n");
    println!("═══════════════════════════════════════════════════════════\n");

    // Output shares with storage instructions
    let storage_locations = [
        "USB drive (home safe)",
        "Cloud storage (encrypted)",
        "Paper backup (fireproof safe)",
        "Trusted colleague/partner",
        "Bank safety deposit box",
    ];

    for (i, share) in shares.iter().enumerate() {
        let share_b64 = BASE64.encode(share);
        println!("📦 Share {} - Store in: {}", i + 1, storage_locations[i]);
        println!("   {share_b64}");
        println!();
    }

    println!("═══════════════════════════════════════════════════════════");
    println!("\n⚠️  CRITICAL SECURITY INSTRUCTIONS:\n");
    println!("1. Store each share in a SEPARATE, secure location");
    println!("2. Any 3 shares can reconstruct the full key");
    println!("3. Losing >2 shares = PERMANENT key loss (database unrecoverable)");
    println!("4. Individual shares reveal NO information about the key");
    println!("5. SECURELY DELETE the original key file after verification:");
    println!("   $ shred -uvz -n 5 db_key.txt");
    println!("\n6. Test reconstruction with 3 shares BEFORE deleting original:");
    println!("   $ cargo run --bin reconstruct_key\n");

    Ok(())
}

/// Decode key from hex, base64, or raw bytes
fn decode_key(input: &str) -> Result<Vec<u8>> {
    // Try hex first
    if let Ok(bytes) = hex::decode(input) {
        return Ok(bytes);
    }

    // Try base64
    if let Ok(bytes) = BASE64.decode(input) {
        return Ok(bytes);
    }

    // Try raw bytes (ASCII/UTF-8)
    let bytes = input.as_bytes().to_vec();
    if bytes.len() == 32 {
        return Ok(bytes);
    }

    anyhow::bail!(
        "Could not decode key. Expected:\n  \
         - 64 hex characters (e.g., a1b2c3...)\n  \
         - Base64 string (e.g., YWJjZGVm...)\n  \
         - Raw 32-byte ASCII string"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex() -> Result<()> {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let decoded = decode_key(hex_key)?;
        assert_eq!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn test_decode_base64() -> Result<()> {
        let key_bytes = b"test_encryption_key_32_bytes!!";
        let b64_key = BASE64.encode(key_bytes);
        let decoded = decode_key(&b64_key)?;
        assert_eq!(decoded, key_bytes);
        Ok(())
    }

    #[test]
    fn test_decode_raw() -> Result<()> {
        let raw_key = "test_encryption_key_32_bytes!!";
        let decoded = decode_key(raw_key)?;
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, raw_key.as_bytes());
        Ok(())
    }

    #[test]
    fn test_decode_invalid_length() {
        let short_key = "too_short";
        let result = decode_key(short_key);
        assert!(result.is_err());
    }
}
