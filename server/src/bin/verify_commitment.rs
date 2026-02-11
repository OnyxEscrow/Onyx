#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case
)]
//! Verify commitment mask against on-chain commitment
//!
//! Usage: cargo run --release --bin verify_commitment

use anyhow::{Context, Result};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

// H generator point (used for amount in Pedersen commitment)
// This is the "alternate base point" used in Monero
const H_POINT_HEX: &str = "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94";

fn main() -> Result<()> {
    println!("=== Commitment Verification Tool for Escrow 0f41a60e ===\n");

    // Escrow parameters from read_escrow output and daemon query
    let view_key_hex = "cf995e55e989984c8bc6722217e6be0f8687c2e796e3873cfe7a7fa0e6d00609";
    let tx_pub_key_hex = "c3725cf1289a79e3034cc7b9024ffcce704c347866c923f3b632ae6c3d28b5ce";
    let stored_mask_hex = "ad6986ba69aa4d94958005837d6f85269a31b49cd19a133702ab303b1d48f701";
    let amount: u64 = 3_000_000_000; // piconeros (0.003 XMR)

    // Multisig address: 53bU1FZE6Uc5EZQTjCD4L2LpsVXgTCJFHBqkfu1pWoYuXJULDvMdUBiCYXY4U6b39yaCEfjwbVRJiCaBf2BjebGXCyGtRGT

    // On-chain data from tx 2c5ad7a31c58e30e89877febd625affb1d276007f579023f79883067abaca4c9
    let commitment_0_hex = "1dfb0a88ccad1107afa7494d78d30b50794d325b23591c0112dc1f39879686b4";
    let commitment_1_hex = "2eb4939447851e5e8433e98949e686637588c1becded535a4b3fb088264f14d2";
    let view_tag_0 = 0x85u8;
    let view_tag_1 = 0xe2u8;
    let output_key_0 = "c763c6c49141b483d1a8655992ce10e143c9b1b20fced5331211b9e2e108540e";
    let output_key_1 = "2df29f09f81cb6520252dbd03757f8e50ff3d5cf7a32f28c03b497bd8afbbbff";
    let encrypted_amount_0_hex = "55c11175d57ca059";
    let encrypted_amount_1_hex = "e58447e6f969c022";
    let global_index_0 = 9647631u64;
    let global_index_1 = 9647632u64;

    println!("Input parameters:");
    println!("  View key:      {view_key_hex}");
    println!("  TX pub key:    {tx_pub_key_hex}");
    println!("  Stored mask:   {stored_mask_hex}");
    println!("  Amount:        {amount} piconeros (0.003 XMR)");
    println!();
    println!("On-chain transaction outputs:");
    println!(
        "  Output 0: key={output_key_0} view_tag={view_tag_0:02x} global_idx={global_index_0}"
    );
    println!(
        "  Output 1: key={output_key_1} view_tag={view_tag_1:02x} global_idx={global_index_1}"
    );
    println!();

    // Parse keys
    let view_key_bytes: [u8; 32] = hex::decode(view_key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid view key length"))?;
    let view_scalar = Scalar::from_bytes_mod_order(view_key_bytes);

    let tx_pub_bytes: [u8; 32] = hex::decode(tx_pub_key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid tx pub key length"))?;
    let tx_pub_point = CompressedEdwardsY(tx_pub_bytes)
        .decompress()
        .context("Failed to decompress tx_pub_key")?;

    // Parse H point
    let h_bytes: [u8; 32] = hex::decode(H_POINT_HEX)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid H point length"))?;
    let h_point = CompressedEdwardsY(h_bytes)
        .decompress()
        .context("Failed to decompress H point")?;

    // Compute shared derivation: D = 8 * view_priv * tx_pub_key
    let shared_point = view_scalar * tx_pub_point;
    let derivation = shared_point.mul_by_cofactor();
    let derivation_bytes = derivation.compress().to_bytes();

    println!("=== ECDH Derivation ===");
    println!("derivation = {}", hex::encode(derivation_bytes));
    println!();

    // Find which output belongs to us
    println!("=== Output Ownership Verification ===");

    // Decode multisig address to get spend public key
    // Address: 53bU1FZE6Uc5EZQTjCD4L2LpsVXgTCJFHBqkfu1pWoYuXJULDvMdUBiCYXY4U6b39yaCEfjwbVRJiCaBf2BjebGXCyGtRGT
    let multisig_address = "53bU1FZE6Uc5EZQTjCD4L2LpsVXgTCJFHBqkfu1pWoYuXJULDvMdUBiCYXY4U6b39yaCEfjwbVRJiCaBf2BjebGXCyGtRGT";
    let decoded_addr = monero_base58_decode(multisig_address);

    if decoded_addr.len() >= 65 {
        let spend_pub_bytes: [u8; 32] = decoded_addr[1..33].try_into().unwrap();
        let spend_pub_point = CompressedEdwardsY(spend_pub_bytes)
            .decompress()
            .context("Failed to decompress spend pubkey")?;

        println!(
            "Multisig address network: {} (24=stagenet)",
            decoded_addr[0]
        );
        println!("Multisig spend pubkey: {}", hex::encode(spend_pub_bytes));
        println!();

        // Check each output
        for output_idx in [0u64, 1] {
            println!("--- Testing output index {output_idx} ---");

            // 1. Compute derivation_to_scalar: Hs(derivation || varint(output_idx))
            let mut hasher = Keccak256::new();
            hasher.update(derivation_bytes);
            hasher.update(encode_varint(output_idx));
            let shared_secret: [u8; 32] = hasher.finalize().into();
            let scalar = Scalar::from_bytes_mod_order(shared_secret);

            println!("  shared_secret = {}", hex::encode(shared_secret));

            // 2. Check view_tag (first byte of shared_secret before reduce)
            let expected_view_tag = shared_secret[0];
            let onchain_view_tag = if output_idx == 0 {
                view_tag_0
            } else {
                view_tag_1
            };
            if expected_view_tag == onchain_view_tag {
                println!("  ✅ view_tag matches: {expected_view_tag:02x}");
            } else {
                println!(
                    "  ❌ view_tag mismatch: expected {expected_view_tag:02x}, onchain {onchain_view_tag:02x}"
                );
            }

            // 3. Derive expected one-time output key: P = Hs(...)*G + B
            let scalar_g = scalar * ED25519_BASEPOINT_POINT;
            let expected_output_key = scalar_g + spend_pub_point;
            let expected_output_key_hex = hex::encode(expected_output_key.compress().to_bytes());

            let onchain_output_key = if output_idx == 0 {
                output_key_0
            } else {
                output_key_1
            };
            if expected_output_key_hex == onchain_output_key {
                println!("  ✅ OUTPUT KEY MATCHES - This output belongs to us!");
            } else {
                println!("  ❌ output key doesn't match");
                println!("     expected: {expected_output_key_hex}");
                println!("     onchain:  {onchain_output_key}");
            }

            // 4. Derive amount decryption key: Hs("amount" || shared_secret)
            let mut amount_hasher = Keccak256::new();
            amount_hasher.update(b"amount");
            amount_hasher.update(scalar.as_bytes());
            let amount_factor: [u8; 32] = amount_hasher.finalize().into();

            // Decode encrypted amount (XOR with first 8 bytes)
            let encrypted_amount_hex = if output_idx == 0 {
                encrypted_amount_0_hex
            } else {
                encrypted_amount_1_hex
            };
            let encrypted_amount = hex::decode(encrypted_amount_hex)?;
            let mut decoded_bytes = [0u8; 8];
            for i in 0..8 {
                decoded_bytes[i] = encrypted_amount[i] ^ amount_factor[i];
            }
            let decoded_amount = u64::from_le_bytes(decoded_bytes);
            println!(
                "  decoded amount = {} piconeros ({} XMR)",
                decoded_amount,
                decoded_amount as f64 / 1e12
            );

            if decoded_amount == amount {
                println!("  ✅ AMOUNT MATCHES!");
            }

            // 5. Derive commitment mask: Hs("commitment_mask" || shared_secret)
            let mut mask_hasher = Keccak256::new();
            mask_hasher.update(b"commitment_mask");
            mask_hasher.update(scalar.as_bytes());
            let mask_bytes: [u8; 32] = mask_hasher.finalize().into();
            let mask_scalar = Scalar::from_bytes_mod_order(mask_bytes);
            let derived_mask_hex = hex::encode(mask_scalar.as_bytes());

            println!("  derived mask = {derived_mask_hex}");

            // 6. Verify commitment: C = mask*G + amount*H
            let amount_scalar = Scalar::from(amount);
            let commitment_point =
                (mask_scalar * ED25519_BASEPOINT_POINT) + (amount_scalar * h_point);
            let computed_commitment = hex::encode(commitment_point.compress().to_bytes());

            let onchain_commitment = if output_idx == 0 {
                commitment_0_hex
            } else {
                commitment_1_hex
            };
            println!("  computed commitment = {computed_commitment}");
            println!("  onchain commitment  = {onchain_commitment}");

            if computed_commitment == onchain_commitment {
                println!("  ✅✅✅ COMMITMENT MATCHES! This is our output!");
                println!();
                println!("***** CORRECT VALUES FOR ESCROW *****");
                println!("  funding_output_index = {output_idx}");
                println!(
                    "  funding_global_index = {}",
                    if output_idx == 0 {
                        global_index_0
                    } else {
                        global_index_1
                    }
                );
                println!("  funding_commitment_mask = {derived_mask_hex}");
                println!("*************************************");
            }

            println!();
        }
    }

    // Also show comparison with stored mask
    println!("=== Comparison with Stored Values ===");
    println!("Stored mask:           {stored_mask_hex}");
    println!("Currently stored output_index: 0");
    println!("Currently stored global_index: 9647632 (which is actually output 1!)");

    Ok(())
}

/// Derive commitment mask from view key and tx_pub_key (Monero formula)
fn derive_commitment_mask(
    view_key_priv_hex: &str,
    tx_pub_key_hex: &str,
    output_index: u64,
) -> Result<String> {
    // Parse view key
    let view_key_bytes: [u8; 32] = hex::decode(view_key_priv_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid view key"))?;
    let view_scalar = Scalar::from_bytes_mod_order(view_key_bytes);

    // Parse tx_pub_key
    let tx_pub_bytes: [u8; 32] = hex::decode(tx_pub_key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid tx pub key"))?;
    let tx_pub_point = CompressedEdwardsY(tx_pub_bytes)
        .decompress()
        .context("Failed to decompress tx_pub_key")?;

    // derivation = 8 * view_priv * tx_pub_key
    let cofactor = Scalar::from(8u64);
    let derivation_point = (cofactor * view_scalar) * tx_pub_point;
    let derivation_bytes = derivation_point.compress().to_bytes();

    // shared_secret = Hs(derivation || varint(output_index))
    let mut hasher = Keccak256::new();
    hasher.update(derivation_bytes);
    hasher.update(encode_varint(output_index));
    let shared_secret = hasher.finalize();

    // mask = Hs("commitment_mask" || shared_secret)
    let mut mask_hasher = Keccak256::new();
    mask_hasher.update(b"commitment_mask");
    mask_hasher.update(shared_secret);
    let mask = mask_hasher.finalize();

    // Reduce to scalar
    let mask_scalar = Scalar::from_bytes_mod_order(mask.into());

    Ok(hex::encode(mask_scalar.as_bytes()))
}

/// Encode u64 as varint
fn encode_varint(n: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut val = n;
    while val >= 0x80 {
        result.push((val as u8) | 0x80);
        val >>= 7;
    }
    result.push(val as u8);
    result
}

/// Monero Base58 alphabet
const MONERO_BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a Monero base58 address
fn monero_base58_decode(s: &str) -> Vec<u8> {
    fn base58_decode_block(block: &[u8]) -> Vec<u8> {
        let mut num: u128 = 0;
        for &ch in block {
            let idx = MONERO_BASE58_ALPHABET
                .iter()
                .position(|&c| c == ch)
                .expect("valid base58 char");
            num = num * 58 + idx as u128;
        }
        let out_len = match block.len() {
            11 => 8,
            7 => 5,
            6 => 4,
            5 => 3,
            4 => 2,
            3 => 1,
            _ => 8,
        };
        let mut result = Vec::with_capacity(out_len);
        for i in (0..out_len).rev() {
            result.push((num >> (i * 8)) as u8);
        }
        result
    }

    let bytes = s.as_bytes();
    let mut result = Vec::new();
    let full_blocks = bytes.len() / 11;
    let remainder = bytes.len() % 11;

    for i in 0..full_blocks {
        result.extend(base58_decode_block(&bytes[i * 11..(i + 1) * 11]));
    }
    if remainder > 0 {
        result.extend(base58_decode_block(&bytes[full_blocks * 11..]));
    }
    result
}
