pub mod core;         // nexus-crypto-core re-exports for gradual migration
pub mod crypto;
pub mod encrypted_relay;  // Phase 2: End-to-end encrypted relay for non-custodial signing
pub mod multisig_coordinator;
pub mod round_robin;  // Round-robin CLSAG signing for 2-of-3 multisig (v0.8.0)
pub mod clsag_debug;  // Debug instrumentation for CLSAG
pub mod frost_dkg;    // FROST DKG (RFC 9591) for 2-of-3 threshold CLSAG (v0.12.0)

#[cfg(test)]
mod test_vectors;     // CLSAG test vector validation (audit module)

// Re-export crypto functions for JavaScript
pub use crypto::{
    generate_monero_wallet,
    restore_wallet_from_seed,
    prepare_multisig_wasm,
    make_multisig_wasm,
    sign_multisig_tx_wasm,
    // New CLSAG signing functions (monero-clsag-mirror)
    compute_key_image,
    compute_partial_key_image,  // For multisig key image aggregation
    sign_clsag_wasm,            // For single-signer
    sign_clsag_partial_wasm,    // For 2-of-3 multisig (DEPRECATED - use round_robin)
    generate_nonce_commitment,  // MuSig2-style nonce generation (v0.9.0)
    SignInputData,
};

// Re-export round-robin signing functions (v0.8.0 - correct approach)
pub use round_robin::{
    create_partial_tx_wasm,     // Signer 1: Create partial TX
    complete_partial_tx_wasm,   // Signer 2: Complete signature
    verify_clsag_wasm,          // Verify CLSAG locally before broadcast (v0.8.1)
    dump_clsag_params_wasm,     // Dump params for external verification (v0.8.1)
    PartialTx,
    CompletedClsag,
    ClsagVerificationResult,
};

// Re-export FROST DKG functions (v0.12.0 - RFC 9591 threshold CLSAG)
pub use frost_dkg::{
    frost_dkg_part1,                    // DKG Round 1: Generate commitment
    frost_dkg_part2,                    // DKG Round 2: Compute secret shares
    frost_dkg_part3,                    // DKG Round 3: Finalize KeyPackage
    frost_extract_secret_share,         // Extract scalar from KeyPackage for CLSAG
    frost_compute_lagrange_coefficient, // Compute λ_i for threshold signing
    frost_role_to_index,                // Convert role string to participant index
    frost_derive_address,               // Derive Monero address from group_pubkey (v0.45.0)
    DkgRound1Result,
    DkgRound2Result,
    DkgFinalResult,
    FrostAddressResult,
};

// Re-export encrypted relay functions (Phase 2 - 100% non-custodial)
pub use encrypted_relay::{
    generate_ephemeral_keypair,
    encrypt_partial_signature,
    decrypt_partial_signature,
    create_encrypted_partial_for_relay,
    EphemeralKeypair,
    EncryptedPartialResult,
    DecryptedPartialResult,
    PartialSignatureData,
};

use bip39::Mnemonic;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

/// Network byte for Monero addresses
pub const MAINNET_ADDRESS_BYTE: u8 = 18;   // Mainnet addresses start with '4'
pub const TESTNET_ADDRESS_BYTE: u8 = 53;   // Testnet addresses start with '9'
pub const STAGENET_ADDRESS_BYTE: u8 = 24;  // Stagenet addresses start with '5'

/// Parse network string to network byte
/// Accepts: "mainnet", "stagenet", "testnet" (case insensitive)
pub fn network_string_to_byte(network: &str) -> Result<u8, String> {
    match network.to_lowercase().as_str() {
        "mainnet" | "main" => Ok(MAINNET_ADDRESS_BYTE),
        "stagenet" | "stage" => Ok(STAGENET_ADDRESS_BYTE),
        "testnet" | "test" => Ok(TESTNET_ADDRESS_BYTE),
        _ => Err(format!("Unknown network: {}. Use 'mainnet', 'stagenet', or 'testnet'", network)),
    }
}

/// Result structure returned to JavaScript
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletResult {
    pub seed: String,
    pub address: String,
    pub view_key_pub: String,
    pub spend_key_pub: String,
    pub spend_key_priv: String, // Required for signing (compute_partial_key_image, etc.)
    pub address_hash: String,
}

/// Generate a new Monero wallet from a random BIP39 seed
///
/// # Arguments
/// * `network` - Optional network: "mainnet", "stagenet", "testnet". Defaults to "mainnet".
#[wasm_bindgen]
pub fn generate_wallet(network: Option<String>) -> Result<JsValue, JsValue> {
    let network_str = network.as_deref().unwrap_or("mainnet");
    let network_byte = network_string_to_byte(network_str)
        .map_err(|e| JsValue::from_str(&e))?;
    // Generate 128-bit entropy for 12-word mnemonic
    // Uses getrandom with js feature -> crypto.getRandomValues()
    let mut entropy = [0u8; 16];  // 16 bytes = 128 bits = 12 words
    getrandom::getrandom(&mut entropy)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate entropy: {}", e)))?;

    // Create mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate mnemonic: {}", e)))?;

    let seed_phrase = mnemonic.words().collect::<Vec<&str>>().join(" ");

    // Use the original entropy for key derivation (16 bytes for 12 words)
    // We need to expand it to 32 bytes for spend key using SHA256
    let mut entropy_extended = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(entropy);
    hasher.update(b"monero_spend_key");  // Domain separation
    let extended: [u8; 32] = hasher.finalize().into();
    entropy_extended.copy_from_slice(&extended);

    // Create spend key from extended entropy
    let mut spend_key_bytes = [0u8; 32];
    spend_key_bytes.copy_from_slice(&entropy_extended);

    // Monero uses scalar reduction for ed25519
    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_bytes);
    let spend_key_bytes_reduced = spend_scalar.to_bytes();

    // View key is derived as Keccak256(spend_key) in Monero
    let mut view_key_hasher = Keccak256::new();
    view_key_hasher.update(spend_key_bytes_reduced);
    let view_key_hash: [u8; 32] = view_key_hasher.finalize().into();
    let view_scalar = Scalar::from_bytes_mod_order(view_key_hash);

    // Derive public keys (scalar * base point)
    let spend_public = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &spend_scalar;
    let view_public = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &view_scalar;

    // Convert public keys to bytes
    let spend_pub_bytes = spend_public.compress().to_bytes();
    let view_pub_bytes = view_public.compress().to_bytes();

    // Convert keys to hex (for response)
    let view_key_pub_hex = hex::encode(view_pub_bytes);
    let spend_key_pub_hex = hex::encode(spend_pub_bytes);
    let spend_key_priv_hex = hex::encode(spend_key_bytes_reduced);

    // Generate Monero address with specified network
    let address_string = generate_monero_address_with_network(&spend_pub_bytes, &view_pub_bytes, network_byte)
        .map_err(|e| JsValue::from_str(&format!("Address generation failed: {}", e)))?;

    // Compute address hash (SHA256 for server verification)
    let mut address_hasher = Sha256::new();
    address_hasher.update(address_string.as_bytes());
    let address_hash = hex::encode(address_hasher.finalize());

    // Construct result
    let result = WalletResult {
        seed: seed_phrase.clone(),
        address: address_string,
        view_key_pub: view_key_pub_hex,
        spend_key_pub: spend_key_pub_hex,
        spend_key_priv: spend_key_priv_hex,
        address_hash,
    };

    // SECURITY: Zeroize sensitive data before dropping
    entropy_extended.zeroize();
    spend_key_bytes.zeroize();
    drop(seed_phrase);

    // Serialize to JsValue
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Generate Monero address from public spend and view keys with explicit network byte
///
/// Monero address format:
/// Base58(network_byte || public_spend_key || public_view_key || checksum)
/// where checksum = Keccak256(network_byte || public_spend_key || public_view_key)[0..4]
///
/// Uses base58_monero::encode_check() which automatically appends the Keccak256 checksum
pub fn generate_monero_address_with_network(
    spend_pub: &[u8; 32],
    view_pub: &[u8; 32],
    network_byte: u8,
) -> Result<String, String> {
    // Construct address data: network_byte || spend_pub || view_pub (65 bytes)
    // The checksum will be added automatically by encode_check()
    let mut address_data = Vec::with_capacity(65);
    address_data.push(network_byte);
    address_data.extend_from_slice(spend_pub);
    address_data.extend_from_slice(view_pub);

    // Encode to Base58 with automatic Keccak256 checksum
    // encode_check() appends 4-byte checksum before encoding
    let address = base58_monero::encode_check(&address_data)
        .map_err(|e| format!("Base58 encoding failed: {}", e))?;

    Ok(address)
}

/// Generate Monero address (defaults to mainnet for production safety)
///
/// **DEPRECATED**: Use `generate_monero_address_with_network()` with explicit network byte.
pub fn generate_monero_address(spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> Result<String, String> {
    // Default to mainnet for production safety
    generate_monero_address_with_network(spend_pub, view_pub, MAINNET_ADDRESS_BYTE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_generate_wallet_structure() {
        // Test with default (mainnet)
        let result = generate_wallet(None).expect("Wallet generation failed");

        // Deserialize back to Rust for validation
        let wallet: WalletResult = serde_wasm_bindgen::from_value(result)
            .expect("Failed to deserialize");

        // Validate seed format (12 words separated by spaces)
        let words: Vec<&str> = wallet.seed.split_whitespace().collect();
        assert_eq!(words.len(), 12, "Seed must be 12 words");

        // Validate address format (Monero mainnet starts with '4')
        assert!(
            wallet.address.starts_with('4'),
            "Mainnet address must start with 4, got: {}",
            wallet.address.chars().next().unwrap_or('?')
        );

        // Validate hex key lengths
        assert_eq!(
            wallet.view_key_pub.len(),
            64,
            "Public view key must be 64 hex chars"
        );
        assert_eq!(
            wallet.spend_key_pub.len(),
            64,
            "Public spend key must be 64 hex chars"
        );
        assert_eq!(
            wallet.address_hash.len(),
            64,
            "SHA256 hash must be 64 hex chars"
        );

        // Validate hex encoding
        assert!(
            hex::decode(&wallet.view_key_pub).is_ok(),
            "Invalid view key hex"
        );
        assert!(
            hex::decode(&wallet.spend_key_pub).is_ok(),
            "Invalid spend key hex"
        );
        assert!(
            hex::decode(&wallet.address_hash).is_ok(),
            "Invalid address hash hex"
        );
    }

    #[wasm_bindgen_test]
    fn test_generate_wallet_stagenet() {
        // Test with explicit stagenet
        let result = generate_wallet(Some("stagenet".to_string())).expect("Wallet generation failed");

        let wallet: WalletResult = serde_wasm_bindgen::from_value(result)
            .expect("Failed to deserialize");

        // Validate stagenet address format (starts with '5')
        assert!(
            wallet.address.starts_with('5'),
            "Stagenet address must start with 5, got: {}",
            wallet.address.chars().next().unwrap_or('?')
        );
    }

    #[wasm_bindgen_test]
    fn test_generate_wallet_uniqueness() {
        // Generate two wallets and ensure they're different
        let result1 = generate_wallet(None).expect("First generation failed");
        let result2 = generate_wallet(None).expect("Second generation failed");

        let wallet1: WalletResult = serde_wasm_bindgen::from_value(result1).unwrap();
        let wallet2: WalletResult = serde_wasm_bindgen::from_value(result2).unwrap();

        assert_ne!(wallet1.seed, wallet2.seed, "Seeds must be unique");
        assert_ne!(wallet1.address, wallet2.address, "Addresses must be unique");
    }

    #[wasm_bindgen_test]
    fn test_address_hash_consistency() {
        let result = generate_wallet(None).expect("Generation failed");
        let wallet: WalletResult = serde_wasm_bindgen::from_value(result).unwrap();

        // Manually compute SHA256 and verify
        let mut hasher = Sha256::new();
        hasher.update(wallet.address.as_bytes());
        let expected_hash = hex::encode(hasher.finalize());

        assert_eq!(wallet.address_hash, expected_hash, "Address hash mismatch");
    }

    #[test]
    fn test_generate_monero_address_format() {
        // Test with known public keys (zeros for testing)
        let spend_pub = [0u8; 32];
        let view_pub = [0u8; 32];

        // Test mainnet (default)
        let address = generate_monero_address(&spend_pub, &view_pub)
            .expect("Address generation failed");

        // Should start with '4' for mainnet (default)
        assert!(address.starts_with('4'), "Mainnet address should start with 4");

        // Should be valid Base58 with checksum
        let decoded = base58_monero::decode_check(&address)
            .expect("Address should be valid Base58 with checksum");

        // Decoded should be 65 bytes: 1 network + 32 spend + 32 view
        assert_eq!(decoded.len(), 65, "Decoded address should be 65 bytes");
        assert_eq!(decoded[0], MAINNET_ADDRESS_BYTE, "First byte should be mainnet byte");

        // Test stagenet explicitly
        let stagenet_address = generate_monero_address_with_network(&spend_pub, &view_pub, STAGENET_ADDRESS_BYTE)
            .expect("Stagenet address generation failed");
        assert!(stagenet_address.starts_with('5'), "Stagenet address should start with 5");
    }

    #[test]
    fn test_address_length() {
        // Monero addresses are always 95 characters
        let spend_pub = [1u8; 32];
        let view_pub = [2u8; 32];

        let address = generate_monero_address(&spend_pub, &view_pub)
            .expect("Address generation failed");

        assert_eq!(address.len(), 95, "Monero address should be 95 characters");
    }
}
