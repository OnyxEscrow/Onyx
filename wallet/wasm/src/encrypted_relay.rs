//! Encrypted Relay Module for 100% Non-Custodial FROST Signing
//!
//! This module provides end-to-end encryption for FROST partial signatures.
//! The server NEVER sees the decrypted data - only opaque encrypted blobs.
//!
//! Flow:
//! 1. First signer: ECDH + ChaCha20Poly1305 encrypt partial sig → server
//! 2. Second signer: Fetch blob, decrypt with ECDH, complete signature
//!
//! Crypto:
//! - Key Exchange: X25519 (ECDH)
//! - Encryption: ChaCha20Poly1305 (AEAD)
//! - Nonce: 12 bytes random

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Result of generating an ephemeral keypair
#[derive(Serialize, Deserialize)]
pub struct EphemeralKeypair {
    /// Hex-encoded private key (32 bytes = 64 hex chars)
    pub private_key_hex: String,
    /// Hex-encoded public key (32 bytes = 64 hex chars)
    pub public_key_hex: String,
}

/// Result of encrypting a partial signature
#[derive(Serialize, Deserialize)]
pub struct EncryptedPartialResult {
    /// Base64-encoded ciphertext
    pub encrypted_blob: String,
    /// Hex-encoded nonce (12 bytes = 24 hex chars)
    pub nonce_hex: String,
    /// Hex-encoded ephemeral public key
    pub ephemeral_pubkey_hex: String,
}

/// Result of decrypting and completing signature
#[derive(Serialize, Deserialize)]
pub struct DecryptedPartialResult {
    /// Decrypted partial signature data (JSON)
    pub partial_data_json: String,
}

/// Partial signature data structure (what gets encrypted)
#[derive(Serialize, Deserialize, Clone)]
pub struct PartialSignatureData {
    /// c1 value (hex)
    pub c1: String,
    /// s values for all ring members (hex array)
    pub s_values: Vec<String>,
    /// D point (hex)
    pub d: String,
    /// Pseudo output commitment (hex)
    pub pseudo_out: String,
    /// Key image (hex)
    pub key_image: String,
    /// mu_P aggregate (hex)
    pub mu_p: String,
    /// mu_C aggregate (hex)
    pub mu_c: String,
    /// First signer's partial s[l] (hex)
    pub s_l_partial: String,
    /// Real input index in ring
    pub signer_index: usize,
    /// Mask delta for output commitment
    pub mask_delta: String,
    /// TX prefix hash (hex)
    pub tx_prefix_hash: String,
    /// Ring data: [[pubkey, commitment], ...]
    pub ring: Vec<[String; 2]>,
}

/// Generate an ephemeral X25519 keypair for ECDH
///
/// Returns JSON with private_key_hex and public_key_hex
#[wasm_bindgen]
pub fn generate_ephemeral_keypair() -> Result<JsValue, JsValue> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let result = EphemeralKeypair {
        private_key_hex: hex::encode(secret.as_bytes()),
        public_key_hex: hex::encode(public.as_bytes()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Encrypt partial signature data for relay
///
/// # Arguments
/// * `partial_data_json` - JSON string of PartialSignatureData
/// * `my_private_key_hex` - My ephemeral private key (hex)
/// * `peer_pubkey_hex` - Peer's ephemeral public key (hex)
///
/// # Returns
/// JSON with encrypted_blob (base64), nonce_hex, ephemeral_pubkey_hex
#[wasm_bindgen]
pub fn encrypt_partial_signature(
    partial_data_json: &str,
    my_private_key_hex: &str,
    peer_pubkey_hex: &str,
) -> Result<JsValue, JsValue> {
    // Parse private key
    let private_bytes = hex::decode(my_private_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid private key hex: {e}")))?;

    if private_bytes.len() != 32 {
        return Err(JsValue::from_str("Private key must be 32 bytes"));
    }

    let mut private_arr = [0u8; 32];
    private_arr.copy_from_slice(&private_bytes);
    let my_secret = StaticSecret::from(private_arr);
    private_arr.zeroize();

    // Parse peer public key
    let peer_bytes = hex::decode(peer_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid peer pubkey hex: {e}")))?;

    if peer_bytes.len() != 32 {
        return Err(JsValue::from_str("Peer public key must be 32 bytes"));
    }

    let mut peer_arr = [0u8; 32];
    peer_arr.copy_from_slice(&peer_bytes);
    let peer_public = PublicKey::from(peer_arr);

    // Derive shared secret via ECDH
    let shared_secret = my_secret.diffie_hellman(&peer_public);

    // Use SHA3-256 to derive encryption key (Keccak family, consistent with Monero)
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    let key_bytes = hasher.finalize();

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Cipher init failed: {e}")))?;

    // Generate random nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| JsValue::from_str(&format!("Nonce generation failed: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the partial data
    let plaintext = partial_data_json.as_bytes();
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;

    // Return result
    let my_public = PublicKey::from(&my_secret);
    let result = EncryptedPartialResult {
        encrypted_blob: base64::encode(&ciphertext),
        nonce_hex: hex::encode(nonce_bytes),
        ephemeral_pubkey_hex: hex::encode(my_public.as_bytes()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Decrypt partial signature from relay
///
/// # Arguments
/// * `encrypted_blob_base64` - Base64-encoded ciphertext
/// * `nonce_hex` - Hex-encoded nonce (12 bytes)
/// * `peer_pubkey_hex` - First signer's ephemeral public key (hex)
/// * `my_private_key_hex` - My ephemeral private key (hex)
///
/// # Returns
/// JSON with partial_data_json (decrypted)
#[wasm_bindgen]
pub fn decrypt_partial_signature(
    encrypted_blob_base64: &str,
    nonce_hex: &str,
    peer_pubkey_hex: &str,
    my_private_key_hex: &str,
) -> Result<JsValue, JsValue> {
    // Parse private key
    let private_bytes = hex::decode(my_private_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid private key hex: {e}")))?;

    if private_bytes.len() != 32 {
        return Err(JsValue::from_str("Private key must be 32 bytes"));
    }

    let mut private_arr = [0u8; 32];
    private_arr.copy_from_slice(&private_bytes);
    let my_secret = StaticSecret::from(private_arr);
    private_arr.zeroize();

    // Parse peer public key
    let peer_bytes = hex::decode(peer_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid peer pubkey hex: {e}")))?;

    if peer_bytes.len() != 32 {
        return Err(JsValue::from_str("Peer public key must be 32 bytes"));
    }

    let mut peer_arr = [0u8; 32];
    peer_arr.copy_from_slice(&peer_bytes);
    let peer_public = PublicKey::from(peer_arr);

    // Parse nonce
    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid nonce hex: {e}")))?;

    if nonce_bytes.len() != 12 {
        return Err(JsValue::from_str("Nonce must be 12 bytes"));
    }

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decode ciphertext
    let ciphertext = base64::decode(encrypted_blob_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid base64: {e}")))?;

    // Derive shared secret via ECDH
    let shared_secret = my_secret.diffie_hellman(&peer_public);

    // Use SHA3-256 to derive encryption key
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    let key_bytes = hasher.finalize();

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Cipher init failed: {e}")))?;

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {e}")))?;

    // Convert to string
    let partial_data_json = String::from_utf8(plaintext)
        .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8: {e}")))?;

    let result = DecryptedPartialResult { partial_data_json };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create encrypted partial signature for relay (convenience wrapper)
///
/// Combines keypair generation and encryption in one call.
///
/// # Arguments
/// * `partial_data_json` - JSON string of PartialSignatureData
/// * `peer_pubkey_hex` - Peer's ephemeral public key (hex)
///
/// # Returns
/// JSON with encrypted_blob (base64), nonce_hex, ephemeral_pubkey_hex, private_key_hex
#[wasm_bindgen]
pub fn create_encrypted_partial_for_relay(
    partial_data_json: &str,
    peer_pubkey_hex: &str,
) -> Result<JsValue, JsValue> {
    // Generate ephemeral keypair
    let secret = StaticSecret::random_from_rng(OsRng);
    let my_public = PublicKey::from(&secret);
    let my_private_hex = hex::encode(secret.as_bytes());
    let my_public_hex = hex::encode(my_public.as_bytes());

    // Encrypt
    let encrypted = encrypt_partial_signature(partial_data_json, &my_private_hex, peer_pubkey_hex)?;

    // Add private key to result for later use
    #[derive(Serialize)]
    struct FullEncryptedResult {
        encrypted_blob: String,
        nonce_hex: String,
        ephemeral_pubkey_hex: String,
        ephemeral_private_key_hex: String,
    }

    let encrypted_result: EncryptedPartialResult = serde_wasm_bindgen::from_value(encrypted)?;

    let full_result = FullEncryptedResult {
        encrypted_blob: encrypted_result.encrypted_blob,
        nonce_hex: encrypted_result.nonce_hex,
        ephemeral_pubkey_hex: my_public_hex,
        ephemeral_private_key_hex: my_private_hex,
    };

    serde_wasm_bindgen::to_value(&full_result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate two keypairs
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_secret);

        let alice_private_hex = hex::encode(alice_secret.as_bytes());
        let alice_public_hex = hex::encode(alice_public.as_bytes());
        let bob_private_hex = hex::encode(bob_secret.as_bytes());
        let bob_public_hex = hex::encode(bob_public.as_bytes());

        // Test data
        let test_data = r#"{"c1":"abcd","s_values":["1234"],"d":"5678"}"#;

        // Alice encrypts for Bob
        let encrypted = encrypt_partial_signature(test_data, &alice_private_hex, &bob_public_hex);
        assert!(encrypted.is_ok());

        let encrypted_result: EncryptedPartialResult =
            serde_wasm_bindgen::from_value(encrypted.unwrap()).unwrap();

        // Bob decrypts
        let decrypted = decrypt_partial_signature(
            &encrypted_result.encrypted_blob,
            &encrypted_result.nonce_hex,
            &encrypted_result.ephemeral_pubkey_hex,
            &bob_private_hex,
        );
        assert!(decrypted.is_ok());

        let decrypted_result: DecryptedPartialResult =
            serde_wasm_bindgen::from_value(decrypted.unwrap()).unwrap();

        assert_eq!(decrypted_result.partial_data_json, test_data);
    }
}
