//! Symmetric encryption using ChaCha20Poly1305 AEAD.
//!
//! Provides authenticated encryption for FROST partial signatures.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroize;

use super::ecdh::derive_shared_key;
use super::types::EncryptedResult;
use crate::types::errors::{CryptoError, CryptoResult};

/// ChaCha20Poly1305 nonce size (12 bytes).
pub const NONCE_SIZE: usize = 12;

/// Encrypt data using ChaCha20Poly1305.
///
/// This performs ECDH key derivation and encrypts the plaintext.
///
/// # Arguments
///
/// * `plaintext` - Data to encrypt
/// * `my_private_key_hex` - Sender's ephemeral private key (hex)
/// * `peer_public_key_hex` - Recipient's ephemeral public key (hex)
///
/// # Returns
///
/// `EncryptedResult` containing the encrypted blob, nonce, and sender's public key.
///
/// # Security
///
/// - Uses random 12-byte nonce
/// - AEAD provides both confidentiality and authenticity
/// - Key is derived from X25519 ECDH + SHA3-256
pub fn encrypt_data(
    plaintext: &str,
    my_private_key_hex: &str,
    peer_public_key_hex: &str,
) -> CryptoResult<EncryptedResult> {
    // Derive shared encryption key
    let mut key = derive_shared_key(my_private_key_hex, peer_public_key_hex)?;

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CryptoError::InternalError(format!("Cipher init failed: {}", e)))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        CryptoError::NonceGenerationFailed(format!("Nonce generation failed: {}", e))
    })?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| CryptoError::InternalError(format!("Encryption failed: {}", e)))?;

    // Derive our public key for the result
    let my_public_hex = super::ecdh::derive_public_key(my_private_key_hex)?;

    // Zeroize key
    key.zeroize();

    Ok(EncryptedResult::new(
        base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        hex::encode(nonce_bytes),
        my_public_hex,
    ))
}

/// Decrypt data using ChaCha20Poly1305.
///
/// # Arguments
///
/// * `encrypted_blob_base64` - Base64-encoded ciphertext
/// * `nonce_hex` - Hex-encoded nonce (12 bytes)
/// * `peer_public_key_hex` - Sender's ephemeral public key (hex)
/// * `my_private_key_hex` - Recipient's ephemeral private key (hex)
///
/// # Returns
///
/// Decrypted plaintext string.
///
/// # Errors
///
/// Returns error if:
/// - Decryption fails (invalid ciphertext or wrong key)
/// - Nonce/key parsing fails
/// - Result is not valid UTF-8
pub fn decrypt_data(
    encrypted_blob_base64: &str,
    nonce_hex: &str,
    peer_public_key_hex: &str,
    my_private_key_hex: &str,
) -> CryptoResult<String> {
    // Derive shared encryption key
    let mut key = derive_shared_key(my_private_key_hex, peer_public_key_hex)?;

    // Parse nonce
    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid nonce hex: {}", e)))?;

    if nonce_bytes.len() != NONCE_SIZE {
        return Err(CryptoError::InvalidLength {
            field: "nonce".into(),
            expected: NONCE_SIZE,
            actual: nonce_bytes.len(),
        });
    }

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decode ciphertext
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(encrypted_blob_base64)
        .map_err(|e| CryptoError::InternalError(format!("Invalid base64: {}", e)))?;

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CryptoError::InternalError(format!("Cipher init failed: {}", e)))?;

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| CryptoError::InternalError(format!("Decryption failed: {}", e)))?;

    // Zeroize key
    key.zeroize();

    // Convert to string
    String::from_utf8(plaintext)
        .map_err(|e| CryptoError::InternalError(format!("Invalid UTF-8: {}", e)))
}

/// Encrypt arbitrary bytes (not just strings).
///
/// Returns encrypted data and nonce as raw bytes.
pub fn encrypt_bytes(
    plaintext: &[u8],
    encryption_key: &[u8; 32],
) -> CryptoResult<(Vec<u8>, [u8; NONCE_SIZE])> {
    let cipher = ChaCha20Poly1305::new_from_slice(encryption_key)
        .map_err(|e| CryptoError::InternalError(format!("Cipher init failed: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        CryptoError::NonceGenerationFailed(format!("Nonce generation failed: {}", e))
    })?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::InternalError(format!("Encryption failed: {}", e)))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt arbitrary bytes.
pub fn decrypt_bytes(
    ciphertext: &[u8],
    nonce: &[u8; NONCE_SIZE],
    decryption_key: &[u8; 32],
) -> CryptoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(decryption_key)
        .map_err(|e| CryptoError::InternalError(format!("Cipher init failed: {}", e)))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::InternalError(format!("Decryption failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::ecdh::generate_ephemeral_keypair;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let alice = generate_ephemeral_keypair().unwrap();
        let bob = generate_ephemeral_keypair().unwrap();

        let plaintext = "Secret FROST partial signature data!";

        // Alice encrypts for Bob
        let encrypted =
            encrypt_data(plaintext, &alice.private_key_hex, &bob.public_key_hex).unwrap();

        assert!(!encrypted.encrypted_blob.is_empty());
        assert_eq!(encrypted.nonce_hex.len(), NONCE_SIZE * 2); // hex encoding
        assert_eq!(encrypted.ephemeral_pubkey_hex, alice.public_key_hex);

        // Bob decrypts
        let decrypted = decrypt_data(
            &encrypted.encrypted_blob,
            &encrypted.nonce_hex,
            &encrypted.ephemeral_pubkey_hex, // Alice's pubkey
            &bob.private_key_hex,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_bytes_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"Binary data: \x00\x01\x02\xff";

        let (ciphertext, nonce) = encrypt_bytes(plaintext, &key).unwrap();
        let decrypted = decrypt_bytes(&ciphertext, &nonce, &key).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let alice = generate_ephemeral_keypair().unwrap();
        let bob = generate_ephemeral_keypair().unwrap();
        let eve = generate_ephemeral_keypair().unwrap(); // Attacker

        let plaintext = "Secret data";

        // Alice encrypts for Bob
        let encrypted =
            encrypt_data(plaintext, &alice.private_key_hex, &bob.public_key_hex).unwrap();

        // Eve tries to decrypt (should fail)
        let result = decrypt_data(
            &encrypted.encrypted_blob,
            &encrypted.nonce_hex,
            &encrypted.ephemeral_pubkey_hex,
            &eve.private_key_hex, // Wrong key!
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let alice = generate_ephemeral_keypair().unwrap();
        let bob = generate_ephemeral_keypair().unwrap();

        let encrypted = encrypt_data(
            "Original message",
            &alice.private_key_hex,
            &bob.public_key_hex,
        )
        .unwrap();

        // Tamper with the ciphertext
        let tampered = format!("X{}", &encrypted.encrypted_blob[1..]);

        let result = decrypt_data(
            &tampered,
            &encrypted.nonce_hex,
            &encrypted.ephemeral_pubkey_hex,
            &bob.private_key_hex,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nonce_length() {
        let alice = generate_ephemeral_keypair().unwrap();
        let bob = generate_ephemeral_keypair().unwrap();

        let encrypted = encrypt_data("Test", &alice.private_key_hex, &bob.public_key_hex).unwrap();

        // Wrong nonce length
        let result = decrypt_data(
            &encrypted.encrypted_blob,
            "1234", // Too short
            &encrypted.ephemeral_pubkey_hex,
            &bob.private_key_hex,
        );

        assert!(result.is_err());
    }
}
