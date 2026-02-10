//! Encryption types for the relay module.

use alloc::string::String;
use zeroize::Zeroize;

/// Result of generating an ephemeral X25519 keypair.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct EphemeralKeypair {
    /// Private key (hex, 32 bytes = 64 hex chars).
    ///
    /// **Security**: Keep in memory only, never persist!
    pub private_key_hex: String,

    /// Public key (hex, 32 bytes = 64 hex chars).
    ///
    /// Safe to share with peer.
    #[zeroize(skip)]
    pub public_key_hex: String,
}

/// Result of encrypting data for relay.
#[derive(Clone)]
pub struct EncryptedResult {
    /// Base64-encoded ciphertext (includes AEAD tag).
    pub encrypted_blob: String,

    /// Nonce used for encryption (hex, 12 bytes = 24 hex chars).
    pub nonce_hex: String,

    /// Sender's ephemeral public key (hex, 32 bytes = 64 hex chars).
    ///
    /// The recipient needs this for ECDH key derivation.
    pub ephemeral_pubkey_hex: String,
}

/// Result of decrypting data from relay.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DecryptedResult {
    /// Decrypted plaintext data.
    pub plaintext: String,
}

impl EphemeralKeypair {
    /// Create a new ephemeral keypair from hex strings.
    pub fn new(private_key_hex: String, public_key_hex: String) -> Self {
        Self {
            private_key_hex,
            public_key_hex,
        }
    }
}

impl EncryptedResult {
    /// Create a new encrypted result.
    pub fn new(encrypted_blob: String, nonce_hex: String, ephemeral_pubkey_hex: String) -> Self {
        Self {
            encrypted_blob,
            nonce_hex,
            ephemeral_pubkey_hex,
        }
    }
}

impl DecryptedResult {
    /// Create a new decrypted result.
    pub fn new(plaintext: String) -> Self {
        Self { plaintext }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_keypair_creation() {
        let keypair = EphemeralKeypair::new("0".repeat(64), "1".repeat(64));
        assert_eq!(keypair.private_key_hex.len(), 64);
        assert_eq!(keypair.public_key_hex.len(), 64);
    }

    #[test]
    fn test_encrypted_result_creation() {
        let result = EncryptedResult::new("blob".to_string(), "0".repeat(24), "1".repeat(64));
        assert_eq!(result.nonce_hex.len(), 24);
        assert_eq!(result.ephemeral_pubkey_hex.len(), 64);
    }
}
