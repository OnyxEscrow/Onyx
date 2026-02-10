//! Encryption utilities for secure FROST signing relay and key backup.
//!
//! This module provides:
//!
//! 1. **E2E Encryption** for FROST partial signatures (X25519 + ChaCha20Poly1305)
//! 2. **Key Backup Encryption** for FROST key_packages (Argon2id + ChaCha20Poly1305)
//!
//! ## E2E Encryption Protocol (signatures)
//!
//! 1. Key Exchange: X25519 (ECDH) for shared secret derivation
//! 2. Key Derivation: SHA3-256 of shared secret
//! 3. Encryption: ChaCha20Poly1305 (AEAD)
//! 4. Nonce: 12 bytes random
//!
//! ## Backup Encryption Protocol (key storage)
//!
//! 1. Key Derivation: Argon2id (m=64MB, t=3, p=4)
//! 2. Encryption: ChaCha20Poly1305 (AEAD)
//! 3. Format: salt (16) || nonce (12) || ciphertext
//!
//! ## Flow (E2E)
//!
//! 1. First signer generates ephemeral keypair
//! 2. First signer encrypts partial signature with peer's public key
//! 3. Encrypted blob is relayed through server
//! 4. Second signer decrypts with their private key
//!
//! ## Security Notes
//!
//! - Server NEVER sees decrypted data (blind relay)
//! - Ephemeral keys should be used once and discarded
//! - All sensitive data is zeroized on drop
//! - Argon2id backup encryption resists GPU/ASIC brute-force

pub mod backup;
pub mod ecdh;
pub mod symmetric;
pub mod types;

// Re-export main types
pub use types::{DecryptedResult, EncryptedResult, EphemeralKeypair};

// Re-export functions
pub use ecdh::{derive_shared_key, generate_ephemeral_keypair};
pub use symmetric::{decrypt_data, encrypt_data};

// Re-export backup functions
pub use backup::{
    decrypt_key_from_backup, derive_backup_id, encrypt_key_for_backup, encrypted_size,
    verify_backup_password, HEADER_SIZE, KEY_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};
