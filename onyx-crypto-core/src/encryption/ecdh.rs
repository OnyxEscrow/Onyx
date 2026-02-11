//! ECDH key exchange using X25519.
//!
//! Provides ephemeral keypair generation and shared secret derivation
//! for end-to-end encryption of FROST partial signatures.

use alloc::format;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::types::EphemeralKeypair;
use crate::types::errors::{CryptoError, CryptoResult};

/// Generate an ephemeral X25519 keypair for ECDH.
///
/// Creates a random private key and derives the corresponding public key.
/// The private key should be kept in memory only and never persisted.
///
/// # Returns
///
/// `EphemeralKeypair` containing private and public keys as hex strings.
///
/// # Example
///
/// ```rust,ignore
/// let keypair = generate_ephemeral_keypair()?;
/// // Share keypair.public_key_hex with peer
/// // Keep keypair.private_key_hex in memory only!
/// ```
pub fn generate_ephemeral_keypair() -> CryptoResult<EphemeralKeypair> {
    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut secret_bytes).map_err(|e| {
        CryptoError::NonceGenerationFailed(format!("Keypair generation failed: {e}"))
    })?;

    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    let keypair = EphemeralKeypair::new(
        hex::encode(secret.as_bytes()),
        hex::encode(public.as_bytes()),
    );

    // Zeroize raw bytes
    secret_bytes.zeroize();

    Ok(keypair)
}

/// Derive a shared encryption key using X25519 ECDH.
///
/// Computes the shared secret and hashes it with SHA3-256 to produce
/// a 32-byte key suitable for `ChaCha20Poly1305`.
///
/// # Arguments
///
/// * `my_private_key_hex` - Your ephemeral private key (hex, 32 bytes)
/// * `peer_public_key_hex` - Peer's ephemeral public key (hex, 32 bytes)
///
/// # Returns
///
/// 32-byte encryption key derived from the shared secret.
///
/// # Example
///
/// ```rust,ignore
/// // Alice and Bob exchange public keys
/// let alice_keypair = generate_ephemeral_keypair()?;
/// let bob_keypair = generate_ephemeral_keypair()?;
///
/// // Both derive the same shared key
/// let alice_key = derive_shared_key(&alice_keypair.private_key_hex, &bob_keypair.public_key_hex)?;
/// let bob_key = derive_shared_key(&bob_keypair.private_key_hex, &alice_keypair.public_key_hex)?;
/// assert_eq!(alice_key, bob_key);
/// ```
pub fn derive_shared_key(
    my_private_key_hex: &str,
    peer_public_key_hex: &str,
) -> CryptoResult<[u8; 32]> {
    // Parse private key
    let private_bytes = hex::decode(my_private_key_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid private key hex: {e}")))?;

    if private_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "private_key".into(),
            expected: 32,
            actual: private_bytes.len(),
        });
    }

    let mut private_arr = [0u8; 32];
    private_arr.copy_from_slice(&private_bytes);
    let my_secret = StaticSecret::from(private_arr);
    private_arr.zeroize();

    // Parse peer public key
    let peer_bytes = hex::decode(peer_public_key_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid peer pubkey hex: {e}")))?;

    if peer_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "peer_public_key".into(),
            expected: 32,
            actual: peer_bytes.len(),
        });
    }

    let mut peer_arr = [0u8; 32];
    peer_arr.copy_from_slice(&peer_bytes);
    let peer_public = PublicKey::from(peer_arr);

    // Derive shared secret via ECDH
    let shared_secret = my_secret.diffie_hellman(&peer_public);

    // Hash with SHA3-256 to derive encryption key (consistent with Monero/Keccak family)
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    let key_hash = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_hash);

    Ok(key)
}

/// Derive public key from private key.
///
/// # Arguments
///
/// * `private_key_hex` - Private key (hex, 32 bytes)
///
/// # Returns
///
/// Public key as hex string.
pub fn derive_public_key(private_key_hex: &str) -> CryptoResult<String> {
    let private_bytes = hex::decode(private_key_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid private key hex: {e}")))?;

    if private_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "private_key".into(),
            expected: 32,
            actual: private_bytes.len(),
        });
    }

    let mut private_arr = [0u8; 32];
    private_arr.copy_from_slice(&private_bytes);
    let secret = StaticSecret::from(private_arr);
    let public = PublicKey::from(&secret);

    private_arr.zeroize();

    Ok(hex::encode(public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ephemeral_keypair() {
        let keypair = generate_ephemeral_keypair().unwrap();

        assert_eq!(keypair.private_key_hex.len(), 64);
        assert_eq!(keypair.public_key_hex.len(), 64);
    }

    #[test]
    fn test_keypair_uniqueness() {
        let kp1 = generate_ephemeral_keypair().unwrap();
        let kp2 = generate_ephemeral_keypair().unwrap();

        assert_ne!(kp1.private_key_hex, kp2.private_key_hex);
        assert_ne!(kp1.public_key_hex, kp2.public_key_hex);
    }

    #[test]
    fn test_derive_shared_key_symmetric() {
        // Alice and Bob generate keypairs
        let alice = generate_ephemeral_keypair().unwrap();
        let bob = generate_ephemeral_keypair().unwrap();

        // Derive shared keys from both sides
        let alice_key = derive_shared_key(&alice.private_key_hex, &bob.public_key_hex).unwrap();
        let bob_key = derive_shared_key(&bob.private_key_hex, &alice.public_key_hex).unwrap();

        // Must be the same!
        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_derive_shared_key_invalid_private() {
        let result = derive_shared_key("invalid", "0".repeat(64).as_str());
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_shared_key_wrong_length() {
        let result = derive_shared_key("1234", "0".repeat(64).as_str());
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_public_key() {
        let keypair = generate_ephemeral_keypair().unwrap();
        let derived = derive_public_key(&keypair.private_key_hex).unwrap();

        assert_eq!(derived, keypair.public_key_hex);
    }
}
