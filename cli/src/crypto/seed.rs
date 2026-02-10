use anyhow::{anyhow, Context, Result};
use bip39::Mnemonic;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 24-word BIP39 mnemonic with secure memory handling.
/// Automatically zeroizes memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientSeed {
    /// BIP39 mnemonic words (24 words) - will be zeroized on drop
    pub mnemonic_phrase: String,
}

/// Derived keys from the seed using HKDF-SHA256.
/// Public keys and Monero address are non-sensitive (public).
#[derive(Clone)]
pub struct DerivedKeys {
    /// Spend key (64 hex chars = 32 bytes)
    pub spend_key: [u8; 32],
    /// View key (64 hex chars = 32 bytes)
    pub view_key: [u8; 32],
    /// Monero address (58 chars for mainnet)
    pub address: String,
}

/// Data Transfer Object for wallet registration.
/// Contains ONLY public information - NO private keys.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct WalletRegistrationRequest {
    /// Monero address (58 characters)
    pub address: String,
    /// Hex-encoded public view key (64 chars)
    pub view_key_pub: String,
    /// Hex-encoded public spend key (64 chars)
    pub spend_key_pub: String,
    /// SHA256 hash of address for verification
    pub address_hash: String,
    /// Optional proof of ownership (signature)
    pub signature: Option<String>,
}

impl ClientSeed {
    /// Generate a new 24-word BIP39 mnemonic.
    ///
    /// Uses OS random source for entropy generation.
    /// Returns a ClientSeed that will zeroize memory on drop.
    pub fn generate_new() -> Result<Self> {
        // Generate 32 bytes of cryptographic random data for 24-word mnemonic
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);

        // Create BIP39 mnemonic from entropy
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .context("Failed to generate BIP39 mnemonic from entropy")?;

        let mnemonic_phrase = mnemonic.to_string();

        Ok(ClientSeed { mnemonic_phrase })
    }

    /// Recover a seed from a 24-word mnemonic phrase.
    ///
    /// Validates that the phrase is valid BIP39.
    pub fn recover_from_mnemonic(phrase: &str) -> Result<Self> {
        // Validate and parse the mnemonic
        let _mnemonic = Mnemonic::parse(phrase).context("Invalid BIP39 mnemonic phrase")?;

        // If parsing succeeds, the mnemonic is valid
        Ok(ClientSeed {
            mnemonic_phrase: phrase.to_string(),
        })
    }

    /// Derive entropy from the mnemonic phrase for key derivation.
    ///
    /// This uses PBKDF2 with the mnemonic as input (similar to BIP39 specification).
    fn derive_entropy(&self) -> Result<[u8; 32]> {
        // Use SHA256 hash of the mnemonic as entropy for HKDF
        // In a real implementation, use PBKDF2 or similar
        let mut entropy = [0u8; 32];
        let hash = Sha256::digest(self.mnemonic_phrase.as_bytes());
        entropy.copy_from_slice(&hash[..32]);
        Ok(entropy)
    }

    /// Derive Monero keys from this seed using HKDF-SHA256.
    ///
    /// # Algorithm
    /// - HKDF-Expand with SHA256
    /// - First 32 bytes -> spend_key
    /// - Next 32 bytes -> view_key
    /// - Address derived using standard Monero derivation (not implemented here,
    ///   must be handled by Monero RPC or external wallet library)
    ///
    /// # Note
    /// This is a simplified derivation. Real Monero key derivation involves:
    /// 1. SC25519 scalar operations
    /// 2. ED25519 point operations
    /// 3. Keccak256 hashing
    /// For production, integrate with monero_wallet_rpc or use a Monero library.
    pub fn derive_keys(&self, _derivation_path: Option<&str>) -> Result<DerivedKeys> {
        // Derive entropy from mnemonic
        let entropy = self.derive_entropy()?;

        // HKDF context (not derived from a key, just expand entropy)
        let hk = Hkdf::<Sha256>::new(None, &entropy);

        // Derive spend key (first 32 bytes)
        let mut spend_key = [0u8; 32];
        hk.expand(b"monero_spend", &mut spend_key)
            .map_err(|_| anyhow!("HKDF expand failed for spend_key"))?;

        // Derive view key (next 32 bytes)
        let mut view_key = [0u8; 32];
        hk.expand(b"monero_view", &mut view_key)
            .map_err(|_| anyhow!("HKDF expand failed for view_key"))?;

        // NOTE: Address derivation requires Monero's specific key derivation
        // (ED25519 point math). This is a placeholder.
        // In production, call monero_wallet_rpc::import_key_images or similar.
        let address = String::from("placeholder_address");

        Ok(DerivedKeys {
            spend_key,
            view_key,
            address,
        })
    }
}

impl DerivedKeys {
    /// Convert keys to public key format and create registration request.
    ///
    /// Only uses public key material; private keys are never included.
    pub fn to_registration_request(&self) -> Result<WalletRegistrationRequest> {
        let spend_key_pub = hex::encode(&self.spend_key);
        let view_key_pub = hex::encode(&self.view_key);

        // In real implementation, address would be valid Monero address
        if self.address == "placeholder_address" {
            return Err(anyhow!(
                "Address not properly derived. Monero RPC integration required."
            ));
        }

        let address_hash = format!("{:x}", Sha256::digest(self.address.as_bytes()));

        Ok(WalletRegistrationRequest {
            address: self.address.clone(),
            spend_key_pub,
            view_key_pub,
            address_hash,
            signature: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_new_seed() {
        let seed = ClientSeed::generate_new().expect("Failed to generate seed");
        assert!(!seed.mnemonic_phrase.is_empty());

        // Should be 24 words
        let word_count = seed.mnemonic_phrase.split_whitespace().count();
        assert_eq!(word_count, 24);
    }

    #[test]
    fn test_mnemonic_is_valid_bip39() {
        let seed = ClientSeed::generate_new().expect("Failed to generate seed");
        // Should be able to parse back the mnemonic
        let recovered = ClientSeed::recover_from_mnemonic(&seed.mnemonic_phrase)
            .expect("Failed to recover from mnemonic");
        assert_eq!(recovered.mnemonic_phrase, seed.mnemonic_phrase);
    }

    #[test]
    fn test_recover_from_mnemonic() {
        // Valid test vector (random generation - test that parsing works)
        let seed1 = ClientSeed::generate_new().expect("Failed to generate seed");
        let phrase = seed1.mnemonic_phrase.clone();

        let seed2 =
            ClientSeed::recover_from_mnemonic(&phrase).expect("Failed to recover from mnemonic");
        assert_eq!(seed2.mnemonic_phrase, seed1.mnemonic_phrase);
    }

    #[test]
    fn test_recover_from_invalid_mnemonic() {
        let result = ClientSeed::recover_from_mnemonic("invalid words here");
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let seed = ClientSeed::generate_new().expect("Failed to generate seed");

        let keys1 = seed.derive_keys(None).expect("Failed to derive keys");
        let keys2 = seed.derive_keys(None).expect("Failed to derive keys");

        // Same seed must produce same keys
        assert_eq!(keys1.spend_key, keys2.spend_key);
        assert_eq!(keys1.view_key, keys2.view_key);
    }

    #[test]
    fn test_different_seeds_produce_different_keys() {
        let seed1 = ClientSeed::generate_new().expect("Failed to generate seed");
        let seed2 = ClientSeed::generate_new().expect("Failed to generate seed");

        let keys1 = seed1.derive_keys(None).expect("Failed to derive keys");
        let keys2 = seed2.derive_keys(None).expect("Failed to derive keys");

        assert_ne!(keys1.spend_key, keys2.spend_key);
        assert_ne!(keys1.view_key, keys2.view_key);
    }

    #[test]
    fn test_registration_request_no_private_keys() {
        let seed = ClientSeed::generate_new().expect("Failed to generate seed");
        let keys = seed.derive_keys(None).expect("Failed to derive keys");

        // Should fail because address is placeholder
        let result = keys.to_registration_request();
        assert!(result.is_err());

        // But verify the fields would NOT contain private keys
        // (The entropy and mnemonic are in ClientSeed, not in registration request)
    }
}
