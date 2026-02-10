use crate::crypto::seed::{ClientSeed, DerivedKeys, WalletRegistrationRequest};
use anyhow::Result;

/// Contract for seed generation and key derivation operations.
///
/// Implementations must ensure:
/// - Private keys are never logged or exposed
/// - Memory is securely cleared after use
/// - Deterministic key derivation (same seed = same keys)
pub trait SeedManager {
    /// Generate a new 24-word BIP39 mnemonic.
    fn generate_new() -> Result<ClientSeed>;

    /// Recover seed from a 24-word mnemonic phrase.
    fn recover_from_mnemonic(words: &str) -> Result<ClientSeed>;

    /// Derive Monero keys from the seed.
    fn derive_keys(&self, seed: &ClientSeed) -> Result<DerivedKeys>;

    /// Create a wallet registration request (public keys only).
    fn to_registration_request(&self, keys: &DerivedKeys) -> Result<WalletRegistrationRequest>;
}

/// Default implementation using BIP39 + HKDF-SHA256
pub struct DefaultSeedManager;

impl DefaultSeedManager {
    /// Generate a new seed
    pub fn generate_new() -> Result<ClientSeed> {
        ClientSeed::generate_new()
    }

    /// Recover from mnemonic
    pub fn recover_from_mnemonic(words: &str) -> Result<ClientSeed> {
        ClientSeed::recover_from_mnemonic(words)
    }

    /// Derive keys from seed
    pub fn derive_keys(seed: &ClientSeed) -> Result<DerivedKeys> {
        seed.derive_keys(None)
    }

    /// Create registration request from derived keys
    pub fn to_registration_request(keys: &DerivedKeys) -> Result<WalletRegistrationRequest> {
        keys.to_registration_request()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_manager_generate() {
        let seed = DefaultSeedManager::generate_new().expect("Failed to generate seed");
        assert!(!seed.mnemonic_phrase.is_empty());
    }

    #[test]
    fn test_seed_manager_recovery() {
        let original = DefaultSeedManager::generate_new().expect("Failed to generate seed");
        let recovered = DefaultSeedManager::recover_from_mnemonic(&original.mnemonic_phrase)
            .expect("Failed to recover");
        assert_eq!(original.mnemonic_phrase, recovered.mnemonic_phrase);
    }

    #[test]
    fn test_seed_manager_derive_keys() {
        let seed = DefaultSeedManager::generate_new().expect("Failed to generate seed");
        let keys = DefaultSeedManager::derive_keys(&seed).expect("Failed to derive keys");

        assert_eq!(keys.spend_key.len(), 32);
        assert_eq!(keys.view_key.len(), 32);
    }
}
