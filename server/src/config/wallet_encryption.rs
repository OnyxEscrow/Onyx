//! Wallet Encryption Configuration
//!
//! CRITICAL SECURITY MODULE: This module manages wallet file encryption passwords.
//!
//! Without encryption, anyone with filesystem access can steal all escrow funds.
//! This module ensures all wallet files are encrypted with a strong password.

use once_cell::sync::Lazy;
use rand::Rng;
use std::env;
use std::sync::RwLock;
use tracing::{error, info, warn};

/// Minimum password length for wallet encryption
const MIN_PASSWORD_LENGTH: usize = 32;

/// Wallet encryption configuration
#[derive(Debug, Clone)]
pub struct WalletEncryptionConfig {
    /// The encryption password for wallet files
    password: String,
    /// Whether encryption is enabled
    enabled: bool,
}

impl WalletEncryptionConfig {
    /// Get the password (for use in create_wallet/open_wallet)
    pub fn password(&self) -> &str {
        if self.enabled {
            &self.password
        } else {
            "" // Empty password = no encryption (DANGEROUS)
        }
    }

    /// Check if encryption is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Global wallet encryption config
static WALLET_ENCRYPTION: Lazy<RwLock<WalletEncryptionConfig>> = Lazy::new(|| {
    RwLock::new(WalletEncryptionConfig {
        password: String::new(),
        enabled: false,
    })
});

/// Generate a cryptographically secure random password
fn generate_secure_password() -> String {
    let mut rng = rand::thread_rng();
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let password: String = (0..64)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();
    password
}

/// Load wallet encryption configuration from environment
///
/// Reads from WALLET_ENCRYPTION_PASSWORD environment variable.
/// If not set and MONERO_NETWORK=mainnet, this will generate a random password
/// and warn the user to save it.
///
/// # Security Warning
///
/// If you lose the password, you lose access to all wallet files.
/// For mainnet, ensure WALLET_ENCRYPTION_PASSWORD is set and backed up.
pub fn load_wallet_encryption_config() -> WalletEncryptionConfig {
    let network = env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
    let is_mainnet = network.to_lowercase() == "mainnet";

    // Check for explicit password
    if let Ok(password) = env::var("WALLET_ENCRYPTION_PASSWORD") {
        if password.len() < MIN_PASSWORD_LENGTH {
            warn!(
                "WALLET_ENCRYPTION_PASSWORD is too short ({} chars, minimum {})",
                password.len(),
                MIN_PASSWORD_LENGTH
            );
            if is_mainnet {
                panic!(
                    "WALLET_ENCRYPTION_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters for mainnet"
                );
            }
        }

        let config = WalletEncryptionConfig {
            password,
            enabled: true,
        };

        // Store in global
        if let Ok(mut global) = WALLET_ENCRYPTION.write() {
            *global = config.clone();
        }

        info!("✅ Wallet encryption enabled with configured password");
        return config;
    }

    // Check for explicit disable
    if env::var("WALLET_ENCRYPTION_DISABLED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
    {
        if is_mainnet {
            error!("❌ CRITICAL: Wallet encryption cannot be disabled on mainnet!");
            panic!("WALLET_ENCRYPTION_DISABLED=true is not allowed when MONERO_NETWORK=mainnet");
        }

        warn!("⚠️  Wallet encryption DISABLED - wallet files are NOT protected!");
        warn!("   This is only acceptable for testnet/stagenet development.");

        let config = WalletEncryptionConfig {
            password: String::new(),
            enabled: false,
        };

        if let Ok(mut global) = WALLET_ENCRYPTION.write() {
            *global = config.clone();
        }

        return config;
    }

    // No password configured - generate one for mainnet
    if is_mainnet {
        let password = generate_secure_password();

        error!("⚠️  WARNING: No WALLET_ENCRYPTION_PASSWORD configured for mainnet!");
        error!("");
        error!("   A random password has been generated for this session:");
        error!("   WALLET_ENCRYPTION_PASSWORD={}", &password);
        error!("");
        error!("   ⚠️  SAVE THIS PASSWORD NOW!");
        error!("   Without it, you will lose access to all wallet files.");
        error!("");
        error!("   Add to .env file:");
        error!("   WALLET_ENCRYPTION_PASSWORD={}", &password);
        error!("");

        let config = WalletEncryptionConfig {
            password,
            enabled: true,
        };

        if let Ok(mut global) = WALLET_ENCRYPTION.write() {
            *global = config.clone();
        }

        return config;
    }

    // Testnet/stagenet without password - warn but allow
    warn!(
        "⚠️  No WALLET_ENCRYPTION_PASSWORD set for {} network",
        network
    );
    warn!("   Wallet files will NOT be encrypted.");
    warn!("   Set WALLET_ENCRYPTION_PASSWORD for production use.");

    let config = WalletEncryptionConfig {
        password: String::new(),
        enabled: false,
    };

    if let Ok(mut global) = WALLET_ENCRYPTION.write() {
        *global = config.clone();
    }

    config
}

/// Get the wallet encryption password for use in create_wallet/open_wallet
///
/// This is the main function to use when creating or opening wallets.
/// Returns empty string if encryption is disabled.
pub fn get_wallet_password() -> String {
    if let Ok(config) = WALLET_ENCRYPTION.read() {
        if config.enabled {
            return config.password.clone();
        }
    }

    // Try to load config if not initialized
    let config = load_wallet_encryption_config();
    config.password
}

/// Check if wallet encryption is enabled
pub fn is_wallet_encryption_enabled() -> bool {
    if let Ok(config) = WALLET_ENCRYPTION.read() {
        return config.enabled;
    }
    false
}

/// Validate wallet encryption on startup
///
/// Call this during server startup to ensure proper encryption configuration.
pub fn validate_wallet_encryption_on_startup() {
    let config = load_wallet_encryption_config();

    let network = env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());

    if config.enabled {
        info!("✅ Wallet encryption enabled for {} network", network);
    } else {
        warn!("⚠️  Wallet encryption DISABLED for {} network", network);
        if network.to_lowercase() == "mainnet" {
            panic!("Wallet encryption must be enabled for mainnet");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_password() {
        let password = generate_secure_password();
        assert_eq!(password.len(), 64);
        // Verify it contains at least some variety
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_numeric()));
    }

    #[test]
    fn test_min_password_length() {
        assert!(MIN_PASSWORD_LENGTH >= 32);
    }
}
