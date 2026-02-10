//! Platform Fee Wallet Configuration
//!
//! CRITICAL SECURITY MODULE: This module validates the platform fee wallet
//! address on startup to prevent fund loss from network mismatches.
//!
//! The platform fee wallet receives a percentage of every transaction.
//! If this address is invalid or on the wrong network, ALL PLATFORM FEES
//! WILL BE PERMANENTLY LOST.

use crate::crypto::address_validation::{validate_address, validate_address_for_network, MoneroNetwork};
use once_cell::sync::Lazy;
use std::env;
use std::sync::RwLock;
use tracing::{error, info};

/// Configuration error for platform wallet
#[derive(Debug, Clone)]
pub enum PlatformWalletError {
    /// Environment variable not set
    NotConfigured,
    /// Address validation failed
    InvalidAddress(String),
    /// Network mismatch between address and MONERO_NETWORK
    NetworkMismatch {
        address_network: MoneroNetwork,
        expected_network: MoneroNetwork,
    },
    /// MONERO_NETWORK environment variable is invalid
    InvalidNetworkConfig(String),
}

impl std::fmt::Display for PlatformWalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformWalletError::NotConfigured => {
                write!(f, "PLATFORM_FEE_WALLET environment variable not set")
            }
            PlatformWalletError::InvalidAddress(msg) => {
                write!(f, "Invalid platform fee wallet address: {}", msg)
            }
            PlatformWalletError::NetworkMismatch {
                address_network,
                expected_network,
            } => {
                write!(
                    f,
                    "CRITICAL: Platform wallet is for {} but MONERO_NETWORK={} - THIS WOULD LOSE ALL FEES",
                    address_network, expected_network
                )
            }
            PlatformWalletError::InvalidNetworkConfig(val) => {
                write!(f, "Invalid MONERO_NETWORK value: {}", val)
            }
        }
    }
}

impl std::error::Error for PlatformWalletError {}

/// Validated platform wallet configuration
#[derive(Debug, Clone)]
pub struct PlatformWalletConfig {
    /// The validated wallet address
    pub address: String,
    /// The network this address belongs to
    pub network: MoneroNetwork,
    /// Fee percentage for release (in basis points, 500 = 5%)
    pub release_fee_bps: u64,
    /// Fee percentage for refunds (in basis points, 300 = 3%)
    pub refund_fee_bps: u64,
}

/// Global validated platform wallet (initialized on first access)
static PLATFORM_WALLET: Lazy<RwLock<Option<PlatformWalletConfig>>> =
    Lazy::new(|| RwLock::new(None));

/// Get the current network from environment
pub fn get_configured_network() -> Result<MoneroNetwork, PlatformWalletError> {
    let network_str = env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());

    MoneroNetwork::from_str(&network_str)
        .ok_or_else(|| PlatformWalletError::InvalidNetworkConfig(network_str))
}

/// Validate and load platform wallet configuration
///
/// This function MUST be called at server startup. It will:
/// 1. Read PLATFORM_FEE_WALLET from environment
/// 2. Validate the address cryptographically (checksum verification)
/// 3. Verify the address matches MONERO_NETWORK
/// 4. Return error if any validation fails
///
/// # Panics
///
/// This function is designed to be called with `.expect()` at startup
/// so the server refuses to start with an invalid configuration.
pub fn load_platform_wallet() -> Result<PlatformWalletConfig, PlatformWalletError> {
    // Get expected network
    let expected_network = get_configured_network()?;

    // Get platform wallet address
    let address = env::var("PLATFORM_FEE_WALLET")
        .map_err(|_| PlatformWalletError::NotConfigured)?;

    // Validate address with full checksum verification
    let address_network = validate_address(&address)
        .map_err(|e| PlatformWalletError::InvalidAddress(e.to_string()))?;

    // CRITICAL: Verify network matches
    if address_network != expected_network {
        return Err(PlatformWalletError::NetworkMismatch {
            address_network,
            expected_network,
        });
    }

    // Get fee configuration
    let release_fee_bps: u64 = env::var("PLATFORM_FEE_RELEASE_BPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500); // Default 5%

    let refund_fee_bps: u64 = env::var("PLATFORM_FEE_REFUND_BPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300); // Default 3%

    let config = PlatformWalletConfig {
        address,
        network: expected_network,
        release_fee_bps,
        refund_fee_bps,
    };

    // Store in global
    if let Ok(mut wallet) = PLATFORM_WALLET.write() {
        *wallet = Some(config.clone());
    }

    info!(
        network = %expected_network,
        release_fee_bps = release_fee_bps,
        refund_fee_bps = refund_fee_bps,
        "Platform wallet validated successfully"
    );

    Ok(config)
}

/// Get the validated platform wallet address
///
/// This function returns the platform wallet address ONLY if it has been
/// validated. If validation hasn't occurred or failed, it returns an error.
///
/// # Usage
///
/// ```rust
/// let address = get_platform_wallet_address()
///     .expect("Platform wallet not configured - server should not have started");
/// ```
pub fn get_platform_wallet_address() -> Result<String, PlatformWalletError> {
    // Try to get from cache first
    if let Ok(wallet) = PLATFORM_WALLET.read() {
        if let Some(ref config) = *wallet {
            return Ok(config.address.clone());
        }
    }

    // Not initialized - try to load
    let config = load_platform_wallet()?;
    Ok(config.address)
}

/// Get the validated platform wallet configuration
///
/// Returns the full configuration including fee percentages.
pub fn get_platform_wallet_config() -> Result<PlatformWalletConfig, PlatformWalletError> {
    // Try to get from cache first
    if let Ok(wallet) = PLATFORM_WALLET.read() {
        if let Some(ref config) = *wallet {
            return Ok(config.clone());
        }
    }

    // Not initialized - try to load
    load_platform_wallet()
}

/// Validate platform wallet on startup (CALL THIS IN main())
///
/// This function should be called early in the server startup sequence.
/// It validates the platform wallet configuration and panics if invalid.
///
/// # Panics
///
/// Panics with a clear error message if:
/// - PLATFORM_FEE_WALLET is not set
/// - The address fails checksum validation
/// - The address is for a different network than MONERO_NETWORK
///
/// # Example
///
/// ```rust
/// fn main() {
///     // ... setup logging ...
///
///     // CRITICAL: Validate platform wallet before accepting any connections
///     validate_platform_wallet_on_startup();
///
///     // ... start server ...
/// }
/// ```
pub fn validate_platform_wallet_on_startup() {
    match load_platform_wallet() {
        Ok(config) => {
            info!(
                "✅ Platform wallet validated for {} network",
                config.network
            );
            // Log first and last 6 chars of address for verification
            let addr = &config.address;
            if addr.len() >= 12 {
                info!(
                    "   Address: {}...{} (validated with checksum)",
                    &addr[..6],
                    &addr[addr.len() - 6..]
                );
            }
        }
        Err(e) => {
            error!("❌ CRITICAL: Platform wallet validation failed!");
            error!("   Error: {}", e);
            error!("");
            error!("   This is a FATAL error. The server cannot start.");
            error!("");

            match e {
                PlatformWalletError::NotConfigured => {
                    error!("   FIX: Set PLATFORM_FEE_WALLET in .env to a valid {} address",
                        get_configured_network().unwrap_or(MoneroNetwork::Mainnet));
                    error!("   Generate with: monero-wallet-cli --generate-new-wallet platform_fee");
                }
                PlatformWalletError::NetworkMismatch { ref address_network, ref expected_network } => {
                    error!("   The address starts with '{}' which is for {}",
                        if *address_network == MoneroNetwork::Mainnet { "4/8" }
                        else if *address_network == MoneroNetwork::Stagenet { "5/7" }
                        else { "9/A/B" },
                        address_network);
                    error!("   But MONERO_NETWORK={}", expected_network);
                    error!("");
                    error!("   FIX: Either:");
                    error!("   1. Change PLATFORM_FEE_WALLET to a {} address (starts with {})",
                        expected_network,
                        if *expected_network == MoneroNetwork::Mainnet { "'4' or '8'" }
                        else if *expected_network == MoneroNetwork::Stagenet { "'5' or '7'" }
                        else { "'9', 'A', or 'B'" });
                    error!("   2. Or change MONERO_NETWORK={} if you're testing on {}",
                        address_network, address_network);
                }
                PlatformWalletError::InvalidAddress(ref msg) => {
                    error!("   The address failed cryptographic validation: {}", msg);
                    error!("   This means the checksum is wrong or the address is corrupted.");
                    error!("");
                    error!("   FIX: Generate a new wallet address with:");
                    error!("   monero-wallet-cli --{} --generate-new-wallet platform_fee",
                        get_configured_network().unwrap_or(MoneroNetwork::Mainnet));
                }
                PlatformWalletError::InvalidNetworkConfig(ref val) => {
                    error!("   MONERO_NETWORK='{}' is not valid", val);
                    error!("   FIX: Set MONERO_NETWORK to 'mainnet', 'stagenet', or 'testnet'");
                }
            }

            error!("");
            error!("   ⚠️  DO NOT BYPASS THIS CHECK - IT PREVENTS PERMANENT FUND LOSS");
            panic!("Platform wallet validation failed: {}", e);
        }
    }
}

/// Check if we're configured for mainnet (for extra warnings)
pub fn is_mainnet() -> bool {
    get_configured_network()
        .map(|n| n == MoneroNetwork::Mainnet)
        .unwrap_or(false)
}

/// Get release fee in basis points
pub fn get_release_fee_bps() -> u64 {
    get_platform_wallet_config()
        .map(|c| c.release_fee_bps)
        .unwrap_or(500)
}

/// Get refund fee in basis points
pub fn get_refund_fee_bps() -> u64 {
    get_platform_wallet_config()
        .map(|c| c.refund_fee_bps)
        .unwrap_or(300)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_from_env_default() {
        // Clear env var to test default
        env::remove_var("MONERO_NETWORK");
        let network = get_configured_network();
        assert!(network.is_ok());
        assert_eq!(network.unwrap(), MoneroNetwork::Mainnet);
    }

    #[test]
    fn test_network_mismatch_detection() {
        // This is the stagenet address from .env
        let stagenet_addr = "58WZHPMi4UZbb6jmyphVHiDNkYXNf8wLWhjB4SxHBvG9YNHsyZmntHjj9junfWQJjqixi48rWpoWWGgZBPjrE6HMUKNfmZx";

        // Validate for mainnet should fail
        let result = validate_address_for_network(stagenet_addr, MoneroNetwork::Mainnet);
        assert!(result.is_err());
    }

    #[test]
    fn test_fee_defaults() {
        assert_eq!(get_release_fee_bps(), 500); // 5%
        assert_eq!(get_refund_fee_bps(), 300);  // 3%
    }
}
