//! Transaction fee configuration for Monero Marketplace
//!
//! Post-2025 mainnet-ready fee values based on network analysis.
//! Fees are configurable via environment variables for flexibility.

use std::env;

/// Default transaction fee in atomic units (0.00005 XMR)
/// This is the mainnet-recommended fee after 2025 fee analysis.
/// Stagenet/testnet may use higher values for faster confirmation.
///
/// Override via TX_FEE_ATOMIC environment variable.
pub const DEFAULT_TX_FEE_ATOMIC: u64 = 50_000_000;

/// Conservative fee reserve for wallet operations (0.0001 XMR)
/// Used when calculating maximum sendable amount.
///
/// Override via FEE_RESERVE_ATOMIC environment variable.
pub const DEFAULT_FEE_RESERVE_ATOMIC: u64 = 100_000_000;

/// Minimum fee in atomic units (0.00001 XMR)
/// Below this, transactions may not be relayed by the network.
pub const MIN_TX_FEE_ATOMIC: u64 = 10_000_000;

/// Maximum fee in atomic units (0.001 XMR)
/// Above this, the fee is likely a user error.
pub const MAX_TX_FEE_ATOMIC: u64 = 1_000_000_000;

/// Get the configured transaction fee in atomic units.
///
/// Reads from TX_FEE_ATOMIC environment variable, falling back to default.
/// Returns error if the configured value is outside valid bounds.
pub fn get_tx_fee() -> u64 {
    env::var("TX_FEE_ATOMIC")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(|fee: u64| {
            if fee < MIN_TX_FEE_ATOMIC {
                tracing::warn!(
                    fee = fee,
                    min = MIN_TX_FEE_ATOMIC,
                    "TX_FEE_ATOMIC below minimum, using minimum"
                );
                MIN_TX_FEE_ATOMIC
            } else if fee > MAX_TX_FEE_ATOMIC {
                tracing::warn!(
                    fee = fee,
                    max = MAX_TX_FEE_ATOMIC,
                    "TX_FEE_ATOMIC above maximum, using maximum"
                );
                MAX_TX_FEE_ATOMIC
            } else {
                fee
            }
        })
        .unwrap_or(DEFAULT_TX_FEE_ATOMIC)
}

/// Get the configured fee reserve for wallet operations.
///
/// Reads from FEE_RESERVE_ATOMIC environment variable, falling back to default.
pub fn get_fee_reserve() -> u64 {
    env::var("FEE_RESERVE_ATOMIC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_FEE_RESERVE_ATOMIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_fee_values() {
        // 0.00005 XMR = 50_000_000 atomic
        assert_eq!(DEFAULT_TX_FEE_ATOMIC, 50_000_000);
        // 0.0001 XMR = 100_000_000 atomic
        assert_eq!(DEFAULT_FEE_RESERVE_ATOMIC, 100_000_000);
    }

    #[test]
    fn test_fee_bounds() {
        assert!(MIN_TX_FEE_ATOMIC < DEFAULT_TX_FEE_ATOMIC);
        assert!(DEFAULT_TX_FEE_ATOMIC < MAX_TX_FEE_ATOMIC);
        assert!(DEFAULT_FEE_RESERVE_ATOMIC <= MAX_TX_FEE_ATOMIC);
    }
}
