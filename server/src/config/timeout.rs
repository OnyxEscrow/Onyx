//! Timeout configuration for escrow and wallet operations
//!
//! This module defines timeout policies for various escrow states and operations
//! to prevent stuck transactions and improve system resilience.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Timeout configuration for escrow operations
///
/// Defines deadline policies for each escrow state. When a deadline is exceeded,
/// the TimeoutMonitor triggers appropriate actions (cancel, refund, escalate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Maximum time to complete multisig setup (prepare + exchange + finalize)
    ///
    /// After this period, escrow in "created" status is auto-cancelled.
    /// Default: 1 hour
    pub multisig_setup_timeout_secs: u64,

    /// Maximum time for buyer to fund the multisig address
    ///
    /// After this period, escrow in "funded" status (multisig ready but no deposit)
    /// is auto-cancelled and parties are notified.
    /// Default: 24 hours
    pub funding_timeout_secs: u64,

    /// Maximum time for blockchain transaction to confirm
    ///
    /// After this period, escrows in "releasing" or "refunding" status
    /// trigger alerts (transaction may be stuck in mempool).
    /// Default: 6 hours
    pub transaction_confirmation_timeout_secs: u64,

    /// Maximum time for arbiter to resolve a dispute
    ///
    /// After this period, dispute is escalated (admin intervention required).
    /// Default: 7 days
    pub dispute_resolution_timeout_secs: u64,

    /// Maximum time for vendor to ship after funding confirmed
    ///
    /// After this period, order is auto-disputed and buyer notified.
    /// Default: 14 days (1209600 seconds)
    pub shipping_timeout_secs: u64,

    /// How often the TimeoutMonitor polls for expired escrows
    ///
    /// Lower values = faster detection, higher DB load.
    /// Default: 60 seconds
    pub poll_interval_secs: u64,

    /// Send warning notification before expiration
    ///
    /// TimeoutMonitor sends EscrowExpiring event this many seconds before deadline.
    /// Default: 3600 seconds (1 hour)
    pub warning_threshold_secs: u64,

    /// Grace period for underfunded escrows (v0.68.0)
    ///
    /// After funding timeout, underfunded escrows enter a grace period
    /// during which the buyer can either complete funding or request refund.
    /// Default: 48 hours
    pub grace_period_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            multisig_setup_timeout_secs: 3600,            // 1 hour
            funding_timeout_secs: 86400,                  // 24 hours
            transaction_confirmation_timeout_secs: 21600, // 6 hours
            dispute_resolution_timeout_secs: 604800,      // 7 days
            shipping_timeout_secs: 1209600,               // 14 days
            poll_interval_secs: 60,                       // 1 minute
            warning_threshold_secs: 3600,                 // 1 hour
            grace_period_secs: 172800,                    // 48 hours (v0.68.0)
        }
    }
}

impl TimeoutConfig {
    /// Create TimeoutConfig from environment variables
    ///
    /// Reads configuration from:
    /// - TIMEOUT_MULTISIG_SETUP_SECS
    /// - TIMEOUT_FUNDING_SECS
    /// - TIMEOUT_TX_CONFIRMATION_SECS
    /// - TIMEOUT_DISPUTE_RESOLUTION_SECS
    /// - TIMEOUT_POLL_INTERVAL_SECS
    /// - TIMEOUT_WARNING_THRESHOLD_SECS
    ///
    /// Falls back to defaults if not set.
    pub fn from_env() -> Self {
        Self {
            multisig_setup_timeout_secs: std::env::var("TIMEOUT_MULTISIG_SETUP_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            funding_timeout_secs: std::env::var("TIMEOUT_FUNDING_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(86400),
            transaction_confirmation_timeout_secs: std::env::var("TIMEOUT_TX_CONFIRMATION_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(21600),
            dispute_resolution_timeout_secs: std::env::var("TIMEOUT_DISPUTE_RESOLUTION_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(604800),
            shipping_timeout_secs: std::env::var("TIMEOUT_SHIPPING_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1209600),
            poll_interval_secs: std::env::var("TIMEOUT_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
            warning_threshold_secs: std::env::var("TIMEOUT_WARNING_THRESHOLD_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            grace_period_secs: std::env::var("TIMEOUT_GRACE_PERIOD_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(172800), // 48 hours (v0.68.0)
        }
    }

    /// Get timeout duration for a specific escrow status
    ///
    /// Returns the configured timeout for the given status, or None if
    /// the status doesn't have an associated timeout policy.
    pub fn timeout_for_status(&self, status: &str) -> Option<Duration> {
        match status {
            "created" => Some(Duration::from_secs(self.multisig_setup_timeout_secs)),
            "funded" => Some(Duration::from_secs(self.funding_timeout_secs)),
            // v0.68.0: Underfunded uses same timeout as funded (then enters grace period)
            "underfunded" => Some(Duration::from_secs(self.funding_timeout_secs)),
            // v0.67: Shipping timeout - vendor must ship within 14 days
            "shipped_pending" | "awaiting_shipment" => {
                Some(Duration::from_secs(self.shipping_timeout_secs))
            }
            "releasing" | "refunding" => Some(Duration::from_secs(
                self.transaction_confirmation_timeout_secs,
            )),
            "disputed" => Some(Duration::from_secs(self.dispute_resolution_timeout_secs)),
            // Terminal states have no timeout
            "completed" | "refunded" | "cancelled" | "cancelled_recoverable" | "expired" => None,
            _ => None,
        }
    }

    /// Get grace period as Duration (v0.68.0)
    pub fn grace_period(&self) -> Duration {
        Duration::from_secs(self.grace_period_secs)
    }

    /// Get warning threshold as Duration
    pub fn warning_threshold(&self) -> Duration {
        Duration::from_secs(self.warning_threshold_secs)
    }

    /// Get poll interval as Duration
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TimeoutConfig::default();
        assert_eq!(config.multisig_setup_timeout_secs, 3600);
        assert_eq!(config.funding_timeout_secs, 86400);
        assert_eq!(config.transaction_confirmation_timeout_secs, 21600);
        assert_eq!(config.dispute_resolution_timeout_secs, 604800);
        assert_eq!(config.poll_interval_secs, 60);
        assert_eq!(config.warning_threshold_secs, 3600);
    }

    #[test]
    fn test_timeout_for_status() {
        let config = TimeoutConfig::default();

        // Active states with timeouts
        assert_eq!(
            config.timeout_for_status("created"),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            config.timeout_for_status("funded"),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(
            config.timeout_for_status("releasing"),
            Some(Duration::from_secs(21600))
        );
        assert_eq!(
            config.timeout_for_status("refunding"),
            Some(Duration::from_secs(21600))
        );
        assert_eq!(
            config.timeout_for_status("disputed"),
            Some(Duration::from_secs(604800))
        );

        // Terminal states with no timeout
        assert_eq!(config.timeout_for_status("completed"), None);
        assert_eq!(config.timeout_for_status("refunded"), None);
        assert_eq!(config.timeout_for_status("cancelled"), None);
        assert_eq!(config.timeout_for_status("expired"), None);
    }

    #[test]
    fn test_warning_threshold() {
        let config = TimeoutConfig::default();
        assert_eq!(config.warning_threshold(), Duration::from_secs(3600));
    }

    #[test]
    fn test_poll_interval() {
        let config = TimeoutConfig::default();
        assert_eq!(config.poll_interval(), Duration::from_secs(60));
    }

    #[test]
    fn test_from_env_defaults() {
        // When env vars are not set, should use defaults
        let config = TimeoutConfig::from_env();
        assert_eq!(config.multisig_setup_timeout_secs, 3600);
        assert_eq!(config.funding_timeout_secs, 86400);
    }
}
