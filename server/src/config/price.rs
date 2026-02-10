//! XMR/USD price display configuration
//!
//! Provides admin-configured exchange rate for displaying USD equivalents.
//! No external API calls - rate is set via XMR_USD_RATE environment variable.

use std::env;

/// XMR/USD exchange rate for price display (admin-configured, no external API)
/// Stored as app_data and accessed by frontend handlers
#[derive(Clone, Copy, Debug)]
pub struct XmrUsdRate(pub f64);

impl XmrUsdRate {
    /// Load rate from environment variable XMR_USD_RATE
    /// Returns XmrUsdRate(0.0) if not set or invalid
    pub fn from_env() -> Self {
        let rate = env::var("XMR_USD_RATE")
            .unwrap_or_else(|_| "0.0".to_string())
            .parse()
            .unwrap_or(0.0);
        Self(rate)
    }

    /// Convert XMR amount to USD equivalent
    /// Returns None if rate is not configured (0.0)
    pub fn to_usd(&self, xmr: f64) -> Option<f64> {
        if self.0 > 0.0 {
            Some(xmr * self.0)
        } else {
            None
        }
    }

    /// Returns true if USD display is enabled
    pub fn is_enabled(&self) -> bool {
        self.0 > 0.0
    }

    /// Get the raw rate value
    pub fn rate(&self) -> f64 {
        self.0
    }
}

impl Default for XmrUsdRate {
    fn default() -> Self {
        Self(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmr_usd_rate_disabled() {
        let rate = XmrUsdRate(0.0);
        assert!(!rate.is_enabled());
        assert!(rate.to_usd(1.0).is_none());
    }

    #[test]
    fn test_xmr_usd_rate_enabled() {
        let rate = XmrUsdRate(150.0);
        assert!(rate.is_enabled());
        assert_eq!(rate.to_usd(1.0), Some(150.0));
        assert_eq!(rate.to_usd(0.5), Some(75.0));
    }

    #[test]
    fn test_xmr_usd_rate_precision() {
        let rate = XmrUsdRate(150.0);
        // 0.001234 XMR at $150/XMR = $0.1851
        let usd = rate.to_usd(0.001234).unwrap();
        assert!((usd - 0.1851).abs() < 0.0001);
    }
}
