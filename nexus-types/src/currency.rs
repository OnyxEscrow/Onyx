//! Currency types and conversion utilities
//!
//! Provides currency enums and helpers for BTC/XMR amounts.

use serde::{Deserialize, Serialize};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Supported currencies in NEXUS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum Currency {
    /// Bitcoin (on-chain)
    BTC,
    /// Bitcoin Lightning
    #[serde(rename = "BTC_LN")]
    BtcLightning,
    /// Monero
    XMR,
}

impl Currency {
    /// Get currency code as string
    pub fn code(&self) -> &'static str {
        match self {
            Currency::BTC => "BTC",
            Currency::BtcLightning => "BTC_LN",
            Currency::XMR => "XMR",
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Currency::BTC => "Bitcoin",
            Currency::BtcLightning => "Bitcoin Lightning",
            Currency::XMR => "Monero",
        }
    }

    /// Get smallest unit name
    pub fn smallest_unit(&self) -> &'static str {
        match self {
            Currency::BTC | Currency::BtcLightning => "satoshi",
            Currency::XMR => "piconero",
        }
    }

    /// Conversion factor to smallest unit
    pub fn to_atomic_factor(&self) -> u64 {
        match self {
            Currency::BTC | Currency::BtcLightning => 100_000_000,        // 1 BTC = 10^8 sats
            Currency::XMR => 1_000_000_000_000,                            // 1 XMR = 10^12 piconeros
        }
    }
}

impl std::fmt::Display for Currency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::str::FromStr for Currency {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "BTC" | "BITCOIN" => Ok(Currency::BTC),
            "BTC_LN" | "LIGHTNING" | "LN" => Ok(Currency::BtcLightning),
            "XMR" | "MONERO" => Ok(Currency::XMR),
            _ => Err(format!("Unknown currency: {}", s)),
        }
    }
}

// ============================================================================
// WASM Exports
// ============================================================================

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl Currency {
    /// Get currency code as string (WASM export)
    #[wasm_bindgen(js_name = "getCode")]
    pub fn js_code(&self) -> String {
        self.code().to_string()
    }

    /// Get human-readable name (WASM export)
    #[wasm_bindgen(js_name = "getName")]
    pub fn js_name(&self) -> String {
        self.name().to_string()
    }
}

// ============================================================================
// Amount Conversion Helpers
// ============================================================================

/// Bitcoin amount in satoshis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcAmount(pub u64);

impl BtcAmount {
    /// Create from satoshis
    pub fn from_sats(sats: u64) -> Self {
        Self(sats)
    }

    /// Create from BTC (floating point)
    pub fn from_btc(btc: f64) -> Self {
        Self((btc * 100_000_000.0) as u64)
    }

    /// Get value in satoshis
    pub fn sats(&self) -> u64 {
        self.0
    }

    /// Get value in BTC
    pub fn btc(&self) -> f64 {
        self.0 as f64 / 100_000_000.0
    }

    /// Format for display (e.g., "0.00123456 BTC")
    pub fn display(&self) -> String {
        format!("{:.8} BTC", self.btc())
    }
}

/// Monero amount in piconeros (atomic units)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmrAmount(pub u64);

impl XmrAmount {
    /// Create from piconeros
    pub fn from_atomic(atomic: u64) -> Self {
        Self(atomic)
    }

    /// Create from XMR (floating point)
    pub fn from_xmr(xmr: f64) -> Self {
        Self((xmr * 1_000_000_000_000.0) as u64)
    }

    /// Get value in piconeros
    pub fn atomic(&self) -> u64 {
        self.0
    }

    /// Get value in XMR
    pub fn xmr(&self) -> f64 {
        self.0 as f64 / 1_000_000_000_000.0
    }

    /// Format for display (e.g., "1.234567890123 XMR")
    pub fn display(&self) -> String {
        format!("{:.12} XMR", self.xmr())
    }
}

// ============================================================================
// Payment Method
// ============================================================================

/// Payment method for orders
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum PaymentMethod {
    /// Direct XMR payment to escrow
    #[serde(rename = "xmr")]
    Xmr,
    /// BTC on-chain → swap → XMR escrow
    #[serde(rename = "btc_onchain")]
    BtcOnchain,
    /// BTC Lightning → swap → XMR escrow
    #[serde(rename = "btc_lightning")]
    BtcLightning,
}

impl PaymentMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            PaymentMethod::Xmr => "xmr",
            PaymentMethod::BtcOnchain => "btc_onchain",
            PaymentMethod::BtcLightning => "btc_lightning",
        }
    }

    /// Whether this payment method requires a swap
    pub fn requires_swap(&self) -> bool {
        matches!(self, PaymentMethod::BtcOnchain | PaymentMethod::BtcLightning)
    }

    /// Get the source currency for this payment method
    pub fn source_currency(&self) -> Currency {
        match self {
            PaymentMethod::Xmr => Currency::XMR,
            PaymentMethod::BtcOnchain => Currency::BTC,
            PaymentMethod::BtcLightning => Currency::BtcLightning,
        }
    }
}

impl std::fmt::Display for PaymentMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for PaymentMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "xmr" => Ok(PaymentMethod::Xmr),
            "btc_onchain" => Ok(PaymentMethod::BtcOnchain),
            "btc_lightning" => Ok(PaymentMethod::BtcLightning),
            _ => Err(format!("Unknown payment method: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_currency_display() {
        assert_eq!(Currency::BTC.code(), "BTC");
        assert_eq!(Currency::XMR.code(), "XMR");
        assert_eq!(Currency::BtcLightning.code(), "BTC_LN");
    }

    #[test]
    fn test_btc_amount() {
        let amt = BtcAmount::from_btc(1.5);
        assert_eq!(amt.sats(), 150_000_000);
        assert!((amt.btc() - 1.5).abs() < 0.0001);
    }

    #[test]
    fn test_xmr_amount() {
        let amt = XmrAmount::from_xmr(2.5);
        assert_eq!(amt.atomic(), 2_500_000_000_000);
        assert!((amt.xmr() - 2.5).abs() < 0.0001);
    }

    #[test]
    fn test_payment_method() {
        assert!(!PaymentMethod::Xmr.requires_swap());
        assert!(PaymentMethod::BtcOnchain.requires_swap());
        assert!(PaymentMethod::BtcLightning.requires_swap());
    }
}
