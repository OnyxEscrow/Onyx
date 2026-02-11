//! Swap Types for BTC→XMR Exchange
//!
//! Types used for communication between:
//! - WASM clients (escrow address generation)
//! - Server (swap provider coordination via Tor)
//! - Frontend (payment UI)

use serde::{Deserialize, Serialize};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::currency::{Currency, PaymentMethod};

// ============================================================================
// Swap Provider Types
// ============================================================================

/// Available swap providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SwapProvider {
    /// FixedFloat.com - Primary provider
    FixedFloat,
    /// Trocador.app - Privacy-focused aggregator
    Trocador,
    /// Future: Native CMD atomic swaps
    Atomic,
}

impl SwapProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            SwapProvider::FixedFloat => "fixedfloat",
            SwapProvider::Trocador => "trocador",
            SwapProvider::Atomic => "atomic",
        }
    }

    /// Fee percentage for this provider
    pub fn fee_percent(&self) -> f64 {
        match self {
            SwapProvider::FixedFloat => 0.5,
            SwapProvider::Trocador => 0.5, // Varies by underlying exchange
            SwapProvider::Atomic => 0.0,   // Network fees only
        }
    }

    /// Estimated time in minutes
    pub fn estimated_time_minutes(&self) -> u16 {
        match self {
            SwapProvider::FixedFloat => 15,
            SwapProvider::Trocador => 20,
            SwapProvider::Atomic => 30, // Atomic swaps take longer
        }
    }
}

impl std::fmt::Display for SwapProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SwapProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fixedfloat" => Ok(SwapProvider::FixedFloat),
            "trocador" => Ok(SwapProvider::Trocador),
            "atomic" => Ok(SwapProvider::Atomic),
            _ => Err(format!("Unknown swap provider: {s}")),
        }
    }
}

// ============================================================================
// Swap Status
// ============================================================================

/// Status of a swap order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SwapStatus {
    /// Waiting for user to send BTC
    AwaitingDeposit,
    /// BTC transaction detected in mempool
    DepositDetected,
    /// BTC transaction confirmed
    DepositConfirmed,
    /// Provider executing the swap
    Swapping,
    /// XMR sent to escrow address
    SwapComplete,
    /// Full flow completed and verified
    Completed,
    /// Quote expired before deposit
    Expired,
    /// Swap failed
    Failed,
    /// BTC refunded to user
    Refunded,
}

impl SwapStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SwapStatus::AwaitingDeposit => "awaiting_deposit",
            SwapStatus::DepositDetected => "deposit_detected",
            SwapStatus::DepositConfirmed => "deposit_confirmed",
            SwapStatus::Swapping => "swapping",
            SwapStatus::SwapComplete => "swap_complete",
            SwapStatus::Completed => "completed",
            SwapStatus::Expired => "expired",
            SwapStatus::Failed => "failed",
            SwapStatus::Refunded => "refunded",
        }
    }

    /// Is this a terminal status?
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SwapStatus::Completed | SwapStatus::Expired | SwapStatus::Failed | SwapStatus::Refunded
        )
    }

    /// Is this a success status?
    pub fn is_success(&self) -> bool {
        matches!(self, SwapStatus::Completed | SwapStatus::SwapComplete)
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            SwapStatus::AwaitingDeposit => "Waiting for your BTC payment",
            SwapStatus::DepositDetected => "BTC payment detected, waiting for confirmation",
            SwapStatus::DepositConfirmed => "BTC payment confirmed, starting swap",
            SwapStatus::Swapping => "Converting BTC to XMR",
            SwapStatus::SwapComplete => "XMR sent to escrow",
            SwapStatus::Completed => "Swap completed successfully",
            SwapStatus::Expired => "Quote expired - please create a new order",
            SwapStatus::Failed => "Swap failed - contact support",
            SwapStatus::Refunded => "BTC refunded to your address",
        }
    }
}

impl std::fmt::Display for SwapStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SwapStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "awaiting_deposit" => Ok(SwapStatus::AwaitingDeposit),
            "deposit_detected" => Ok(SwapStatus::DepositDetected),
            "deposit_confirmed" => Ok(SwapStatus::DepositConfirmed),
            "swapping" => Ok(SwapStatus::Swapping),
            "swap_complete" => Ok(SwapStatus::SwapComplete),
            "completed" => Ok(SwapStatus::Completed),
            "expired" => Ok(SwapStatus::Expired),
            "failed" => Ok(SwapStatus::Failed),
            "refunded" => Ok(SwapStatus::Refunded),
            _ => Err(format!("Unknown swap status: {s}")),
        }
    }
}

// ============================================================================
// API Request/Response Types (Shared between server & frontend)
// ============================================================================

/// Request to create a swap (sent from frontend to server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSwapRequest {
    /// Order ID this swap is for
    pub order_id: String,
    /// XMR escrow address (generated by WASM)
    pub escrow_address: String,
    /// Amount of XMR needed (piconeros)
    pub xmr_amount: u64,
    /// Preferred payment method
    pub payment_method: PaymentMethod,
    /// Optional: preferred provider
    pub preferred_provider: Option<SwapProvider>,
}

/// Response from creating a swap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSwapResponse {
    /// Swap order details
    pub swap_order: SwapOrderInfo,
    /// BTC amount to pay (satoshis)
    pub btc_amount: u64,
    /// Exchange rate used (BTC/XMR)
    pub rate: f64,
    /// Quote valid until (Unix timestamp)
    pub valid_until: i64,
}

/// Swap order information (returned to frontend)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapOrderInfo {
    /// Internal swap order ID
    pub id: String,
    /// Order ID this swap is for
    pub order_id: String,
    /// Provider handling the swap
    pub provider: SwapProvider,
    /// BTC deposit address (user pays here)
    pub deposit_address: String,
    /// XMR payout address (escrow)
    pub payout_address: String,
    /// Current status
    pub status: SwapStatus,
    /// BTC amount to deposit (satoshis)
    pub btc_amount: u64,
    /// Expected XMR amount (piconeros)
    pub xmr_amount: u64,
    /// Created timestamp (Unix)
    pub created_at: i64,
    /// Status description for UI
    pub status_description: String,
}

/// Request to check swap status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSwapStatusRequest {
    /// Swap order ID
    pub swap_id: String,
}

/// Response with swap status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSwapStatusResponse {
    /// Swap order info with updated status
    pub swap_order: SwapOrderInfo,
    /// BTC transaction hash (if deposited)
    pub btc_tx_hash: Option<String>,
    /// BTC confirmations
    pub btc_confirmations: Option<u32>,
    /// XMR transaction hash (if completed)
    pub xmr_tx_hash: Option<String>,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Quote request (get rate without creating swap)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteRequest {
    /// Source currency
    pub from_currency: Currency,
    /// Destination currency
    pub to_currency: Currency,
    /// Amount to swap (in source currency atomic units)
    pub amount: u64,
    /// Direction: "from" (amount is source) or "to" (amount is destination)
    pub direction: String,
}

/// Quote response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapQuote {
    /// Provider offering this quote
    pub provider: SwapProvider,
    /// Amount to send (atomic units)
    pub from_amount: u64,
    /// Amount to receive (atomic units)
    pub to_amount: u64,
    /// Exchange rate
    pub rate: f64,
    /// Fee percentage
    pub fee_percent: f64,
    /// Estimated time (minutes)
    pub estimated_minutes: u16,
    /// Quote valid until (Unix timestamp)
    pub valid_until: i64,
}

// ============================================================================
// WASM Exports
// ============================================================================

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl SwapProvider {
    #[wasm_bindgen(js_name = "getName")]
    pub fn js_name(&self) -> String {
        self.as_str().to_string()
    }

    #[wasm_bindgen(js_name = "getFeePercent")]
    pub fn js_fee_percent(&self) -> f64 {
        self.fee_percent()
    }

    #[wasm_bindgen(js_name = "getEstimatedMinutes")]
    pub fn js_estimated_minutes(&self) -> u16 {
        self.estimated_time_minutes()
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl SwapStatus {
    #[wasm_bindgen(js_name = "getName")]
    pub fn js_name(&self) -> String {
        self.as_str().to_string()
    }

    #[wasm_bindgen(js_name = "getDescription")]
    pub fn js_description(&self) -> String {
        self.description().to_string()
    }

    #[wasm_bindgen(js_name = "isTerminal")]
    pub fn js_is_terminal(&self) -> bool {
        self.is_terminal()
    }

    #[wasm_bindgen(js_name = "isSuccess")]
    pub fn js_is_success(&self) -> bool {
        self.is_success()
    }
}

// ============================================================================
// JSON Serialization Helpers (for JS interop)
// ============================================================================

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn parse_swap_quote(json: &str) -> Result<JsValue, JsValue> {
    let quote: SwapQuote = serde_json::from_str(json)
        .map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;

    serde_wasm_bindgen::to_value(&quote)
        .map_err(|e| JsValue::from_str(&format!("Serialize error: {}", e)))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn parse_swap_order_info(json: &str) -> Result<JsValue, JsValue> {
    let info: SwapOrderInfo = serde_json::from_str(json)
        .map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;

    serde_wasm_bindgen::to_value(&info)
        .map_err(|e| JsValue::from_str(&format!("Serialize error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_provider() {
        assert_eq!(SwapProvider::FixedFloat.as_str(), "fixedfloat");
        assert!(SwapProvider::FixedFloat.fee_percent() > 0.0);
    }

    #[test]
    fn test_swap_status() {
        assert!(!SwapStatus::AwaitingDeposit.is_terminal());
        assert!(SwapStatus::Completed.is_terminal());
        assert!(SwapStatus::Completed.is_success());
        assert!(!SwapStatus::Failed.is_success());
    }

    #[test]
    fn test_create_swap_request_serialization() {
        let req = CreateSwapRequest {
            order_id: "order_123".to_string(),
            escrow_address: "44ABC...XYZ".to_string(),
            xmr_amount: 1_000_000_000_000,
            payment_method: PaymentMethod::BtcOnchain,
            preferred_provider: Some(SwapProvider::FixedFloat),
        };

        let json = serde_json::to_string(&req).unwrap();
        let parsed: CreateSwapRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.order_id, req.order_id);
        assert_eq!(parsed.xmr_amount, req.xmr_amount);
    }

    #[test]
    fn test_swap_order_info_serialization() {
        let info = SwapOrderInfo {
            id: "swap_123".to_string(),
            order_id: "order_456".to_string(),
            provider: SwapProvider::FixedFloat,
            deposit_address: "bc1q...".to_string(),
            payout_address: "44ABC...".to_string(),
            status: SwapStatus::AwaitingDeposit,
            btc_amount: 100_000,
            xmr_amount: 1_000_000_000_000,
            created_at: 1705670400,
            status_description: "Waiting for payment".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("fixedfloat"));
        assert!(json.contains("awaiting_deposit"));
    }
}
