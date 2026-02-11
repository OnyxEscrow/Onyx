//! Fee estimation for Monero transactions
//!
//! Provides accurate fee estimation using the daemon RPC `get_fee_estimate` method.
//! Supports multiple priority levels and proper fee quantization per Monero protocol.

use monero_marketplace_common::error::MoneroError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Fee priority levels matching Monero wallet priorities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FeePriority {
    /// Unimportant (1x multiplier) - may take longer to confirm
    Unimportant,
    /// Normal priority (4x multiplier) - default, ~20 min confirmation
    #[default]
    Normal,
    /// Elevated priority (20x multiplier) - faster confirmation
    Elevated,
    /// Priority (166x multiplier) - near-instant inclusion
    Priority,
}

impl FeePriority {
    /// Get the fee multiplier for this priority level
    /// Based on Monero's wallet2.cpp fee multipliers
    pub fn multiplier(&self) -> u64 {
        match self {
            FeePriority::Unimportant => 1,
            FeePriority::Normal => 4,
            FeePriority::Elevated => 20,
            FeePriority::Priority => 166,
        }
    }

    /// Get grace blocks for this priority (affects get_fee_estimate)
    /// More grace blocks = lower fee estimate
    pub fn grace_blocks(&self) -> u64 {
        match self {
            FeePriority::Unimportant => 50,
            FeePriority::Normal => 10,
            FeePriority::Elevated => 5,
            FeePriority::Priority => 0,
        }
    }
}

impl std::str::FromStr for FeePriority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unimportant" | "low" => Ok(FeePriority::Unimportant),
            "normal" | "default" | "medium" => Ok(FeePriority::Normal),
            "elevated" | "high" => Ok(FeePriority::Elevated),
            "priority" | "urgent" => Ok(FeePriority::Priority),
            _ => Err(format!(
                "Unknown priority: {s}. Valid: unimportant, normal, elevated, priority"
            )),
        }
    }
}

/// Estimated fee for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Fee per byte in atomic units (piconero)
    pub fee_per_byte: u64,
    /// Quantization mask used for fee calculation
    pub quantization_mask: u64,
    /// Estimated fee for a typical 2-output transaction (~1500 bytes)
    pub estimated_fee_2_outputs: u64,
    /// Estimated fee for a 3-output transaction (~2000 bytes)
    pub estimated_fee_3_outputs: u64,
    /// Priority level used for estimation
    pub priority: FeePriority,
    /// Whether fee estimation is available (false if daemon unreachable)
    pub available: bool,
}

impl FeeEstimate {
    /// Calculate fee for a given transaction size with proper quantization
    ///
    /// Fee calculation follows Monero protocol:
    /// `fee = (size * fee_per_byte + mask - 1) / mask * mask`
    pub fn calculate_fee(&self, tx_size_bytes: u64) -> u64 {
        let raw_fee = tx_size_bytes * self.fee_per_byte;
        quantize_fee(raw_fee, self.quantization_mask)
    }
}

/// Quantize fee according to Monero protocol
/// Formula: `(fee + mask - 1) / mask * mask`
/// This rounds up to the nearest multiple of the mask
fn quantize_fee(fee: u64, mask: u64) -> u64 {
    if mask == 0 {
        return fee;
    }
    fee.div_ceil(mask) * mask
}

/// Response from daemon RPC get_fee_estimate
#[derive(Debug, Deserialize)]
struct GetFeeEstimateResponse {
    fee: u64,
    #[serde(default)]
    quantization_mask: u64,
    status: String,
}

/// Fee estimation client for Monero daemon RPC
#[derive(Clone)]
pub struct FeeEstimator {
    daemon_url: String,
    client: Client,
}

impl FeeEstimator {
    /// Create a new fee estimator for a daemon URL
    ///
    /// # Arguments
    /// * `daemon_url` - Monero daemon RPC URL (e.g., "http://127.0.0.1:18081")
    pub fn new(daemon_url: &str) -> Result<Self, MoneroError> {
        // Validate localhost for security
        if !daemon_url.contains("127.0.0.1") && !daemon_url.contains("localhost") {
            return Err(MoneroError::ValidationError(
                "Daemon URL must be localhost for security".to_string(),
            ));
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| MoneroError::NetworkError(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            daemon_url: daemon_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    /// Get fee estimate from daemon
    ///
    /// # Arguments
    /// * `priority` - Fee priority level
    ///
    /// # Returns
    /// `FeeEstimate` with fee per byte and estimated transaction fees
    pub async fn get_fee_estimate(
        &self,
        priority: FeePriority,
    ) -> Result<FeeEstimate, MoneroError> {
        let grace_blocks = priority.grace_blocks();

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_fee_estimate",
            "params": {
                "grace_blocks": grace_blocks
            }
        });

        let response = self
            .client
            .post(format!("{}/json_rpc", self.daemon_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    MoneroError::RpcUnreachable
                } else {
                    MoneroError::NetworkError(e.to_string())
                }
            })?;

        if !response.status().is_success() {
            return Err(MoneroError::RpcError(format!(
                "Daemon returned HTTP {}",
                response.status()
            )));
        }

        let rpc_response: serde_json::Value = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse error: {e}")))?;

        // Check for RPC error
        if let Some(error) = rpc_response.get("error") {
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");
            return Err(MoneroError::RpcError(message.to_string()));
        }

        let result = rpc_response
            .get("result")
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        let fee_per_byte = result
            .get("fee")
            .and_then(|f| f.as_u64())
            .ok_or_else(|| MoneroError::InvalidResponse("Missing fee field".to_string()))?;

        // Default quantization mask if not provided (Monero v0.18+)
        let quantization_mask = result
            .get("quantization_mask")
            .and_then(|m| m.as_u64())
            .unwrap_or(10000); // Default 10000 piconero

        let status = result
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("OK");

        if status != "OK" {
            return Err(MoneroError::RpcError(format!("Daemon status: {status}")));
        }

        // Apply priority multiplier
        let adjusted_fee = fee_per_byte * priority.multiplier();

        // Calculate estimated fees for typical transaction sizes
        // 2-output tx: ~1500 bytes (normal release/refund)
        // 3-output tx: ~2000 bytes (release with platform fee)
        let estimated_fee_2_outputs = quantize_fee(adjusted_fee * 1500, quantization_mask);
        let estimated_fee_3_outputs = quantize_fee(adjusted_fee * 2000, quantization_mask);

        Ok(FeeEstimate {
            fee_per_byte: adjusted_fee,
            quantization_mask,
            estimated_fee_2_outputs,
            estimated_fee_3_outputs,
            priority,
            available: true,
        })
    }

    /// Get fee estimates for all priority levels
    pub async fn get_all_fee_estimates(&self) -> Result<Vec<FeeEstimate>, MoneroError> {
        let priorities = [
            FeePriority::Unimportant,
            FeePriority::Normal,
            FeePriority::Elevated,
            FeePriority::Priority,
        ];

        let mut estimates = Vec::with_capacity(4);
        for priority in priorities {
            estimates.push(self.get_fee_estimate(priority).await?);
        }

        Ok(estimates)
    }
}

/// Default fee estimate when daemon is unreachable
/// Uses conservative mainnet values (2024 averages)
pub fn default_fee_estimate(priority: FeePriority) -> FeeEstimate {
    // Conservative base fee (mainnet 2024 average: ~20000 piconero/byte)
    let base_fee = 20000u64;
    let quantization_mask = 10000u64;

    let adjusted_fee = base_fee * priority.multiplier();
    let estimated_fee_2_outputs = quantize_fee(adjusted_fee * 1500, quantization_mask);
    let estimated_fee_3_outputs = quantize_fee(adjusted_fee * 2000, quantization_mask);

    FeeEstimate {
        fee_per_byte: adjusted_fee,
        quantization_mask,
        estimated_fee_2_outputs,
        estimated_fee_3_outputs,
        priority,
        available: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_quantization() {
        // Test with mask of 10000
        assert_eq!(quantize_fee(9999, 10000), 10000);
        assert_eq!(quantize_fee(10000, 10000), 10000);
        assert_eq!(quantize_fee(10001, 10000), 20000);
        assert_eq!(quantize_fee(15000, 10000), 20000);
        assert_eq!(quantize_fee(20000, 10000), 20000);
        assert_eq!(quantize_fee(20001, 10000), 30000);

        // Zero mask should return original fee
        assert_eq!(quantize_fee(12345, 0), 12345);
    }

    #[test]
    fn test_priority_multipliers() {
        assert_eq!(FeePriority::Unimportant.multiplier(), 1);
        assert_eq!(FeePriority::Normal.multiplier(), 4);
        assert_eq!(FeePriority::Elevated.multiplier(), 20);
        assert_eq!(FeePriority::Priority.multiplier(), 166);
    }

    #[test]
    fn test_priority_from_str() {
        assert_eq!(
            "normal".parse::<FeePriority>().unwrap(),
            FeePriority::Normal
        );
        assert_eq!(
            "low".parse::<FeePriority>().unwrap(),
            FeePriority::Unimportant
        );
        assert_eq!(
            "high".parse::<FeePriority>().unwrap(),
            FeePriority::Elevated
        );
        assert_eq!(
            "urgent".parse::<FeePriority>().unwrap(),
            FeePriority::Priority
        );
        assert!("invalid".parse::<FeePriority>().is_err());
    }

    #[test]
    fn test_default_fee_estimate() {
        let estimate = default_fee_estimate(FeePriority::Normal);
        assert!(!estimate.available);
        assert!(estimate.fee_per_byte > 0);
        assert!(estimate.estimated_fee_2_outputs > 0);
        assert!(estimate.estimated_fee_3_outputs > estimate.estimated_fee_2_outputs);
    }

    #[test]
    fn test_fee_estimate_calculation() {
        let estimate = FeeEstimate {
            fee_per_byte: 20000,
            quantization_mask: 10000,
            estimated_fee_2_outputs: 0,
            estimated_fee_3_outputs: 0,
            priority: FeePriority::Normal,
            available: true,
        };

        // 1500 bytes * 20000 = 30_000_000 piconero
        // Quantized: 30_000_000 (already multiple of 10000)
        assert_eq!(estimate.calculate_fee(1500), 30000000);

        // 1501 bytes * 20000 = 30_020_000 piconero
        // Quantized: 30_020_000 (already multiple of 10000)
        assert_eq!(estimate.calculate_fee(1501), 30020000);

        // 1502 bytes * 20000 = 30_040_000 piconero
        // Quantized: 30_040_000 (already multiple of 10000)
        assert_eq!(estimate.calculate_fee(1502), 30040000);
    }
}
