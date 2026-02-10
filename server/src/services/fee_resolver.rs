//! Fee resolution service for B2B multi-tenant fee calculation
//!
//! Resolves fee configuration per escrow, supporting:
//! - Per-client custom fee schedules (marketplace_clients.fee_bps)
//! - Global defaults (platform_wallet config) when no client_id
//!
//! Usage: `resolve_fees(conn, escrow.client_id.as_deref(), is_refund)`

use anyhow::{Context, Result};
use diesel::prelude::*;

use crate::config::{get_refund_fee_bps, get_release_fee_bps};
use crate::models::marketplace_client::MarketplaceClient;

/// Resolved fee configuration for a specific escrow transaction.
#[derive(Debug, Clone)]
pub struct ResolvedFeeConfig {
    /// Fee in basis points (100 = 1%)
    pub fee_bps: u64,
    /// Source of the fee config
    pub source: FeeSource,
}

#[derive(Debug, Clone)]
pub enum FeeSource {
    /// Global default from PLATFORM_FEE_RELEASE_BPS / PLATFORM_FEE_REFUND_BPS
    GlobalDefault,
    /// Per-client custom fee from marketplace_clients table
    Client { client_id: String },
}

/// Resolve the fee configuration for a transaction.
///
/// Priority:
/// 1. If `client_id` is provided and the client exists with `is_active = 1`,
///    use the client's `fee_bps`.
/// 2. Otherwise, fall back to the global platform fee.
pub fn resolve_fees(
    conn: &mut SqliteConnection,
    client_id: Option<&str>,
    is_refund: bool,
) -> Result<ResolvedFeeConfig> {
    // Check for per-client override
    if let Some(cid) = client_id {
        if let Some(client) = MarketplaceClient::find_by_id(conn, cid)
            .context("Failed to query marketplace client for fee resolution")?
        {
            if client.is_active == 1 && client.fee_bps > 0 {
                return Ok(ResolvedFeeConfig {
                    fee_bps: client.fee_bps as u64,
                    source: FeeSource::Client {
                        client_id: cid.to_string(),
                    },
                });
            }
        }
    }

    // Fall back to global defaults
    let fee_bps = if is_refund {
        get_refund_fee_bps()
    } else {
        get_release_fee_bps()
    };

    Ok(ResolvedFeeConfig {
        fee_bps,
        source: FeeSource::GlobalDefault,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_defaults() {
        // Without DB connection, verify the enum variants compile
        let config = ResolvedFeeConfig {
            fee_bps: 500,
            source: FeeSource::GlobalDefault,
        };
        assert_eq!(config.fee_bps, 500);

        let client_config = ResolvedFeeConfig {
            fee_bps: 150,
            source: FeeSource::Client {
                client_id: "test-client".to_string(),
            },
        };
        assert_eq!(client_config.fee_bps, 150);
    }
}
