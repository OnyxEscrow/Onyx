//! Fee estimation API handlers
//!
//! Provides endpoints for querying Monero transaction fee estimates.
//! Uses the daemon pool for high-availability fee estimation.

use actix_web::{get, web, HttpResponse};
use monero_marketplace_wallet::{
    fee_estimation::{default_fee_estimate, FeeEstimate, FeePriority},
    DaemonPool,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Query parameters for fee estimation
#[derive(Debug, Deserialize)]
pub struct FeeEstimateQuery {
    /// Priority level: unimportant, normal (default), elevated, priority
    #[serde(default)]
    pub priority: Option<String>,
    /// Transaction size in bytes (optional, for custom size estimation)
    pub tx_size: Option<u64>,
}

/// Response for fee estimation endpoint
#[derive(Debug, Serialize)]
pub struct FeeEstimateResponse {
    /// Fee per byte in atomic units (piconero)
    pub fee_per_byte: u64,
    /// Quantization mask
    pub quantization_mask: u64,
    /// Estimated fee for 2-output transaction (typical release/refund)
    pub estimated_fee_2_outputs: u64,
    /// Estimated fee for 3-output transaction (release with platform fee)
    pub estimated_fee_3_outputs: u64,
    /// Estimated fee for custom size (if tx_size provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_fee_custom: Option<u64>,
    /// Priority level used
    pub priority: String,
    /// Whether estimate is from live daemon (false = cached/default)
    pub live: bool,
    /// Fee in XMR for display (2-output transaction)
    pub fee_xmr: String,
}

impl From<FeeEstimate> for FeeEstimateResponse {
    fn from(estimate: FeeEstimate) -> Self {
        // Convert piconero to XMR for display (1 XMR = 10^12 piconero)
        let fee_xmr = estimate.estimated_fee_2_outputs as f64 / 1_000_000_000_000.0;

        Self {
            fee_per_byte: estimate.fee_per_byte,
            quantization_mask: estimate.quantization_mask,
            estimated_fee_2_outputs: estimate.estimated_fee_2_outputs,
            estimated_fee_3_outputs: estimate.estimated_fee_3_outputs,
            estimated_fee_custom: None,
            priority: format!("{:?}", estimate.priority).to_lowercase(),
            live: estimate.available,
            fee_xmr: format!("{:.12}", fee_xmr),
        }
    }
}

/// Response for all fee estimates
#[derive(Debug, Serialize)]
pub struct AllFeeEstimatesResponse {
    pub estimates: Vec<FeeEstimateResponse>,
    pub recommended: String,
    pub daemon_height: Option<u64>,
    pub daemon_url: Option<String>,
}

/// GET /api/v1/fees/estimate
///
/// Get fee estimate for a Monero transaction.
///
/// Query parameters:
/// - `priority`: Fee priority (unimportant, normal, elevated, priority). Default: normal
/// - `tx_size`: Custom transaction size in bytes for fee calculation
///
/// Example responses:
///
/// Success (daemon available):
/// ```json
/// {
///   "fee_per_byte": 80000,
///   "quantization_mask": 10000,
///   "estimated_fee_2_outputs": 120000000,
///   "estimated_fee_3_outputs": 160000000,
///   "priority": "normal",
///   "live": true,
///   "fee_xmr": "0.000120000000"
/// }
/// ```
///
/// Fallback (daemon unavailable):
/// ```json
/// {
///   "fee_per_byte": 80000,
///   "quantization_mask": 10000,
///   "estimated_fee_2_outputs": 120000000,
///   "estimated_fee_3_outputs": 160000000,
///   "priority": "normal",
///   "live": false,
///   "fee_xmr": "0.000120000000"
/// }
/// ```
#[get("/v1/fees/estimate")]
pub async fn get_fee_estimate(
    daemon_pool: web::Data<Arc<DaemonPool>>,
    query: web::Query<FeeEstimateQuery>,
) -> HttpResponse {
    // Parse priority
    let priority = query
        .priority
        .as_ref()
        .and_then(|p| p.parse::<FeePriority>().ok())
        .unwrap_or(FeePriority::Normal);

    // Try to get live estimate from daemon
    let estimate = match daemon_pool.get_fee_estimate(priority).await {
        Ok(est) => est,
        Err(e) => {
            tracing::warn!(
                "Failed to get fee estimate from daemon: {}, using default",
                e
            );
            default_fee_estimate(priority)
        }
    };

    let mut response = FeeEstimateResponse::from(estimate.clone());

    // Calculate custom size fee if requested
    if let Some(tx_size) = query.tx_size {
        response.estimated_fee_custom = Some(estimate.calculate_fee(tx_size));
    }

    HttpResponse::Ok().json(response)
}

/// GET /api/v1/fees/all
///
/// Get fee estimates for all priority levels.
///
/// Returns estimates for: unimportant, normal, elevated, priority
///
/// Example response:
/// ```json
/// {
///   "estimates": [
///     { "priority": "unimportant", "fee_per_byte": 20000, ... },
///     { "priority": "normal", "fee_per_byte": 80000, ... },
///     { "priority": "elevated", "fee_per_byte": 400000, ... },
///     { "priority": "priority", "fee_per_byte": 3320000, ... }
///   ],
///   "recommended": "normal",
///   "daemon_height": 3000000,
///   "daemon_url": "http://127.0.0.1:18081"
/// }
/// ```
#[get("/v1/fees/all")]
pub async fn get_all_fee_estimates(daemon_pool: web::Data<Arc<DaemonPool>>) -> HttpResponse {
    // Get daemon info for height
    let (daemon_height, daemon_url) = match daemon_pool.get_info().await {
        Ok(info) => (Some(info.height), Some(info.served_by)),
        Err(_) => (None, None),
    };

    // Get all estimates
    let estimates = match daemon_pool.get_all_fee_estimates().await {
        Ok(ests) => ests.into_iter().map(FeeEstimateResponse::from).collect(),
        Err(e) => {
            tracing::warn!(
                "Failed to get fee estimates from daemon: {}, using defaults",
                e
            );
            vec![
                FeeEstimateResponse::from(default_fee_estimate(FeePriority::Unimportant)),
                FeeEstimateResponse::from(default_fee_estimate(FeePriority::Normal)),
                FeeEstimateResponse::from(default_fee_estimate(FeePriority::Elevated)),
                FeeEstimateResponse::from(default_fee_estimate(FeePriority::Priority)),
            ]
        }
    };

    HttpResponse::Ok().json(AllFeeEstimatesResponse {
        estimates,
        recommended: "normal".to_string(),
        daemon_height,
        daemon_url,
    })
}

/// Daemon health summary response
#[derive(Debug, Serialize)]
pub struct DaemonHealthSummary {
    /// Total number of endpoints
    pub total: usize,
    /// Number of healthy endpoints
    pub healthy: usize,
    /// Number of unhealthy endpoints
    pub unhealthy: usize,
    /// Average response time of healthy endpoints (ms)
    pub avg_response_time_ms: u64,
    /// Highest block height among healthy endpoints
    pub max_height: Option<u64>,
    /// Individual endpoint health
    pub endpoints: Vec<monero_marketplace_wallet::daemon_pool::DaemonHealth>,
}

/// GET /api/v1/daemon/health
///
/// Get health status of all daemon endpoints in the pool.
///
/// Example response:
/// ```json
/// {
///   "total": 2,
///   "healthy": 2,
///   "unhealthy": 0,
///   "avg_response_time_ms": 45,
///   "max_height": 3000000,
///   "endpoints": [
///     { "url": "http://127.0.0.1:18081", "healthy": true, "height": 3000000, ... },
///     { "url": "http://127.0.0.1:28081", "healthy": true, "height": 2999998, ... }
///   ]
/// }
/// ```
#[get("/v1/daemon/health")]
pub async fn get_daemon_health(daemon_pool: web::Data<Arc<DaemonPool>>) -> HttpResponse {
    let health_results = daemon_pool.get_all_health().await;

    let total = health_results.len();
    let healthy_endpoints: Vec<_> = health_results.iter().filter(|r| r.healthy).collect();
    let healthy_count = healthy_endpoints.len();

    let avg_response_time_ms = if healthy_count > 0 {
        healthy_endpoints
            .iter()
            .filter_map(|r| r.last_response_ms)
            .sum::<u64>()
            / healthy_count as u64
    } else {
        0
    };

    let max_height = healthy_endpoints.iter().filter_map(|r| r.height).max();

    let summary = DaemonHealthSummary {
        total,
        healthy: healthy_count,
        unhealthy: total - healthy_count,
        avg_response_time_ms,
        max_height,
        endpoints: health_results,
    };

    HttpResponse::Ok().json(summary)
}

/// Configure fee estimation routes
pub fn configure_fee_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(get_fee_estimate)
        .service(get_all_fee_estimates)
        .service(get_daemon_health);
}
