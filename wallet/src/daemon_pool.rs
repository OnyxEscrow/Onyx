//! Daemon Pool with Health-Based Routing and Automatic Failover
//!
//! Provides high-availability access to Monero daemon RPCs with:
//! - Round-robin load balancing
//! - Health-based routing (unhealthy daemons skipped)
//! - Automatic health recovery when daemons come back online
//! - Configurable health check intervals
//!
//! # Example
//! ```rust,ignore
//! use monero_marketplace_wallet::daemon_pool::{DaemonPool, DaemonConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = DaemonConfig {
//!         urls: vec![
//!             "http://127.0.0.1:18081".to_string(),
//!             "http://127.0.0.1:18082".to_string(),
//!         ],
//!         health_check_interval_secs: 30,
//!         request_timeout_secs: 10,
//!         max_failures: 3,
//!     };
//!
//!     let pool = DaemonPool::new(config).await.unwrap();
//!     let info = pool.get_info().await.unwrap();
//!     println!("Height: {}", info.height);
//! }
//! ```

use crate::fee_estimation::{FeeEstimate, FeeEstimator, FeePriority};
use monero_marketplace_common::error::MoneroError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configuration for daemon pool
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// List of daemon RPC URLs (e.g., ["http://127.0.0.1:18081"])
    pub urls: Vec<String>,
    /// Health check interval in seconds (default: 30)
    pub health_check_interval_secs: u64,
    /// Request timeout in seconds (default: 10)
    pub request_timeout_secs: u64,
    /// Maximum consecutive failures before marking unhealthy
    pub max_failures: u32,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            urls: vec!["http://127.0.0.1:18081".to_string()],
            health_check_interval_secs: 30,
            request_timeout_secs: 10,
            max_failures: 3,
        }
    }
}

impl DaemonConfig {
    /// Create config from environment variables
    ///
    /// Environment variables:
    /// - `DAEMON_URLS`: Comma-separated list of daemon URLs
    /// - `DAEMON_HEALTH_CHECK_INTERVAL`: Health check interval in seconds (default: 30)
    /// - `DAEMON_REQUEST_TIMEOUT`: Request timeout in seconds (default: 10)
    pub fn from_env() -> Self {
        let urls = std::env::var("DAEMON_URLS")
            .map(|s| s.split(',').map(|u| u.trim().to_string()).collect())
            .unwrap_or_else(|_| vec!["http://127.0.0.1:18081".to_string()]);

        let health_check_interval_secs = std::env::var("DAEMON_HEALTH_CHECK_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let request_timeout_secs = std::env::var("DAEMON_REQUEST_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        Self {
            urls,
            health_check_interval_secs,
            request_timeout_secs,
            max_failures: 3,
        }
    }
}

/// Health status of a single daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonHealth {
    /// Daemon URL
    pub url: String,
    /// Whether daemon is currently healthy
    pub healthy: bool,
    /// Last successful response time (milliseconds)
    pub last_response_ms: Option<u64>,
    /// Current block height (if known)
    pub height: Option<u64>,
    /// Network (mainnet, testnet, stagenet)
    pub network: Option<String>,
    /// Consecutive failure count
    pub failure_count: u32,
    /// Last check timestamp (Unix seconds)
    pub last_check: u64,
    /// Error message if unhealthy
    pub error: Option<String>,
}

/// Internal state for a daemon endpoint
struct DaemonEndpoint {
    url: String,
    client: Client,
    fee_estimator: FeeEstimator,
    healthy: RwLock<bool>,
    failure_count: AtomicU64,
    last_response_ms: AtomicU64,
    last_height: AtomicU64,
    last_check: AtomicU64,
    last_error: RwLock<Option<String>>,
    network: RwLock<Option<String>>,
}

impl DaemonEndpoint {
    fn new(url: &str, timeout_secs: u64) -> Result<Self, MoneroError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| MoneroError::NetworkError(format!("Failed to build client: {}", e)))?;

        let fee_estimator = FeeEstimator::new(url)?;

        Ok(Self {
            url: url.to_string(),
            client,
            fee_estimator,
            healthy: RwLock::new(true), // Assume healthy until proven otherwise
            failure_count: AtomicU64::new(0),
            last_response_ms: AtomicU64::new(0),
            last_height: AtomicU64::new(0),
            last_check: AtomicU64::new(0),
            last_error: RwLock::new(None),
            network: RwLock::new(None),
        })
    }

    async fn check_health(&self) -> bool {
        let start = Instant::now();

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_info"
        });

        let result = self
            .client
            .post(format!("{}/json_rpc", self.url))
            .json(&request)
            .send()
            .await;

        let elapsed_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(response) if response.status().is_success() => {
                if let Ok(json) = response.json::<serde_json::Value>().await {
                    if let Some(result) = json.get("result") {
                        // Extract height
                        if let Some(height) = result.get("height").and_then(|h| h.as_u64()) {
                            self.last_height.store(height, Ordering::SeqCst);
                        }

                        // Extract network
                        let network = if result
                            .get("mainnet")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            "mainnet"
                        } else if result
                            .get("stagenet")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            "stagenet"
                        } else if result
                            .get("testnet")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            "testnet"
                        } else {
                            "unknown"
                        };
                        *self.network.write().await = Some(network.to_string());

                        // Mark healthy
                        self.failure_count.store(0, Ordering::SeqCst);
                        self.last_response_ms.store(elapsed_ms, Ordering::SeqCst);
                        self.last_check.store(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            Ordering::SeqCst,
                        );
                        *self.healthy.write().await = true;
                        *self.last_error.write().await = None;

                        return true;
                    }
                }
            }
            Ok(response) => {
                let error = format!("HTTP {}", response.status());
                self.mark_failure(&error).await;
            }
            Err(e) => {
                let error = if e.is_connect() {
                    "Connection refused".to_string()
                } else if e.is_timeout() {
                    "Request timeout".to_string()
                } else {
                    e.to_string()
                };
                self.mark_failure(&error).await;
            }
        }

        false
    }

    async fn mark_failure(&self, error: &str) {
        let failures = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        self.last_check.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::SeqCst,
        );
        *self.last_error.write().await = Some(error.to_string());

        // Mark unhealthy after 3 consecutive failures
        if failures >= 3 {
            *self.healthy.write().await = false;
        }
    }

    async fn get_health(&self) -> DaemonHealth {
        DaemonHealth {
            url: self.url.clone(),
            healthy: *self.healthy.read().await,
            last_response_ms: {
                let ms = self.last_response_ms.load(Ordering::SeqCst);
                if ms > 0 {
                    Some(ms)
                } else {
                    None
                }
            },
            height: {
                let h = self.last_height.load(Ordering::SeqCst);
                if h > 0 {
                    Some(h)
                } else {
                    None
                }
            },
            network: self.network.read().await.clone(),
            failure_count: self.failure_count.load(Ordering::SeqCst) as u32,
            last_check: self.last_check.load(Ordering::SeqCst),
            error: self.last_error.read().await.clone(),
        }
    }

    async fn is_healthy(&self) -> bool {
        *self.healthy.read().await
    }
}

/// Daemon pool response for get_info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonInfo {
    pub height: u64,
    pub target_height: u64,
    pub difficulty: u64,
    pub tx_pool_size: u64,
    pub version: String,
    pub mainnet: bool,
    pub testnet: bool,
    pub stagenet: bool,
    /// Which daemon served this request
    pub served_by: String,
}

/// High-availability daemon pool with automatic failover
pub struct DaemonPool {
    endpoints: Vec<Arc<DaemonEndpoint>>,
    current_index: AtomicUsize,
    config: DaemonConfig,
}

impl DaemonPool {
    /// Create a new daemon pool with the given configuration
    pub async fn new(config: DaemonConfig) -> Result<Self, MoneroError> {
        if config.urls.is_empty() {
            return Err(MoneroError::ValidationError(
                "At least one daemon URL required".to_string(),
            ));
        }

        // Validate all URLs are localhost (security)
        for url in &config.urls {
            if !url.contains("127.0.0.1") && !url.contains("localhost") {
                return Err(MoneroError::ValidationError(format!(
                    "Daemon URL must be localhost for security: {}",
                    url
                )));
            }
        }

        let mut endpoints = Vec::with_capacity(config.urls.len());
        for url in &config.urls {
            endpoints.push(Arc::new(DaemonEndpoint::new(
                url,
                config.request_timeout_secs,
            )?));
        }

        let pool = Self {
            endpoints,
            current_index: AtomicUsize::new(0),
            config,
        };

        // Initial health check
        pool.check_all_health().await;

        Ok(pool)
    }

    /// Create pool from environment variables
    pub async fn from_env() -> Result<Self, MoneroError> {
        Self::new(DaemonConfig::from_env()).await
    }

    /// Get the next healthy daemon (round-robin with health filtering)
    fn get_next_healthy(&self) -> Option<Arc<DaemonEndpoint>> {
        let len = self.endpoints.len();
        let start = self.current_index.fetch_add(1, Ordering::SeqCst) % len;

        // Try each endpoint starting from current index
        for i in 0..len {
            let idx = (start + i) % len;
            let endpoint = &self.endpoints[idx];

            // Use try_read to avoid blocking - if locked, skip to next
            if let Ok(guard) = endpoint.healthy.try_read() {
                if *guard {
                    return Some(Arc::clone(endpoint));
                }
            }
        }

        // No healthy endpoints found, return first one anyway (let it fail with proper error)
        Some(Arc::clone(&self.endpoints[0]))
    }

    /// Check health of all daemons
    pub async fn check_all_health(&self) {
        for endpoint in &self.endpoints {
            endpoint.check_health().await;
        }
    }

    /// Start background health check loop
    ///
    /// This spawns a tokio task that periodically checks daemon health.
    /// Call this once after creating the pool.
    pub fn start_health_checks(self: &Arc<Self>) {
        let pool = Arc::clone(self);
        let interval = Duration::from_secs(pool.config.health_check_interval_secs);

        tokio::spawn(async move {
            let mut check_interval = tokio::time::interval(interval);
            loop {
                check_interval.tick().await;
                pool.check_all_health().await;
                tracing::debug!("Daemon health check completed");
            }
        });
    }

    /// Get health status of all daemons
    pub async fn get_all_health(&self) -> Vec<DaemonHealth> {
        let mut health = Vec::with_capacity(self.endpoints.len());
        for endpoint in &self.endpoints {
            health.push(endpoint.get_health().await);
        }
        health
    }

    /// Get daemon info from a healthy daemon
    pub async fn get_info(&self) -> Result<DaemonInfo, MoneroError> {
        let endpoint = self
            .get_next_healthy()
            .ok_or_else(|| MoneroError::RpcUnreachable)?;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_info"
        });

        let response = endpoint
            .client
            .post(format!("{}/json_rpc", endpoint.url))
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

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse error: {}", e)))?;

        let result = json
            .get("result")
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result".to_string()))?;

        Ok(DaemonInfo {
            height: result.get("height").and_then(|v| v.as_u64()).unwrap_or(0),
            target_height: result
                .get("target_height")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            difficulty: result
                .get("difficulty")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            tx_pool_size: result
                .get("tx_pool_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            version: result
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            mainnet: result
                .get("mainnet")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            testnet: result
                .get("testnet")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            stagenet: result
                .get("stagenet")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            served_by: endpoint.url.clone(),
        })
    }

    /// Get fee estimate from a healthy daemon
    pub async fn get_fee_estimate(
        &self,
        priority: FeePriority,
    ) -> Result<FeeEstimate, MoneroError> {
        let endpoint = self
            .get_next_healthy()
            .ok_or_else(|| MoneroError::RpcUnreachable)?;

        endpoint.fee_estimator.get_fee_estimate(priority).await
    }

    /// Get all fee estimates (all priority levels)
    pub async fn get_all_fee_estimates(&self) -> Result<Vec<FeeEstimate>, MoneroError> {
        let endpoint = self
            .get_next_healthy()
            .ok_or_else(|| MoneroError::RpcUnreachable)?;

        endpoint.fee_estimator.get_all_fee_estimates().await
    }

    /// Broadcast a raw transaction
    pub async fn submit_transaction(&self, tx_hex: &str) -> Result<String, MoneroError> {
        let endpoint = self
            .get_next_healthy()
            .ok_or_else(|| MoneroError::RpcUnreachable)?;

        let request = serde_json::json!({
            "tx_as_hex": tx_hex,
            "do_not_relay": false
        });

        let response = endpoint
            .client
            .post(format!("{}/sendrawtransaction", endpoint.url))
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

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse error: {}", e)))?;

        let status = json
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("UNKNOWN");

        if status != "OK" {
            let reason = json
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("Unknown error");
            return Err(MoneroError::RpcError(format!(
                "Transaction rejected: {}",
                reason
            )));
        }

        // Return status or transaction hash if available
        Ok(status.to_string())
    }

    /// Get current block height
    pub async fn get_height(&self) -> Result<u64, MoneroError> {
        let info = self.get_info().await?;
        Ok(info.height)
    }

    /// Get transaction pool information
    pub async fn get_transaction_pool(&self) -> Result<serde_json::Value, MoneroError> {
        let endpoint = self
            .get_next_healthy()
            .ok_or_else(|| MoneroError::RpcUnreachable)?;

        let response = endpoint
            .client
            .post(format!("{}/get_transaction_pool", endpoint.url))
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    MoneroError::RpcUnreachable
                } else {
                    MoneroError::NetworkError(e.to_string())
                }
            })?;

        response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_config_default() {
        let config = DaemonConfig::default();
        assert_eq!(config.urls.len(), 1);
        assert_eq!(config.health_check_interval_secs, 30);
        assert_eq!(config.request_timeout_secs, 10);
    }

    #[tokio::test]
    async fn test_daemon_pool_validation() {
        // Empty URLs should fail
        let config = DaemonConfig {
            urls: vec![],
            ..Default::default()
        };
        assert!(DaemonPool::new(config).await.is_err());

        // Non-localhost URL should fail
        let config = DaemonConfig {
            urls: vec!["http://192.168.1.1:18081".to_string()],
            ..Default::default()
        };
        assert!(DaemonPool::new(config).await.is_err());

        // Localhost should succeed (even if daemon not running)
        let config = DaemonConfig {
            urls: vec!["http://127.0.0.1:18081".to_string()],
            ..Default::default()
        };
        // This will succeed creating the pool, even if daemon is down
        let result = DaemonPool::new(config).await;
        assert!(result.is_ok());
    }
}
