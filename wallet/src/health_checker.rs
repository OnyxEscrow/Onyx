//! Health checker for Monero RPC endpoints
//!
//! Provides health monitoring for both daemon and wallet RPC instances.
//! Used by DaemonPool for automatic failover decisions.

use monero_marketplace_common::error::MoneroError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Health check result for an RPC endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// URL that was checked
    pub url: String,
    /// Whether the endpoint is healthy
    pub healthy: bool,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Block height (for daemon/wallet RPC)
    pub height: Option<u64>,
    /// Network type (mainnet, testnet, stagenet)
    pub network: Option<String>,
    /// Version string
    pub version: Option<String>,
    /// Error message if unhealthy
    pub error: Option<String>,
    /// Timestamp of check (Unix seconds)
    pub checked_at: u64,
}

/// Health checker for Monero RPC endpoints
#[derive(Clone)]
pub struct HealthChecker {
    client: Client,
    timeout: Duration,
}

impl HealthChecker {
    /// Create a new health checker with default timeout (5 seconds)
    pub fn new() -> Result<Self, MoneroError> {
        Self::with_timeout(Duration::from_secs(5))
    }

    /// Create a new health checker with custom timeout
    pub fn with_timeout(timeout: Duration) -> Result<Self, MoneroError> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| MoneroError::NetworkError(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Self { client, timeout })
    }

    /// Check health of a daemon RPC endpoint
    ///
    /// Uses `get_info` RPC method to verify daemon is responding.
    pub async fn check_daemon(&self, url: &str) -> HealthCheckResult {
        let start = Instant::now();
        let checked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_info"
        });

        let result = self
            .client
            .post(format!("{}/json_rpc", url.trim_end_matches('/')))
            .json(&request)
            .send()
            .await;

        let response_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(response) if response.status().is_success() => {
                match response.json::<serde_json::Value>().await {
                    Ok(json) => {
                        if let Some(result) = json.get("result") {
                            let height = result.get("height").and_then(|h| h.as_u64());
                            let version = result
                                .get("version")
                                .and_then(|v| v.as_str())
                                .map(String::from);

                            let network = if result.get("mainnet").and_then(|v| v.as_bool()).unwrap_or(false) {
                                Some("mainnet".to_string())
                            } else if result.get("stagenet").and_then(|v| v.as_bool()).unwrap_or(false) {
                                Some("stagenet".to_string())
                            } else if result.get("testnet").and_then(|v| v.as_bool()).unwrap_or(false) {
                                Some("testnet".to_string())
                            } else {
                                None
                            };

                            HealthCheckResult {
                                url: url.to_string(),
                                healthy: true,
                                response_time_ms,
                                height,
                                network,
                                version,
                                error: None,
                                checked_at,
                            }
                        } else {
                            HealthCheckResult {
                                url: url.to_string(),
                                healthy: false,
                                response_time_ms,
                                height: None,
                                network: None,
                                version: None,
                                error: Some("Invalid RPC response: missing result".to_string()),
                                checked_at,
                            }
                        }
                    }
                    Err(e) => HealthCheckResult {
                        url: url.to_string(),
                        healthy: false,
                        response_time_ms,
                        height: None,
                        network: None,
                        version: None,
                        error: Some(format!("JSON parse error: {}", e)),
                        checked_at,
                    },
                }
            }
            Ok(response) => HealthCheckResult {
                url: url.to_string(),
                healthy: false,
                response_time_ms,
                height: None,
                network: None,
                version: None,
                error: Some(format!("HTTP error: {}", response.status())),
                checked_at,
            },
            Err(e) => {
                let error = if e.is_connect() {
                    "Connection refused".to_string()
                } else if e.is_timeout() {
                    "Request timeout".to_string()
                } else {
                    e.to_string()
                };

                HealthCheckResult {
                    url: url.to_string(),
                    healthy: false,
                    response_time_ms,
                    height: None,
                    network: None,
                    version: None,
                    error: Some(error),
                    checked_at,
                }
            }
        }
    }

    /// Check health of a wallet RPC endpoint
    ///
    /// Uses `get_version` RPC method to verify wallet RPC is responding.
    pub async fn check_wallet_rpc(&self, url: &str) -> HealthCheckResult {
        let start = Instant::now();
        let checked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_version"
        });

        let result = self
            .client
            .post(format!("{}/json_rpc", url.trim_end_matches('/')))
            .json(&request)
            .send()
            .await;

        let response_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(response) if response.status().is_success() => {
                match response.json::<serde_json::Value>().await {
                    Ok(json) => {
                        if let Some(result) = json.get("result") {
                            let version = result
                                .get("version")
                                .and_then(|v| v.as_u64())
                                .map(|v| format!("0x{:x}", v));

                            HealthCheckResult {
                                url: url.to_string(),
                                healthy: true,
                                response_time_ms,
                                height: None, // Wallet RPC doesn't return height in get_version
                                network: None,
                                version,
                                error: None,
                                checked_at,
                            }
                        } else if let Some(error) = json.get("error") {
                            let message = error
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("Unknown error");
                            HealthCheckResult {
                                url: url.to_string(),
                                healthy: false,
                                response_time_ms,
                                height: None,
                                network: None,
                                version: None,
                                error: Some(format!("RPC error: {}", message)),
                                checked_at,
                            }
                        } else {
                            HealthCheckResult {
                                url: url.to_string(),
                                healthy: false,
                                response_time_ms,
                                height: None,
                                network: None,
                                version: None,
                                error: Some("Invalid RPC response".to_string()),
                                checked_at,
                            }
                        }
                    }
                    Err(e) => HealthCheckResult {
                        url: url.to_string(),
                        healthy: false,
                        response_time_ms,
                        height: None,
                        network: None,
                        version: None,
                        error: Some(format!("JSON parse error: {}", e)),
                        checked_at,
                    },
                }
            }
            Ok(response) => HealthCheckResult {
                url: url.to_string(),
                healthy: false,
                response_time_ms,
                height: None,
                network: None,
                version: None,
                error: Some(format!("HTTP error: {}", response.status())),
                checked_at,
            },
            Err(e) => {
                let error = if e.is_connect() {
                    "Connection refused".to_string()
                } else if e.is_timeout() {
                    "Request timeout".to_string()
                } else {
                    e.to_string()
                };

                HealthCheckResult {
                    url: url.to_string(),
                    healthy: false,
                    response_time_ms,
                    height: None,
                    network: None,
                    version: None,
                    error: Some(error),
                    checked_at,
                }
            }
        }
    }

    /// Check multiple daemon endpoints in parallel
    pub async fn check_daemons(&self, urls: &[String]) -> Vec<HealthCheckResult> {
        let futures: Vec<_> = urls.iter().map(|url| self.check_daemon(url)).collect();
        futures::future::join_all(futures).await
    }

    /// Check multiple wallet RPC endpoints in parallel
    pub async fn check_wallet_rpcs(&self, urls: &[String]) -> Vec<HealthCheckResult> {
        let futures: Vec<_> = urls.iter().map(|url| self.check_wallet_rpc(url)).collect();
        futures::future::join_all(futures).await
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new().expect("Failed to create default HealthChecker")
    }
}

/// Aggregate health status for a pool of endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolHealthSummary {
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
    /// Individual health results
    pub endpoints: Vec<HealthCheckResult>,
}

impl PoolHealthSummary {
    /// Create a summary from individual health check results
    pub fn from_results(results: Vec<HealthCheckResult>) -> Self {
        let total = results.len();
        let healthy: Vec<_> = results.iter().filter(|r| r.healthy).collect();
        let healthy_count = healthy.len();
        let unhealthy_count = total - healthy_count;

        let avg_response_time_ms = if healthy_count > 0 {
            healthy.iter().map(|r| r.response_time_ms).sum::<u64>() / healthy_count as u64
        } else {
            0
        };

        let max_height = healthy
            .iter()
            .filter_map(|r| r.height)
            .max();

        Self {
            total,
            healthy: healthy_count,
            unhealthy: unhealthy_count,
            avg_response_time_ms,
            max_height,
            endpoints: results,
        }
    }

    /// Check if pool is in a healthy state (at least one healthy endpoint)
    pub fn is_healthy(&self) -> bool {
        self.healthy > 0
    }

    /// Check if pool is degraded (some but not all endpoints unhealthy)
    pub fn is_degraded(&self) -> bool {
        self.healthy > 0 && self.unhealthy > 0
    }

    /// Check if pool is completely down (no healthy endpoints)
    pub fn is_down(&self) -> bool {
        self.healthy == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_health_summary() {
        let results = vec![
            HealthCheckResult {
                url: "http://127.0.0.1:18081".to_string(),
                healthy: true,
                response_time_ms: 50,
                height: Some(1000),
                network: Some("mainnet".to_string()),
                version: Some("0.18.0".to_string()),
                error: None,
                checked_at: 0,
            },
            HealthCheckResult {
                url: "http://127.0.0.1:18082".to_string(),
                healthy: true,
                response_time_ms: 100,
                height: Some(1001),
                network: Some("mainnet".to_string()),
                version: Some("0.18.0".to_string()),
                error: None,
                checked_at: 0,
            },
            HealthCheckResult {
                url: "http://127.0.0.1:18083".to_string(),
                healthy: false,
                response_time_ms: 5000,
                height: None,
                network: None,
                version: None,
                error: Some("Connection refused".to_string()),
                checked_at: 0,
            },
        ];

        let summary = PoolHealthSummary::from_results(results);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.healthy, 2);
        assert_eq!(summary.unhealthy, 1);
        assert_eq!(summary.avg_response_time_ms, 75); // (50 + 100) / 2
        assert_eq!(summary.max_height, Some(1001));
        assert!(summary.is_healthy());
        assert!(summary.is_degraded());
        assert!(!summary.is_down());
    }

    #[test]
    fn test_pool_health_all_down() {
        let results = vec![
            HealthCheckResult {
                url: "http://127.0.0.1:18081".to_string(),
                healthy: false,
                response_time_ms: 5000,
                height: None,
                network: None,
                version: None,
                error: Some("Timeout".to_string()),
                checked_at: 0,
            },
        ];

        let summary = PoolHealthSummary::from_results(results);

        assert!(!summary.is_healthy());
        assert!(!summary.is_degraded());
        assert!(summary.is_down());
    }
}
