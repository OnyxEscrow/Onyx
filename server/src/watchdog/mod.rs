//! Minimal WalletRpcWatchdog - Health check + auto-restart
//!
//! Simple supervision for wallet-rpc processes. No circuit breaker (unnecessary
//! for non-custodial read-only operations).

mod error;

pub use error::{WatchdogError, WatchdogResult};

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

/// Wallet role for logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletRole {
    Buyer,
    Vendor,
    Arbiter,
    Monitor,
}

impl WalletRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            WalletRole::Buyer => "buyer",
            WalletRole::Vendor => "vendor",
            WalletRole::Arbiter => "arbiter",
            WalletRole::Monitor => "monitor",
        }
    }
}

/// Process info for a managed wallet-rpc
struct ProcessInfo {
    child: Option<Child>,
    role: WalletRole,
    restart_count: u32,
    last_healthy: std::time::Instant,
}

/// Watchdog configuration
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// Health check interval (default: 15s)
    pub health_check_interval: Duration,
    /// Health check timeout (default: 5s)
    pub health_check_timeout: Duration,
    /// Max restart attempts before giving up (default: 5)
    pub max_restart_attempts: u32,
    /// Cooldown between restarts (default: 10s)
    pub restart_cooldown: Duration,
    /// Network: "stagenet", "testnet", or "mainnet"
    pub network: String,
    /// Base port (e.g., 38083 for stagenet)
    pub base_port: u16,
    /// Daemon address
    pub daemon_address: String,
    /// Wallet directory
    pub wallet_dir: String,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            health_check_interval: Duration::from_secs(15),
            health_check_timeout: Duration::from_secs(5),
            max_restart_attempts: 5,
            restart_cooldown: Duration::from_secs(10),
            network: "stagenet".to_string(),
            base_port: 38083,
            daemon_address: "127.0.0.1:38081".to_string(),
            wallet_dir: "./stagenet-wallets".to_string(),
        }
    }
}

impl WatchdogConfig {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        let base_port = match network.as_str() {
            "mainnet" => 18083,
            "testnet" => 28083,
            _ => 38083, // stagenet
        };
        let daemon_port = match network.as_str() {
            "mainnet" => 18081,
            "testnet" => 28081,
            _ => 38081,
        };

        Self {
            network: network.clone(),
            base_port,
            daemon_address: format!("127.0.0.1:{}", daemon_port),
            wallet_dir: std::env::var("WALLET_DIR").unwrap_or_else(|_| {
                format!("./{}-wallets", network)
            }),
            ..Default::default()
        }
    }
}

/// Minimal watchdog service
pub struct WalletRpcWatchdog {
    processes: RwLock<HashMap<u16, ProcessInfo>>,
    config: WatchdogConfig,
    shutdown: std::sync::atomic::AtomicBool,
}

impl WalletRpcWatchdog {
    /// Create new watchdog
    pub fn new(config: WatchdogConfig) -> Self {
        Self {
            processes: RwLock::new(HashMap::new()),
            config,
            shutdown: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Start all wallet-rpc processes
    pub async fn start_all_processes(&self) -> WatchdogResult<()> {
        let roles = [
            (self.config.base_port, WalletRole::Buyer),
            (self.config.base_port + 1, WalletRole::Vendor),
            (self.config.base_port + 2, WalletRole::Arbiter),
            (self.config.base_port + 3, WalletRole::Monitor),
        ];

        for (port, role) in roles {
            // Check if already running
            if self.is_healthy(port).await {
                info!("wallet-rpc {} already running on port {}", role.as_str(), port);
                let mut procs = self.processes.write().await;
                procs.insert(port, ProcessInfo {
                    child: None, // External process
                    role,
                    restart_count: 0,
                    last_healthy: std::time::Instant::now(),
                });
                continue;
            }

            self.spawn_process(port, role).await?;
        }

        info!("All wallet-rpc processes started");
        Ok(())
    }

    /// Spawn a single wallet-rpc process
    async fn spawn_process(&self, port: u16, role: WalletRole) -> WatchdogResult<()> {
        info!("Spawning wallet-rpc {} on port {}", role.as_str(), port);

        let network_flag = match self.config.network.as_str() {
            "mainnet" => "",
            "testnet" => "--testnet",
            _ => "--stagenet",
        };

        let mut cmd = Command::new("monero-wallet-rpc");

        if !network_flag.is_empty() {
            cmd.arg(network_flag);
        }

        cmd.args([
            "--rpc-bind-port", &port.to_string(),
            "--rpc-bind-ip", "127.0.0.1",
            "--disable-rpc-login",
            "--wallet-dir", &self.config.wallet_dir,
            "--daemon-address", &self.config.daemon_address,
            "--trusted-daemon",
            "--log-level", "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());

        let child = cmd.spawn().map_err(|e| WatchdogError::SpawnFailed {
            port,
            reason: e.to_string(),
        })?;

        let pid = child.id();
        info!("wallet-rpc {} spawned with PID {} on port {}", role.as_str(), pid, port);

        // Wait for process to become healthy
        let mut attempts = 0;
        let max_wait_attempts = 30; // 30 * 1s = 30s max wait

        while attempts < max_wait_attempts {
            sleep(Duration::from_secs(1)).await;
            if self.is_healthy(port).await {
                info!("wallet-rpc {} healthy on port {}", role.as_str(), port);
                break;
            }
            attempts += 1;
        }

        if attempts >= max_wait_attempts {
            error!("wallet-rpc {} failed to become healthy on port {}", role.as_str(), port);
            return Err(WatchdogError::HealthCheckFailed {
                port,
                reason: "Timeout waiting for process to become healthy".to_string(),
            });
        }

        let mut procs = self.processes.write().await;
        procs.insert(port, ProcessInfo {
            child: Some(child),
            role,
            restart_count: 0,
            last_healthy: std::time::Instant::now(),
        });

        Ok(())
    }

    /// Check if a wallet-rpc is healthy via JSON-RPC
    pub async fn is_healthy(&self, port: u16) -> bool {
        let url = format!("http://127.0.0.1:{}/json_rpc", port);
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "health",
            "method": "get_version"
        });

        let result = timeout(self.config.health_check_timeout, async {
            reqwest::Client::new()
                .post(&url)
                .json(&payload)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false)
        })
        .await;

        result.unwrap_or(false)
    }

    /// Start the monitoring loop (call via tokio::spawn)
    pub async fn start_monitoring(self: Arc<Self>) {
        info!(
            "Starting watchdog monitoring loop (interval: {:?})",
            self.config.health_check_interval
        );

        while !self.shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            sleep(self.config.health_check_interval).await;

            if let Err(e) = self.health_check_cycle().await {
                error!("Health check cycle error: {}", e);
            }
        }

        info!("Watchdog monitoring loop stopped");
    }

    /// Single health check cycle
    async fn health_check_cycle(&self) -> WatchdogResult<()> {
        let ports: Vec<u16> = self.processes.read().await.keys().copied().collect();

        for port in ports {
            let healthy = self.is_healthy(port).await;

            let mut procs = self.processes.write().await;
            if let Some(info) = procs.get_mut(&port) {
                if healthy {
                    debug!("Port {} ({}) healthy", port, info.role.as_str());
                    info.last_healthy = std::time::Instant::now();
                } else {
                    warn!(
                        "Port {} ({}) UNHEALTHY - triggering restart",
                        port,
                        info.role.as_str()
                    );

                    let role = info.role;
                    let restart_count = info.restart_count;
                    drop(procs);

                    if restart_count < self.config.max_restart_attempts {
                        if let Err(e) = self.restart_process(port, role).await {
                            error!("Failed to restart port {}: {}", port, e);
                        }
                    } else {
                        error!(
                            "CRITICAL: Max restarts ({}) exceeded for port {} ({})",
                            self.config.max_restart_attempts,
                            port,
                            role.as_str()
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Restart a process
    async fn restart_process(&self, port: u16, role: WalletRole) -> WatchdogResult<()> {
        info!("Restarting wallet-rpc {} on port {}", role.as_str(), port);

        // Kill existing process
        {
            let mut procs = self.processes.write().await;
            if let Some(info) = procs.get_mut(&port) {
                if let Some(ref mut child) = info.child {
                    // Try graceful shutdown first
                    let _ = child.kill();
                }
                info.restart_count += 1;
            }
        }

        // Wait for port to be free
        sleep(self.config.restart_cooldown).await;

        // Respawn
        self.spawn_process(port, role).await?;

        info!("wallet-rpc {} restarted successfully on port {}", role.as_str(), port);
        Ok(())
    }

    /// Get health status for all processes
    pub async fn get_health_status(&self) -> HashMap<u16, bool> {
        let ports: Vec<u16> = self.processes.read().await.keys().copied().collect();
        let mut status = HashMap::new();

        for port in ports {
            status.insert(port, self.is_healthy(port).await);
        }

        status
    }

    /// Trigger graceful shutdown
    pub fn shutdown(&self) {
        info!("Watchdog shutdown requested");
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        std::env::set_var("MONERO_NETWORK", "stagenet");
        let config = WatchdogConfig::from_env();
        assert_eq!(config.network, "stagenet");
        assert_eq!(config.base_port, 38083);
    }

    #[test]
    fn test_wallet_role_str() {
        assert_eq!(WalletRole::Buyer.as_str(), "buyer");
        assert_eq!(WalletRole::Monitor.as_str(), "monitor");
    }
}
