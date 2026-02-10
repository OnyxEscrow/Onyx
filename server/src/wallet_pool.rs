//! Wallet Pool - Production-grade wallet rotation system
//!
//! This module provides intelligent rotation of Monero wallet-rpc instances
//! to support unlimited concurrent escrows with limited RPC resources.
//!
//! # Architecture
//!
//! - **Pool of RPC instances**: 3-6 monero-wallet-rpc processes (configurable)
//! - **Wallets on disk**: All multisig wallets persisted to filesystem
//! - **Load-on-demand**: Wallets opened only when needed for signing
//! - **Auto-close**: Wallets closed after operation to free RPC slots
//!
//! # Workflow
//!
//! 1. **Escrow creation**:
//!    - Acquire 3 free RPC slots
//!    - Create 3 multisig wallets (buyer, vendor, arbiter)
//!    - Perform multisig setup (prepare → make → finalize)
//!    - Close all 3 wallets → Wallets saved to disk
//!    - Release RPC slots
//!
//! 2. **Transaction signing** (days/weeks later):
//!    - Acquire 1 free RPC slot
//!    - Load specific wallet (e.g., buyer_temp_escrow_xxx)
//!    - Sign transaction
//!    - Close wallet
//!    - Release RPC slot
//!
//! # Security
//!
//! - Wallet files encrypted with password from WALLET_ENCRYPTION_PASSWORD env var
//! - RPC instances bound to localhost only (127.0.0.1)
//! - Timeout-based locking to prevent resource exhaustion
//! - Atomic operations with proper error recovery

use crate::config::get_wallet_password;
use anyhow::{Context, Result};
use monero_marketplace_common::types::MoneroConfig;
use monero_marketplace_wallet::client::MoneroClient;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Role of a wallet in the multisig escrow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletRole {
    Buyer,
    Vendor,
    Arbiter,
}

impl WalletRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Buyer => "buyer",
            Self::Vendor => "vendor",
            Self::Arbiter => "arbiter",
        }
    }
}

/// Represents a single RPC instance in the pool
#[derive(Debug, Clone)]
pub struct RpcInstance {
    /// RPC port (e.g., 18082)
    pub port: u16,

    /// RPC URL (e.g., http://127.0.0.1:18082/json_rpc)
    pub url: String,

    /// Currently loaded wallet (if any)
    pub loaded_wallet: Option<WalletSlot>,

    /// Lock expiration time
    pub locked_until: Option<Instant>,
}

impl RpcInstance {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            url: format!("http://127.0.0.1:{}/json_rpc", port),
            loaded_wallet: None,
            locked_until: None,
        }
    }

    /// Check if this RPC instance is free (not locked and no wallet loaded)
    pub fn is_free(&self) -> bool {
        // Check if lock expired
        if let Some(until) = self.locked_until {
            if Instant::now() < until {
                return false; // Still locked
            }
        }

        // Free if no wallet loaded or lock expired
        self.loaded_wallet.is_none() || self.locked_until.map_or(true, |u| Instant::now() >= u)
    }

    /// Acquire lock on this RPC instance for specified duration
    pub fn acquire(&mut self, duration: Duration) {
        self.locked_until = Some(Instant::now() + duration);
    }

    /// Release lock on this RPC instance
    pub fn release(&mut self) {
        self.locked_until = None;
        self.loaded_wallet = None;
    }
}

/// Information about a wallet currently loaded in an RPC instance
#[derive(Debug, Clone)]
pub struct WalletSlot {
    /// Wallet filename (e.g., "buyer_temp_escrow_ac506a15")
    pub wallet_name: String,

    /// Escrow ID this wallet belongs to
    pub escrow_id: Uuid,

    /// Role of this wallet
    pub role: WalletRole,

    /// When this slot was created
    pub loaded_at: Instant,
}

/// Pool of wallet-rpc instances with intelligent rotation
pub struct WalletPool {
    /// All available RPC instances
    rpc_instances: Arc<RwLock<Vec<RpcInstance>>>,

    /// Directory where wallet files are stored
    wallet_dir: PathBuf,

    /// Default lock duration for operations (30 seconds)
    default_lock_duration: Duration,

    /// Mapping of escrow_id -> wallet filenames for quick lookup
    escrow_wallets: Arc<RwLock<HashMap<Uuid, EscrowWallets>>>,
}

/// Wallet filenames for a specific escrow
#[derive(Debug, Clone)]
pub struct EscrowWallets {
    pub buyer: String,
    pub vendor: String,
    pub arbiter: String,
}

impl WalletPool {
    /// Create a new WalletPool
    ///
    /// # Arguments
    /// * `rpc_ports` - List of monero-wallet-rpc ports (e.g., vec![18082, 18083, 18084])
    /// * `wallet_dir` - Directory where wallet files are stored
    pub fn new(rpc_ports: Vec<u16>, wallet_dir: PathBuf) -> Self {
        let instances = rpc_ports.into_iter().map(RpcInstance::new).collect();

        Self {
            rpc_instances: Arc::new(RwLock::new(instances)),
            wallet_dir,
            default_lock_duration: Duration::from_secs(30),
            escrow_wallets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a free RPC instance, waiting if necessary
    ///
    /// Returns the port number of the acquired RPC instance.
    /// The instance is locked for `default_lock_duration`.
    pub async fn acquire_rpc(&self) -> Result<u16> {
        // Try to acquire immediately
        {
            let mut instances = self.rpc_instances.write().await;
            if let Some(instance) = instances.iter_mut().find(|i| i.is_free()) {
                instance.acquire(self.default_lock_duration);
                info!(port = instance.port, "Acquired RPC instance");
                return Ok(instance.port);
            }
        }

        // If no free instance, wait and retry
        warn!("No free RPC instances, waiting...");

        for attempt in 1..=10 {
            tokio::time::sleep(Duration::from_secs(2)).await;

            let mut instances = self.rpc_instances.write().await;
            if let Some(instance) = instances.iter_mut().find(|i| i.is_free()) {
                instance.acquire(self.default_lock_duration);
                info!(
                    port = instance.port,
                    attempt, "Acquired RPC instance after waiting"
                );
                return Ok(instance.port);
            }
        }

        Err(anyhow::anyhow!(
            "No RPC instances available after 20 seconds. All slots occupied."
        ))
    }

    /// Release an RPC instance by port
    pub async fn release_rpc(&self, port: u16) -> Result<()> {
        let mut instances = self.rpc_instances.write().await;

        if let Some(instance) = instances.iter_mut().find(|i| i.port == port) {
            instance.release();
            info!(port, "Released RPC instance");
            Ok(())
        } else {
            Err(anyhow::anyhow!("RPC instance with port {} not found", port))
        }
    }

    /// Generate wallet filename for a specific escrow and role
    pub fn wallet_filename(&self, escrow_id: Uuid, role: WalletRole) -> String {
        format!("{}_temp_escrow_{}", role.as_str(), escrow_id)
    }

    /// Register wallet filenames for an escrow
    pub async fn register_escrow_wallets(&self, escrow_id: Uuid) {
        let wallets = EscrowWallets {
            buyer: self.wallet_filename(escrow_id, WalletRole::Buyer),
            vendor: self.wallet_filename(escrow_id, WalletRole::Vendor),
            arbiter: self.wallet_filename(escrow_id, WalletRole::Arbiter),
        };

        self.escrow_wallets.write().await.insert(escrow_id, wallets);
        info!(escrow_id = %escrow_id, "Registered escrow wallet filenames");
    }

    /// Load a wallet for signing operations
    ///
    /// This will:
    /// 1. Acquire a free RPC instance
    /// 2. Close any currently open wallet on that instance
    /// 3. Open the requested wallet from disk
    /// 4. Return a MoneroClient connected to that wallet
    pub async fn load_wallet_for_signing(
        &self,
        escrow_id: Uuid,
        role: WalletRole,
    ) -> Result<(MoneroClient, u16)> {
        let port = self.acquire_rpc().await?;

        // Create MoneroClient for this RPC instance
        let config = MoneroConfig {
            rpc_url: format!("http://127.0.0.1:{}", port),
            ..Default::default()
        };

        let client = MoneroClient::new(config)
            .context("Failed to create MoneroClient for wallet loading")?;

        // Close any currently open wallet (ignore errors)
        let _ = client.close_wallet().await;

        // Get wallet filename
        let wallet_name = self.wallet_filename(escrow_id, role);

        // Open the wallet from disk
        match client
            .open_wallet(&wallet_name, &get_wallet_password())
            .await
        {
            Ok(_) => {
                info!(
                    escrow_id = %escrow_id,
                    role = role.as_str(),
                    port,
                    "Loaded wallet for signing"
                );

                // Update RPC instance state
                {
                    let mut instances = self.rpc_instances.write().await;
                    if let Some(instance) = instances.iter_mut().find(|i| i.port == port) {
                        instance.loaded_wallet = Some(WalletSlot {
                            wallet_name,
                            escrow_id,
                            role,
                            loaded_at: Instant::now(),
                        });
                    }
                }

                Ok((client, port))
            }
            Err(e) => {
                error!(
                    escrow_id = %escrow_id,
                    role = role.as_str(),
                    error = %e,
                    "Failed to open wallet for signing"
                );

                // Release RPC on failure
                self.release_rpc(port).await?;

                Err(anyhow::anyhow!("Failed to open wallet: {}", e))
            }
        }
    }

    /// Close wallet and release RPC instance
    pub async fn close_wallet(&self, port: u16) -> Result<()> {
        // Create temporary client to close wallet
        let config = MoneroConfig {
            rpc_url: format!("http://127.0.0.1:{}", port),
            ..Default::default()
        };

        let client = MoneroClient::new(config)?;

        // Close wallet (ignore errors if already closed)
        let _ = client.close_wallet().await;

        // Release RPC instance
        self.release_rpc(port).await?;

        info!(port, "Closed wallet and released RPC instance");
        Ok(())
    }

    /// Get statistics about the pool
    pub async fn stats(&self) -> PoolStats {
        let instances = self.rpc_instances.read().await;

        let total = instances.len();
        let free = instances.iter().filter(|i| i.is_free()).count();
        let busy = total - free;

        PoolStats { total, free, busy }
    }
}

/// Statistics about the wallet pool
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total: usize,
    pub free: usize,
    pub busy: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_instance_lifecycle() {
        let mut instance = RpcInstance::new(18082);

        assert!(instance.is_free());

        instance.acquire(Duration::from_secs(1));
        assert!(!instance.is_free());

        std::thread::sleep(Duration::from_millis(1100));
        assert!(instance.is_free()); // Lock expired

        instance.release();
        assert!(instance.is_free());
    }

    #[test]
    fn test_wallet_filename_generation() {
        let pool = WalletPool::new(vec![18082], PathBuf::from("/tmp/wallets"));

        let escrow_id = Uuid::parse_str("ac506a15-9ab8-4819-bab7-20787705dd15").unwrap();

        let buyer_name = pool.wallet_filename(escrow_id, WalletRole::Buyer);
        assert_eq!(
            buyer_name,
            "buyer_temp_escrow_ac506a15-9ab8-4819-bab7-20787705dd15"
        );

        let vendor_name = pool.wallet_filename(escrow_id, WalletRole::Vendor);
        assert_eq!(
            vendor_name,
            "vendor_temp_escrow_ac506a15-9ab8-4819-bab7-20787705dd15"
        );
    }
}
