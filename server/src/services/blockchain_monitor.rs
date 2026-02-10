//! Blockchain monitoring service for tracking Monero transactions
//!
//! This service monitors the Monero blockchain for:
//! - Transaction confirmations
//! - Escrow funding status
//! - Transaction completion

use actix::Addr;
use anyhow::{Context, Result};
use futures_util::future::join_all;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Batch size for parallel escrow checks
/// Limits concurrent RPC calls to avoid overwhelming wallet-rpc
/// IMPORTANT: Must not exceed the number of available RPC ports!
const PARALLEL_BATCH_SIZE: usize = 4;

/// Get network-aware monitoring RPC ports
/// Each parallel escrow check uses a different port to avoid wallet collisions
/// NOTE: Only one wallet can be open per wallet-rpc at a time, so parallel checks
/// MUST use different ports or they will interfere with each other.
fn get_monitoring_rpc_ports() -> Vec<u16> {
    let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
    match network.to_lowercase().as_str() {
        "mainnet" => vec![18083, 18084, 18085, 18086], // NOT 18082 (that's monerod restricted RPC!)
        "testnet" => vec![28082, 28083, 28084, 28086],
        _ => vec![38083, 38084, 38085, 38086], // stagenet default
    }
}

use crate::crypto::encryption::decrypt_field;
use crate::crypto::mask_derivation::{derive_commitment_mask, find_our_output_and_derive_mask};
use crate::crypto::view_key::validate_view_key_matches_address;
use crate::db::{
    db_load_escrow, db_load_escrow_by_str, db_update_escrow_status, db_update_escrow_status_by_str,
    DbPool,
};
use crate::models::escrow::Escrow;
use crate::models::notification::{NewNotification, Notification, NotificationType};
// Order model removed in EaaS transformation - escrow status is the source of truth
use crate::models::wallet_rpc_config::WalletRpcConfig;
use crate::wallet_manager::WalletManager;
use crate::websocket::WebSocketServer;

/// Configuration for blockchain monitoring
#[derive(Clone, Debug)]
pub struct MonitorConfig {
    /// How often to check for transaction updates (in seconds)
    pub poll_interval_secs: u64,
    /// Number of confirmations required to consider a transaction settled
    pub required_confirmations: u32,
    /// Maximum number of blocks to scan in a single poll
    pub max_blocks_per_poll: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 30,
            // Post-2025 recommendation: 15+ confirmations after reorg attacks
            // See: https://blog.monerica.com/articles/how-many-confirmations-for-monero
            required_confirmations: 15,
            max_blocks_per_poll: 100,
        }
    }
}

/// Tracks consecutive failures per escrow for alerting
#[derive(Debug, Clone)]
struct ConsecutiveFailure {
    count: u32,
    first_failure_at: chrono::DateTime<chrono::Utc>,
    last_error: String,
}

/// Alert threshold for consecutive failures
const CONSECUTIVE_FAILURE_ALERT_THRESHOLD: u32 = 5;

/// Maximum time to wait for wallet refresh (5 minutes)
const WALLET_REFRESH_TIMEOUT_SECS: u64 = 300;

/// Blockchain monitoring service
pub struct BlockchainMonitor {
    wallet_manager: Arc<Mutex<WalletManager>>,
    db: DbPool,
    #[allow(dead_code)]
    websocket: Addr<WebSocketServer>,
    config: MonitorConfig,
    /// Encryption key for decrypting wallet RPC configs (non-custodial escrows)
    encryption_key: Vec<u8>,
    /// Track consecutive failures per escrow for alerting
    consecutive_failures:
        Arc<std::sync::Mutex<std::collections::HashMap<String, ConsecutiveFailure>>>,
}

impl BlockchainMonitor {
    /// Create a new blockchain monitor
    pub fn new(
        wallet_manager: Arc<Mutex<WalletManager>>,
        db: DbPool,
        websocket: Addr<WebSocketServer>,
        config: MonitorConfig,
        encryption_key: Vec<u8>,
    ) -> Self {
        info!(
            "BlockchainMonitor initialized with poll_interval={}s, required_confirmations={}",
            config.poll_interval_secs, config.required_confirmations
        );
        Self {
            wallet_manager,
            db,
            websocket,
            config,
            encryption_key,
            consecutive_failures: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Kill any process listening on a specific port
    ///
    /// Tries multiple methods for portability:
    /// 1. fuser (most Linux systems)
    /// 2. lsof + kill (macOS and some Linux)
    /// 3. pkill by name (fallback)
    async fn kill_process_on_port(&self, port: u16) -> bool {
        // Method 1: fuser (Linux)
        if let Ok(output) = std::process::Command::new("fuser")
            .args(["-k", &format!("{}/tcp", port)])
            .output()
        {
            if output.status.success() || !output.stderr.is_empty() {
                return true;
            }
        }

        // Method 2: lsof + kill (macOS, BSD)
        if let Ok(output) = std::process::Command::new("lsof")
            .args(["-t", "-i", &format!(":{}", port)])
            .output()
        {
            if output.status.success() {
                let pids = String::from_utf8_lossy(&output.stdout);
                for pid in pids.lines() {
                    if let Ok(pid_num) = pid.trim().parse::<i32>() {
                        let _ = std::process::Command::new("kill")
                            .args(["-9", &pid_num.to_string()])
                            .output();
                    }
                }
                return true;
            }
        }

        // Method 3: pkill by name (fallback - kills ALL monero-wallet-rpc)
        // Only use as last resort since it kills all instances
        if let Ok(output) = std::process::Command::new("pkill")
            .args(["-9", "-f", &format!("monero-wallet-rpc.*{}", port)])
            .output()
        {
            return output.status.success();
        }

        false
    }

    /// v0.75.0: Verify daemon is synced before wallet operations
    ///
    /// Checks monerod sync status to prevent wallet operations when daemon
    /// is still syncing (which would cause false negative balance checks).
    async fn verify_daemon_synced(&self) -> bool {
        let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        let daemon_port = match network.as_str() {
            "mainnet" => 18081,
            "testnet" => 28081,
            _ => 38081,
        };
        let daemon_url = format!("http://127.0.0.1:{}/json_rpc", daemon_port);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        let response = client
            .post(&daemon_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_info"
            }))
            .send()
            .await;

        match response {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(body) => {
                    let synced = body["result"]["synchronized"].as_bool().unwrap_or(false);
                    let height = body["result"]["height"].as_u64().unwrap_or(0);
                    let target_height = body["result"]["target_height"].as_u64().unwrap_or(0);

                    if !synced {
                        warn!(
                            "⚠️ [MONITOR] Daemon not synced yet (height {}/{})  - skipping poll",
                            height, target_height
                        );
                        return false;
                    }

                    info!("✅ [MONITOR] Daemon synced at height {}", height);
                    true
                }
                Err(e) => {
                    warn!("⚠️ [MONITOR] Failed to parse daemon response: {}", e);
                    false
                }
            },
            Err(e) => {
                error!("❌ [MONITOR] Daemon unreachable: {}", e);
                false
            }
        }
    }

    /// Record a consecutive failure for an escrow
    ///
    /// Alerts if threshold is exceeded.
    fn record_consecutive_failure(&self, escrow_id: &str, error_msg: &str) {
        let mut failures = self.consecutive_failures.lock().unwrap();
        let entry = failures
            .entry(escrow_id.to_string())
            .or_insert(ConsecutiveFailure {
                count: 0,
                first_failure_at: chrono::Utc::now(),
                last_error: String::new(),
            });

        entry.count += 1;
        entry.last_error = error_msg.to_string();

        if entry.count >= CONSECUTIVE_FAILURE_ALERT_THRESHOLD {
            error!(
                "🚨 [MONITOR] ALERT: Escrow {} has failed {} consecutive times since {}. Last error: {}",
                escrow_id, entry.count, entry.first_failure_at.format("%Y-%m-%d %H:%M:%S UTC"), entry.last_error
            );

            // Create admin notification (via WebSocket broadcast)
            self.websocket.do_send(crate::websocket::WsEvent::MultisigSetupStuck {
                escrow_id: escrow_id.to_string(),
                minutes_stuck: ((chrono::Utc::now() - entry.first_failure_at).num_minutes()) as u64,
                last_step: "funding_detection".to_string(),
                suggested_action: format!(
                    "Escrow {} funding detection failing. {} consecutive failures. Check wallet-rpc and daemon status.",
                    escrow_id, entry.count
                ),
            });
        }
    }

    /// Clear consecutive failures on success
    fn clear_consecutive_failures(&self, escrow_id: &str) {
        let mut failures = self.consecutive_failures.lock().unwrap();
        if failures.remove(escrow_id).is_some() {
            info!(
                "✅ [MONITOR] Cleared failure tracking for escrow {}",
                escrow_id
            );
        }
    }

    /// Ensure wallet-rpc is healthy, with auto-restart capability
    ///
    /// This function:
    /// 1. Checks if wallet-rpc responds to get_version
    /// 2. If unhealthy, attempts to restart the process
    /// 3. Waits for recovery (up to 60 seconds)
    /// 4. Returns true if healthy, false if recovery failed
    ///
    /// PRODUCTION CRITICAL: This prevents funding detection failures
    async fn ensure_wallet_rpc_healthy(&self, port: u16) -> bool {
        let url = format!("http://127.0.0.1:{}/json_rpc", port);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        // Step 1: Quick health check
        let health_check = || async {
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "id": "health",
                "method": "get_version"
            });

            match client.post(&url).json(&payload).send().await {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            }
        };

        if health_check().await {
            return true; // Already healthy
        }

        // Step 2: wallet-rpc is unhealthy - attempt restart
        warn!(
            "⚠️ [MONITOR] wallet-rpc on port {} unresponsive - attempting auto-restart",
            port
        );

        // Kill any existing process on the port
        // Try multiple methods for portability
        let killed = self.kill_process_on_port(port).await;
        if killed {
            info!("🔄 [MONITOR] Killed existing process on port {}", port);
        }

        // Wait a bit for port to be freed
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Step 3: Start new wallet-rpc process
        let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        let wallet_dir =
            std::env::var("WALLET_DIR").unwrap_or_else(|_| format!("./{}-wallets", network));
        let daemon_port = match network.as_str() {
            "mainnet" => 18081,
            "testnet" => 28081,
            "stagenet" | _ => 38081,
        };

        let network_flag = match network.as_str() {
            "mainnet" => "",
            "testnet" => "--testnet",
            _ => "--stagenet",
        };

        let mut cmd = std::process::Command::new("monero-wallet-rpc");

        if !network_flag.is_empty() {
            cmd.arg(network_flag);
        }

        cmd.args([
            "--rpc-bind-port",
            &port.to_string(),
            "--rpc-bind-ip",
            "127.0.0.1",
            "--disable-rpc-login",
            "--wallet-dir",
            &wallet_dir,
            "--daemon-address",
            &format!("127.0.0.1:{}", daemon_port),
            "--trusted-daemon",
            "--log-level",
            "1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

        match cmd.spawn() {
            Ok(child) => {
                info!(
                    "🚀 [MONITOR] Spawned wallet-rpc on port {} (PID {})",
                    port,
                    child.id()
                );
            }
            Err(e) => {
                error!("❌ [MONITOR] Failed to spawn wallet-rpc: {}", e);
                return false;
            }
        }

        // Step 4: Wait for wallet-rpc to become healthy (max 60s)
        let max_wait = 60;
        for i in 0..max_wait {
            tokio::time::sleep(Duration::from_secs(1)).await;

            if health_check().await {
                info!(
                    "✅ [MONITOR] wallet-rpc on port {} recovered after {}s",
                    port,
                    i + 1
                );
                return true;
            }

            if i % 10 == 9 {
                info!("⏳ [MONITOR] Still waiting for wallet-rpc... {}s", i + 1);
            }
        }

        error!(
            "❌ [MONITOR] wallet-rpc on port {} failed to recover after {}s",
            port, max_wait
        );
        false
    }

    /// Start monitoring in background
    ///
    /// This spawns a background task that periodically checks for:
    /// - New transactions to escrow addresses
    /// - Confirmation updates for pending transactions
    /// - Transaction completions
    pub async fn start_monitoring(self: Arc<Self>) {
        let mut poll_timer = interval(Duration::from_secs(self.config.poll_interval_secs));

        info!("Starting blockchain monitoring loop");

        loop {
            poll_timer.tick().await;

            if let Err(e) = Self::poll_escrows_parallel(Arc::clone(&self)).await {
                error!("Error polling escrows: {}", e);
            }
        }
    }

    /// Poll all active escrows for transaction updates (PARALLEL version)
    ///
    /// Uses batched parallel processing to check multiple escrows concurrently.
    /// Batch size is limited by PARALLEL_BATCH_SIZE to avoid overwhelming wallet-rpc.
    async fn poll_escrows_parallel(self_arc: Arc<Self>) -> Result<()> {
        // v0.75.0: STEP 0 - Verify daemon is synced BEFORE any wallet operations
        // This prevents false negatives from wallet refresh when daemon is still syncing
        if !self_arc.verify_daemon_synced().await {
            warn!("⚠️ [MONITOR] Daemon not synced - skipping this poll cycle");
            return Ok(()); // Don't fail, just skip this cycle
        }

        // PRODUCTION SAFETY: Health check wallet-rpc BEFORE any operations
        // This prevents silent failures and enables auto-recovery
        let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        let rpc_port = match network.as_str() {
            "mainnet" => 18086,
            "testnet" => 28086,
            "stagenet" | _ => 38086,
        };

        if !self_arc.ensure_wallet_rpc_healthy(rpc_port).await {
            error!("❌ [MONITOR] wallet-rpc on port {} unresponsive after recovery attempts - skipping poll cycle", rpc_port);
            return Ok(()); // Don't fail, just skip this cycle
        }

        // Get all escrows in 'funded' state (waiting for buyer to deposit)
        let funded_escrows = self_arc.get_funded_escrows().await?;
        let total_funded = funded_escrows.len();

        info!(
            "Polling {} funded escrows for updates (parallel, batch_size={})",
            total_funded, PARALLEL_BATCH_SIZE
        );

        // Process funded escrows in parallel batches
        // Each escrow in a batch uses a DIFFERENT RPC port to avoid wallet collisions
        for (batch_idx, chunk) in funded_escrows.chunks(PARALLEL_BATCH_SIZE).enumerate() {
            let batch_start = std::time::Instant::now();
            let batch_size = chunk.len();

            // Create futures for each escrow in this batch, assigning RPC ports by escrow ID hash
            // This ensures the same escrow ALWAYS uses the same port, avoiding "wallet opened by another program" errors
            // Phase 1.5: Use recovery wrapper for automatic wallet lock conflict resolution
            let futures: Vec<_> = chunk
                .iter()
                .map(|escrow_id_str| {
                    let self_clone = Arc::clone(&self_arc);
                    let eid = escrow_id_str.clone();
                    // Assign RPC port based on escrow ID hash (consistent across poll cycles)
                    let rpc_ports = get_monitoring_rpc_ports();
                    let hash: u64 = eid
                        .bytes()
                        .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
                    let port_idx = (hash % rpc_ports.len() as u64) as usize;
                    let rpc_port = rpc_ports[port_idx];
                    async move {
                        // Use recovery wrapper for automatic lock conflict resolution
                        self_clone
                            .check_escrow_funding_with_recovery(&eid, rpc_port)
                            .await;
                    }
                })
                .collect();

            // Execute batch in parallel
            join_all(futures).await;

            info!(
                "📊 [PARALLEL] Batch {}/{} completed: {} escrows in {:?}",
                batch_idx + 1,
                (total_funded + PARALLEL_BATCH_SIZE - 1) / PARALLEL_BATCH_SIZE,
                batch_size,
                batch_start.elapsed()
            );

            // Small pause between batches to avoid RPC overload
            if batch_idx < (total_funded / PARALLEL_BATCH_SIZE) {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        // Get all escrows in 'releasing' or 'refunding' state (transactions in flight)
        let pending_tx_escrows = self_arc.get_pending_transaction_escrows().await?;
        let total_pending = pending_tx_escrows.len();

        info!(
            "Polling {} escrows with pending transactions (parallel)",
            total_pending
        );

        // Process pending tx escrows in parallel batches
        for chunk in pending_tx_escrows.chunks(PARALLEL_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|escrow_id_str| {
                    let self_clone = Arc::clone(&self_arc);
                    let eid = escrow_id_str.clone();
                    async move {
                        if let Err(e) = self_clone.check_transaction_confirmations(&eid).await {
                            warn!("Error checking transaction for escrow {}: {}", eid, e);
                        }
                    }
                })
                .collect();

            join_all(futures).await;

            // Small pause between batches
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Ok(())
    }

    // ========================================================================
    // Phase 1.5: Wallet Lock Recovery Functions (PRODUCTION-GRADE AUTO-RECOVERY)
    // ========================================================================

    /// Close wallet on ALL monitoring RPC ports
    ///
    /// When a wallet lock conflict occurs, the wallet might be stuck open on
    /// a different port than expected. This function propagates close_wallet
    /// to all ports to clear any stale locks.
    ///
    /// # Arguments
    /// * `wallet_filename` - The wallet filename to close (without path)
    async fn close_wallet_on_all_ports(&self, wallet_filename: &str) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        let rpc_ports = get_monitoring_rpc_ports();
        info!(
            "🔄 [RECOVERY] Propagating close_wallet to all {} ports for wallet '{}'",
            rpc_ports.len(),
            wallet_filename
        );

        for port in &rpc_ports {
            let url = format!("http://127.0.0.1:{}/json_rpc", port);

            // Try to close - ignore errors (wallet might not be open on this port)
            let result = client
                .post(&url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "0",
                    "method": "close_wallet"
                }))
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    info!("🔄 [RECOVERY] close_wallet sent to port {} (may or may not have had wallet open)", port);
                }
                Ok(resp) => {
                    // Non-success status is fine - wallet might not be open
                    let _ = resp; // Silence unused warning
                }
                Err(_) => {
                    // Timeout or connection error - port might be down, that's OK
                }
            }
        }

        info!(
            "✅ [RECOVERY] Wallet close propagated to all ports: {}",
            wallet_filename
        );
    }

    /// Clean up stale wallet lock files
    ///
    /// Monero wallet-rpc creates .lock files to prevent concurrent access.
    /// If the process crashes, these lock files can become stale and prevent
    /// future access. This function removes them.
    ///
    /// # Arguments
    /// * `wallet_filename` - The wallet filename (without path)
    fn cleanup_wallet_lock_files(&self, wallet_filename: &str) {
        let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        let wallet_dir =
            std::env::var("WALLET_DIR").unwrap_or_else(|_| format!("./{}-wallets", network));

        // Check for .lock file (wallet-rpc creates this)
        let lock_path = format!("{}/{}.lock", wallet_dir, wallet_filename);

        if std::path::Path::new(&lock_path).exists() {
            match std::fs::remove_file(&lock_path) {
                Ok(_) => {
                    info!("🗑️ [RECOVERY] Removed stale lock file: {}", lock_path);
                }
                Err(e) => {
                    warn!(
                        "⚠️ [RECOVERY] Failed to remove lock file {}: {}",
                        lock_path, e
                    );
                }
            }
        }

        // Also check for .keys.lock file (some versions create this)
        let keys_lock_path = format!("{}/{}.keys.lock", wallet_dir, wallet_filename);

        if std::path::Path::new(&keys_lock_path).exists() {
            match std::fs::remove_file(&keys_lock_path) {
                Ok(_) => {
                    info!(
                        "🗑️ [RECOVERY] Removed stale keys lock file: {}",
                        keys_lock_path
                    );
                }
                Err(e) => {
                    warn!(
                        "⚠️ [RECOVERY] Failed to remove keys lock file {}: {}",
                        keys_lock_path, e
                    );
                }
            }
        }
    }

    /// Check escrow funding with automatic recovery from wallet lock conflicts
    ///
    /// This is a production-grade wrapper around `check_escrow_funding` that:
    /// 1. Attempts the normal funding check
    /// 2. If "wallet opened by another" error occurs:
    ///    - Propagates close_wallet to ALL RPC ports
    ///    - Cleans up stale .lock files
    ///    - Waits with exponential backoff
    ///    - Retries up to MAX_RETRIES times
    /// 3. If all retries fail, logs error and returns (will retry next poll cycle)
    ///
    /// # Arguments
    /// * `escrow_id` - The escrow UUID to check
    /// * `primary_port` - The primary RPC port assigned to this escrow (hash-based)
    async fn check_escrow_funding_with_recovery(&self, escrow_id: &str, primary_port: u16) {
        const MAX_RETRIES: u32 = 3;
        const BASE_RETRY_DELAY_MS: u64 = 2000;

        let wallet_filename = format!("view_only_escrow_{}", escrow_id);

        for attempt in 0..MAX_RETRIES {
            match self.check_escrow_funding(escrow_id, primary_port).await {
                Ok(_) => {
                    // v0.75.0: Success - clear any failure tracking
                    self.clear_consecutive_failures(escrow_id);
                    return;
                }
                Err(e) => {
                    let error_str = e.to_string();

                    // Check if this is a wallet lock conflict
                    if error_str.contains("opened by another")
                        || error_str.contains("wallet is locked")
                        || error_str.contains("Failed to open wallet")
                    {
                        warn!(
                            "🔒 [RECOVERY] Wallet lock conflict for escrow {} on port {}, attempt {}/{}",
                            escrow_id, primary_port, attempt + 1, MAX_RETRIES
                        );

                        // RECOVERY STEP 1: Close wallet on ALL ports
                        self.close_wallet_on_all_ports(&wallet_filename).await;

                        // RECOVERY STEP 2: Clean up stale lock files
                        self.cleanup_wallet_lock_files(&wallet_filename);

                        // RECOVERY STEP 3: Wait with exponential backoff
                        let delay_ms = BASE_RETRY_DELAY_MS * (attempt as u64 + 1);
                        info!(
                            "⏳ [RECOVERY] Waiting {}ms before retry {} for escrow {}",
                            delay_ms,
                            attempt + 2,
                            escrow_id
                        );
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                        // Continue to next retry attempt
                        continue;
                    }

                    // v0.75.0: Track consecutive failures for non-recoverable errors
                    self.record_consecutive_failure(escrow_id, &error_str);

                    // Not a wallet lock error - log and skip (don't retry)
                    warn!(
                        "❌ [MONITOR] Non-recoverable error checking escrow {} on port {}: {}",
                        escrow_id, primary_port, e
                    );
                    return;
                }
            }
        }

        // All retries exhausted
        self.record_consecutive_failure(escrow_id, "Max retries exceeded for wallet lock conflict");
        error!(
            "❌ [RECOVERY] Max retries ({}) exceeded for escrow {} - will retry next poll cycle",
            MAX_RETRIES, escrow_id
        );
    }

    /// Check if an escrow is non-custodial (FROST/WASM)
    ///
    /// All FROST escrows are non-custodial. Detection:
    /// 1. Has multisig_view_key (FROST DKG completed) → non-custodial
    /// 2. Has buyer_wallet_info BLOB (legacy WASM) → non-custodial
    /// 3. Otherwise → custodial (legacy, should not exist)
    async fn is_non_custodial_escrow(&self, escrow_id: &str) -> Result<bool> {
        let mut conn = self.db.get().context("Failed to get DB connection")?;
        let escrow_id_clone = escrow_id.to_string();

        let result = tokio::task::spawn_blocking(move || {
            use crate::schema::escrows::dsl::*;
            use diesel::prelude::*;

            escrows
                .filter(id.eq(&escrow_id_clone))
                .select((multisig_view_key, buyer_wallet_info))
                .first::<(Option<String>, Option<Vec<u8>>)>(&mut conn)
        })
        .await
        .context("Task join error")??;

        // FROST escrows have multisig_view_key from DKG; legacy WASM have wallet_info BLOBs
        Ok(result.0.is_some() || result.1.is_some())
    }

    /// Check if an escrow multisig address has received funding
    ///
    /// This monitors the multisig wallet balance and updates escrow status
    /// when funds are detected. Supports both custodial (server-managed wallets)
    /// and non-custodial (client RPC) modes.
    ///
    /// # Parameters
    /// - `escrow_id`: The escrow UUID to check
    /// - `rpc_port`: The wallet-rpc port to use (each parallel check MUST use a different port)
    async fn check_escrow_funding(&self, escrow_id: &str, rpc_port: u16) -> Result<()> {
        let escrow = db_load_escrow_by_str(&self.db, escrow_id).await?;

        // Escrow must have a multisig address
        let multisig_address = escrow
            .multisig_address
            .ok_or_else(|| anyhow::anyhow!("Escrow {} has no multisig address", escrow_id))?;

        info!(
            "Checking funding for escrow {} at address {}",
            escrow_id,
            &multisig_address[..10]
        );

        let escrow_id_str = escrow_id.to_string();

        // Detect if this is a non-custodial WASM escrow
        let is_wasm = self.is_non_custodial_escrow(escrow_id).await?;

        if is_wasm {
            // ========================================================================
            // INSTRUMENTATION: Complete tracing for blockchain monitor debug
            // ========================================================================
            let monitor_start = std::time::Instant::now();
            info!(
                "🔬 [MONITOR-TRACE] ========== START check_escrow_funding for {} ==========",
                escrow_id
            );

            // WASM NON-CUSTODIAL MODE: Create view-only wallet using shared multisig view key
            info!("🔬 [MONITOR-TRACE] Step 1: WASM escrow detected");

            // Get the SHARED multisig view key
            let view_key = match escrow.multisig_view_key {
                Some(ref key) => {
                    info!(
                        "🔬 [MONITOR-TRACE] Step 2: Got view_key (len={})",
                        key.len()
                    );
                    key.clone()
                }
                None => {
                    error!("🔬 [MONITOR-TRACE] FAILED at Step 2: Missing multisig_view_key");
                    return Err(anyhow::anyhow!(
                        "WASM escrow {} missing multisig_view_key - finalization incomplete",
                        escrow_id
                    ));
                }
            };

            // Validate view key format
            if view_key.len() != 64 || !view_key.chars().all(|c| c.is_ascii_hexdigit()) {
                error!("🔬 [MONITOR-TRACE] FAILED at Step 2b: Invalid view_key format");
                return Err(anyhow::anyhow!(
                    "Invalid multisig_view_key format for escrow {}",
                    escrow_id
                ));
            }
            info!("🔬 [MONITOR-TRACE] Step 2b: view_key format valid");

            // CRITICAL: Cryptographic validation - view key must derive to address's view public key
            match validate_view_key_matches_address(&view_key, &multisig_address) {
                Ok(true) => {
                    info!(
                        "🔬 [MONITOR-TRACE] Step 2c: ✅ View key VALIDATED - matches address cryptographically"
                    );
                }
                Ok(false) => {
                    error!(
                        "🔬 [MONITOR-TRACE] CRITICAL: View key MISMATCH for escrow {}!",
                        escrow_id
                    );
                    error!(
                        "   view_key: {}... does NOT derive to address: {}...",
                        &view_key[..16],
                        &multisig_address[..20]
                    );
                    return Err(anyhow::anyhow!(
                        "Data corruption: view_key doesn't match multisig_address for escrow {}. \
                         This escrow cannot be monitored until the correct view key is stored.",
                        escrow_id
                    ));
                }
                Err(e) => {
                    error!(
                        "🔬 [MONITOR-TRACE] View key validation error for escrow {}: {}",
                        escrow_id, e
                    );
                    return Err(anyhow::anyhow!(
                        "View key validation failed for escrow {}: {}",
                        escrow_id,
                        e
                    ));
                }
            }

            // Network configuration - use passed rpc_port to avoid wallet collisions in parallel
            let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
            let daemon_port = match network.as_str() {
                "mainnet" => 18081,
                "testnet" => 28081,
                "stagenet" | _ => 38081,
            };
            // Use the RPC port passed as parameter (enables parallel checks on different ports)
            let rpc_url = format!("http://127.0.0.1:{}/json_rpc", rpc_port);
            let daemon_url = format!("http://127.0.0.1:{}/json_rpc", daemon_port);
            info!(
                "🔬 [MONITOR-TRACE] Step 3: Using RPC port {} daemon {}",
                rpc_port, daemon_url
            );

            // Build HTTP client with timeouts (300s for slow wallet scans)
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .context("Failed to build HTTP client")?;
            info!("🔬 [MONITOR-TRACE] Step 4: HTTP client built with 300s timeout");

            // NOTE: We intentionally skip close_wallet here to avoid race conditions.
            // If multiple monitor cycles run concurrently, close_wallet from cycle N+1
            // can interrupt cycle N's get_balance call.
            // Instead, we try to open existing wallet first, then create if needed.
            info!("🔬 [MONITOR-TRACE] Step 5: Skipping close_wallet (race condition fix)");

            // Get blockchain height from daemon
            info!("🔬 [MONITOR-TRACE] Step 6: Getting blockchain height from daemon...");
            let height_response = client
                .post(&daemon_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "0",
                    "method": "get_info"
                }))
                .send()
                .await;

            // Fallback heights as of Jan 2026 - update quarterly!
            // These are used when daemon is unreachable, to avoid scanning from genesis
            let fallback_height = match network.as_str() {
                "mainnet" => 3550000, // Updated Jan 2026 (mainnet ~3,596,000)
                "testnet" => 2950000, // Updated Jan 2026
                "stagenet" | _ => 2100000,
            };

            let restore_height = match height_response {
                Ok(resp) => {
                    let height_json: serde_json::Value = resp.json().await.unwrap_or_default();
                    let current_height = height_json["result"]["height"].as_u64().unwrap_or(0);
                    let calculated = if current_height > 100 {
                        current_height - 100
                    } else {
                        0
                    };
                    info!(
                        "🔬 [MONITOR-TRACE] Step 6 result: daemon height={}, restore_height={}",
                        current_height, calculated
                    );
                    calculated
                }
                Err(e) => {
                    warn!("🔬 [MONITOR-TRACE] Step 6 result: daemon unreachable ({}), using fallback {}", e, fallback_height);
                    fallback_height
                }
            };

            // Generate or open view-only wallet
            // IMPORTANT: Try to OPEN first, only CREATE if doesn't exist
            // This preserves sync state and avoids repeated blockchain scans
            let wallet_filename = format!("view_only_escrow_{}", escrow_id);
            let wallet_password = format!("escrow_{}", escrow_id);

            // Track if wallet already existed (affects refresh behavior)
            let mut wallet_was_opened = false;

            info!(
                "🔬 [MONITOR-TRACE] Step 7: Trying to OPEN existing wallet '{}' first...",
                wallet_filename
            );

            // Step 7a: Try to open existing wallet first
            let open_response = client
                .post(&rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "0",
                    "method": "open_wallet",
                    "params": {
                        "filename": wallet_filename,
                        "password": wallet_password
                    }
                }))
                .send()
                .await;

            match open_response {
                Ok(resp) => {
                    let open_body: serde_json::Value = resp.json().await.unwrap_or_default();

                    if open_body.get("error").is_none() {
                        // Wallet opened successfully - but we MUST verify it's the correct wallet!
                        // BUG FIX: Wallet files can be corrupted/overwritten, address validation is critical
                        info!(
                            "🔬 [MONITOR-TRACE] Step 7a: Wallet file opened, validating address..."
                        );

                        // Get the wallet's actual address
                        let addr_response = client
                            .post(&rpc_url)
                            .json(&serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": "0",
                                "method": "get_address"
                            }))
                            .send()
                            .await;

                        let wallet_address = match addr_response {
                            Ok(resp) => {
                                let addr_body: serde_json::Value =
                                    resp.json().await.unwrap_or_default();
                                addr_body["result"]["address"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string()
                            }
                            Err(e) => {
                                warn!(
                                    "🔬 [MONITOR-TRACE] Step 7a: Failed to get wallet address: {}",
                                    e
                                );
                                String::new()
                            }
                        };

                        if wallet_address == multisig_address {
                            // Wallet is correct!
                            wallet_was_opened = true;
                            info!("🔬 [MONITOR-TRACE] Step 7a: ✅ Wallet VERIFIED - address matches (already synced)");
                        } else {
                            // CRITICAL: Wallet file is corrupted - wrong address!
                            error!(
                                "🔬 [MONITOR-TRACE] Step 7a: ❌ WALLET CORRUPTED! Expected {} got {}",
                                &multisig_address[..20],
                                if wallet_address.len() >= 20 { &wallet_address[..20] } else { &wallet_address }
                            );

                            // Close and delete the corrupted wallet, then recreate
                            info!("🔬 [MONITOR-TRACE] Step 7a: Closing corrupted wallet...");
                            let _ = client
                                .post(&rpc_url)
                                .json(&serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": "0",
                                    "method": "close_wallet"
                                }))
                                .send()
                                .await;

                            // Delete corrupted wallet files
                            let wallet_dir = std::env::var("WALLET_DIR")
                                .unwrap_or_else(|_| "./stagenet-wallets".to_string());
                            let wallet_base = format!("{}/{}", wallet_dir, wallet_filename);
                            for ext in &["", ".keys", ".address.txt"] {
                                let path = format!("{}{}", wallet_base, ext);
                                if std::path::Path::new(&path).exists() {
                                    if let Err(e) = std::fs::remove_file(&path) {
                                        warn!(
                                            "Failed to delete corrupted wallet file {}: {}",
                                            path, e
                                        );
                                    } else {
                                        info!(
                                            "🔬 [MONITOR-TRACE] Deleted corrupted file: {}",
                                            path
                                        );
                                    }
                                }
                            }

                            // Now recreate with correct keys
                            info!("🔬 [MONITOR-TRACE] Step 7a: Recreating wallet with correct view key...");
                            let generate_payload = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": "0",
                                "method": "generate_from_keys",
                                "params": {
                                    "restore_height": restore_height,
                                    "filename": wallet_filename,
                                    "address": multisig_address,
                                    "viewkey": view_key,
                                    "spendkey": "",
                                    "password": wallet_password
                                }
                            });

                            let gen_response =
                                client.post(&rpc_url).json(&generate_payload).send().await;

                            match gen_response {
                                Ok(resp) => {
                                    let gen_body: serde_json::Value =
                                        resp.json().await.unwrap_or_default();
                                    if gen_body.get("error").is_some() {
                                        let gen_err = gen_body["error"]["message"]
                                            .as_str()
                                            .unwrap_or("unknown");
                                        error!(
                                            "🔬 [MONITOR-TRACE] FAILED to recreate wallet: {}",
                                            gen_err
                                        );
                                        return Err(anyhow::anyhow!(
                                            "Failed to recreate corrupted wallet: {}",
                                            gen_err
                                        ));
                                    }
                                    info!("🔬 [MONITOR-TRACE] Step 7a: ✅ Wallet RECREATED successfully");
                                    // wallet_was_opened stays false - new wallet needs full scan
                                }
                                Err(e) => {
                                    error!("🔬 [MONITOR-TRACE] FAILED to recreate wallet: {}", e);
                                    return Err(anyhow::anyhow!(
                                        "Failed to recreate corrupted wallet: {}",
                                        e
                                    ));
                                }
                            }
                        }
                    } else {
                        let err_msg = open_body["error"]["message"].as_str().unwrap_or("");
                        info!(
                            "🔬 [MONITOR-TRACE] Step 7a: open_wallet failed: {}",
                            err_msg
                        );

                        // Wallet doesn't exist - need to create it
                        if err_msg.contains("Failed to open wallet")
                            || err_msg.contains("does not exist")
                        {
                            info!("🔬 [MONITOR-TRACE] Step 7b: Wallet doesn't exist, creating with restore_height={}", restore_height);

                            let generate_payload = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": "0",
                                "method": "generate_from_keys",
                                "params": {
                                    "restore_height": restore_height,
                                    "filename": wallet_filename,
                                    "address": multisig_address,
                                    "viewkey": view_key,
                                    "spendkey": "",
                                    "password": wallet_password
                                }
                            });

                            let generate_start = std::time::Instant::now();
                            let generate_response =
                                client.post(&rpc_url).json(&generate_payload).send().await;

                            match generate_response {
                                Ok(gen_resp) => {
                                    let gen_body: serde_json::Value =
                                        gen_resp.json().await.unwrap_or_default();
                                    info!("🔬 [MONITOR-TRACE] Step 7b: generate_from_keys result in {:?}: {:?}",
                                          generate_start.elapsed(), gen_body);

                                    if gen_body.get("error").is_some() {
                                        let gen_err = gen_body["error"]["message"]
                                            .as_str()
                                            .unwrap_or("unknown");
                                        // If wallet already exists (race condition), try to open again
                                        if gen_err.contains("already exists")
                                            || gen_err.contains("Cannot create")
                                        {
                                            info!("🔬 [MONITOR-TRACE] Step 7c: Wallet created by another process, opening...");
                                            let retry_open = client
                                                .post(&rpc_url)
                                                .json(&serde_json::json!({
                                                    "jsonrpc": "2.0",
                                                    "id": "0",
                                                    "method": "open_wallet",
                                                    "params": {
                                                        "filename": wallet_filename,
                                                        "password": wallet_password
                                                    }
                                                }))
                                                .send()
                                                .await
                                                .context(
                                                    "Failed to open wallet after create race",
                                                )?;
                                            let retry_body: serde_json::Value =
                                                retry_open.json().await.unwrap_or_default();
                                            if retry_body.get("error").is_some() {
                                                error!(
                                                    "🔬 [MONITOR-TRACE] FAILED at Step 7c: {:?}",
                                                    retry_body["error"]
                                                );
                                                return Err(anyhow::anyhow!(
                                                    "Failed to open wallet: {:?}",
                                                    retry_body["error"]
                                                ));
                                            }
                                            wallet_was_opened = true;
                                        } else {
                                            error!(
                                                "🔬 [MONITOR-TRACE] FAILED at Step 7b: {}",
                                                gen_err
                                            );
                                            return Err(anyhow::anyhow!(
                                                "Failed to create view-only wallet: {}",
                                                gen_err
                                            ));
                                        }
                                    }
                                    // wallet_was_opened stays false - new wallet needs full scan
                                }
                                Err(e) => {
                                    error!(
                                        "🔬 [MONITOR-TRACE] FAILED at Step 7b: HTTP error: {}",
                                        e
                                    );
                                    return Err(anyhow::anyhow!(
                                        "Failed to create view-only wallet: {}",
                                        e
                                    ));
                                }
                            }
                        } else {
                            // Some other error (maybe wallet is locked by another process)
                            error!(
                                "🔬 [MONITOR-TRACE] FAILED at Step 7a: Unexpected error: {}",
                                err_msg
                            );
                            return Err(anyhow::anyhow!("Failed to open wallet: {}", err_msg));
                        }
                    }
                }
                Err(e) => {
                    error!("🔬 [MONITOR-TRACE] FAILED at Step 7: HTTP error: {}", e);
                    return Err(anyhow::anyhow!(
                        "Failed to open/create view-only wallet: {}",
                        e
                    ));
                }
            }

            // Step 8: Refresh wallet
            // CRITICAL: If wallet was opened (already exists), refresh WITHOUT start_height
            // This allows incremental sync from last saved state instead of full rescan
            let refresh_payload = if wallet_was_opened {
                info!("🔬 [MONITOR-TRACE] Step 8: Wallet was OPENED, refreshing incrementally (no start_height)...");
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "0",
                    "method": "refresh"
                    // No start_height = continue from last sync point
                })
            } else {
                info!("🔬 [MONITOR-TRACE] Step 8: Wallet was CREATED, refreshing with start_height={}...", restore_height);
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "0",
                    "method": "refresh",
                    "params": {
                        "start_height": restore_height
                    }
                })
            };

            let refresh_start = std::time::Instant::now();
            info!(
                "🔬 [MONITOR-TRACE] Step 8: Sending refresh request (timeout={}s)...",
                WALLET_REFRESH_TIMEOUT_SECS
            );

            // v0.75.0: Wrap refresh in timeout to prevent indefinite blocking
            // Wallet refresh can take a long time for new wallets scanning from restore_height
            let refresh_future = client.post(&rpc_url).json(&refresh_payload).send();

            let refresh_response = match tokio::time::timeout(
                Duration::from_secs(WALLET_REFRESH_TIMEOUT_SECS),
                refresh_future,
            )
            .await
            {
                Ok(Ok(resp)) => {
                    info!(
                        "🔬 [MONITOR-TRACE] Step 8: Refresh HTTP {} in {:?}",
                        resp.status(),
                        refresh_start.elapsed()
                    );
                    resp
                }
                Ok(Err(e)) => {
                    error!(
                        "🔬 [MONITOR-TRACE] FAILED at Step 8: Refresh HTTP error after {:?}: {}",
                        refresh_start.elapsed(),
                        e
                    );
                    return Err(anyhow::anyhow!("Failed to send refresh request: {}", e));
                }
                Err(_) => {
                    // TIMEOUT - wallet-rpc may be stuck
                    error!(
                        "🔬 [MONITOR-TRACE] CRITICAL: Refresh TIMEOUT after {}s - wallet-rpc may be stuck!",
                        WALLET_REFRESH_TIMEOUT_SECS
                    );
                    warn!(
                        "⚠️ [MONITOR] Wallet refresh timed out on port {} - consider restarting wallet-rpc",
                        rpc_port
                    );
                    return Err(anyhow::anyhow!(
                        "Refresh timeout after {}s - wallet-rpc may need restart",
                        WALLET_REFRESH_TIMEOUT_SECS
                    ));
                }
            };

            if !refresh_response.status().is_success() {
                let status = refresh_response.status();
                let error_text = refresh_response.text().await.unwrap_or_default();
                error!(
                    "🔬 [MONITOR-TRACE] FAILED at Step 8: HTTP {} - {}",
                    status, error_text
                );
                return Err(anyhow::anyhow!(
                    "Refresh HTTP error {}: {}",
                    status,
                    error_text
                ));
            }

            let refresh_result: serde_json::Value = match refresh_response.json().await {
                Ok(json) => {
                    info!("🔬 [MONITOR-TRACE] Step 8: Refresh response parsed");
                    json
                }
                Err(e) => {
                    error!(
                        "🔬 [MONITOR-TRACE] FAILED at Step 8: JSON parse error: {}",
                        e
                    );
                    return Err(anyhow::anyhow!("Failed to parse refresh response: {}", e));
                }
            };

            if let Some(error) = refresh_result.get("error") {
                error!(
                    "🔬 [MONITOR-TRACE] FAILED at Step 8: RPC error: {:?}",
                    error
                );
                return Err(anyhow::anyhow!("Refresh RPC error: {}", error));
            }

            let blocks_fetched = refresh_result["result"]["blocks_fetched"]
                .as_u64()
                .unwrap_or(0);
            let received_money = refresh_result["result"]["received_money"]
                .as_bool()
                .unwrap_or(false);
            info!(
                "🔬 [MONITOR-TRACE] Step 8 COMPLETE: blocks_fetched={}, received_money={}, elapsed={:?}",
                blocks_fetched, received_money, refresh_start.elapsed()
            );

            // Step 8b: Save wallet state to disk (critical for persistence!)
            // This ensures next poll cycle can do incremental sync instead of full rescan
            info!("🔬 [MONITOR-TRACE] Step 8b: Saving wallet state to disk...");
            let store_response = client
                .post(&rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "0",
                    "method": "store"
                }))
                .send()
                .await;

            match store_response {
                Ok(resp) => {
                    let store_body: serde_json::Value = resp.json().await.unwrap_or_default();
                    if store_body.get("error").is_some() {
                        warn!(
                            "🔬 [MONITOR-TRACE] Step 8b: store failed (non-fatal): {:?}",
                            store_body["error"]
                        );
                    } else {
                        info!("🔬 [MONITOR-TRACE] Step 8b: ✅ Wallet state saved");
                    }
                }
                Err(e) => {
                    warn!(
                        "🔬 [MONITOR-TRACE] Step 8b: store HTTP error (non-fatal): {}",
                        e
                    );
                }
            }

            // Get balance
            info!("🔬 [MONITOR-TRACE] Step 9: Getting balance...");
            let balance_payload = serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_balance"
            });

            let balance_start = std::time::Instant::now();
            let balance_response = match client.post(&rpc_url).json(&balance_payload).send().await {
                Ok(resp) => {
                    info!(
                        "🔬 [MONITOR-TRACE] Step 9: get_balance HTTP {} in {:?}",
                        resp.status(),
                        balance_start.elapsed()
                    );
                    resp
                }
                Err(e) => {
                    error!(
                        "🔬 [MONITOR-TRACE] FAILED at Step 9: get_balance HTTP error: {}",
                        e
                    );
                    return Err(anyhow::anyhow!("Failed to send get_balance request: {}", e));
                }
            };

            // Check HTTP status
            if !balance_response.status().is_success() {
                let status = balance_response.status();
                let error_text = balance_response.text().await.unwrap_or_default();
                error!(
                    "🔬 [MONITOR-TRACE] FAILED at Step 9: HTTP {} - {}",
                    status, error_text
                );
                return Err(anyhow::anyhow!(
                    "get_balance HTTP error {}: {}",
                    status,
                    error_text
                ));
            }

            let balance_result: serde_json::Value = match balance_response.json().await {
                Ok(json) => {
                    info!("🔬 [MONITOR-TRACE] Step 9: Balance response: {:?}", json);
                    json
                }
                Err(e) => {
                    error!(
                        "🔬 [MONITOR-TRACE] FAILED at Step 9: JSON parse error: {}",
                        e
                    );
                    return Err(anyhow::anyhow!("Failed to parse balance response: {}", e));
                }
            };

            // Check for RPC error
            if let Some(error) = balance_result.get("error") {
                error!(
                    "🔬 [MONITOR-TRACE] FAILED at Step 9: RPC error: {:?}",
                    error
                );
                return Err(anyhow::anyhow!("get_balance RPC error: {}", error));
            }

            let total_balance = balance_result["result"]["balance"]
                .as_u64()
                .ok_or_else(|| {
                    error!("🔬 [MONITOR-TRACE] FAILED at Step 9: Missing 'balance' field");
                    anyhow::anyhow!("Missing balance in response: {:?}", balance_result)
                })?;

            let unlocked_balance = balance_result["result"]["unlocked_balance"]
                .as_u64()
                .ok_or_else(|| {
                    error!("🔬 [MONITOR-TRACE] FAILED at Step 9: Missing 'unlocked_balance' field");
                    anyhow::anyhow!("Missing unlocked_balance in response: {:?}", balance_result)
                })?;

            info!(
                "🔬 [MONITOR-TRACE] Step 9 COMPLETE: total={}, unlocked={}, expected={}",
                total_balance, unlocked_balance, escrow.amount
            );

            // Check if funds have arrived
            info!(
                "🔬 [MONITOR-TRACE] Step 10: Checking funding condition: total={}, unlocked={}, expected={}",
                total_balance, unlocked_balance, escrow.amount
            );

            // v0.85.0: Early payment detection - TX visible but not yet fully confirmed
            // total_balance includes unconfirmed/locked outputs (1-9 confirmations)
            // unlocked_balance only includes 10+ confirmation outputs
            if total_balance > 0 && unlocked_balance < escrow.amount as u64 {
                // Update balance_received with total_balance (includes unconfirmed)
                let escrow_id_str = escrow_id.to_string();
                let balance = total_balance as i64;
                let db_pool = self.db.clone();

                if let Err(e) = tokio::task::spawn_blocking(move || {
                    let mut conn = db_pool.get().context("Failed to get DB connection")?;
                    Escrow::update_balance_received(&mut conn, escrow_id_str, balance)
                })
                .await
                .context("Task join error")?
                {
                    error!(
                        "🔬 [MONITOR-TRACE] Step 10: ⚠️ Failed to update balance_received: {}",
                        e
                    );
                } else {
                    info!("🔬 [MONITOR-TRACE] Step 10: Updated balance_received to {} piconero (total, includes unconfirmed)", total_balance);
                }

                // Transition to payment_detected if currently "created"
                if escrow.status == "created" {
                    info!(
                        "🔬 [MONITOR-TRACE] Step 10-EARLY: 💰 Payment detected! total={} piconero, waiting for confirmations (unlocked={})...",
                        total_balance, unlocked_balance
                    );

                    match db_update_escrow_status_by_str(&self.db, escrow_id, "payment_detected")
                        .await
                    {
                        Ok(_) => {
                            info!("🔬 [MONITOR-TRACE] Step 10-EARLY: Status updated to 'payment_detected'");

                            // Notify both parties via WebSocket
                            use crate::websocket::WsEvent;
                            self.websocket.do_send(WsEvent::PaymentDetected {
                                escrow_id: escrow_id.to_string(),
                                amount_detected: total_balance,
                                amount_required: escrow.amount as u64,
                                buyer_id: escrow.buyer_id.clone(),
                                vendor_id: escrow.vendor_id.clone(),
                            });
                        }
                        Err(e) => {
                            error!(
                                "🔬 [MONITOR-TRACE] Step 10-EARLY: Failed to update status: {}",
                                e
                            );
                        }
                    }
                }

                // If unlocked > 0 but < amount, also handle underfunded (partial confirmed payment)
                if unlocked_balance > 0
                    && unlocked_balance < escrow.amount as u64
                    && escrow.status != "underfunded"
                    && escrow.status != "payment_detected"
                {
                    // Fall through to underfunded handling below
                } else {
                    // Payment detected but not yet confirmed enough - keep polling
                    return Ok(());
                }
            }

            // v0.68.0: Always update balance_received when unlocked funds detected
            if unlocked_balance > 0 {
                let escrow_id_str = escrow_id.to_string();
                let balance = unlocked_balance as i64;
                let db_pool = self.db.clone();

                if let Err(e) = tokio::task::spawn_blocking(move || {
                    let mut conn = db_pool.get().context("Failed to get DB connection")?;
                    Escrow::update_balance_received(&mut conn, escrow_id_str, balance)
                })
                .await
                .context("Task join error")?
                {
                    error!(
                        "🔬 [MONITOR-TRACE] Step 10: ⚠️ Failed to update balance_received: {}",
                        e
                    );
                } else {
                    info!("🔬 [MONITOR-TRACE] Step 10: Updated balance_received to {} piconero (unlocked/confirmed)", unlocked_balance);
                }
            }

            // v0.68.0: Check for partial payment (underfunded)
            if unlocked_balance > 0 && unlocked_balance < escrow.amount as u64 {
                // Partial payment detected - transition to underfunded if not already
                if escrow.status != "underfunded" {
                    info!(
                        "🔬 [MONITOR-TRACE] Step 10-PARTIAL: Partial payment detected: {} / {} piconero ({:.1}%)",
                        unlocked_balance, escrow.amount,
                        (unlocked_balance as f64 / escrow.amount as f64) * 100.0
                    );

                    // Update status to underfunded
                    match db_update_escrow_status_by_str(&self.db, escrow_id, "underfunded").await {
                        Ok(_) => {
                            info!("🔬 [MONITOR-TRACE] Step 10-PARTIAL: Escrow status updated to 'underfunded'");

                            // Create notification for buyer about partial payment
                            let shortfall = escrow.amount as u64 - unlocked_balance;
                            let shortfall_xmr = shortfall as f64 / 1_000_000_000_000.0;
                            let received_xmr = unlocked_balance as f64 / 1_000_000_000_000.0;

                            let db_pool = self.db.clone();
                            let buyer_id = escrow.buyer_id.clone();
                            let escrow_id_str = escrow_id.to_string();

                            let amount_required = escrow.amount;
                            let _ = tokio::task::spawn_blocking(move || {
                                let mut conn = match db_pool.get() {
                                    Ok(c) => c,
                                    Err(_) => return,
                                };

                                let notification = NewNotification::new(
                                    buyer_id,
                                    NotificationType::EscrowUpdate,
                                    "Partial Payment Received".to_string(),
                                    format!(
                                        "Received {:.6} XMR for escrow, but {:.6} XMR more is required. Send the remaining amount to complete funding.",
                                        received_xmr, shortfall_xmr
                                    ),
                                    Some(format!("/escrow/{}", escrow_id_str)),
                                    Some(serde_json::json!({
                                        "escrow_id": escrow_id_str,
                                        "balance_received": unlocked_balance,
                                        "amount_required": amount_required,
                                        "shortfall": shortfall
                                    }).to_string()),
                                );

                                let _ = Notification::create(notification, &mut conn);
                            });
                        }
                        Err(e) => {
                            error!("🔬 [MONITOR-TRACE] Step 10-PARTIAL: Failed to update status to underfunded: {}", e);
                        }
                    }
                }

                // Don't proceed with funding capture - wait for full amount
                return Ok(());
            }

            if unlocked_balance > 0 && unlocked_balance >= escrow.amount as u64 {
                info!("🔬 [MONITOR-TRACE] Step 10: ✅ FUNDED! Capturing commitment mask...");

                // Step 10a: Capture commitment mask from incoming transfers
                // The mask (blinding factor) is required for CLSAG ring signatures
                let incoming_response = client
                    .post(&rpc_url)
                    .json(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": "0",
                        "method": "incoming_transfers",
                        "params": {
                            "transfer_type": "available"
                        }
                    }))
                    .send()
                    .await;

                let mut funding_mask: Option<String> = None;
                let mut funding_tx_hash: Option<String> = None;
                let mut funding_global_index: Option<i32> = None;
                let mut funding_output_index: Option<i32> = None;
                let mut funding_output_pubkey: Option<String> = None;
                let mut funding_tx_pubkey: Option<String> = None; // v0.8.2: For PKI derivation

                match incoming_response {
                    Ok(resp) => {
                        let incoming_json: serde_json::Value =
                            resp.json().await.unwrap_or_default();
                        info!(
                            "🔬 [MONITOR-TRACE] Step 10a: incoming_transfers response: {:?}",
                            incoming_json
                        );

                        // Extract transfers array
                        if let Some(transfers) = incoming_json["result"]["transfers"].as_array() {
                            // Find the transfer with the largest amount (should be the escrow funding)
                            for transfer in transfers {
                                let amount = transfer["amount"].as_u64().unwrap_or(0);
                                if amount >= escrow.amount as u64 {
                                    // Found the funding transfer - extract mask
                                    if let Some(mask) = transfer["mask"].as_str() {
                                        funding_mask = Some(mask.to_string());
                                        info!("🔬 [MONITOR-TRACE] Step 10a: ✅ Found commitment mask (len={})", mask.len());
                                    } else {
                                        warn!("🔬 [MONITOR-TRACE] Step 10a: ⚠️ Transfer found but 'mask' field missing");
                                    }
                                    if let Some(tx_hash) = transfer["tx_hash"].as_str() {
                                        funding_tx_hash = Some(tx_hash.to_string());
                                    }
                                    if let Some(global_idx) = transfer["global_index"].as_u64() {
                                        funding_global_index = Some(global_idx as i32);
                                    }
                                    // Extract output pubkey for auto-PKI
                                    if let Some(pubkey) = transfer["pubkey"].as_str() {
                                        funding_output_pubkey = Some(pubkey.to_string());
                                        info!("🔬 [MONITOR-TRACE] Step 10a: ✅ Found output pubkey: {}...", &pubkey[..16.min(pubkey.len())]);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "🔬 [MONITOR-TRACE] Step 10a: ⚠️ Failed to get incoming_transfers: {}",
                            e
                        );
                    }
                }

                // Step 10b: If mask not found in incoming_transfers, DERIVE IT from view key
                // View-only wallets cannot provide the mask directly, but we can derive it
                // using: mask = Hs("commitment_mask" || Hs(8 * view_priv * tx_pub_key || output_index))
                if funding_mask.is_none() {
                    if let Some(tx_hash) = funding_tx_hash.as_ref() {
                        info!("🔬 [MONITOR-TRACE] Step 10b: Deriving commitment mask from view key...");

                        // Step 10b.1: Get tx_pub_key from daemon via get_transactions
                        // BUG #C5 FIX: Use MONERO_DAEMON_URL env var instead of hardcoded port
                        let daemon_base = std::env::var("MONERO_DAEMON_URL")
                            .unwrap_or_else(|_| "http://127.0.0.1:18081".to_string());
                        let daemon_url = format!("{}/get_transactions", daemon_base);
                        let daemon_response = client
                            .post(daemon_url)
                            .json(&serde_json::json!({
                                "txs_hashes": [tx_hash],
                                "decode_as_json": true
                            }))
                            .send()
                            .await;

                        match daemon_response {
                            Ok(resp) => {
                                let daemon_json: serde_json::Value =
                                    resp.json().await.unwrap_or_default();

                                // Extract tx_pub_key from tx extra field
                                // The extra field is in the decoded JSON, look for "extra" array
                                if let Some(txs) = daemon_json.get("txs").and_then(|t| t.as_array())
                                {
                                    if let Some(tx) = txs.first() {
                                        // Try to get extra from as_json parsed version
                                        if let Some(as_json_str) =
                                            tx.get("as_json").and_then(|j| j.as_str())
                                        {
                                            if let Ok(tx_parsed) =
                                                serde_json::from_str::<serde_json::Value>(
                                                    as_json_str,
                                                )
                                            {
                                                // Step 10b.1: Extract tx_pub_key from extra field
                                                let mut tx_pub_key_hex: Option<String> = None;
                                                if let Some(extra) = tx_parsed
                                                    .get("extra")
                                                    .and_then(|e| e.as_array())
                                                {
                                                    let extra_bytes: Vec<u8> = extra
                                                        .iter()
                                                        .filter_map(|v| v.as_u64().map(|n| n as u8))
                                                        .collect();

                                                    // Look for tag 0x01 (tx_pub_key marker)
                                                    for i in 0..extra_bytes.len() {
                                                        if extra_bytes[i] == 0x01
                                                            && i + 33 <= extra_bytes.len()
                                                        {
                                                            let tx_pub_key_bytes =
                                                                &extra_bytes[i + 1..i + 33];
                                                            tx_pub_key_hex =
                                                                Some(hex::encode(tx_pub_key_bytes));
                                                            // v0.8.2: Store tx_pub_key for PKI derivation
                                                            funding_tx_pubkey =
                                                                tx_pub_key_hex.clone();
                                                            if let Some(ref pk) = tx_pub_key_hex {
                                                                let display_len =
                                                                    std::cmp::min(16, pk.len());
                                                                info!("🔬 [MONITOR-TRACE] Step 10b.1: Found tx_pub_key: {}...",
                                                                &pk[..display_len]);
                                                            }
                                                            break;
                                                        }
                                                    }
                                                }

                                                // Step 10b.2: Extract output keys from vout array
                                                // Supports both old format (target.key) and new tagged_key format (target.tagged_key.key)
                                                let mut output_keys: Vec<String> = Vec::new();
                                                if let Some(vout) =
                                                    tx_parsed.get("vout").and_then(|v| v.as_array())
                                                {
                                                    for vout_entry in vout {
                                                        // Extract target key from each output
                                                        if let Some(target) =
                                                            vout_entry.get("target")
                                                        {
                                                            // Try new tagged_key format first (Monero v0.18+)
                                                            if let Some(tagged_key) =
                                                                target.get("tagged_key")
                                                            {
                                                                if let Some(key) = tagged_key
                                                                    .get("key")
                                                                    .and_then(|k| k.as_str())
                                                                {
                                                                    output_keys
                                                                        .push(key.to_string());
                                                                    continue;
                                                                }
                                                            }
                                                            // Fallback to old format (pre-v0.18)
                                                            if let Some(key) = target
                                                                .get("key")
                                                                .and_then(|k| k.as_str())
                                                            {
                                                                output_keys.push(key.to_string());
                                                            }
                                                        }
                                                    }
                                                    info!("🔬 [MONITOR-TRACE] Step 10b.2: Found {} output keys", output_keys.len());
                                                }

                                                // Step 10b.3: Use automated output detection and mask derivation
                                                if let Some(ref tx_pub_key) = tx_pub_key_hex {
                                                    if !output_keys.is_empty() {
                                                        // Use the new automated function to find our output
                                                        match find_our_output_and_derive_mask(
                                                            &view_key,
                                                            tx_pub_key,
                                                            &multisig_address,
                                                            &output_keys,
                                                            None, // encrypted_amounts not needed for mask
                                                        ) {
                                                            Ok(result) => {
                                                                info!("🔬 [MONITOR-TRACE] Step 10b.3: ✅ Found our output at index {}",
                                                                result.output_index);
                                                                info!("🔬 [MONITOR-TRACE] Step 10b.3: ✅ Mask derived successfully (len={})",
                                                                result.commitment_mask.len());
                                                                funding_mask =
                                                                    Some(result.commitment_mask);
                                                                funding_output_index = Some(
                                                                    result.output_index as i32,
                                                                );
                                                            }
                                                            Err(e) => {
                                                                // BUG 2.18 FIX: Do NOT fallback to index 0 - this causes CLSAG failures
                                                                // If output detection fails, we MUST NOT guess - leave funding_mask = None
                                                                error!("🔬 [MONITOR-TRACE] Step 10b.3: ❌ CRITICAL: Output detection failed: {}", e);
                                                                error!("🔬 [MONITOR-TRACE] Step 10b.3: ❌ Cannot derive funding_mask - escrow will require manual re-funding");
                                                                // Do NOT set funding_mask - leave as None to prevent corrupted escrow
                                                            }
                                                        }
                                                    } else {
                                                        // BUG 2.18 FIX: Do NOT fallback to index 0 when output keys are missing
                                                        // This would guess the wrong output and cause CLSAG signature failures
                                                        error!("🔬 [MONITOR-TRACE] Step 10b.2: ❌ CRITICAL: No output keys found in transaction");
                                                        error!("🔬 [MONITOR-TRACE] Step 10b.2: ❌ Cannot safely derive funding_mask without output verification");
                                                        // Leave funding_mask as None - escrow will not be signable but won't be corrupted
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("🔬 [MONITOR-TRACE] Step 10b: Daemon request failed: {}", e);
                            }
                        }
                    } // Close if let Some(tx_hash)
                } // Close if funding_mask.is_none()

                // Step 10c: Store commitment data in database if found
                // BUG 2.19 FIX: ALL fields must be present - no fallback to 0!
                if let (Some(mask), Some(tx_hash), Some(output_idx), Some(global_idx)) = (
                    &funding_mask,
                    &funding_tx_hash,
                    funding_output_index,
                    funding_global_index,
                ) {
                    info!("🔬 [MONITOR-TRACE] Step 10c: Storing commitment data in DB (output_index={}, global_index={})...",
                        output_idx, global_idx);
                    let escrow_id_str = escrow_id.to_string();
                    let mask_clone = mask.clone();
                    let tx_hash_clone = tx_hash.clone();
                    let global_index = global_idx;
                    let pubkey_clone = funding_output_pubkey.clone();
                    let tx_pubkey_clone = funding_tx_pubkey.clone(); // v0.8.2: For PKI derivation
                    let db_pool = self.db.clone();

                    // v0.8.2: Log tx_pub_key storage
                    if let Some(ref tx_pk) = tx_pubkey_clone {
                        info!(
                            "🔬 [MONITOR-TRACE] Step 10c: Storing tx_pub_key for PKI: {}...",
                            &tx_pk[..16.min(tx_pk.len())]
                        );
                    }

                    match tokio::task::spawn_blocking(move || {
                        let mut conn = db_pool.get().context("Failed to get DB connection")?;
                        Escrow::update_funding_commitment_data(
                            &mut conn,
                            escrow_id_str,
                            &mask_clone,
                            &tx_hash_clone,
                            output_idx, // Now using auto-detected output_index
                            global_index,
                            pubkey_clone.as_deref(), // Output pubkey for auto-PKI
                            tx_pubkey_clone.as_deref(), // v0.8.2: TX pubkey R for PKI derivation
                        )
                    })
                    .await
                    {
                        Ok(Ok(_)) => {
                            info!("🔬 [MONITOR-TRACE] Step 10c: ✅ Commitment data stored (output_index={}, tx_pubkey={})",
                                output_idx,
                                funding_tx_pubkey.as_ref().map(|s| &s[..16.min(s.len())]).unwrap_or("none"));
                        }
                        Ok(Err(e)) => {
                            error!("🔬 [MONITOR-TRACE] Step 10c: ❌ Failed to store commitment data: {}", e);
                        }
                        Err(e) => {
                            error!("🔬 [MONITOR-TRACE] Step 10c: ❌ Task join error: {}", e);
                        }
                    }
                } else {
                    // BUG 2.19: Log which field is missing - helps debug funding detection issues
                    error!(
                        "🔬 [MONITOR-TRACE] Step 10c: ❌ CRITICAL - Missing required funding data!"
                    );
                    error!("🔬 [MONITOR-TRACE] Step 10c: funding_mask={}, funding_tx_hash={}, funding_output_index={:?}, funding_global_index={:?}",
                        funding_mask.is_some(), funding_tx_hash.is_some(), funding_output_index, funding_global_index);
                    error!("🔬 [MONITOR-TRACE] Step 10c: ❌ Escrow will NOT be signable - re-fund required after fix");
                }

                // Step 10d: Update escrow status to "funded" (v0.75.0: renamed from "active")
                // GUARD: Only transition to "funded" from pre-funded states.
                // Never regress shipped/releasing/completed back to funded.
                let pre_funded_states = ["created", "payment_detected", "underfunded"];
                if pre_funded_states.contains(&escrow.status.as_str()) {
                    info!("🔬 [MONITOR-TRACE] Step 10d: Updating escrow status to 'funded'...");
                    match db_update_escrow_status_by_str(&self.db, escrow_id, "funded").await {
                        Ok(_) => {
                            info!("🔬 [MONITOR-TRACE] Step 10d: Escrow status updated to 'funded'");

                            // v0.75.0: Send WebSocket notification for funded status
                            use crate::websocket::WsEvent;
                            self.websocket.do_send(WsEvent::EscrowFunded {
                                escrow_id: escrow_id.to_string(),
                                amount_funded: unlocked_balance,
                                buyer_id: escrow.buyer_id.clone(),
                                vendor_id: escrow.vendor_id.clone(),
                            });
                        }
                        Err(e) => {
                            error!(
                                "🔬 [MONITOR-TRACE] FAILED at Step 10d: DB update error: {}",
                                e
                            );
                            return Err(e.context("Failed to update escrow status to funded"));
                        }
                    }
                } else {
                    info!("🔬 [MONITOR-TRACE] Step 10d: Skipping - escrow already at '{}' (not regressing to funded)", escrow.status);
                }

                // EaaS: No Order table - escrow status is the source of truth
                info!(
                    "🔬 [MONITOR-TRACE] Step 11: Escrow {} funded (EaaS mode)",
                    escrow_id
                );

                // v0.75.0: Clear any failure tracking on success
                self.clear_consecutive_failures(escrow_id);
            }

            return Ok(());
        }

        // CUSTODIAL MODE: Use server-managed wallet with monero-wallet-rpc
        info!(
            "🔍 [CUSTODIAL] Using server-managed wallet for escrow {}",
            escrow_id
        );

        let wallet_filename = format!("buyer_temp_escrow_{}", escrow_id);
        // Use first available wallet-rpc port for the network
        let rpc_ports = get_monitoring_rpc_ports();
        let rpc_url = format!("http://127.0.0.1:{}/json_rpc", rpc_ports[0]);

        let client = reqwest::Client::new();

        // Open custodial wallet
        info!("Opening custodial wallet file: {}", wallet_filename);

        let open_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "open_wallet",
            "params": {
                "filename": wallet_filename
            }
        });

        client
            .post(&rpc_url)
            .json(&open_payload)
            .send()
            .await
            .context("Failed to send open_wallet request")?;

        // Refresh wallet to sync with blockchain
        let refresh_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "refresh"
        });

        client
            .post(&rpc_url)
            .json(&refresh_payload)
            .send()
            .await
            .context("Failed to refresh wallet")?;

        // Get balance
        let balance_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_balance"
        });

        let response = client
            .post(&rpc_url)
            .json(&balance_payload)
            .send()
            .await
            .context("Failed to send get_balance request")?;

        let balance_result: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse balance response")?;

        let total_balance = balance_result["result"]["balance"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing balance in response"))?;

        let unlocked_balance = balance_result["result"]["unlocked_balance"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing unlocked_balance in response"))?;

        info!(
            "Escrow {} wallet balance: total={}, unlocked={}, expected={}",
            escrow_id, total_balance, unlocked_balance, escrow.amount
        );

        // Check if funds have arrived (use unlocked balance for safety)
        if unlocked_balance >= escrow.amount as u64 {
            // GUARD: Only transition to "funded" from pre-funded states
            let pre_funded_states = ["created", "payment_detected", "underfunded"];
            if pre_funded_states.contains(&escrow.status.as_str()) {
                info!(
                    "Escrow {} is now funded! Updating status to 'funded'",
                    escrow_id
                );

                db_update_escrow_status_by_str(&self.db, escrow_id, "funded")
                    .await
                    .context("Failed to update escrow status to funded")?;

                info!("Escrow {} funded (EaaS mode)", escrow_id);
            } else {
                info!(
                    "Escrow {} already at '{}' - not regressing to funded",
                    escrow_id, escrow.status
                );
            }
            // Keep existing post-funded logic below (WebSocket notification etc.)

            // v0.75.0: Notify all parties via WebSocket about escrow funded
            use crate::websocket::WsEvent;
            self.websocket.do_send(WsEvent::EscrowFunded {
                escrow_id: escrow_id.to_string(),
                amount_funded: unlocked_balance,
                buyer_id: escrow.buyer_id.clone(),
                vendor_id: escrow.vendor_id.clone(),
            });

            // === v0.75.0: Create persistent notifications for all 3 parties ===
            let db_pool_notif = self.db.clone();
            let escrow_id_owned = escrow_id.to_string();
            let escrow_link = format!("/escrow/{}", escrow_id_owned);
            let escrow_short = &escrow_id_owned[..8];
            let buyer_id = escrow.buyer_id.clone();
            let vendor_id = escrow.vendor_id.clone();
            let arbiter_id = escrow.arbiter_id.clone();
            let short_id = escrow_short.to_string();
            let link = escrow_link.clone();

            let eid_for_notif = escrow_id_owned.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let mut conn = match db_pool_notif.get() {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(
                            escrow_id = %eid_for_notif,
                            error = %e,
                            "[MONITOR-NOTIF] Failed to get DB connection for escrow funded notifications"
                        );
                        return;
                    }
                };

                tracing::info!(
                    escrow_id = %eid_for_notif,
                    buyer_id = %buyer_id,
                    vendor_id = %vendor_id,
                    arbiter_id = %arbiter_id,
                    "[MONITOR-NOTIF] Creating 'Escrow Funded' notifications for 3 parties"
                );

                // 1. BUYER notification
                let buyer_notif = NewNotification::new(
                    buyer_id.clone(),
                    NotificationType::EscrowUpdate,
                    "Payment Received - Awaiting Shipment".to_string(),
                    format!(
                        "Escrow {} is funded. Vendor will now ship your order.",
                        short_id
                    ),
                    Some(link.clone()),
                    None,
                );
                match Notification::create(buyer_notif, &mut conn) {
                    Ok(_) => {
                        tracing::info!(escrow_id = %eid_for_notif, user_id = %buyer_id, "[MONITOR-NOTIF] ✅ Buyer notification created")
                    }
                    Err(e) => {
                        tracing::error!(escrow_id = %eid_for_notif, user_id = %buyer_id, error = %e, "[MONITOR-NOTIF] ❌ Failed to create buyer notification")
                    }
                }

                // 2. VENDOR notification (IT'S YOUR TURN)
                let vendor_notif = NewNotification::new(
                    vendor_id.clone(),
                    NotificationType::EscrowUpdate,
                    "Payment Received - Ship Now".to_string(),
                    format!(
                        "Escrow {} funded! Ship the order and click 'Confirm Shipped'.",
                        short_id
                    ),
                    Some(link.clone()),
                    None,
                );
                match Notification::create(vendor_notif, &mut conn) {
                    Ok(_) => {
                        tracing::info!(escrow_id = %eid_for_notif, user_id = %vendor_id, "[MONITOR-NOTIF] ✅ Vendor notification created")
                    }
                    Err(e) => {
                        tracing::error!(escrow_id = %eid_for_notif, user_id = %vendor_id, error = %e, "[MONITOR-NOTIF] ❌ Failed to create vendor notification")
                    }
                }

                // 3. ARBITER notification
                let arbiter_notif = NewNotification::new(
                    arbiter_id.clone(),
                    NotificationType::EscrowUpdate,
                    "Escrow Funded - Monitoring".to_string(),
                    format!(
                        "Escrow {} is funded. Monitor for potential disputes.",
                        short_id
                    ),
                    Some(link),
                    None,
                );
                match Notification::create(arbiter_notif, &mut conn) {
                    Ok(_) => {
                        tracing::info!(escrow_id = %eid_for_notif, user_id = %arbiter_id, "[MONITOR-NOTIF] ✅ Arbiter notification created")
                    }
                    Err(e) => {
                        tracing::error!(escrow_id = %eid_for_notif, user_id = %arbiter_id, error = %e, "[MONITOR-NOTIF] ❌ Failed to create arbiter notification")
                    }
                }
            });

            info!("Escrow {} funding complete and parties notified", escrow_id);
        } else {
            info!(
                "Escrow {} still waiting for funds: {}/{} atomic units",
                escrow_id, unlocked_balance, escrow.amount
            );
        }

        Ok(())
    }

    /// Check confirmation status of a transaction
    ///
    /// Monitors transactions in 'releasing' or 'refunding' status to track
    /// blockchain confirmations. When threshold is reached, finalizes the escrow.
    async fn check_transaction_confirmations(&self, escrow_id: &str) -> Result<()> {
        let escrow = db_load_escrow_by_str(&self.db, escrow_id).await?;

        info!(
            "Checking transaction confirmations for escrow {} (status: {})",
            escrow_id, escrow.status
        );

        // Escrow must have a transaction hash (release or refund tx)
        let tx_hash = match &escrow.transaction_hash {
            Some(hash) => hash,
            None => {
                warn!(
                    "Escrow {} in {} status but has no transaction_hash",
                    escrow_id, escrow.status
                );
                return Ok(());
            }
        };

        // Only monitor transactions in releasing or refunding status
        if !matches!(escrow.status.as_str(), "releasing" | "refunding") {
            return Ok(());
        }

        info!(
            "Checking confirmations for transaction {} (escrow {})",
            &tx_hash[..10],
            escrow_id
        );

        // Get buyer wallet ID to query transaction details
        let buyer_wallet_id = escrow
            .buyer_id
            .parse::<Uuid>()
            .context("Failed to parse buyer_id as Uuid")?;

        // Query transaction details from blockchain
        let wallet_manager = self.wallet_manager.lock().await;
        let transfer_info = match wallet_manager
            .get_transfer_by_txid(buyer_wallet_id, tx_hash)
            .await
        {
            Ok(info) => info,
            Err(e) => {
                warn!(
                    "Failed to get transaction details for {}: {}",
                    &tx_hash[..10],
                    e
                );
                return Ok(());
            }
        };
        drop(wallet_manager);

        info!(
            "Transaction {} has {} confirmations (required: {})",
            &tx_hash[..10],
            transfer_info.confirmations,
            self.config.required_confirmations
        );

        // Check if transaction has enough confirmations
        if transfer_info.confirmations >= self.config.required_confirmations {
            // Determine final status based on current status
            let final_status = match escrow.status.as_str() {
                "releasing" => {
                    // Transaction completed successfully → Trigger review invitation
                    self.trigger_review_invitation(escrow_id, tx_hash)
                        .await
                        .context("Failed to trigger review invitation")?;
                    "completed"
                }
                "refunding" => "refunded",
                _ => {
                    warn!(
                        "Unexpected escrow status {} for confirmation check",
                        escrow.status
                    );
                    return Ok(());
                }
            };

            info!(
                "Transaction {} confirmed! Updating escrow {} to status '{}'",
                &tx_hash[..10],
                escrow_id,
                final_status
            );

            // Update escrow to final status
            db_update_escrow_status_by_str(&self.db, escrow_id, final_status)
                .await
                .context("Failed to update escrow to final status")?;

            // Notify all parties via WebSocket
            use crate::websocket::WsEvent;
            self.websocket.do_send(WsEvent::TransactionConfirmed {
                tx_hash: tx_hash.clone(),
                confirmations: transfer_info.confirmations,
            });

            info!(
                "Escrow {} finalized with status '{}' (tx: {})",
                escrow_id,
                final_status,
                &tx_hash[..10]
            );
        }

        Ok(())
    }

    /// Trigger review invitation to buyer after escrow transaction completion
    ///
    /// This method is automatically called when a transaction reaches the required
    /// number of confirmations. It sends a WebSocket notification to the buyer,
    /// inviting them to submit a review for the completed transaction.
    ///
    /// # Arguments
    /// * `escrow_id` - The UUID of the escrow that was completed
    /// * `tx_hash` - The transaction hash on the blockchain
    ///
    /// # Production-Ready Features
    /// - Proper error handling with context
    /// - Secure logging (only first 8 chars of tx_hash)
    /// - UUID parsing validation
    /// - Database access error handling
    async fn trigger_review_invitation(&self, escrow_id: &str, tx_hash: &str) -> Result<()> {
        let escrow = db_load_escrow_by_str(&self.db, escrow_id)
            .await
            .context("Failed to load escrow for review invitation")?;

        // Send WebSocket notification to buyer
        use crate::websocket::WsEvent;
        self.websocket.do_send(WsEvent::ReviewInvitation {
            escrow_id: escrow_id.to_string(),
            tx_hash: tx_hash.to_string(),
            buyer_id: escrow.buyer_id.clone(),
            vendor_id: escrow.vendor_id.clone(),
        });

        info!(
            "Review invitation sent to buyer {} for completed transaction {} (vendor: {})",
            escrow.buyer_id,
            &tx_hash[..8], // Only log first 8 chars for privacy
            escrow.vendor_id
        );

        Ok(())
    }

    /// Get all escrows in 'funded' state
    async fn get_funded_escrows(&self) -> Result<Vec<String>> {
        let mut conn = self.db.get().context("Failed to get DB connection")?;

        let escrow_ids = tokio::task::spawn_blocking(move || {
            use crate::schema::escrows::dsl::*;
            use diesel::prelude::*;

            // Monitor escrows that need blockchain checking:
            // "created" = multisig setup complete, waiting for payment
            // "payment_detected" = TX seen on chain but < 10 confirmations
            // "funded" = payment confirmed (re-check for commitment mask if missing)
            // Also include "shipped"/"releasing" with missing funding_output_pubkey
            // (recovery: re-extract TX data if first extraction failed)
            escrows
                .filter(
                    status
                        .eq("created")
                        .or(status.eq("payment_detected"))
                        .or(status.eq("funded"))
                        .or(status
                            .eq("shipped")
                            .or(status.eq("releasing"))
                            .and(funding_output_pubkey.is_null())),
                )
                .filter(multisig_address.is_not_null())
                .select(id)
                .load::<String>(&mut conn)
        })
        .await
        .context("Task join error")??;

        Ok(escrow_ids)
    }

    /// Get all escrows with pending transactions
    async fn get_pending_transaction_escrows(&self) -> Result<Vec<String>> {
        let mut conn = self.db.get().context("Failed to get DB connection")?;

        let escrow_ids = tokio::task::spawn_blocking(move || {
            use crate::schema::escrows::dsl::*;
            use diesel::prelude::*;

            escrows
                .filter(
                    status
                        .eq("releasing")
                        .or(status.eq("refunding"))
                        .or(status.eq("active")),
                )
                .select(id)
                .load::<String>(&mut conn)
        })
        .await
        .context("Task join error")??;

        Ok(escrow_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_config_default() {
        let config = MonitorConfig::default();
        assert_eq!(config.poll_interval_secs, 30);
        // Post-2025: 15 confirmations recommended after reorg attacks
        assert_eq!(config.required_confirmations, 15);
        assert_eq!(config.max_blocks_per_poll, 100);
    }

    #[test]
    fn test_monitor_config_custom() {
        let config = MonitorConfig {
            poll_interval_secs: 60,
            required_confirmations: 20,
            max_blocks_per_poll: 200,
        };
        assert_eq!(config.poll_interval_secs, 60);
        assert_eq!(config.required_confirmations, 20);
        assert_eq!(config.max_blocks_per_poll, 200);
    }
}
