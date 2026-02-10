//! Non-custodial wallet client for Phase 2 migration
//!
//! This module implements the client-side flow for non-custodial escrow:
//! 1. Client creates local wallet (NOT on server)
//! 2. Client runs local monero-wallet-rpc
//! 3. Client registers RPC URL with server coordinator
//! 4. Client participates in coordinated multisig setup
//! 5. Client finalizes multisig locally (server never touches keys)
//!
//! **Architecture:**
//! ```
//! Client (local wallet-rpc) → Server (coordinator only) ← Other clients
//! ```

use anyhow::{Context, Result};
use monero_marketplace_common::types::MoneroConfig;
use monero_marketplace_wallet::MoneroClient;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info, warn};

// ============================================================================
// REQUEST/RESPONSE TYPES (match server/src/handlers/noncustodial.rs)
// ============================================================================

/// Request to register client wallet with coordinator
#[derive(Debug, Serialize)]
struct RegisterClientWalletRequest {
    pub escrow_id: String,
    pub role: String, // "buyer", "seller", or "arbiter"
    pub rpc_url: String,
}

/// Response from coordinator after registration
#[derive(Debug, Deserialize)]
struct RegisterClientWalletResponse {
    pub success: bool,
    pub message: String,
    pub escrow_id: String,
    pub role: String,
    pub coordination_state: String,
    pub awaiting: Vec<String>,
}

/// Request to coordinate multisig exchange
#[derive(Debug, Serialize)]
struct CoordinateExchangeRequest {
    pub escrow_id: String,
}

/// Response with exchanged multisig infos
#[derive(Debug, Deserialize)]
struct CoordinateExchangeResponse {
    pub success: bool,
    pub message: String,
    pub escrow_id: String,
    pub exchange_result: MultisigExchangeResult,
}

#[derive(Debug, Deserialize)]
struct MultisigExchangeResult {
    pub buyer_receives: Vec<String>,
    pub seller_receives: Vec<String>,
    pub arbiter_receives: Vec<String>,
}

/// Coordination status response
#[derive(Debug, Deserialize)]
struct GetCoordinationStatusResponse {
    pub success: bool,
    pub escrow_id: String,
    pub state: String,
    pub buyer_registered: bool,
    pub seller_registered: bool,
    pub arbiter_registered: bool,
    pub ready_for_exchange: bool,
    pub multisig_result: Option<MultisigExchangeResult>,
}

// ============================================================================
// NON-CUSTODIAL CLIENT
// ============================================================================

/// Non-custodial escrow client
///
/// This client interacts with:
/// - Local monero-wallet-rpc (for actual wallet operations)
/// - Server coordinator API (for multisig info exchange only)
pub struct NonCustodialClient {
    /// Local wallet RPC client
    local_wallet: MoneroClient,
    /// HTTP client for server API calls
    http_client: HttpClient,
    /// Server coordinator URL (e.g., "http://localhost:8080")
    server_url: String,
    /// Client's role in escrow
    role: EscrowRole,
    /// Local RPC URL
    local_rpc_url: String,
}

/// Role in escrow (matches server enum)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowRole {
    Buyer,
    Seller,
    Arbiter,
}

impl EscrowRole {
    pub fn as_str(&self) -> &str {
        match self {
            EscrowRole::Buyer => "buyer",
            EscrowRole::Seller => "seller",
            EscrowRole::Arbiter => "arbiter",
        }
    }
}

impl std::fmt::Display for EscrowRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl NonCustodialClient {
    /// Create new non-custodial client
    ///
    /// **Parameters:**
    /// - `local_rpc_url`: Local monero-wallet-rpc URL (e.g., "http://127.0.0.1:18083")
    /// - `server_url`: Server coordinator URL (e.g., "http://localhost:8080")
    /// - `role`: Client's role in escrow
    pub fn new(local_rpc_url: String, server_url: String, role: EscrowRole) -> Result<Self> {
        let config = MoneroConfig {
            rpc_url: local_rpc_url.clone(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 120, // Increased from 30 to handle slow wallet operations
        };

        let local_wallet =
            MoneroClient::new(config).context("Failed to create local wallet client")?;

        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            local_wallet,
            http_client,
            server_url,
            role,
            local_rpc_url,
        })
    }

    /// Initialize non-custodial escrow flow
    ///
    /// **Flow:**
    /// 1. Create local wallet (if not exists)
    /// 2. Prepare multisig locally
    /// 3. Register with server coordinator
    /// 4. Wait for other participants
    /// 5. Coordinate multisig info exchange
    /// 6. Finalize multisig locally
    ///
    /// **Returns:** Multisig address
    pub async fn init_escrow(&self, escrow_id: &str, wallet_name: &str) -> Result<String> {
        info!(
            "🔐 Starting non-custodial escrow initialization for {}",
            self.role.as_str()
        );
        info!("Escrow ID: {}", escrow_id);
        info!("Local wallet: {}", wallet_name);

        // Step 1: Create local wallet
        self.create_local_wallet(wallet_name).await?;

        // Step 2: Prepare multisig locally
        info!("📝 Preparing multisig locally...");
        let prepare_result = self
            .local_wallet
            .multisig()
            .prepare_multisig()
            .await
            .context("Failed to prepare multisig")?;

        info!("✅ Local multisig prepared");
        info!(
            "Multisig info length: {} chars",
            prepare_result.multisig_info.len()
        );

        // Step 3: Register with server coordinator
        info!("📡 Registering with server coordinator...");
        self.register_with_coordinator(escrow_id).await?;

        // Step 4: Wait for other participants
        info!("⏳ Waiting for other participants to register...");
        self.wait_for_all_participants(escrow_id).await?;

        // Step 5: Coordinate multisig exchange (buyer) OR wait for result (seller/arbiter)
        let infos_to_use = if self.role == EscrowRole::Buyer {
            info!("🔄 Buyer: Coordinating multisig info exchange...");
            self.coordinate_exchange(escrow_id).await?
        } else {
            info!(
                "⏳ {}: Waiting for buyer to coordinate multisig exchange...",
                self.role
            );
            self.wait_for_multisig_result(escrow_id).await?
        };

        info!("✅ Received {} multisig infos", infos_to_use.len());

        // Step 6: Finalize multisig locally
        info!("🔧 Finalizing multisig locally (make_multisig with threshold=2)...");
        let make_result = self
            .local_wallet
            .multisig()
            .make_multisig(2, infos_to_use)
            .await
            .context("Failed to make multisig")?;

        info!("✅ Multisig wallet created (Round 1 complete)");
        info!("Multisig address: {}", make_result.address);
        info!(
            "Multisig info length: {} chars",
            make_result.multisig_info.len()
        );

        // Step 7: Exchange multisig keys ROUND 1 (2-of-3 requires TWO rounds!)
        info!("🔑 Exchange multisig keys - ROUND 1...");
        let others_keys_r1 = self
            .coordinate_key_exchange(escrow_id, &make_result.multisig_info)
            .await?;

        info!("📥 Received {} keys for round 1", others_keys_r1.len());

        let exchange_result_r1 = self
            .local_wallet
            .multisig()
            .exchange_multisig_keys(others_keys_r1)
            .await
            .context("Failed to exchange_multisig_keys (Round 1)")?;

        info!(
            "✅ Round 1 complete! Multisig info: {} chars",
            exchange_result_r1.multisig_info.len()
        );

        // Step 8: Exchange multisig keys ROUND 2 (CRITICAL - makes wallet READY)
        info!("🔑 Exchange multisig keys - ROUND 2 (finalizing)...");

        // Use coordinate_sync_round with round=1 for the second exchange_multisig_keys
        let round2_infos = self
            .coordinate_sync_round(escrow_id, 1, &exchange_result_r1.multisig_info)
            .await
            .context("Failed to coordinate round 2 exchange")?;

        info!("📥 Received {} keys for round 2", round2_infos.len());

        let exchange_result_r2 = self
            .local_wallet
            .multisig()
            .exchange_multisig_keys(round2_infos)
            .await
            .context("Failed to exchange_multisig_keys (Round 2)")?;

        info!("✅ Round 2 complete! Wallet should now be READY");
        info!("Final multisig address: {}", exchange_result_r2.address);

        // Verify wallet is now READY (not just in multisig mode)
        let is_multisig = self
            .local_wallet
            .multisig()
            .is_multisig()
            .await
            .context("Failed to check multisig status")?;

        if !is_multisig {
            return Err(anyhow::anyhow!(
                "Wallet not in multisig mode after 2 rounds of exchange_multisig_keys!"
            ));
        }

        info!("✅ Confirmed wallet is in multisig mode and ready for transactions");

        // Step 8: Complete multisig synchronization (2 rounds of export/import)
        info!("🔄 Starting multisig synchronization (2 rounds required)...");
        self.complete_multisig_sync(escrow_id)
            .await
            .context("Failed to complete multisig synchronization")?;

        info!("✅ Multisig fully synchronized and READY for transactions!");

        // Step 8: Start monitoring blockchain for incoming funds
        info!("👁️  Starting blockchain monitoring...");
        info!("Waiting for funds to arrive at: {}", make_result.address);

        // Launch monitoring in background (non-blocking)
        // Create new MoneroClient instance for monitoring (MoneroClient doesn't implement Clone)
        let monitor_config = MoneroConfig {
            rpc_url: self.local_rpc_url.clone(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 30,
        };
        let monitor_client =
            MoneroClient::new(monitor_config).context("Failed to create monitoring client")?;
        let monitor_address = make_result.address.clone();
        let monitor_server_url = self.server_url.clone();
        let monitor_escrow_id = escrow_id.to_string();

        tokio::spawn(async move {
            if let Err(e) = Self::monitor_blockchain_static(
                monitor_client,
                &monitor_address,
                &monitor_server_url,
                &monitor_escrow_id,
            )
            .await
            {
                error!("Blockchain monitoring failed: {}", e);
            }
        });

        info!("ℹ️  Next steps:");
        info!(
            "  1. Buyer sends XMR to multisig address: {}",
            make_result.address
        );
        info!("  2. System will detect funds automatically");
        info!("  3. Escrow status will update to 'funded'");

        Ok(make_result.address)
    }

    /// Coordinate multisig key exchange (Round 2 after make_multisig)
    ///
    /// **Critical:** This step finalizes the 2-of-3 multisig wallet setup.
    /// After make_multisig(), each wallet has a multisig_info string that needs
    /// to be exchanged via exchange_multisig_keys() before the wallet can export/import.
    ///
    /// Uses sync-round endpoint with round=0 for key exchange.
    async fn coordinate_key_exchange(
        &self,
        escrow_id: &str,
        our_multisig_info: &str,
    ) -> Result<Vec<String>> {
        info!("🔄 Coordinating key exchange (using sync-round with round=0)...");

        self.coordinate_sync_round(escrow_id, 0, our_multisig_info)
            .await
    }

    /// Complete multisig synchronization (2 rounds of export/import)
    ///
    /// **Critical:** This MUST be done AFTER exchange_multisig_keys() finalizes the wallet.
    /// Monero multisig requires 2 rounds of export/import to fully synchronize wallet state.
    async fn complete_multisig_sync(&self, escrow_id: &str) -> Result<()> {
        info!("🔄 Round 1: Export/Import multisig info...");

        // Round 1: Export
        let export_round1 = self
            .local_wallet
            .multisig()
            .export_multisig_info()
            .await
            .context("Failed to export multisig info (round 1)")?;

        info!("📤 Round 1 export: {} chars", export_round1.info.len());

        // Coordinate round 1 with server (using round=2 to avoid collision with exchange_multisig_keys round=1)
        let others_round1 = self
            .coordinate_sync_round(escrow_id, 2, &export_round1.info)
            .await?;

        info!(
            "📥 Received {} infos from other participants (round 1)",
            others_round1.len()
        );

        // Round 1: Import
        let import_result1 = self
            .local_wallet
            .multisig()
            .import_multisig_info(others_round1)
            .await
            .context("Failed to import multisig info (round 1)")?;

        info!(
            "✅ Multisig sync complete: {} outputs processed",
            import_result1.n_outputs
        );

        Ok(())
    }

    /// Coordinate a sync round with the server
    ///
    /// Sends our export info to server and receives exports from other participants
    async fn coordinate_sync_round(
        &self,
        escrow_id: &str,
        round: u8,
        our_export: &str,
    ) -> Result<Vec<String>> {
        let url = format!("{}/api/v2/escrow/sync-round", self.server_url);

        #[derive(serde::Serialize)]
        struct SyncRoundRequest {
            escrow_id: String,
            round: u8,
            role: String,
            export_info: String,
        }

        #[derive(serde::Deserialize)]
        struct SyncRoundResponse {
            success: bool,
            received_infos: Vec<String>,
        }

        let request = SyncRoundRequest {
            escrow_id: escrow_id.to_string(),
            round,
            role: self.role.as_str().to_string(),
            export_info: our_export.to_string(),
        };

        // Retry logic with exponential backoff (wait for other participants)
        let max_attempts = 60; // 60 attempts * 2s = 2 minutes max
        let mut attempts = 0;

        loop {
            attempts += 1;
            if attempts > max_attempts {
                return Err(anyhow::anyhow!(
                    "Timeout waiting for sync round {} participants after {} attempts",
                    round,
                    max_attempts
                ));
            }

            let response = self
                .http_client
                .post(&url)
                .json(&request)
                .send()
                .await
                .context("Failed to send sync round request")?;

            if !response.status().is_success() {
                warn!(
                    "Sync round {} not ready yet (attempt {}), retrying...",
                    round, attempts
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            let sync_response: SyncRoundResponse = response
                .json()
                .await
                .context("Failed to parse sync round response")?;

            if !sync_response.success {
                warn!(
                    "Sync round {} not ready (attempt {}), retrying...",
                    round, attempts
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            // We should receive exactly 2 infos (from the other 2 participants)
            if sync_response.received_infos.len() != 2 {
                warn!(
                    "Sync round {} incomplete: expected 2 infos, got {} (attempt {}), retrying...",
                    round,
                    sync_response.received_infos.len(),
                    attempts
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            info!("✅ Sync round {} coordination complete", round);
            return Ok(sync_response.received_infos);
        }
    }

    /// Monitor blockchain for incoming funds (static method for spawn)
    async fn monitor_blockchain_static(
        wallet: MoneroClient,
        address: &str,
        server_url: &str,
        escrow_id: &str,
    ) -> Result<()> {
        info!(
            "👁️  Monitoring blockchain for address: {}...",
            &address[..15]
        );

        let mut last_balance: u64 = 0;
        let check_interval = Duration::from_secs(30); // Check every 30 seconds

        loop {
            // Get current balance (returns tuple: (balance, unlocked_balance))
            match wallet.rpc().get_balance().await {
                Ok((balance, _unlocked_balance)) => {
                    if balance > last_balance {
                        let amount_xmr = balance as f64 / 1e12;
                        info!("🎉 FUNDS RECEIVED! Balance: {} XMR", amount_xmr);

                        // Notify server that funds were received
                        if let Err(e) =
                            Self::notify_funds_received_static(server_url, escrow_id, balance).await
                        {
                            error!("Failed to notify server of funds: {}", e);
                        }

                        last_balance = balance;

                        // Continue monitoring for additional deposits
                    } else if balance > 0 && last_balance == 0 {
                        // First detection of non-zero balance
                        let amount_xmr = balance as f64 / 1e12;
                        info!("💰 Current balance: {} XMR", amount_xmr);
                        last_balance = balance;
                    }
                }
                Err(e) => {
                    warn!("Failed to check balance: {}", e);
                }
            }

            tokio::time::sleep(check_interval).await;
        }
    }

    /// Notify server that funds were received (static method)
    async fn notify_funds_received_static(
        server_url: &str,
        escrow_id: &str,
        balance: u64,
    ) -> Result<()> {
        let url = format!("{}/api/v2/escrow/funds-received", server_url);

        #[derive(serde::Serialize)]
        struct FundsReceivedRequest {
            escrow_id: String,
            balance: u64,
        }

        let client = HttpClient::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let request = FundsReceivedRequest {
            escrow_id: escrow_id.to_string(),
            balance,
        };

        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send funds notification")?;

        if response.status().is_success() {
            info!("✅ Server notified of funds received");
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow::anyhow!(
                "Server notification failed: {}",
                error_text
            ))
        }
    }

    /// Create local wallet (skip if exists)
    ///
    /// **Performance Optimization:** Uses restore_height to skip blockchain scanning.
    /// Fresh wallets created with current blockchain height scan <5 seconds instead of 30+ seconds.
    async fn create_local_wallet(&self, wallet_name: &str) -> Result<()> {
        info!("📁 Creating local wallet '{}'...", wallet_name);

        // CRITICAL OPTIMIZATION: Get current blockchain height to skip historical scanning
        // This reduces wallet creation from 30+ seconds (full scan) to <5 seconds
        let restore_height = match self.local_wallet.rpc().get_block_height().await {
            Ok(height) => {
                info!("🔍 Current blockchain height: {}", height);
                Some(height)
            }
            Err(e) => {
                warn!("⚠️  Could not get blockchain height: {}. Wallet will scan from genesis (slow!)", e);
                None
            }
        };

        // Try to create wallet (will fail if exists, which is ok)
        match self.local_wallet.rpc().create_wallet(wallet_name, "").await {
            Ok(_) => {
                info!("✅ Wallet '{}' created", wallet_name);
                // CRITICAL: Open the wallet immediately after creation
                // The RPC daemon keeps wallets in memory - create_wallet() only creates the file,
                // we must call open_wallet() to make it the active wallet
                self.local_wallet
                    .rpc()
                    .open_wallet(wallet_name, "")
                    .await
                    .context("Failed to open newly created wallet")?;
                info!("✅ Wallet '{}' opened and ready", wallet_name);
                Ok(())
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("already exists")
                    || error_msg.contains("Cannot create wallet")
                    || error_msg.contains("EOF while parsing")
                {
                    warn!(
                        "Wallet '{}' already exists, attempting to open it",
                        wallet_name
                    );
                    // If wallet exists, try to open it
                    self.local_wallet
                        .rpc()
                        .open_wallet(wallet_name, "")
                        .await
                        .context("Failed to open existing wallet")?;
                    info!("✅ Wallet '{}' opened", wallet_name);
                    Ok(())
                } else {
                    Err(e).context("Failed to create wallet")
                }
            }
        }
    }

    /// Register local wallet RPC URL with server coordinator
    async fn register_with_coordinator(&self, escrow_id: &str) -> Result<()> {
        let url = format!("{}/api/v2/escrow/register-wallet", self.server_url);

        let request = RegisterClientWalletRequest {
            escrow_id: escrow_id.to_string(),
            role: self.role.as_str().to_string(),
            rpc_url: self.local_rpc_url.clone(),
        };

        let response = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send registration request")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow::anyhow!("Registration failed: {}", error_text));
        }

        let reg_response: RegisterClientWalletResponse = response
            .json()
            .await
            .context("Failed to parse registration response")?;

        if !reg_response.success {
            return Err(anyhow::anyhow!(
                "Registration failed: {}",
                reg_response.message
            ));
        }

        info!(
            "✅ Registered as {} for escrow {}",
            self.role.as_str(),
            escrow_id
        );
        info!("State: {}", reg_response.coordination_state);
        if !reg_response.awaiting.is_empty() {
            info!("Waiting for: {:?}", reg_response.awaiting);
        }

        Ok(())
    }

    /// Wait for all participants to register
    async fn wait_for_all_participants(&self, escrow_id: &str) -> Result<()> {
        let url = format!(
            "{}/api/v2/escrow/coordination-status/{}",
            self.server_url, escrow_id
        );
        let max_attempts = 60; // 60 attempts * 2s = 2 minutes max
        let mut attempts = 0;

        loop {
            attempts += 1;
            if attempts > max_attempts {
                return Err(anyhow::anyhow!(
                    "Timeout waiting for participants after {} attempts",
                    max_attempts
                ));
            }

            let response = self
                .http_client
                .get(&url)
                .send()
                .await
                .context("Failed to get coordination status")?;

            if !response.status().is_success() {
                warn!("Status check failed (attempt {}), retrying...", attempts);
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            let status: GetCoordinationStatusResponse = response
                .json()
                .await
                .context("Failed to parse status response")?;

            if status.buyer_registered && status.seller_registered && status.arbiter_registered {
                info!("✅ All participants registered!");
                return Ok(());
            }

            let missing: Vec<&str> = vec![
                (!status.buyer_registered).then_some("buyer"),
                (!status.seller_registered).then_some("seller"),
                (!status.arbiter_registered).then_some("arbiter"),
            ]
            .into_iter()
            .flatten()
            .collect();

            info!(
                "Waiting for participants: {:?} (attempt {}/{})",
                missing, attempts, max_attempts
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Wait for multisig coordination result (for seller/arbiter polling)
    async fn wait_for_multisig_result(&self, escrow_id: &str) -> Result<Vec<String>> {
        let url = format!(
            "{}/api/v2/escrow/coordination-status/{}",
            self.server_url, escrow_id
        );
        let max_attempts = 60; // 60 attempts * 2s = 2 minutes max

        for attempt in 1..=max_attempts {
            let response = self
                .http_client
                .get(&url)
                .send()
                .await
                .context("Failed to get coordination status")?;

            if !response.status().is_success() {
                warn!("Status check failed (attempt {}), retrying...", attempt);
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            let status: GetCoordinationStatusResponse = response
                .json()
                .await
                .context("Failed to parse status response")?;

            if let Some(multisig_result) = status.multisig_result {
                // Extract the correct Vec for this role
                let infos = match self.role.as_str() {
                    "buyer" => multisig_result.buyer_receives,
                    "seller" => multisig_result.seller_receives,
                    "arbiter" => multisig_result.arbiter_receives,
                    _ => return Err(anyhow::anyhow!("Invalid role: {}", self.role)),
                };

                info!(
                    "✅ Received multisig infos from server ({} infos)",
                    infos.len()
                );
                return Ok(infos);
            }

            info!(
                "⏳ Waiting for multisig coordination... (attempt {}/{})",
                attempt, max_attempts
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for multisig coordination after {} attempts",
            max_attempts
        ))
    }

    /// Coordinate multisig info exchange through server
    ///
    /// Server will:
    /// 1. Call prepare_multisig on all 3 wallets
    /// 2. Collect all multisig_info strings
    /// 3. Return the appropriate infos for this role
    async fn coordinate_exchange(&self, escrow_id: &str) -> Result<Vec<String>> {
        let url = format!("{}/api/v2/escrow/coordinate-exchange", self.server_url);

        let request = CoordinateExchangeRequest {
            escrow_id: escrow_id.to_string(),
        };

        let response = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send coordinate request")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow::anyhow!("Coordination failed: {}", error_text));
        }

        let coord_response: CoordinateExchangeResponse = response
            .json()
            .await
            .context("Failed to parse coordination response")?;

        if !coord_response.success {
            return Err(anyhow::anyhow!(
                "Coordination failed: {}",
                coord_response.message
            ));
        }

        // Extract the multisig infos for our role
        let infos = match self.role {
            EscrowRole::Buyer => coord_response.exchange_result.buyer_receives,
            EscrowRole::Seller => coord_response.exchange_result.seller_receives,
            EscrowRole::Arbiter => coord_response.exchange_result.arbiter_receives,
        };

        info!("✅ Coordination successful");
        info!(
            "Received {} multisig infos from other participants",
            infos.len()
        );

        if infos.len() != 2 {
            error!("❌ Expected 2 multisig infos but got {}", infos.len());
            return Err(anyhow::anyhow!(
                "Invalid number of multisig infos: expected 2, got {}",
                infos.len()
            ));
        }

        Ok(infos)
    }

    /// Get local wallet info for debugging
    pub async fn get_wallet_info(&self) -> Result<()> {
        info!("Getting local wallet information...");

        let wallet_info = self.local_wallet.get_wallet_info().await?;

        info!("📊 Wallet Information:");
        info!("  Multisig: {}", wallet_info.is_multisig);
        if let Some(threshold) = wallet_info.multisig_threshold {
            if let Some(total) = wallet_info.multisig_total {
                info!("  Threshold: {}/{}", threshold, total);
            }
        }
        info!("  Balance: {} XMR", wallet_info.balance as f64 / 1e12);
        info!("  Block Height: {}", wallet_info.block_height);

        Ok(())
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Parse role string to EscrowRole enum
pub fn parse_role(role_str: &str) -> Result<EscrowRole> {
    match role_str.to_lowercase().as_str() {
        "buyer" => Ok(EscrowRole::Buyer),
        "seller" => Ok(EscrowRole::Seller),
        "arbiter" => Ok(EscrowRole::Arbiter),
        _ => Err(anyhow::anyhow!(
            "Invalid role: must be 'buyer', 'seller', or 'arbiter'"
        )),
    }
}
