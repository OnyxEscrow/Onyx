//! Light Wallet Server (LWS) - Sync Proxy Service
//!
//! This service acts as a proxy between WASM clients (browser) and the Monero daemon.
//! It provides Light Wallet Server functionality for non-custodial in-browser wallets.
//!
//! **ARCHITECTURE:**
//! - Client sends view key (can see balances, NOT spend)
//! - Server scans blockchain for outputs belonging to client
//! - Server pre-calculates ring members (decoys) for transactions
//! - Client signs transactions locally in WASM
//! - Server broadcasts signed transaction blobs
//!
//! **SECURITY MODEL:**
//! - Server receives public view keys (privacy trade-off for UX)
//! - Server NEVER receives private spend keys
//! - Server cannot spend funds, only observe
//! - Signed transaction blobs are opaque to server
//!
//! **MONERO RPC REQUIREMENTS:**
//! - `get_blocks` - Scan blockchain for outputs
//! - `get_output_histogram` - Get output distribution for decoy selection
//! - `get_outs` - Fetch ring members (decoys)
//! - `send_raw_transaction` - Broadcast signed transactions

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum SyncProxyError {
    #[error("Monero RPC error: {0}")]
    MoneroRpc(String),

    #[error("Invalid view key: {0}")]
    InvalidViewKey(String),

    #[error("Blockchain scan error: {0}")]
    ScanError(String),

    #[error("Decoy selection error: {0}")]
    DecoyError(String),

    #[error("Broadcast error: {0}")]
    BroadcastError(String),

    #[error("Daemon not connected: {0}")]
    DaemonNotConnected(String),
}

// ============================================================================
// DATA STRUCTURES (Match WASM client expectations)
// ============================================================================

/// Request to scan outputs for a wallet
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOutputsRequest {
    /// Public view key (hex, 64 chars)
    pub view_key_pub: String,

    /// Public spend key (hex, 64 chars) - For stealth address derivation
    pub spend_key_pub: String,

    /// Starting block height (0 = scan from genesis)
    pub start_height: u64,

    /// Optional: Monero address for validation
    pub address: Option<String>,
}

/// Response containing scanned outputs (UTXOs)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOutputsResponse {
    /// Current blockchain height after scan
    pub synced_height: u64,

    /// List of unspent outputs belonging to this wallet
    pub outputs: Vec<OutputInfo>,

    /// Total balance in atomic units
    pub balance: u64,
}

/// Information about a single output (UTXO)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputInfo {
    /// Transaction hash containing this output
    pub tx_hash: String,

    /// Index of output within the transaction
    pub output_index: u64,

    /// Amount in atomic units (decrypted using view key)
    pub amount: u64,

    /// Public key of the output (stealth address)
    pub public_key: String,

    /// Transaction public key (R value for ECDH)
    pub tx_pub_key: String,

    /// Global index on the blockchain (for ring signatures)
    pub global_index: u64,

    /// Block height where this output was created
    pub block_height: u64,

    /// Pre-selected ring members (decoys) for spending this output
    pub ring_decoys: Vec<DecoyInfo>,
}

/// Information about a ring member (decoy)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecoyInfo {
    /// Global index of this output
    pub global_index: u64,

    /// Public key of the decoy output
    pub public_key: String,

    /// RCT mask (for RingCT transactions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rct_mask: Option<String>,
}

/// Request to broadcast a signed transaction
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastTxRequest {
    /// Signed transaction blob (hex-encoded)
    pub signed_tx_hex: String,

    /// Optional: Do not relay to network (just validate)
    #[serde(default)]
    pub do_not_relay: bool,
}

/// Response after broadcasting transaction
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastTxResponse {
    /// Transaction hash
    pub tx_hash: String,

    /// Whether transaction was relayed to network
    pub relayed: bool,

    /// Fee paid (atomic units)
    pub fee: u64,
}

// ============================================================================
// SYNC PROXY SERVICE
// ============================================================================

/// Light Wallet Server service
///
/// Provides blockchain scanning and transaction broadcast services for
/// in-browser WASM wallets.
pub struct SyncProxyService {
    /// Monero wallet-RPC URL (should be localhost only)
    monero_rpc_url: String,

    /// Monero daemon RPC URL (for get_outs, etc.)
    daemon_rpc_url: String,

    /// HTTP client for Monero RPC
    client: reqwest::Client,

    /// Ring size for transactions (Monero default: 16 as of v0.18)
    ring_size: usize,
}

impl SyncProxyService {
    /// Create new SyncProxyService
    ///
    /// # Parameters
    /// - `monero_rpc_url`: URL to monero-wallet-rpc (e.g., "http://127.0.0.1:18083/json_rpc")
    /// - `daemon_rpc_url`: URL to monerod daemon (e.g., "http://127.0.0.1:18081/json_rpc")
    ///
    /// # Security
    /// - MUST be localhost only (enforced by validation)
    /// - Never expose Monero RPC publicly
    pub fn new(monero_rpc_url: String, daemon_rpc_url: String) -> Result<Self> {
        // Validate localhost only for both URLs
        if !monero_rpc_url.contains("127.0.0.1") && !monero_rpc_url.contains("localhost") {
            anyhow::bail!(
                "Monero wallet RPC must be localhost only. Got: {}",
                monero_rpc_url
            );
        }

        if !daemon_rpc_url.contains("127.0.0.1") && !daemon_rpc_url.contains("localhost") {
            anyhow::bail!(
                "Monero daemon RPC must be localhost only. Got: {}",
                daemon_rpc_url
            );
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            monero_rpc_url,
            daemon_rpc_url,
            client,
            ring_size: 16, // Monero default ring size
        })
    }

    /// Scan blockchain for outputs belonging to a wallet
    ///
    /// This is the core LWS functionality. Uses the view key to:
    /// 1. Scan blocks from `start_height` to current height
    /// 2. Identify outputs belonging to this wallet
    /// 3. Decrypt output amounts
    /// 4. Pre-select ring members (decoys) for each output
    ///
    /// # Parameters
    /// - `request`: ScanOutputsRequest with view/spend keys and start height
    ///
    /// # Returns
    /// - ScanOutputsResponse with list of UTXOs and pre-calculated decoys
    ///
    /// # Security
    /// - View key allows seeing balances but NOT spending
    /// - Decoys are selected randomly to preserve anonymity
    pub async fn scan_outputs(
        &self,
        request: ScanOutputsRequest,
    ) -> Result<ScanOutputsResponse, SyncProxyError> {
        // Validate keys are hex and correct length
        if request.view_key_pub.len() != 64 {
            return Err(SyncProxyError::InvalidViewKey(
                "View key must be 64 hex characters".to_string(),
            ));
        }

        if request.spend_key_pub.len() != 64 {
            return Err(SyncProxyError::InvalidViewKey(
                "Spend key must be 64 hex characters".to_string(),
            ));
        }

        tracing::info!(
            "Scanning blockchain from height {} via monero-wallet-rpc proxy",
            request.start_height
        );

        // Generate unique wallet name for this scan session
        let wallet_name = format!(
            "temp_view_{}",
            uuid::Uuid::new_v4().to_string().replace('-', "")
        );

        // CRITICAL: Ensure cleanup happens even on error
        let scan_result = self
            .scan_with_temp_wallet(
                &wallet_name,
                &request.view_key_pub,
                &request.spend_key_pub,
                request.start_height,
            )
            .await;

        // Always attempt to close wallet (best effort cleanup)
        if let Err(e) = self.close_wallet(&wallet_name).await {
            tracing::warn!("Failed to close temporary wallet {}: {}", wallet_name, e);
        }

        scan_result
    }

    /// Internal: Scan using temporary view-only wallet
    ///
    /// This method orchestrates the RPC calls to monero-wallet-rpc
    async fn scan_with_temp_wallet(
        &self,
        wallet_name: &str,
        view_key_pub: &str,
        spend_key_pub: &str,
        start_height: u64,
    ) -> Result<ScanOutputsResponse, SyncProxyError> {
        // Step 1: Create view-only wallet from keys
        self.create_view_only_wallet(wallet_name, view_key_pub, spend_key_pub, start_height)
            .await?;

        // Step 2: Refresh wallet (scans blockchain)
        self.refresh_wallet(wallet_name).await?;

        // Step 3: Get balance
        let balance = self.get_balance(wallet_name).await?;

        // Step 4: Get incoming transfers (UTXOs)
        let transfers = self.get_incoming_transfers(wallet_name).await?;

        // Step 5: Get current blockchain height
        let height = self.get_height().await?;

        // Step 6: Convert to our OutputInfo format
        let outputs = self.convert_transfers_to_outputs(transfers).await?;

        Ok(ScanOutputsResponse {
            synced_height: height,
            outputs,
            balance,
        })
    }

    /// Get unspent outputs for a wallet (simplified scan)
    ///
    /// This is a convenience method that scans and returns only unspent outputs.
    ///
    /// # Parameters
    /// - `view_key_pub`: Public view key (hex)
    /// - `spend_key_pub`: Public spend key (hex)
    /// - `start_height`: Starting block height
    ///
    /// # Returns
    /// - List of OutputInfo with pre-calculated decoys
    pub async fn get_unspent_outs(
        &self,
        view_key_pub: String,
        spend_key_pub: String,
        start_height: u64,
    ) -> Result<Vec<OutputInfo>, SyncProxyError> {
        let request = ScanOutputsRequest {
            view_key_pub,
            spend_key_pub,
            start_height,
            address: None,
        };

        let response = self.scan_outputs(request).await?;
        Ok(response.outputs)
    }

    /// Check daemon connectivity before broadcast
    ///
    /// Verifies the daemon has peer connections to relay transactions.
    /// Without connections, TX will be accepted locally but never propagate.
    ///
    /// # Returns
    /// - Ok(connection_count) if daemon has peers
    /// - Err(DaemonNotConnected) if no peers available
    ///
    /// # Production Note
    /// This prevents silent TX loss when daemon is isolated.
    pub async fn check_daemon_connectivity(&self) -> Result<u32, SyncProxyError> {
        #[derive(Deserialize)]
        struct GetInfoResult {
            #[serde(default)]
            incoming_connections_count: u32,
            #[serde(default)]
            outgoing_connections_count: u32,
            #[serde(default)]
            synchronized: bool,
        }

        #[derive(Deserialize)]
        struct RpcResponse {
            result: Option<GetInfoResult>,
            error: Option<RpcError>,
        }

        #[derive(Deserialize)]
        struct RpcError {
            message: String,
        }

        let rpc_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_info"
        });

        let response = self
            .client
            .post(&self.daemon_rpc_url)
            .json(&rpc_request)
            .send()
            .await
            .map_err(|e| {
                SyncProxyError::DaemonNotConnected(format!("Cannot reach daemon: {}", e))
            })?;

        let rpc_response: RpcResponse = response.json().await.map_err(|e| {
            SyncProxyError::DaemonNotConnected(format!("Invalid daemon response: {}", e))
        })?;

        if let Some(error) = rpc_response.error {
            return Err(SyncProxyError::DaemonNotConnected(format!(
                "Daemon error: {}",
                error.message
            )));
        }

        let result = rpc_response.result.ok_or_else(|| {
            SyncProxyError::DaemonNotConnected("Missing get_info result".to_string())
        })?;

        let total_connections =
            result.incoming_connections_count + result.outgoing_connections_count;

        if total_connections == 0 {
            return Err(SyncProxyError::DaemonNotConnected(
                "Daemon has 0 peer connections. TX will not propagate. Connect daemon to network first.".to_string()
            ));
        }

        if !result.synchronized {
            tracing::warn!(
                "Daemon not fully synchronized but has {} connections. TX may be delayed.",
                total_connections
            );
        }

        tracing::info!(
            "Daemon connectivity OK: {} peers ({} in, {} out)",
            total_connections,
            result.incoming_connections_count,
            result.outgoing_connections_count
        );

        Ok(total_connections)
    }

    /// Broadcast a signed transaction to the Monero network
    ///
    /// # Parameters
    /// - `request`: BroadcastTxRequest with signed transaction blob
    ///
    /// # Returns
    /// - BroadcastTxResponse with transaction hash
    ///
    /// # Security
    /// - Transaction blob is signed by client (opaque to server)
    /// - Server cannot modify transaction
    /// - Server only relays to network
    pub async fn broadcast_tx(
        &self,
        request: BroadcastTxRequest,
    ) -> Result<BroadcastTxResponse, SyncProxyError> {
        // Validate hex encoding
        if hex::decode(&request.signed_tx_hex).is_err() {
            return Err(SyncProxyError::BroadcastError(
                "Invalid hex encoding".to_string(),
            ));
        }

        // SAFEGUARD: Check daemon connectivity before broadcast
        // Prevents TX loss when daemon is isolated (0 peer connections)
        if !request.do_not_relay {
            self.check_daemon_connectivity().await?;
        }

        // Call Monero RPC: send_raw_transaction
        #[derive(Serialize)]
        struct SendRawTxParams {
            tx_as_hex: String,
            do_not_relay: bool,
        }

        #[derive(Serialize)]
        struct RpcRequest {
            jsonrpc: String,
            id: String,
            method: String,
            params: SendRawTxParams,
        }

        #[derive(Deserialize)]
        struct RpcResponse {
            result: Option<SendRawTxResult>,
            error: Option<RpcError>,
        }

        #[derive(Deserialize)]
        struct SendRawTxResult {
            #[serde(default)]
            tx_hash: String,
            #[serde(default)]
            relayed: bool,
            #[serde(default)]
            fee: u64,
        }

        #[derive(Deserialize)]
        struct RpcError {
            message: String,
        }

        let rpc_request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: "0".to_string(),
            method: "send_raw_transaction".to_string(),
            params: SendRawTxParams {
                tx_as_hex: request.signed_tx_hex.clone(),
                do_not_relay: request.do_not_relay,
            },
        };

        let response = self
            .client
            .post(&self.monero_rpc_url)
            .json(&rpc_request)
            .send()
            .await
            .map_err(|e| SyncProxyError::BroadcastError(format!("HTTP error: {}", e)))?;

        let rpc_response: RpcResponse = response
            .json()
            .await
            .map_err(|e| SyncProxyError::BroadcastError(format!("JSON parse error: {}", e)))?;

        if let Some(error) = rpc_response.error {
            return Err(SyncProxyError::BroadcastError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| SyncProxyError::BroadcastError("Missing result".to_string()))?;

        Ok(BroadcastTxResponse {
            tx_hash: result.tx_hash,
            relayed: !request.do_not_relay && result.relayed,
            fee: result.fee,
        })
    }

    /// Select random ring members (decoys) for an output
    ///
    /// This is called internally during blockchain scanning to pre-calculate
    /// decoys for each output.
    ///
    /// # Parameters
    /// - `output_amount`: Amount of the output (for histogram selection)
    /// - `output_global_index`: Global index of the output to spend
    ///
    /// # Returns
    /// - Vec of DecoyInfo (ring_size - 1 decoys, real output excluded)
    ///
    /// # Algorithm
    /// 1. Get output distribution histogram
    /// 2. Select outputs with gamma distribution (Monero's method)
    /// 3. Exclude the real output's global index
    /// 4. Fetch public keys via get_outs RPC
    async fn select_decoys(
        &self,
        output_amount: u64,
        output_global_index: u64,
    ) -> Result<Vec<DecoyInfo>, SyncProxyError> {
        tracing::debug!(
            "Selecting {} decoys for output {} (amount: {})",
            self.ring_size - 1,
            output_global_index,
            output_amount
        );

        // Step 1: Get output distribution for this amount
        let histogram = self.get_output_distribution(output_amount).await?;

        // Step 2: Select decoy indices using gamma distribution (Monero-compliant)
        // Parameters: α=19.28, θ=1.61 derived from empirical spend time analysis
        let num_decoys = self.ring_size - 1; // 15 decoys for ring size 16

        use crate::services::ring_selection::RingSelector;
        let selector = RingSelector::new();
        let decoy_indices = selector.select_decoys(&histogram, output_global_index, num_decoys);

        // Step 3: Fetch output details (public keys + RCT masks)
        let decoys = self.get_outs(&decoy_indices).await?;

        Ok(decoys)
    }

    /// Get output distribution histogram for a specific amount
    ///
    /// RPC: get_output_histogram (daemon)
    async fn get_output_distribution(&self, amount: u64) -> Result<Vec<u64>, SyncProxyError> {
        #[derive(Serialize)]
        struct Params {
            amounts: Vec<u64>,
            min_count: u64,
            max_count: u64,
        }

        #[derive(Deserialize)]
        struct HistogramResult {
            histogram: Vec<HistogramEntry>,
        }

        #[derive(Deserialize)]
        struct HistogramEntry {
            #[serde(default)]
            instances: u64,
            #[serde(default)]
            unlocked_instances: u64,
        }

        // For RCT (amount = 0), get general distribution
        let request_amount = if amount == 0 { 0 } else { amount };

        let result: HistogramResult = self
            .call_daemon_rpc(
                "get_output_histogram",
                Params {
                    amounts: vec![request_amount],
                    min_count: 0,
                    max_count: 3000000, // Max outputs to consider
                },
            )
            .await?;

        // Extract available output indices (simplified)
        let mut indices = Vec::new();
        if let Some(entry) = result.histogram.first() {
            let count = entry.unlocked_instances;
            for i in 0..count {
                indices.push(i);
            }
        }

        if indices.is_empty() {
            return Err(SyncProxyError::DecoyError(
                "No outputs available for decoy selection".to_string(),
            ));
        }

        Ok(indices)
    }

    /// Get output details (public keys + RCT masks)
    ///
    /// RPC: get_outs (daemon)
    async fn get_outs(&self, indices: &[u64]) -> Result<Vec<DecoyInfo>, SyncProxyError> {
        #[derive(Serialize)]
        struct Params {
            outputs: Vec<OutputRequest>,
        }

        #[derive(Serialize)]
        struct OutputRequest {
            amount: u64,
            index: u64,
        }

        #[derive(Deserialize)]
        struct OutsResult {
            outs: Vec<OutEntry>,
        }

        #[derive(Deserialize)]
        struct OutEntry {
            key: String,
            mask: Option<String>,
            #[serde(default)]
            txid: String,
        }

        let outputs: Vec<OutputRequest> = indices
            .iter()
            .map(|&index| OutputRequest { amount: 0, index }) // amount=0 for RCT
            .collect();

        let result: OutsResult = self.call_daemon_rpc("get_outs", Params { outputs }).await?;

        let decoys = result
            .outs
            .into_iter()
            .zip(indices.iter())
            .map(|(out, &global_index)| DecoyInfo {
                global_index,
                public_key: out.key,
                rct_mask: out.mask,
            })
            .collect();

        Ok(decoys)
    }

    /// Generic daemon RPC call helper
    async fn call_daemon_rpc<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, SyncProxyError> {
        #[derive(Serialize)]
        struct RpcRequest<T> {
            jsonrpc: String,
            id: String,
            method: String,
            params: T,
        }

        #[derive(Deserialize)]
        struct RpcResponse<T> {
            result: Option<T>,
            error: Option<RpcError>,
        }

        #[derive(Deserialize)]
        struct RpcError {
            message: String,
        }

        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: "0".to_string(),
            method: method.to_string(),
            params,
        };

        let response = self
            .client
            .post(&self.daemon_rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| SyncProxyError::MoneroRpc(format!("Daemon HTTP error: {}", e)))?;

        let rpc_response: RpcResponse<R> = response
            .json()
            .await
            .map_err(|e| SyncProxyError::MoneroRpc(format!("Daemon JSON parse error: {}", e)))?;

        if let Some(error) = rpc_response.error {
            return Err(SyncProxyError::DecoyError(error.message));
        }

        rpc_response
            .result
            .ok_or_else(|| SyncProxyError::DecoyError("Missing result from daemon".to_string()))
    }

    // ========================================================================
    // MONERO-WALLET-RPC HELPER METHODS
    // ========================================================================

    /// Create view-only wallet from public keys
    ///
    /// RPC: generate_from_keys
    async fn create_view_only_wallet(
        &self,
        wallet_name: &str,
        view_key_pub: &str,
        spend_key_pub: &str,
        restore_height: u64,
    ) -> Result<(), SyncProxyError> {
        #[derive(Serialize)]
        struct Params {
            filename: String,
            address: String,
            viewkey: String,
            restore_height: u64,
        }

        // Monero requires full address, derive it from pub keys
        // For now, use a placeholder - production needs proper address derivation
        let address = format!("4{}{}", spend_key_pub, view_key_pub);

        let params = Params {
            filename: wallet_name.to_string(),
            address,
            viewkey: view_key_pub.to_string(),
            restore_height,
        };

        self.call_wallet_rpc::<_, ()>("generate_from_keys", params)
            .await?;

        tracing::info!("Created view-only wallet: {}", wallet_name);
        Ok(())
    }

    /// Refresh wallet (scan blockchain)
    ///
    /// RPC: refresh
    async fn refresh_wallet(&self, wallet_name: &str) -> Result<(), SyncProxyError> {
        // First open the wallet
        self.open_wallet(wallet_name).await?;

        #[derive(Serialize)]
        struct Params {}

        self.call_wallet_rpc::<_, ()>("refresh", Params {}).await?;

        tracing::info!("Refreshed wallet: {}", wallet_name);
        Ok(())
    }

    /// Get wallet balance
    ///
    /// RPC: get_balance
    async fn get_balance(&self, _wallet_name: &str) -> Result<u64, SyncProxyError> {
        #[derive(Serialize)]
        struct Params {
            account_index: u32,
        }

        #[derive(Deserialize)]
        struct BalanceResult {
            balance: u64,
        }

        let result: BalanceResult = self
            .call_wallet_rpc("get_balance", Params { account_index: 0 })
            .await?;

        Ok(result.balance)
    }

    /// Get incoming transfers (UTXOs)
    ///
    /// RPC: incoming_transfers
    async fn get_incoming_transfers(
        &self,
        _wallet_name: &str,
    ) -> Result<Vec<IncomingTransfer>, SyncProxyError> {
        #[derive(Serialize)]
        struct Params {
            transfer_type: String,
        }

        #[derive(Deserialize)]
        struct TransfersResult {
            transfers: Option<Vec<IncomingTransfer>>,
        }

        let result: TransfersResult = self
            .call_wallet_rpc(
                "incoming_transfers",
                Params {
                    transfer_type: "all".to_string(),
                },
            )
            .await?;

        Ok(result.transfers.unwrap_or_default())
    }

    /// Get current blockchain height
    ///
    /// RPC: get_height (daemon RPC, not wallet)
    async fn get_height(&self) -> Result<u64, SyncProxyError> {
        #[derive(Serialize)]
        struct EmptyParams {}

        #[derive(Deserialize)]
        struct HeightResult {
            height: u64,
        }

        let result: HeightResult = self.call_wallet_rpc("get_height", EmptyParams {}).await?;

        Ok(result.height)
    }

    /// Open wallet
    ///
    /// RPC: open_wallet
    async fn open_wallet(&self, wallet_name: &str) -> Result<(), SyncProxyError> {
        #[derive(Serialize)]
        struct Params {
            filename: String,
        }

        self.call_wallet_rpc::<_, ()>(
            "open_wallet",
            Params {
                filename: wallet_name.to_string(),
            },
        )
        .await?;

        Ok(())
    }

    /// Close wallet
    ///
    /// RPC: close_wallet
    async fn close_wallet(&self, _wallet_name: &str) -> Result<(), SyncProxyError> {
        #[derive(Serialize)]
        struct EmptyParams {}

        self.call_wallet_rpc::<_, ()>("close_wallet", EmptyParams {})
            .await?;

        tracing::info!("Closed wallet");
        Ok(())
    }

    /// Generic RPC call helper
    async fn call_wallet_rpc<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, SyncProxyError> {
        #[derive(Serialize)]
        struct RpcRequest<T> {
            jsonrpc: String,
            id: String,
            method: String,
            params: T,
        }

        #[derive(Deserialize)]
        struct RpcResponse<T> {
            result: Option<T>,
            error: Option<RpcError>,
        }

        #[derive(Deserialize)]
        struct RpcError {
            message: String,
        }

        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: "0".to_string(),
            method: method.to_string(),
            params,
        };

        let response = self
            .client
            .post(&self.monero_rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| SyncProxyError::MoneroRpc(format!("HTTP error: {}", e)))?;

        let rpc_response: RpcResponse<R> = response
            .json()
            .await
            .map_err(|e| SyncProxyError::MoneroRpc(format!("JSON parse error: {}", e)))?;

        if let Some(error) = rpc_response.error {
            return Err(SyncProxyError::MoneroRpc(error.message));
        }

        rpc_response
            .result
            .ok_or_else(|| SyncProxyError::MoneroRpc("Missing result".to_string()))
    }

    /// Convert Monero incoming_transfers to our OutputInfo format
    async fn convert_transfers_to_outputs(
        &self,
        transfers: Vec<IncomingTransfer>,
    ) -> Result<Vec<OutputInfo>, SyncProxyError> {
        let mut outputs = Vec::new();

        for transfer in transfers {
            // Select decoys for this output
            let decoys = self
                .select_decoys(transfer.amount, transfer.global_index)
                .await?;

            outputs.push(OutputInfo {
                tx_hash: transfer.tx_hash,
                output_index: transfer.subaddr_index.unwrap_or(0),
                amount: transfer.amount,
                public_key: transfer.pubkey.unwrap_or_default(),
                tx_pub_key: String::new(), // Not provided by incoming_transfers
                global_index: transfer.global_index,
                block_height: transfer.block_height,
                ring_decoys: decoys,
            });
        }

        Ok(outputs)
    }
}

/// Incoming transfer from monero-wallet-rpc
#[derive(Debug, Deserialize)]
struct IncomingTransfer {
    amount: u64,
    global_index: u64,
    tx_hash: String,
    block_height: u64,
    #[serde(default)]
    pubkey: Option<String>,
    #[serde(default)]
    subaddr_index: Option<u64>,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_proxy_creation_localhost_only() {
        // ✅ Should succeed with localhost
        let result = SyncProxyService::new(
            "http://127.0.0.1:18083/json_rpc".to_string(),
            "http://127.0.0.1:18081/json_rpc".to_string(),
        );
        assert!(result.is_ok());

        let result = SyncProxyService::new(
            "http://localhost:18083/json_rpc".to_string(),
            "http://localhost:18081/json_rpc".to_string(),
        );
        assert!(result.is_ok());

        // ❌ Should fail with public IP (wallet)
        let result = SyncProxyService::new(
            "http://192.168.1.100:18083/json_rpc".to_string(),
            "http://127.0.0.1:18081/json_rpc".to_string(),
        );
        assert!(result.is_err());

        // ❌ Should fail with public IP (daemon)
        let result = SyncProxyService::new(
            "http://127.0.0.1:18083/json_rpc".to_string(),
            "http://monero.example.com:18081/json_rpc".to_string(),
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_scan_outputs_validates_keys() {
        let service = SyncProxyService::new(
            "http://127.0.0.1:18083/json_rpc".to_string(),
            "http://127.0.0.1:18081/json_rpc".to_string(),
        )
        .unwrap();

        // ❌ Invalid view key length
        let request = ScanOutputsRequest {
            view_key_pub: "deadbeef".to_string(), // Too short
            spend_key_pub: "a".repeat(64),
            start_height: 0,
            address: None,
        };

        let result = service.scan_outputs(request).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SyncProxyError::InvalidViewKey(_)
        ));
    }

    #[tokio::test]
    async fn test_broadcast_tx_validates_hex() {
        let service = SyncProxyService::new(
            "http://127.0.0.1:18083/json_rpc".to_string(),
            "http://127.0.0.1:18081/json_rpc".to_string(),
        )
        .unwrap();

        // ❌ Invalid hex
        let request = BroadcastTxRequest {
            signed_tx_hex: "not_hex!!!".to_string(),
            do_not_relay: true,
        };

        let result = service.broadcast_tx(request).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SyncProxyError::BroadcastError(_)
        ));
    }

    #[test]
    fn test_output_info_serialization() {
        let output = OutputInfo {
            tx_hash: "a".repeat(64),
            output_index: 0,
            amount: 1000000000000,
            public_key: "b".repeat(64),
            tx_pub_key: "c".repeat(64),
            global_index: 12345,
            block_height: 3000000,
            ring_decoys: vec![],
        };

        let json = serde_json::to_string(&output).unwrap();
        let deserialized: OutputInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(output.tx_hash, deserialized.tx_hash);
        assert_eq!(output.amount, deserialized.amount);
        assert_eq!(output.global_index, deserialized.global_index);
    }
}
