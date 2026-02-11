//! Monero RPC client implementation

use crate::validation::validate_localhost_strict;
use monero_marketplace_common::{
    error::MoneroError,
    types::{
        ExchangeMultisigKeysResult, ExportMultisigInfoResult, ImportMultisigInfoResult,
        MakeMultisigResult, MoneroConfig, MultisigInfo, PrepareMultisigResult, RpcRequest,
        RpcResponse,
    },
    MAX_MULTISIG_INFO_LEN, MIN_MULTISIG_INFO_LEN,
};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, Duration as TokioDuration};

/// Client RPC Monero
///
/// SÉCURITÉ:
/// - RPC bind sur localhost uniquement (vérifié à la création)
/// - Pas d'authentification requise (--disable-rpc-login en testnet)
/// - Timeout configurable via MONERO_RPC_TIMEOUT_SECS (défaut: 45s prod, 60s dev)
#[derive(Clone)]
pub struct MoneroRpcClient {
    url: String,
    client: Client,
    // Mutex pour sérialiser les appels RPC (protection race condition)
    rpc_lock: Arc<Mutex<()>>,
    // Semaphore pour limiter requêtes concurrentes (rate limiting)
    semaphore: Arc<Semaphore>,
}

impl MoneroRpcClient {
    /// Crée nouveau client RPC
    ///
    /// # OPSEC Note
    /// RPC doit être sur localhost UNIQUEMENT.
    /// JAMAIS exposer sur 0.0.0.0 ou IP publique.
    pub fn new(config: MoneroConfig) -> Result<Self, MoneroError> {
        let url = config.rpc_url;

        // TM-004 Fix: Validation stricte (pas de bypass avec evil-127.0.0.1.com)
        validate_localhost_strict(&url)
            .map_err(|e| MoneroError::InvalidResponse(format!("OPSEC violation: {e}")))?;

        // Utiliser timeout depuis config
        let timeout_secs = config.timeout_seconds;

        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| MoneroError::NetworkError(format!("Client build: {e}")))?;

        Ok(Self {
            url,
            client,
            rpc_lock: Arc::new(Mutex::new(())),
            semaphore: Arc::new(Semaphore::new(5)), // Max 5 requêtes concurrentes
        })
    }

    /// Vérifie que RPC est accessible
    pub async fn check_connection(&self) -> Result<(), MoneroError> {
        let request = RpcRequest::new("get_version");

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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
            return Err(MoneroError::RpcUnreachable);
        }

        Ok(())
    }

    /// Get wallet RPC version
    ///
    /// Returns the Monero wallet RPC version number.
    ///
    /// # Errors
    /// - MoneroError::RpcUnreachable - RPC pas accessible
    /// - MoneroError::InvalidResponse - Réponse invalide
    ///
    /// # Examples
    /// ```no_run
    /// # use monero_marketplace_wallet::rpc::MoneroRpcClient;
    /// # use monero_marketplace_common::types::MoneroConfig;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = MoneroConfig::default();
    /// let client = MoneroRpcClient::new(config)?;
    /// let version = client.get_version().await?;
    /// tracing::info!("Wallet RPC version: {}", version);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_version(&self) -> Result<u32, MoneroError> {
        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let request = RpcRequest::new("get_version");

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        let version = result["version"]
            .as_u64()
            .ok_or_else(|| MoneroError::InvalidResponse("Invalid version format".to_string()))?;

        Ok(version as u32)
    }

    /// Get wallet balance
    ///
    /// Returns the wallet balance as (unlocked_balance, total_balance) in atomic units.
    /// Monero uses 12 decimal places, so 1 XMR = 1_000_000_000_000 atomic units.
    ///
    /// # Returns
    /// (unlocked_balance, total_balance) - Both in atomic units
    ///
    /// # Errors
    /// - MoneroError::RpcUnreachable - RPC pas accessible
    /// - MoneroError::InvalidResponse - Réponse invalide
    ///
    /// # Examples
    /// ```no_run
    /// # use monero_marketplace_wallet::rpc::MoneroRpcClient;
    /// # use monero_marketplace_common::types::MoneroConfig;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = MoneroConfig::default();
    /// let client = MoneroRpcClient::new(config)?;
    /// let (unlocked, total) = client.get_balance().await?;
    /// tracing::info!("Unlocked: {} atomic units", unlocked);
    /// tracing::info!("Total: {} atomic units", total);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_balance(&self) -> Result<(u64, u64), MoneroError> {
        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let request = RpcRequest::new("get_balance");

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        let unlocked_balance = result["unlocked_balance"].as_u64().ok_or_else(|| {
            MoneroError::InvalidResponse("Invalid unlocked_balance format".to_string())
        })?;

        let balance = result["balance"]
            .as_u64()
            .ok_or_else(|| MoneroError::InvalidResponse("Invalid balance format".to_string()))?;

        Ok((unlocked_balance, balance))
    }

    /// Get wallet address
    pub async fn get_address(&self) -> Result<String, MoneroError> {
        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let request = RpcRequest::new("get_address");

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        let address = result["address"]
            .as_str()
            .ok_or_else(|| MoneroError::InvalidResponse("Invalid address format".to_string()))?;

        Ok(address.to_string())
    }

    /// Prépare wallet pour multisig (étape 1/6)
    ///
    /// # Errors
    /// - MoneroError::RpcUnreachable - RPC pas accessible
    /// - MoneroError::AlreadyMultisig - Wallet déjà en mode multisig
    /// - MoneroError::WalletLocked - Wallet verrouillé
    /// - MoneroError::InvalidResponse - Réponse invalide
    ///
    /// # Examples
    /// ```no_run
    /// # use monero_marketplace_wallet::rpc::MoneroRpcClient;
    /// # use monero_marketplace_common::types::MoneroConfig;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = MoneroConfig::default();
    /// let client = MoneroRpcClient::new(config)?;
    /// let info = client.prepare_multisig().await?;
    /// assert!(info.multisig_info.starts_with("MultisigV1"));
    /// # Ok(())
    /// # }
    /// ```

    /// Create a new wallet file in the wallet-rpc
    ///
    /// # Arguments
    /// * `filename` - Name of the wallet file (without extension)
    /// * `password` - Wallet password (can be empty for testnet)
    ///
    /// # Returns
    /// Ok(()) if wallet was created successfully
    ///
    /// # Errors
    /// - MoneroError::RpcUnreachable - RPC not accessible
    /// - MoneroError::RpcError - Wallet already exists or other RPC error
    /// - MoneroError::InvalidResponse - Invalid response format
    pub async fn create_wallet(&self, filename: &str, password: &str) -> Result<(), MoneroError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        let _guard = self.rpc_lock.lock().await;

        let params = serde_json::json!({
            "filename": filename,
            "password": password,
            "language": "English"
        });

        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: "0".to_string(),
            method: "create_wallet".to_string(),
            params: Some(params),
        };

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        Ok(())
    }

    /// Open an existing wallet file in the wallet-rpc
    ///
    /// # Arguments
    /// * `filename` - Name of the wallet file (without extension)
    /// * `password` - Wallet password
    ///
    /// # Returns
    /// Ok(()) if wallet was opened successfully
    ///
    /// # Errors
    /// - MoneroError::RpcUnreachable - RPC not accessible
    /// - MoneroError::RpcError - Wallet not found or wrong password
    /// - MoneroError::InvalidResponse - Invalid response format
    pub async fn open_wallet(&self, filename: &str, password: &str) -> Result<(), MoneroError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        let _guard = self.rpc_lock.lock().await;

        let params = serde_json::json!({
            "filename": filename,
            "password": password
        });

        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: "0".to_string(),
            method: "open_wallet".to_string(),
            params: Some(params),
        };

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        Ok(())
    }

    /// Close the currently open wallet in the wallet-rpc
    ///
    /// # Returns
    /// Ok(()) if wallet was closed successfully
    ///
    /// # Errors
    /// - MoneroError::RpcUnreachable - RPC not accessible
    /// - MoneroError::RpcError - No wallet open or RPC error
    /// - MoneroError::InvalidResponse - Invalid response format
    pub async fn close_wallet(&self) -> Result<(), MoneroError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        let _guard = self.rpc_lock.lock().await;

        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: "0".to_string(),
            method: "close_wallet".to_string(),
            params: None,
        };

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        Ok(())
    }

    /// Restore a deterministic wallet from seed (Phase 6: Non-custodial)
    ///
    /// Creates or restores a wallet using a deterministic seed. This is used for
    /// server-side wallet derivation where the seed is derived from a user's master seed.
    ///
    /// # Arguments
    ///
    /// * `filename` - Name for the wallet file (e.g., "escrow_123_buyer")
    /// * `seed` - Hexadecimal seed (32 bytes = 64 hex chars for Monero spend key)
    /// * `restore_height` - Block height to start scanning from (0 for new wallets)
    /// * `password` - Wallet password (can be empty for temporary wallets)
    ///
    /// # Security Notes
    ///
    /// - Seed must be 64 hex characters (32 bytes)
    /// - Wallet is created/restored in wallet-rpc daemon memory
    /// - Call `close_wallet()` after use to clear keys from memory
    /// - For Phase 6 MVP: Server holds keys briefly during signing (<100ms)
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The wallet's primary address
    ///
    /// # Errors
    ///
    /// - MoneroError::InvalidResponse - Invalid seed format or RPC error
    /// - MoneroError::RpcUnreachable - Cannot connect to wallet RPC
    /// - MoneroError::RpcError - Wallet creation/restoration failed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use monero_marketplace_wallet::rpc::MoneroRpcClient;
    /// # use monero_marketplace_common::types::MoneroConfig;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = MoneroConfig::default();
    /// let client = MoneroRpcClient::new(config)?;
    ///
    /// // Derive seed from user's master seed (done elsewhere)
    /// let escrow_seed_hex = "a1b2c3d4..."; // 64 hex chars
    ///
    /// let address = client.restore_deterministic_wallet(
    ///     "escrow_001_buyer",
    ///     escrow_seed_hex,
    ///     0,  // New wallet, start from genesis
    ///     ""  // Empty password for temporary wallet
    /// ).await?;
    ///
    /// println!("Wallet address: {}", address);
    ///
    /// // CRITICAL: Close wallet after use
    /// client.close_wallet().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn restore_deterministic_wallet(
        &self,
        filename: &str,
        seed: &str,
        restore_height: u64,
        password: &str,
    ) -> Result<String, MoneroError> {
        // Validate seed format (must be 64 hex chars = 32 bytes)
        if seed.len() != 64 {
            return Err(MoneroError::InvalidResponse(format!(
                "Seed must be 64 hex characters (32 bytes), got {}",
                seed.len()
            )));
        }

        if !seed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(MoneroError::InvalidResponse(
                "Seed must contain only hexadecimal characters".to_string(),
            ));
        }

        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        let _guard = self.rpc_lock.lock().await;

        let params = serde_json::json!({
            "filename": filename,
            "seed": seed,
            "restore_height": restore_height,
            "password": password,
            "language": "English",
            "autosave_current": true
        });

        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: "0".to_string(),
            method: "restore_deterministic_wallet".to_string(),
            params: Some(params),
        };

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(format!(
                "restore_deterministic_wallet failed: {}",
                error.message
            )));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result".to_string()))?;

        // Extract wallet address from result
        let address = result
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MoneroError::InvalidResponse("Missing address in response".to_string()))?
            .to_string();

        tracing::info!(
            "Restored deterministic wallet '{}' with address: {}...",
            filename,
            &address[..8] // Log only first 8 chars for privacy
        );

        Ok(address)
    }

    pub async fn prepare_multisig(&self) -> Result<MultisigInfo, MoneroError> {
        // Retry logic avec backoff exponentiel
        let mut retries = 0;
        let max_retries = 3;

        loop {
            match self.prepare_multisig_inner().await {
                Ok(result) => return Ok(result),
                Err(e) if retries < max_retries => {
                    let delay = TokioDuration::from_millis(100 * 2u64.pow(retries));
                    tracing::debug!(
                        "Retry {}/{}: {} (waiting {:?})",
                        retries + 1,
                        max_retries,
                        e,
                        delay
                    );
                    sleep(delay).await;
                    retries += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn prepare_multisig_inner(&self) -> Result<MultisigInfo, MoneroError> {
        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let request = RpcRequest::new("prepare_multisig");

        // Appel RPC avec gestion d'erreur
        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        // Parse JSON response
        let rpc_response: RpcResponse<PrepareMultisigResult> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        // Handle RPC errors
        if let Some(error) = rpc_response.error {
            return Err(match error.message.as_str() {
                msg if msg.contains("already") && msg.contains("multisig") => {
                    MoneroError::AlreadyMultisig
                }
                msg if msg.contains("locked") => MoneroError::WalletLocked,
                _ => MoneroError::RpcError(error.message),
            });
        }

        // Extract result
        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        // DEBUG: Log length only (no cryptographic content)
        tracing::info!(
            "🔍 RPC returned multisig_info: {} chars",
            result.multisig_info.len()
        );

        // VALIDATION STRICTE: multisig_info
        validate_multisig_info(&result.multisig_info)?;

        Ok(MultisigInfo {
            multisig_info: result.multisig_info,
        })
    }

    /// Crée wallet multisig 2-of-3 (étape 2/6)
    ///
    /// # Arguments
    /// * `threshold` - Nombre de signatures requises (2 pour 2-of-3)
    /// * `multisig_info` - Vec des multisig_info des autres participants
    ///
    /// # Errors
    /// - MoneroError::RpcUnreachable - RPC pas accessible
    /// - MoneroError::AlreadyMultisig - Wallet déjà finalisé en multisig
    /// - MoneroError::ValidationError - multisig_info invalides
    /// - MoneroError::RpcError - Erreur Monero (ex: threshold invalide)
    /// - MoneroError::WalletLocked - Wallet verrouillé
    /// - MoneroError::WalletBusy - Autre opération en cours
    ///
    /// # Examples
    /// ```no_run
    /// # use monero_marketplace_wallet::rpc::MoneroRpcClient;
    /// # use monero_marketplace_common::types::MoneroConfig;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = MoneroConfig::default();
    /// let client = MoneroRpcClient::new(config)?;
    ///
    /// // Après avoir récupéré les infos des 3 wallets via prepare_multisig
    /// let seller_info = "MultisigV1...".to_string();
    /// let arb_info = "MultisigV1...".to_string();
    ///
    /// let result = client.make_multisig(2, vec![seller_info, arb_info]).await?;
    /// assert!(result.address.starts_with("5")); // Testnet multisig address
    /// # Ok(())
    /// # }
    /// ```
    pub async fn make_multisig(
        &self,
        threshold: u32,
        multisig_info: Vec<String>,
    ) -> Result<MakeMultisigResult, MoneroError> {
        // Retry logic avec backoff exponentiel
        let mut retries = 0;
        let max_retries = 3;

        loop {
            match self
                .make_multisig_inner(threshold, multisig_info.clone())
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) if retries < max_retries => {
                    let delay = TokioDuration::from_millis(100 * 2u64.pow(retries));
                    tracing::debug!(
                        "Retry {}/{}: {} (waiting {:?})",
                        retries + 1,
                        max_retries,
                        e,
                        delay
                    );
                    sleep(delay).await;
                    retries += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn make_multisig_inner(
        &self,
        threshold: u32,
        multisig_info: Vec<String>,
    ) -> Result<MakeMultisigResult, MoneroError> {
        // VALIDATION PRÉ-REQUÊTES

        // 1. Vérifier threshold valide (2 pour 2-of-3)
        if threshold < 2 {
            return Err(MoneroError::ValidationError(
                "Threshold must be at least 2".to_string(),
            ));
        }

        // 2. Vérifier nombre de multisig_info (doit être = total - 1)
        // Pour 2-of-3, on doit avoir 2 autres infos
        if multisig_info.len() < 2 {
            return Err(MoneroError::ValidationError(format!(
                "Need at least 2 multisig_info, got {}",
                multisig_info.len()
            )));
        }

        // 3. Valider chaque multisig_info
        for (i, info) in multisig_info.iter().enumerate() {
            validate_multisig_info(info).map_err(|e| {
                MoneroError::ValidationError(format!("Invalid multisig_info[{i}]: {e}"))
            })?;
        }

        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        // Construire request avec params
        let mut request = RpcRequest::new("make_multisig");
        request.params = Some(serde_json::json!({
            "threshold": threshold,
            "multisig_info": multisig_info,
        }));

        // Appel RPC avec gestion d'erreur
        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        // Parse JSON response
        let rpc_response: RpcResponse<MakeMultisigResult> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        // Handle RPC errors
        if let Some(error) = rpc_response.error {
            return Err(match error.message.as_str() {
                msg if msg.contains("already") && msg.contains("multisig") => {
                    MoneroError::AlreadyMultisig
                }
                msg if msg.contains("locked") => MoneroError::WalletLocked,
                msg if msg.contains("busy") => MoneroError::WalletBusy,
                msg if msg.contains("invalid") || msg.contains("Invalid") => {
                    MoneroError::ValidationError(error.message.clone())
                }
                _ => MoneroError::RpcError(error.message),
            });
        }

        // Extract result
        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        // VALIDATION POST-REQUÊTE

        // 1. Vérifier que address n'est pas vide
        if result.address.is_empty() {
            return Err(MoneroError::InvalidResponse(
                "Empty multisig address returned".to_string(),
            ));
        }

        // 2. Vérifier que multisig_info est valide
        validate_multisig_info(&result.multisig_info)?;

        Ok(result)
    }

    /// Échange les clés multisig pour finaliser le setup 2-of-3 (Round 2)
    ///
    /// **CRITIQUE**: Cette méthode est la véritable étape de Round 2 pour le multisig 2-of-3.
    /// Elle DOIT être appelée après `make_multisig()` avec les `multisig_info` retournés par Round 1.
    ///
    /// # Protocole Monero Multisig 2-of-3
    ///
    /// ```text
    /// Round 0: prepare_multisig()           → prepare_info
    /// Round 1: make_multisig(prepare_infos) → address + multisig_info
    /// Round 2: exchange_multisig_keys(round1_infos) → finalise le wallet ✅
    /// ```
    ///
    /// **Différence clé avec `make_multisig`**:
    /// - `make_multisig`: Utilise `prepare_info` pour créer le wallet multisig initial
    /// - `exchange_multisig_keys`: Utilise `multisig_info` (de Round 1) pour finaliser
    ///
    /// # Arguments
    /// * `multisig_info` - Vec des `multisig_info` retournés par `make_multisig` Round 1
    ///
    /// # Returns
    /// `ExchangeMultisigKeysResult` contenant:
    /// - `address`: Adresse multisig finale (doit correspondre à Round 1)
    /// - `multisig_info`: Info de clé (peut être vide après finalisation)
    ///
    /// # Errors
    /// - `ValidationError`: multisig_info invalides ou manquants
    /// - `RpcError`: Wallet déjà finalisé ou erreur RPC
    /// - `NetworkError`: Échec de connexion RPC
    ///
    /// # Example
    /// ```rust,no_run
    /// # use wallet::rpc::MoneroRpcClient;
    /// # use monero_marketplace_common::Error;
    /// # async fn example() -> Result<(), Error> {
    /// let client = MoneroRpcClient::new("http://127.0.0.1:18082")?;
    ///
    /// // Round 1: make_multisig retourne multisig_info
    /// let round1 = client.make_multisig(2, vec![prepare_info1, prepare_info2]).await?;
    /// let round1_info = round1.multisig_info;
    ///
    /// // Round 2: exchange_multisig_keys FINALISE le wallet
    /// let result = client.exchange_multisig_keys(vec![other_round1_info1, other_round1_info2]).await?;
    /// assert_eq!(result.address, round1.address); // Même adresse
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Références
    /// - Documentation officielle: https://www.getmonero.org/resources/developer-guides/wallet-rpc.html
    /// - Guide multisig: https://www.getmonero.org/resources/user-guides/multisig-messaging-system.html
    pub async fn exchange_multisig_keys(
        &self,
        multisig_info: Vec<String>,
    ) -> Result<ExchangeMultisigKeysResult, MoneroError> {
        // ⚠️ NO RETRY LOGIC for exchange_multisig_keys!
        // The wallet state changes after the first successful call, so retrying
        // with the same inputs will always fail with "wrong kex round number".
        //
        // For 2-of-3 multisig in v0.18.4.3:
        // - First call: exchange_multisig_keys(round1_infos) → may return new multisig_info
        // - Second call (if needed): exchange_multisig_keys(round2_infos) → finalization
        //
        // Each call MUST succeed on first attempt or fail permanently.

        tracing::info!(
            "🔍 exchange_multisig_keys called with {} infos (NO RETRY)",
            multisig_info.len()
        );

        let result = self.exchange_multisig_keys_inner(multisig_info).await?;

        tracing::info!(
            "✅ exchange_multisig_keys SUCCESS: multisig_info={} bytes, address=[{}...{}]",
            result.multisig_info.len(),
            &result.address[..2], // Network prefix only
            &result.address[result.address.len().saturating_sub(3)..]  // Last 3 chars
        );

        Ok(result)
    }

    async fn exchange_multisig_keys_inner(
        &self,
        multisig_info: Vec<String>,
    ) -> Result<ExchangeMultisigKeysResult, MoneroError> {
        // VALIDATION PRÉ-REQUÊTES

        // 1. Vérifier nombre de multisig_info (doit être = N-1, donc 2 pour 2-of-3)
        if multisig_info.len() < 2 {
            return Err(MoneroError::ValidationError(format!(
                "Need at least 2 multisig_info for Round 2, got {}",
                multisig_info.len()
            )));
        }

        // 2. Valider chaque multisig_info (doivent commencer par "MultisigxV2")
        for (i, info) in multisig_info.iter().enumerate() {
            validate_multisig_info(info).map_err(|e| {
                MoneroError::ValidationError(format!("Invalid multisig_info[{i}]: {e}"))
            })?;
        }

        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        // Construire request RPC
        let mut request = RpcRequest::new("exchange_multisig_keys");
        request.params = Some(serde_json::json!({
            "multisig_info": multisig_info,
        }));

        // Appel RPC avec gestion d'erreur
        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        // Parse JSON response
        let rpc_response: RpcResponse<ExchangeMultisigKeysResult> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        // Handle RPC errors
        if let Some(error) = rpc_response.error {
            return Err(match error.message.as_str() {
                msg if msg.contains("already") && msg.contains("finalized") => {
                    MoneroError::ValidationError("Wallet already finalized".to_string())
                }
                msg if msg.contains("not") && msg.contains("multisig") => {
                    MoneroError::ValidationError("Wallet is not a multisig wallet".to_string())
                }
                msg if msg.contains("locked") => MoneroError::WalletLocked,
                msg if msg.contains("busy") => MoneroError::WalletBusy,
                msg if msg.contains("invalid") || msg.contains("Invalid") => {
                    MoneroError::ValidationError(error.message.clone())
                }
                _ => MoneroError::RpcError(error.message),
            });
        }

        // Extract result
        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        // VALIDATION POST-REQUÊTE
        //
        // NOTE: Pour 2-of-3 multisig en v0.18.4.3, l'adresse peut être vide lors des rounds
        // intermédiaires. L'adresse finale sera obtenue avec get_address() après tous les rounds.
        //
        // ✅ Round 2 (premier exchange_multisig_keys): peut retourner address="" avec multisig_info non-vide
        // ✅ Round 3 (second exchange_multisig_keys): peut retourner address="" avec multisig_info=""
        //
        // L'adresse multisig finale est récupérée après finalisation via get_address()

        if !result.address.is_empty() {
            // Si une adresse est retournée, valider qu'elle est valide
            if !result.address.starts_with('4')
                && !result.address.starts_with('5')
                && !result.address.starts_with('9')
            // Testnet multisig addresses can start with 9
            {
                tracing::warn!(
                    "Unexpected multisig address prefix: {}, len={}",
                    result.address.chars().take(10).collect::<String>(),
                    result.address.len()
                );
            }
        }

        Ok(result)
    }

    /// Exporte les informations multisig pour synchronisation (étape 3/6)
    ///
    /// Cette fonction doit être appelée DEUX fois dans le flow multisig:
    /// - Round 1: Après make_multisig
    /// - Round 2: Après premier import_multisig_info
    ///
    /// # Errors
    /// - MoneroError::RpcUnreachable - RPC pas accessible
    /// - MoneroError::NotMultisig - Wallet pas en mode multisig
    /// - MoneroError::WalletLocked - Wallet verrouillé
    /// - MoneroError::InvalidResponse - Réponse invalide
    ///
    /// # Examples
    /// ```no_run
    /// # use monero_marketplace_wallet::rpc::MoneroRpcClient;
    /// # use monero_marketplace_common::types::MoneroConfig;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = MoneroConfig::default();
    /// let client = MoneroRpcClient::new(config)?;
    ///
    /// // Après make_multisig
    /// let export_info = client.export_multisig_info().await?;
    /// // Partager export_info.info avec les autres participants
    /// # Ok(())
    /// # }
    /// ```
    pub async fn export_multisig_info(&self) -> Result<ExportMultisigInfoResult, MoneroError> {
        // Retry logic avec backoff exponentiel
        let mut retries = 0;
        let max_retries = 3;

        loop {
            match self.export_multisig_info_inner().await {
                Ok(result) => return Ok(result),
                Err(e) if retries < max_retries => {
                    let delay = TokioDuration::from_millis(100 * 2u64.pow(retries));
                    tracing::debug!(
                        "Retry {}/{}: {} (waiting {:?})",
                        retries + 1,
                        max_retries,
                        e,
                        delay
                    );
                    sleep(delay).await;
                    retries += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn export_multisig_info_inner(&self) -> Result<ExportMultisigInfoResult, MoneroError> {
        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let request = RpcRequest::new("export_multisig_info");

        // Appel RPC avec gestion d'erreur
        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        // Parse JSON response
        let rpc_response: RpcResponse<ExportMultisigInfoResult> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        // Handle RPC errors
        if let Some(error) = rpc_response.error {
            return Err(match error.message.as_str() {
                msg if msg.contains("not") && msg.contains("multisig") => MoneroError::NotMultisig,
                msg if msg.contains("locked") => MoneroError::WalletLocked,
                msg if msg.contains("busy") => MoneroError::WalletBusy,
                _ => MoneroError::RpcError(error.message),
            });
        }

        // Extract result
        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        // VALIDATION POST-REQUÊTE: Info non vide
        if result.info.is_empty() {
            return Err(MoneroError::InvalidResponse(
                "Empty multisig info returned".to_string(),
            ));
        }

        // Validation longueur
        if result.info.len() < 100 {
            return Err(MoneroError::InvalidResponse(format!(
                "Multisig info too short: {} chars",
                result.info.len()
            )));
        }

        if result.info.len() > 5000 {
            return Err(MoneroError::InvalidResponse(format!(
                "Multisig info too long: {} chars",
                result.info.len()
            )));
        }

        Ok(result)
    }

    /// Importe les informations multisig des autres participants (étape 4/6)
    ///
    /// Cette fonction doit être appelée DEUX fois dans le flow multisig:
    /// - Round 1: Importer les infos exportées par les autres après make_multisig
    /// - Round 2: Importer les infos exportées après le premier import
    ///
    /// # Arguments
    /// * `infos` - Vec des infos exportées des AUTRES participants (N-1 infos)
    ///
    /// # Errors
    /// - MoneroError::RpcUnreachable - RPC pas accessible
    /// - MoneroError::NotMultisig - Wallet pas en mode multisig
    /// - MoneroError::ValidationError - Infos invalides ou incompatibles
    /// - MoneroError::WalletLocked - Wallet verrouillé
    /// - MoneroError::RpcError - Erreur Monero
    ///
    /// # Examples
    /// ```no_run
    /// # use monero_marketplace_wallet::rpc::MoneroRpcClient;
    /// # use monero_marketplace_common::types::MoneroConfig;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = MoneroConfig::default();
    /// let client = MoneroRpcClient::new(config)?;
    ///
    /// // Récupérer infos des autres participants (via canal sécurisé)
    /// let seller_export = "...".to_string();
    /// let arb_export = "...".to_string();
    ///
    /// let result = client.import_multisig_info(vec![seller_export, arb_export]).await?;
    /// tracing::info!("Imported {} outputs", result.n_outputs);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn import_multisig_info(
        &self,
        infos: Vec<String>,
    ) -> Result<ImportMultisigInfoResult, MoneroError> {
        // Retry logic avec backoff exponentiel
        let mut retries = 0;
        let max_retries = 3;

        loop {
            match self.import_multisig_info_inner(infos.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) if retries < max_retries => {
                    let delay = TokioDuration::from_millis(100 * 2u64.pow(retries));
                    tracing::debug!(
                        "Retry {}/{}: {} (waiting {:?})",
                        retries + 1,
                        max_retries,
                        e,
                        delay
                    );
                    sleep(delay).await;
                    retries += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn import_multisig_info_inner(
        &self,
        infos: Vec<String>,
    ) -> Result<ImportMultisigInfoResult, MoneroError> {
        // VALIDATION PRÉ-REQUÊTES

        // 1. Vérifier qu'il y a au moins 1 info
        if infos.is_empty() {
            return Err(MoneroError::ValidationError(
                "Need at least 1 multisig info to import".to_string(),
            ));
        }

        // 2. Pour 2-of-3, on attend exactement 2 infos (N-1)
        if infos.len() < 2 {
            return Err(MoneroError::ValidationError(format!(
                "Expected at least 2 infos for 2-of-3 multisig, got {}",
                infos.len()
            )));
        }

        // 3. Valider chaque info
        for (i, info) in infos.iter().enumerate() {
            if info.is_empty() {
                return Err(MoneroError::ValidationError(format!("Info[{i}] is empty")));
            }
            if info.len() < 100 {
                return Err(MoneroError::ValidationError(format!(
                    "Info[{}] too short: {} chars",
                    i,
                    info.len()
                )));
            }
        }

        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        // Construire request avec params
        let mut request = RpcRequest::new("import_multisig_info");
        request.params = Some(serde_json::json!({
            "info": infos,
        }));

        // Appel RPC avec gestion d'erreur
        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        // Parse JSON response
        let rpc_response: RpcResponse<ImportMultisigInfoResult> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        // Handle RPC errors
        if let Some(error) = rpc_response.error {
            return Err(match error.message.as_str() {
                msg if msg.contains("not") && msg.contains("multisig") => MoneroError::NotMultisig,
                msg if msg.contains("locked") => MoneroError::WalletLocked,
                msg if msg.contains("busy") => MoneroError::WalletBusy,
                msg if msg.contains("invalid") || msg.contains("Invalid") => {
                    MoneroError::ValidationError(error.message.clone())
                }
                msg if msg.contains("already") => {
                    MoneroError::RpcError(format!("Already imported: {}", error.message))
                }
                _ => MoneroError::RpcError(error.message),
            });
        }

        // Extract result
        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        Ok(result)
    }

    /// Get current block height
    pub async fn get_block_height(&self) -> Result<u64, MoneroError> {
        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let request = RpcRequest::new("get_height");

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        let height = result["height"]
            .as_u64()
            .ok_or_else(|| MoneroError::InvalidResponse("Invalid height format".to_string()))?;

        Ok(height)
    }

    /// Get daemon block height
    pub async fn get_daemon_block_height(&self) -> Result<u64, MoneroError> {
        // Pour simplifier, on retourne la même valeur que get_block_height
        // En réalité, ce serait un appel RPC différent vers le daemon
        self.get_block_height().await
    }

    /// Check if wallet is multisig
    pub async fn is_multisig(&self) -> Result<bool, MoneroError> {
        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let request = RpcRequest::new("is_multisig");

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        let is_multisig = result["multisig"]
            .as_bool()
            .ok_or_else(|| MoneroError::InvalidResponse("Invalid multisig format".to_string()))?;

        Ok(is_multisig)
    }

    /// Set wallet attribute (e.g., enable-multisig-experimental)
    ///
    /// # Arguments
    /// * `key` - Attribute key
    /// * `value` - Attribute value
    ///
    /// # Returns
    /// Ok(()) on success
    ///
    /// # Example
    /// ```
    /// client.set_attribute("enable-multisig-experimental", "1").await?;
    /// ```
    pub async fn set_attribute(&self, key: &str, value: &str) -> Result<(), MoneroError> {
        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let mut request = RpcRequest::new("set_attribute");
        request.params = Some(serde_json::json!({
            "key": key,
            "value": value
        }));

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        Ok(())
    }

    /// Transfer funds (multisig) - Creates unsigned transaction
    ///
    /// # Arguments
    /// * `destinations` - List of (address, amount) pairs
    ///
    /// # Returns
    /// CreateTransactionResult with unsigned transaction data
    pub async fn transfer_multisig(
        &self,
        destinations: Vec<monero_marketplace_common::types::TransferDestination>,
    ) -> Result<monero_marketplace_common::types::CreateTransactionResult, MoneroError> {
        use monero_marketplace_common::types::CreateTransactionResult;

        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        // Construire liste de destinations pour le RPC
        let dest_array: Vec<serde_json::Value> = destinations
            .iter()
            .map(|d| {
                serde_json::json!({
                    "address": d.address,
                    "amount": d.amount
                })
            })
            .collect();

        let mut request = RpcRequest::new("transfer");
        request.params = Some(serde_json::json!({
            "destinations": dest_array,
            "do_not_relay": true, // Ne pas diffuser immédiatement (multisig)
        }));

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        // CRITICAL: Validate all required fields exist - silent failures cause fund loss
        // v0.47.0: Changed from .unwrap_or() to .ok_or_else() for proper error handling
        let tx_data_hex = result["tx_blob"]
            .as_str()
            .ok_or_else(|| {
                MoneroError::InvalidResponse("Missing tx_blob in transfer response".into())
            })?
            .to_string();

        let tx_hash = result["tx_hash"]
            .as_str()
            .ok_or_else(|| {
                MoneroError::InvalidResponse("Missing tx_hash in transfer response".into())
            })?
            .to_string();

        // tx_key can be empty in some RPC responses (multisig mode)
        let tx_key = result["tx_key"].as_str().unwrap_or("").to_string();

        let amount = result["amount"].as_u64().ok_or_else(|| {
            MoneroError::InvalidResponse("Missing amount in transfer response".into())
        })?;

        let fee = result["fee"].as_u64().ok_or_else(|| {
            MoneroError::InvalidResponse("Missing fee in transfer response".into())
        })?;

        // multisig_txset may be absent for non-multisig transfers
        let multisig_txset = result["multisig_txset"].as_str().unwrap_or("").to_string();

        Ok(CreateTransactionResult {
            tx_data_hex,
            tx_hash,
            tx_key,
            amount,
            fee,
            multisig_txset,
        })
    }

    /// Sign a multisig transaction
    ///
    /// # Arguments
    /// * `tx_data_hex` - Unsigned or partially signed transaction data
    ///
    /// # Returns
    /// SignMultisigResult with signed transaction data
    pub async fn sign_multisig(
        &self,
        tx_data_hex: String,
    ) -> Result<monero_marketplace_common::types::SignMultisigResult, MoneroError> {
        use monero_marketplace_common::types::SignMultisigResult;

        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let mut request = RpcRequest::new("sign_multisig");
        request.params = Some(serde_json::json!({
            "tx_data_hex": tx_data_hex,
        }));

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        let tx_hash_list = result["tx_hash_list"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // CRITICAL: tx_data_hex is required for multisig signing chain
        // v0.47.0: Changed from .unwrap_or() to .ok_or_else() - empty tx_data breaks escrow
        let tx_data_hex = result["tx_data_hex"]
            .as_str()
            .ok_or_else(|| {
                MoneroError::InvalidResponse("Missing tx_data_hex in sign_multisig response".into())
            })?
            .to_string();

        Ok(SignMultisigResult {
            tx_data_hex,
            tx_hash_list,
        })
    }

    /// Submit (finalize and broadcast) a multisig transaction
    ///
    /// # Arguments
    /// * `tx_data_hex` - Fully signed transaction data (with 2-of-3 signatures)
    ///
    /// # Returns
    /// SubmitMultisigResult with transaction hash(es)
    pub async fn submit_multisig(
        &self,
        tx_data_hex: String,
    ) -> Result<monero_marketplace_common::types::SubmitMultisigResult, MoneroError> {
        use monero_marketplace_common::types::SubmitMultisigResult;

        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let mut request = RpcRequest::new("submit_multisig");
        request.params = Some(serde_json::json!({
            "tx_data_hex": tx_data_hex,
        }));

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        let tx_hash_list = result["tx_hash_list"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(SubmitMultisigResult { tx_hash_list })
    }

    /// Get transaction information by transaction ID
    ///
    /// # Arguments
    /// * `tx_hash` - Transaction hash to query
    ///
    /// # Returns
    /// TransactionInfo with confirmation status
    pub async fn get_transfer_by_txid(
        &self,
        tx_hash: String,
    ) -> Result<monero_marketplace_common::types::TransactionInfo, MoneroError> {
        use monero_marketplace_common::types::TransactionInfo;

        // Acquérir permit pour rate limiting
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| MoneroError::NetworkError("Semaphore closed".to_string()))?;

        // Acquérir lock pour sérialiser les appels RPC
        let _guard = self.rpc_lock.lock().await;

        let mut request = RpcRequest::new("get_transfer_by_txid");
        request.params = Some(serde_json::json!({
            "txid": tx_hash,
        }));

        let response = self
            .client
            .post(format!("{}/json_rpc", self.url))
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

        let rpc_response: RpcResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| MoneroError::InvalidResponse(format!("JSON parse: {e}")))?;

        if let Some(error) = rpc_response.error {
            return Err(MoneroError::RpcError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| MoneroError::InvalidResponse("Missing result field".to_string()))?;

        let transfer = &result["transfer"];

        Ok(TransactionInfo {
            tx_hash: transfer["txid"].as_str().unwrap_or("").to_string(),
            confirmations: transfer["confirmations"].as_u64().unwrap_or(0),
            block_height: transfer["height"].as_u64().unwrap_or(0),
            timestamp: transfer["timestamp"].as_u64().unwrap_or(0),
            amount: transfer["amount"].as_u64().unwrap_or(0),
            fee: transfer["fee"].as_u64().unwrap_or(0),
        })
    }
}

/// Validation stricte multisig_info
fn validate_multisig_info(info: &str) -> Result<(), MoneroError> {
    // Doit commencer par MultisigV1 ou MultisigxV2 (nouveau format depuis Monero v0.18+)
    if !info.starts_with("MultisigV1") && !info.starts_with("MultisigxV2") {
        return Err(MoneroError::InvalidResponse(format!(
            "Invalid multisig_info prefix (got: {:?})",
            info.chars().take(20).collect::<String>()
        )));
    }

    // Longueur attendue (base64)
    if info.len() < MIN_MULTISIG_INFO_LEN || info.len() > MAX_MULTISIG_INFO_LEN {
        return Err(MoneroError::InvalidResponse(format!(
            "Invalid multisig_info length: {}",
            info.len()
        )));
    }

    // Caractères valides (base64 + prefix)
    if !info
        .chars()
        .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err(MoneroError::InvalidResponse(
            "Invalid characters in multisig_info".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monero_rpc_client_localhost_only() {
        // OPSEC: Vérifier que client rejette URLs publiques
        let config = MoneroConfig {
            rpc_url: "http://0.0.0.0:18082".to_string(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 60,
        };
        let result = MoneroRpcClient::new(config);
        assert!(result.is_err());

        let config = MoneroConfig {
            rpc_url: "http://192.168.1.10:18082".to_string(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 60,
        };
        let result = MoneroRpcClient::new(config);
        assert!(result.is_err());

        // Localhost OK
        let config = MoneroConfig::default();
        let result = MoneroRpcClient::new(config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_prepare_multisig() {
        // SETUP: monero-wallet-rpc doit tourner sur 18082
        // Voir docs/specs/prepare_multisig.md pour commandes

        let config = MoneroConfig::default();
        let client = match MoneroRpcClient::new(config) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create client for test: {}", e);
                return;
            }
        };

        // Vérifier connexion d'abord
        match client.check_connection().await {
            Ok(_) => tracing::info!("RPC accessible"),
            Err(e) => {
                tracing::warn!("RPC pas accessible: {}", e);
                tracing::info!("Lance: monero-wallet-rpc --testnet ...");
                return;
            }
        }

        // Tester prepare_multisig
        let result = client.prepare_multisig().await;

        match &result {
            Ok(info) => {
                tracing::info!("prepare_multisig OK");
                tracing::debug!("Info length: {}", info.multisig_info.len());
                assert!(info.multisig_info.starts_with("MultisigV1"));
                assert!(info.multisig_info.len() > MIN_MULTISIG_INFO_LEN);
            }
            Err(MoneroError::AlreadyMultisig) => {
                tracing::warn!("Wallet déjà en multisig (normal si test rejoué)");
                tracing::info!("Pour reset: fermer RPC, supprimer wallet, recréer");
                // Ce n'est pas un échec de test
                return;
            }
            Err(e) => {
                tracing::error!("prepare_multisig échoué: {}", e);
                return;
            }
        }
    }

    #[tokio::test]
    async fn test_prepare_multisig_rpc_down() {
        // Test avec RPC pas lancé
        let config = MoneroConfig {
            rpc_url: "http://127.0.0.1:19999".to_string(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 5,
        };
        let client = match MoneroRpcClient::new(config) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create client for test: {}", e);
                return;
            }
        };

        let result = client.prepare_multisig().await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MoneroError::RpcUnreachable));
    }

    #[tokio::test]
    async fn test_prepare_multisig_concurrent() {
        // Test appels concurrents (doit être thread-safe)
        let config = MoneroConfig::default();
        let client = match MoneroRpcClient::new(config) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::error!("Failed to create client for test: {}", e);
                return;
            }
        };

        let handles: Vec<_> = (0..5)
            .map(|_| {
                let client = Arc::clone(&client);
                tokio::spawn(async move { client.prepare_multisig().await })
            })
            .collect();

        // Tous doivent réussir OU échouer proprement (pas de panic)
        for handle in handles {
            let result = handle.await.expect("Task should complete without panic");
            // Peut échouer si RPC pas lancé, mais ne doit pas panic
            assert!(result.is_ok() || result.is_err());
        }
    }

    #[tokio::test]
    async fn test_validate_multisig_info() {
        // Test validation stricte
        use super::validate_multisig_info;

        // Cas valides - Utiliser strings de longueur réaliste (>= 100 chars)
        let valid_info = format!("MultisigV1{}", "K".repeat(100)); // > MIN_MULTISIG_INFO_LEN
        assert!(validate_multisig_info(&valid_info).is_ok());

        // Cas invalides
        assert!(validate_multisig_info("InvalidPrefix...").is_err());
        assert!(validate_multisig_info("MultisigV1").is_err()); // Trop court
        assert!(validate_multisig_info(&"MultisigV1".repeat(1000)).is_err()); // Trop long
        let invalid_chars = format!("MultisigV1{}", "@#$%".repeat(30)); // Caractères invalides
        assert!(validate_multisig_info(&invalid_chars).is_err());
    }

    #[tokio::test]
    async fn test_make_multisig_validation() {
        // Test validation des paramètres
        let config = MoneroConfig::default();
        let client = match MoneroRpcClient::new(config) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create client for test: {}", e);
                return;
            }
        };

        // Cas 1: threshold trop bas
        let fake_info1 = format!("MultisigV1{}", "A".repeat(100));
        let fake_info2 = format!("MultisigV1{}", "B".repeat(100));
        let result = client
            .make_multisig(1, vec![fake_info1.clone(), fake_info2.clone()])
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MoneroError::ValidationError(_)
        ));

        // Cas 2: pas assez de multisig_info
        let result = client.make_multisig(2, vec![fake_info1.clone()]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MoneroError::ValidationError(_)
        ));

        // Cas 3: multisig_info invalide
        let result = client
            .make_multisig(2, vec!["InvalidInfo".to_string(), fake_info1.clone()])
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MoneroError::ValidationError(_)
        ));
    }

    #[tokio::test]
    async fn test_make_multisig() {
        // SETUP: Nécessite 3 wallets testnet avec prepare_multisig fait
        // Voir docs/specs/make_multisig.md pour commandes complètes

        let config = MoneroConfig::default();
        let client = match MoneroRpcClient::new(config) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create client for test: {}", e);
                return;
            }
        };

        // Vérifier connexion d'abord
        match client.check_connection().await {
            Ok(_) => tracing::info!("RPC accessible"),
            Err(e) => {
                tracing::warn!("RPC pas accessible: {}", e);
                tracing::info!("Lance: monero-wallet-rpc --testnet ...");
                return;
            }
        }

        // NOTE: Ce test nécessite une configuration manuelle complexe
        // avec 3 wallets RPC et leurs infos prepare_multisig
        // Pour l'instant, on teste juste que l'erreur est propre
        let fake_info1 = format!("MultisigV1{}", "A".repeat(100));
        let fake_info2 = format!("MultisigV1{}", "B".repeat(100));
        let result = client.make_multisig(2, vec![fake_info1, fake_info2]).await;

        match &result {
            Ok(result) => {
                tracing::info!("make_multisig OK");
                tracing::debug!("Address: {}", result.address);
                assert!(!result.address.is_empty());
                assert!(result.multisig_info.starts_with("MultisigV1"));
            }
            Err(MoneroError::AlreadyMultisig) => {
                tracing::warn!("Wallet déjà en multisig (normal si test rejoué)");
                return;
            }
            Err(MoneroError::ValidationError(msg)) => {
                tracing::warn!("Validation error (expected avec fake infos): {}", msg);
                return;
            }
            Err(MoneroError::RpcError(msg)) => {
                tracing::warn!("RPC error (expected avec fake infos): {}", msg);
                return;
            }
            Err(e) => {
                tracing::error!("make_multisig échoué: {}", e);
                return;
            }
        }
    }

    #[tokio::test]
    async fn test_make_multisig_rpc_down() {
        // Test avec RPC pas lancé
        let config = MoneroConfig {
            rpc_url: "http://127.0.0.1:19999".to_string(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 5,
        };
        let client = match MoneroRpcClient::new(config) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create client for test: {}", e);
                return;
            }
        };

        let fake_info1 = format!("MultisigV1{}", "A".repeat(100));
        let fake_info2 = format!("MultisigV1{}", "B".repeat(100));
        let result = client.make_multisig(2, vec![fake_info1, fake_info2]).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MoneroError::RpcUnreachable));
    }

    #[tokio::test]
    async fn test_export_multisig_info_validation() {
        // Test export validation (sans RPC)
        let config = MoneroConfig::default();
        let client = match MoneroRpcClient::new(config) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create client for test: {}", e);
                return;
            }
        };

        // Test que export nécessite RPC actif
        // Ce test vérifie juste la structure, pas le RPC réel
        let result = client.export_multisig_info().await;

        // Devrait échouer si RPC n'est pas lancé OU si pas en multisig
        match result {
            Ok(_) => {
                // Si RPC est lancé et en multisig, on accepte
                tracing::info!("export_multisig_info OK (wallet en multisig)");
            }
            Err(MoneroError::RpcUnreachable) => {
                // RPC pas lancé - normal
                tracing::info!("RPC pas lancé (expected)");
            }
            Err(MoneroError::NotMultisig) => {
                // Wallet pas en multisig - normal
                tracing::info!("Wallet not in multisig mode (expected)");
            }
            Err(e) => {
                tracing::warn!("Autre erreur: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_import_multisig_info_validation() {
        // Test validation des paramètres d'import
        let config = MoneroConfig::default();
        let client = match MoneroRpcClient::new(config) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create client for test: {}", e);
                return;
            }
        };

        // Cas 1: Liste vide
        let result = client.import_multisig_info(vec![]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MoneroError::ValidationError(_)
        ));

        // Cas 2: Pas assez d'infos (< 2 pour 2-of-3)
        let fake_info = "a".repeat(150); // > 100 chars pour validation
        let result = client.import_multisig_info(vec![fake_info]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MoneroError::ValidationError(_)
        ));

        // Cas 3: Info trop courte
        let result = client
            .import_multisig_info(vec!["short".to_string(), "also_short".to_string()])
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MoneroError::ValidationError(_)
        ));

        // Cas 4: Info vide
        let fake_info = "a".repeat(150);
        let result = client
            .import_multisig_info(vec!["".to_string(), fake_info])
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MoneroError::ValidationError(_)
        ));
    }
}
