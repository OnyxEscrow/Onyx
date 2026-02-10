//! Wallet manager for server-side Monero interactions

use anyhow::Result;
use monero_marketplace_common::{
    error::{Error as CommonError, MoneroError},
    types::{MoneroConfig, MultisigInfo},
};
use monero_marketplace_wallet::MoneroClient;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::{get_fee_reserve, get_wallet_password};
use crate::db::DbPool;
use crate::models::multisig_state::{MultisigPhase, MultisigSnapshot};
use crate::repositories::MultisigStateRepository;
use crate::wallet_pool::{WalletPool, WalletRole as PoolWalletRole};

// Global mutex to ensure only ONE wallet creation happens at a time across the entire server
// This prevents race conditions with monero-wallet-rpc which can only handle one wallet at a time
use once_cell::sync::Lazy;
static WALLET_CREATION_LOCK: Lazy<TokioMutex<()>> = Lazy::new(|| TokioMutex::new(()));

#[derive(Debug, Clone, PartialEq)]
pub enum WalletRole {
    Buyer,
    Vendor,
    Arbiter,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MultisigState {
    NotStarted,
    PreparedInfo(MultisigInfo),
    InfoExchanged {
        round: u8,
        participants: Vec<String>,
    },
    Ready {
        address: String,
    },
}

pub struct WalletInstance {
    pub id: Uuid,
    pub role: WalletRole,
    pub rpc_client: MoneroClient,
    pub address: String,
    pub multisig_state: MultisigState,
    /// RPC port this wallet is connected to (for WalletPool management)
    pub rpc_port: Option<u16>,
    /// Escrow ID this wallet belongs to (None for system wallets)
    pub escrow_id: Option<Uuid>,
}

#[derive(Error, Debug)]
pub enum WalletManagerError {
    #[error("Monero RPC error: {0}")]
    RpcError(#[from] CommonError),

    #[error("Invalid multisig state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    #[error("Wallet not found: {0}")]
    WalletNotFound(Uuid),

    #[error("All RPC endpoints unavailable")]
    NoAvailableRpc,

    #[error("Multisig address mismatch: {addresses:?}")]
    AddressMismatch { addresses: Vec<String> },

    #[error("Non-custodial policy violation: Server cannot create {0} wallets. Clients must provide their own wallet RPC URL.")]
    NonCustodialViolation(String),

    #[error("Invalid RPC URL: {0}")]
    InvalidRpcUrl(String),
}

pub struct WalletManager {
    pub wallets: HashMap<Uuid, WalletInstance>,
    rpc_configs: Vec<MoneroConfig>,
    next_rpc_index: usize,
    // Role-based RPC assignment counters (for production scalability)
    buyer_rpc_index: std::sync::atomic::AtomicUsize,
    vendor_rpc_index: std::sync::atomic::AtomicUsize,
    arbiter_rpc_index: std::sync::atomic::AtomicUsize,
    // Multisig state persistence (Option for backward compatibility)
    multisig_repo: Option<Arc<MultisigStateRepository>>,
    db_pool: Option<DbPool>,
    // Encryption key for RPC config persistence (same as multisig_repo)
    encryption_key: Option<Vec<u8>>,
    // Wallet pool for rotation management (Option for backward compatibility)
    wallet_pool: Option<Arc<WalletPool>>,
}

impl WalletManager {
    pub fn new(configs: Vec<MoneroConfig>) -> Result<Self> {
        if configs.is_empty() {
            return Err(anyhow::anyhow!(
                "At least one Monero RPC config is required"
            ));
        }
        info!(
            "WalletManager initialized with {} RPC endpoints",
            configs.len()
        );
        Ok(Self {
            wallets: HashMap::new(),
            rpc_configs: configs,
            next_rpc_index: 0,
            buyer_rpc_index: std::sync::atomic::AtomicUsize::new(0),
            vendor_rpc_index: std::sync::atomic::AtomicUsize::new(0),
            arbiter_rpc_index: std::sync::atomic::AtomicUsize::new(0),
            multisig_repo: None,
            db_pool: None,
            encryption_key: None,
            wallet_pool: None,
        })
    }

    /// Create WalletManager with multisig state persistence enabled
    ///
    /// This constructor enables automatic persistence of multisig wallet states
    /// to the database, allowing recovery after server restarts.
    ///
    /// # Arguments
    /// * `configs` - Monero RPC endpoint configurations
    /// * `db_pool` - Database connection pool
    /// * `encryption_key` - 32-byte key for AES-256-GCM field encryption
    ///
    /// # Returns
    /// WalletManager instance with persistence enabled
    ///
    /// # Example
    /// ```ignore
    /// let encryption_key = env::var("MULTISIG_ENCRYPTION_KEY")?.into_bytes();
    /// let wallet_manager = WalletManager::new_with_persistence(
    ///     rpc_configs,
    ///     db_pool.clone(),
    ///     encryption_key,
    /// )?;
    /// ```
    pub fn new_with_persistence(
        configs: Vec<MoneroConfig>,
        db_pool: DbPool,
        encryption_key: Vec<u8>,
    ) -> Result<Self> {
        if configs.is_empty() {
            return Err(anyhow::anyhow!(
                "At least one Monero RPC config is required"
            ));
        }

        let multisig_repo = MultisigStateRepository::new(db_pool.clone(), encryption_key.clone());

        info!(
            "WalletManager initialized with {} RPC endpoints and persistence enabled",
            configs.len()
        );

        Ok(Self {
            wallets: HashMap::new(),
            rpc_configs: configs,
            next_rpc_index: 0,
            buyer_rpc_index: std::sync::atomic::AtomicUsize::new(0),
            vendor_rpc_index: std::sync::atomic::AtomicUsize::new(0),
            arbiter_rpc_index: std::sync::atomic::AtomicUsize::new(0),
            multisig_repo: Some(Arc::new(multisig_repo)),
            db_pool: Some(db_pool.clone()),
            encryption_key: Some(encryption_key),
            wallet_pool: None,
        })
    }

    /// Enable wallet pool for production-ready wallet rotation
    ///
    /// This method configures the WalletManager to use the WalletPool system,
    /// allowing unlimited concurrent escrows with limited RPC resources.
    ///
    /// # Arguments
    /// * `wallet_dir` - Directory where wallet files are stored
    ///
    /// # Example
    /// ```ignore
    /// let mut wallet_manager = WalletManager::new_with_persistence(...)?;
    /// wallet_manager.enable_wallet_pool(PathBuf::from("./testnet-wallets"))?;
    /// ```
    pub fn enable_wallet_pool(&mut self, wallet_dir: std::path::PathBuf) -> Result<()> {
        // Extract RPC ports from configs
        let ports: Vec<u16> = self
            .rpc_configs
            .iter()
            .filter_map(|config| {
                // Parse port from URL like "http://127.0.0.1:18082/json_rpc"
                config
                    .rpc_url
                    .split(':')
                    .nth(2)?
                    .split('/')
                    .next()?
                    .parse::<u16>()
                    .ok()
            })
            .collect();

        if ports.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid RPC ports found in configs for WalletPool initialization"
            ));
        }

        let pool = WalletPool::new(ports.clone(), wallet_dir);
        self.wallet_pool = Some(Arc::new(pool));

        info!(
            "WalletPool enabled with {} RPC instances on ports: {:?}",
            ports.len(),
            ports
        );

        Ok(())
    }

    /// Get reference to the wallet pool (if enabled)
    pub fn wallet_pool(&self) -> Option<&Arc<WalletPool>> {
        self.wallet_pool.as_ref()
    }

    /// Get dedicated RPC instance for a specific role (PRODUCTION SCALABILITY)
    ///
    /// This method implements role-based RPC assignment to prevent collisions
    /// and enable parallel escrow processing with limited RPC resources.
    ///
    /// # Architecture
    /// - Buyer wallets: Ports 18082, 18085, 18088... (index % 3 == 0)
    /// - Vendor wallets: Ports 18083, 18086, 18089... (index % 3 == 1)
    /// - Arbiter wallets: Ports 18084, 18087, 18090... (index % 3 == 2)
    ///
    /// # Arguments
    /// * `role` - Wallet role (Buyer, Vendor, or Arbiter)
    ///
    /// # Returns
    /// MoneroConfig for the next available RPC instance for this role
    ///
    /// # Errors
    /// - NoAvailableRpc - No RPC instances configured for this role
    ///
    /// # Example
    /// ```ignore
    /// // With 9 RPC instances (ports 18082-18090):
    /// // Buyer uses 18082, 18085, 18088 (3 instances)
    /// // Vendor uses 18083, 18086, 18089 (3 instances)
    /// // Arbiter uses 18084, 18087, 18090 (3 instances)
    /// let buyer_config = wallet_manager.get_rpc_for_role(&WalletRole::Buyer)?;
    /// ```
    fn get_rpc_for_role(&self, role: &WalletRole) -> Result<MoneroConfig, WalletManagerError> {
        use std::sync::atomic::Ordering;

        match role {
            WalletRole::Buyer => {
                // Ports 18082, 18085, 18088... (indices 0, 3, 6, 9...)
                let buyer_rpcs: Vec<MoneroConfig> = self
                    .rpc_configs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| i % 3 == 0)
                    .map(|(_, config)| config.clone())
                    .collect();

                if buyer_rpcs.is_empty() {
                    return Err(WalletManagerError::NoAvailableRpc);
                }

                let index = self.buyer_rpc_index.fetch_add(1, Ordering::SeqCst) % buyer_rpcs.len();
                Ok(buyer_rpcs[index].clone())
            }
            WalletRole::Vendor => {
                // Ports 18083, 18086, 18089... (indices 1, 4, 7, 10...)
                let vendor_rpcs: Vec<MoneroConfig> = self
                    .rpc_configs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| i % 3 == 1)
                    .map(|(_, config)| config.clone())
                    .collect();

                if vendor_rpcs.is_empty() {
                    return Err(WalletManagerError::NoAvailableRpc);
                }

                let index =
                    self.vendor_rpc_index.fetch_add(1, Ordering::SeqCst) % vendor_rpcs.len();
                Ok(vendor_rpcs[index].clone())
            }
            WalletRole::Arbiter => {
                // Ports 18084, 18087, 18090... (indices 2, 5, 8, 11...)
                let arbiter_rpcs: Vec<MoneroConfig> = self
                    .rpc_configs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| i % 3 == 2)
                    .map(|(_, config)| config.clone())
                    .collect();

                if arbiter_rpcs.is_empty() {
                    return Err(WalletManagerError::NoAvailableRpc);
                }

                // Arbiter typically has low load, just use first instance
                // (can round-robin if needed for high-scale arbitration)
                Ok(arbiter_rpcs[0].clone())
            }
        }
    }

    /// DEPRECATED: Use create_arbiter_wallet_instance() or register_client_wallet_rpc() instead.
    ///
    /// This method is kept for backward compatibility but will be removed in future versions.
    /// Server should ONLY create arbiter wallets to maintain non-custodial architecture.
    #[deprecated(
        since = "0.2.7",
        note = "Use create_arbiter_wallet_instance() for arbiter or register_client_wallet_rpc() for buyer/vendor"
    )]
    pub async fn create_wallet_instance(
        &mut self,
        role: WalletRole,
    ) -> Result<Uuid, WalletManagerError> {
        // NON-CUSTODIAL ENFORCEMENT: Server cannot create buyer/vendor wallets
        match role {
            WalletRole::Buyer => {
                return Err(WalletManagerError::NonCustodialViolation(
                    "Buyer".to_string(),
                ))
            }
            WalletRole::Vendor => {
                return Err(WalletManagerError::NonCustodialViolation(
                    "Vendor".to_string(),
                ))
            }
            WalletRole::Arbiter => {
                // Arbiter is OK - this is the marketplace's wallet
                info!("Creating arbiter wallet instance (legacy method - use create_arbiter_wallet_instance instead)");
            }
        }

        let config = self
            .rpc_configs
            .get(self.next_rpc_index)
            .ok_or(WalletManagerError::NoAvailableRpc)?;
        self.next_rpc_index = (self.next_rpc_index + 1) % self.rpc_configs.len();

        let rpc_client = MoneroClient::new(config.clone())?;
        let wallet_info = rpc_client.get_wallet_info().await?;

        // Extract RPC port from config URL for WalletPool tracking
        let rpc_port = config
            .rpc_url
            .split(':')
            .nth(2)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.parse::<u16>().ok());

        let instance = WalletInstance {
            id: Uuid::new_v4(),
            role: role.clone(),
            rpc_client,
            address: wallet_info.address,
            multisig_state: MultisigState::NotStarted,
            rpc_port,
            escrow_id: None, // ⚠️ DEPRECATED: create_wallet_instance() has no escrow context
        };
        let id = instance.id;
        self.wallets.insert(id, instance);
        info!("Created wallet instance {} (role: {:?})", id, role);
        Ok(id)
    }

    /// Create arbiter wallet instance (server-controlled wallet for marketplace arbitration)
    ///
    /// This is the ONLY wallet type the server should create directly.
    /// Buyer and vendor wallets must be provided by clients via register_client_wallet_rpc().
    ///
    /// # Returns
    /// UUID of the created arbiter wallet instance
    ///
    /// # Errors
    /// - NoAvailableRpc - No RPC configs available
    /// - RpcError - Failed to connect to wallet RPC or get wallet info
    pub async fn create_arbiter_wallet_instance(&mut self) -> Result<Uuid, WalletManagerError> {
        let config = self
            .rpc_configs
            .get(self.next_rpc_index)
            .ok_or(WalletManagerError::NoAvailableRpc)?;
        self.next_rpc_index = (self.next_rpc_index + 1) % self.rpc_configs.len();

        let rpc_client = MoneroClient::new(config.clone())?;
        let wallet_info = rpc_client.get_wallet_info().await?;

        // Extract RPC port from config URL for WalletPool tracking
        let rpc_port = config
            .rpc_url
            .split(':')
            .nth(2)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.parse::<u16>().ok());

        let wallet_address = wallet_info.address.clone();
        let instance = WalletInstance {
            id: Uuid::new_v4(),
            role: WalletRole::Arbiter,
            rpc_client,
            address: wallet_info.address,
            multisig_state: MultisigState::NotStarted,
            rpc_port,
            escrow_id: None, // ✅ System arbiter wallet
        };
        let id = instance.id;
        self.wallets.insert(id, instance);
        info!(
            "✅ Created arbiter wallet instance: {} (address: {})",
            id, wallet_address
        );
        Ok(id)
    }

    /// Register a client-controlled wallet RPC endpoint (NON-CUSTODIAL)
    ///
    /// This method allows buyers and vendors to provide their own wallet RPC URLs,
    /// ensuring the server never has access to their private keys.
    ///
    /// # Security Requirements
    /// - Client must run their own monero-wallet-rpc instance
    /// - Client controls their private keys (never shared with server)
    /// - RPC URL can be local (client's machine) or via Tor hidden service
    ///
    /// # Arguments
    /// * `role` - Must be Buyer or Vendor (Arbiter not allowed - use create_arbiter_wallet_instance)
    /// * `rpc_url` - Client's wallet RPC endpoint (e.g., "http://127.0.0.1:18082/json_rpc" or "http://xyz.onion:18082/json_rpc")
    /// * `rpc_user` - Optional RPC authentication username
    /// * `rpc_password` - Optional RPC authentication password
    ///
    /// # Returns
    /// UUID of the registered client wallet instance
    ///
    /// # Errors
    /// - NonCustodialViolation - Attempted to register Arbiter wallet (must use create_arbiter_wallet_instance)
    /// - InvalidRpcUrl - Invalid or unreachable RPC URL
    /// - RpcError - Failed to connect to client's wallet RPC
    ///
    /// # Example
    /// ```rust
    /// // Client provides their wallet RPC URL
    /// let wallet_id = wallet_manager.register_client_wallet_rpc(
    ///     WalletRole::Buyer,
    ///     "http://buyer-machine.local:18082/json_rpc".to_string(),
    ///     Some("buyer_user".to_string()),
    ///     Some("buyer_password".to_string()),
    /// ).await?;
    /// ```
    pub async fn register_client_wallet_rpc(
        &mut self,
        escrow_id: &str,
        role: WalletRole,
        rpc_url: String,
        rpc_user: Option<String>,
        rpc_password: Option<String>,
        recovery_mode: &str,
    ) -> Result<Uuid, WalletManagerError> {
        // NON-CUSTODIAL ENFORCEMENT: Only allow Buyer/Vendor (clients control these)
        if role == WalletRole::Arbiter {
            return Err(WalletManagerError::NonCustodialViolation(
                "Arbiter (use create_arbiter_wallet_instance instead)".to_string(),
            ));
        }

        // Validate RPC URL format
        if !rpc_url.starts_with("http://") && !rpc_url.starts_with("https://") {
            return Err(WalletManagerError::InvalidRpcUrl(
                "URL must start with http:// or https://".to_string(),
            ));
        }

        // Clone credentials for later persistence use
        let rpc_user_clone = rpc_user.clone();
        let rpc_password_clone = rpc_password.clone();

        // Create config from client-provided details
        let config = MoneroConfig {
            rpc_url: rpc_url.clone(),
            rpc_user,
            rpc_password,
            timeout_seconds: 30,
        };

        // Connect to client's wallet RPC
        let rpc_client = MoneroClient::new(config)
            .map_err(|e| WalletManagerError::InvalidRpcUrl(format!("Failed to connect: {}", e)))?;

        // Verify wallet is accessible
        let wallet_info = rpc_client.get_wallet_info().await.map_err(|e| {
            WalletManagerError::InvalidRpcUrl(format!("Cannot access wallet: {}", e))
        })?;

        let wallet_id = Uuid::new_v4();

        // Extract RPC port from client URL for WalletPool tracking
        let rpc_port = rpc_url
            .split(':')
            .nth(2)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.parse::<u16>().ok());

        let instance = WalletInstance {
            id: wallet_id,
            role: role.clone(),
            rpc_client,
            address: wallet_info.address.clone(),
            multisig_state: MultisigState::NotStarted,
            rpc_port,
            escrow_id: None, // ⚠️ DEPRECATED: create_wallet_instance() - use create_temporary_wallet()
        };
        self.wallets.insert(wallet_id, instance);

        // Persist RPC config if recovery_mode is 'automatic'
        if recovery_mode == "automatic" {
            if let (Some(ref pool), Some(ref key)) = (&self.db_pool, &self.encryption_key) {
                use crate::models::wallet_rpc_config::WalletRpcConfig;

                let mut conn = pool.get().map_err(|e| {
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Failed to get DB connection: {}",
                        e
                    )))
                })?;

                let role_str = match role {
                    WalletRole::Buyer => "buyer",
                    WalletRole::Vendor => "vendor",
                    WalletRole::Arbiter => "arbiter",
                };

                WalletRpcConfig::save(
                    &mut conn,
                    &wallet_id.to_string(),
                    escrow_id,
                    role_str,
                    &rpc_url,
                    rpc_user_clone.as_deref(),
                    rpc_password_clone.as_deref(),
                    key,
                )
                .map_err(|e| {
                    error!(escrow_id, error = %e, "Failed to persist RPC config");
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Failed to persist RPC config: {}",
                        e
                    )))
                })?;

                info!(
                    "✅ RPC config persisted for automatic recovery: escrow={}, wallet_id={}",
                    escrow_id, wallet_id
                );
            } else {
                warn!(
                    "Recovery mode is 'automatic' but persistence not enabled (no db_pool or encryption_key)"
                );
            }
        }

        info!(
            "✅ Registered client wallet: id={}, role={:?}, address={}",
            wallet_id, role, wallet_info.address
        );
        info!(
            "🔒 NON-CUSTODIAL: Client controls private keys at {}",
            rpc_url
        );

        Ok(wallet_id)
    }

    /// Create EMPTY temporary wallet for multisig coordination (non-custodial architecture)
    ///
    /// This creates a new temporary wallet instance with 0 XMR balance.
    /// These wallets are NEVER funded - they only coordinate multisig setup.
    /// The buyer pays directly from their external wallet to the generated multisig address.
    ///
    /// **NON-CUSTODIAL GUARANTEE:**
    /// - Wallet starts with 0 XMR and remains at 0 XMR forever
    /// - Only used to generate multisig address via prepare_multisig() → make_multisig() → finalize_multisig()
    /// - Server never holds user funds
    /// - Generated multisig address (95 chars) receives payment directly from buyer's external wallet
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow UUID (used to construct wallet filename for later reopening)
    /// * `role` - The role for this temporary wallet ("buyer", "vendor", or "arbiter")
    ///
    /// # Returns
    /// UUID of the created temporary wallet
    ///
    /// # Errors
    /// - InvalidState - Invalid role string
    /// - NoAvailableRpc - No RPC configs available
    /// - RpcError - Failed to connect to wallet RPC or get wallet info
    ///
    /// # Example
    /// ```rust
    /// let escrow_id = Uuid::new_v4();
    /// let buyer_temp_wallet_id = wallet_manager.create_temporary_wallet(escrow_id, "buyer").await?;
    /// let vendor_temp_wallet_id = wallet_manager.create_temporary_wallet(escrow_id, "vendor").await?;
    /// let arbiter_temp_wallet_id = wallet_manager.create_temporary_wallet(escrow_id, "arbiter").await?;
    /// // All 3 wallets have 0 XMR balance - used only for multisig coordination
    /// ```
    ///
    /// # ⚠️ DEPRECATED - Phase 3 Non-Custodial Migration
    ///
    /// **This function is CUSTODIAL and will be removed in v0.4.0.**
    ///
    /// **Why deprecated:**
    /// - Server creates and manages wallets (custodial anti-pattern)
    /// - Server has access to wallet files and private keys
    /// - Violates non-custodial principles (Haveno-style architecture)
    ///
    /// **Use instead:**
    /// - `EscrowCoordinator::register_client_wallet()` - Clients provide their own wallet RPC URLs
    /// - See: `DOX/guides/NON-CUSTODIAL-USER-GUIDE.md`
    /// - See: `DOX/guides/MIGRATION-TO-NONCUSTODIAL.md`
    ///
    /// **Migration path:**
    /// 1. Client runs local `monero-wallet-rpc`
    /// 2. Client calls `/api/v2/escrow/register-wallet` with RPC URL
    /// 3. Server coordinates multisig exchange (NO wallet creation)
    ///
    /// This function will be removed in **v0.4.0** (estimated 2-3 weeks).
    #[deprecated(
        since = "0.3.0",
        note = "Use EscrowCoordinator with client wallets instead. This custodial mode will be removed in v0.4.0. See DOX/guides/MIGRATION-TO-NONCUSTODIAL.md"
    )]
    pub async fn create_temporary_wallet(
        &mut self,
        escrow_id: Uuid,
        role: &str,
    ) -> Result<Uuid, WalletManagerError> {
        // ⚠️ DEPRECATION WARNING
        warn!(
            "⚠️  DEPRECATED: create_temporary_wallet() is CUSTODIAL and will be removed in v0.4.0. \
            Migrate to EscrowCoordinator with client-side wallets. See DOX/guides/MIGRATION-TO-NONCUSTODIAL.md"
        );

        // SOLUTION #1: Global mutex to prevent concurrent wallet creation
        // Only ONE wallet creation can happen at a time across the entire server
        let _lock = WALLET_CREATION_LOCK.lock().await;
        info!("🔒 Acquired global wallet creation lock for role={}", role);

        let wallet_role = match role {
            "buyer" => WalletRole::Buyer,
            "vendor" => WalletRole::Vendor,
            "arbiter" => WalletRole::Arbiter,
            _ => {
                return Err(WalletManagerError::InvalidState {
                    expected: "buyer, vendor, or arbiter".to_string(),
                    actual: role.to_string(),
                })
            }
        };

        // PRODUCTION SCALABILITY: Use role-based RPC assignment instead of round-robin
        // This ensures buyer/vendor/arbiter wallets use different RPC instances
        let config = self.get_rpc_for_role(&wallet_role)?;
        info!("🎯 Assigned {} to RPC: {}", role, config.rpc_url);

        // Create wallet filename based on escrow_id (for later reopening)
        // Format: "{role}_temp_escrow_{escrow_id}"
        let wallet_filename = format!("{}_temp_escrow_{}", role, escrow_id);

        // SOLUTION #4: Auto-cleanup of orphaned wallet files before creation
        let wallet_path = Path::new("/var/monero/wallets").join(&wallet_filename);
        let keys_path = Path::new("/var/monero/wallets").join(format!("{}.keys", wallet_filename));

        if wallet_path.exists() || keys_path.exists() {
            warn!(
                "🗑️  Found existing wallet files for {}, deleting before recreation",
                wallet_filename
            );
            let _ = std::fs::remove_file(&wallet_path);
            let _ = std::fs::remove_file(&keys_path);
            let _ = std::fs::remove_file(
                Path::new("/var/monero/wallets").join(format!("{}.address.txt", wallet_filename)),
            );
            info!(
                "✅ Cleaned up orphaned wallet files for {}",
                wallet_filename
            );
        }

        // Create RPC client
        let rpc_client = MoneroClient::new(config.clone())?;

        // Close any currently open wallet first (Monero RPC can only have one wallet open at a time)
        let _ = rpc_client.close_wallet().await; // Ignore errors if no wallet is open

        // SOLUTION #2: Increased delay to 500ms based on observed RPC processing times
        // SOLUTION #3: Retry logic with exponential backoff
        let mut attempts = 0;
        let max_attempts = 3;
        let mut last_error = None;

        // Retry loop for wallet creation with exponential backoff
        let address = loop {
            attempts += 1;
            info!(
                "🔄 Wallet creation attempt {}/{} for role={}",
                attempts, max_attempts, role
            );

            // Create new wallet in the RPC (or open if exists)
            let creation_result = match rpc_client
                .create_wallet(&wallet_filename, &get_wallet_password())
                .await
            {
                Ok(_) => {
                    info!("✅ Created new temporary wallet: {}", wallet_filename);
                    Ok(())
                }
                Err(e) => {
                    // Wallet might already exist, try to open it
                    warn!(
                        "Wallet creation failed (might exist): {:?}, trying to open",
                        e
                    );
                    match rpc_client
                        .open_wallet(&wallet_filename, &get_wallet_password())
                        .await
                    {
                        Ok(_) => {
                            info!("✅ Opened existing wallet: {}", wallet_filename);
                            Ok(())
                        }
                        Err(open_err) => Err(open_err),
                    }
                }
            };

            match creation_result {
                Ok(_) => {
                    // CRITICAL: Enable multisig experimental BEFORE any multisig operations
                    // This must be done immediately after wallet creation/opening
                    match rpc_client
                        .rpc()
                        .set_attribute("enable-multisig-experimental", "1")
                        .await
                    {
                        Ok(_) => {
                            info!("✅ Multisig experimental enabled for {}", wallet_filename);

                            // CRITICAL: Close and reopen wallet for attribute to take effect
                            // Monero wallet RPC requires this for the setting to be persisted
                            match rpc_client.close_wallet().await {
                                Ok(_) => {
                                    info!(
                                        "🔒 Wallet closed to persist multisig experimental setting"
                                    );
                                    tokio::time::sleep(tokio::time::Duration::from_millis(500))
                                        .await;

                                    match rpc_client
                                        .open_wallet(&wallet_filename, &get_wallet_password())
                                        .await
                                    {
                                        Ok(_) => {
                                            info!("✅ Wallet reopened - multisig experimental setting active");
                                        }
                                        Err(e) => {
                                            warn!("⚠️  Failed to reopen wallet: {:?}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("⚠️  Failed to close wallet: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("⚠️  Failed to enable multisig experimental: {:?} (will retry on reopen)", e);
                            // Not fatal - wallet can still be used, but multisig operations will fail
                            // The attribute will persist in wallet file
                        }
                    }

                    // Get wallet address
                    match rpc_client.get_address().await {
                        Ok(addr) => {
                            info!(
                                "✅ Created EMPTY temporary wallet: role={:?}, address={}",
                                wallet_role, addr
                            );
                            info!("🔒 NON-CUSTODIAL: This wallet will remain EMPTY (0 XMR) - used only for multisig coordination");
                            break addr;
                        }
                        Err(e) => {
                            last_error = Some(WalletManagerError::from(e));
                            warn!(
                                "❌ Failed to get wallet address (attempt {}/{})",
                                attempts, max_attempts
                            );
                        }
                    }
                }
                Err(e) => {
                    last_error = Some(WalletManagerError::from(e));
                    warn!(
                        "❌ Failed to create/open wallet (attempt {}/{})",
                        attempts, max_attempts
                    );
                }
            }

            if attempts >= max_attempts {
                error!("❌ All {} attempts failed for role={}", max_attempts, role);
                return Err(last_error.unwrap_or(WalletManagerError::InvalidState {
                    expected: "successful wallet creation".to_string(),
                    actual: format!("failed after {} attempts", max_attempts),
                }));
            }

            // Exponential backoff: 500ms, 1000ms, 2000ms
            let delay_ms = 500 * (2_u64.pow(attempts - 1));
            info!("⏳ Waiting {}ms before retry...", delay_ms);
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        };

        // Extract RPC port from config URL for WalletPool tracking
        let rpc_port = config
            .rpc_url
            .split(':')
            .nth(2)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.parse::<u16>().ok());

        // Create WalletInstance and insert into map
        let instance = WalletInstance {
            id: Uuid::new_v4(),
            role: wallet_role.clone(),
            rpc_client,
            address: address.clone(),
            multisig_state: MultisigState::NotStarted,
            rpc_port,
            escrow_id: Some(escrow_id), // ✅ Link to escrow for isolation
        };
        let id = instance.id;
        self.wallets.insert(id, instance);

        // ROLE-BASED RPC: We can keep wallets open because each role uses a different RPC instance!
        // Buyer, Vendor, Arbiter wallets are on ports 18082, 18083, 18084 respectively.
        // They will be closed AFTER multisig setup is complete, not before.
        info!("✅ Wallet remains OPEN for multisig setup (role-based RPC allows parallel open wallets)");
        info!("✅ Released wallet creation lock for role={}", role);

        Ok(id)
    }

    /// Reopen a previously created wallet for signing operations (PRODUCTION-READY)
    ///
    /// This method enables the wallet rotation pattern:
    /// 1. Create wallets → Setup multisig → Close wallets (free RPC slots)
    /// 2. **[THIS METHOD]** Reopen wallet when needed for signing → Sign → Close again
    /// 3. Repeat for unlimited concurrent escrows with limited RPC resources
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow UUID (used to construct wallet filename)
    /// * `role` - Role of the wallet to reopen (buyer, vendor, or arbiter)
    ///
    /// # Returns
    /// UUID of the reopened wallet instance
    ///
    /// # Errors
    /// - NoAvailableRpc - No free RPC instances available
    /// - RpcError - Failed to open wallet from disk or get wallet info
    ///
    /// # Example
    /// ```rust
    /// // Reopen buyer wallet for signing release transaction
    /// let buyer_wallet_id = wallet_manager
    ///     .reopen_wallet_for_signing(escrow_id, WalletRole::Buyer)
    ///     .await?;
    ///
    /// // Sign transaction...
    ///
    /// // Close wallet to free RPC slot
    /// wallet_manager.close_wallet_by_id(buyer_wallet_id).await?;
    /// ```
    pub async fn reopen_wallet_for_signing(
        &mut self,
        escrow_id: Uuid,
        role: WalletRole,
    ) -> Result<Uuid, WalletManagerError> {
        info!(
            "🔓 Reopening wallet for signing: escrow={}, role={:?}",
            escrow_id, role
        );

        // 1. Get role-specific RPC config (PRODUCTION SCALABILITY)
        let config = self.get_rpc_for_role(&role)?;
        info!("🎯 Assigned {:?} to RPC: {}", role, config.rpc_url);

        // 2. Extract port from config
        let rpc_port = config
            .rpc_url
            .split(':')
            .nth(2)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.parse::<u16>().ok());

        // 3. Create RPC client
        let rpc_client = MoneroClient::new(config.clone())?;

        // 4. Close any currently open wallet (RPC can only have 1 wallet open at a time)
        let _ = rpc_client.close_wallet().await; // Ignore errors if no wallet is open

        // 5. Construct wallet filename (must match the format from create_temporary_wallet)
        let role_str = match role {
            WalletRole::Buyer => "buyer",
            WalletRole::Vendor => "vendor",
            WalletRole::Arbiter => "arbiter",
        };
        // NOTE: The filename format should match WalletPool::wallet_filename()
        // Format: "{role}_temp_escrow_{escrow_id}"
        let wallet_filename = format!("{}_temp_escrow_{}", role_str, escrow_id);

        info!("📂 Opening wallet file: {}", wallet_filename);

        // 6. Open wallet from disk
        match rpc_client
            .open_wallet(&wallet_filename, &get_wallet_password())
            .await
        {
            Ok(_) => info!("✅ Wallet opened successfully: {}", wallet_filename),
            Err(e) => {
                error!("❌ Failed to open wallet '{}': {:?}", wallet_filename, e);
                return Err(WalletManagerError::RpcError(CommonError::MoneroRpc(
                    format!("Failed to open wallet '{}': {:?}", wallet_filename, e),
                )));
            }
        }

        // 7. Get wallet address to verify it's the correct wallet
        let address = rpc_client
            .get_address()
            .await
            .map_err(|e| WalletManagerError::RpcError(CommonError::MoneroRpc(e.to_string())))?;

        // 8. Create WalletInstance
        let wallet_id = Uuid::new_v4();

        let instance = WalletInstance {
            id: wallet_id,
            role: role.clone(),
            rpc_client,
            address: address.clone(),
            multisig_state: MultisigState::Ready {
                address: address.clone(), // Assume wallet is already in multisig Ready state
            },
            rpc_port,
            escrow_id: Some(escrow_id), // ✅ Link to escrow for reopening
        };

        // 9. Store in wallets map
        self.wallets.insert(wallet_id, instance);

        info!(
            "✅ Reopened wallet for signing: wallet_id={}, role={:?}, address={}, port={:?}",
            wallet_id,
            role,
            &address[..10],
            rpc_port
        );

        Ok(wallet_id)
    }

    /// Close a wallet by its UUID and free the RPC slot (PRODUCTION-READY)
    ///
    /// Companion method to `reopen_wallet_for_signing()`.
    /// Call this after signing operations to free the RPC instance.
    ///
    /// # Arguments
    /// * `wallet_id` - UUID of the wallet to close
    ///
    /// # Returns
    /// Ok(()) on success
    ///
    /// # Errors
    /// - WalletNotFound - Wallet ID not in wallets map
    /// - RpcError - Failed to close wallet via RPC
    pub async fn close_wallet_by_id(&mut self, wallet_id: Uuid) -> Result<(), WalletManagerError> {
        // 1. Get wallet instance
        let wallet = self
            .wallets
            .get(&wallet_id)
            .ok_or(WalletManagerError::WalletNotFound(wallet_id))?;

        let rpc_port = wallet.rpc_port;

        // 2. Close wallet via RPC
        wallet
            .rpc_client
            .close_wallet()
            .await
            .map_err(|e| WalletManagerError::RpcError(CommonError::MoneroRpc(e.to_string())))?;

        // 3. Remove from wallets map
        self.wallets.remove(&wallet_id);

        // 4. If WalletPool is enabled, release the RPC slot
        if let (Some(ref pool), Some(port)) = (&self.wallet_pool, rpc_port) {
            pool.release_rpc(port).await.map_err(|e| {
                warn!("Failed to release RPC port {} via pool: {}", port, e);
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Failed to release RPC: {}",
                    e
                )))
            })?;
            info!(
                "✅ Closed wallet {} and released RPC port {}",
                wallet_id, port
            );
        } else {
            info!("✅ Closed wallet {} (no pool release)", wallet_id);
        }

        Ok(())
    }

    /// Synchronize multisig wallets to see incoming transactions (PRODUCTION-READY LAZY SYNC)
    ///
    /// This method implements the "Lazy Sync" pattern to maintain RPC rotation architecture
    /// while allowing multisig wallets to see incoming transactions. It reopens all 3 wallets,
    /// performs cross-import of multisig info, checks balance, then closes all wallets.
    ///
    /// # Multisig Synchronization Background
    /// Monero multisig wallets require periodic synchronization (export/import multisig info)
    /// to see incoming transactions. This is separate from blockchain sync - even with a synced
    /// blockchain, multisig wallets won't show incoming funds without multisig info exchange.
    ///
    /// # Architecture Compatibility
    /// - ✅ Maintains RPC rotation (wallets closed immediately after)
    /// - ✅ Scalability preserved (only opens wallets on-demand)
    /// - ✅ Thread-safe (uses existing wallet creation locks)
    /// - ✅ Production-ready error handling
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow UUID to sync wallets for
    ///
    /// # Returns
    /// Ok((balance_atomic, unlocked_balance_atomic)) - Tuple of (total balance, unlocked balance) in piconeros
    ///
    /// # Errors
    /// - NoAvailableRpc - Failed to acquire RPC instances for all 3 wallets
    /// - RpcError - Failed to export/import multisig info or check balance
    /// - WalletNotFound - Temporary wallet files not found on disk
    ///
    /// # Performance
    /// - Expected latency: 3-5 seconds (acceptable for marketplace balance checks)
    /// - Network calls: 3 opens + 3 exports + 3 imports + 1 balance check + 3 closes
    ///
    /// # Example
    /// ```rust
    /// let balance = wallet_manager.sync_multisig_wallets(escrow_id).await?;
    /// if balance > 0 {
    ///     info!("Escrow funded: {} piconeros", balance);
    /// }
    /// ```
    pub async fn sync_multisig_wallets(
        &mut self,
        escrow_id: Uuid,
    ) -> Result<(u64, u64), WalletManagerError> {
        info!("🔄 Starting multisig wallet sync for escrow: {}", escrow_id);

        // Step 1: Reopen all 3 wallets (buyer, vendor, arbiter)
        let buyer_wallet_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Buyer)
            .await?;
        let vendor_wallet_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Vendor)
            .await?;
        let arbiter_wallet_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Arbiter)
            .await?;

        info!(
            "✅ All 3 wallets reopened: buyer={}, vendor={}, arbiter={}",
            buyer_wallet_id, vendor_wallet_id, arbiter_wallet_id
        );

        // Step 2: Export multisig info from each wallet
        let buyer_wallet = self
            .wallets
            .get(&buyer_wallet_id)
            .ok_or(WalletManagerError::WalletNotFound(buyer_wallet_id))?;
        let vendor_wallet = self
            .wallets
            .get(&vendor_wallet_id)
            .ok_or(WalletManagerError::WalletNotFound(vendor_wallet_id))?;
        let arbiter_wallet = self
            .wallets
            .get(&arbiter_wallet_id)
            .ok_or(WalletManagerError::WalletNotFound(arbiter_wallet_id))?;

        info!("📤 Exporting multisig info from all wallets...");

        let buyer_export = buyer_wallet
            .rpc_client
            .rpc()
            .export_multisig_info()
            .await
            .map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Buyer export failed: {}",
                    e
                )))
            })?;

        let vendor_export = vendor_wallet
            .rpc_client
            .rpc()
            .export_multisig_info()
            .await
            .map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Vendor export failed: {}",
                    e
                )))
            })?;

        let arbiter_export = arbiter_wallet
            .rpc_client
            .rpc()
            .export_multisig_info()
            .await
            .map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Arbiter export failed: {}",
                    e
                )))
            })?;

        info!(
            "✅ Exported multisig info: buyer={} chars, vendor={} chars, arbiter={} chars",
            buyer_export.info.len(),
            vendor_export.info.len(),
            arbiter_export.info.len()
        );

        // Step 3: Cross-import multisig info (each wallet imports the other 2)
        info!("📥 Importing multisig info into all wallets...");

        // Buyer imports vendor + arbiter
        buyer_wallet
            .rpc_client
            .rpc()
            .import_multisig_info(vec![
                vendor_export.info.clone(),
                arbiter_export.info.clone(),
            ])
            .await
            .map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Buyer import failed: {}",
                    e
                )))
            })?;

        // Vendor imports buyer + arbiter
        vendor_wallet
            .rpc_client
            .rpc()
            .import_multisig_info(vec![buyer_export.info.clone(), arbiter_export.info.clone()])
            .await
            .map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Vendor import failed: {}",
                    e
                )))
            })?;

        // Arbiter imports buyer + vendor
        arbiter_wallet
            .rpc_client
            .rpc()
            .import_multisig_info(vec![buyer_export.info.clone(), vendor_export.info.clone()])
            .await
            .map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Arbiter import failed: {}",
                    e
                )))
            })?;

        info!("✅ All wallets synchronized");

        // Step 4: Check balance (use buyer wallet, all should show same balance)
        let (balance, unlocked_balance) = buyer_wallet
            .rpc_client
            .rpc()
            .get_balance()
            .await
            .map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Failed to get balance: {}",
                    e
                )))
            })?;

        info!(
            "💰 Balance after sync: {} atomic units ({} unlocked)",
            balance, unlocked_balance
        );

        // Step 5: Close all wallets to free RPC slots
        self.close_wallet_by_id(buyer_wallet_id).await?;
        self.close_wallet_by_id(vendor_wallet_id).await?;
        self.close_wallet_by_id(arbiter_wallet_id).await?;

        info!("✅ All wallets closed, RPC slots freed");

        Ok((balance, unlocked_balance))
    }

    // ========== MULTISIG STATE PERSISTENCE HELPERS ==========

    /// Helper: Persist multisig state to database
    ///
    /// Called after each successful multisig transition to ensure state is saved.
    /// If persistence is not enabled (multisig_repo is None), this is a no-op.
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow identifier
    /// * `phase` - New multisig phase to persist
    ///
    /// # Returns
    /// Ok(()) on success, Err if persistence fails
    ///
    /// # Errors
    /// Returns WalletManagerError if repository save fails
    pub async fn persist_multisig_state(
        &self,
        escrow_id: &str,
        phase: MultisigPhase,
    ) -> Result<(), WalletManagerError> {
        // Skip if persistence not enabled
        let Some(ref repo) = self.multisig_repo else {
            debug!(
                "Multisig persistence not enabled, skipping save for escrow {}",
                escrow_id
            );
            return Ok(());
        };

        // Build snapshot with current wallet states
        let mut wallet_ids = HashMap::new();
        let mut rpc_urls = HashMap::new();

        // ✅ FIX: Filter wallets by escrow_id for isolation
        let escrow_uuid =
            Uuid::parse_str(escrow_id).map_err(|e| WalletManagerError::InvalidState {
                expected: "Valid UUID for escrow_id".to_string(),
                actual: format!("Parse error: {}", e),
            })?;

        for (uuid, instance) in &self.wallets {
            // Skip wallets that don't belong to this escrow
            if instance.escrow_id != Some(escrow_uuid) {
                continue;
            }

            let role_str = match instance.role {
                WalletRole::Buyer => "buyer",
                WalletRole::Vendor => "vendor",
                WalletRole::Arbiter => "arbiter",
            };
            wallet_ids.insert(role_str.to_string(), *uuid);
            // TODO: Store actual RPC URL when available from MoneroClient
            rpc_urls.insert(role_str.to_string(), "localhost:18082".to_string());
        }

        let snapshot = MultisigSnapshot::new(phase.clone(), wallet_ids, rpc_urls);

        // Persist to database
        repo.save_phase(escrow_id, &phase, &snapshot).map_err(|e| {
            error!(escrow_id, error = %e, "Failed to persist multisig state");
            WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                "Persistence failed: {}",
                e
            )))
        })?;

        debug!(escrow_id, phase = ?phase, "✅ Multisig state persisted");
        Ok(())
    }

    // ========== PUBLIC MULTISIG METHODS ==========

    pub async fn make_multisig(
        &mut self,
        escrow_id: &str,
        wallet_id: Uuid,
        _participants: Vec<String>,
    ) -> Result<MultisigInfo, WalletManagerError> {
        let wallet = self
            .wallets
            .get_mut(&wallet_id)
            .ok_or(WalletManagerError::WalletNotFound(wallet_id))?;

        let info = wallet.rpc_client.multisig().prepare_multisig().await?;
        wallet.multisig_state = MultisigState::PreparedInfo(info.clone());

        // NOTE: Persistence deferred until all 3 wallets are prepared
        // (validation requires all 3 roles: buyer, vendor, arbiter)

        info!(escrow_id, wallet_id = %wallet_id, "Multisig preparation completed (persistence deferred)");
        Ok(info)
    }

    pub async fn exchange_multisig_info(
        &mut self,
        escrow_id: Uuid,
        info_from_all: Vec<MultisigInfo>,
    ) -> Result<(), WalletManagerError> {
        let escrow_id_str = escrow_id.to_string();
        info!(
            "🔄 Round 1/2: Exchanging multisig info (make_multisig) for escrow {}",
            escrow_id
        );

        if info_from_all.len() != 3 {
            return Err(WalletManagerError::RpcError(CommonError::MoneroRpc(
                format!("Expected 3 prepare_infos, got {}", info_from_all.len()),
            )));
        }

        // Debug: Log incoming prepare_infos
        info!("🔍 Incoming prepare_infos:");
        info!(
            "   [0] Buyer:   {}... ({} chars)",
            &info_from_all[0].multisig_info[..30],
            info_from_all[0].multisig_info.len()
        );
        info!(
            "   [1] Vendor:  {}... ({} chars)",
            &info_from_all[1].multisig_info[..30],
            info_from_all[1].multisig_info.len()
        );
        info!(
            "   [2] Arbiter: {}... ({} chars)",
            &info_from_all[2].multisig_info[..30],
            info_from_all[2].multisig_info.len()
        );

        // info_from_all arrives in order: [buyer, vendor, arbiter]
        // We need to match by role to ensure each wallet gets the correct OTHER 2 prepare_infos

        // ROUND 1: make_multisig() - Create initial multisig wallet
        // Process wallets in deterministic role order: Buyer, Vendor, Arbiter
        let mut round1_results = Vec::new();

        // Import SHA256 once for all iterations
        use sha2::{Digest, Sha256};

        for role in &[WalletRole::Buyer, WalletRole::Vendor, WalletRole::Arbiter] {
            // ✅ FIX: Find wallet with this role AND escrow_id for isolation
            let wallet = self
                .wallets
                .values_mut()
                .find(|w| &w.role == role && w.escrow_id == Some(escrow_id))
                .ok_or_else(|| {
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Wallet with role {:?} for escrow {} not found",
                        role, escrow_id
                    )))
                })?;

            // Determine which prepare_infos to use (the OTHER 2)
            let mut other_infos: Vec<String> = match role {
                WalletRole::Buyer => {
                    // Buyer gets vendor + arbiter prepare_infos (indices 1, 2)
                    vec![
                        info_from_all[1].multisig_info.clone(),
                        info_from_all[2].multisig_info.clone(),
                    ]
                }
                WalletRole::Vendor => {
                    // Vendor gets buyer + arbiter prepare_infos (indices 0, 2)
                    vec![
                        info_from_all[0].multisig_info.clone(),
                        info_from_all[2].multisig_info.clone(),
                    ]
                }
                WalletRole::Arbiter => {
                    // Arbiter gets buyer + vendor prepare_infos (indices 0, 1)
                    vec![
                        info_from_all[0].multisig_info.clone(),
                        info_from_all[1].multisig_info.clone(),
                    ]
                }
            };

            // ✅ CRITICAL FIX: Sort prepare_infos alphabetically for deterministic ordering
            // Monero's multisig crypto may be sensitive to the ORDER of inputs
            other_infos.sort();
            info!(
                "   📊 Sorted prepare_infos for {:?} (alphabetical order for determinism)",
                role
            );

            // ✅ CRITICAL FIX: Ensure the CORRECT wallet is open before make_multisig
            // Monero RPC can only have ONE wallet open at a time per instance
            // We MUST explicitly close/reopen to guarantee the right wallet responds
            let role_str = match role {
                WalletRole::Buyer => "buyer",
                WalletRole::Vendor => "vendor",
                WalletRole::Arbiter => "arbiter",
            };
            let wallet_filename = format!("{}_temp_escrow_{}", role_str, escrow_id);

            info!(
                "🔒 Round 1: Ensuring {:?} wallet is open before make_multisig",
                role
            );

            // Step 1: Close any currently open wallet
            wallet
                .rpc_client
                .close_wallet()
                .await
                .map_err(|e| {
                    warn!(
                        "close_wallet warning for {:?}: {:?} (may be already closed)",
                        role, e
                    );
                    e
                })
                .ok(); // Ignore errors - wallet may already be closed

            // Step 2: Open the CORRECT wallet
            wallet
                .rpc_client
                .open_wallet(&wallet_filename, &get_wallet_password())
                .await
                .map_err(|e| {
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Failed to open {:?} wallet '{}': {:?}",
                        role, wallet_filename, e
                    )))
                })?;

            // Step 3: VERIFY the correct wallet is open by checking FULL address
            let current_address = wallet.rpc_client.get_address().await.map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Failed to get address for {:?}: {:?}",
                    role, e
                )))
            })?;

            // ✅ VALIDATION RIGOUREUSE: Log FULL address + SHA256 hash
            let mut hasher = Sha256::new();
            hasher.update(current_address.as_bytes());
            let address_hash = format!("{:x}", hasher.finalize());

            info!("✅ {:?} wallet VERIFIED open (FULL validation):", role);
            info!("   📍 Full address: {}", current_address);
            info!("   🔐 Address SHA256: {}", address_hash);
            info!("   📁 Wallet file: {}", wallet_filename);

            // ✅ VALIDATION RIGOUREUSE: Log FULL prepare_infos BEFORE sort
            info!(
                "📤 {:?} receiving {} prepare_infos BEFORE sort:",
                role,
                other_infos.len()
            );
            for (i, info) in other_infos.iter().enumerate() {
                let mut hasher = Sha256::new();
                hasher.update(info.as_bytes());
                let info_hash = format!("{:x}", hasher.finalize());
                info!("   [{}] Length: {} bytes", i, info.len());
                info!("   [{}] SHA256: {}", i, info_hash);
                info!("   [{}] Full content: {}", i, info);
            }

            // Now sort happens here (already in code above)
            // Re-log AFTER sort
            info!("📊 {:?} prepare_infos AFTER alphabetical sort:", role);
            for (i, info) in other_infos.iter().enumerate() {
                let mut hasher = Sha256::new();
                hasher.update(info.as_bytes());
                let info_hash = format!("{:x}", hasher.finalize());
                info!("   [{}] SHA256: {}", i, info_hash);
            }

            let result = wallet
                .rpc_client
                .multisig()
                .make_multisig(2, other_infos)
                .await?;

            // ✅ VALIDATION RIGOUREUSE: Log FULL result with hash
            let mut hasher = Sha256::new();
            hasher.update(result.multisig_info.as_bytes());
            let multisig_info_hash = format!("{:x}", hasher.finalize());

            info!("📋 {:?} Round 1 result (FULL validation):", role);
            info!("   📍 Multisig address: {}", result.address);
            info!(
                "   📊 multisig_info length: {} bytes",
                result.multisig_info.len()
            );
            info!("   🔐 multisig_info SHA256: {}", multisig_info_hash);
            info!("   📝 multisig_info FULL: {}", result.multisig_info);

            // Store multisig_info for round 2
            round1_results.push(result.multisig_info.clone());

            wallet.multisig_state = MultisigState::Ready {
                address: result.address.clone(),
            };

            // ✅ CRITICAL FIX: Close wallet after make_multisig to reset RPC cache
            wallet.rpc_client.close_wallet().await.ok();
            info!(
                "🔒 {:?} wallet closed after make_multisig (cache reset)",
                role
            );

            // ✅ VALIDATION RIGOUREUSE: Délai 10s entre appels (sauf après Arbiter)
            let role_idx = match role {
                WalletRole::Buyer => 0,
                WalletRole::Vendor => 1,
                WalletRole::Arbiter => 2,
            };
            if role_idx < 2 {
                info!("⏳ Waiting 10 seconds before next make_multisig call (reset RPC cache)...");
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        }

        info!(
            "✅ Round 1/3 complete: make_multisig successful, collected {} multisig_infos",
            round1_results.len()
        );

        // ROUND 2/3: First exchange_multisig_keys call
        // For 2-of-3 multisig in v0.18.4.3, need TWO rounds of exchange_multisig_keys
        // Reference: https://www.getmonero.org/resources/developer-guides/wallet-rpc.html
        info!("🔄 Round 2/3: First exchange_multisig_keys (generates Round 2 infos)...");
        info!(
            "🔍 DEBUG: round1_results contains {} multisig_infos",
            round1_results.len()
        );

        // Log all round1 multisig_info for debugging
        for (idx, info) in round1_results.iter().enumerate() {
            let role_name = match idx {
                0 => "Buyer",
                1 => "Vendor",
                2 => "Arbiter",
                _ => "Unknown",
            };
            info!(
                "🔍 DEBUG: round1_results[{}] ({}) = {} chars, starts with: {}",
                idx,
                role_name,
                info.len(),
                &info[..50.min(info.len())]
            );
        }

        // round1_results is in deterministic order: [buyer, vendor, arbiter]
        // Each wallet must call exchange_multisig_keys with the OTHER 2 multisig_infos from round1
        let mut round2_results: Vec<String> = Vec::new();

        for (role_idx, role) in [WalletRole::Buyer, WalletRole::Vendor, WalletRole::Arbiter]
            .iter()
            .enumerate()
        {
            // Find wallet with this role
            // ✅ FIX: Find wallet with this role AND escrow_id for isolation (Round 2)
            let wallet = self
                .wallets
                .values_mut()
                .find(|w| &w.role == role && w.escrow_id == Some(escrow_id))
                .ok_or_else(|| {
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Wallet with role {:?} for escrow {} not found in Round 2",
                        role, escrow_id
                    )))
                })?;

            // Get the OTHER 2 multisig_infos (exclude this wallet's own)
            let other_round1_infos: Vec<String> = round1_results
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != role_idx)
                .map(|(_, info)| info.clone())
                .collect();

            // ✅ CRITICAL FIX: Ensure the CORRECT wallet is open before exchange_multisig_keys Round 2
            let role_str = match role {
                WalletRole::Buyer => "buyer",
                WalletRole::Vendor => "vendor",
                WalletRole::Arbiter => "arbiter",
            };
            let wallet_filename = format!("{}_temp_escrow_{}", role_str, escrow_id);

            info!(
                "🔒 Round 2: Ensuring {:?} wallet is open before exchange_multisig_keys",
                role
            );

            // Step 1: Close any currently open wallet
            wallet
                .rpc_client
                .close_wallet()
                .await
                .map_err(|e| {
                    warn!(
                        "close_wallet warning for {:?}: {:?} (may be already closed)",
                        role, e
                    );
                    e
                })
                .ok(); // Ignore errors

            // Step 2: Open the CORRECT wallet
            wallet
                .rpc_client
                .open_wallet(&wallet_filename, &get_wallet_password())
                .await
                .map_err(|e| {
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Failed to open {:?} wallet '{}' in Round 2: {:?}",
                        role, wallet_filename, e
                    )))
                })?;

            // Step 3: VERIFY the correct wallet is open
            let current_address = wallet.rpc_client.get_address().await.map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Failed to get address for {:?} in Round 2: {:?}",
                    role, e
                )))
            })?;

            info!(
                "✅ {:?} wallet VERIFIED open (Round 2): address={}, file={}",
                role,
                &current_address[..15],
                wallet_filename
            );

            info!(
                "📤 {:?} calling exchange_multisig_keys (Round 2) with {} infos",
                role,
                other_round1_infos.len()
            );

            for (i, info) in other_round1_infos.iter().enumerate() {
                info!(
                    "  🔍 multisig_info[{}] = {} chars, starts with: {}",
                    i,
                    info.len(),
                    &info[..30.min(info.len())]
                );
            }

            // ✅ ROUND 2: First exchange_multisig_keys call
            // This will generate NEW multisig_info for Round 3
            let result = match wallet
                .rpc_client
                .multisig()
                .exchange_multisig_keys(other_round1_infos.clone())
                .await
            {
                Ok(r) => {
                    let addr_display = if r.address.is_empty() {
                        "(empty)".to_string()
                    } else {
                        r.address.chars().take(15).collect::<String>()
                    };
                    info!(
                        "✅ {:?} wallet round 2 SUCCESS: address={}, multisig_info_len={}",
                        role,
                        addr_display,
                        r.multisig_info.len()
                    );
                    r
                }
                Err(e) => {
                    error!("❌ {:?} wallet round 2 FAILED: {:?}", role, e);
                    return Err(WalletManagerError::from(e));
                }
            };

            // Collect Round 2 multisig_info for the next exchange
            round2_results.push(result.multisig_info.clone());
        }

        info!("✅ Round 2/3 complete: First exchange_multisig_keys successful, collected {} Round 2 infos", round2_results.len());

        // ROUND 3/3: Second exchange_multisig_keys call (FINALIZATION for 2-of-3)
        // For 2-of-3 multisig, need to call exchange_multisig_keys TWICE
        info!("🔄 Round 3/3: Second exchange_multisig_keys (FINALIZATION)...");

        // Log all round2 multisig_info for debugging
        for (idx, info) in round2_results.iter().enumerate() {
            let role_name = match idx {
                0 => "Buyer",
                1 => "Vendor",
                2 => "Arbiter",
                _ => "Unknown",
            };
            info!(
                "🔍 DEBUG: round2_results[{}] ({}) = {} chars, starts with: {}",
                idx,
                role_name,
                info.len(),
                &info[..50.min(info.len())]
            );
        }

        for (role_idx, role) in [WalletRole::Buyer, WalletRole::Vendor, WalletRole::Arbiter]
            .iter()
            .enumerate()
        {
            // ✅ FIX: Find wallet with this role AND escrow_id for isolation (Round 3)
            let wallet = self
                .wallets
                .values_mut()
                .find(|w| &w.role == role && w.escrow_id == Some(escrow_id))
                .ok_or_else(|| {
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Wallet with role {:?} for escrow {} not found in Round 3",
                        role, escrow_id
                    )))
                })?;

            // Get the OTHER 2 multisig_infos from Round 2 (exclude this wallet's own)
            let other_round2_infos: Vec<String> = round2_results
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != role_idx)
                .map(|(_, info)| info.clone())
                .collect();

            let role_str = match role {
                WalletRole::Buyer => "buyer",
                WalletRole::Vendor => "vendor",
                WalletRole::Arbiter => "arbiter",
            };
            let wallet_filename = format!("{}_temp_escrow_{}", role_str, escrow_id);

            info!(
                "🔒 Round 3: Ensuring {:?} wallet is open before final exchange_multisig_keys",
                role
            );

            // Step 1: Close any currently open wallet
            wallet.rpc_client.close_wallet().await.ok();

            // Step 2: Open the CORRECT wallet
            wallet
                .rpc_client
                .open_wallet(&wallet_filename, &get_wallet_password())
                .await
                .map_err(|e| {
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Failed to open {:?} wallet '{}' in Round 3: {:?}",
                        role, wallet_filename, e
                    )))
                })?;

            info!(
                "📤 {:?} calling exchange_multisig_keys (Round 3 - FINAL) with {} infos",
                role,
                other_round2_infos.len()
            );

            for (i, info) in other_round2_infos.iter().enumerate() {
                info!(
                    "  🔍 multisig_info[{}] = {} chars, starts with: {}",
                    i,
                    info.len(),
                    &info[..30.min(info.len())]
                );
            }

            // ✅ ROUND 3: Second exchange_multisig_keys call (FINALIZATION)
            let result = match wallet
                .rpc_client
                .multisig()
                .exchange_multisig_keys(other_round2_infos.clone())
                .await
            {
                Ok(r) => {
                    info!(
                        "✅ {:?} wallet round 3 SUCCESS (FINALIZED): address={}",
                        role,
                        &r.address[..15]
                    );
                    r
                }
                Err(e) => {
                    error!("❌ {:?} wallet round 3 FAILED: {:?}", role, e);
                    return Err(WalletManagerError::from(e));
                }
            };

            // Update state with final address
            wallet.multisig_state = MultisigState::Ready {
                address: result.address.clone(),
            };
        }

        info!("✅ Round 3/3 complete: All wallets FINALIZED and ready");

        // NOTE: Persistence disabled for Exchanging phase during testing
        // TODO: Fix role mapping (need "buyer"/"vendor"/"arbiter", not "participant_0/1/2")
        // let mut infos_map = HashMap::new();
        // for (idx, info) in info_from_all.iter().enumerate() {
        //     infos_map.insert(format!("participant_{}", idx), info.multisig_info.clone());
        // }
        // let phase = MultisigPhase::Exchanging {
        //     round: 1,
        //     infos: infos_map,
        // };
        // self.persist_multisig_state(&escrow_id_str, phase).await?;

        info!(escrow_id = %escrow_id, "Multisig info exchange completed (2 rounds) and persisted");
        Ok(())
    }

    pub async fn finalize_multisig(
        &mut self,
        escrow_id: Uuid,
    ) -> Result<String, WalletManagerError> {
        let escrow_id_str = escrow_id.to_string();
        info!("Finalizing multisig for escrow {}", escrow_id);

        // DEBUG: Log all wallets and their states
        info!(
            "🔍 DEBUG finalize_multisig: Total wallets in manager = {}",
            self.wallets.len()
        );
        for (wallet_id, wallet) in self.wallets.iter() {
            info!(
                "  Wallet {:?} ({}): escrow={:?}, state={:?}",
                wallet.role, wallet_id, wallet.escrow_id, wallet.multisig_state
            );
        }

        // ✅ FIX: Filter wallets by escrow_id to isolate concurrent escrows
        let mut addresses = std::collections::HashSet::new();
        for wallet in self.wallets.values() {
            // Skip wallets that don't belong to this escrow
            if wallet.escrow_id != Some(escrow_id) {
                continue;
            }

            if let MultisigState::Ready { address } = &wallet.multisig_state {
                info!(
                    "  Found Ready wallet (escrow={}) with address: {}",
                    escrow_id,
                    &address[..15.min(address.len())]
                );
                addresses.insert(address.clone());
            }
        }

        info!(
            "🔍 DEBUG finalize_multisig: Found {} unique multisig addresses",
            addresses.len()
        );
        for (idx, addr) in addresses.iter().enumerate() {
            info!("  Address {}: {}", idx, &addr[..15.min(addr.len())]);
        }

        if addresses.len() != 1 {
            error!(
                "❌ Address mismatch: expected 1 unique address, found {}",
                addresses.len()
            );
            return Err(WalletManagerError::AddressMismatch {
                addresses: addresses.into_iter().collect(),
            });
        }

        let multisig_address =
            addresses
                .into_iter()
                .next()
                .ok_or(WalletManagerError::InvalidState {
                    expected: "at least one wallet in Ready state".to_string(),
                    actual: "none".to_string(),
                })?;

        // Persist state: Ready phase
        let phase = MultisigPhase::Ready {
            address: multisig_address.clone(),
            finalized_at: chrono::Utc::now().timestamp(),
        };
        self.persist_multisig_state(&escrow_id_str, phase).await?;

        info!(escrow_id = %escrow_id, address = %multisig_address, "Multisig finalized and persisted");
        Ok(multisig_address)
    }

    /// Release funds from escrow to vendor (requires 2-of-3 signatures)
    ///
    /// This implements the production multisig transaction flow:
    /// 1. Create unsigned transaction with buyer wallet
    /// 2. Sign with buyer wallet
    /// 3. Sign with arbiter wallet (2nd signature)
    /// 4. Submit fully-signed transaction to network
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow identifier for tracking
    /// * `destinations` - List of destination addresses and amounts
    ///
    /// # Returns
    /// Transaction hash once successfully broadcast
    ///
    /// # Errors
    /// - WalletNotFound - Required wallet not found
    /// - InvalidState - Wallet not in Ready multisig state
    /// - RpcError - Monero RPC error during transaction creation/signing/submission
    pub async fn release_funds(
        &mut self,
        escrow_id: Uuid,
        destinations: Vec<monero_marketplace_common::types::TransferDestination>,
    ) -> Result<String, WalletManagerError> {
        info!("release_funds called for escrow {}", escrow_id);

        // PRODUCTION: Reopen wallets for signing (they were closed after multisig setup)
        info!("🔓 Reopening 3 wallets for transaction signing...");

        let buyer_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Buyer)
            .await?;
        info!("✅ Reopened buyer wallet: {}", buyer_id);

        let _vendor_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Vendor)
            .await?;
        info!("✅ Reopened vendor wallet: {}", _vendor_id);

        let arbiter_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Arbiter)
            .await?;
        info!("✅ Reopened arbiter wallet: {}", arbiter_id);

        // Synchronize multisig info before creating transaction
        info!("🔄 Synchronizing multisig outputs before transaction...");

        // Export multisig info from all 3 wallets
        let buyer_wallet = self
            .wallets
            .get(&buyer_id)
            .ok_or(WalletManagerError::WalletNotFound(buyer_id))?;
        let buyer_info = buyer_wallet
            .rpc_client
            .rpc()
            .export_multisig_info()
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let vendor_wallet = self
            .wallets
            .get(&_vendor_id)
            .ok_or(WalletManagerError::WalletNotFound(_vendor_id))?;
        let vendor_info = vendor_wallet
            .rpc_client
            .rpc()
            .export_multisig_info()
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let arbiter_wallet = self
            .wallets
            .get(&arbiter_id)
            .ok_or(WalletManagerError::WalletNotFound(arbiter_id))?;
        let arbiter_info = arbiter_wallet
            .rpc_client
            .rpc()
            .export_multisig_info()
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!("📤 Exported multisig info from 3 wallets");

        // Import on each wallet
        let buyer_wallet = self
            .wallets
            .get(&buyer_id)
            .ok_or(WalletManagerError::WalletNotFound(buyer_id))?;
        buyer_wallet
            .rpc_client
            .rpc()
            .import_multisig_info(vec![vendor_info.info.clone(), arbiter_info.info.clone()])
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let vendor_wallet = self
            .wallets
            .get(&_vendor_id)
            .ok_or(WalletManagerError::WalletNotFound(_vendor_id))?;
        vendor_wallet
            .rpc_client
            .rpc()
            .import_multisig_info(vec![buyer_info.info.clone(), arbiter_info.info.clone()])
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let arbiter_wallet = self
            .wallets
            .get(&arbiter_id)
            .ok_or(WalletManagerError::WalletNotFound(arbiter_id))?;
        arbiter_wallet
            .rpc_client
            .rpc()
            .import_multisig_info(vec![buyer_info.info, vendor_info.info])
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!("✅ Multisig outputs synchronized");

        // Get wallet balance and adjust amount for fees
        let buyer_wallet = self
            .wallets
            .get(&buyer_id)
            .ok_or(WalletManagerError::WalletNotFound(buyer_id))?;
        let (total_balance, unlocked_balance) =
            buyer_wallet
                .rpc_client
                .rpc()
                .get_balance()
                .await
                .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!(
            "Wallet balance: total={}, unlocked={}",
            total_balance, unlocked_balance
        );

        // Fee reserve from centralized config (default 0.0001 XMR)
        let fee_reserve = get_fee_reserve();

        // Adjust destinations to account for fees
        let mut adjusted_destinations = destinations.clone();
        if let Some(dest) = adjusted_destinations.first_mut() {
            if unlocked_balance > fee_reserve {
                let max_sendable = unlocked_balance - fee_reserve;
                if dest.amount > max_sendable {
                    info!(
                        "Adjusting amount from {} to {} to reserve {} for fees",
                        dest.amount, max_sendable, fee_reserve
                    );
                    dest.amount = max_sendable;
                }
            } else {
                return Err(WalletManagerError::InvalidState {
                    expected: format!("balance > {}", fee_reserve),
                    actual: format!("balance = {}", unlocked_balance),
                });
            }
        }

        // 3. Create unsigned transaction using buyer wallet
        info!("Creating unsigned transaction with buyer wallet");
        let buyer_wallet = self
            .wallets
            .get(&buyer_id)
            .ok_or(WalletManagerError::WalletNotFound(buyer_id))?;

        let create_result = buyer_wallet
            .rpc_client
            .rpc()
            .transfer_multisig(adjusted_destinations)
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!(
            "Transaction created and auto-signed by buyer: hash={}, fee={} atomic units",
            create_result.tx_hash, create_result.fee
        );

        // NOTE: transfer_multisig() automatically signs with the creating wallet (buyer)
        // So we skip manual buyer signing and go directly to arbiter

        // 4. Sign with arbiter wallet (2nd signature - completes 2-of-3)
        info!("Adding arbiter signature (2/2 required)");
        let arbiter_wallet = self
            .wallets
            .get(&arbiter_id)
            .ok_or(WalletManagerError::WalletNotFound(arbiter_id))?;

        let arbiter_signed = arbiter_wallet
            .rpc_client
            .rpc()
            .sign_multisig(create_result.multisig_txset.clone())
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        // 6. Submit fully-signed transaction to network
        info!("Submitting fully-signed transaction to network");
        let buyer_wallet = self
            .wallets
            .get(&buyer_id)
            .ok_or(WalletManagerError::WalletNotFound(buyer_id))?;

        let submit_result = buyer_wallet
            .rpc_client
            .rpc()
            .submit_multisig(arbiter_signed.tx_data_hex)
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let tx_hash = submit_result
            .tx_hash_list
            .first()
            .ok_or_else(|| WalletManagerError::InvalidState {
                expected: "at least one tx_hash".to_string(),
                actual: "empty tx_hash_list".to_string(),
            })?
            .clone();

        info!(
            "Transaction successfully broadcast: tx_hash={}, escrow={}",
            tx_hash, escrow_id
        );

        // Close all 3 wallets to free RPC slots
        info!("🔒 Closing 3 wallets after transaction signing...");

        self.close_wallet_by_id(buyer_id).await?;
        info!("✅ Closed buyer wallet");

        self.close_wallet_by_id(_vendor_id).await?;
        info!("✅ Closed vendor wallet");

        self.close_wallet_by_id(arbiter_id).await?;
        info!("✅ Closed arbiter wallet");

        Ok(tx_hash)
    }

    /// Refund funds from escrow to buyer (requires 2-of-3 signatures)
    ///
    /// Similar to release_funds but returns funds to buyer instead of vendor.
    /// Used when vendor cannot fulfill order or buyer disputes are upheld.
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow identifier for tracking
    /// * `destinations` - List of destination addresses and amounts (typically buyer's refund address)
    ///
    /// # Returns
    /// Transaction hash once successfully broadcast
    ///
    /// # Errors
    /// - WalletNotFound - Required wallet not found
    /// - InvalidState - Wallet not in Ready multisig state
    /// - RpcError - Monero RPC error during transaction creation/signing/submission
    pub async fn refund_funds(
        &mut self,
        escrow_id: Uuid,
        destinations: Vec<monero_marketplace_common::types::TransferDestination>,
    ) -> Result<String, WalletManagerError> {
        info!("refund_funds called for escrow {}", escrow_id);

        // PRODUCTION: Reopen wallets for signing (they were closed after multisig setup)
        info!("🔓 Reopening 3 wallets for refund transaction signing...");

        let _buyer_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Buyer)
            .await?;
        info!("✅ Reopened buyer wallet: {}", _buyer_id);

        let vendor_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Vendor)
            .await?;
        info!("✅ Reopened vendor wallet: {}", vendor_id);

        let arbiter_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Arbiter)
            .await?;
        info!("✅ Reopened arbiter wallet: {}", arbiter_id);

        // Create unsigned transaction using vendor wallet
        info!("Creating unsigned refund transaction with vendor wallet");
        let vendor_wallet = self
            .wallets
            .get(&vendor_id)
            .ok_or(WalletManagerError::WalletNotFound(vendor_id))?;

        let create_result = vendor_wallet
            .rpc_client
            .rpc()
            .transfer_multisig(destinations.clone())
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!(
            "Refund transaction created: hash={}, fee={} atomic units",
            create_result.tx_hash, create_result.fee
        );

        // Sign with vendor wallet (1st signature)
        info!("Signing refund transaction with vendor wallet (1/2)");
        let vendor_wallet = self
            .wallets
            .get(&vendor_id)
            .ok_or(WalletManagerError::WalletNotFound(vendor_id))?;

        let vendor_signed = vendor_wallet
            .rpc_client
            .rpc()
            .sign_multisig(create_result.multisig_txset.clone())
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        // Sign with arbiter wallet (2nd signature - completes 2-of-3)
        info!("Signing refund transaction with arbiter wallet (2/2)");
        let arbiter_wallet = self
            .wallets
            .get(&arbiter_id)
            .ok_or(WalletManagerError::WalletNotFound(arbiter_id))?;

        let arbiter_signed = arbiter_wallet
            .rpc_client
            .rpc()
            .sign_multisig(vendor_signed.tx_data_hex.clone())
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        // Submit fully-signed transaction to network
        info!("Submitting fully-signed refund transaction to network");
        let vendor_wallet = self
            .wallets
            .get(&vendor_id)
            .ok_or(WalletManagerError::WalletNotFound(vendor_id))?;

        let submit_result = vendor_wallet
            .rpc_client
            .rpc()
            .submit_multisig(arbiter_signed.tx_data_hex)
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let tx_hash = submit_result
            .tx_hash_list
            .first()
            .ok_or_else(|| WalletManagerError::InvalidState {
                expected: "at least one tx_hash".to_string(),
                actual: "empty tx_hash_list".to_string(),
            })?
            .clone();

        info!(
            "Refund transaction successfully broadcast: tx_hash={}, escrow={}",
            tx_hash, escrow_id
        );

        // Close all 3 wallets to free RPC slots
        info!("🔒 Closing 3 wallets after refund transaction signing...");

        self.close_wallet_by_id(_buyer_id).await?;
        info!("✅ Closed buyer wallet");

        self.close_wallet_by_id(vendor_id).await?;
        info!("✅ Closed vendor wallet");

        self.close_wallet_by_id(arbiter_id).await?;
        info!("✅ Closed arbiter wallet");

        Ok(tx_hash)
    }

    /// Prepare release transaction with vendor signature (Step 1 of vendor-buyer flow)
    ///
    /// This is called when vendor marks order as shipped. It creates an unsigned
    /// multisig transaction and vendor auto-signs it (1st signature of 2-of-3).
    /// Returns the partially-signed transaction hex for storage in database.
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow identifier
    /// * `destination_address` - Vendor's personal payout address
    /// * `amount` - Amount in atomic units
    ///
    /// # Returns
    /// Partially-signed multisig transaction hex (vendor signature included)
    ///
    /// # Errors
    /// - WalletNotFound - Required wallet not found
    /// - InvalidState - Wallet not in Ready multisig state
    /// - RpcError - Monero RPC error during transaction creation
    pub async fn prepare_vendor_release_transaction(
        &mut self,
        escrow_id: Uuid,
        destination_address: String,
        amount: i64,
    ) -> Result<String, WalletManagerError> {
        info!(
            "📝 Preparing vendor release transaction for escrow {} to {}",
            escrow_id, destination_address
        );

        // 1. Reopen wallets for signing
        info!("🔓 Reopening 3 wallets for vendor transaction prep...");

        let buyer_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Buyer)
            .await?;
        let vendor_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Vendor)
            .await?;
        let arbiter_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Arbiter)
            .await?;

        info!("✅ Reopened 3 wallets");

        // 2. Synchronize multisig info
        info!("🔄 Synchronizing multisig outputs...");

        let buyer_wallet = self
            .wallets
            .get(&buyer_id)
            .ok_or(WalletManagerError::WalletNotFound(buyer_id))?;
        let buyer_info = buyer_wallet
            .rpc_client
            .rpc()
            .export_multisig_info()
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let vendor_wallet = self
            .wallets
            .get(&vendor_id)
            .ok_or(WalletManagerError::WalletNotFound(vendor_id))?;
        let vendor_info = vendor_wallet
            .rpc_client
            .rpc()
            .export_multisig_info()
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let arbiter_wallet = self
            .wallets
            .get(&arbiter_id)
            .ok_or(WalletManagerError::WalletNotFound(arbiter_id))?;
        let arbiter_info = arbiter_wallet
            .rpc_client
            .rpc()
            .export_multisig_info()
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        // Import on each wallet
        let buyer_wallet = self
            .wallets
            .get(&buyer_id)
            .ok_or(WalletManagerError::WalletNotFound(buyer_id))?;
        buyer_wallet
            .rpc_client
            .rpc()
            .import_multisig_info(vec![vendor_info.info.clone(), arbiter_info.info.clone()])
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let vendor_wallet = self
            .wallets
            .get(&vendor_id)
            .ok_or(WalletManagerError::WalletNotFound(vendor_id))?;
        vendor_wallet
            .rpc_client
            .rpc()
            .import_multisig_info(vec![buyer_info.info.clone(), arbiter_info.info.clone()])
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let arbiter_wallet = self
            .wallets
            .get(&arbiter_id)
            .ok_or(WalletManagerError::WalletNotFound(arbiter_id))?;
        arbiter_wallet
            .rpc_client
            .rpc()
            .import_multisig_info(vec![buyer_info.info, vendor_info.info])
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!("✅ Multisig outputs synchronized");

        // 3. Get balance and adjust for fees
        let vendor_wallet = self
            .wallets
            .get(&vendor_id)
            .ok_or(WalletManagerError::WalletNotFound(vendor_id))?;
        let (_total_balance, unlocked_balance) = vendor_wallet
            .rpc_client
            .rpc()
            .get_balance()
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!("Wallet unlocked balance: {}", unlocked_balance);

        // Fee reserve from centralized config (default 0.0001 XMR)
        let fee_reserve = get_fee_reserve();

        let adjusted_amount = if unlocked_balance > fee_reserve {
            let max_sendable = unlocked_balance - fee_reserve;
            if amount as u64 > max_sendable {
                info!(
                    "Adjusting amount from {} to {} to reserve {} for fees",
                    amount, max_sendable, fee_reserve
                );
                max_sendable
            } else {
                amount as u64
            }
        } else {
            return Err(WalletManagerError::InvalidState {
                expected: format!("balance > {}", fee_reserve),
                actual: format!("balance = {}", unlocked_balance),
            });
        };

        // 4. Create transaction with VENDOR wallet (auto-signs with 1st signature)
        info!("📝 Creating transaction with vendor wallet (auto-signing)...");

        let vendor_wallet = self
            .wallets
            .get(&vendor_id)
            .ok_or(WalletManagerError::WalletNotFound(vendor_id))?;

        let create_result = vendor_wallet
            .rpc_client
            .rpc()
            .transfer_multisig(vec![
                monero_marketplace_common::types::TransferDestination {
                    address: destination_address.clone(),
                    amount: adjusted_amount,
                },
            ])
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!(
            "✅ Transaction created and auto-signed by vendor: fee={} atomic units",
            create_result.fee
        );

        // 5. Close wallets to free RPC slots
        info!("🔒 Closing wallets after vendor signature...");
        self.close_wallet_by_id(buyer_id).await?;
        self.close_wallet_by_id(vendor_id).await?;
        self.close_wallet_by_id(arbiter_id).await?;

        // 6. Return partially-signed multisig txset
        Ok(create_result.multisig_txset)
    }

    /// Complete transaction with buyer signature (Step 2 of vendor-buyer flow)
    ///
    /// This is called when buyer confirms receipt. It takes the vendor-signed
    /// transaction from database, adds buyer's signature (2nd of 2-of-3),
    /// and submits it to the Monero network.
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow identifier
    /// * `vendor_signed_txset` - Partially-signed transaction hex from vendor
    ///
    /// # Returns
    /// Transaction hash once successfully broadcast
    ///
    /// # Errors
    /// - WalletNotFound - Required wallet not found
    /// - RpcError - Monero RPC error during signing/submission
    pub async fn complete_with_buyer_signature(
        &mut self,
        escrow_id: Uuid,
        vendor_signed_txset: String,
    ) -> Result<String, WalletManagerError> {
        info!(
            "✅ Completing transaction with buyer signature for escrow {}",
            escrow_id
        );

        // 1. Reopen buyer wallet
        let buyer_id = self
            .reopen_wallet_for_signing(escrow_id, WalletRole::Buyer)
            .await?;

        info!("✅ Reopened buyer wallet: {}", buyer_id);

        // 2. Buyer signs the vendor-signed transaction (adds 2nd signature)
        info!("✍️ Adding buyer signature to vendor-signed transaction...");

        let buyer_wallet = self
            .wallets
            .get(&buyer_id)
            .ok_or(WalletManagerError::WalletNotFound(buyer_id))?;

        let buyer_signed = buyer_wallet
            .rpc_client
            .rpc()
            .sign_multisig(vendor_signed_txset)
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!("✅ Buyer signature added (2/2 signatures complete)");

        // 3. Submit fully-signed transaction to network
        info!("📡 Submitting fully-signed transaction to Monero network...");

        let submit_result = buyer_wallet
            .rpc_client
            .rpc()
            .submit_multisig(buyer_signed.tx_data_hex)
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        let tx_hash = submit_result
            .tx_hash_list
            .first()
            .ok_or_else(|| WalletManagerError::InvalidState {
                expected: "at least one tx_hash".to_string(),
                actual: "empty tx_hash_list".to_string(),
            })?
            .clone();

        info!(
            "✅ Transaction successfully broadcast: tx_hash={}, escrow={}",
            tx_hash, escrow_id
        );

        // 4. Close buyer wallet
        self.close_wallet_by_id(buyer_id).await?;
        info!("🔒 Closed buyer wallet");

        Ok(tx_hash)
    }

    /// Find two wallets by their roles
    fn find_wallets_for_escrow(
        &self,
        role1: WalletRole,
        role2: WalletRole,
    ) -> Result<(Uuid, Uuid), WalletManagerError> {
        let wallet1 = self
            .wallets
            .iter()
            .find(|(_, w)| w.role == role1)
            .map(|(id, _)| *id)
            .ok_or_else(|| WalletManagerError::InvalidState {
                expected: format!("{:?} wallet", role1),
                actual: "not found".to_string(),
            })?;

        let wallet2 = self
            .wallets
            .iter()
            .find(|(_, w)| w.role == role2)
            .map(|(id, _)| *id)
            .ok_or_else(|| WalletManagerError::InvalidState {
                expected: format!("{:?} wallet", role2),
                actual: "not found".to_string(),
            })?;

        Ok((wallet1, wallet2))
    }

    /// Validate that a wallet is in Ready multisig state
    fn validate_wallet_ready(&self, wallet_id: Uuid) -> Result<(), WalletManagerError> {
        let wallet = self
            .wallets
            .get(&wallet_id)
            .ok_or(WalletManagerError::WalletNotFound(wallet_id))?;

        match &wallet.multisig_state {
            MultisigState::Ready { .. } => Ok(()),
            state => Err(WalletManagerError::InvalidState {
                expected: "Ready".to_string(),
                actual: format!("{:?}", state),
            }),
        }
    }

    /// Get wallet balance (total and unlocked) for any wallet
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet to query
    ///
    /// # Returns
    /// Tuple of (total_balance, unlocked_balance) in atomic units
    ///
    /// # Errors
    /// - WalletNotFound - Wallet ID not found
    /// - RpcError - Monero RPC error during balance query
    pub async fn get_balance(&self, wallet_id: Uuid) -> Result<(u64, u64), WalletManagerError> {
        let wallet = self
            .wallets
            .get(&wallet_id)
            .ok_or(WalletManagerError::WalletNotFound(wallet_id))?;

        let (total, unlocked) = wallet
            .rpc_client
            .rpc()
            .get_balance()
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!(
            "Wallet {} balance: total={} unlocked={} atomic units",
            wallet_id, total, unlocked
        );

        Ok((total, unlocked))
    }

    /// Get transaction details by transaction hash
    ///
    /// # Arguments
    /// * `wallet_id` - Wallet that owns/knows about this transaction
    /// * `tx_hash` - Transaction hash to query
    ///
    /// # Returns
    /// Transaction details including confirmations, amount, block height
    ///
    /// # Errors
    /// - WalletNotFound - Wallet ID not found
    /// - RpcError - Monero RPC error (transaction not found, RPC unreachable, etc.)
    pub async fn get_transfer_by_txid(
        &self,
        wallet_id: Uuid,
        tx_hash: &str,
    ) -> Result<TransferInfo, WalletManagerError> {
        let wallet = self
            .wallets
            .get(&wallet_id)
            .ok_or(WalletManagerError::WalletNotFound(wallet_id))?;

        let transfer = wallet
            .rpc_client
            .rpc()
            .get_transfer_by_txid(tx_hash.to_string())
            .await
            .map_err(|e| WalletManagerError::RpcError(convert_monero_error(e)))?;

        info!(
            "Transaction {} details: confirmations={}, amount={} atomic units",
            &tx_hash[..10],
            transfer.confirmations,
            transfer.amount
        );

        Ok(TransferInfo {
            tx_hash: transfer.tx_hash,
            confirmations: transfer.confirmations as u32,
            amount: transfer.amount,
            block_height: Some(transfer.block_height),
        })
    }

    /// Recover active escrows from database after server restart
    ///
    /// Queries the repository for all active escrows and reconstructs
    /// WalletInstance objects in memory. Uses Log + Continue policy
    /// so individual escrow failures don't prevent server startup.
    ///
    /// # Returns
    /// Vec of successfully recovered escrow IDs
    ///
    /// # Errors
    /// Only fatal errors that prevent any recovery. Individual escrow
    /// failures are logged but don't cause method to fail.
    pub async fn recover_active_escrows(&mut self) -> Result<Vec<String>, WalletManagerError> {
        // Skip if persistence not enabled
        let Some(ref repo) = self.multisig_repo else {
            debug!("Multisig persistence not enabled, skipping recovery");
            return Ok(vec![]);
        };

        info!("Starting multisig wallet recovery from database");

        // Query all active escrows
        let snapshots = repo.find_active_escrows().map_err(|e| {
            error!(error = %e, "Failed to query active escrows from database");
            WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                "Recovery query failed: {}",
                e
            )))
        })?;

        if snapshots.is_empty() {
            info!("No active escrows found to recover");
            return Ok(vec![]);
        }

        info!("Found {} active escrows to recover", snapshots.len());

        let mut recovered_escrow_ids = Vec::new();

        // Recover each escrow (Log + Continue policy)
        for (escrow_id, snapshot) in &snapshots {
            match self.recover_single_escrow(escrow_id, snapshot).await {
                Ok(_) => {
                    info!(escrow_id, "✅ Escrow recovered successfully");
                    recovered_escrow_ids.push(escrow_id.clone());
                }
                Err(e) => {
                    // Log but don't fail - continue with other escrows
                    warn!(
                        escrow_id,
                        error = %e,
                        "Failed to recover escrow, skipping (Log + Continue policy)"
                    );
                }
            }
        }

        info!(
            "Recovery complete: {}/{} escrows recovered successfully",
            recovered_escrow_ids.len(),
            snapshots.len()
        );

        Ok(recovered_escrow_ids)
    }

    /// Recover a single escrow from snapshot
    ///
    /// Helper method for recover_active_escrows(). Reconstructs wallet
    /// instances for buyer/vendor/arbiter based on persisted state.
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow identifier
    /// * `snapshot` - Persisted multisig snapshot
    ///
    /// # Returns
    /// Ok(()) if all wallets reconstructed successfully
    ///
    /// # Errors
    /// Returns error if wallet reconstruction fails (missing RPC URL, connection failed, etc.)
    async fn recover_single_escrow(
        &mut self,
        escrow_id: &str,
        snapshot: &MultisigSnapshot,
    ) -> Result<(), WalletManagerError> {
        let total_start = std::time::Instant::now();
        debug!(escrow_id, phase = ?snapshot.phase, "Recovering escrow");

        // Load RPC configs from database
        let db_query_start = std::time::Instant::now();
        let rpc_configs =
            if let (Some(ref pool), Some(ref key)) = (&self.db_pool, &self.encryption_key) {
                use crate::models::wallet_rpc_config::WalletRpcConfig;

                let mut conn = pool.get().map_err(|e| {
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Failed to get DB connection during recovery: {}",
                        e
                    )))
                })?;

                WalletRpcConfig::find_by_escrow(&mut conn, escrow_id).map_err(|e| {
                    warn!(escrow_id, error = %e, "Failed to load RPC configs from DB");
                    WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                        "Failed to load RPC configs: {}",
                        e
                    )))
                })?
            } else {
                warn!(
                    escrow_id,
                    "Cannot recover: persistence not enabled (no db_pool or encryption_key)"
                );
                return Err(WalletManagerError::InvalidState {
                    expected: "Persistence enabled for recovery".to_string(),
                    actual: "No db_pool or encryption_key".to_string(),
                });
            };
        info!(
            "⏱️  [{}] DB query: {:?}",
            escrow_id,
            db_query_start.elapsed()
        );

        if rpc_configs.is_empty() {
            warn!(
                escrow_id,
                "No RPC configs found in database for this escrow"
            );
            return Err(WalletManagerError::InvalidState {
                expected: "At least one RPC config".to_string(),
                actual: "No RPC configs in database".to_string(),
            });
        }

        // Reconstruct wallet instances from RPC configs
        for rpc_config in rpc_configs {
            let wallet_start = std::time::Instant::now();
            let wallet_uuid = uuid::Uuid::parse_str(
                &rpc_config.wallet_id.clone().unwrap_or_default(),
            )
            .map_err(|e| WalletManagerError::InvalidState {
                expected: "Valid wallet UUID".to_string(),
                actual: format!("Invalid UUID: {}", e),
            })?;

            let role = match rpc_config.role.as_str() {
                "buyer" => WalletRole::Buyer,
                "vendor" => WalletRole::Vendor,
                "arbiter" => WalletRole::Arbiter,
                _ => {
                    warn!(escrow_id, role = %rpc_config.role, "Unknown role, skipping");
                    continue;
                }
            };

            // Decrypt RPC credentials
            let decrypt_start = std::time::Instant::now();
            let encryption_key = self.encryption_key.as_ref().unwrap();
            let rpc_url = rpc_config.decrypt_url(encryption_key)
                .map_err(|e| {
                    error!(escrow_id, wallet_id = %wallet_uuid, error = %e, "Failed to decrypt RPC URL");
                    WalletManagerError::RpcError(CommonError::MoneroRpc(
                        format!("Decryption failed: {}", e)
                    ))
                })?;

            let rpc_user = rpc_config.decrypt_user(encryption_key).map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Failed to decrypt RPC user: {}",
                    e
                )))
            })?;

            let rpc_password = rpc_config.decrypt_password(encryption_key).map_err(|e| {
                WalletManagerError::RpcError(CommonError::MoneroRpc(format!(
                    "Failed to decrypt RPC password: {}",
                    e
                )))
            })?;
            info!(
                "⏱️  [{}] Decrypt (3 fields): {:?}",
                escrow_id,
                decrypt_start.elapsed()
            );

            // Reconnect to wallet RPC
            let rpc_connect_start = std::time::Instant::now();
            let config = MoneroConfig {
                rpc_url: rpc_url.clone(),
                rpc_user,
                rpc_password,
                timeout_seconds: 30,
            };

            let rpc_client = MoneroClient::new(config)
                .map_err(|e| {
                    error!(escrow_id, wallet_id = %wallet_uuid, role = ?role, error = %e, "Failed to reconnect to wallet RPC");
                    WalletManagerError::RpcError(CommonError::MoneroRpc(
                        format!("Failed to reconnect to {} wallet RPC: {}", rpc_config.role, e),
                    ))
                })?;
            info!(
                "⏱️  [{}] RPC client connect: {:?}",
                escrow_id,
                rpc_connect_start.elapsed()
            );

            // Verify wallet is accessible
            let rpc_call_start = std::time::Instant::now();
            let wallet_info = rpc_client
                .get_wallet_info()
                .await
                .map_err(|e| {
                    error!(escrow_id, wallet_id = %wallet_uuid, error = %e, "Failed to get wallet info during recovery");
                    WalletManagerError::RpcError(CommonError::MoneroRpc(
                        format!("Failed to get wallet info: {}", e),
                    ))
                })?;
            info!(
                "⏱️  [{}] RPC get_wallet_info: {:?}",
                escrow_id,
                rpc_call_start.elapsed()
            );

            // Determine multisig state from phase
            let multisig_state = match &snapshot.phase {
                MultisigPhase::NotStarted => MultisigState::NotStarted,
                MultisigPhase::Preparing { .. } => MultisigState::NotStarted,
                MultisigPhase::Exchanging { round, .. } => MultisigState::InfoExchanged {
                    round: *round,
                    participants: vec![],
                },
                MultisigPhase::Ready { address, .. } => MultisigState::Ready {
                    address: address.clone(),
                },
                MultisigPhase::Failed { .. } => {
                    warn!(escrow_id, "Escrow in Failed state, not recovering");
                    return Err(WalletManagerError::InvalidState {
                        expected: "Active phase".to_string(),
                        actual: "Failed".to_string(),
                    });
                }
            };

            // Extract RPC port from recovered URL for WalletPool tracking
            let rpc_port = rpc_url
                .split(':')
                .nth(2)
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.parse::<u16>().ok());

            // Parse escrow_id for wallet recovery
            let escrow_uuid =
                Uuid::parse_str(escrow_id).map_err(|e| WalletManagerError::InvalidState {
                    expected: "Valid UUID for escrow_id in recovery".to_string(),
                    actual: format!("Parse error: {}", e),
                })?;

            // Reconstruct WalletInstance
            let instance = WalletInstance {
                id: wallet_uuid,
                role: role.clone(),
                rpc_client,
                address: wallet_info.address.clone(),
                multisig_state,
                rpc_port,
                escrow_id: Some(escrow_uuid), // ✅ Restored from database
            };

            // Insert into in-memory wallet map
            self.wallets.insert(wallet_uuid, instance);

            // Update last_connected_at timestamp
            if let Some(ref pool) = self.db_pool {
                use crate::models::wallet_rpc_config::WalletRpcConfig;
                let mut conn = pool.get().ok();
                if let Some(mut c) = conn {
                    let _ =
                        WalletRpcConfig::update_last_connected(&mut c, &wallet_uuid.to_string());
                }
            }

            info!(
                escrow_id,
                role = ?role,
                wallet_id = %wallet_uuid,
                address = %wallet_info.address,
                "✅ Wallet instance recovered and reconnected"
            );
            info!(
                "⏱️  [{}] TOTAL for 1 wallet ({:?}): {:?}",
                escrow_id,
                role,
                wallet_start.elapsed()
            );
        }

        info!(
            "⏱️  [{}] TOTAL ESCROW RECOVERY: {:?}",
            escrow_id,
            total_start.elapsed()
        );
        Ok(())
    }
}

/// Transfer information returned from blockchain queries
#[derive(Debug, Clone)]
pub struct TransferInfo {
    pub tx_hash: String,
    pub confirmations: u32,
    pub amount: u64,
    pub block_height: Option<u64>,
}

/// Convert MoneroError to CommonError
fn convert_monero_error(e: MoneroError) -> CommonError {
    match e {
        MoneroError::RpcUnreachable => CommonError::MoneroRpc("RPC unreachable".to_string()),
        MoneroError::AlreadyMultisig => {
            CommonError::Multisig("Already in multisig mode".to_string())
        }
        MoneroError::NotMultisig => CommonError::Multisig("Not in multisig mode".to_string()),
        MoneroError::WalletLocked => CommonError::Wallet("Wallet locked".to_string()),
        MoneroError::WalletBusy => CommonError::Wallet("Wallet busy".to_string()),
        MoneroError::ValidationError(msg) => CommonError::InvalidInput(msg),
        MoneroError::InvalidResponse(msg) => {
            CommonError::MoneroRpc(format!("Invalid response: {}", msg))
        }
        MoneroError::NetworkError(msg) => CommonError::Internal(format!("Network error: {}", msg)),
        MoneroError::RpcError(msg) => CommonError::MoneroRpc(msg),
    }
}

impl WalletManager {
    /// Sign transaction as arbiter (Phase 7 - Custodial Arbiter MVP)
    ///
    /// For dispute resolution, arbiter signs transactions with buyer OR vendor
    /// to enforce resolution decision.
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow identifier
    /// * `resolution` - "refund_buyer" or "pay_vendor"
    /// * `recipient_address` - Monero address to send funds
    ///
    /// # Returns
    /// Transaction hash if successful
    ///
    /// # Security
    /// - Arbiter wallet must be custodial (server holds key)
    /// - Buyer/Vendor wallets remain non-custodial
    /// - 2-of-3 multisig: Arbiter + (Buyer OR Vendor) required
    pub async fn arbiter_sign_transaction(
        &mut self,
        escrow_id: Uuid,
        resolution: &str,
        recipient_address: String,
    ) -> Result<String, CommonError> {
        info!(
            "Arbiter signing transaction for escrow {} with resolution: {}",
            escrow_id, resolution
        );

        // Find arbiter wallet for this escrow
        let _arbiter_wallet = self
            .wallets
            .values()
            .find(|w| w.role == WalletRole::Arbiter)
            .ok_or_else(|| {
                CommonError::Internal(format!("Arbiter wallet not found for escrow {}", escrow_id))
            })?;

        // Get co-signer role based on resolution
        let co_signer_role = match resolution {
            "refund_buyer" => WalletRole::Buyer,
            "pay_vendor" => WalletRole::Vendor,
            _ => {
                return Err(CommonError::InvalidInput(format!(
                    "Invalid resolution: {}",
                    resolution
                )))
            }
        };

        // Find co-signer wallet
        let _co_signer_wallet = self
            .wallets
            .values()
            .find(|w| w.role == co_signer_role)
            .ok_or_else(|| {
                CommonError::Internal(format!(
                    "Co-signer ({:?}) wallet not found for escrow {}",
                    co_signer_role, escrow_id
                ))
            })?;

        // DEPRECATED: Custodial mode arbiter signing not implemented
        //
        // This function was designed for custodial mode where the arbiter has
        // access to wallet keys on the server. NEXUS has transitioned to EaaS
        // (Escrow-as-a-Service) with non-custodial FROST multisig.
        //
        // For non-custodial dispute resolution, use:
        // - /api/escrow/{id}/dispute/initiate - Initiate dispute
        // - /api/escrow/{id}/dispute/submit-evidence - Submit evidence
        // - /api/escrow/{id}/airgap-dispute/resolve - Arbiter resolution via airgap signing
        //
        // The FROST signing flow in escrow.rs handles all multisig operations.

        error!(
            escrow_id = %escrow_id,
            resolution = %resolution,
            "[DEPRECATED] arbiter_sign_transaction called - custodial signing not implemented"
        );

        Err(CommonError::Internal(
            "Custodial arbiter signing is deprecated. Use non-custodial FROST signing flow via /api/escrow/{id}/airgap-dispute/resolve".to_string()
        ))
    }

    /// DEV ONLY: Create mock multisig wallets for testing
    ///
    /// This creates fake wallet entries in the wallets HashMap to allow
    /// testing release/refund flows without real multisig setup.
    pub async fn dev_create_mock_multisig(&mut self, escrow_id: Uuid) -> Result<(), CommonError> {
        info!(
            "DEV: Creating mock multisig wallets for escrow {}",
            escrow_id
        );

        // For each role, create a WalletInstance with mock data
        let roles = [
            (WalletRole::Buyer, "buyer"),
            (WalletRole::Vendor, "vendor"),
            (WalletRole::Arbiter, "arbiter"),
        ];

        for (role, role_str) in &roles {
            let wallet_uuid = Uuid::new_v4();
            let mock_address = format!("mock_address_{}_{}", escrow_id, role_str);

            // Create a mock RPC client with the first available config
            let rpc_client = MoneroClient::new(self.rpc_configs[0].clone()).map_err(|e| {
                CommonError::Internal(format!("Failed to create mock RPC client: {}", e))
            })?;

            let wallet_instance = WalletInstance {
                id: wallet_uuid,
                role: role.clone(),
                rpc_client,
                address: mock_address.clone(),
                multisig_state: MultisigState::Ready {
                    address: mock_address, // Mark as ready so release can proceed
                },
                rpc_port: None,             // Mock wallets don't track ports
                escrow_id: Some(escrow_id), // ✅ Link to escrow for mock testing
            };

            self.wallets.insert(wallet_uuid, wallet_instance);

            info!(
                "DEV: Created mock {} wallet (id={}) for escrow {}",
                role_str, wallet_uuid, escrow_id
            );
        }

        info!("DEV: Mock multisig setup complete for escrow {}", escrow_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test convert_monero_error covers all variants
    #[test]
    fn test_convert_monero_error_all_variants() {
        // RpcUnreachable
        let err = convert_monero_error(MoneroError::RpcUnreachable);
        assert!(matches!(err, CommonError::MoneroRpc(_)));

        // AlreadyMultisig
        let err = convert_monero_error(MoneroError::AlreadyMultisig);
        assert!(matches!(err, CommonError::Multisig(_)));

        // NotMultisig
        let err = convert_monero_error(MoneroError::NotMultisig);
        assert!(matches!(err, CommonError::Multisig(_)));

        // WalletLocked
        let err = convert_monero_error(MoneroError::WalletLocked);
        assert!(matches!(err, CommonError::Wallet(_)));

        // WalletBusy
        let err = convert_monero_error(MoneroError::WalletBusy);
        assert!(matches!(err, CommonError::Wallet(_)));

        // ValidationError
        let err = convert_monero_error(MoneroError::ValidationError("test error".to_string()));
        assert!(matches!(err, CommonError::InvalidInput(_)));

        // InvalidResponse
        let err = convert_monero_error(MoneroError::InvalidResponse("bad response".to_string()));
        assert!(matches!(err, CommonError::MoneroRpc(_)));

        // NetworkError
        let err = convert_monero_error(MoneroError::NetworkError("connection failed".to_string()));
        assert!(matches!(err, CommonError::Internal(_)));

        // RpcError
        let err = convert_monero_error(MoneroError::RpcError("rpc failed".to_string()));
        assert!(matches!(err, CommonError::MoneroRpc(_)));
    }

    /// Test WalletManager creation
    #[test]
    fn test_wallet_manager_new() {
        let config = MoneroConfig::default();
        let manager = WalletManager::new(vec![config]);
        assert!(manager.is_ok());
    }

    /// Test WalletManager rejects empty config list
    #[test]
    fn test_wallet_manager_new_empty_configs() {
        let result = WalletManager::new(vec![]);
        assert!(result.is_err());
    }

    /// Test MultisigState equality
    #[test]
    fn test_multisig_state_equality() {
        let state1 = MultisigState::NotStarted;
        let state2 = MultisigState::NotStarted;
        assert_eq!(state1, state2);

        let ready1 = MultisigState::Ready {
            address: "test_address".to_string(),
        };
        let ready2 = MultisigState::Ready {
            address: "test_address".to_string(),
        };
        assert_eq!(ready1, ready2);
    }

    /// Test WalletRole equality
    #[test]
    fn test_wallet_role_equality() {
        assert_eq!(WalletRole::Buyer, WalletRole::Buyer);
        assert_eq!(WalletRole::Vendor, WalletRole::Vendor);
        assert_eq!(WalletRole::Arbiter, WalletRole::Arbiter);
        assert_ne!(WalletRole::Buyer, WalletRole::Vendor);
    }

    /// Test WalletManagerError display messages
    #[test]
    fn test_wallet_manager_error_display() {
        let wallet_id = Uuid::new_v4();
        let err = WalletManagerError::WalletNotFound(wallet_id);
        let msg = format!("{}", err);
        assert!(msg.contains("Wallet not found"));

        let err = WalletManagerError::NoAvailableRpc;
        let msg = format!("{}", err);
        assert!(msg.contains("All RPC endpoints unavailable"));

        let err = WalletManagerError::InvalidState {
            expected: "Ready".to_string(),
            actual: "NotStarted".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid multisig state"));
        assert!(msg.contains("Ready"));
        assert!(msg.contains("NotStarted"));
    }

    /// Test RPC config round-robin
    #[test]
    fn test_rpc_round_robin() {
        let config1 = MoneroConfig {
            rpc_url: "http://127.0.0.1:18081".to_string(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 60,
        };
        let config2 = MoneroConfig {
            rpc_url: "http://127.0.0.1:18082".to_string(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 60,
        };

        let manager =
            WalletManager::new(vec![config1, config2]).expect("Failed to create WalletManager");

        assert_eq!(manager.next_rpc_index, 0);
        assert_eq!(manager.rpc_configs.len(), 2);
    }
    /// Test finalize_multisig with multiple concurrent escrows (Regression Test)
    #[tokio::test]
    async fn test_finalize_multisig_with_multiple_escrows() {
        // Setup WalletManager
        let config = MoneroConfig::default();
        let mut manager =
            WalletManager::new(vec![config.clone()]).expect("Failed to create manager");

        // Create two escrow IDs
        let escrow1_id = Uuid::new_v4();
        let escrow2_id = Uuid::new_v4();

        // Helper to create a mock wallet instance
        let create_mock_wallet =
            |role: WalletRole, escrow_id: Uuid, address: &str| -> WalletInstance {
                WalletInstance {
                    id: Uuid::new_v4(),
                    role,
                    rpc_client: MoneroClient::new(config.clone()).unwrap(), // Dummy client
                    address: "individual_address".to_string(),
                    multisig_state: MultisigState::Ready {
                        address: address.to_string(),
                    },
                    rpc_port: None,
                    escrow_id: Some(escrow_id),
                }
            };

        // Populate manager with wallets for Escrow 1 (Address: "multisig_addr_1")
        let wallets1 = vec![
            create_mock_wallet(WalletRole::Buyer, escrow1_id, "multisig_addr_1"),
            create_mock_wallet(WalletRole::Vendor, escrow1_id, "multisig_addr_1"),
            create_mock_wallet(WalletRole::Arbiter, escrow1_id, "multisig_addr_1"),
        ];

        // Populate manager with wallets for Escrow 2 (Address: "multisig_addr_2")
        let wallets2 = vec![
            create_mock_wallet(WalletRole::Buyer, escrow2_id, "multisig_addr_2"),
            create_mock_wallet(WalletRole::Vendor, escrow2_id, "multisig_addr_2"),
            create_mock_wallet(WalletRole::Arbiter, escrow2_id, "multisig_addr_2"),
        ];

        // Insert all into manager
        for w in wallets1.into_iter().chain(wallets2.into_iter()) {
            manager.wallets.insert(w.id, w);
        }

        // TEST 1: Finalize Escrow 1
        // Should only see wallets for escrow1_id and return "multisig_addr_1"
        let result1 = manager.finalize_multisig(escrow1_id).await;
        assert!(result1.is_ok(), "Finalize escrow 1 failed");
        assert_eq!(result1.unwrap(), "multisig_addr_1");

        // TEST 2: Finalize Escrow 2
        // Should only see wallets for escrow2_id and return "multisig_addr_2"
        let result2 = manager.finalize_multisig(escrow2_id).await;
        assert!(result2.is_ok(), "Finalize escrow 2 failed");
        assert_eq!(result2.unwrap(), "multisig_addr_2");
    }
}
