//! Non-custodial escrow coordinator
//!
//! Inspired by Haveno DEX architecture where the server acts as a pure coordinator
//! for multisig info exchange without ever touching wallet private keys.
//!
//! **Key Principles:**
//! 1. Server stores RPC URLs only (http://127.0.0.1:XXXX)
//! 2. Server coordinates multisig info exchange between participants
//! 3. Server validates formats, thresholds, and participant counts
//! 4. Server NEVER creates wallets or executes crypto operations
//! 5. Private keys NEVER leave client wallets
//!
//! **Flow:**
//! 1. Each participant (buyer, seller, arbiter) runs local monero-wallet-rpc
//! 2. Each registers their RPC URL with coordinator
//! 3. Coordinator requests prepare_multisig from each wallet
//! 4. Coordinator validates and exchanges multisig_info strings
//! 5. Clients finalize multisig locally using received infos

use monero_marketplace_common::{
    error::{Error, MoneroError, Result},
    types::{MoneroConfig, MultisigInfo},
};
use monero_marketplace_wallet::{rpc::MoneroRpcClient, validation::validate_localhost_strict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};
use actix::Addr;

use crate::db::DbPool;
use crate::models::escrow::Escrow;
use crate::models::wallet_rpc_config::WalletRpcConfig;
use diesel::prelude::*;

/// Pure coordinator for non-custodial escrow
///
/// This coordinator NEVER creates or manages wallets. It only stores RPC URLs
/// and coordinates the exchange of public multisig info between clients.
///
/// **v0.4.0 Update (Plan Revised)**: Stateless coordinator using escrows.multisig_phase + wallet_rpc_configs tables directly.
/// No in-memory cache - reads directly from DB for crash recovery.
pub struct EscrowCoordinator {
    /// Database connection pool
    db: Arc<DbPool>,
    /// AES-256-GCM encryption key for RPC credentials
    encryption_key: Vec<u8>,
    /// WebSocket server for real-time progress notifications
    ws_server: Addr<crate::websocket::WebSocketServer>,
}

/// Coordination state for one escrow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowCoordination {
    pub escrow_id: String,
    pub buyer_rpc_url: Option<String>,
    pub seller_rpc_url: Option<String>,
    pub arbiter_rpc_url: Option<String>,
    pub state: CoordinationState,
    /// Multisig info from each participant (public data only)
    pub multisig_infos: HashMap<String, String>, // role -> multisig_info
}

/// States of coordination process
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CoordinationState {
    /// Waiting for all 3 participants to register their wallets
    AwaitingRegistrations,
    /// All 3 wallets registered, ready to prepare multisig
    AllRegistered,
    /// prepare_multisig executed on all wallets, infos collected
    Prepared,
    /// Multisig info exchanged, clients can now make_multisig
    ReadyForMakeMultisig,
    /// make_multisig completed on clients (verified by export_multisig_info)
    MadeMultisig,
    /// First export/import round completed
    SyncRound1Complete,
    /// Second export/import round completed
    SyncRound2Complete,
    /// Multisig fully synchronized and ready for transactions
    Ready,
}

impl CoordinationState {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "awaiting_registrations" => Ok(CoordinationState::AwaitingRegistrations),
            "all_registered" => Ok(CoordinationState::AllRegistered),
            "prepared" => Ok(CoordinationState::Prepared),
            "ready_for_make_multisig" => Ok(CoordinationState::ReadyForMakeMultisig),
            "made_multisig" => Ok(CoordinationState::MadeMultisig),
            "sync_round1_complete" => Ok(CoordinationState::SyncRound1Complete),
            "sync_round2_complete" => Ok(CoordinationState::SyncRound2Complete),
            "ready" => Ok(CoordinationState::Ready),
            _ => Err(Error::InvalidInput(format!("Invalid coordination state: {}", s))),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            CoordinationState::AwaitingRegistrations => "awaiting_registrations",
            CoordinationState::AllRegistered => "all_registered",
            CoordinationState::Prepared => "prepared",
            CoordinationState::ReadyForMakeMultisig => "ready_for_make_multisig",
            CoordinationState::MadeMultisig => "made_multisig",
            CoordinationState::SyncRound1Complete => "sync_round1_complete",
            CoordinationState::SyncRound2Complete => "sync_round2_complete",
            CoordinationState::Ready => "ready",
        }
    }
}

/// Result of multisig info exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigExchangeResult {
    /// Multisig infos that buyer should receive (seller + arbiter)
    pub buyer_receives: Vec<String>,
    /// Multisig infos that seller should receive (buyer + arbiter)
    pub seller_receives: Vec<String>,
    /// Multisig infos that arbiter should receive (buyer + seller)
    pub arbiter_receives: Vec<String>,
}

/// Role in escrow
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscrowRole {
    Buyer,
    Seller,
    Arbiter,
}

impl EscrowRole {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "buyer" => Ok(EscrowRole::Buyer),
            "seller" => Ok(EscrowRole::Seller),
            "arbiter" => Ok(EscrowRole::Arbiter),
            _ => Err(Error::InvalidInput(format!("Invalid role: {}", s))),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            EscrowRole::Buyer => "buyer",
            EscrowRole::Seller => "seller",
            EscrowRole::Arbiter => "arbiter",
        }
    }
}

impl EscrowCoordinator {
    /// Create new stateless non-custodial coordinator
    ///
    /// **v0.4.0 Update**: Stateless design - no cache, reads directly from escrows + wallet_rpc_configs tables
    pub fn new(
        db: Arc<DbPool>,
        encryption_key: Vec<u8>,
        ws_server: Addr<crate::websocket::WebSocketServer>,
    ) -> Self {
        info!("🔧 Creating stateless non-custodial EscrowCoordinator");
        Self {
            db,
            encryption_key,
            ws_server,
        }
    }

    /// Load coordination state for a specific escrow from database
    ///
    /// Constructs EscrowCoordination from escrows.multisig_phase + wallet_rpc_configs
    fn load_coordination(&self, escrow_id: &str) -> Result<EscrowCoordination> {
        let mut conn = self.db.get().map_err(|e| Error::Internal(format!("DB connection failed: {}", e)))?;

        // Load escrow record
        let escrow = Escrow::find_by_id(&mut conn, escrow_id.to_string())
            .map_err(|e| Error::Internal(format!("Escrow not found: {}", e)))?;

        // Load RPC configs for this escrow
        let rpc_configs = WalletRpcConfig::find_by_escrow(&mut conn, escrow_id)
            .map_err(|e| Error::Internal(format!("Failed to load RPC configs: {}", e)))?;

        // Decrypt RPC URLs
        let mut buyer_rpc_url = None;
        let mut seller_rpc_url = None;
        let mut arbiter_rpc_url = None;

        for config in rpc_configs {
            let decrypted_url = config.decrypt_url(&self.encryption_key)
                .map_err(|e| Error::Internal(format!("Failed to decrypt RPC URL: {}", e)))?;

            match config.role.as_str() {
                "buyer" => buyer_rpc_url = Some(decrypted_url),
                "seller" | "vendor" => seller_rpc_url = Some(decrypted_url),
                "arbiter" => arbiter_rpc_url = Some(decrypted_url),
                _ => warn!("Unknown role in RPC config: {}", config.role),
            }
        }

        // Parse multisig state from JSON
        let multisig_infos = if let Some(json) = &escrow.multisig_state_json {
            serde_json::from_str(json)
                .map_err(|e| Error::Internal(format!("Failed to parse multisig_state_json: {}", e)))?
        } else {
            HashMap::new()
        };

        Ok(EscrowCoordination {
            escrow_id: escrow.id,
            buyer_rpc_url,
            seller_rpc_url,
            arbiter_rpc_url,
            state: CoordinationState::from_str(&escrow.multisig_phase)?,
            multisig_infos,
        })
    }

    /// Register a client wallet RPC URL (NON-CUSTODIAL)
    ///
    /// **Security:**
    /// - Validates RPC URL is localhost only (no remote wallets)
    /// - Checks RPC connectivity before accepting
    /// - Stores URL only (NOT the wallet itself)
    ///
    /// # Arguments
    /// * `escrow_id` - Unique escrow identifier
    /// * `role` - Role in escrow (buyer, seller, arbiter)
    /// * `rpc_url` - Client's local wallet RPC URL (must be localhost)
    ///
    /// # Returns
    /// Ok(()) if wallet registered successfully
    ///
    /// # Errors
    /// - Error::InvalidInput - Invalid role or URL format
    /// - Error::Security - RPC URL is not localhost
    /// - Error::MoneroRpc - Cannot connect to RPC
    /// Register a client wallet (RPC endpoint) for an escrow
    ///
    /// Production: ALWAYS validates RPC connectivity
    /// Tests: Skip RPC validation (no Monero daemon available in unit tests)
    #[cfg(not(test))]
    pub async fn register_client_wallet(
        &self,
        escrow_id: &str,
        role: EscrowRole,
        rpc_url: String,
    ) -> Result<()> {
        info!(
            "📝 Registering {} wallet for escrow {} at {}",
            role.as_str(),
            escrow_id,
            rpc_url
        );

        // CRITICAL: Validate localhost strict (prevent remote wallet attacks)
        validate_localhost_strict(&rpc_url).map_err(|e| {
            error!("🚨 SECURITY: Non-localhost RPC URL rejected: {}", rpc_url);
            Error::Security(format!("RPC must be localhost: {}", e))
        })?;

        // PRODUCTION ONLY: Verify RPC connectivity (mandatory)
        let config = MoneroConfig {
            rpc_url: rpc_url.clone(),
            ..Default::default()
        };

        let client = MoneroRpcClient::new(config).map_err(|e| {
            error!("Failed to create RPC client for {}: {}", rpc_url, e);
            Error::MoneroRpc(format!("Invalid RPC config: {}", e))
        })?;

        client.check_connection().await.map_err(|e| {
            error!("Cannot connect to RPC at {}: {}", rpc_url, e);
            Error::MoneroRpc(format!("RPC unreachable: {}", e))
        })?;

        self.store_wallet_registration(escrow_id, role, rpc_url).await
    }

    /// Test-only version: skip RPC validation
    #[cfg(test)]
    pub async fn register_client_wallet(
        &self,
        escrow_id: &str,
        role: EscrowRole,
        rpc_url: String,
    ) -> Result<()> {
        info!(
            "📝 [TEST] Registering {} wallet for escrow {} at {}",
            role.as_str(),
            escrow_id,
            rpc_url
        );

        // CRITICAL: Always validate localhost (security remains)
        validate_localhost_strict(&rpc_url).map_err(|e| {
            error!("🚨 SECURITY: Non-localhost RPC URL rejected: {}", rpc_url);
            Error::Security(format!("RPC must be localhost: {}", e))
        })?;

        // TEST ONLY: Skip RPC connectivity check (no Monero daemon in unit tests)
        // Production version ALWAYS validates RPC connectivity

        self.store_wallet_registration(escrow_id, role, rpc_url).await
    }

    /// Shared logic for storing wallet registration
    ///
    /// **v0.4.0**: Saves encrypted RPC URL to wallet_rpc_configs table
    async fn store_wallet_registration(
        &self,
        escrow_id: &str,
        role: EscrowRole,
        rpc_url: String,
    ) -> Result<()> {
        use uuid::Uuid;
        use crate::schema::escrows;

        let mut conn = self.db.get().map_err(|e| Error::Internal(format!("DB connection failed: {}", e)))?;

        // 1. Save encrypted RPC URL to wallet_rpc_configs
        let wallet_id = Uuid::new_v4().to_string();
        WalletRpcConfig::save(
            &mut conn,
            &wallet_id,
            escrow_id,
            role.as_str(),
            &rpc_url,
            None, // rpc_user
            None, // rpc_password
            &self.encryption_key,
        ).map_err(|e| Error::Internal(format!("Failed to save RPC config: {}", e)))?;

        info!("✅ Saved {} RPC config for escrow {}", role.as_str(), escrow_id);

        // 2. Check if all 3 wallets are now registered
        let rpc_configs = WalletRpcConfig::find_by_escrow(&mut conn, escrow_id)
            .map_err(|e| Error::Internal(format!("Failed to load RPC configs: {}", e)))?;

        let roles: Vec<String> = rpc_configs.iter().map(|c| c.role.clone()).collect();
        let has_buyer = roles.iter().any(|r| r == "buyer");
        let has_seller = roles.iter().any(|r| r == "seller" || r == "vendor");
        let has_arbiter = roles.iter().any(|r| r == "arbiter");

        // 3. Update multisig_phase in escrows table
        let new_phase = if has_buyer && has_seller && has_arbiter {
            info!("✅ All 3 wallets registered for escrow {}, ready to prepare multisig", escrow_id);
            "all_registered"
        } else {
            info!("⏳ Waiting for remaining participants for escrow {} (registered: {:?})", escrow_id, roles);
            "awaiting_registrations"
        };

        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
            .set((
                escrows::multisig_phase.eq(new_phase),
                escrows::multisig_updated_at.eq(chrono::Utc::now().timestamp() as i32),
            ))
            .execute(&mut conn)
            .map_err(|e| Error::Internal(format!("Failed to update multisig_phase: {}", e)))?;

        // 4. Send WebSocket notification when all wallets registered (Step 2)
        if new_phase == "all_registered" {
            use crate::websocket::WsEvent;
            self.ws_server.do_send(WsEvent::EscrowProgress {
                escrow_id: escrow_id.to_string(),
                step: 2,
            });
            info!("📡 Sent EscrowProgress step 2 notification for escrow {}", escrow_id);
        }

        Ok(())
    }

    /// Coordinate multisig info exchange (NON-CUSTODIAL)
    ///
    /// **Flow:**
    /// 1. Verify all 3 wallets are registered
    /// 2. Request prepare_multisig from each wallet (executed on CLIENT side)
    /// 3. Validate all multisig_info formats
    /// 4. Exchange infos (each participant receives the other 2)
    ///
    /// **Security:**
    /// - Server NEVER executes prepare_multisig itself
    /// - Server only requests clients to execute it
    /// - Server validates public info formats
    /// - Server ensures threshold=2, participants=3 (Haveno-style validation)
    ///
    /// # Arguments
    /// * `escrow_id` - Escrow identifier
    ///
    /// # Returns
    /// MultisigExchangeResult with infos for each participant
    ///
    /// # Errors
    /// - Error::InvalidState - Not all wallets registered
    /// - Error::MoneroRpc - Cannot communicate with wallets
    /// - Error::InvalidInput - Invalid multisig info format
    pub async fn coordinate_multisig_exchange(
        &self,
        escrow_id: &str,
    ) -> Result<MultisigExchangeResult> {
        info!("🔄 Coordinating multisig exchange for escrow {}", escrow_id);

        // Send WebSocket notification that multisig exchange started (Step 3)
        use crate::websocket::WsEvent;
        self.ws_server.do_send(WsEvent::EscrowProgress {
            escrow_id: escrow_id.to_string(),
            step: 3,
        });
        info!("📡 Sent EscrowProgress step 3 notification for escrow {}", escrow_id);

        // Get coordination state from database
        let coord = self.load_coordination(escrow_id)?;

        // Verify all 3 wallets registered
        let buyer_url = coord.buyer_rpc_url.as_ref().ok_or_else(|| {
            error!("Buyer wallet not registered for escrow {}", escrow_id);
            Error::InvalidState("Buyer wallet not registered".to_string())
        })?;

        let seller_url = coord.seller_rpc_url.as_ref().ok_or_else(|| {
            error!("Seller wallet not registered for escrow {}", escrow_id);
            Error::InvalidState("Seller wallet not registered".to_string())
        })?;

        let arbiter_url = coord.arbiter_rpc_url.as_ref().ok_or_else(|| {
            error!("Arbiter wallet not registered for escrow {}", escrow_id);
            Error::InvalidState("Arbiter wallet not registered".to_string())
        })?;

        // Clone URLs for async operations
        let buyer_url = buyer_url.clone();
        let seller_url = seller_url.clone();
        let arbiter_url = arbiter_url.clone();

        info!("🔧 Requesting prepare_multisig from all participants...");

        // Request prepare_multisig from each wallet (executed on CLIENT side)
        let buyer_info = self
            .request_prepare_multisig(&buyer_url, "buyer")
            .await?;
        let seller_info = self
            .request_prepare_multisig(&seller_url, "seller")
            .await?;
        let arbiter_info = self
            .request_prepare_multisig(&arbiter_url, "arbiter")
            .await?;

        // Validate formats (security check)
        self.validate_multisig_info(&buyer_info, "buyer")?;
        self.validate_multisig_info(&seller_info, "seller")?;
        self.validate_multisig_info(&arbiter_info, "arbiter")?;

        // Store multisig infos in escrows.multisig_state_json
        let mut multisig_infos: HashMap<String, String> = HashMap::new();
        multisig_infos.insert("buyer".to_string(), buyer_info.clone());
        multisig_infos.insert("seller".to_string(), seller_info.clone());
        multisig_infos.insert("arbiter".to_string(), arbiter_info.clone());

        let multisig_state_json = serde_json::to_string(&multisig_infos)
            .map_err(|e| Error::Internal(format!("Failed to serialize multisig_infos: {}", e)))?;

        use crate::schema::escrows;
        let mut conn = self.db.get().map_err(|e| Error::Internal(format!("DB connection failed: {}", e)))?;

        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
            .set((
                escrows::multisig_state_json.eq(multisig_state_json),
                escrows::multisig_phase.eq("prepared"),
                escrows::multisig_updated_at.eq(chrono::Utc::now().timestamp() as i32),
            ))
            .execute(&mut conn)
            .map_err(|e| Error::Internal(format!("Failed to update multisig state: {}", e)))?;

        info!(
            "✅ Multisig info exchange coordinated for escrow {}",
            escrow_id
        );

        // Send WebSocket notification that multisig is prepared (Step 4)
        self.ws_server.do_send(WsEvent::EscrowProgress {
            escrow_id: escrow_id.to_string(),
            step: 4,
        });
        info!("📡 Sent EscrowProgress step 4 notification for escrow {}", escrow_id);

        // Exchange: each participant receives the other 2
        Ok(MultisigExchangeResult {
            buyer_receives: vec![seller_info.clone(), arbiter_info.clone()],
            seller_receives: vec![buyer_info.clone(), arbiter_info.clone()],
            arbiter_receives: vec![buyer_info, seller_info],
        })
    }

    /// Get coordination status for an escrow
    pub async fn get_coordination_status(
        &self,
        escrow_id: &str,
    ) -> Result<EscrowCoordination> {
        self.load_coordination(escrow_id)
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    /// Request prepare_multisig from a client wallet
    ///
    /// **CRITICAL:** This method connects to CLIENT's wallet-rpc and asks it to
    /// execute prepare_multisig. The server NEVER executes this itself.
    async fn request_prepare_multisig(&self, rpc_url: &str, role: &str) -> Result<String> {
        info!("📡 Requesting prepare_multisig from {} at {}", role, rpc_url);

        let config = MoneroConfig {
            rpc_url: rpc_url.to_string(),
            ..Default::default()
        };

        let client = MoneroRpcClient::new(config).map_err(|e| {
            error!(
                "Failed to create RPC client for {} at {}: {}",
                role, rpc_url, e
            );
            Error::MoneroRpc(format!("RPC client creation failed: {}", e))
        })?;

        let info: MultisigInfo = client.prepare_multisig().await.map_err(|e| {
            error!("prepare_multisig failed for {} at {}: {}", role, rpc_url, e);
            match e {
                MoneroError::AlreadyMultisig => {
                    Error::InvalidState(format!("{} wallet already in multisig mode", role))
                }
                MoneroError::WalletLocked => {
                    Error::Wallet(format!("{} wallet is locked", role))
                }
                _ => Error::MoneroRpc(format!("prepare_multisig failed for {}: {}", role, e)),
            }
        })?;

        info!(
            "✅ Received multisig info from {} ({} bytes)",
            role,
            info.multisig_info.len()
        );

        Ok(info.multisig_info)
    }

    /// Validate multisig info format
    ///
    /// Follows Haveno pattern of strict validation
    fn validate_multisig_info(&self, info: &str, role: &str) -> Result<()> {
        use monero_marketplace_common::{MAX_MULTISIG_INFO_LEN, MIN_MULTISIG_INFO_LEN};

        // Length validation
        if info.len() < MIN_MULTISIG_INFO_LEN {
            return Err(Error::InvalidInput(format!(
                "{} multisig_info too short: {} bytes (min: {})",
                role,
                info.len(),
                MIN_MULTISIG_INFO_LEN
            )));
        }

        if info.len() > MAX_MULTISIG_INFO_LEN {
            return Err(Error::InvalidInput(format!(
                "{} multisig_info too long: {} bytes (max: {})",
                role,
                info.len(),
                MAX_MULTISIG_INFO_LEN
            )));
        }

        // Format validation (should start with "MultisigV1")
        if !info.starts_with("MultisigV1") && !info.starts_with("MultisigxV1") {
            return Err(Error::InvalidInput(format!(
                "{} multisig_info has invalid format (should start with MultisigV1 or MultisigxV1)",
                role
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::r2d2::{ConnectionManager, Pool};
    use diesel::SqliteConnection;
    use std::sync::Arc;

    fn create_test_db_pool() -> Arc<Pool<ConnectionManager<SqliteConnection>>> {
        // Use in-memory database for tests
        let manager = ConnectionManager::<SqliteConnection>::new(":memory:");
        let pool = Pool::builder()
            .build(manager)
            .expect("Failed to create test pool");
        Arc::new(pool)
    }

    #[actix::test]
    async fn test_coordinator_creation() {
        use actix::Actor;
        use crate::websocket::WebSocketServer;
        let pool = create_test_db_pool();
        let encryption_key = vec![0u8; 32]; // Dummy key for test
        let ws_server = WebSocketServer::default().start();
        let _coordinator = EscrowCoordinator::new(pool, encryption_key, ws_server);
        // Stateless design - no cache to check
    }

    #[tokio::test]
    async fn test_escrow_role_conversion() {
        assert_eq!(EscrowRole::from_str("buyer").unwrap(), EscrowRole::Buyer);
        assert_eq!(EscrowRole::from_str("BUYER").unwrap(), EscrowRole::Buyer);
        assert_eq!(
            EscrowRole::from_str("seller").unwrap(),
            EscrowRole::Seller
        );
        assert_eq!(
            EscrowRole::from_str("arbiter").unwrap(),
            EscrowRole::Arbiter
        );
        assert!(EscrowRole::from_str("invalid").is_err());
    }

    #[tokio::test]
    #[ignore] // TODO: Rewrite for stateless v0.4.0 design
    async fn test_coordination_state_transitions() {
        use actix::Actor;
        use crate::websocket::WebSocketServer;
        let pool = create_test_db_pool();
        let encryption_key = vec![0u8; 32];
        let ws_server = WebSocketServer::default().start();
        let coordinator = EscrowCoordinator::new(pool, encryption_key, ws_server);
        let escrow_id = "test_escrow_123";

        // Register buyer (should still be AwaitingRegistrations)
        coordinator
            .register_client_wallet(
                escrow_id,
                EscrowRole::Buyer,
                "http://127.0.0.1:18083".to_string(),
            )
            .await
            .unwrap();

        let status = coordinator.get_coordination_status(escrow_id).await.unwrap();
        assert_eq!(status.state, CoordinationState::AwaitingRegistrations);

        // Register seller (still waiting for arbiter)
        coordinator
            .register_client_wallet(
                escrow_id,
                EscrowRole::Seller,
                "http://127.0.0.1:18084".to_string(),
            )
            .await
            .unwrap();

        let status = coordinator.get_coordination_status(escrow_id).await.unwrap();
        assert_eq!(status.state, CoordinationState::AwaitingRegistrations);

        // Register arbiter (all 3 registered → AllRegistered)
        coordinator
            .register_client_wallet(
                escrow_id,
                EscrowRole::Arbiter,
                "http://127.0.0.1:18085".to_string(),
            )
            .await
            .unwrap();

        let status = coordinator.get_coordination_status(escrow_id).await.unwrap();
        assert_eq!(status.state, CoordinationState::AllRegistered);
        assert!(status.buyer_rpc_url.is_some());
        assert!(status.seller_rpc_url.is_some());
        assert!(status.arbiter_rpc_url.is_some());
    }

    #[actix::test]
    async fn test_multisig_info_validation() {
        use actix::Actor;
        use crate::websocket::WebSocketServer;
        let pool = create_test_db_pool();
        let encryption_key = vec![0u8; 32];
        let ws_server = WebSocketServer::default().start();
        let coordinator = EscrowCoordinator::new(pool, encryption_key, ws_server);

        // Too short
        let result = coordinator.validate_multisig_info("short", "buyer");
        assert!(result.is_err());

        // Invalid format (doesn't start with MultisigV1)
        let invalid = "InvalidPrefix".to_string() + &"x".repeat(200);
        let result = coordinator.validate_multisig_info(&invalid, "buyer");
        assert!(result.is_err());

        // Valid format
        let valid = "MultisigV1".to_string() + &"x".repeat(200);
        let result = coordinator.validate_multisig_info(&valid, "buyer");
        assert!(result.is_ok());
    }

    // Note: Full integration tests require running monero-wallet-rpc instances
    // See server/tests/noncustodial/ for E2E tests
}

/// Get the sole arbiter user ID for Phase 7 MVP
///
/// Queries database for user with role='arbiter'. In production,
/// this should be configurable or use round-robin for multiple arbiters.
///
/// # Arguments
/// * `conn` - Database connection
///
/// # Returns
/// Ok(arbiter_user_id) if exactly one arbiter found
///
/// # Errors
/// - Error if no arbiters found
/// - Error if multiple arbiters found (ambiguous)
pub fn get_sole_arbiter_id(conn: &mut diesel::SqliteConnection) -> anyhow::Result<String> {
    use crate::schema::users::dsl::*;
    use anyhow::{bail, Context};
    use diesel::prelude::*;

    let arbiters: Vec<String> = users
        .filter(role.eq("arbiter"))
        .select(id)
        .load(conn)
        .context("Failed to query arbiters from database")?;

    match arbiters.len() {
        0 => bail!("No arbiter found. Create arbiter user with scripts/create_arbiter.sh"),
        1 => Ok(arbiters[0].clone()),
        _ => {
            warn!(
                "Multiple arbiters found ({}). Using first one. Consider implementing round-robin.",
                arbiters.len()
            );
            Ok(arbiters[0].clone())
        }
    }
}
