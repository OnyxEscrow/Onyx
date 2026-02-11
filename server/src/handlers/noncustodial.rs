//! Non-custodial escrow handlers (Haveno-inspired)
//!
//! This module provides API endpoints for the non-custodial escrow flow
//! where clients run their own monero-wallet-rpc instances and the server
//! acts as a pure coordinator for multisig info exchange.
//!
//! **Architecture Difference:**
//! - Old (handlers/escrow.rs): Server manages wallets via WalletManager
//! - New (this file): Server coordinates client wallets via EscrowCoordinator
//!
//! **Key Principle:**
//! The server NEVER creates, opens, or manages wallets. It only stores RPC URLs
//! and coordinates the exchange of public multisig info.

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::coordination::{EscrowCoordinator, EscrowRole, MultisigExchangeResult};

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

/// Request to register a client's local wallet RPC
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterClientWalletRequest {
    /// Escrow ID this wallet is for
    #[validate(length(min = 1, max = 100))]
    pub escrow_id: String,

    /// Role in escrow (buyer, seller, or arbiter)
    #[validate(length(min = 1, max = 20))]
    pub role: String,

    /// Client's local wallet RPC URL (must be localhost)
    /// Example: "http://127.0.0.1:18083"
    #[validate(url, length(min = 10, max = 200))]
    pub rpc_url: String,
}

/// Response after successful wallet registration
#[derive(Debug, Serialize)]
pub struct RegisterClientWalletResponse {
    pub success: bool,
    pub message: String,
    pub escrow_id: String,
    pub role: String,
    pub coordination_state: String,
    pub awaiting: Vec<String>, // List of roles still needed
}

/// Request to coordinate multisig exchange
#[derive(Debug, Deserialize, Validate)]
pub struct CoordinateExchangeRequest {
    /// Escrow ID to coordinate
    #[validate(length(min = 1, max = 100))]
    pub escrow_id: String,
}

/// Response with multisig infos for each participant
#[derive(Debug, Serialize)]
pub struct CoordinateExchangeResponse {
    pub success: bool,
    pub message: String,
    pub escrow_id: String,
    pub exchange_result: MultisigExchangeResult,
}

/// Request to get coordination status
#[derive(Debug, Deserialize)]
pub struct GetCoordinationStatusRequest {
    pub escrow_id: String,
}

/// Response with current coordination state
#[derive(Debug, Serialize)]
pub struct GetCoordinationStatusResponse {
    pub success: bool,
    pub escrow_id: String,
    pub state: String,
    pub buyer_registered: bool,
    pub seller_registered: bool,
    pub arbiter_registered: bool,
    pub ready_for_exchange: bool,
}

// ============================================================================
// HANDLERS
// ============================================================================

/// POST /api/v2/escrow/register-wallet
///
/// Register a client's local wallet RPC URL for non-custodial escrow.
///
/// **Flow:**
/// 1. Client starts local monero-wallet-rpc (e.g., on port 18083)
/// 2. Client calls this endpoint with escrow_id, role, and RPC URL
/// 3. Server validates localhost and checks RPC connectivity
/// 4. Server stores URL (NOT the wallet itself)
/// 5. When all 3 participants register, state → AllRegistered
///
/// **Example Request:**
/// ```json
/// {
///   "escrow_id": "escrow_abc123",
///   "role": "buyer",
///   "rpc_url": "http://127.0.0.1:18083"
/// }
/// ```
pub async fn register_client_wallet(
    coordinator: web::Data<EscrowCoordinator>,
    req: web::Json<RegisterClientWalletRequest>,
) -> impl Responder {
    use tracing::{error, info};

    // Validate request
    if let Err(e) = req.validate() {
        error!("Validation error in register_client_wallet: {}", e);
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": format!("Validation failed: {}", e)
        }));
    }

    // Parse role
    let role = match EscrowRole::from_str(&req.role) {
        Ok(r) => r,
        Err(e) => {
            error!("Invalid role '{}': {}", req.role, e);
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("Invalid role: {}", e)
            }));
        }
    };

    info!(
        "📝 Registering {} wallet for escrow {} at {}",
        role.as_str(),
        req.escrow_id,
        req.rpc_url
    );

    // Register with coordinator
    match coordinator
        .register_client_wallet(&req.escrow_id, role.clone(), req.rpc_url.clone())
        .await
    {
        Ok(()) => {
            // Get updated status to see what's still needed
            let status = coordinator
                .get_coordination_status(&req.escrow_id)
                .await
                .unwrap();

            let awaiting = vec![
                status.buyer_rpc_url.is_none().then_some("buyer"),
                status.seller_rpc_url.is_none().then_some("seller"),
                status.arbiter_rpc_url.is_none().then_some("arbiter"),
            ]
            .into_iter()
            .filter_map(|x| x.map(String::from))
            .collect::<Vec<_>>();

            let message = if awaiting.is_empty() {
                "✅ All participants registered! Ready to coordinate multisig exchange.".to_string()
            } else {
                format!(
                    "✅ {} wallet registered. Waiting for: {:?}",
                    role.as_str(),
                    awaiting
                )
            };

            info!(
                "✅ {} wallet registered for escrow {}, state: {:?}",
                role.as_str(),
                req.escrow_id,
                status.state
            );

            HttpResponse::Ok().json(RegisterClientWalletResponse {
                success: true,
                message,
                escrow_id: req.escrow_id.clone(),
                role: req.role.clone(),
                coordination_state: format!("{:?}", status.state),
                awaiting,
            })
        }
        Err(e) => {
            error!(
                "Failed to register {} wallet for escrow {}: {}",
                role.as_str(),
                req.escrow_id,
                e
            );
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Registration failed: {}", e)
            }))
        }
    }
}

/// POST /api/v2/escrow/coordinate-exchange
///
/// Coordinate multisig info exchange between all participants.
///
/// **Prerequisites:**
/// - All 3 wallets must be registered (buyer, seller, arbiter)
/// - Each wallet must have executed prepare_multisig locally
///
/// **Flow:**
/// 1. Server requests prepare_multisig from each client wallet
/// 2. Server validates all multisig_info formats
/// 3. Server exchanges infos (each gets the other 2)
/// 4. Clients finalize with make_multisig locally
///
/// **Example Request:**
/// ```json
/// {
///   "escrow_id": "escrow_abc123"
/// }
/// ```
///
/// **Example Response:**
/// ```json
/// {
///   "success": true,
///   "message": "Multisig exchange coordinated",
///   "exchange_result": {
///     "buyer_receives": ["MultisigV1...", "MultisigV1..."],
///     "seller_receives": ["MultisigV1...", "MultisigV1..."],
///     "arbiter_receives": ["MultisigV1...", "MultisigV1..."]
///   }
/// }
/// ```
pub async fn coordinate_multisig_exchange(
    coordinator: web::Data<EscrowCoordinator>,
    req: web::Json<CoordinateExchangeRequest>,
) -> impl Responder {
    use tracing::{error, info};

    // Validate request
    if let Err(e) = req.validate() {
        error!("Validation error in coordinate_exchange: {}", e);
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": format!("Validation failed: {}", e)
        }));
    }

    info!(
        "🔄 Coordinating multisig exchange for escrow {}",
        req.escrow_id
    );

    // Coordinate exchange
    match coordinator
        .coordinate_multisig_exchange(&req.escrow_id)
        .await
    {
        Ok(exchange_result) => {
            info!(
                "✅ Multisig exchange coordinated for escrow {}",
                req.escrow_id
            );

            HttpResponse::Ok().json(CoordinateExchangeResponse {
                success: true,
                message: "✅ Multisig info exchange coordinated successfully. Clients can now finalize with make_multisig.".to_string(),
                escrow_id: req.escrow_id.clone(),
                exchange_result,
            })
        }
        Err(e) => {
            error!(
                "Failed to coordinate multisig exchange for escrow {}: {}",
                req.escrow_id, e
            );
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Coordination failed: {}", e)
            }))
        }
    }
}

/// GET /api/v2/escrow/coordination-status/{escrow_id}
///
/// Get current coordination status for an escrow.
///
/// **Returns:**
/// - Current state (AwaitingRegistrations, AllRegistered, Prepared, etc.)
/// - Which participants are registered
/// - Whether ready for multisig exchange
pub async fn get_coordination_status(
    coordinator: web::Data<EscrowCoordinator>,
    escrow_id: web::Path<String>,
) -> impl Responder {
    use tracing::{error, info};

    let escrow_id = escrow_id.into_inner();
    info!("📊 Getting coordination status for escrow {}", escrow_id);

    match coordinator.get_coordination_status(&escrow_id).await {
        Ok(status) => {
            let buyer_registered = status.buyer_rpc_url.is_some();
            let seller_registered = status.seller_rpc_url.is_some();
            let arbiter_registered = status.arbiter_rpc_url.is_some();
            let ready_for_exchange = buyer_registered && seller_registered && arbiter_registered;

            HttpResponse::Ok().json(GetCoordinationStatusResponse {
                success: true,
                escrow_id,
                state: format!("{:?}", status.state),
                buyer_registered,
                seller_registered,
                arbiter_registered,
                ready_for_exchange,
            })
        }
        Err(e) => {
            error!(
                "Failed to get coordination status for escrow {}: {}",
                escrow_id, e
            );
            HttpResponse::NotFound().json(serde_json::json!({
                "success": false,
                "error": format!("Escrow not found: {}", e)
            }))
        }
    }
}

/// POST /api/v2/escrow/sync-round
///
/// Coordinate multisig synchronization rounds.
///
/// **Flow:**
/// 1. Each participant exports multisig_info
/// 2. Participant sends their export to this endpoint
/// 3. Server collects exports from all 3 participants
/// 4. Server returns exports from the OTHER 2 participants
///
/// **Rounds:**
/// - Round 1: After make_multisig()
/// - Round 2: After importing round 1 exports
///
/// **Example Request:**
/// ```json
/// {
///   "escrow_id": "escrow_abc123",
///   "round": 1,
///   "role": "buyer",
///   "export_info": "MultisigxV1..."
/// }
/// ```
pub async fn coordinate_sync_round(req: web::Json<SyncRoundRequest>) -> impl Responder {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tracing::{info, warn};

    // In-memory storage for sync round exports
    // Key: (escrow_id, round) -> HashMap<role, export_info>
    static SYNC_STORAGE: Lazy<Mutex<HashMap<(String, u8), HashMap<String, String>>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));

    let escrow_key = (req.escrow_id.clone(), req.round);

    info!(
        "🔄 Sync round {} for escrow {} from {}",
        req.round, req.escrow_id, req.role
    );

    // Store our export
    {
        let mut storage = SYNC_STORAGE.lock().unwrap();
        let round_exports = storage.entry(escrow_key.clone()).or_default();
        round_exports.insert(req.role.clone(), req.export_info.clone());

        info!(
            "Stored export for {} (round {}), total participants: {}",
            req.role,
            req.round,
            round_exports.len()
        );
    }

    // Wait for all 3 participants (or timeout)
    let storage = SYNC_STORAGE.lock().unwrap();
    let round_exports = storage.get(&escrow_key);

    if let Some(exports) = round_exports {
        if exports.len() == 3 {
            // All participants ready! Return the OTHER 2 exports
            let mut received_infos = Vec::new();
            for (role, export) in exports.iter() {
                if role != &req.role {
                    received_infos.push(export.clone());
                }
            }

            info!(
                "✅ Sync round {} complete for {}, returning {} exports",
                req.round,
                req.role,
                received_infos.len()
            );

            return HttpResponse::Ok().json(SyncRoundResponse {
                success: true,
                received_infos,
            });
        } else {
            // Not all participants ready yet
            warn!(
                "Sync round {} for escrow {} incomplete: {}/3 participants",
                req.round,
                req.escrow_id,
                exports.len()
            );
        }
    }

    // Not ready yet
    HttpResponse::Accepted().json(SyncRoundResponse {
        success: false,
        received_infos: vec![],
    })
}

/// POST /api/v2/escrow/funds-received
///
/// Client notifies server that funds were detected on multisig address.
///
/// **Flow:**
/// 1. Client monitors blockchain locally
/// 2. Client detects funds arrival
/// 3. Client calls this endpoint
/// 4. Server updates escrow status to "funded"
///
/// **Example Request:**
/// ```json
/// {
///   "escrow_id": "escrow_abc123",
///   "balance": 1500000000000
/// }
/// ```
pub async fn funds_received_notification(
    req: web::Json<FundsReceivedRequest>,
    db: web::Data<crate::db::DbPool>,
) -> impl Responder {
    use crate::schema::escrows;
    use diesel::prelude::*;
    use tracing::{error, info};

    info!(
        "💰 Funds received notification for escrow {}: {} atomic units",
        req.escrow_id, req.balance
    );

    let escrow_id = req.escrow_id.clone();
    let balance = req.balance;
    let db_clone = db.get_ref().clone();

    // Update escrow status in database
    let result = tokio::task::spawn_blocking(move || {
        let mut conn = db_clone
            .get()
            .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {e}"))?;

        diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
            .set((
                escrows::status.eq("funded"),
                escrows::updated_at.eq(chrono::Utc::now().naive_utc()),
            ))
            .execute(&mut conn)
            .map_err(|e| anyhow::anyhow!("Failed to update escrow status: {e}"))?;

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            let amount_xmr = balance as f64 / 1e12;
            info!(
                "✅ Escrow {} status updated to 'funded' ({} XMR)",
                req.escrow_id, amount_xmr
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Escrow status updated to funded"
            }))
        }
        Ok(Err(e)) => {
            error!("Failed to update escrow status: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to update status: {}", e)
            }))
        }
        Err(e) => {
            error!("Task panic: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Internal server error"
            }))
        }
    }
}

// ============================================================================
// NEW REQUEST/RESPONSE TYPES FOR SYNC AND MONITORING
// ============================================================================

#[derive(Debug, Deserialize, Validate)]
pub struct SyncRoundRequest {
    #[validate(length(min = 1))]
    pub escrow_id: String,
    pub round: u8,
    #[validate(length(min = 1))]
    pub role: String,
    #[validate(length(min = 1))]
    pub export_info: String,
}

#[derive(Debug, Serialize)]
pub struct SyncRoundResponse {
    pub success: bool,
    pub received_infos: Vec<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct FundsReceivedRequest {
    #[validate(length(min = 1))]
    pub escrow_id: String,
    pub balance: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_client_wallet_request_validation() {
        // Valid request
        let valid_req = RegisterClientWalletRequest {
            escrow_id: "escrow_123".to_string(),
            role: "buyer".to_string(),
            rpc_url: "http://127.0.0.1:18083".to_string(),
        };
        assert!(valid_req.validate().is_ok());

        // Invalid: empty escrow_id
        let invalid_req = RegisterClientWalletRequest {
            escrow_id: "".to_string(),
            role: "buyer".to_string(),
            rpc_url: "http://127.0.0.1:18083".to_string(),
        };
        assert!(invalid_req.validate().is_err());

        // Invalid: malformed URL
        let invalid_req = RegisterClientWalletRequest {
            escrow_id: "escrow_123".to_string(),
            role: "buyer".to_string(),
            rpc_url: "not-a-url".to_string(),
        };
        assert!(invalid_req.validate().is_err());
    }
}
