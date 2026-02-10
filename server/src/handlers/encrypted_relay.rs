//! Encrypted Relay Handlers for 100% Non-Custodial FROST Signing
//!
//! API endpoints for encrypted share relay:
//! - POST /api/v2/escrow/{id}/relay           - Store encrypted partial signature
//! - GET  /api/v2/escrow/{id}/relay           - Retrieve encrypted partial signature
//! - POST /api/v2/escrow/{id}/broadcast-signed - Broadcast completed signed transaction
//!
//! The server NEVER sees decrypted FROST shares - only opaque encrypted blobs.

use actix_session::Session;
use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::db::{db_load_escrow, DbPool};
use crate::models::encrypted_relay::{EncryptedRelay, NewEncryptedRelay, MAX_PAYLOAD_SIZE};
use crate::models::escrow::Escrow;
use crate::schema::escrows;
use monero_marketplace_wallet::daemon_pool::DaemonPool;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to store encrypted partial signature
#[derive(Debug, Deserialize)]
pub struct StoreRelayRequest {
    /// Base64-encoded encrypted blob (ChaCha20Poly1305 ciphertext)
    pub encrypted_blob: String,
    /// Role of the first signer (buyer/vendor)
    pub role: String,
    /// Hex-encoded ephemeral public key for ECDH
    pub ephemeral_pubkey: String,
    /// Hex-encoded nonce (12 bytes = 24 hex chars)
    pub nonce: String,
}

/// Response after storing relay
#[derive(Debug, Serialize)]
pub struct StoreRelayResponse {
    pub success: bool,
    pub relay_id: String,
    pub expires_at: String,
}

/// Response when retrieving relay
#[derive(Debug, Serialize)]
pub struct GetRelayResponse {
    pub success: bool,
    pub encrypted_blob: String,
    pub first_signer_role: String,
    pub first_signer_pubkey: String,
    pub nonce: String,
    pub relay_id: String,
}

/// Request to broadcast signed transaction
#[derive(Debug, Deserialize)]
pub struct BroadcastSignedRequest {
    /// Hex-encoded fully signed transaction
    pub signed_tx_hex: String,
}

/// Response after broadcast
#[derive(Debug, Serialize)]
pub struct BroadcastResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Generic error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Get user ID from session
fn get_user_id(session: &Session) -> Option<String> {
    session.get::<String>("user_id").ok().flatten()
}

/// Validate role is buyer or vendor
fn validate_signer_role(role: &str) -> bool {
    matches!(role.to_lowercase().as_str(), "buyer" | "vendor")
}

/// Get user's role in escrow
fn get_user_role_in_escrow(escrow: &Escrow, user_id: &str) -> Option<String> {
    if escrow.buyer_id == user_id {
        Some("buyer".to_string())
    } else if escrow.vendor_id == user_id {
        Some("vendor".to_string())
    } else if escrow.arbiter_id == user_id {
        Some("arbiter".to_string())
    } else {
        None
    }
}

/// Get the other signer role (for relay retrieval)
fn get_other_signer_role(first_role: &str) -> Option<&'static str> {
    match first_role.to_lowercase().as_str() {
        "buyer" => Some("vendor"),
        "vendor" => Some("buyer"),
        _ => None,
    }
}

// =============================================================================
// Handlers
// =============================================================================

/// Store encrypted partial signature (first signer)
///
/// POST /api/v2/escrow/{id}/relay
///
/// The first signer computes their partial CLSAG signature in WASM,
/// encrypts it with ChaCha20Poly1305 using ECDH shared secret,
/// and stores the opaque blob here for the second signer.
pub async fn store_encrypted_relay(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<StoreRelayRequest>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    // Authenticate user
    let user_id = match get_user_id(&session) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                success: false,
                error: "Not authenticated".to_string(),
            });
        }
    };

    // Validate role
    if !validate_signer_role(&body.role) {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Role must be 'buyer' or 'vendor'".to_string(),
        });
    }

    // Validate blob size
    if body.encrypted_blob.len() > MAX_PAYLOAD_SIZE {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Encrypted blob too large (max {} bytes)", MAX_PAYLOAD_SIZE),
        });
    }

    // Validate nonce format (24 hex chars = 12 bytes)
    if body.nonce.len() != 24 || hex::decode(&body.nonce).is_err() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Invalid nonce: must be 24 hex characters".to_string(),
        });
    }

    // Validate pubkey format (64 hex chars = 32 bytes)
    if body.ephemeral_pubkey.len() != 64 || hex::decode(&body.ephemeral_pubkey).is_err() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Invalid ephemeral_pubkey: must be 64 hex characters".to_string(),
        });
    }

    // Parse escrow_id as UUID
    let escrow_uuid = match Uuid::parse_str(&escrow_id) {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid escrow ID format".to_string(),
            });
        }
    };

    // Load escrow and verify user is participant
    let escrow = match db_load_escrow(&pool, escrow_uuid).await {
        Ok(e) => e,
        Err(_) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                success: false,
                error: "Escrow not found".to_string(),
            });
        }
    };

    // Get DB connection for relay operations
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB pool error: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Database error".to_string(),
            });
        }
    };

    // Verify user role matches claimed role
    let user_role = match get_user_role_in_escrow(&escrow, &user_id) {
        Some(r) => r,
        None => {
            return HttpResponse::Forbidden().json(ErrorResponse {
                success: false,
                error: "Not a participant in this escrow".to_string(),
            });
        }
    };

    if user_role.to_lowercase() != body.role.to_lowercase() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            success: false,
            error: format!(
                "Role mismatch: you are '{}', claimed '{}'",
                user_role, body.role
            ),
        });
    }

    // Check no pending relay exists
    match EncryptedRelay::find_pending_by_escrow(&mut conn, &escrow_id) {
        Ok(existing_list) => {
            if let Some(existing) = existing_list.into_iter().next() {
                if existing.is_expired() {
                    // Mark expired and continue
                    let _ = EncryptedRelay::mark_expired(&mut conn, &existing.id);
                } else {
                    return HttpResponse::Conflict().json(ErrorResponse {
                        success: false,
                        error: "A pending relay already exists for this escrow".to_string(),
                    });
                }
            }
        }
        Err(e) => {
            error!("DB query error: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Database error".to_string(),
            });
        }
    }

    // Create new relay entry
    let new_relay = NewEncryptedRelay::new(
        escrow_id.clone(),
        body.encrypted_blob.clone(),
        body.role.to_lowercase(),
        body.ephemeral_pubkey.clone(),
        body.nonce.clone(),
    );

    match new_relay.insert(&mut conn) {
        Ok(relay) => {
            info!(
                "Encrypted relay stored: escrow={}, role={}, relay_id={}",
                escrow_id, body.role, relay.id
            );

            HttpResponse::Ok().json(StoreRelayResponse {
                success: true,
                relay_id: relay.id,
                expires_at: relay.expires_at,
            })
        }
        Err(e) => {
            error!("Failed to store relay: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Failed to store relay".to_string(),
            })
        }
    }
}

/// Retrieve encrypted partial signature (second signer)
///
/// GET /api/v2/escrow/{id}/relay
///
/// The second signer retrieves the encrypted blob, decrypts it in WASM
/// using ECDH shared secret, completes the CLSAG signature, and broadcasts.
pub async fn get_encrypted_relay(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    // Authenticate user
    let user_id = match get_user_id(&session) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                success: false,
                error: "Not authenticated".to_string(),
            });
        }
    };

    // Parse escrow_id as UUID
    let escrow_uuid = match Uuid::parse_str(&escrow_id) {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid escrow ID format".to_string(),
            });
        }
    };

    // Load escrow and verify user is participant
    let escrow = match db_load_escrow(&pool, escrow_uuid).await {
        Ok(e) => e,
        Err(_) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                success: false,
                error: "Escrow not found".to_string(),
            });
        }
    };

    // Get user's role
    let user_role = match get_user_role_in_escrow(&escrow, &user_id) {
        Some(r) => r,
        None => {
            return HttpResponse::Forbidden().json(ErrorResponse {
                success: false,
                error: "Not a participant in this escrow".to_string(),
            });
        }
    };

    // Get DB connection for relay operations
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB pool error: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Database error".to_string(),
            });
        }
    };

    // Find pending relay
    let relay = match EncryptedRelay::find_pending_by_escrow(&mut conn, &escrow_id) {
        Ok(relays) => match relays.into_iter().next() {
            Some(r) => r,
            None => {
                return HttpResponse::NotFound().json(ErrorResponse {
                    success: false,
                    error: "No pending relay for this escrow".to_string(),
                });
            }
        },
        Err(e) => {
            error!("DB query error: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Database error".to_string(),
            });
        }
    };

    // Check if relay is expired
    if relay.is_expired() {
        let _ = EncryptedRelay::mark_expired(&mut conn, &relay.id);
        return HttpResponse::Gone().json(ErrorResponse {
            success: false,
            error: "Relay has expired".to_string(),
        });
    }

    // Verify user is the OTHER signer (not the one who created the relay)
    let expected_retriever_role = match get_other_signer_role(&relay.first_signer_role) {
        Some(r) => r,
        None => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Invalid first signer role in relay".to_string(),
            });
        }
    };

    if user_role.to_lowercase() != expected_retriever_role {
        return HttpResponse::Forbidden().json(ErrorResponse {
            success: false,
            error: format!(
                "Only '{}' can retrieve this relay (you are '{}')",
                expected_retriever_role, user_role
            ),
        });
    }

    // Mark as consumed
    if let Err(e) = EncryptedRelay::mark_consumed(&mut conn, &relay.id) {
        warn!("Failed to mark relay as consumed: {}", e);
        // Continue anyway - the data is still valid
    }

    info!(
        "Encrypted relay retrieved: escrow={}, relay_id={}, retriever={}",
        escrow_id, relay.id, user_role
    );

    HttpResponse::Ok().json(GetRelayResponse {
        success: true,
        encrypted_blob: relay.encrypted_blob,
        first_signer_role: relay.first_signer_role,
        first_signer_pubkey: relay.first_signer_pubkey,
        nonce: relay.nonce,
        relay_id: relay.id,
    })
}

/// Broadcast a fully signed transaction
///
/// POST /api/v2/escrow/{id}/broadcast-signed
///
/// After the second signer completes the CLSAG in WASM, they send the
/// fully signed TX hex here for broadcast to the Monero daemon.
pub async fn broadcast_signed_transaction(
    pool: web::Data<DbPool>,
    daemon_pool: web::Data<Arc<DaemonPool>>,
    path: web::Path<String>,
    body: web::Json<BroadcastSignedRequest>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    // Authenticate user
    let user_id = match get_user_id(&session) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                success: false,
                error: "Not authenticated".to_string(),
            });
        }
    };

    // Validate TX hex format
    if body.signed_tx_hex.is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "signed_tx_hex cannot be empty".to_string(),
        });
    }

    if hex::decode(&body.signed_tx_hex).is_err() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Invalid hex in signed_tx_hex".to_string(),
        });
    }

    // Parse escrow_id as UUID
    let escrow_uuid = match Uuid::parse_str(&escrow_id) {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid escrow ID format".to_string(),
            });
        }
    };

    // Load escrow and verify user is participant
    let escrow = match db_load_escrow(&pool, escrow_uuid).await {
        Ok(e) => e,
        Err(_) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                success: false,
                error: "Escrow not found".to_string(),
            });
        }
    };

    // Verify user is participant
    if get_user_role_in_escrow(&escrow, &user_id).is_none() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            success: false,
            error: "Not a participant in this escrow".to_string(),
        });
    }

    // Compute TX hash for tracking (Keccak256 of raw bytes)
    let tx_bytes = hex::decode(&body.signed_tx_hex).unwrap(); // Already validated above
    let tx_hash = {
        let mut hasher = Keccak256::new();
        hasher.update(&tx_bytes);
        hex::encode(hasher.finalize())
    };

    info!(
        "Broadcasting signed TX for escrow {}: {} bytes, hash={}...",
        escrow_id,
        tx_bytes.len(),
        &tx_hash[..16]
    );

    // Broadcast to Monero daemon via DaemonPool
    match daemon_pool.submit_transaction(&body.signed_tx_hex).await {
        Ok(_status) => {
            info!("TX broadcast successful: {}", tx_hash);

            // Update escrow status to completed with tx_hash
            if let Ok(mut conn) = pool.get() {
                let _ = diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
                    .set((
                        escrows::status.eq("completed"),
                        escrows::transaction_hash.eq(Some(&tx_hash)),
                        escrows::updated_at.eq(chrono::Utc::now().naive_utc()),
                    ))
                    .execute(&mut conn);
            }

            HttpResponse::Ok().json(BroadcastResponse {
                success: true,
                tx_hash: Some(tx_hash),
                error: None,
            })
        }
        Err(e) => {
            error!("TX broadcast failed: {:?}", e);
            HttpResponse::InternalServerError().json(BroadcastResponse {
                success: false,
                tx_hash: Some(tx_hash), // Still return hash for debugging
                error: Some(format!("Broadcast failed: {:?}", e)),
            })
        }
    }
}

/// Check relay status (for debugging/monitoring)
///
/// GET /api/v2/escrow/{id}/relay/status
pub async fn get_relay_status(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    // Authenticate user
    let user_id = match get_user_id(&session) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                success: false,
                error: "Not authenticated".to_string(),
            });
        }
    };

    // Parse escrow_id as UUID
    let escrow_uuid = match Uuid::parse_str(&escrow_id) {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid escrow ID format".to_string(),
            });
        }
    };

    // Load escrow and verify user is participant
    let escrow = match db_load_escrow(&pool, escrow_uuid).await {
        Ok(e) => e,
        Err(_) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                success: false,
                error: "Escrow not found".to_string(),
            });
        }
    };

    // Verify user is participant
    if get_user_role_in_escrow(&escrow, &user_id).is_none() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            success: false,
            error: "Not a participant in this escrow".to_string(),
        });
    }

    // Get DB connection for relay operations
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB pool error: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Database error".to_string(),
            });
        }
    };

    // Find relay
    match EncryptedRelay::find_pending_by_escrow(&mut conn, &escrow_id) {
        Ok(relays) => {
            if let Some(relay) = relays.into_iter().next() {
                #[derive(Serialize)]
                struct RelayStatusResponse {
                    success: bool,
                    has_pending_relay: bool,
                    first_signer_role: String,
                    is_expired: bool,
                    expires_at: String,
                }

                let is_expired = relay.is_expired();
                HttpResponse::Ok().json(RelayStatusResponse {
                    success: true,
                    has_pending_relay: true,
                    first_signer_role: relay.first_signer_role,
                    is_expired,
                    expires_at: relay.expires_at,
                })
            } else {
                #[derive(Serialize)]
                struct NoRelayResponse {
                    success: bool,
                    has_pending_relay: bool,
                }

                HttpResponse::Ok().json(NoRelayResponse {
                    success: true,
                    has_pending_relay: false,
                })
            }
        }
        Err(e) => {
            error!("DB query error: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Database error".to_string(),
            })
        }
    }
}

// =============================================================================
// Route Configuration
// =============================================================================

/// Configure encrypted relay routes
///
/// Adds the following endpoints to the API:
/// - POST /v2/escrow/{id}/relay           - Store encrypted partial signature
/// - GET  /v2/escrow/{id}/relay           - Retrieve encrypted partial signature
/// - GET  /v2/escrow/{id}/relay/status    - Check relay status
/// - POST /v2/escrow/{id}/broadcast-signed - Broadcast completed transaction
///
/// NOTE: Uses direct .route() calls instead of web::scope() to avoid shadowing
/// other /v2/escrow/{id}/... routes defined in main.rs
pub fn configure_encrypted_relay_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/v2/escrow/{id}/relay",
        web::post().to(store_encrypted_relay),
    )
    .route("/v2/escrow/{id}/relay", web::get().to(get_encrypted_relay))
    .route(
        "/v2/escrow/{id}/relay/status",
        web::get().to(get_relay_status),
    )
    .route(
        "/v2/escrow/{id}/broadcast-signed",
        web::post().to(broadcast_signed_transaction),
    );
}
