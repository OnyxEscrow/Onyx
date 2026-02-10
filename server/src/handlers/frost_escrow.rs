//! FROST DKG + Signing Escrow Handlers (RFC 9591)
//!
//! API endpoints for FROST 2-of-3 threshold CLSAG escrow:
//!
//! ## DKG Routes
//! - POST /api/escrow/frost/{id}/init        - Initialize FROST DKG
//! - POST /api/escrow/frost/{id}/dkg/round1  - Submit Round 1 package
//! - GET  /api/escrow/frost/{id}/dkg/round1  - Get all Round 1 packages
//! - POST /api/escrow/frost/{id}/dkg/round2  - Submit Round 2 packages
//! - GET  /api/escrow/frost/{id}/dkg/round2  - Get Round 2 packages for caller
//! - POST /api/escrow/frost/{id}/dkg/complete - Finalize DKG with group pubkey
//! - GET  /api/escrow/frost/{id}/status      - Get DKG status
//! - GET  /api/escrow/frost/{id}/lagrange    - Get Lagrange coefficients
//!
//! ## Signing Routes (delegated to frost_signing module)
//! - POST /api/escrow/frost/{id}/sign/init     - Initialize signing session
//! - POST /api/escrow/frost/{id}/sign/nonces   - Submit nonce commitment
//! - GET  /api/escrow/frost/{id}/sign/nonces   - Get aggregated nonces
//! - POST /api/escrow/frost/{id}/sign/partial  - Submit partial signature
//! - GET  /api/escrow/frost/{id}/sign/status   - Get signing status
//! - POST /api/escrow/frost/{id}/sign/complete - Aggregate and broadcast
//! - GET  /api/escrow/frost/{id}/sign/tx-data  - Get TX data for signing

use actix::Addr;
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::SqliteConnection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::handlers::auth_helpers::get_authenticated_identity;
use crate::models::escrow::Escrow;
use crate::models::frost_dkg::{DkgStatus, FrostRole};
use crate::models::notification::{NewNotification, Notification, NotificationType};
use crate::models::shield_backup::ShieldBackup;
use crate::models::webhook::WebhookEventType;
use crate::services::arbiter_auto_dkg::ArbiterAutoDkg;
use crate::services::frost_coordinator::FrostCoordinator;
use crate::services::webhook_dispatcher::{
    build_escrow_payload, emit_webhook_nonblocking, WebhookDispatcher,
};
use crate::websocket::{NotifyUser, WebSocketServer, WsEvent};

type DbPool = Pool<ConnectionManager<SqliteConnection>>;

/// Request to submit Round 1 package
#[derive(Debug, Deserialize)]
pub struct Round1Request {
    pub role: String,    // "buyer", "vendor", "arbiter"
    pub package: String, // Hex-encoded Round 1 package
}

/// Request to submit Round 2 packages
#[derive(Debug, Deserialize)]
pub struct Round2Request {
    pub role: String,                      // Sender role
    pub packages: HashMap<String, String>, // Recipient index -> package hex
}

/// Request to complete DKG
#[derive(Debug, Deserialize)]
pub struct CompleteDkgRequest {
    pub group_pubkey: String, // Hex-encoded group public key (32 bytes = 64 hex chars)
    pub multisig_address: String, // Monero address (95 characters)
    pub multisig_view_key: String, // Hex-encoded view key (32 bytes = 64 hex chars)
}

/// Request for Lagrange coefficients
#[derive(Debug, Deserialize)]
pub struct LagrangeRequest {
    pub signer1: String, // First signer role
    pub signer2: String, // Second signer role
}

/// Response with Lagrange coefficients
#[derive(Debug, Serialize)]
pub struct LagrangeResponse {
    pub signer1_lambda: String,
    pub signer2_lambda: String,
}

/// Request to register a shield backup
#[derive(Debug, Deserialize)]
pub struct RegisterShieldRequest {
    pub backup_id: String,
    pub role: String,
}

/// Request to verify a shield backup
#[derive(Debug, Deserialize)]
pub struct VerifyShieldRequest {
    pub backup_id: String,
}

/// Generic API response
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }
    }
}

/// Initialize FROST DKG for an escrow
///
/// POST /api/escrow/frost/{id}/init
pub async fn init_frost_dkg(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    // Dual auth: API key or session
    let user_id = match get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Not authenticated"));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostCoordinator::init_dkg(&mut conn, &escrow_id) {
        Ok(_state) => {
            info!(escrow_id = %escrow_id, user_id = %user_id, "FROST DKG initialized");
            // Use get_status to properly query frost_dkg_complete from escrows table
            match FrostCoordinator::get_status(&mut conn, &escrow_id) {
                Ok(status) => HttpResponse::Ok().json(ApiResponse::success(status)),
                Err(e) => {
                    error!("Failed to get DKG status: {}", e);
                    HttpResponse::InternalServerError().json(ApiResponse::<()>::error(&format!(
                        "Failed to get DKG status: {}",
                        e
                    )))
                }
            }
        }
        Err(e) => {
            error!("Failed to init FROST DKG: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(&format!(
                "Failed to init DKG: {}",
                e
            )))
        }
    }
}

/// Submit Round 1 package
///
/// POST /api/escrow/frost/{id}/dkg/round1
pub async fn submit_round1(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<Round1Request>,
    session: Session,
    websocket: web::Data<Addr<WebSocketServer>>,
    arbiter_auto_dkg: web::Data<Option<Arc<ArbiterAutoDkg>>>,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    // Dual auth: API key or session
    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let role = match FrostRole::from_str(&body.role) {
        Some(r) => r,
        None => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid role"));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostCoordinator::submit_round1(&mut conn, &escrow_id, role, &body.package) {
        Ok(all_submitted) => {
            // === ARBITER AUTO-DKG ===
            // If buyer or vendor submitted, try to auto-generate arbiter's Round 1
            if role != FrostRole::Arbiter {
                if let Some(ref auto_dkg) = arbiter_auto_dkg.as_ref() {
                    let escrow_id_clone = escrow_id.clone();
                    let auto_dkg_clone = Arc::clone(auto_dkg);

                    // Spawn async task to not block the response
                    tokio::spawn(async move {
                        match auto_dkg_clone.maybe_generate_round1(&escrow_id_clone).await {
                            Ok(generated) => {
                                if generated {
                                    info!(
                                        escrow_id = %escrow_id_clone,
                                        "🤖 Arbiter Round 1 auto-generated successfully"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(
                                    escrow_id = %escrow_id_clone,
                                    error = %e,
                                    "Failed to auto-generate arbiter Round 1"
                                );
                            }
                        }
                    });
                }
            }

            let status =
                FrostCoordinator::get_status(&mut conn, &escrow_id).unwrap_or_else(|_| DkgStatus {
                    escrow_id: escrow_id.clone(),
                    round1_complete: all_submitted,
                    round2_complete: false,
                    dkg_complete: false,
                    participants: crate::models::frost_dkg::DkgParticipants {
                        buyer_round1_ready: false,
                        vendor_round1_ready: false,
                        arbiter_round1_ready: false,
                        buyer_round2_ready: false,
                        vendor_round2_ready: false,
                        arbiter_round2_ready: false,
                    },
                });

            // === FROST DKG NOTIFICATIONS ===
            // Notify all parties about Round 1 progress
            if let Ok(escrow) = Escrow::find_by_id(&mut conn, escrow_id.clone()) {
                let parties_submitted = compute_round1_submitted(&status.participants);
                let parties_pending = compute_round1_pending(&status.participants);

                // If all submitted, notify that Round 1 is complete
                if all_submitted {
                    notify_all_parties(
                        &websocket,
                        &escrow,
                        WsEvent::FrostDkgRound1Complete {
                            escrow_id: parse_uuid_safe(&escrow_id),
                        },
                    );
                    info!(escrow_id = %escrow_id, "FROST DKG Round 1 complete, notifying parties");
                } else {
                    // Notify each party about Round 1 progress
                    for (party_id, party_role) in get_party_list(&escrow) {
                        // Send WebSocket notification
                        websocket.do_send(NotifyUser {
                            user_id: party_id.clone(),
                            event: WsEvent::FrostDkgRound1Required {
                                escrow_id: parse_uuid_safe(&escrow_id),
                                party_role: party_role.clone(),
                                parties_submitted: parties_submitted.clone(),
                                parties_pending: parties_pending.clone(),
                            },
                        });

                        // Create PERSISTENT DB notification for parties that need to act
                        if parties_pending.contains(&party_role) {
                            let notification = NewNotification::new(
                                party_id.to_string(),
                                NotificationType::DkgRoundRequired,
                                "🔐 Your Turn - Set Up Security".to_string(),
                                format!(
                                    "Complete security setup for order #{}. Waiting for: {}",
                                    &escrow_id[..8],
                                    parties_pending.join(", ")
                                ),
                                Some(format!("/escrow/{}", escrow_id)),
                                Some(
                                    serde_json::json!({
                                        "escrow_id": escrow_id,
                                        "round": 1,
                                        "persistent": true
                                    })
                                    .to_string(),
                                ),
                            );

                            if let Err(e) = Notification::create(notification, &mut conn) {
                                warn!(
                                    escrow_id = %escrow_id,
                                    user_id = %party_id,
                                    error = %e,
                                    "Failed to create persistent notification for DKG Round 1"
                                );
                            }
                        }
                    }
                }
            }

            HttpResponse::Ok().json(ApiResponse::success(status))
        }
        Err(e) => {
            error!("Failed to submit Round 1: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(&format!(
                "Failed to submit: {}",
                e
            )))
        }
    }
}

/// Get all Round 1 packages
///
/// GET /api/escrow/frost/{id}/dkg/round1
pub async fn get_round1_packages(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostCoordinator::get_all_round1_packages(&mut conn, &escrow_id) {
        Ok(packages_json) => {
            let packages: serde_json::Value =
                serde_json::from_str(&packages_json).unwrap_or(serde_json::json!({}));
            HttpResponse::Ok().json(ApiResponse::success(packages))
        }
        Err(e) => HttpResponse::BadRequest().json(ApiResponse::<()>::error(&format!("{}", e))),
    }
}

/// Submit Round 2 packages
///
/// POST /api/escrow/frost/{id}/dkg/round2
pub async fn submit_round2(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<Round2Request>,
    session: Session,
    websocket: web::Data<Addr<WebSocketServer>>,
    arbiter_auto_dkg: web::Data<Option<Arc<ArbiterAutoDkg>>>,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let role = match FrostRole::from_str(&body.role) {
        Some(r) => r,
        None => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid role"));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostCoordinator::submit_round2(&mut conn, &escrow_id, role, &body.packages) {
        Ok(all_complete) => {
            // === ARBITER AUTO-DKG ROUND 2 ===
            // If buyer or vendor submitted, try to auto-generate arbiter's Round 2
            if role != FrostRole::Arbiter {
                if let Some(ref auto_dkg) = arbiter_auto_dkg.as_ref() {
                    let escrow_id_clone = escrow_id.clone();
                    let auto_dkg_clone = Arc::clone(auto_dkg);

                    tokio::spawn(async move {
                        match auto_dkg_clone.maybe_generate_round2(&escrow_id_clone).await {
                            Ok(generated) => {
                                if generated {
                                    info!(
                                        escrow_id = %escrow_id_clone,
                                        "🤖 Arbiter Round 2 auto-generated successfully"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(
                                    escrow_id = %escrow_id_clone,
                                    error = %e,
                                    "Failed to auto-generate arbiter Round 2"
                                );
                            }
                        }
                    });
                }
            }

            let status =
                FrostCoordinator::get_status(&mut conn, &escrow_id).unwrap_or_else(|_| DkgStatus {
                    escrow_id: escrow_id.clone(),
                    round1_complete: true,
                    round2_complete: all_complete,
                    dkg_complete: false,
                    participants: crate::models::frost_dkg::DkgParticipants {
                        buyer_round1_ready: true,
                        vendor_round1_ready: true,
                        arbiter_round1_ready: true,
                        buyer_round2_ready: false,
                        vendor_round2_ready: false,
                        arbiter_round2_ready: false,
                    },
                });

            // === FROST DKG ROUND 2 NOTIFICATIONS ===
            if let Ok(escrow) = Escrow::find_by_id(&mut conn, escrow_id.clone()) {
                let packages_submitted = count_round2_packages(&status.participants);

                // If all Round 2 packages submitted, notify completion
                if all_complete {
                    notify_all_parties(
                        &websocket,
                        &escrow,
                        WsEvent::FrostDkgRound2Complete {
                            escrow_id: parse_uuid_safe(&escrow_id),
                        },
                    );
                    info!(escrow_id = %escrow_id, "FROST DKG Round 2 complete, notifying parties");
                } else {
                    // Notify each party about Round 2 progress
                    for (party_id, party_role) in get_party_list(&escrow) {
                        // Send WebSocket notification
                        websocket.do_send(NotifyUser {
                            user_id: party_id.clone(),
                            event: WsEvent::FrostDkgRound2Required {
                                escrow_id: parse_uuid_safe(&escrow_id),
                                party_role: party_role.clone(),
                                packages_submitted,
                                packages_total: 6, // 3 parties × 2 packages each
                            },
                        });

                        // Create PERSISTENT DB notification for parties that need to submit Round 2
                        let party_round2_complete = match party_role.as_str() {
                            "buyer" => status.participants.buyer_round2_ready,
                            "vendor" => status.participants.vendor_round2_ready,
                            "arbiter" => status.participants.arbiter_round2_ready,
                            _ => true,
                        };

                        if !party_round2_complete {
                            let notification = NewNotification::new(
                                party_id.to_string(),
                                NotificationType::DkgRoundRequired,
                                "🔐 Your Turn - Continue Setup".to_string(),
                                format!(
                                    "Continue security setup for order #{}. Progress: {}/6",
                                    &escrow_id[..8],
                                    packages_submitted
                                ),
                                Some(format!("/escrow/{}", escrow_id)),
                                Some(
                                    serde_json::json!({
                                        "escrow_id": escrow_id,
                                        "round": 2,
                                        "persistent": true
                                    })
                                    .to_string(),
                                ),
                            );

                            if let Err(e) = Notification::create(notification, &mut conn) {
                                warn!(
                                    escrow_id = %escrow_id,
                                    user_id = %party_id,
                                    error = %e,
                                    "Failed to create persistent notification for DKG Round 2"
                                );
                            }
                        }
                    }
                }
            }

            HttpResponse::Ok().json(ApiResponse::success(status))
        }
        Err(e) => {
            error!("Failed to submit Round 2: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(&format!(
                "Failed to submit: {}",
                e
            )))
        }
    }
}

/// Get Round 2 packages for caller
///
/// GET /api/escrow/frost/{id}/dkg/round2?role=buyer
pub async fn get_round2_packages(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let role_str = query.get("role").cloned().unwrap_or_default();
    let role = match FrostRole::from_str(&role_str) {
        Some(r) => r,
        None => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                "Invalid or missing role parameter",
            ));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostCoordinator::get_round2_packages_for(&mut conn, &escrow_id, role) {
        Ok(packages_json) => {
            let packages: serde_json::Value =
                serde_json::from_str(&packages_json).unwrap_or(serde_json::json!({}));
            HttpResponse::Ok().json(ApiResponse::success(packages))
        }
        Err(e) => HttpResponse::BadRequest().json(ApiResponse::<()>::error(&format!("{}", e))),
    }
}

/// Complete DKG with group public key and derived address
///
/// POST /api/escrow/frost/{id}/dkg/complete
pub async fn complete_dkg(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<CompleteDkgRequest>,
    session: Session,
    websocket: web::Data<Addr<WebSocketServer>>,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    // Validate group_pubkey (32 bytes = 64 hex chars)
    if body.group_pubkey.len() != 64 || !body.group_pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Invalid group_pubkey: must be 64 hex characters",
        ));
    }

    // Validate multisig_address (Monero addresses are 95 characters)
    if body.multisig_address.len() != 95 {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Invalid multisig_address: must be 95 characters",
        ));
    }

    // Validate multisig_view_key (32 bytes = 64 hex chars)
    if body.multisig_view_key.len() != 64
        || !body
            .multisig_view_key
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Invalid multisig_view_key: must be 64 hex characters",
        ));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Store the address for notification before moving body
    let multisig_address_for_notification = body.multisig_address.clone();

    match FrostCoordinator::complete_dkg(
        &mut conn,
        &escrow_id,
        &body.group_pubkey,
        &body.multisig_address,
        &body.multisig_view_key,
    ) {
        Ok(()) => {
            info!(
                escrow_id = %escrow_id,
                address_prefix = &body.multisig_address[..10],
                "FROST DKG complete with address stored"
            );
            let status =
                FrostCoordinator::get_status(&mut conn, &escrow_id).unwrap_or_else(|_| DkgStatus {
                    escrow_id: escrow_id.clone(),
                    round1_complete: true,
                    round2_complete: true,
                    dkg_complete: true,
                    participants: crate::models::frost_dkg::DkgParticipants {
                        buyer_round1_ready: true,
                        vendor_round1_ready: true,
                        arbiter_round1_ready: true,
                        buyer_round2_ready: true,
                        vendor_round2_ready: true,
                        arbiter_round2_ready: true,
                    },
                });

            // === FROST DKG COMPLETE NOTIFICATION ===
            // Notify all parties that the 2-of-3 multisig wallet is ready
            if let Ok(escrow) = Escrow::find_by_id(&mut conn, escrow_id.clone()) {
                notify_all_parties(
                    &websocket,
                    &escrow,
                    WsEvent::FrostDkgComplete {
                        escrow_id: parse_uuid_safe(&escrow_id),
                        multisig_address: multisig_address_for_notification,
                    },
                );
                info!(escrow_id = %escrow_id, "FROST DKG complete, notifying all parties");
            }

            HttpResponse::Ok().json(ApiResponse::success(status))
        }
        Err(e) => {
            error!("Failed to complete DKG: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(&format!(
                "Failed to complete: {}",
                e
            )))
        }
    }
}

/// Get DKG status
///
/// GET /api/escrow/frost/{id}/status
pub async fn get_dkg_status(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostCoordinator::get_status(&mut conn, &escrow_id) {
        Ok(status) => HttpResponse::Ok().json(ApiResponse::success(status)),
        Err(e) => HttpResponse::NotFound().json(ApiResponse::<()>::error(&format!(
            "DKG state not found: {}",
            e
        ))),
    }
}

/// Get Lagrange coefficients for a signing pair
///
/// GET /api/escrow/frost/lagrange?signer1=buyer&signer2=vendor
pub async fn get_lagrange_coefficients(query: web::Query<LagrangeRequest>) -> HttpResponse {
    match FrostCoordinator::get_lagrange_coefficients(&query.signer1, &query.signer2) {
        Ok((lambda1, lambda2)) => {
            let response = LagrangeResponse {
                signer1_lambda: lambda1,
                signer2_lambda: lambda2,
            };
            HttpResponse::Ok().json(ApiResponse::success(response))
        }
        Err(e) => HttpResponse::BadRequest().json(ApiResponse::<()>::error(&format!("{}", e))),
    }
}

// ============================================================================
// Shield Backup Handlers
// ============================================================================

/// Register a shield backup
///
/// POST /api/escrow/frost/{id}/shield/register
pub async fn register_shield(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<RegisterShieldRequest>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    let user_id = match get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Not authenticated"));
        }
    };

    // Validate role
    if !["buyer", "vendor", "arbiter"].contains(&body.role.as_str()) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid role"));
    }

    // Validate backup_id format (should be hex string)
    if body.backup_id.len() < 32 || !body.backup_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Invalid backup_id format"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Check if shield already exists for this user/escrow
    match ShieldBackup::find_by_user_escrow(&mut conn, &escrow_id, &user_id) {
        Ok(Some(existing)) => {
            // Record exists - update backup_id if different (recovery scenario)
            if existing.backup_id == body.backup_id {
                info!(
                    escrow_id = %escrow_id,
                    user_id = %user_id,
                    "Shield already registered with matching backup_id"
                );
            } else {
                info!(
                    escrow_id = %escrow_id,
                    user_id = %user_id,
                    "Updating shield backup_id during recovery"
                );
                if let Err(e) =
                    ShieldBackup::update_backup_id(&mut conn, &existing.id, &body.backup_id)
                {
                    error!("Failed to update shield backup_id: {}", e);
                    return HttpResponse::InternalServerError()
                        .json(ApiResponse::<()>::error("Failed to update shield"));
                }
            }
            return HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "message": "Shield registered"
            })));
        }
        Ok(None) => {
            // Create new shield record
        }
        Err(e) => {
            error!("Failed to query shield backup: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    }

    match ShieldBackup::create(&mut conn, &escrow_id, &user_id, &body.role, &body.backup_id) {
        Ok(backup) => {
            info!(
                escrow_id = %escrow_id,
                user_id = %user_id,
                role = %body.role,
                "Shield backup registered"
            );
            HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "id": backup.id,
                "backup_id": backup.backup_id,
                "created_at": backup.created_at.format("%Y-%m-%d %H:%M UTC").to_string()
            })))
        }
        Err(e) => {
            error!("Failed to create shield backup: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(&format!(
                "Failed to register shield: {}",
                e
            )))
        }
    }
}

/// Verify a shield backup exists
///
/// POST /api/escrow/frost/{id}/shield/verify
pub async fn verify_shield(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<VerifyShieldRequest>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match ShieldBackup::verify_for_escrow(&mut conn, &escrow_id, &body.backup_id) {
        Ok(Some(backup)) => {
            // Mark as verified
            if let Err(e) = ShieldBackup::mark_verified(&mut conn, &backup.id) {
                warn!("Failed to mark shield as verified: {}", e);
            }
            HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "valid": true,
                "backup_id": backup.backup_id
            })))
        }
        Ok(None) => HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
            "valid": false
        }))),
        Err(e) => {
            error!("Failed to verify shield: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Verification failed"))
        }
    }
}

/// Get shield status for current user
///
/// GET /api/escrow/frost/{id}/shield/status
pub async fn get_shield_status(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    let user_id = match get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Not authenticated"));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    let status = ShieldBackup::get_status(&mut conn, &escrow_id, &user_id);
    HttpResponse::Ok().json(status)
}

// ============================================================================
// v0.75.0: Shipped Tracking Handlers
// ============================================================================

/// Request to confirm shipment (vendor action)
#[derive(Debug, Deserialize)]
pub struct ConfirmShippedRequest {
    /// Optional tracking information (carrier, tracking number)
    pub tracking_info: Option<String>,
    /// Estimated delivery days (default: 14)
    pub estimated_delivery_days: Option<u32>,
}

/// Request to confirm receipt (buyer action)
#[derive(Debug, Deserialize)]
pub struct ConfirmReceiptRequest {
    /// REQUIRED: Explicit consent to release funds
    pub consent_confirmed: bool,
    /// Optional feedback about the transaction
    pub feedback: Option<String>,
}

/// Confirm shipment (Vendor only)
///
/// POST /api/escrow/frost/{id}/ship
///
/// Called by vendor after shipping goods/services. Changes status from
/// "funded" to "shipped" and sets auto_release_at for buyer timeout.
pub async fn confirm_shipped(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
    body: web::Json<ConfirmShippedRequest>,
    websocket: web::Data<Addr<WebSocketServer>>,
    webhook_dispatcher: web::Data<Arc<WebhookDispatcher>>,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    // 1. Dual auth: API key or session
    let user_id = match get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Not authenticated"));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // 2. Load escrow
    let escrow = match Escrow::find_by_id(&mut conn, escrow_id.clone()) {
        Ok(e) => e,
        Err(_) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error("Escrow not found"));
        }
    };

    // 3. Verify status == "funded"
    if escrow.status != "funded" {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(&format!(
            "E_INVALID_STATUS: Expected 'funded', got '{}'",
            escrow.status
        )));
    }

    // 4. Verify caller == vendor_id
    if escrow.vendor_id != user_id {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error(
            "E_NOT_VENDOR: Only vendor can confirm shipment",
        ));
    }

    // 5. CRITICAL: Verify vendor_payout_address is set
    if escrow.vendor_payout_address.is_none() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "E_PAYOUT_ADDRESS_REQUIRED: Set your payout address before shipping",
        ));
    }

    // 6. Calculate auto_release_at (default: 14 days)
    let delivery_days = body.estimated_delivery_days.unwrap_or(14);
    let auto_release_at = chrono::Utc::now() + chrono::Duration::days(delivery_days as i64);

    // 7. Update escrow to "shipped"
    if let Err(e) = Escrow::update_shipped_status(
        &mut conn,
        &escrow_id,
        body.tracking_info.clone(),
        auto_release_at,
    ) {
        error!("Failed to update shipped status: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to update escrow status"));
    }

    info!(
        escrow_id = %escrow_id,
        vendor_id = %user_id,
        auto_release_days = delivery_days,
        "Escrow marked as shipped"
    );

    // 8. WebSocket notification to buyer
    websocket.do_send(WsEvent::EscrowShipped {
        escrow_id: escrow_id.clone(),
        vendor_id: escrow.vendor_id.clone(),
        buyer_id: escrow.buyer_id.clone(),
        tracking_info: body.tracking_info.clone(),
        auto_release_at: auto_release_at.naive_utc(),
    });
    info!(
        "[WebSocket] Broadcast EscrowShipped for {} to buyer {}",
        escrow_id, escrow.buyer_id
    );

    // 9. Create persistent notification for buyer
    let notification = NewNotification::new(
        escrow.buyer_id.clone(),
        NotificationType::EscrowUpdate,
        "Order Shipped - Confirm When Received".to_string(),
        format!(
            "Vendor shipped your order. Confirm receipt within {} days or funds auto-release.",
            delivery_days
        ),
        Some(format!("/escrow/{}", escrow_id)),
        Some(
            serde_json::json!({
                "escrow_id": escrow_id,
                "event": "shipped",
                "auto_release_days": delivery_days
            })
            .to_string(),
        ),
    );

    if let Err(e) = Notification::create(notification, &mut conn) {
        warn!("Failed to create shipped notification: {}", e);
    }

    // B2B Webhook: EscrowShipped
    emit_webhook_nonblocking(
        webhook_dispatcher.get_ref().clone(),
        WebhookEventType::EscrowShipped,
        build_escrow_payload(
            &escrow_id,
            "escrow.shipped",
            serde_json::json!({
                "vendor_id": user_id,
                "tracking_info": body.tracking_info,
                "auto_release_at": auto_release_at.to_rfc3339(),
                "status": "shipped",
            }),
        ),
    );

    HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "success": true,
        "status": "shipped",
        "auto_release_at": auto_release_at.to_rfc3339(),
        "message": format!("Buyer has {} days to confirm receipt", delivery_days)
    })))
}

/// Confirm receipt and release funds (Buyer only)
///
/// POST /api/escrow/frost/{id}/confirm-receipt
///
/// Called by buyer when they receive goods/services. Sets buyer_release_requested
/// to trigger Arbiter Watchdog auto-signing.
pub async fn confirm_receipt(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
    body: web::Json<ConfirmReceiptRequest>,
    websocket: web::Data<Addr<WebSocketServer>>,
    webhook_dispatcher: web::Data<Arc<WebhookDispatcher>>,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    // 1. CRITICAL: Validate explicit consent
    if !body.consent_confirmed {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "E_CONSENT_REQUIRED: Must explicitly consent to release funds",
        ));
    }

    // 2. Dual auth: API key or session
    let user_id = match get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Not authenticated"));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // 3. Load escrow
    let escrow = match Escrow::find_by_id(&mut conn, escrow_id.clone()) {
        Ok(e) => e,
        Err(_) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error("Escrow not found"));
        }
    };

    // 4. Verify status == "shipped"
    if escrow.status != "shipped" {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(&format!(
            "E_INVALID_STATUS: Expected 'shipped', got '{}'",
            escrow.status
        )));
    }

    // 5. Verify caller == buyer_id
    if escrow.buyer_id != user_id {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error(
            "E_NOT_BUYER: Only buyer can confirm receipt",
        ));
    }

    // 6. Update escrow to trigger Arbiter Watchdog
    use crate::schema::escrows;
    use diesel::prelude::*;

    if let Err(e) = diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
        .set((
            escrows::buyer_release_requested.eq(true),
            escrows::status.eq("releasing"),
            escrows::updated_at.eq(diesel::dsl::now),
        ))
        .execute(&mut conn)
    {
        error!("Failed to update escrow for release: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to initiate release"));
    }

    info!(
        escrow_id = %escrow_id,
        buyer_id = %user_id,
        "Buyer confirmed receipt - triggering Arbiter Watchdog"
    );

    // 7. WebSocket notification to vendor
    websocket.do_send(WsEvent::BuyerConfirmedReceipt {
        escrow_id: escrow_id.clone(),
        buyer_id: escrow.buyer_id.clone(),
        vendor_id: escrow.vendor_id.clone(),
    });
    info!(
        "[WebSocket] Broadcast BuyerConfirmedReceipt for {} to vendor {}",
        escrow_id, escrow.vendor_id
    );

    // 8. Create persistent notification for vendor
    let notification = NewNotification::new(
        escrow.vendor_id.clone(),
        NotificationType::EscrowUpdate,
        "Buyer Confirmed Receipt - Releasing Funds".to_string(),
        "Buyer confirmed receipt. Arbiter is signing release transaction.".to_string(),
        Some(format!("/escrow/{}", escrow_id)),
        Some(
            serde_json::json!({
                "escrow_id": escrow_id,
                "event": "buyer_confirmed_receipt"
            })
            .to_string(),
        ),
    );

    if let Err(e) = Notification::create(notification, &mut conn) {
        warn!("Failed to create receipt confirmation notification: {}", e);
    }

    // B2B Webhook: EscrowReleased (buyer confirmed, release in progress)
    emit_webhook_nonblocking(
        webhook_dispatcher.get_ref().clone(),
        WebhookEventType::EscrowReleased,
        build_escrow_payload(
            &escrow_id,
            "escrow.released",
            serde_json::json!({
                "buyer_id": user_id,
                "status": "releasing",
            }),
        ),
    );

    HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "success": true,
        "status": "releasing",
        "message": "Arbiter Watchdog will auto-sign within 30 seconds"
    })))
}

/// Configure FROST escrow routes (DKG + Signing)
/// NOTE: This is called from within the /api scope in main.rs
/// All FROST routes are merged into a single scope to avoid Actix routing conflicts.
pub fn configure_frost_routes(cfg: &mut web::ServiceConfig) {
    use super::frost_signing;

    cfg.service(
        web::scope("/escrow/frost")
            // DKG routes
            .route("/{id}/init", web::post().to(init_frost_dkg))
            .route("/{id}/dkg/round1", web::post().to(submit_round1))
            .route("/{id}/dkg/round1", web::get().to(get_round1_packages))
            .route("/{id}/dkg/round2", web::post().to(submit_round2))
            .route("/{id}/dkg/round2", web::get().to(get_round2_packages))
            .route("/{id}/dkg/complete", web::post().to(complete_dkg))
            .route("/{id}/status", web::get().to(get_dkg_status))
            .route("/lagrange", web::get().to(get_lagrange_coefficients))
            // Shield backup routes
            .route("/{id}/shield/register", web::post().to(register_shield))
            .route("/{id}/shield/verify", web::post().to(verify_shield))
            .route("/{id}/shield/status", web::get().to(get_shield_status))
            // v0.75.0: Shipped tracking routes
            .route("/{id}/ship", web::post().to(confirm_shipped))
            .route("/{id}/confirm-receipt", web::post().to(confirm_receipt))
            // Signing routes (delegated to frost_signing handlers)
            .route(
                "/{id}/sign/init",
                web::post().to(frost_signing::init_frost_signing),
            )
            .route(
                "/{id}/sign/nonces",
                web::post().to(frost_signing::submit_nonce_commitment),
            )
            .route(
                "/{id}/sign/nonces",
                web::get().to(frost_signing::get_nonce_commitments),
            )
            .route(
                "/{id}/sign/partial",
                web::post().to(frost_signing::submit_partial_signature),
            )
            .route(
                "/{id}/sign/status",
                web::get().to(frost_signing::get_signing_status),
            )
            .route(
                "/{id}/sign/complete",
                web::post().to(frost_signing::complete_and_broadcast),
            )
            .route(
                "/{id}/sign/tx-data",
                web::get().to(frost_signing::get_tx_data),
            )
            .route(
                "/{id}/sign/first-signer-data",
                web::get().to(frost_signing::get_first_signer_data),
            ),
    );
}

// ============================================================================
// FROST DKG Notification Helper Functions
// ============================================================================

/// Parse UUID safely, returning a nil UUID if parsing fails
fn parse_uuid_safe(id: &str) -> Uuid {
    Uuid::parse_str(id).unwrap_or_else(|e| {
        warn!("Failed to parse escrow_id '{}' as UUID: {}", id, e);
        Uuid::nil()
    })
}

/// Get list of all parties (buyer, vendor, arbiter) with their roles
fn get_party_list(escrow: &Escrow) -> Vec<(Uuid, String)> {
    let mut parties = Vec::new();

    if let Ok(buyer_id) = Uuid::parse_str(&escrow.buyer_id) {
        parties.push((buyer_id, "buyer".to_string()));
    }
    if let Ok(vendor_id) = Uuid::parse_str(&escrow.vendor_id) {
        parties.push((vendor_id, "vendor".to_string()));
    }
    if let Ok(arbiter_id) = Uuid::parse_str(&escrow.arbiter_id) {
        parties.push((arbiter_id, "arbiter".to_string()));
    }

    parties
}

/// Compute which parties have submitted Round 1 data
fn compute_round1_submitted(
    participants: &crate::models::frost_dkg::DkgParticipants,
) -> Vec<String> {
    let mut submitted = Vec::new();
    if participants.buyer_round1_ready {
        submitted.push("buyer".to_string());
    }
    if participants.vendor_round1_ready {
        submitted.push("vendor".to_string());
    }
    if participants.arbiter_round1_ready {
        submitted.push("arbiter".to_string());
    }
    submitted
}

/// Compute which parties still need to submit Round 1 data
fn compute_round1_pending(participants: &crate::models::frost_dkg::DkgParticipants) -> Vec<String> {
    let mut pending = Vec::new();
    if !participants.buyer_round1_ready {
        pending.push("buyer".to_string());
    }
    if !participants.vendor_round1_ready {
        pending.push("vendor".to_string());
    }
    if !participants.arbiter_round1_ready {
        pending.push("arbiter".to_string());
    }
    pending
}

/// Count how many Round 2 packages have been submitted (0-6)
fn count_round2_packages(participants: &crate::models::frost_dkg::DkgParticipants) -> u8 {
    let mut count = 0u8;
    // Each party submits 2 packages (one for each other party)
    if participants.buyer_round2_ready {
        count += 2;
    }
    if participants.vendor_round2_ready {
        count += 2;
    }
    if participants.arbiter_round2_ready {
        count += 2;
    }
    count
}

/// Notify all 3 escrow parties with the same event
fn notify_all_parties(
    websocket: &web::Data<Addr<WebSocketServer>>,
    escrow: &Escrow,
    event: WsEvent,
) {
    for (party_id, role) in get_party_list(escrow) {
        websocket.do_send(NotifyUser {
            user_id: party_id,
            event: event.clone(),
        });
        info!(party_role = %role, "Sent DKG notification to party");
    }
}
