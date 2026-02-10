//! Escrow E2EE Chat API Handlers
//!
//! REST API endpoints for end-to-end encrypted group messaging within escrows.
//! Each message is encrypted 3 times (once per participant: buyer, vendor, arbiter).
//!
//! # Security Model
//! - X25519 ECDH key exchange for shared secret derivation
//! - ChaCha20Poly1305 AEAD for message encryption
//! - Ephemeral keys per message for Perfect Forward Secrecy
//! - Server only stores encrypted blobs (blind relay)
//!
//! # Endpoints (v2)
//! - POST /api/v2/escrow/{id}/chat/keypair     - Register messaging keypair
//! - GET  /api/v2/escrow/{id}/chat/keypairs    - Get all 3 participants' pubkeys
//! - POST /api/v2/escrow/{id}/chat/send        - Send encrypted message (3 copies)
//! - GET  /api/v2/escrow/{id}/chat/messages    - Get chat history
//! - POST /api/v2/escrow/{id}/chat/{msg}/read  - Mark message as read
//! - GET  /api/v2/escrow/{id}/chat/export      - Export as signed evidence (disputes)

use actix::Addr;
use actix_session::Session;
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::db::DbPool;
use crate::models::escrow::Escrow;
use crate::models::escrow_message::{
    EscrowKeypairsDto, EscrowMessageKeypair, EscrowMessageReadReceipt, NewEscrowMessageKeypair,
    NewSecureEscrowMessage, SecureEscrowMessage, SecureEscrowMessageDto,
};
use crate::models::user::User;
use crate::websocket::{NotifyUser, WebSocketServer, WsEvent};

// ============================================================================
// Constants
// ============================================================================

/// Maximum encrypted message size (3MB base64)
const MAX_MESSAGE_SIZE: usize = 3 * 1024 * 1024;

/// Maximum messages per page
const MAX_PAGE_SIZE: i64 = 50;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to register a messaging keypair
#[derive(Debug, Deserialize)]
pub struct RegisterKeypairRequest {
    pub public_key: String, // X25519 public key (hex)
}

/// Request to send an encrypted message
#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub encrypted_content_buyer: String, // Ciphertext for buyer (base64)
    pub encrypted_content_vendor: String, // Ciphertext for vendor (base64)
    pub encrypted_content_arbiter: String, // Ciphertext for arbiter (base64)
    pub sender_ephemeral_pubkey: String, // X25519 ephemeral public key (hex)
    pub nonce: String,                   // 12-byte nonce (hex)
    pub frost_signature: Option<String>, // Optional FROST signature for non-repudiation
}

/// Query parameters for message listing
#[derive(Debug, Deserialize)]
pub struct MessagesQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Standard API response
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

    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.to_string()),
        }
    }
}

/// Messages list response
#[derive(Debug, Serialize)]
pub struct MessagesResponse {
    pub messages: Vec<SecureEscrowMessageDto>,
    pub total: i64,
    pub has_more: bool,
}

/// Message created response
#[derive(Debug, Serialize)]
pub struct MessageCreatedResponse {
    pub id: String,
    pub created_at: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get authenticated user from session
fn get_user_from_session(session: &Session) -> Result<(String, String), HttpResponse> {
    let user_id = session
        .get::<String>("user_id")
        .map_err(|e| {
            error!("Session error: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Session error"))
        })?
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"))
        })?;

    let username = session
        .get::<String>("username")
        .ok()
        .flatten()
        .unwrap_or_else(|| "Unknown".to_string());

    Ok((user_id, username))
}

/// Get user's role in an escrow
fn get_user_role_in_escrow(
    conn: &mut diesel::SqliteConnection,
    escrow_id: &str,
    user_id: &str,
) -> Result<String, HttpResponse> {
    use crate::schema::escrows;
    use diesel::prelude::*;

    let escrow: Escrow = escrows::table
        .filter(escrows::id.eq(escrow_id))
        .first(conn)
        .map_err(|_| HttpResponse::NotFound().json(ApiResponse::<()>::error("Escrow not found")))?;

    if escrow.buyer_id == user_id {
        Ok("buyer".to_string())
    } else if escrow.vendor_id == user_id {
        Ok("vendor".to_string())
    } else if escrow.arbiter_id == user_id {
        Ok("arbiter".to_string())
    } else {
        Err(HttpResponse::Forbidden()
            .json(ApiResponse::<()>::error("Not a participant in this escrow")))
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /api/v2/escrow/{id}/chat/keypair - Register messaging keypair
pub async fn register_keypair(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
    body: web::Json<RegisterKeypairRequest>,
) -> impl Responder {
    let escrow_id = path.into_inner();
    let (user_id, _username) = match get_user_from_session(&session) {
        Ok(u) => u,
        Err(r) => return r,
    };

    // Validate public key format (should be 64 hex chars for X25519)
    if body.public_key.len() != 64 || !body.public_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Invalid public key format"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB pool error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Get user's role in escrow
    let role = match get_user_role_in_escrow(&mut conn, &escrow_id, &user_id) {
        Ok(r) => r,
        Err(r) => return r,
    };

    // Register keypair
    let new_keypair = NewEscrowMessageKeypair::new(
        escrow_id.clone(),
        user_id.clone(),
        role.clone(),
        body.public_key.clone(),
    );

    match EscrowMessageKeypair::register(&mut conn, new_keypair) {
        Ok(keypair) => {
            info!(
                "Registered chat keypair for {} ({}) in escrow {}",
                user_id, role, escrow_id
            );
            HttpResponse::Ok().json(ApiResponse::success(keypair))
        }
        Err(e) => {
            error!("Failed to register keypair: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to register keypair"))
        }
    }
}

/// GET /api/v2/escrow/{id}/chat/keypairs - Get all participants' pubkeys
pub async fn get_keypairs(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> impl Responder {
    let escrow_id = path.into_inner();
    let (user_id, _) = match get_user_from_session(&session) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB pool error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Verify user is a participant
    if get_user_role_in_escrow(&mut conn, &escrow_id, &user_id).is_err() {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Not a participant"));
    }

    match EscrowMessageKeypair::get_keypairs_dto(&mut conn, &escrow_id) {
        Ok(dto) => HttpResponse::Ok().json(ApiResponse::success(dto)),
        Err(e) => {
            error!("Failed to get keypairs: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to get keypairs"))
        }
    }
}

/// POST /api/v2/escrow/{id}/chat/send - Send encrypted message
pub async fn send_message(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
    body: web::Json<SendMessageRequest>,
    ws_server: web::Data<Addr<WebSocketServer>>,
) -> impl Responder {
    let escrow_id = path.into_inner();
    let (user_id, username) = match get_user_from_session(&session) {
        Ok(u) => u,
        Err(r) => return r,
    };

    // Validate message sizes
    if body.encrypted_content_buyer.len() > MAX_MESSAGE_SIZE
        || body.encrypted_content_vendor.len() > MAX_MESSAGE_SIZE
        || body.encrypted_content_arbiter.len() > MAX_MESSAGE_SIZE
    {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Message too large"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB pool error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Get user's role
    let role = match get_user_role_in_escrow(&mut conn, &escrow_id, &user_id) {
        Ok(r) => r,
        Err(r) => return r,
    };

    // Check buyer + vendor keypairs are registered (arbiter is automated, no browser)
    match EscrowMessageKeypair::get_keypairs_dto(&mut conn, &escrow_id) {
        Ok(dto) if !dto.buyer_vendor_registered => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                "Buyer and vendor must both register keypairs before chatting",
            ));
        }
        Err(e) => {
            error!("Failed to check keypairs: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
        _ => {}
    }

    // Create message
    let new_message = NewSecureEscrowMessage::new(
        escrow_id.clone(),
        user_id.clone(),
        role.clone(),
        body.encrypted_content_buyer.clone(),
        body.encrypted_content_vendor.clone(),
        body.encrypted_content_arbiter.clone(),
        body.sender_ephemeral_pubkey.clone(),
        body.nonce.clone(),
        body.frost_signature.clone(),
    );

    match SecureEscrowMessage::create(&mut conn, new_message) {
        Ok(message) => {
            info!(
                "Chat message sent in escrow {} by {} ({})",
                escrow_id, user_id, role
            );

            // Notify other participants via WebSocket
            use crate::schema::escrows;
            use diesel::prelude::*;

            if let Ok(escrow) = escrows::table
                .filter(escrows::id.eq(&escrow_id))
                .first::<Escrow>(&mut conn)
            {
                let participants = vec![
                    escrow.buyer_id.clone(),
                    escrow.vendor_id.clone(),
                    escrow.arbiter_id.clone(),
                ];

                for participant_id in participants {
                    if participant_id != user_id && !participant_id.is_empty() {
                        let event = WsEvent::EscrowChatMessage {
                            escrow_id: escrow_id.clone(),
                            message_id: message.id.clone(),
                            sender_id: user_id.clone(),
                            sender_role: role.clone(),
                            sender_username: username.clone(),
                        };

                        if let Ok(uuid) = uuid::Uuid::parse_str(&participant_id) {
                            ws_server.do_send(NotifyUser {
                                user_id: uuid,
                                event,
                            });
                        }
                    }
                }
            }

            HttpResponse::Ok().json(ApiResponse::success(MessageCreatedResponse {
                id: message.id,
                created_at: message.created_at,
            }))
        }
        Err(e) => {
            error!("Failed to create message: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to send message"))
        }
    }
}

/// GET /api/v2/escrow/{id}/chat/messages - Get chat history
pub async fn get_messages(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
    query: web::Query<MessagesQuery>,
) -> impl Responder {
    let escrow_id = path.into_inner();
    let (user_id, _) = match get_user_from_session(&session) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let limit = query.limit.unwrap_or(50).min(MAX_PAGE_SIZE);
    let offset = query.offset.unwrap_or(0);

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB pool error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Get user's role
    let role = match get_user_role_in_escrow(&mut conn, &escrow_id, &user_id) {
        Ok(r) => r,
        Err(r) => return r,
    };

    // Get messages
    let messages = match SecureEscrowMessage::find_by_escrow_for_role(
        &mut conn,
        &escrow_id,
        &role,
        limit + 1, // Fetch one extra to check if there are more
        offset,
    ) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to get messages: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to get messages"));
        }
    };

    let has_more = messages.len() as i64 > limit;
    let messages: Vec<_> = messages.into_iter().take(limit as usize).collect();

    // Get total count
    let total = SecureEscrowMessage::count_for_escrow(&mut conn, &escrow_id).unwrap_or(0);

    // Convert to DTOs with read status
    let mut dtos = Vec::new();
    for msg in messages {
        let is_read = if msg.sender_id == user_id {
            true // Own messages are always "read"
        } else {
            EscrowMessageReadReceipt::is_read_by_user(&mut conn, &msg.id, &user_id).unwrap_or(false)
        };

        dtos.push(msg.to_dto_for_role(&role, &user_id, is_read));
    }

    // Reverse to get chronological order (query is DESC)
    dtos.reverse();

    HttpResponse::Ok().json(ApiResponse::success(MessagesResponse {
        messages: dtos,
        total,
        has_more,
    }))
}

/// POST /api/v2/escrow/{id}/chat/{msg_id}/read - Mark message as read
pub async fn mark_message_read(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (escrow_id, message_id) = path.into_inner();
    let (user_id, _) = match get_user_from_session(&session) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB pool error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Verify user is a participant
    if get_user_role_in_escrow(&mut conn, &escrow_id, &user_id).is_err() {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Not a participant"));
    }

    match EscrowMessageReadReceipt::mark_read(&mut conn, &message_id, &user_id) {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::success(())),
        Err(e) => {
            error!("Failed to mark message read: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to mark as read"))
        }
    }
}

/// GET /api/v2/escrow/{id}/chat/export - Export chat for dispute evidence
pub async fn export_chat_for_dispute(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> impl Responder {
    let escrow_id = path.into_inner();
    let (user_id, _) = match get_user_from_session(&session) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB pool error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Verify user is a participant and escrow is disputed
    let role = match get_user_role_in_escrow(&mut conn, &escrow_id, &user_id) {
        Ok(r) => r,
        Err(r) => return r,
    };

    use crate::schema::escrows;
    use diesel::prelude::*;

    let escrow: Escrow = match escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
    {
        Ok(e) => e,
        Err(_) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error("Escrow not found"))
        }
    };

    // Only allow export for disputed escrows or arbiters
    if escrow.status != "disputed" && role != "arbiter" {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error(
            "Chat export only available for disputed escrows",
        ));
    }

    match SecureEscrowMessage::export_for_dispute(&mut conn, &escrow_id) {
        Ok(messages) => {
            info!(
                "Chat exported for dispute in escrow {} by {}",
                escrow_id, user_id
            );
            HttpResponse::Ok().json(ApiResponse::success(messages))
        }
        Err(e) => {
            error!("Failed to export chat: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to export chat"))
        }
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure escrow chat routes
pub fn configure_escrow_chat_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/v2/escrow/{escrow_id}/chat")
            .route("/keypair", web::post().to(register_keypair))
            .route("/keypairs", web::get().to(get_keypairs))
            .route("/send", web::post().to(send_message))
            .route("/messages", web::get().to(get_messages))
            .route("/{message_id}/read", web::post().to(mark_message_read))
            .route("/export", web::get().to(export_chat_for_dispute)),
    );
}
