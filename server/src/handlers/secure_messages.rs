//! Secure E2E Encrypted Messaging API handlers
//!
//! REST API endpoints for end-to-end encrypted messaging between users.
//! All message content is encrypted client-side - server only stores encrypted blobs.
//!
//! # Security Model
//! - X25519 ECDH key exchange for shared secret derivation
//! - ChaCha20Poly1305 AEAD for message encryption
//! - Ephemeral keys per message for Perfect Forward Secrecy
//! - Private keys encrypted with password-derived key before storage
//!
//! # Endpoints
//! - POST /api/secure-messages/keypair - Create/update messaging keypair
//! - GET /api/secure-messages/keypair - Get own keypair (for decryption setup)
//! - GET /api/secure-messages/pubkey/{user_id} - Get user's public key
//! - POST /api/secure-messages/send - Send encrypted message
//! - GET /api/secure-messages/conversation/{user_id} - Get conversation with user
//! - GET /api/secure-messages/conversations - List all conversations
//! - POST /api/secure-messages/{id}/read - Mark message as read
//! - DELETE /api/secure-messages/{id} - Soft-delete message
//! - GET /api/secure-messages/unread-count - Get unread message count

use actix::Addr;
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::db::DbPool;
use crate::middleware::csrf::validate_csrf_token;
use crate::models::secure_message::{
    ConversationSummary, MessageKeypair, MessageReadReceipt, NewMessageKeypair, NewSecureMessage,
    SecureMessage, SecureMessageDto,
};
use crate::models::user::User;
use crate::websocket::{NotifyUser, WebSocketServer, WsEvent};

// ============================================================================
// Constants
// ============================================================================

/// Maximum encrypted message size (3MB base64 - supports ~2MB images after encoding)
const MAX_MESSAGE_SIZE: usize = 3 * 1024 * 1024;

/// Maximum messages per page
const MAX_PAGE_SIZE: i64 = 50;

/// Rate limit: messages per hour per user
const RATE_LIMIT_PER_HOUR: i64 = 50;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create/update messaging keypair
#[derive(Debug, Deserialize)]
pub struct CreateKeypairRequest {
    pub public_key: String,            // X25519 public key (base64)
    pub encrypted_private_key: String, // Encrypted with password (base64)
    pub key_salt: String,              // Salt for key derivation (base64)
    pub csrf_token: String,
}

/// Request to send encrypted message
#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub recipient_id: String,
    pub encrypted_content: String, // ChaCha20Poly1305 ciphertext (base64)
    pub nonce: String,             // 12-byte nonce (base64)
    pub sender_ephemeral_pubkey: String, // X25519 ephemeral public key
    pub expires_in_hours: Option<i64>, // Optional TTL
    pub csrf_token: String,
}

/// Pagination query params
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
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

    pub fn error(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

/// Keypair response (without private key)
#[derive(Debug, Serialize)]
pub struct KeypairResponse {
    pub id: String,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub key_salt: String,
    pub created_at: String,
}

/// Public key response
#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub user_id: String,
    pub username: String,
    pub public_key: String,
}

/// Conversation response
#[derive(Debug, Serialize)]
pub struct ConversationResponse {
    pub messages: Vec<SecureMessageDto>,
    pub other_user: UserSummary,
    pub total_count: i64,
}

/// User summary for conversations
#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub has_keypair: bool,
}

/// Unread count response
#[derive(Debug, Serialize)]
pub struct UnreadCountResponse {
    pub count: i64,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get authenticated user ID from session
fn get_user_id(session: &Session) -> Result<String, HttpResponse> {
    session
        .get::<String>("user_id")
        .map_err(|_| {
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Session error"))
        })?
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Authentication required"))
        })
}

/// Validate base64 string length
fn validate_base64_field(value: &str, name: &str, max_len: usize) -> Result<(), HttpResponse> {
    if value.is_empty() {
        return Err(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(format!("{} is required", name))));
    }
    if value.len() > max_len {
        return Err(
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(format!(
                "{} exceeds maximum size",
                name
            ))),
        );
    }
    // Basic base64 validation
    if !value
        .chars()
        .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err(
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(format!(
                "{} is not valid base64",
                name
            ))),
        );
    }
    Ok(())
}

/// Validate encrypted private key field (JSON format with ciphertext and iv)
fn validate_encrypted_key_field(
    value: &str,
    name: &str,
    max_len: usize,
) -> Result<(), HttpResponse> {
    if value.is_empty() {
        return Err(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(format!("{} is required", name))));
    }
    if value.len() > max_len {
        return Err(
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(format!(
                "{} exceeds maximum size",
                name
            ))),
        );
    }
    // Validate JSON format: {"ciphertext":"...","iv":"..."}
    if !value.starts_with('{') || !value.ends_with('}') {
        return Err(
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(format!(
                "{} must be JSON format",
                name
            ))),
        );
    }
    // Basic check for required fields
    if !value.contains("ciphertext") || !value.contains("iv") {
        return Err(
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(format!(
                "{} missing required fields",
                name
            ))),
        );
    }
    Ok(())
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /api/secure-messages/keypair - Create or update messaging keypair
///
/// The private key must be encrypted client-side before sending.
/// Server stores encrypted private key blob.
pub async fn create_keypair(
    pool: web::Data<DbPool>,
    session: Session,
    req: web::Json<CreateKeypairRequest>,
) -> impl Responder {
    // CSRF validation
    if !validate_csrf_token(&session, &req.csrf_token) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Invalid CSRF token"));
    }

    // Auth check
    let user_id = match get_user_id(&session) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Validate inputs
    // P-256 public key is 65 bytes raw = ~88 base64 chars, allow 128 for safety
    if let Err(resp) = validate_base64_field(&req.public_key, "public_key", 128) {
        return resp;
    }
    // Encrypted private key is JSON format {"ciphertext":"...","iv":"..."}, allow 1024
    if let Err(resp) =
        validate_encrypted_key_field(&req.encrypted_private_key, "encrypted_private_key", 1024)
    {
        return resp;
    }
    if let Err(resp) = validate_base64_field(&req.key_salt, "key_salt", 64) {
        return resp;
    }

    // Get DB connection
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Create keypair
    let new_keypair = NewMessageKeypair::new(
        user_id.clone(),
        req.public_key.clone(),
        req.encrypted_private_key.clone(),
        req.key_salt.clone(),
    );

    match MessageKeypair::create_or_replace(new_keypair, &mut conn) {
        Ok(keypair) => {
            info!("Created messaging keypair for user");
            HttpResponse::Ok().json(ApiResponse::success(KeypairResponse {
                id: keypair.id,
                public_key: keypair.public_key,
                encrypted_private_key: keypair.encrypted_private_key,
                key_salt: keypair.key_salt,
                created_at: keypair.created_at,
            }))
        }
        Err(e) => {
            error!("Failed to create keypair: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to create keypair"))
        }
    }
}

/// GET /api/secure-messages/keypair - Get own keypair for decryption setup
pub async fn get_own_keypair(pool: web::Data<DbPool>, session: Session) -> impl Responder {
    let user_id = match get_user_id(&session) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match MessageKeypair::get_active_for_user(&user_id, &mut conn) {
        Ok(Some(keypair)) => HttpResponse::Ok().json(ApiResponse::success(KeypairResponse {
            id: keypair.id,
            public_key: keypair.public_key,
            encrypted_private_key: keypair.encrypted_private_key,
            key_salt: keypair.key_salt,
            created_at: keypair.created_at,
        })),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            "No keypair found. Create one first.",
        )),
        Err(e) => {
            error!("Failed to get keypair: {:?}", e); // Debug format for full error chain
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to retrieve keypair"))
        }
    }
}

/// GET /api/secure-messages/pubkey/{user_id} - Get user's public key for encryption
pub async fn get_user_pubkey(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> impl Responder {
    // Auth check (must be logged in)
    if let Err(resp) = get_user_id(&session) {
        return resp;
    }

    let target_user_id = path.into_inner();

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Get user info
    let user = match User::find_by_id(&mut conn, target_user_id.clone()) {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error("User not found"));
        }
    };

    // Get public key
    match MessageKeypair::get_public_key_for_user(&target_user_id, &mut conn) {
        Ok(Some(pubkey)) => HttpResponse::Ok().json(ApiResponse::success(PublicKeyResponse {
            user_id: target_user_id,
            username: user.username,
            public_key: pubkey,
        })),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            "User has not set up secure messaging",
        )),
        Err(e) => {
            error!("Failed to get public key: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to retrieve public key"))
        }
    }
}

/// POST /api/secure-messages/send - Send encrypted message
pub async fn send_message(
    pool: web::Data<DbPool>,
    session: Session,
    ws_server: web::Data<Addr<WebSocketServer>>,
    req: web::Json<SendMessageRequest>,
) -> impl Responder {
    // CSRF validation
    if !validate_csrf_token(&session, &req.csrf_token) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Invalid CSRF token"));
    }

    let sender_id = match get_user_id(&session) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Validate inputs
    if req.recipient_id.is_empty() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Recipient ID is required"));
    }
    if req.recipient_id == sender_id {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Cannot send message to yourself"));
    }
    if let Err(resp) = validate_base64_field(
        &req.encrypted_content,
        "encrypted_content",
        MAX_MESSAGE_SIZE,
    ) {
        return resp;
    }
    if let Err(resp) = validate_base64_field(&req.nonce, "nonce", 24) {
        return resp;
    }
    // P-256 ephemeral public key is 65 bytes = ~88 base64 chars, allow 128
    if let Err(resp) =
        validate_base64_field(&req.sender_ephemeral_pubkey, "sender_ephemeral_pubkey", 128)
    {
        return resp;
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Verify recipient exists and get sender info for notification
    let sender = match User::find_by_id(&mut conn, sender_id.clone()) {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to get sender info"));
        }
    };

    if User::find_by_id(&mut conn, req.recipient_id.clone()).is_err() {
        return HttpResponse::NotFound().json(ApiResponse::<()>::error("Recipient not found"));
    }

    // Calculate expiry if provided
    let expires_at = req.expires_in_hours.map(|hours| {
        let expiry = chrono::Utc::now() + chrono::Duration::hours(hours);
        expiry.format("%Y-%m-%d %H:%M:%S").to_string()
    });

    // Create message
    let new_message = NewSecureMessage::new(
        sender_id.clone(),
        req.recipient_id.clone(),
        req.encrypted_content.clone(),
        req.nonce.clone(),
        req.sender_ephemeral_pubkey.clone(),
        expires_at,
    );

    match SecureMessage::create(new_message, &mut conn) {
        Ok(message) => {
            info!("Secure message sent");

            // Send WebSocket notification to recipient
            if let Ok(recipient_uuid) = Uuid::parse_str(&req.recipient_id) {
                ws_server.do_send(NotifyUser {
                    user_id: recipient_uuid,
                    event: WsEvent::SecureMessageReceived {
                        message_id: message.id.clone(),
                        sender_id: sender_id.clone(),
                        sender_username: sender.username.clone(),
                        conversation_id: message.conversation_id.clone(),
                        created_at: message.created_at.clone(),
                    },
                });
            }

            HttpResponse::Ok().json(ApiResponse::success(SecureMessageDto {
                id: message.id,
                conversation_id: message.conversation_id,
                sender_id: message.sender_id,
                recipient_id: message.recipient_id,
                encrypted_content: message.encrypted_content,
                nonce: message.nonce,
                sender_ephemeral_pubkey: message.sender_ephemeral_pubkey,
                created_at: message.created_at,
                is_read: false,
                is_own_message: true,
            }))
        }
        Err(e) => {
            error!("Failed to send message: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to send message"))
        }
    }
}

/// GET /api/secure-messages/conversation/{user_id} - Get conversation with user
pub async fn get_conversation(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
    query: web::Query<PaginationQuery>,
) -> impl Responder {
    let user_id = match get_user_id(&session) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let other_user_id = path.into_inner();
    let limit = query.limit.unwrap_or(20).min(MAX_PAGE_SIZE);
    let offset = query.offset.unwrap_or(0);

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Get other user info
    let other_user = match User::find_by_id(&mut conn, other_user_id.clone()) {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error("User not found"));
        }
    };

    // Check if other user has keypair
    let other_has_keypair = MessageKeypair::get_public_key_for_user(&other_user_id, &mut conn)
        .map(|k| k.is_some())
        .unwrap_or(false);

    // Get messages
    let messages =
        match SecureMessage::get_conversation(&user_id, &other_user_id, limit, offset, &mut conn) {
            Ok(msgs) => msgs,
            Err(e) => {
                error!("Failed to load conversation: {}", e);
                return HttpResponse::InternalServerError()
                    .json(ApiResponse::<()>::error("Failed to load conversation"));
            }
        };

    // Convert to DTOs with read status
    let message_dtos: Vec<SecureMessageDto> = messages
        .into_iter()
        .map(|msg| {
            let is_read = MessageReadReceipt::is_read(&msg.id, &mut conn).unwrap_or(false);
            SecureMessageDto {
                id: msg.id,
                conversation_id: msg.conversation_id,
                sender_id: msg.sender_id.clone(),
                recipient_id: msg.recipient_id,
                encrypted_content: msg.encrypted_content,
                nonce: msg.nonce,
                sender_ephemeral_pubkey: msg.sender_ephemeral_pubkey,
                created_at: msg.created_at,
                is_read,
                is_own_message: msg.sender_id == user_id,
            }
        })
        .collect();

    // Mark received messages as read
    if let Err(e) = MessageReadReceipt::mark_conversation_read(&user_id, &other_user_id, &mut conn)
    {
        warn!("Failed to mark messages as read: {}", e);
    }

    HttpResponse::Ok().json(ApiResponse::success(ConversationResponse {
        messages: message_dtos,
        other_user: UserSummary {
            id: other_user.id,
            username: other_user.username,
            has_keypair: other_has_keypair,
        },
        total_count: 0, // Could add count query if needed
    }))
}

/// GET /api/secure-messages/conversations - List all conversations
pub async fn list_conversations(pool: web::Data<DbPool>, session: Session) -> impl Responder {
    let user_id = match get_user_id(&session) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match SecureMessage::get_conversations_for_user(&user_id, &mut conn) {
        Ok(conversations) => {
            let summaries: Vec<ConversationSummary> = conversations
                .into_iter()
                .map(|(conv_id, other_id, other_username, unread)| {
                    let has_keypair = MessageKeypair::get_public_key_for_user(&other_id, &mut conn)
                        .map(|k| k.is_some())
                        .unwrap_or(false);

                    ConversationSummary {
                        conversation_id: conv_id,
                        other_user_id: other_id,
                        other_username,
                        last_message_at: String::new(), // Could add from query
                        unread_count: unread,
                        has_keypair,
                    }
                })
                .collect();

            HttpResponse::Ok().json(ApiResponse::success(summaries))
        }
        Err(e) => {
            error!("Failed to list conversations: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to list conversations"))
        }
    }
}

/// POST /api/secure-messages/{id}/read - Mark message as read
pub async fn mark_message_read(
    pool: web::Data<DbPool>,
    session: Session,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    // CSRF from header
    let csrf_token = req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if !validate_csrf_token(&session, csrf_token) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Invalid CSRF token"));
    }

    let user_id = match get_user_id(&session) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let message_id = path.into_inner();

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Verify user is recipient
    use crate::schema::secure_messages::dsl;
    use diesel::prelude::*;

    let message: Option<SecureMessage> = dsl::secure_messages
        .find(&message_id)
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    match message {
        Some(msg) if msg.recipient_id == user_id => {
            if let Err(e) = MessageReadReceipt::mark_read(&message_id, &mut conn) {
                error!("Failed to mark as read: {}", e);
                return HttpResponse::InternalServerError()
                    .json(ApiResponse::<()>::error("Failed to mark as read"));
            }
            HttpResponse::Ok().json(ApiResponse::success(true))
        }
        Some(_) => HttpResponse::Forbidden().json(ApiResponse::<()>::error(
            "Cannot mark others' messages as read",
        )),
        None => HttpResponse::NotFound().json(ApiResponse::<()>::error("Message not found")),
    }
}

/// DELETE /api/secure-messages/{id} - Soft-delete message
pub async fn delete_message(
    pool: web::Data<DbPool>,
    session: Session,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let csrf_token = req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if !validate_csrf_token(&session, csrf_token) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Invalid CSRF token"));
    }

    let user_id = match get_user_id(&session) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let message_id = path.into_inner();

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match SecureMessage::soft_delete(&message_id, &user_id, &mut conn) {
        Ok(true) => {
            info!("Message soft-deleted");
            HttpResponse::Ok().json(ApiResponse::success(true))
        }
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            "Message not found or not authorized",
        )),
        Err(e) => {
            error!("Failed to delete message: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to delete message"))
        }
    }
}

/// GET /api/secure-messages/unread-count - Get unread message count
pub async fn get_unread_count(pool: web::Data<DbPool>, session: Session) -> impl Responder {
    let user_id = match get_user_id(&session) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match SecureMessage::count_unread_for_user(&user_id, &mut conn) {
        Ok(count) => HttpResponse::Ok().json(ApiResponse::success(UnreadCountResponse { count })),
        Err(e) => {
            error!("Failed to count unread: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to count unread messages"))
        }
    }
}
