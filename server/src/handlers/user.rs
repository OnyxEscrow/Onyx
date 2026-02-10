//! User API handlers for profile and escrow management

use actix::Addr;
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

use crate::db::DbPool;
use crate::models::escrow::{Escrow, NewEscrow};
use crate::models::user::User;
use crate::models::webhook::WebhookEventType;
use crate::schema::{escrows, users};
use crate::services::webhook_dispatcher::{
    build_escrow_payload, emit_webhook_nonblocking, WebhookDispatcher,
};
use crate::websocket::{WebSocketServer, WsEvent};

/// Response struct for user escrow list
#[derive(Debug, Serialize)]
struct EscrowResponse {
    id: String,
    order_id: Option<String>,
    amount: i64,
    status: String,
    user_role: String,
    multisig_phase: String,
    created_at: String,
    user_wallet_configured: bool,
    // EaaS fields
    external_reference: Option<String>,
    description: Option<String>,
}

// ============================================================================
// Dashboard API (v0.71.0)
// ============================================================================

/// Dashboard escrow response with additional UI fields
#[derive(Debug, Serialize)]
pub struct DashboardEscrow {
    pub id: String,
    pub status: String,
    pub amount: i64,
    pub role: String,
    pub counterparty: Option<CounterpartyInfo>,
    pub created_at: String,
    pub updated_at: String,
    pub multisig_phase: String,
    pub frost_dkg_complete: bool,
    pub has_shield: bool,
    pub unread_messages: i32,
    pub external_reference: Option<String>,
    pub description: Option<String>,
    pub multisig_address: Option<String>,
    pub dkg_phase: String,
    pub funded_amount: i64,
    pub confirmations: i32,
    pub broadcast_tx_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CounterpartyInfo {
    pub id: String,
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total: i32,
    pub active: i32,
    pub completed: i32,
    pub disputed: i32,
    pub total_volume: i64,
    pub as_buyer: i32,
    pub as_vendor: i32,
    pub as_arbiter: i32,
}

#[derive(Debug, Serialize)]
pub struct PaginationMeta {
    pub page: i32,
    pub per_page: i32,
    pub total: i32,
}

#[derive(Debug, Deserialize)]
pub struct DashboardQuery {
    pub status: Option<String>,
    pub role: Option<String>,
    pub sort_by: Option<String>,
    /// Legacy offset-based pagination (still supported)
    pub page: Option<i32>,
    pub per_page: Option<i32>,
    /// Cursor-based pagination (preferred for B2B)
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// GET /api/user/escrows/dashboard - Get escrows with stats and pagination
///
/// Returns escrows with statistics and pagination metadata for the dashboard UI
pub async fn get_user_escrows_dashboard(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<DashboardQuery>,
) -> impl Responder {
    // Require authentication
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Fetch all escrows where user is participant
    let buyer_escrows = Escrow::find_by_buyer(&mut conn, user_id.clone()).unwrap_or_default();
    let vendor_escrows = Escrow::find_by_vendor(&mut conn, user_id.clone()).unwrap_or_default();
    let arbiter_escrows = Escrow::find_by_arbiter(&mut conn, user_id.clone()).unwrap_or_default();

    // Build dashboard escrows with role info
    let mut all_escrows: Vec<(Escrow, String)> = Vec::new();

    for e in buyer_escrows {
        all_escrows.push((e, "buyer".to_string()));
    }
    for e in vendor_escrows {
        all_escrows.push((e, "vendor".to_string()));
    }
    for e in arbiter_escrows {
        all_escrows.push((e, "arbiter".to_string()));
    }

    // Calculate stats before filtering
    let stats = DashboardStats {
        total: all_escrows.len() as i32,
        active: all_escrows
            .iter()
            .filter(|(e, _)| {
                matches!(
                    e.status.as_str(),
                    "pending_dkg" | "awaiting_funding" | "funded" | "shipped" | "signing_initiated"
                )
            })
            .count() as i32,
        completed: all_escrows
            .iter()
            .filter(|(e, _)| e.status == "completed" || e.status == "released")
            .count() as i32,
        disputed: all_escrows
            .iter()
            .filter(|(e, _)| e.status == "disputed")
            .count() as i32,
        total_volume: all_escrows.iter().map(|(e, _)| e.amount).sum(),
        as_buyer: all_escrows.iter().filter(|(_, r)| r == "buyer").count() as i32,
        as_vendor: all_escrows.iter().filter(|(_, r)| r == "vendor").count() as i32,
        as_arbiter: all_escrows.iter().filter(|(_, r)| r == "arbiter").count() as i32,
    };

    // Apply filters
    if let Some(ref status_filter) = query.status {
        let statuses: Vec<&str> = status_filter.split(',').collect();
        all_escrows.retain(|(e, _)| statuses.contains(&e.status.as_str()));
    }
    if let Some(ref role_filter) = query.role {
        let roles: Vec<&str> = role_filter.split(',').collect();
        all_escrows.retain(|(_, r)| roles.contains(&r.as_str()));
    }

    // Sort
    match query.sort_by.as_deref() {
        Some("amount_desc") => all_escrows.sort_by(|a, b| b.0.amount.cmp(&a.0.amount)),
        Some("amount_asc") => all_escrows.sort_by(|a, b| a.0.amount.cmp(&b.0.amount)),
        Some("status") => all_escrows.sort_by(|a, b| a.0.status.cmp(&b.0.status)),
        _ => all_escrows.sort_by(|a, b| b.0.created_at.cmp(&a.0.created_at)), // default: newest first
    }

    // Pagination: cursor-based (preferred) or offset-based (legacy)
    let use_cursor = query.cursor.is_some() || query.limit.is_some();
    let total = all_escrows.len() as i32;

    let (paginated, cursor_next, cursor_has_more, page, per_page) = if use_cursor {
        let limit = query.limit.unwrap_or(20).min(100);
        let start_idx = if let Some(ref cursor_str) = query.cursor {
            match decode_cursor(cursor_str) {
                Some(cursor_id) => all_escrows
                    .iter()
                    .position(|(e, _)| e.id == cursor_id)
                    .map(|pos| pos + 1)
                    .unwrap_or(0),
                None => 0,
            }
        } else {
            0
        };
        let window: Vec<_> = all_escrows
            .into_iter()
            .skip(start_idx)
            .take(limit + 1)
            .collect();
        let has_more = window.len() > limit;
        let items: Vec<_> = window.into_iter().take(limit).collect();
        let next = if has_more {
            items.last().map(|(e, _)| encode_cursor(&e.id))
        } else {
            None
        };
        (items, next, has_more, 1, limit as i32)
    } else {
        let page = query.page.unwrap_or(1).max(1);
        let per_page = query.per_page.unwrap_or(10).min(50);
        let start = ((page - 1) * per_page) as usize;
        let items: Vec<_> = all_escrows
            .into_iter()
            .skip(start)
            .take(per_page as usize)
            .collect();
        (items, None, false, page, per_page)
    };

    // Build response with counterparty info
    let mut dashboard_escrows: Vec<DashboardEscrow> = Vec::new();

    for (escrow, role) in paginated {
        // Get counterparty
        let counterparty_id = match role.as_str() {
            "buyer" => &escrow.vendor_id,
            "vendor" => &escrow.buyer_id,
            _ => &escrow.buyer_id, // arbiter sees buyer as primary
        };

        let counterparty = if counterparty_id != "pending" {
            users::table
                .filter(users::id.eq(counterparty_id))
                .first::<User>(&mut conn)
                .optional()
                .ok()
                .flatten()
                .map(|u| CounterpartyInfo {
                    id: u.id,
                    username: u.username,
                })
        } else {
            None
        };

        // Determine DKG phase
        let dkg_phase = if escrow.frost_dkg_complete {
            "complete"
        } else if escrow.multisig_phase == "preparing" || escrow.multisig_phase == "round1" {
            "round1"
        } else if escrow.multisig_phase == "round2" {
            "round2"
        } else {
            "pending"
        };

        dashboard_escrows.push(DashboardEscrow {
            id: escrow.id.clone(),
            status: escrow.status.clone(),
            amount: escrow.amount,
            role: role.clone(),
            counterparty,
            created_at: escrow.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            updated_at: escrow.updated_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            multisig_phase: escrow.multisig_phase.clone(),
            frost_dkg_complete: escrow.frost_dkg_complete,
            has_shield: false,  // TODO: check shield_backups table
            unread_messages: 0, // TODO: check escrow_messages table
            external_reference: escrow.external_reference.clone(),
            description: escrow.description.clone(),
            multisig_address: escrow.multisig_address.clone(),
            dkg_phase: dkg_phase.to_string(),
            funded_amount: escrow.balance_received,
            confirmations: 0, // TODO: Add confirmations tracking to Escrow model
            broadcast_tx_hash: escrow.broadcast_tx_hash.clone(),
        });
    }

    let pagination = PaginationMeta {
        page,
        per_page,
        total,
    };

    info!(
        "Dashboard: {} escrows for user {} (page {}/{})",
        dashboard_escrows.len(),
        user_id,
        page,
        (total + per_page - 1) / per_page
    );

    let mut response = serde_json::json!({
        "escrows": dashboard_escrows,
        "statistics": stats,
        "pagination": pagination
    });

    // Add cursor-based pagination fields when using cursor mode
    if use_cursor {
        if let Some(ref next_cursor) = cursor_next {
            response["cursor"] = serde_json::json!(next_cursor);
        }
        response["has_more"] = serde_json::json!(cursor_has_more);
    }

    HttpResponse::Ok().json(response)
}

/// Cursor-based pagination query parameters
#[derive(Debug, Deserialize)]
pub struct CursorQuery {
    /// Base64-encoded cursor (escrow ID of last item in previous page)
    pub cursor: Option<String>,
    /// Number of items per page (default 20, max 100)
    pub limit: Option<usize>,
}

/// Cursor-paginated response wrapper
#[derive(Debug, Serialize)]
pub struct CursorPaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    /// Opaque cursor for next page (base64-encoded escrow ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// True if more results exist after this page
    pub has_more: bool,
}

/// Decode a base64 cursor to an escrow ID
fn decode_cursor(cursor: &str) -> Option<String> {
    URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// Encode an escrow ID to a base64 cursor
fn encode_cursor(escrow_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(escrow_id.as_bytes())
}

/// GET /api/user/escrows - Get all escrows for authenticated user
///
/// Supports cursor-based pagination via `?cursor=...&limit=20`.
/// Returns `{ data: [...], cursor: "...", has_more: true/false }`.
///
/// Backwards-compatible: if no cursor/limit params provided, returns all escrows
/// in the same flat array format as before (for existing B2C consumers).
pub async fn get_user_escrows(
    pool: web::Data<DbPool>,
    session: Session,
    req: HttpRequest,
    query: web::Query<CursorQuery>,
) -> impl Responder {
    // Require authentication (dual-auth: API key or session)
    let user_id = match crate::handlers::auth_helpers::get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Fetch escrows where user is buyer, vendor, or arbiter
    let buyer_escrows = Escrow::find_by_buyer(&mut conn, user_id.clone()).unwrap_or_default();
    let vendor_escrows = Escrow::find_by_vendor(&mut conn, user_id.clone()).unwrap_or_default();
    let arbiter_escrows = Escrow::find_by_arbiter(&mut conn, user_id.clone()).unwrap_or_default();

    // Combine all escrows
    let mut all_escrows = Vec::new();

    for escrow in buyer_escrows {
        all_escrows.push(EscrowResponse {
            id: escrow.id.clone(),
            order_id: escrow.order_id.clone(),
            amount: escrow.amount,
            status: escrow.status.clone(),
            user_role: "Buyer".to_string(),
            multisig_phase: escrow.multisig_phase.clone(),
            created_at: escrow.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            user_wallet_configured: escrow.buyer_wallet_info.is_some(),
            external_reference: escrow.external_reference.clone(),
            description: escrow.description.clone(),
        });
    }

    for escrow in vendor_escrows {
        all_escrows.push(EscrowResponse {
            id: escrow.id.clone(),
            order_id: escrow.order_id.clone(),
            amount: escrow.amount,
            status: escrow.status.clone(),
            user_role: "Vendor".to_string(),
            multisig_phase: escrow.multisig_phase.clone(),
            created_at: escrow.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            user_wallet_configured: escrow.vendor_wallet_info.is_some(),
            external_reference: escrow.external_reference.clone(),
            description: escrow.description.clone(),
        });
    }

    for escrow in arbiter_escrows {
        all_escrows.push(EscrowResponse {
            id: escrow.id.clone(),
            order_id: escrow.order_id.clone(),
            amount: escrow.amount,
            status: escrow.status.clone(),
            user_role: "Arbiter".to_string(),
            multisig_phase: escrow.multisig_phase.clone(),
            created_at: escrow.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            user_wallet_configured: escrow.arbiter_wallet_info.is_some(),
            external_reference: escrow.external_reference.clone(),
            description: escrow.description.clone(),
        });
    }

    // Sort by created_at descending (most recent first), then by id for stable ordering
    all_escrows.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.id.cmp(&a.id))
    });

    let limit = query.limit.unwrap_or(20).min(100);
    let use_cursor_pagination = query.cursor.is_some() || query.limit.is_some();

    if use_cursor_pagination {
        // Cursor-based pagination: skip items until we pass the cursor
        let start_idx = if let Some(ref cursor_str) = query.cursor {
            match decode_cursor(cursor_str) {
                Some(cursor_id) => {
                    // Find position after the cursor item
                    all_escrows
                        .iter()
                        .position(|e| e.id == cursor_id)
                        .map(|pos| pos + 1)
                        .unwrap_or(0)
                }
                None => 0,
            }
        } else {
            0
        };

        // Take limit + 1 to detect has_more
        let window: Vec<_> = all_escrows
            .into_iter()
            .skip(start_idx)
            .take(limit + 1)
            .collect();
        let has_more = window.len() > limit;
        let page: Vec<_> = window.into_iter().take(limit).collect();

        let next_cursor = if has_more {
            page.last().map(|e| encode_cursor(&e.id))
        } else {
            None
        };

        info!(
            "Retrieved {} escrows (cursor page) for user {}",
            page.len(),
            user_id
        );

        HttpResponse::Ok().json(CursorPaginatedResponse {
            data: page,
            cursor: next_cursor,
            has_more,
        })
    } else {
        // Backwards-compatible: return flat array for existing consumers
        info!(
            "Retrieved {} escrows for user {}",
            all_escrows.len(),
            user_id
        );
        HttpResponse::Ok().json(all_escrows)
    }
}

// ============================================================================
// Escrow Creation
// ============================================================================

/// Request body for creating a new escrow
#[derive(Debug, Deserialize)]
pub struct CreateEscrowRequest {
    /// Amount in atomic units (piconero)
    pub amount: i64,
    /// Description of the agreement
    pub description: Option<String>,
    /// Role of the creator (buyer or seller)
    #[serde(default = "default_role")]
    pub creator_role: String,
    /// External reference for B2B integration
    pub external_reference: Option<String>,
}

fn default_role() -> String {
    "buyer".to_string()
}

/// Response for escrow creation
#[derive(Debug, Serialize)]
pub struct CreateEscrowResponse {
    pub escrow_id: String,
    pub address: Option<String>,
    pub status: String,
    pub role: String,
}

/// POST /api/escrows/create - Create a new escrow
pub async fn create_escrow(
    pool: web::Data<DbPool>,
    session: Session,
    req: HttpRequest,
    body: web::Json<CreateEscrowRequest>,
    webhook_dispatcher: web::Data<Arc<WebhookDispatcher>>,
) -> impl Responder {
    // Dual auth: API key (B2B) or session (B2C)
    let user_id = match crate::handlers::auth_helpers::get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Validate amount
    if body.amount <= 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Amount must be positive"
        }));
    }

    // EaaS Flow: No counterparty required at creation
    // Counterparty joins later via shared link

    // Validate creator_role
    let creator_role = body.creator_role.to_lowercase();
    if creator_role != "buyer" && creator_role != "seller" && creator_role != "vendor" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "creator_role must be 'buyer' or 'seller'"
        }));
    }

    // Set buyer/vendor based on creator role
    // The other party is "pending" until they join
    let (buyer_id, vendor_id) = if creator_role == "seller" || creator_role == "vendor" {
        ("pending".to_string(), user_id.clone())
    } else {
        (user_id.clone(), "pending".to_string())
    };

    // Arbiter will be assigned when counterparty joins
    let arbiter_id = "pending".to_string();

    // Generate escrow ID
    let escrow_id = format!(
        "esc_{}",
        Uuid::new_v4().to_string().replace("-", "")[..16].to_string()
    );
    // EaaS: Use escrow_id as order_id (self-reference for standalone escrows)
    let order_id: Option<String> = Some(escrow_id.clone());

    // Clone for logging after move
    let order_id_log = order_id.clone();
    let buyer_id_log = buyer_id.clone();
    let vendor_id_log = vendor_id.clone();

    // Create escrow with EaaS status
    let now = chrono::Utc::now().naive_utc();
    let new_escrow = NewEscrow {
        id: escrow_id.clone(),
        order_id,
        buyer_id,
        vendor_id,
        arbiter_id,
        amount: body.amount,
        status: "pending_counterparty".to_string(), // EaaS: waiting for counterparty to join
        created_at: now,
        updated_at: now,
        last_activity_at: now,
        multisig_phase: "not_started".to_string(),
        multisig_updated_at: 0,
        recovery_mode: "manual".to_string(),
        balance_received: 0,
        frost_enabled: true,
        frost_dkg_complete: false,
        external_reference: body.external_reference.clone(),
        description: body.description.clone(),
        // Arbiter Watchdog fields (v0.70.0)
        buyer_release_requested: false,
        vendor_refund_requested: false,
        arbiter_auto_signed: false,
        escalated_to_human: false,
        // B2B multi-tenancy (v1.1.0)
        client_id: None,
        metadata_json: None,
    };

    match Escrow::create(&mut conn, new_escrow) {
        Ok(escrow) => {
            info!(
                "Created EaaS escrow {} by {} as {}",
                escrow_id, user_id, creator_role
            );

            // B2B Webhook: EscrowCreated
            emit_webhook_nonblocking(
                webhook_dispatcher.get_ref().clone(),
                WebhookEventType::EscrowCreated,
                build_escrow_payload(
                    &escrow_id,
                    "escrow.created",
                    serde_json::json!({
                        "amount": body.amount,
                        "creator_role": creator_role,
                        "status": "pending_counterparty",
                        "external_reference": body.external_reference,
                    }),
                ),
            );

            HttpResponse::Created().json(serde_json::json!({
                "escrow_id": escrow.id,
                "status": escrow.status,
                "creator_role": creator_role,
                "join_link": format!("/join/{}", escrow.id),
            }))
        }
        Err(e) => {
            error!("Failed to create escrow: {:?}", e);
            error!(
                "Escrow creation details - id: {}, order_id: {:?}, buyer: {}, vendor: {}",
                escrow_id, order_id_log, buyer_id_log, vendor_id_log
            );
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create escrow: {}", e)
            }))
        }
    }
}

// ============================================================================
// EaaS Endpoints: Public & Join
// ============================================================================

/// GET /api/escrows/{id}/public - Get escrow details for join page (no auth)
pub async fn get_escrow_public(pool: web::Data<DbPool>, path: web::Path<String>) -> impl Responder {
    let escrow_id = path.into_inner();

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Find escrow
    let escrow: Option<Escrow> = escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    let escrow = match escrow {
        Some(e) => e,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Escrow not found"
            }));
        }
    };

    // Determine creator role based on who is NOT "pending"
    let creator_role = if escrow.buyer_id == "pending" {
        "seller"
    } else {
        "buyer"
    };

    HttpResponse::Ok().json(serde_json::json!({
        "id": escrow.id,
        "creator_role": creator_role,
        "amount": escrow.amount,
        "description": escrow.description,
        "status": escrow.status,
        "created_at": escrow.created_at.to_string(),
    }))
}

/// POST /api/escrows/{id}/join - Join an escrow as counterparty
pub async fn join_escrow(
    pool: web::Data<DbPool>,
    session: Session,
    req: HttpRequest,
    path: web::Path<String>,
    webhook_dispatcher: web::Data<Arc<WebhookDispatcher>>,
) -> impl Responder {
    let escrow_id = path.into_inner();

    // Require authentication (dual-auth: API key or session)
    let user_id = match crate::handlers::auth_helpers::get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Find escrow
    let escrow: Option<Escrow> = escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    let escrow = match escrow {
        Some(e) => e,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Escrow not found"
            }));
        }
    };

    // Check status
    if escrow.status != "pending_counterparty" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "This escrow is no longer accepting participants",
            "status": escrow.status,
        }));
    }

    // Prevent joining own escrow
    if escrow.buyer_id == user_id || escrow.vendor_id == user_id {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "You cannot join your own escrow"
        }));
    }

    // Determine which role to assign
    let (new_buyer_id, new_vendor_id, assigned_role) = if escrow.buyer_id == "pending" {
        (user_id.clone(), escrow.vendor_id.clone(), "buyer")
    } else {
        (escrow.buyer_id.clone(), user_id.clone(), "seller")
    };

    // Find system arbiter
    let arbiter: Option<User> = users::table
        .filter(users::role.eq("arbiter"))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    let arbiter_id = arbiter
        .map(|a| a.id)
        .unwrap_or_else(|| "system_arbiter".to_string());

    // Update escrow
    let update_result = diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
        .set((
            escrows::buyer_id.eq(&new_buyer_id),
            escrows::vendor_id.eq(&new_vendor_id),
            escrows::arbiter_id.eq(&arbiter_id),
            escrows::status.eq("pending_dkg"), // Ready for DKG
            escrows::updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(&mut conn);

    match update_result {
        Ok(_) => {
            info!(
                "User {} joined escrow {} as {}",
                user_id, escrow_id, assigned_role
            );

            // B2B Webhook: MultisigSetupStarted (counterparty joined, DKG can begin)
            emit_webhook_nonblocking(
                webhook_dispatcher.get_ref().clone(),
                WebhookEventType::MultisigSetupStarted,
                build_escrow_payload(
                    &escrow_id,
                    "multisig.setup_started",
                    serde_json::json!({
                        "joined_role": assigned_role,
                        "status": "pending_dkg",
                    }),
                ),
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "role": assigned_role,
                "escrow_id": escrow_id,
                "status": "pending_dkg",
            }))
        }
        Err(e) => {
            error!("Failed to update escrow: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to join escrow"
            }))
        }
    }
}

/// GET /api/escrows/{id}/lobby-status - Get participant readiness for DKG
pub async fn get_lobby_status(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> impl Responder {
    let escrow_id = path.into_inner();

    // Require authentication
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Find escrow
    let escrow: Option<Escrow> = escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    let escrow = match escrow {
        Some(e) => e,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Escrow not found"
            }));
        }
    };

    // Check user is a participant
    let is_participant =
        escrow.buyer_id == user_id || escrow.vendor_id == user_id || escrow.arbiter_id == user_id;

    if !is_participant {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You are not a participant in this escrow"
        }));
    }

    // Determine participant status
    let buyer_joined = escrow.buyer_id != "pending";
    let vendor_joined = escrow.vendor_id != "pending";
    let arbiter_assigned = escrow.arbiter_id != "pending";
    let all_ready = buyer_joined && vendor_joined && arbiter_assigned;

    // Determine DKG status based on escrow status
    let dkg_status = match escrow.status.as_str() {
        "pending_counterparty" => "pending",
        "pending_dkg" => {
            if escrow.multisig_address.is_some() {
                "complete"
            } else {
                "pending"
            }
        }
        "awaiting_funding" | "funded" | "delivered" | "pending_release" | "completed"
        | "disputed" => "complete",
        _ => "pending",
    };

    HttpResponse::Ok().json(serde_json::json!({
        "escrow_id": escrow_id,
        "buyer_joined": buyer_joined,
        "vendor_joined": vendor_joined,
        "arbiter_assigned": arbiter_assigned,
        "all_ready": all_ready,
        "dkg_status": dkg_status,
        "status": escrow.status,
    }))
}

/// POST /api/escrows/{id}/start-dkg - Start multisig setup when all parties ready
pub async fn start_dkg(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> impl Responder {
    let escrow_id = path.into_inner();

    // Require authentication
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Find escrow
    let escrow: Option<Escrow> = escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    let escrow = match escrow {
        Some(e) => e,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Escrow not found"
            }));
        }
    };

    // Check user is a participant
    let is_participant =
        escrow.buyer_id == user_id || escrow.vendor_id == user_id || escrow.arbiter_id == user_id;

    if !is_participant {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You are not a participant in this escrow"
        }));
    }

    // Check all parties have joined
    if escrow.buyer_id == "pending"
        || escrow.vendor_id == "pending"
        || escrow.arbiter_id == "pending"
    {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "All parties must join before starting DKG",
            "buyer_joined": escrow.buyer_id != "pending",
            "vendor_joined": escrow.vendor_id != "pending",
            "arbiter_assigned": escrow.arbiter_id != "pending"
        }));
    }

    // Check escrow is in correct status
    let valid_statuses = ["pending_counterparty", "pending_dkg", "pending"];
    if !valid_statuses.contains(&escrow.status.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Escrow is not in a valid state for DKG",
            "current_status": escrow.status
        }));
    }

    // Update status to pending_dkg (multisig setup in progress)
    match diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
        .set((
            escrows::status.eq("pending_dkg"),
            escrows::multisig_phase.eq("preparing"),
            escrows::updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(&mut conn)
    {
        Ok(_) => {
            info!("DKG started for escrow {} by user {}", escrow_id, user_id);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Multisig setup initiated",
                "escrow_id": escrow_id,
                "status": "pending_dkg",
                "next_step": "Participants will now exchange DKG keys"
            }))
        }
        Err(e) => {
            error!("Failed to start DKG for escrow {}: {:?}", escrow_id, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to start DKG"
            }))
        }
    }
}

// ============================================================================
// Escrow State Transitions
// ============================================================================

/// Request body for mark_delivered
#[derive(Debug, serde::Deserialize)]
pub struct MarkDeliveredRequest {
    pub vendor_payout_address: String,
}

/// POST /api/escrow/{id}/deliver - Mark escrow as shipped (vendor only)
/// Stores payout address AND changes status to "shipped" in one action
pub async fn mark_delivered(
    pool: web::Data<DbPool>,
    websocket: web::Data<Addr<WebSocketServer>>,
    session: Session,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<MarkDeliveredRequest>,
    webhook_dispatcher: web::Data<Arc<WebhookDispatcher>>,
) -> impl Responder {
    let escrow_id = path.into_inner();

    // Require authentication (dual-auth: API key or session)
    let user_id = match crate::handlers::auth_helpers::get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    // Validate payout address
    let payout_address = &body.vendor_payout_address;
    if payout_address.len() != 95 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid payout address: must be 95 characters",
            "received_length": payout_address.len()
        }));
    }
    if !payout_address.starts_with('4') {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid payout address: must start with '4' (mainnet)"
        }));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Find escrow
    let escrow: Option<Escrow> = escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    let escrow = match escrow {
        Some(e) => e,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Escrow not found"
            }));
        }
    };

    // Verify user is vendor
    if escrow.vendor_id != user_id {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Only the vendor can mark as shipped"
        }));
    }

    // Verify escrow is funded
    if escrow.status != "funded" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Escrow must be funded before marking as shipped",
            "current_status": escrow.status
        }));
    }

    // Update payout address AND status to shipped in one operation
    match diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
        .set((
            escrows::vendor_payout_address.eq(payout_address),
            escrows::status.eq("shipped"),
        ))
        .execute(&mut conn)
    {
        Ok(_) => {
            info!(
                "Escrow {} marked as shipped by vendor {} (payout: {}...{})",
                escrow_id,
                user_id,
                &payout_address[..12],
                &payout_address[payout_address.len() - 8..]
            );

            // Broadcast EscrowShipped event to notify buyer
            websocket.do_send(WsEvent::EscrowShipped {
                escrow_id: escrow_id.clone(),
                vendor_id: user_id.clone(),
                buyer_id: escrow.buyer_id.clone(),
                tracking_info: None,
                auto_release_at: chrono::Utc::now().naive_utc() + chrono::Duration::days(14),
            });
            info!(
                "[WebSocket] Broadcast EscrowShipped for {} to buyer {}",
                escrow_id, escrow.buyer_id
            );

            // B2B Webhook: EscrowShipped
            emit_webhook_nonblocking(
                webhook_dispatcher.get_ref().clone(),
                WebhookEventType::EscrowShipped,
                build_escrow_payload(
                    &escrow_id,
                    "escrow.shipped",
                    serde_json::json!({
                        "vendor_id": user_id,
                        "status": "shipped",
                    }),
                ),
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "status": "shipped",
                "vendor_payout_address": payout_address,
                "message": "Escrow marked as shipped. Awaiting buyer confirmation."
            }))
        }
        Err(e) => {
            error!("Failed to update escrow: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update escrow"
            }))
        }
    }
}

/// POST /api/escrow/{id}/confirm - Confirm receipt (buyer only)
pub async fn confirm_delivery(
    pool: web::Data<DbPool>,
    session: Session,
    req: HttpRequest,
    path: web::Path<String>,
    webhook_dispatcher: web::Data<Arc<WebhookDispatcher>>,
) -> impl Responder {
    let escrow_id = path.into_inner();

    // Require authentication (dual-auth: API key or session)
    let user_id = match crate::handlers::auth_helpers::get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Find escrow
    let escrow: Option<Escrow> = escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    let escrow = match escrow {
        Some(e) => e,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Escrow not found"
            }));
        }
    };

    // Verify user is buyer
    if escrow.buyer_id != user_id {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Only the buyer can confirm delivery"
        }));
    }

    // Verify escrow is in shipped status
    if escrow.status != "shipped" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Escrow must be marked as shipped before confirming",
            "current_status": escrow.status
        }));
    }

    // Update status to signing_initiated (triggers release flow)
    match diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
        .set(escrows::status.eq("signing_initiated"))
        .execute(&mut conn)
    {
        Ok(_) => {
            info!(
                "Escrow {} confirmed by buyer {}, initiating release",
                escrow_id, user_id
            );

            // B2B Webhook: MultisigSigningRequired (buyer confirmed, signing can begin)
            emit_webhook_nonblocking(
                webhook_dispatcher.get_ref().clone(),
                WebhookEventType::MultisigSigningRequired,
                build_escrow_payload(
                    &escrow_id,
                    "multisig.signing_required",
                    serde_json::json!({
                        "buyer_id": user_id,
                        "status": "signing_initiated",
                    }),
                ),
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "status": "signing_initiated",
                "message": "Delivery confirmed, release signing initiated"
            }))
        }
        Err(e) => {
            error!("Failed to update escrow status: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update escrow status"
            }))
        }
    }
}

// ============================================================================
// Arbiter Endpoints
// ============================================================================

/// Response for arbiter dispute list
#[derive(Debug, Serialize)]
pub struct ArbiterDisputeResponse {
    pub id: String,
    pub escrow_id: String,
    pub status: String,
    pub reason: Option<String>,
    pub buyer_username: String,
    pub vendor_username: String,
    pub amount: i64,
    pub created_at: String,
    pub dispute_created_at: Option<String>,
}

/// GET /api/arbiter/disputes - List all disputes for arbiter
pub async fn get_arbiter_disputes(pool: web::Data<DbPool>, session: Session) -> impl Responder {
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Verify user is arbiter
    let user: Option<User> = users::table
        .filter(users::id.eq(&user_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    match &user {
        Some(u) if u.role == "arbiter" => {}
        _ => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Only arbiters can access this endpoint"
            }));
        }
    }

    // Platform has a single arbiter role — show ALL disputed escrows
    // Role check above already gates access to arbiter-only users
    let disputes: Vec<Escrow> = escrows::table
        .filter(escrows::status.eq("disputed"))
        .order(escrows::created_at.desc())
        .load(&mut conn)
        .unwrap_or_default();

    // Get usernames for buyers and vendors
    let mut response: Vec<ArbiterDisputeResponse> = Vec::new();

    for escrow in disputes {
        let buyer: Option<User> = users::table
            .filter(users::id.eq(&escrow.buyer_id))
            .first(&mut conn)
            .optional()
            .unwrap_or(None);

        let vendor: Option<User> = users::table
            .filter(users::id.eq(&escrow.vendor_id))
            .first(&mut conn)
            .optional()
            .unwrap_or(None);

        response.push(ArbiterDisputeResponse {
            id: format!("disp_{}", &escrow.id[4..]),
            escrow_id: escrow.id.clone(),
            status: escrow.status.clone(),
            reason: escrow.dispute_reason.clone(),
            buyer_username: buyer
                .map(|u| u.username)
                .unwrap_or_else(|| "Unknown".to_string()),
            vendor_username: vendor
                .map(|u| u.username)
                .unwrap_or_else(|| "Unknown".to_string()),
            amount: escrow.amount,
            created_at: escrow.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            dispute_created_at: escrow
                .dispute_created_at
                .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()),
        });
    }

    info!(
        "Retrieved {} disputes for arbiter {}",
        response.len(),
        user_id
    );

    HttpResponse::Ok().json(serde_json::json!({
        "disputes": response,
        "total": response.len()
    }))
}

/// GET /api/arbiter/disputes/{id} - Get single dispute details
pub async fn get_arbiter_dispute_detail(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> impl Responder {
    let dispute_id = path.into_inner();
    // Convert dispute_id to escrow_id (disp_xxx -> esc_xxx)
    let escrow_id = dispute_id.replace("disp_", "esc_");

    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Verify user is arbiter
    let user: Option<User> = users::table
        .filter(users::id.eq(&user_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    match &user {
        Some(u) if u.role == "arbiter" => {}
        _ => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Only arbiters can access this endpoint"
            }));
        }
    }

    // Find the escrow
    let escrow: Option<Escrow> = escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    let escrow = match escrow {
        Some(e) => e,
        None => {
            // Try without prefix conversion
            match escrows::table
                .filter(escrows::id.eq(&dispute_id))
                .first::<Escrow>(&mut conn)
                .optional()
                .unwrap_or(None)
            {
                Some(e) => e,
                None => {
                    return HttpResponse::NotFound().json(serde_json::json!({
                        "error": "Dispute not found"
                    }));
                }
            }
        }
    };

    // Verify arbiter is assigned to this escrow
    if escrow.arbiter_id != user_id {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You are not the arbiter for this escrow"
        }));
    }

    // Get buyer and vendor info
    let buyer: Option<User> = users::table
        .filter(users::id.eq(&escrow.buyer_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    let vendor: Option<User> = users::table
        .filter(users::id.eq(&escrow.vendor_id))
        .first(&mut conn)
        .optional()
        .unwrap_or(None);

    HttpResponse::Ok().json(serde_json::json!({
        "dispute": {
            "id": format!("disp_{}", &escrow.id[4..]),
            "escrow_id": escrow.id,
            "status": escrow.status,
            "reason": escrow.dispute_reason,
            "buyer": {
                "id": escrow.buyer_id,
                "username": buyer.map(|u| u.username).unwrap_or_else(|| "Unknown".to_string()),
            },
            "vendor": {
                "id": escrow.vendor_id,
                "username": vendor.map(|u| u.username).unwrap_or_else(|| "Unknown".to_string()),
            },
            "amount": escrow.amount,
            "amount_xmr": escrow.amount as f64 / 1_000_000_000_000.0,
            "created_at": escrow.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            "disputed_at": escrow.dispute_created_at.map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()),
            "multisig_address": escrow.multisig_address,
            "description": escrow.description,
        }
    }))
}
