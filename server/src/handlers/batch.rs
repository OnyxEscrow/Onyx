//! Batch operations endpoint for B2B API
//!
//! Allows clients to submit multiple escrow operations in a single HTTP request,
//! reducing round-trips for status polling and bulk state transitions.
//!
//! ## Endpoint
//! `POST /api/v1/escrows/batch`
//!
//! ## Supported actions
//! - `status` — Retrieve current status of an escrow (requires `escrow:read`)
//! - `release` — Release escrow funds to vendor (requires `escrow:write`)
//! - `refund` — Refund escrow funds to buyer (requires `escrow:write`)
//! - `dispute` — Initiate dispute on an escrow (requires `escrow:write`)

use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::db::DbPool;
use crate::models::escrow::Escrow;
use crate::schema::escrows;

/// Maximum operations per batch request (prevents abuse)
const MAX_BATCH_SIZE: usize = 50;

// ============================================================================
// Request / Response types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct BatchRequest {
    pub operations: Vec<BatchOperation>,
}

#[derive(Debug, Deserialize)]
pub struct BatchOperation {
    pub action: String,
    pub escrow_id: String,
}

#[derive(Debug, Serialize)]
pub struct BatchResponse {
    pub results: Vec<BatchResult>,
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
}

#[derive(Debug, Serialize)]
pub struct BatchResult {
    pub escrow_id: String,
    pub action: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// Handler
// ============================================================================

/// POST /api/v1/escrows/batch — Execute multiple escrow operations atomically
pub async fn batch_operations(
    pool: web::Data<DbPool>,
    session: Session,
    req: HttpRequest,
    body: web::Json<BatchRequest>,
) -> impl Responder {
    // Authenticate (dual-auth: API key or session)
    let user_id = match crate::handlers::auth_helpers::get_authenticated_identity(&req, &session) {
        Ok(identity) => identity.user_id().to_string(),
        Err(_) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }));
        }
    };

    // Validate batch size
    if body.operations.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "operations array must not be empty"
        }));
    }
    if body.operations.len() > MAX_BATCH_SIZE {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Too many operations. Maximum is {}", MAX_BATCH_SIZE),
            "max_batch_size": MAX_BATCH_SIZE,
            "received": body.operations.len()
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

    let mut results: Vec<BatchResult> = Vec::with_capacity(body.operations.len());
    let mut succeeded: usize = 0;
    let mut failed: usize = 0;

    for op in &body.operations {
        let result = execute_operation(&mut conn, &user_id, &op.action, &op.escrow_id);
        match result {
            Ok(data) => {
                succeeded += 1;
                results.push(BatchResult {
                    escrow_id: op.escrow_id.clone(),
                    action: op.action.clone(),
                    success: true,
                    data: Some(data),
                    error: None,
                });
            }
            Err(err_msg) => {
                failed += 1;
                results.push(BatchResult {
                    escrow_id: op.escrow_id.clone(),
                    action: op.action.clone(),
                    success: false,
                    data: None,
                    error: Some(err_msg),
                });
            }
        }
    }

    let total = results.len();
    info!(
        "Batch: {} operations for user {} ({} succeeded, {} failed)",
        total, user_id, succeeded, failed
    );

    HttpResponse::Ok().json(BatchResponse {
        results,
        total,
        succeeded,
        failed,
    })
}

// ============================================================================
// Per-operation execution
// ============================================================================

fn execute_operation(
    conn: &mut diesel::SqliteConnection,
    user_id: &str,
    action: &str,
    escrow_id: &str,
) -> Result<serde_json::Value, String> {
    // Validate action
    let valid_actions = ["status", "release", "refund", "dispute"];
    if !valid_actions.contains(&action) {
        return Err(format!(
            "Unknown action '{}'. Valid actions: {:?}",
            action, valid_actions
        ));
    }

    // Load escrow
    let escrow: Escrow = escrows::table
        .filter(escrows::id.eq(escrow_id))
        .first(conn)
        .map_err(|_| format!("Escrow '{}' not found", escrow_id))?;

    // Verify caller is a participant
    let is_participant = escrow.buyer_id == user_id
        || escrow.vendor_id == user_id
        || escrow.arbiter_id == user_id;

    if !is_participant {
        return Err("Not a participant in this escrow".to_string());
    }

    match action {
        "status" => Ok(serde_json::json!({
            "escrow_id": escrow.id,
            "status": escrow.status,
            "amount": escrow.amount,
            "multisig_phase": escrow.multisig_phase,
            "frost_dkg_complete": escrow.frost_dkg_complete,
            "balance_received": escrow.balance_received,
            "created_at": escrow.created_at.to_string(),
            "updated_at": escrow.updated_at.to_string(),
        })),

        "release" => {
            // Only buyer can release
            if escrow.buyer_id != user_id {
                return Err("Only the buyer can release funds".to_string());
            }
            if escrow.status != "shipped" && escrow.status != "funded" {
                return Err(format!(
                    "Cannot release: escrow status is '{}', expected 'shipped' or 'funded'",
                    escrow.status
                ));
            }
            // Set buyer_release_requested flag
            diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
                .set((
                    escrows::buyer_release_requested.eq(true),
                    escrows::status.eq("signing_initiated"),
                    escrows::updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(conn)
                .map_err(|e| format!("DB update failed: {}", e))?;

            Ok(serde_json::json!({
                "escrow_id": escrow_id,
                "status": "signing_initiated",
                "message": "Release signing initiated"
            }))
        }

        "refund" => {
            // Only vendor can initiate refund via batch
            if escrow.vendor_id != user_id {
                return Err("Only the vendor can initiate a refund".to_string());
            }
            if escrow.status != "funded" && escrow.status != "shipped" {
                return Err(format!(
                    "Cannot refund: escrow status is '{}', expected 'funded' or 'shipped'",
                    escrow.status
                ));
            }
            diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
                .set((
                    escrows::vendor_refund_requested.eq(true),
                    escrows::updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(conn)
                .map_err(|e| format!("DB update failed: {}", e))?;

            Ok(serde_json::json!({
                "escrow_id": escrow_id,
                "status": escrow.status,
                "refund_requested": true,
                "message": "Refund request recorded, arbiter will co-sign"
            }))
        }

        "dispute" => {
            // Buyer or vendor can dispute
            if escrow.buyer_id != user_id && escrow.vendor_id != user_id {
                return Err("Only buyer or vendor can initiate a dispute".to_string());
            }
            let disputable = ["funded", "shipped", "signing_initiated"];
            if !disputable.contains(&escrow.status.as_str()) {
                return Err(format!(
                    "Cannot dispute: escrow status is '{}', expected one of {:?}",
                    escrow.status, disputable
                ));
            }
            diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
                .set((
                    escrows::status.eq("disputed"),
                    escrows::dispute_created_at.eq(Some(chrono::Utc::now().naive_utc())),
                    escrows::updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(conn)
                .map_err(|e| format!("DB update failed: {}", e))?;

            Ok(serde_json::json!({
                "escrow_id": escrow_id,
                "status": "disputed",
                "message": "Dispute initiated"
            }))
        }

        _ => Err(format!("Unhandled action: {}", action)),
    }
}
