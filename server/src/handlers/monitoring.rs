//! Monitoring endpoints for admin oversight
//!
//! Provides API endpoints for monitoring escrow health, timeouts, and system status.

use actix_web::{get, web, HttpResponse, Responder};
use serde::Serialize;
use uuid::Uuid;

use crate::db::DbPool;
use crate::models::escrow::Escrow;

/// Response structure for escrow health check
#[derive(Debug, Serialize)]
pub struct EscrowHealthResponse {
    pub total_active_escrows: usize,
    pub escrows_by_status: std::collections::HashMap<String, usize>,
    pub expired_escrows: Vec<ExpiredEscrowInfo>,
    pub expiring_soon: Vec<ExpiringEscrowInfo>,
}

/// Information about an expired escrow
#[derive(Debug, Serialize)]
pub struct ExpiredEscrowInfo {
    pub escrow_id: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub hours_overdue: i64,
}

/// Information about an escrow approaching expiration
#[derive(Debug, Serialize)]
pub struct ExpiringEscrowInfo {
    pub escrow_id: String,
    pub status: String,
    pub expires_at: Option<String>,
    pub seconds_remaining: i64,
    pub action_required: String,
}

/// GET /admin/escrows/health - Get health status of all escrows
///
/// Returns statistics about active escrows, including:
/// - Total count by status
/// - List of expired escrows (past deadline)
/// - List of escrows approaching expiration
///
/// **TODO: Add authentication/authorization for admin-only access**
#[get("/admin/escrows/health")]
pub async fn get_escrow_health(pool: web::Data<DbPool>) -> impl Responder {
    // Get DB connection
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get DB connection: {}", e)
            }));
        }
    };

    // Load all active escrows (non-terminal states)
    let active_escrows = match tokio::task::spawn_blocking(move || {
        use crate::schema::escrows::dsl::*;
        use diesel::prelude::*;

        escrows
            .filter(status.ne("completed"))
            .filter(status.ne("refunded"))
            .filter(status.ne("cancelled"))
            .filter(status.ne("expired"))
            .load::<Escrow>(&mut conn)
    })
    .await
    {
        Ok(Ok(escrows_list)) => escrows_list,
        Ok(Err(e)) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to load escrows: {}", e)
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Task join error: {}", e)
            }));
        }
    };

    // Count escrows by status
    let mut status_counts = std::collections::HashMap::new();
    for escrow in &active_escrows {
        *status_counts.entry(escrow.status.clone()).or_insert(0) += 1;
    }

    // Find expired escrows
    let mut expired_list = Vec::new();
    for escrow in &active_escrows {
        if escrow.is_expired() {
            let hours_overdue = if let Some(expires_at) = escrow.expires_at {
                let now = chrono::Utc::now().naive_utc();
                let duration = now.signed_duration_since(expires_at);
                duration.num_hours()
            } else {
                0
            };

            expired_list.push(ExpiredEscrowInfo {
                escrow_id: escrow.id.clone(),
                status: escrow.status.clone(),
                created_at: escrow.created_at.to_string(),
                expires_at: escrow.expires_at.map(|dt| dt.to_string()),
                hours_overdue,
            });
        }
    }

    // Find escrows expiring soon (within 1 hour)
    let mut expiring_list = Vec::new();
    const WARNING_THRESHOLD_SECS: i64 = 3600; // 1 hour
    for escrow in &active_escrows {
        if escrow.is_expiring_soon(WARNING_THRESHOLD_SECS) {
            let action_required = match escrow.status.as_str() {
                "created" => "Complete multisig setup",
                "funded" => "Buyer: deposit funds to escrow address",
                "releasing" | "refunding" => "Wait for blockchain confirmation",
                "disputed" => "Arbiter: resolve dispute",
                _ => "No action required",
            };

            expiring_list.push(ExpiringEscrowInfo {
                escrow_id: escrow.id.clone(),
                status: escrow.status.clone(),
                expires_at: escrow.expires_at.map(|dt| dt.to_string()),
                seconds_remaining: escrow.seconds_until_expiration().unwrap_or(0),
                action_required: action_required.to_string(),
            });
        }
    }

    let response = EscrowHealthResponse {
        total_active_escrows: active_escrows.len(),
        escrows_by_status: status_counts,
        expired_escrows: expired_list,
        expiring_soon: expiring_list,
    };

    HttpResponse::Ok().json(response)
}

/// GET /admin/escrows/{id}/status - Get detailed status of a specific escrow
///
/// Returns full escrow details including timeout information.
///
/// **TODO: Add authentication/authorization for admin-only access**
#[get("/admin/escrows/{id}/status")]
pub async fn get_escrow_status(
    pool: web::Data<DbPool>,
    escrow_id: web::Path<String>,
) -> impl Responder {
    let escrow_id_str = escrow_id.into_inner();

    // Validate UUID format
    if Uuid::parse_str(&escrow_id_str).is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid escrow ID format (must be UUID)"
        }));
    }

    // Get DB connection
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get DB connection: {}", e)
            }));
        }
    };

    // Load escrow
    let escrow = match tokio::task::spawn_blocking(move || {
        Escrow::find_by_id(&mut conn, escrow_id_str)
    })
    .await
    {
        Ok(Ok(escrow)) => escrow,
        Ok(Err(e)) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Escrow not found: {}", e)
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Task join error: {}", e)
            }));
        }
    };

    // Build response with timeout info
    #[derive(Serialize)]
    struct DetailedEscrowStatus {
        escrow_id: String,
        status: String,
        amount: i64,
        created_at: String,
        last_activity_at: String,
        expires_at: Option<String>,
        seconds_until_expiration: Option<i64>,
        is_expired: bool,
        is_expiring_soon: bool,
        buyer_id: String,
        vendor_id: String,
        arbiter_id: String,
        multisig_address: Option<String>,
        transaction_hash: Option<String>,
    }

    let response = DetailedEscrowStatus {
        escrow_id: escrow.id.clone(),
        status: escrow.status.clone(),
        amount: escrow.amount,
        created_at: escrow.created_at.to_string(),
        last_activity_at: escrow.last_activity_at.to_string(),
        expires_at: escrow.expires_at.map(|dt| dt.to_string()),
        seconds_until_expiration: escrow.seconds_until_expiration(),
        is_expired: escrow.is_expired(),
        is_expiring_soon: escrow.is_expiring_soon(3600),
        buyer_id: escrow.buyer_id,
        vendor_id: escrow.vendor_id,
        arbiter_id: escrow.arbiter_id,
        multisig_address: escrow.multisig_address,
        transaction_hash: escrow.transaction_hash,
    };

    HttpResponse::Ok().json(response)
}
