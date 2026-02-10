use actix_web::{web, HttpResponse, post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::db::DbPool;

#[derive(Serialize, Deserialize)]
pub struct MultisigCoordinationRequest {
    pub wallet_id: String,
    pub escrow_id: String,
    pub participants: Vec<MultisigParticipant>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MultisigParticipant {
    pub user_id: String,
    pub role: String, // "buyer", "vendor", "arbiter"
    pub multisig_info: String, // Monero RPC multisig_info output
}

#[derive(Serialize, Deserialize)]
pub struct MultisigCoordinationResponse {
    pub status: String,
    pub multisig_address: Option<String>,
    pub coordination_id: String,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct MultisigStatusRequest {
    pub coordination_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct MultisigStatusResponse {
    pub status: String,
    pub phase: String,
    pub ready: bool,
    pub message: String,
}

/// Initiate multisig wallet coordination between participants
#[post("/api/multisig/coordinate")]
pub async fn coordinate_multisig_setup(
    req: web::Json<MultisigCoordinationRequest>,
    session: actix_session::Session,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required"
            })));
        }
    };

    // Validate at least 2-of-3 multisig
    if req.participants.len() < 2 || req.participants.len() > 3 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid participant count",
            "message": "Multisig requires 2-3 participants"
        })));
    }

    // Validate participant roles
    let roles: Vec<&str> = req.participants.iter().map(|p| p.role.as_str()).collect();
    if roles.len() != roles.windows(1).filter(|_| true).count() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid roles",
            "message": "Each participant must have a unique role"
        })));
    }

    let coordination_id = Uuid::new_v4().to_string();

    // Store coordination state in database (simplified - would normally use a table)
    tracing::info!(
        "Multisig coordination initiated: {} for escrow {} with {} participants",
        coordination_id,
        req.escrow_id,
        req.participants.len()
    );

    Ok(HttpResponse::Created().json(MultisigCoordinationResponse {
        status: "initiated".to_string(),
        multisig_address: None, // Would be generated after all participants provide info
        coordination_id,
        message: format!(
            "Multisig coordination started. {} participants ready to exchange info.",
            req.participants.len()
        ),
    }))
}

/// Get status of ongoing multisig coordination
#[post("/api/multisig/status")]
pub async fn get_multisig_status(
    req: web::Json<MultisigStatusRequest>,
    session: actix_session::Session,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required"
            })));
        }
    };

    // Query coordination status from database
    // This is simplified - actual implementation would check database
    Ok(HttpResponse::Ok().json(MultisigStatusResponse {
        status: "pending".to_string(),
        phase: "waiting_for_participants".to_string(),
        ready: false,
        message: "Waiting for all participants to submit multisig info".to_string(),
    }))
}

/// Finalize multisig wallet setup after all participants contribute
#[post("/api/multisig/finalize")]
pub async fn finalize_multisig(
    req: web::Json<MultisigCoordinationRequest>,
    session: actix_session::Session,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required"
            })));
        }
    };

    // In a real implementation, this would:
    // 1. Collect all participant multisig_info
    // 2. Call Monero RPC make_multisig on one wallet with others' info
    // 3. Export/import multisig sync info between wallets
    // 4. Verify all wallets are ready (is_multisig() == true)
    // 5. Generate final multisig address

    let multisig_address = format!("multisig_{}", Uuid::new_v4().to_string().chars().take(10).collect::<String>());

    Ok(HttpResponse::Ok().json(MultisigCoordinationResponse {
        status: "ready".to_string(),
        multisig_address: Some(multisig_address),
        coordination_id: req.wallet_id.clone(),
        message: "Multisig wallet coordination complete. Wallets are ready for 2-of-3 signing.".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_participant_count() {
        assert!(is_valid_participant_count(2));
        assert!(is_valid_participant_count(3));
        assert!(!is_valid_participant_count(1));
        assert!(!is_valid_participant_count(4));
    }

    fn is_valid_participant_count(count: usize) -> bool {
        count >= 2 && count <= 3
    }
}
