//! Challenge-response handlers for multisig validation (TM-003)
//!
//! These handlers implement the proof-of-possession workflow to prevent
//! malicious participants from submitting backdoored multisig_info.

use actix_session::Session;
use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::multisig_validation::{
    verify_multisig_submission, ChallengeStore, MultisigChallenge,
};

/// Global challenge store (in-memory for now)
/// TODO: Move to Redis in production for multi-server support
lazy_static::lazy_static! {
    pub static ref CHALLENGE_STORE: ChallengeStore = ChallengeStore::new();
}

/// Response when requesting a challenge
#[derive(Serialize)]
pub struct ChallengeResponse {
    /// Hex-encoded nonce (32 bytes)
    pub nonce: String,

    /// Hex-encoded challenge message to sign (64 bytes BLAKE2b-512)
    pub message: String,

    /// Unix timestamp when challenge expires
    pub expires_at: u64,

    /// Time remaining in seconds
    pub time_remaining: u64,
}

/// Request a challenge for multisig submission
///
/// # Endpoint
///
/// `POST /api/escrow/:escrow_id/multisig/challenge`
///
/// # Authentication
///
/// Requires valid session (user must be logged in)
///
/// # Returns
///
/// ```json
/// {
///   "nonce": "3f7a8b2c9d1e4f5a...",
///   "message": "a1b2c3d4e5f6...",
///   "expires_at": 1698765432,
///   "time_remaining": 300
/// }
/// ```
///
/// # Flow
///
/// 1. User requests challenge
/// 2. Server generates random nonce + timestamp
/// 3. Server stores challenge temporarily (5 min expiry)
/// 4. User signs message offline with their wallet
/// 5. User submits multisig_info + signature to /prepare endpoint
///
/// # Example
///
/// ```bash
/// curl -X POST http://localhost:8080/api/escrow/abc-123/multisig/challenge \
///   -H "Cookie: session=..." \
///   -H "Content-Type: application/json"
/// ```
#[post("/api/escrow/{escrow_id}/multisig/challenge")]
pub async fn request_multisig_challenge(
    escrow_id: web::Path<Uuid>,
    session: Session,
) -> actix_web::Result<impl Responder> {
    // Get authenticated user ID
    let user_id = session
        .get::<String>("user_id")
        .map_err(|_| actix_web::error::ErrorUnauthorized("Session error"))?
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Not authenticated"))?;

    let user_id = Uuid::parse_str(&user_id)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid user ID"))?;

    // Generate challenge
    let challenge = MultisigChallenge::generate(*escrow_id);

    // Store challenge
    CHALLENGE_STORE.store(user_id, *escrow_id, challenge.clone());

    tracing::info!(
        "Generated multisig challenge for user {} on escrow {}",
        user_id,
        escrow_id
    );

    // Prepare response
    let response = ChallengeResponse {
        nonce: hex::encode(&challenge.nonce),
        message: hex::encode(&challenge.message()),
        expires_at: challenge.created_at + 300,
        time_remaining: challenge.time_remaining(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Request body for submitting multisig_info with signature
#[derive(Deserialize)]
pub struct SubmitMultisigInfoRequest {
    /// Monero multisig_info string (starts with "MultisigV1")
    pub multisig_info: String,

    /// Ed25519 signature over challenge message (hex-encoded, 64 bytes)
    pub signature: String,
}

/// Submit multisig_info with challenge-response signature
///
/// # Endpoint
///
/// `POST /api/escrow/:escrow_id/multisig/prepare`
///
/// # Authentication
///
/// Requires valid session + valid challenge
///
/// # Request Body
///
/// ```json
/// {
///   "multisig_info": "MultisigV1abc123...",
///   "signature": "def456789..."
/// }
/// ```
///
/// # Validation
///
/// 1. Retrieve challenge for user/escrow
/// 2. Check challenge not expired (<5 min)
/// 3. Extract public key from multisig_info
/// 4. Verify signature matches public key
/// 5. If valid → accept multisig_info
/// 6. Delete challenge (one-time use)
///
/// # Returns
///
/// ```json
/// {
///   "status": "accepted",
///   "message": "Multisig info validated and stored"
/// }
/// ```
///
/// # Errors
///
/// - 401: Not authenticated
/// - 400: No challenge found (must call /challenge first)
/// - 400: Challenge expired
/// - 403: Signature verification failed (invalid proof-of-possession)
///
/// # Example
///
/// ```bash
/// # 1. Request challenge
/// CHALLENGE=$(curl -X POST .../multisig/challenge | jq -r '.message')
///
/// # 2. Sign challenge with Monero wallet
/// SIGNATURE=$(monero-wallet-cli --testnet <<EOF
/// sign $CHALLENGE
/// exit
/// EOF
/// )
///
/// # 3. Submit with signature
/// curl -X POST .../multisig/prepare \
///   -H "Content-Type: application/json" \
///   -d "{
///     \"multisig_info\": \"$MULTISIG_INFO\",
///     \"signature\": \"$SIGNATURE\"
///   }"
/// ```
#[post("/api/escrow/{escrow_id}/multisig/prepare")]
pub async fn submit_multisig_info_with_signature(
    escrow_id: web::Path<Uuid>,
    payload: web::Json<SubmitMultisigInfoRequest>,
    session: Session,
) -> actix_web::Result<impl Responder> {
    // Get authenticated user ID
    let user_id = session
        .get::<String>("user_id")
        .map_err(|_| actix_web::error::ErrorUnauthorized("Session error"))?
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Not authenticated"))?;

    let user_id = Uuid::parse_str(&user_id)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid user ID"))?;

    // Retrieve challenge
    let challenge = CHALLENGE_STORE.get(user_id, *escrow_id).ok_or_else(|| {
        actix_web::error::ErrorBadRequest(
            "No challenge found. Call /multisig/challenge first to request a challenge.",
        )
    })?;

    // Decode signature from hex
    let signature = hex::decode(&payload.signature).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Invalid signature hex encoding: {}", e))
    })?;

    // Verify multisig submission
    verify_multisig_submission(&payload.multisig_info, &signature, &challenge).map_err(|e| {
        tracing::error!(
            "Multisig validation failed for user {} on escrow {}: {}",
            user_id,
            escrow_id,
            e
        );
        actix_web::error::ErrorForbidden(format!("Signature verification failed: {}", e))
    })?;

    // Delete challenge (one-time use)
    CHALLENGE_STORE.remove(user_id, *escrow_id);

    tracing::info!(
        "✅ Multisig info validated for user {} on escrow {}",
        user_id,
        escrow_id
    );

    // TODO: Store validated multisig_info in database
    // orchestrator.collect_prepare_info(*escrow_id, user_id, payload.multisig_info.clone()).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "accepted",
        "message": "Multisig info validated and stored"
    })))
}

/// Cleanup expired challenges (called periodically)
///
/// This endpoint should be called by a cron job or background task
/// to remove expired challenges from memory.
///
/// # Endpoint
///
/// `POST /api/maintenance/cleanup-challenges`
///
/// # Authentication
///
/// Requires admin role (TODO: implement admin auth check)
#[post("/api/maintenance/cleanup-challenges")]
pub async fn cleanup_expired_challenges() -> impl Responder {
    let before_count = {
        let challenges = CHALLENGE_STORE.challenges.lock().unwrap();
        challenges.len()
    };

    CHALLENGE_STORE.cleanup_expired();

    let after_count = {
        let challenges = CHALLENGE_STORE.challenges.lock().unwrap();
        challenges.len()
    };

    let removed = before_count - after_count;

    tracing::info!("Cleaned up {} expired multisig challenges", removed);

    HttpResponse::Ok().json(serde_json::json!({
        "removed": removed,
        "remaining": after_count
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn test_challenge_request_unauthenticated() {
        let app = test::init_service(App::new().service(request_multisig_challenge)).await;

        let escrow_id = Uuid::new_v4();
        let req = test::TestRequest::post()
            .uri(&format!("/api/escrow/{}/multisig/challenge", escrow_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401); // Unauthorized
    }

    // TODO: Add more tests with mocked authentication
}
