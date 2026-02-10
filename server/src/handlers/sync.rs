//! Sync API Handlers - Light Wallet Server Endpoints
//!
//! These endpoints provide Light Wallet Server (LWS) functionality for
//! in-browser WASM wallets.
//!
//! **ENDPOINTS:**
//! - POST /api/sync/scan - Scan blockchain for outputs
//! - POST /api/sync/broadcast - Broadcast signed transaction
//!
//! **SECURITY:**
//! - Rate-limited (prevent blockchain scan abuse)
//! - Requires authentication (user must be logged in)
//! - View keys logged for audit trail (privacy trade-off)

use actix_session::Session;
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};

use crate::services::sync_proxy::{
    BroadcastTxRequest, ScanOutputsRequest, SyncProxyError, SyncProxyService,
};

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

/// Simplified scan request (from WASM client)
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub view_key_pub: String,
    pub spend_key_pub: String,
    #[serde(default)]
    pub start_height: u64,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: String,
}

// ============================================================================
// HANDLERS
// ============================================================================

/// POST /api/sync/scan
///
/// Scan blockchain for outputs belonging to a wallet.
///
/// # Request Body
/// ```json
/// {
///   "viewKeyPub": "hex...",
///   "spendKeyPub": "hex...",
///   "startHeight": 0
/// }
/// ```
///
/// # Response
/// ```json
/// {
///   "syncedHeight": 3000000,
///   "outputs": [
///     {
///       "txHash": "...",
///       "outputIndex": 0,
///       "amount": 1000000000000,
///       "publicKey": "...",
///       "txPubKey": "...",
///       "globalIndex": 123456,
///       "blockHeight": 2999999,
///       "ringDecoys": [...]
///     }
///   ],
///   "balance": 1000000000000
/// }
/// ```
///
/// # Security
/// - Requires authentication
/// - Rate-limited to prevent abuse
/// - View key logged for audit (privacy trade-off)
pub async fn scan_outputs(
    session: Session,
    sync_service: web::Data<SyncProxyService>,
    request: web::Json<ScanRequest>,
) -> impl Responder {
    // Require authentication
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "UNAUTHORIZED".to_string(),
                details: "Authentication required".to_string(),
            })
        }
    };

    tracing::info!(
        "User {} scanning blockchain from height {}",
        user_id,
        request.start_height
    );

    // PRIVACY WARNING: View key logged (allows server to see future balances)
    tracing::warn!(
        "User {} shared view key (privacy trade-off): {}",
        user_id,
        &request.view_key_pub[..8] // Log only first 8 chars
    );

    let scan_request = ScanOutputsRequest {
        view_key_pub: request.view_key_pub.clone(),
        spend_key_pub: request.spend_key_pub.clone(),
        start_height: request.start_height,
        address: None,
    };

    match sync_service.scan_outputs(scan_request).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => {
            let (status, error_code) = match e {
                SyncProxyError::InvalidViewKey(_) => (400, "INVALID_KEY"),
                SyncProxyError::ScanError(_) => (500, "SCAN_ERROR"),
                _ => (500, "INTERNAL_ERROR"),
            };

            tracing::error!("Scan error for user {}: {}", user_id, e);

            HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap()).json(
                ErrorResponse {
                    error: error_code.to_string(),
                    details: e.to_string(),
                },
            )
        }
    }
}

/// POST /api/sync/broadcast
///
/// Broadcast a signed transaction to the Monero network.
///
/// # Request Body
/// ```json
/// {
///   "signedTxHex": "hex...",
///   "doNotRelay": false
/// }
/// ```
///
/// # Response
/// ```json
/// {
///   "txHash": "...",
///   "relayed": true,
///   "fee": 12000000
/// }
/// ```
///
/// # Security
/// - Requires authentication
/// - Transaction blob is signed by client (opaque to server)
/// - Server cannot modify transaction
pub async fn broadcast_transaction(
    session: Session,
    sync_service: web::Data<SyncProxyService>,
    request: web::Json<BroadcastTxRequest>,
) -> impl Responder {
    // Require authentication
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "UNAUTHORIZED".to_string(),
                details: "Authentication required".to_string(),
            })
        }
    };

    tracing::info!(
        "User {} broadcasting transaction (do_not_relay={})",
        user_id,
        request.do_not_relay
    );

    match sync_service.broadcast_tx(request.into_inner()).await {
        Ok(response) => {
            tracing::info!(
                "Transaction broadcast successful for user {}: {}",
                user_id,
                response.tx_hash
            );
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            tracing::error!("Broadcast error for user {}: {}", user_id, e);

            HttpResponse::BadRequest().json(ErrorResponse {
                error: "BROADCAST_ERROR".to_string(),
                details: e.to_string(),
            })
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[test]
    async fn test_scan_request_deserialization() {
        let json = r#"{
            "viewKeyPub": "a1b2c3d4",
            "spendKeyPub": "e5f6g7h8",
            "startHeight": 1000
        }"#;

        let request: ScanRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.view_key_pub, "a1b2c3d4");
        assert_eq!(request.spend_key_pub, "e5f6g7h8");
        assert_eq!(request.start_height, 1000);
    }

    #[test]
    async fn test_scan_request_default_height() {
        let json = r#"{
            "viewKeyPub": "test",
            "spendKeyPub": "test"
        }"#;

        let request: ScanRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.start_height, 0);
    }

    #[actix_web::test]
    async fn test_scan_outputs_requires_auth() {
        let sync_service = SyncProxyService::new(
            "http://127.0.0.1:18081/json_rpc".to_string(),
            "http://127.0.0.1:18083/json_rpc".to_string(),
        )
        .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(sync_service))
                .route("/api/sync/scan", web::post().to(scan_outputs)),
        )
        .await;

        let request_body = ScanRequest {
            view_key_pub: "a".repeat(64),
            spend_key_pub: "b".repeat(64),
            start_height: 0,
        };

        let req = test::TestRequest::post()
            .uri("/api/sync/scan")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Should return 401 Unauthorized (no session)
        assert_eq!(resp.status(), 401);
    }
}
