//! Multisig Coordination API Handlers
//!
//! Exposes the DbMultisigCoordinator via REST endpoints for remote clients.
//! Supports WASM/CLI clients coordinating multisig setup without exposing RPC.

use actix_web::{web, HttpResponse, post, get};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::coordination::{
    DbMultisigCoordinator, MultisigCoordinator, MultisigCoordinationError, MultisigStage,
    ParticipantType,
};

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

/// Request to initialize a new multisig session
#[derive(Debug, Deserialize)]
pub struct InitSessionRequest {
    pub escrow_id: String,
    pub participants: Vec<ParticipantDto>,
}

/// Participant in multisig session
#[derive(Debug, Deserialize, Serialize)]
pub struct ParticipantDto {
    pub role: String, // "buyer", "vendor", "arbiter"
    pub participant_type: String, // "local_managed" or "remote"
    pub wallet_id: Option<String>, // For LocalManaged
    pub user_id: Option<String>, // For Remote
}

/// Request to submit multisig info (Round 1 or 2)
#[derive(Debug, Deserialize)]
pub struct SubmitInfoRequest {
    pub escrow_id: String,
    pub user_id: String,
    pub multisig_info: String,
    pub stage: String, // "initialization" or "key_exchange"
}

/// Response for successful submission
#[derive(Debug, Serialize)]
pub struct SubmitInfoResponse {
    pub success: bool,
    pub message: String,
    pub current_stage: String,
}

/// Response for peer info request
#[derive(Debug, Serialize)]
pub struct PeerInfoResponse {
    pub peer_infos: Vec<String>,
    pub count: usize,
    pub current_stage: String,
}

/// Response for status check
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub escrow_id: String,
    pub stage: String,
    pub multisig_address: Option<String>,
    pub created_at: i64,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: String,
}

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.details)
    }
}

// ============================================================================
// HANDLER IMPLEMENTATIONS
// ============================================================================

/// Initialize a new multisig coordination session
///
/// # Endpoint
/// POST /api/multisig/init
///
/// # Request Body
/// ```json
/// {
///   "escrow_id": "uuid-here",
///   "participants": [
///     {"role": "buyer", "participant_type": "remote", "user_id": "user123"},
///     {"role": "vendor", "participant_type": "remote", "user_id": "user456"},
///     {"role": "arbiter", "participant_type": "local_managed", "wallet_id": "wallet-uuid"}
///   ]
/// }
/// ```
///
/// # Response
/// - 201 Created: Session initialized
/// - 400 Bad Request: Invalid parameters
/// - 500 Internal Server Error: Database error
#[post("/multisig/init")]
pub async fn init_multisig_session(
    req: web::Json<InitSessionRequest>,
    coordinator: web::Data<DbMultisigCoordinator>,
) -> Result<HttpResponse, actix_web::Error> {
    // Parse escrow_id
    let escrow_id = Uuid::parse_str(&req.escrow_id).map_err(|_| {
        actix_web::error::ErrorBadRequest(ErrorResponse {
            error: "Invalid escrow_id".to_string(),
            details: "Must be a valid UUID".to_string(),
        })
    })?;

    // Convert DTO participants to ParticipantType
    let participants: Result<Vec<(String, ParticipantType)>, actix_web::Error> = req
        .participants
        .iter()
        .map(|p| {
            let ptype = match p.participant_type.as_str() {
                "local_managed" => {
                    let wallet_uuid = p
                        .wallet_id
                        .as_ref()
                        .and_then(|id| Uuid::parse_str(id).ok())
                        .ok_or_else(|| {
                            actix_web::error::ErrorBadRequest(ErrorResponse {
                                error: "Invalid wallet_id".to_string(),
                                details: "LocalManaged participant requires valid wallet_id UUID"
                                    .to_string(),
                            })
                        })?;
                    ParticipantType::LocalManaged {
                        wallet_id: wallet_uuid,
                    }
                }
                "remote" => {
                    let uid = p.user_id.clone().ok_or_else(|| {
                        actix_web::error::ErrorBadRequest(ErrorResponse {
                            error: "Missing user_id".to_string(),
                            details: "Remote participant requires user_id".to_string(),
                        })
                    })?;
                    ParticipantType::Remote { user_id: uid }
                }
                _ => {
                    return Err(actix_web::error::ErrorBadRequest(ErrorResponse {
                        error: "Invalid participant_type".to_string(),
                        details: format!("Unknown type: {}", p.participant_type),
                    }));
                }
            };
            Ok((p.role.clone(), ptype))
        })
        .collect();

    let participants = participants?;

    // Call coordinator
    coordinator
        .as_ref()
        .init_session(escrow_id, participants)
        .await
        .map_err(|e| match e {
            MultisigCoordinationError::StorageError(msg) => {
                actix_web::error::ErrorInternalServerError(ErrorResponse {
                    error: "Database error".to_string(),
                    details: msg,
                })
            }
            MultisigCoordinationError::InvalidMultisigData(msg) => {
                actix_web::error::ErrorBadRequest(ErrorResponse {
                    error: "Invalid data".to_string(),
                    details: msg,
                })
            }
            _ => actix_web::error::ErrorInternalServerError(ErrorResponse {
                error: "Coordination error".to_string(),
                details: format!("{:?}", e),
            }),
        })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "success": true,
        "message": "Multisig session initialized",
        "escrow_id": escrow_id.to_string(),
    })))
}

/// Submit multisig info (Round 1 or Round 2)
///
/// # Endpoint
/// POST /api/multisig/submit
///
/// # Request Body
/// ```json
/// {
///   "escrow_id": "uuid-here",
///   "user_id": "user123",
///   "multisig_info": "base64-encoded-blob",
///   "stage": "initialization"  // or "key_exchange"
/// }
/// ```
///
/// # Response
/// - 200 OK: Info submitted successfully
/// - 400 Bad Request: Invalid data or wrong stage
/// - 401 Unauthorized: User not participant
/// - 404 Not Found: Session not found
/// - 500 Internal Server Error: Database error
#[post("/multisig/submit")]
pub async fn submit_multisig_info(
    req: web::Json<SubmitInfoRequest>,
    coordinator: web::Data<DbMultisigCoordinator>,
) -> Result<HttpResponse, actix_web::Error> {
    // Parse escrow_id
    let escrow_id = Uuid::parse_str(&req.escrow_id).map_err(|_| {
        actix_web::error::ErrorBadRequest(ErrorResponse {
            error: "Invalid escrow_id".to_string(),
            details: "Must be a valid UUID".to_string(),
        })
    })?;

    // Parse stage
    let stage = match req.stage.as_str() {
        "initialization" => MultisigStage::Initialization,
        "key_exchange" => MultisigStage::KeyExchange,
        _ => {
            return Err(actix_web::error::ErrorBadRequest(ErrorResponse {
                error: "Invalid stage".to_string(),
                details: "Must be 'initialization' or 'key_exchange'".to_string(),
            }));
        }
    };

    // Call coordinator
    coordinator
        .as_ref()
        .submit_info(
            escrow_id,
            req.user_id.clone(),
            req.multisig_info.clone(),
            stage,
        )
        .await
        .map_err(|e| match e {
            MultisigCoordinationError::SessionNotFound(_) => {
                actix_web::error::ErrorNotFound(ErrorResponse {
                    error: "Session not found".to_string(),
                    details: format!("No session for escrow {}", escrow_id),
                })
            }
            MultisigCoordinationError::UnauthorizedParticipant(msg) => {
                actix_web::error::ErrorUnauthorized(ErrorResponse {
                    error: "Unauthorized".to_string(),
                    details: msg,
                })
            }
            MultisigCoordinationError::InvalidState { expected, actual } => {
                actix_web::error::ErrorBadRequest(ErrorResponse {
                    error: "Invalid state".to_string(),
                    details: format!("Expected: {}, Actual: {}", expected, actual),
                })
            }
            MultisigCoordinationError::InvalidMultisigData(msg) => {
                actix_web::error::ErrorBadRequest(ErrorResponse {
                    error: "Invalid multisig data".to_string(),
                    details: msg,
                })
            }
            MultisigCoordinationError::StorageError(msg) => {
                actix_web::error::ErrorInternalServerError(ErrorResponse {
                    error: "Database error".to_string(),
                    details: msg,
                })
            }
            _ => actix_web::error::ErrorInternalServerError(ErrorResponse {
                error: "Coordination error".to_string(),
                details: format!("{:?}", e),
            }),
        })?;

    // Get updated stage
    let current_stage = coordinator
        .as_ref()
        .check_progress(escrow_id)
        .await
        .map_err(|_| {
            actix_web::error::ErrorInternalServerError("Failed to check progress")
        })?;

    Ok(HttpResponse::Ok().json(SubmitInfoResponse {
        success: true,
        message: "Multisig info submitted successfully".to_string(),
        current_stage: format!("{:?}", current_stage),
    }))
}

/// Get peer multisig info for a participant
///
/// # Endpoint
/// GET /api/multisig/peer-info/{escrow_id}?user_id={user_id}
///
/// # Query Parameters
/// - `user_id`: ID of the requesting user
///
/// # Response
/// ```json
/// {
///   "peer_infos": ["blob1", "blob2"],
///   "count": 2,
///   "current_stage": "Round1Complete"
/// }
/// ```
///
/// # Response Codes
/// - 200 OK: Peer infos retrieved (may be empty if not all submitted)
/// - 400 Bad Request: Invalid parameters
/// - 401 Unauthorized: User not participant
/// - 404 Not Found: Session not found
#[get("/multisig/peer-info/{escrow_id}")]
pub async fn get_peer_info(
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
    coordinator: web::Data<DbMultisigCoordinator>,
) -> Result<HttpResponse, actix_web::Error> {
    // Parse escrow_id
    let escrow_id = Uuid::parse_str(&path.into_inner()).map_err(|_| {
        actix_web::error::ErrorBadRequest(ErrorResponse {
            error: "Invalid escrow_id".to_string(),
            details: "Must be a valid UUID".to_string(),
        })
    })?;

    // Get user_id from query
    let user_id = query.get("user_id").ok_or_else(|| {
        actix_web::error::ErrorBadRequest(ErrorResponse {
            error: "Missing user_id".to_string(),
            details: "Query parameter 'user_id' is required".to_string(),
        })
    })?;

    // Call coordinator
    let peer_infos = coordinator
        .as_ref()
        .get_peer_info(escrow_id, user_id.clone())
        .await
        .map_err(|e| match e {
            MultisigCoordinationError::SessionNotFound(_) => {
                actix_web::error::ErrorNotFound(ErrorResponse {
                    error: "Session not found".to_string(),
                    details: format!("No session for escrow {}", escrow_id),
                })
            }
            MultisigCoordinationError::UnauthorizedParticipant(msg) => {
                actix_web::error::ErrorUnauthorized(ErrorResponse {
                    error: "Unauthorized".to_string(),
                    details: msg,
                })
            }
            MultisigCoordinationError::StorageError(msg) => {
                actix_web::error::ErrorInternalServerError(ErrorResponse {
                    error: "Database error".to_string(),
                    details: msg,
                })
            }
            _ => actix_web::error::ErrorInternalServerError(ErrorResponse {
                error: "Coordination error".to_string(),
                details: format!("{:?}", e),
            }),
        })?;

    // Get current stage
    let current_stage = coordinator
        .as_ref()
        .check_progress(escrow_id)
        .await
        .map_err(|_| {
            actix_web::error::ErrorInternalServerError("Failed to check progress")
        })?;

    Ok(HttpResponse::Ok().json(PeerInfoResponse {
        count: peer_infos.len(),
        peer_infos,
        current_stage: format!("{:?}", current_stage),
    }))
}

/// Get multisig session status
///
/// # Endpoint
/// GET /api/multisig/status/{escrow_id}
///
/// # Response
/// ```json
/// {
///   "escrow_id": "uuid-here",
///   "stage": "Ready",
///   "multisig_address": "4xxx...",
///   "created_at": 1234567890
/// }
/// ```
///
/// # Response Codes
/// - 200 OK: Status retrieved
/// - 400 Bad Request: Invalid escrow_id
/// - 404 Not Found: Session not found
#[get("/multisig/status/{escrow_id}")]
pub async fn get_multisig_status(
    path: web::Path<String>,
    coordinator: web::Data<DbMultisigCoordinator>,
) -> Result<HttpResponse, actix_web::Error> {
    // Parse escrow_id
    let escrow_id = Uuid::parse_str(&path.into_inner()).map_err(|_| {
        actix_web::error::ErrorBadRequest(ErrorResponse {
            error: "Invalid escrow_id".to_string(),
            details: "Must be a valid UUID".to_string(),
        })
    })?;

    // Get full session state
    let session = coordinator
        .as_ref()
        .get_session_state(escrow_id)
        .await
        .map_err(|e| match e {
            MultisigCoordinationError::SessionNotFound(_) => {
                actix_web::error::ErrorNotFound(ErrorResponse {
                    error: "Session not found".to_string(),
                    details: format!("No session for escrow {}", escrow_id),
                })
            }
            MultisigCoordinationError::StorageError(msg) => {
                actix_web::error::ErrorInternalServerError(ErrorResponse {
                    error: "Database error".to_string(),
                    details: msg,
                })
            }
            _ => actix_web::error::ErrorInternalServerError(ErrorResponse {
                error: "Coordination error".to_string(),
                details: format!("{:?}", e),
            }),
        })?;

    Ok(HttpResponse::Ok().json(StatusResponse {
        escrow_id: escrow_id.to_string(),
        stage: format!("{:?}", session.stage),
        multisig_address: session.multisig_address,
        created_at: session.created_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_participant_dto_serialization() {
        let dto = ParticipantDto {
            role: "buyer".to_string(),
            participant_type: "remote".to_string(),
            wallet_id: None,
            user_id: Some("user123".to_string()),
        };

        let json = serde_json::to_string(&dto).unwrap();
        let deserialized: ParticipantDto = serde_json::from_str(&json).unwrap();

        assert_eq!(dto.role, deserialized.role);
        assert_eq!(dto.participant_type, deserialized.participant_type);
        assert_eq!(dto.user_id, deserialized.user_id);
    }

    #[test]
    fn test_error_response_serialization() {
        let err = ErrorResponse {
            error: "Test error".to_string(),
            details: "Test details".to_string(),
        };

        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("Test error"));
        assert!(json.contains("Test details"));
    }
}
