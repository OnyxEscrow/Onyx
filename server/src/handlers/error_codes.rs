//! NEXUS Error Codes System
//!
//! Provides standardized error codes and responses for the frontend error handling system.
//! Each error code maps to user-friendly messages and actionable recovery flows.
//!
//! # Error Code Categories
//! - SIGN-xxx: Signing/transaction errors
//! - WASM-xxx: WebAssembly module errors
//! - NET-xxx: Network/connectivity errors
//! - MSIG-xxx: Multisig coordination errors
//! - ESC-xxx: Escrow state errors
//! - AUTH-xxx: Authentication errors

use actix_web::HttpResponse;
use serde::{Deserialize, Serialize};

/// Error response with standardized error code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Operation success (always false for errors)
    pub success: bool,
    /// NEXUS error code (e.g., "SIGN-001")
    pub error_code: String,
    /// Human-readable error message
    pub error: String,
    /// Whether the error can be recovered from (client can retry)
    pub recoverable: bool,
    /// Optional additional details for debugging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    /// Create a new error response
    pub fn new(code: &str, message: &str, recoverable: bool) -> Self {
        Self {
            success: false,
            error_code: code.to_string(),
            error: message.to_string(),
            recoverable,
            details: None,
        }
    }

    /// Add optional details
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }
}

// =============================================================================
// SIGNING ERRORS (SIGN-xxx)
// =============================================================================

/// SIGN-001: Wallet not synchronized
pub fn wallet_not_synced() -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(ErrorResponse::new(
        "SIGN-001",
        "Wallet needs synchronization. Please wait and retry.",
        true,
    ))
}

/// SIGN-002: Session expired
pub fn session_expired() -> HttpResponse {
    HttpResponse::Unauthorized().json(ErrorResponse::new(
        "SIGN-002",
        "Session expired. Please log in again.",
        true,
    ))
}

/// SIGN-003: Missing private key
pub fn missing_private_key() -> HttpResponse {
    HttpResponse::BadRequest().json(ErrorResponse::new(
        "SIGN-003",
        "Private key not found. Restore your wallet with your seed phrase.",
        true,
    ))
}

/// SIGN-004: Invalid signature
pub fn invalid_signature(details: Option<&str>) -> HttpResponse {
    let mut response = ErrorResponse::new(
        "SIGN-004",
        "Generated signature is invalid. Data may be corrupted.",
        true,
    );
    if let Some(d) = details {
        response = response.with_details(d);
    }
    HttpResponse::BadRequest().json(response)
}

/// SIGN-005: Already signed
pub fn already_signed() -> HttpResponse {
    HttpResponse::Conflict().json(ErrorResponse::new(
        "SIGN-005",
        "You have already signed this transaction. Waiting for other participants.",
        false,
    ))
}

/// SIGN-006: Insufficient funds
pub fn insufficient_funds() -> HttpResponse {
    HttpResponse::BadRequest().json(ErrorResponse::new(
        "SIGN-006",
        "Insufficient balance in escrow wallet.",
        false,
    ))
}

/// SIGN-007: Key image already used (double-spend)
pub fn key_image_used() -> HttpResponse {
    HttpResponse::Conflict().json(ErrorResponse::new(
        "SIGN-007",
        "This output has already been spent. Double-spend detected.",
        false,
    ))
}

// =============================================================================
// NETWORK ERRORS (NET-xxx)
// =============================================================================

/// NET-001: Connection lost
pub fn connection_lost() -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(ErrorResponse::new(
        "NET-001",
        "Connection lost. Check your internet connection.",
        true,
    ))
}

/// NET-002: Server unreachable
pub fn server_unreachable() -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(ErrorResponse::new(
        "NET-002",
        "Server is not responding. Please try again later.",
        true,
    ))
}

/// NET-003: Network timeout
pub fn network_timeout() -> HttpResponse {
    HttpResponse::GatewayTimeout().json(ErrorResponse::new(
        "NET-003",
        "Request timed out. Tor network may be slow.",
        true,
    ))
}

// =============================================================================
// MULTISIG ERRORS (MSIG-xxx)
// =============================================================================

/// MSIG-001: Waiting for participants
pub fn waiting_for_participants(current: u8, required: u8) -> HttpResponse {
    HttpResponse::Accepted().json(ErrorResponse::new(
        "MSIG-001",
        &format!("Waiting for participants ({}/{})", current, required),
        true,
    ))
}

/// MSIG-002: Multisig exchange failed
pub fn multisig_exchange_failed(details: Option<&str>) -> HttpResponse {
    let mut response = ErrorResponse::new(
        "MSIG-002",
        "Multisig information exchange failed. Please retry coordination.",
        true,
    );
    if let Some(d) = details {
        response = response.with_details(d);
    }
    HttpResponse::BadRequest().json(response)
}

/// MSIG-003: Invalid multisig address
pub fn invalid_multisig_address() -> HttpResponse {
    HttpResponse::BadRequest().json(ErrorResponse::new(
        "MSIG-003",
        "Generated multisig address is invalid. Restart the process.",
        true,
    ))
}

/// MSIG-004: Sync required
pub fn multisig_sync_required() -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(ErrorResponse::new(
        "MSIG-004",
        "Multisig wallets need resynchronization.",
        true,
    ))
}

/// MSIG-005: Invalid address format
pub fn invalid_address_format() -> HttpResponse {
    HttpResponse::BadRequest().json(ErrorResponse::new(
        "MSIG-005",
        "Invalid Monero address format. Must be 95 characters starting with 4/8 (mainnet), 5/7 (stagenet), or 9/A/B (testnet).",
        true,
    ))
}

/// MSIG-006: Invalid key format
pub fn invalid_key_format() -> HttpResponse {
    HttpResponse::BadRequest().json(ErrorResponse::new(
        "MSIG-006",
        "Invalid key format. Must be 64 hexadecimal characters.",
        true,
    ))
}

// =============================================================================
// ESCROW ERRORS (ESC-xxx)
// =============================================================================

/// ESC-001: Escrow not found
pub fn escrow_not_found(escrow_id: &str) -> HttpResponse {
    HttpResponse::NotFound().json(
        ErrorResponse::new(
            "ESC-001",
            "Escrow not found or has been deleted.",
            false,
        )
        .with_details(&format!("escrow_id: {}", escrow_id)),
    )
}

/// ESC-002: Unauthorized action
pub fn unauthorized_escrow_action(action: &str, role: &str) -> HttpResponse {
    HttpResponse::Forbidden().json(
        ErrorResponse::new(
            "ESC-002",
            "You are not authorized to perform this action.",
            false,
        )
        .with_details(&format!("action: {}, role: {}", action, role)),
    )
}

/// ESC-003: Invalid escrow state
pub fn invalid_escrow_state(current_state: &str, required_state: &str) -> HttpResponse {
    HttpResponse::Conflict().json(
        ErrorResponse::new(
            "ESC-003",
            "Escrow is not in the correct state for this action.",
            true,
        )
        .with_details(&format!(
            "current: {}, required: {}",
            current_state, required_state
        )),
    )
}

/// ESC-004: Escrow expired
pub fn escrow_expired() -> HttpResponse {
    HttpResponse::Gone().json(ErrorResponse::new(
        "ESC-004",
        "This escrow has expired. Funds may be reclaimable.",
        true,
    ))
}

// =============================================================================
// AUTHENTICATION ERRORS (AUTH-xxx)
// =============================================================================

/// AUTH-001: Not authenticated
pub fn not_authenticated() -> HttpResponse {
    HttpResponse::Unauthorized().json(ErrorResponse::new(
        "AUTH-001",
        "Authentication required. Please log in.",
        true,
    ))
}

/// AUTH-002: Wrong password
pub fn wrong_password() -> HttpResponse {
    HttpResponse::Unauthorized().json(ErrorResponse::new(
        "AUTH-002",
        "Incorrect password.",
        true,
    ))
}

/// AUTH-003: Account locked
pub fn account_locked(minutes: u32) -> HttpResponse {
    HttpResponse::TooManyRequests().json(
        ErrorResponse::new(
            "AUTH-003",
            &format!(
                "Too many failed attempts. Try again in {} minutes.",
                minutes
            ),
            true,
        ),
    )
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Convert a generic error message to an error response with inferred code
pub fn from_error_message(message: &str) -> HttpResponse {
    let message_lower = message.to_lowercase();

    // Infer error code from message content
    if message_lower.contains("wallet") && message_lower.contains("sync") {
        return wallet_not_synced();
    }
    if message_lower.contains("session") || message_lower.contains("expired") {
        return session_expired();
    }
    if message_lower.contains("private key") || message_lower.contains("spend key") {
        return missing_private_key();
    }
    if message_lower.contains("signature") {
        return invalid_signature(Some(message));
    }
    if message_lower.contains("insufficient") || message_lower.contains("balance") {
        return insufficient_funds();
    }
    if message_lower.contains("key image") {
        return key_image_used();
    }
    if message_lower.contains("timeout") {
        return network_timeout();
    }
    if message_lower.contains("unauthorized") || message_lower.contains("permission") {
        return not_authenticated();
    }
    if message_lower.contains("not found") {
        return HttpResponse::NotFound().json(ErrorResponse::new(
            "ESC-001",
            message,
            false,
        ));
    }

    // Default: generic internal error
    HttpResponse::InternalServerError().json(ErrorResponse::new(
        "UNKNOWN",
        message,
        true,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_creation() {
        let response = ErrorResponse::new("TEST-001", "Test error", true);
        assert_eq!(response.error_code, "TEST-001");
        assert_eq!(response.error, "Test error");
        assert!(response.recoverable);
        assert!(!response.success);
    }

    #[test]
    fn test_error_response_with_details() {
        let response = ErrorResponse::new("TEST-002", "Error", false)
            .with_details("Extra info");
        assert_eq!(response.details, Some("Extra info".to_string()));
    }
}
