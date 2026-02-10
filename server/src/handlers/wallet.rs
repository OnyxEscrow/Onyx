use crate::config::get_configured_network;
use crate::crypto::address_validation::validate_address_for_network;
use crate::db::DbPool;
use crate::models::wallet::{NewWallet, Wallet};
use actix_web::{get, post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

/// Request body for wallet registration
#[derive(Serialize, Deserialize, Clone)]
pub struct WalletRegistrationRequest {
    /// Monero address (58 characters)
    pub address: String,
    /// Hex-encoded public view key (64 chars) - optional for client-generated wallets
    pub view_key_pub: Option<String>,
    /// Hex-encoded public spend key (64 chars) - optional for client-generated wallets
    pub spend_key_pub: Option<String>,
    /// SHA256 hash of address for verification (optional, calculated server-side if not provided)
    pub address_hash: Option<String>,
    /// Optional proof of ownership
    pub signature: Option<String>,
}

/// Response for successful wallet registration
#[derive(Serialize)]
pub struct WalletRegistrationResponse {
    pub status: String,
    pub address: String,
    pub message: String,
}

/// Response for wallet status check
#[derive(Serialize)]
pub struct WalletStatusResponse {
    pub has_wallet: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_count: Option<usize>,
}

/// Check if user has a registered wallet
///
/// This endpoint is used by the checkout flow to determine whether
/// the user needs to generate a new wallet or can use an existing one.
///
/// # Response
/// - 200 OK: Returns wallet status (has_wallet, address if exists)
/// - 401 Unauthorized: User not authenticated
/// - 500 Internal Server Error: Database error
#[get("/wallet/status")]
pub async fn get_wallet_status(
    session: actix_session::Session,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    // Authenticate user from session
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required",
                "details": "Please log in to check wallet status"
            })));
        }
    };

    // Query for user's wallets
    let wallets = web::block(move || {
        let mut conn = pool.get().map_err(|e| format!("DB connection: {}", e))?;
        Wallet::find_by_user_id(&mut conn, user_id.clone())
            .map_err(|e| format!("Query wallets: {}", e))
    })
    .await
    .map_err(|e| {
        eprintln!("Blocking error: {}", e);
        actix_web::error::ErrorInternalServerError("Internal server error")
    })
    .and_then(|result| {
        result.map_err(|e| {
            eprintln!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })
    })?;

    if wallets.is_empty() {
        Ok(HttpResponse::Ok().json(WalletStatusResponse {
            has_wallet: false,
            address: None,
            wallet_count: Some(0),
        }))
    } else {
        // Return first wallet address
        let first_wallet = &wallets[0];
        Ok(HttpResponse::Ok().json(WalletStatusResponse {
            has_wallet: true,
            address: Some(first_wallet.address.clone()),
            wallet_count: Some(wallets.len()),
        }))
    }
}

/// Register a client-side generated wallet
///
/// This handler receives a wallet registration request from the CLI
/// (which has already generated the seed and keys locally, maintaining
/// zero-trust architecture).
///
/// # Request Body
/// - address: Monero address (58 chars)
/// - view_key_pub: Public view key
/// - spend_key_pub: Public spend key
/// - address_hash: SHA256(address)
///
/// # Response
/// - 201 Created: Wallet registered successfully
/// - 400 Bad Request: Invalid address format
/// - 409 Conflict: Wallet already registered
/// - 500 Internal Server Error: Database error
#[post("/wallet/register")]
pub async fn register_wallet(
    req: web::Json<WalletRegistrationRequest>,
    session: actix_session::Session,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    // Authenticate user from session
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required",
                "details": "Please log in to register a wallet"
            })));
        }
    };

    info!("Registering wallet for user {}: {}", user_id, req.address);

    // Validate Monero address with full checksum verification
    if let Err(e) = validate_monero_address(&req.address) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid Monero address",
            "details": e
        })));
    }

    // Validate public key format if provided (should be 64 hex chars = 32 bytes)
    if let Some(ref view_key) = req.view_key_pub {
        if !is_valid_hex_key(view_key) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid view key format",
                "details": "View key must be 64 hexadecimal characters"
            })));
        }
    }

    if let Some(ref spend_key) = req.spend_key_pub {
        if !is_valid_hex_key(spend_key) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid spend key format",
                "details": "Spend key must be 64 hexadecimal characters"
            })));
        }
    }

    // Calculate address hash if not provided
    let address_hash = match &req.address_hash {
        Some(hash) if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) => {
            hash.clone()
        }
        Some(hash) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid address hash",
                "details": format!("Hash must be 64 hexadecimal characters (SHA256), got {} chars", hash.len())
            })));
        }
        None => {
            // Calculate SHA256 hash of address
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(req.address.as_bytes());
            format!("{:x}", hasher.finalize())
        }
    };

    // Check if wallet address already exists
    let address = req.address.clone();
    let address_clone = address.clone();
    let pool_clone = pool.clone();

    let address_exists = web::block(move || {
        let mut conn = pool_clone
            .get()
            .map_err(|e| format!("DB connection: {}", e))?;
        Wallet::address_exists(&mut conn, &address_clone)
            .map_err(|e| format!("Check address: {}", e))
    })
    .await
    .map_err(|e| {
        eprintln!("Blocking error: {}", e);
        actix_web::error::ErrorInternalServerError("Internal server error")
    })
    .and_then(|result| {
        result.map_err(|e| {
            eprintln!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })
    })?;

    if address_exists {
        return Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "Wallet already registered",
            "details": "This address is already registered in the system"
        })));
    }

    // Create and insert wallet
    let wallet_id = Uuid::new_v4().to_string();
    let new_wallet = NewWallet {
        id: wallet_id.clone(),
        user_id: user_id.clone(),
        address: address.clone(),
        address_hash: address_hash.clone(),
        spend_key_pub: req.spend_key_pub.clone().or(Some("".to_string())),
        view_key_pub: req.view_key_pub.clone().or(Some("".to_string())),
        signature: req.signature.clone(),
        daily_limit_atomic: None,
        monthly_limit_atomic: None,
        last_withdrawal_date: None,
        withdrawn_today_atomic: None,
    };

    let _wallet_result = web::block(move || {
        let mut conn = pool.get().map_err(|e| format!("DB connection: {}", e))?;
        Wallet::create(&mut conn, new_wallet).map_err(|e| format!("Create wallet: {}", e))
    })
    .await
    .map_err(|e| {
        eprintln!("Blocking error: {}", e);
        actix_web::error::ErrorInternalServerError("Internal server error")
    })
    .and_then(|result| {
        result.map_err(|e| {
            eprintln!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to register wallet")
        })
    })?;

    info!(
        "Wallet registered successfully: {} (id: {})",
        address, wallet_id
    );

    Ok(HttpResponse::Created().json(WalletRegistrationResponse {
        status: "registered".to_string(),
        address,
        message: "Wallet registered successfully. You can now create escrows.".to_string(),
    }))
}

/// Validate Monero address with full cryptographic checksum verification
///
/// Uses the production-grade `validate_address_for_network` function which:
/// - Decodes Base58-Monero encoding
/// - Verifies Keccak256 checksum
/// - Ensures address matches configured network (mainnet/stagenet/testnet)
///
/// CRITICAL: This prevents loss of funds from invalid or wrong-network addresses
fn validate_monero_address(address: &str) -> Result<(), String> {
    let network =
        get_configured_network().map_err(|e| format!("Network configuration error: {}", e))?;

    validate_address_for_network(address, network).map_err(|e| format!("{}", e))
}

/// Validate hex public key format (should be 64 chars = 32 bytes)
fn is_valid_hex_key(key: &str) -> bool {
    key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Address validation tests are now in crypto::address_validation::tests
    // since we use the central validate_monero_address function with full checksum verification

    #[test]
    fn test_is_valid_hex_key() {
        // Valid 64-char hex string
        let valid_key = "deadbeefcafebabe0123456789abcdef".repeat(2);
        assert!(is_valid_hex_key(&valid_key));

        // Too short
        assert!(!is_valid_hex_key("deadbeef"));

        // Too long
        let long_key = "deadbeef".repeat(10);
        assert!(!is_valid_hex_key(&long_key));

        // Invalid hex characters
        assert!(!is_valid_hex_key(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }
}
