//! WASM Multisig Coordination Client
//!
//! Provides browser-side coordination for 2-of-3 multisig setup without
//! exposing private keys to the server. Implements Haveno-inspired pure
//! coordinator pattern.
//!
//! **CRITICAL SECURITY:**
//! - Private keys NEVER leave browser memory
//! - Server only receives opaque multisig blobs
//! - All cryptographic operations happen client-side

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

/// API base URL (configured at runtime)
const API_BASE: &str = "/api/multisig";

// ============================================================================
// REQUEST/RESPONSE TYPES (must match server/src/handlers/multisig.rs)
// ============================================================================

/// Participant in multisig session
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParticipantDto {
    pub role: String,
    pub participant_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// Initialize multisig session request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitSessionRequest {
    pub escrow_id: String,
    pub participants: Vec<ParticipantDto>,
}

/// Submit multisig info request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitInfoRequest {
    pub escrow_id: String,
    pub user_id: String,
    pub multisig_info: String,
    pub stage: String,
}

/// API response for submission
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitInfoResponse {
    pub success: bool,
    pub message: String,
    pub current_stage: String,
}

/// API response for peer info
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfoResponse {
    pub peer_infos: Vec<String>,
    pub count: usize,
    pub current_stage: String,
}

/// API response for status
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    pub escrow_id: String,
    pub stage: String,
    pub multisig_address: Option<String>,
    pub created_at: i64,
}

/// Error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: String,
}

// ============================================================================
// WASM EXPORTS - JavaScript callable functions
// ============================================================================

/// Initialize a new multisig coordination session
///
/// Called by the escrow initiator (typically the buyer or platform).
///
/// # Parameters
/// - `escrow_id`: Unique escrow identifier (UUID)
/// - `participants_json`: JSON array of ParticipantDto
///
/// # Returns
/// - Success: `{success: true, message: "...", escrow_id: "..."}`
/// - Error: Throws JS exception with error details
///
/// # Security
/// - This only creates coordination metadata
/// - No wallet keys are transmitted
#[wasm_bindgen]
pub async fn init_multisig_session(
    escrow_id: String,
    participants_json: String,
) -> Result<JsValue, JsValue> {
    // Parse participants
    let participants: Vec<ParticipantDto> = serde_json::from_str(&participants_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid participants JSON: {}", e)))?;

    let request = InitSessionRequest {
        escrow_id: escrow_id.clone(),
        participants,
    };

    // Call server API
    let response = fetch_post(&format!("{}/init", API_BASE), &request).await?;

    Ok(response)
}

/// Submit multisig info (Round 1 or Round 2)
///
/// Called by each participant after running `prepare_multisig()` or
/// `make_multisig()` locally in their wallet.
///
/// # Parameters
/// - `escrow_id`: Escrow session identifier
/// - `user_id`: Current user's identifier
/// - `multisig_info`: Base64-encoded multisig blob from wallet RPC
/// - `stage`: "initialization" or "key_exchange"
///
/// # Returns
/// - SubmitInfoResponse with current stage
///
/// # Security
/// - `multisig_info` is opaque to server (encrypted blob)
/// - Server cannot extract private keys from this data
#[wasm_bindgen]
pub async fn submit_multisig_info(
    escrow_id: String,
    user_id: String,
    multisig_info: String,
    stage: String,
) -> Result<JsValue, JsValue> {
    let request = SubmitInfoRequest {
        escrow_id,
        user_id,
        multisig_info,
        stage,
    };

    let response = fetch_post(&format!("{}/submit", API_BASE), &request).await?;

    Ok(response)
}

/// Get peer multisig info
///
/// Called by a participant to retrieve multisig blobs from other parties.
/// Used after submitting own info to proceed to next round.
///
/// # Parameters
/// - `escrow_id`: Escrow session identifier
/// - `user_id`: Current user's identifier
///
/// # Returns
/// - PeerInfoResponse with array of peer multisig blobs
///
/// # Security
/// - Server acts as relay only
/// - Each peer's blob is opaque (no key extraction possible)
#[wasm_bindgen]
pub async fn get_peer_multisig_info(
    escrow_id: String,
    user_id: String,
) -> Result<JsValue, JsValue> {
    let url = format!("{}/peer-info/{}?user_id={}", API_BASE, escrow_id, user_id);

    let response = fetch_get(&url).await?;

    Ok(response)
}

/// Get multisig session status
///
/// # Parameters
/// - `escrow_id`: Escrow session identifier
///
/// # Returns
/// - StatusResponse with current stage and multisig address (if Ready)
#[wasm_bindgen]
pub async fn get_multisig_status(escrow_id: String) -> Result<JsValue, JsValue> {
    let url = format!("{}/status/{}", API_BASE, escrow_id);

    let response = fetch_get(&url).await?;

    Ok(response)
}

// ============================================================================
// HTTP CLIENT HELPERS
// ============================================================================

/// Fetch helper for POST requests
async fn fetch_post<T: Serialize>(url: &str, body: &T) -> Result<JsValue, JsValue> {
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    // Serialize body
    let body_json = serde_json::to_string(body)
        .map_err(|e| JsValue::from_str(&format!("JSON serialization error: {}", e)))?;

    // Create request
    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.body(Some(&JsValue::from_str(&body_json)));

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| JsValue::from_str(&format!("Request creation failed: {:?}", e)))?;

    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| JsValue::from_str(&format!("Header set failed: {:?}", e)))?;

    // Send request
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window object"))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| JsValue::from_str(&format!("Fetch failed: {:?}", e)))?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| JsValue::from_str("Response cast failed"))?;

    // Check status
    if !resp.ok() {
        let status = resp.status();
        let error_text = JsFuture::from(
            resp.text()
                .unwrap_or_else(|_| js_sys::Promise::resolve(&JsValue::from_str("Unknown error"))),
        )
        .await
        .unwrap_or_else(|_| JsValue::from_str("Unknown error"));

        return Err(JsValue::from_str(&format!(
            "HTTP {}: {}",
            status,
            error_text.as_string().unwrap_or_default()
        )));
    }

    // Parse JSON response
    let json = JsFuture::from(
        resp.json()
            .map_err(|e| JsValue::from_str(&format!("JSON parse failed: {:?}", e)))?,
    )
    .await?;

    Ok(json)
}

/// Fetch helper for GET requests
async fn fetch_get(url: &str) -> Result<JsValue, JsValue> {
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| JsValue::from_str(&format!("Request creation failed: {:?}", e)))?;

    let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window object"))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| JsValue::from_str(&format!("Fetch failed: {:?}", e)))?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| JsValue::from_str("Response cast failed"))?;

    if !resp.ok() {
        let status = resp.status();
        let error_text = JsFuture::from(
            resp.text()
                .unwrap_or_else(|_| js_sys::Promise::resolve(&JsValue::from_str("Unknown error"))),
        )
        .await
        .unwrap_or_else(|_| JsValue::from_str("Unknown error"));

        return Err(JsValue::from_str(&format!(
            "HTTP {}: {}",
            status,
            error_text.as_string().unwrap_or_default()
        )));
    }

    let json = JsFuture::from(
        resp.json()
            .map_err(|e| JsValue::from_str(&format!("JSON parse failed: {:?}", e)))?,
    )
    .await?;

    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_participant_dto_serialization() {
        let participant = ParticipantDto {
            role: "buyer".to_string(),
            participant_type: "remote".to_string(),
            wallet_id: None,
            user_id: Some("user123".to_string()),
        };

        let json = serde_json::to_string(&participant).unwrap();
        let deserialized: ParticipantDto = serde_json::from_str(&json).unwrap();

        assert_eq!(participant.role, deserialized.role);
        assert_eq!(participant.user_id, deserialized.user_id);
    }

    #[test]
    fn test_init_session_request_serialization() {
        let request = InitSessionRequest {
            escrow_id: "test-escrow-id".to_string(),
            participants: vec![
                ParticipantDto {
                    role: "buyer".to_string(),
                    participant_type: "remote".to_string(),
                    wallet_id: None,
                    user_id: Some("buyer1".to_string()),
                },
                ParticipantDto {
                    role: "vendor".to_string(),
                    participant_type: "remote".to_string(),
                    wallet_id: None,
                    user_id: Some("vendor1".to_string()),
                },
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-escrow-id"));
        assert!(json.contains("buyer"));
        assert!(json.contains("vendor"));
    }
}
