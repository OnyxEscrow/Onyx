use actix_web::{post, web, HttpResponse};
use monero_marketplace_common::MONERO_RPC_URL;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AddressValidationRequest {
    pub address: String,
}

#[derive(Serialize, Deserialize)]
pub struct AddressValidationResponse {
    pub is_valid: bool,
    pub message: String,
    pub network: Option<String>,
}

/// Validate a Monero address using the actual RPC
#[post("/api/monero/validate-address")]
pub async fn validate_address(
    req: web::Json<AddressValidationRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let address = &req.address;

    // Basic format check first
    if !is_valid_address_format(address) {
        return Ok(HttpResponse::Ok().json(AddressValidationResponse {
            is_valid: false,
            message: "Invalid Monero address format (must be 58 or 95 chars, base58)".to_string(),
            network: None,
        }));
    }

    // Call RPC to validate
    match validate_with_rpc(address).await {
        Ok((is_valid, network)) => Ok(HttpResponse::Ok().json(AddressValidationResponse {
            is_valid,
            message: if is_valid {
                format!(
                    "Valid Monero address ({})",
                    network.clone().unwrap_or("unknown".to_string())
                )
            } else {
                "Address failed RPC validation".to_string()
            },
            network,
        })),
        Err(e) => {
            tracing::warn!("RPC validation error: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "RPC validation unavailable",
                "message": "Could not reach Monero RPC for validation"
            })))
        }
    }
}

/// Basic address format validation (local check)
fn is_valid_address_format(address: &str) -> bool {
    if address.len() != 58 && address.len() != 95 {
        return false;
    }

    address
        .chars()
        .all(|c| matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'))
}

/// Validate address using actual Monero RPC
async fn validate_with_rpc(address: &str) -> Result<(bool, Option<String>), String> {
    use reqwest;
    use serde_json::{json, Value};

    let client = reqwest::Client::new();

    let payload = json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "validate_address",
        "params": {
            "address": address,
            "any_net_type": false
        }
    });

    match client
        .post(format!("{MONERO_RPC_URL}/json_rpc"))
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(body) => {
                if let Some(result) = body.get("result") {
                    let is_valid = result
                        .get("valid")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let network = result
                        .get("nettype")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    Ok((is_valid, network))
                } else if let Some(error) = body.get("error") {
                    Err(format!("RPC error: {error:?}"))
                } else {
                    Err("Invalid RPC response format".to_string())
                }
            }
            Err(e) => Err(format!("JSON parse error: {e}")),
        },
        Err(e) => Err(format!("HTTP error: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_address_format() {
        assert!(is_valid_address_format(
            "48y3eEkwZuHJKDzz3gF7jzHWU8m68yEBGcVrXyKz8H4jkXvMrv3V8xgmKzs6zNHKRZLKfK7ykZfUe3tQJbNMU8h3iR7hJ2D"
        ));
    }

    #[test]
    fn test_invalid_address_length() {
        assert!(!is_valid_address_format("short"));
        assert!(!is_valid_address_format("48y3eEkwZuHJKDzz3gF7jzHWU8m68yEBGcVrXyKz8H4jkXvMrv3V8xgmKzs6zNHKRZLKfK7ykZfUe3tQJbNMU8h3iR7hJ2D00"));
    }

    #[test]
    fn test_invalid_characters() {
        assert!(!is_valid_address_format(
            "48y3eEkwZuHJKDzz3gF7jzHWU8m68yEBGcVrXyKz8H4jkXvMrv3V8xgmKzs6zNHKRZLKfK7ykZfUe3tQJbNMU8h3iR7hJ2O"
        ));
    }
}
