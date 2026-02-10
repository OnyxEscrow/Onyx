//! API Key management handlers for B2B EaaS
//!
//! Provides endpoints for:
//! - Creating new API keys
//! - Listing user's API keys
//! - Revoking API keys
//! - Viewing key statistics
//!
//! All endpoints require session authentication (web UI users)
//! or admin role for tier upgrades.

use actix_session::Session;
use actix_web::{delete, get, post, put, web, HttpMessage, HttpRequest, HttpResponse};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use tracing::info;
use validator::Validate;

use crate::db::DbPool;
use crate::error::ApiError;
use crate::middleware::csrf::validate_csrf_token;
use crate::models::api_key::{ApiKey, ApiKeyInfo, ApiKeyTier};

/// Request to create a new API key
#[derive(Debug, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    /// Human-readable name for the key
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    /// Optional expiration date (ISO 8601 format: YYYY-MM-DD HH:MM:SS)
    pub expires_at: Option<String>,
    /// Optional metadata (JSON string)
    pub metadata: Option<String>,
    /// CSRF token (REQUIRED for all requests)
    pub csrf_token: String,
}

/// Response for listing API keys
#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    pub keys: Vec<ApiKeyInfo>,
    pub total: usize,
}

/// POST /api/api-keys - Create a new API key
///
/// Requires session authentication.
/// Returns the raw API key only once at creation time.
#[post("/api-keys")]
pub async fn create_api_key(
    pool: web::Data<DbPool>,
    session: Session,
    req: web::Json<CreateApiKeyRequest>,
) -> Result<HttpResponse, ApiError> {
    // Require authentication
    let user_id = session
        .get::<String>("user_id")
        .context("Session read error")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Authentication required".to_string()))?;

    // Validate CSRF token (REQUIRED for all requests)
    if !validate_csrf_token(&session, &req.csrf_token) {
        return Err(ApiError::Forbidden("Invalid CSRF token".to_string()));
    }

    // Validate input
    if let Err(e) = req.0.validate() {
        return Err(ApiError::BadRequest(format!("Validation error: {}", e)));
    }

    // Validate expiration date format if provided
    if let Some(ref expires) = req.expires_at {
        if chrono::NaiveDateTime::parse_from_str(expires, "%Y-%m-%d %H:%M:%S").is_err() {
            return Err(ApiError::BadRequest(
                "Invalid expiration date format. Use YYYY-MM-DD HH:MM:SS".to_string(),
            ));
        }
    }

    // Get database connection
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Check user's existing key count (limit to 10 per user for free tier)
    let user_id_for_count = user_id.clone();
    let existing_keys = web::block(move || ApiKey::list_by_user(&mut conn, &user_id_for_count))
        .await
        .context("Database query failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if existing_keys.len() >= 10 {
        return Err(ApiError::BadRequest(
            "Maximum 10 API keys per user. Please revoke an existing key first.".to_string(),
        ));
    }

    // Create the API key
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let name = req.name.clone();
    let expires_at = req.expires_at.clone();
    let metadata = req.metadata.clone();
    let user_id_for_create = user_id.clone();

    let creation_response = web::block(move || {
        ApiKey::create(
            &mut conn,
            &user_id_for_create,
            &name,
            ApiKeyTier::Free, // New keys always start as Free tier
            expires_at,
            metadata,
        )
    })
    .await
    .context("Database operation failed")
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    info!(
        user_id = %user_id,
        key_id = %creation_response.id,
        key_prefix = %creation_response.key_prefix,
        "API key created"
    );

    // Return the raw key (only time it will be shown)
    Ok(HttpResponse::Created().json(serde_json::json!({
        "message": "API key created successfully. Save this key - it won't be shown again!",
        "key": creation_response
    })))
}

/// GET /api/api-keys - List all API keys for the authenticated user
#[get("/api-keys")]
pub async fn list_api_keys(
    pool: web::Data<DbPool>,
    session: Session,
) -> Result<HttpResponse, ApiError> {
    // Require authentication
    let user_id = session
        .get::<String>("user_id")
        .context("Session read error")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Authentication required".to_string()))?;

    // Get database connection
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let keys = web::block(move || ApiKey::list_by_user(&mut conn, &user_id))
        .await
        .context("Database query failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let key_infos: Vec<ApiKeyInfo> = keys.into_iter().map(ApiKeyInfo::from).collect();
    let total = key_infos.len();

    Ok(HttpResponse::Ok().json(ListApiKeysResponse {
        keys: key_infos,
        total,
    }))
}

/// GET /api/api-keys/{id} - Get details of a specific API key
#[get("/api-keys/{id}")]
pub async fn get_api_key(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let key_id = path.into_inner();

    // Require authentication
    let user_id = session
        .get::<String>("user_id")
        .context("Session read error")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Authentication required".to_string()))?;

    // Get database connection
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let key_id_clone = key_id.clone();
    let key = web::block(move || ApiKey::find_by_id(&mut conn, &key_id_clone))
        .await
        .context("Database query failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    match key {
        Some(k) if k.user_id == user_id => Ok(HttpResponse::Ok().json(ApiKeyInfo::from(k))),
        Some(_) => Err(ApiError::Forbidden(
            "You don't have permission to view this key".to_string(),
        )),
        None => Err(ApiError::BadRequest("API key not found".to_string())),
    }
}

/// DELETE /api/api-keys/{id} - Revoke (deactivate) an API key
#[delete("/api-keys/{id}")]
pub async fn revoke_api_key(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let key_id = path.into_inner();

    // Require authentication
    let user_id = session
        .get::<String>("user_id")
        .context("Session read error")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Authentication required".to_string()))?;

    // Get database connection
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let key_id_clone = key_id.clone();
    let user_id_clone = user_id.clone();
    let revoked = web::block(move || ApiKey::deactivate(&mut conn, &key_id_clone, &user_id_clone))
        .await
        .context("Database operation failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if revoked {
        info!(
            user_id = %user_id,
            key_id = %key_id,
            "API key revoked"
        );
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "API key revoked successfully",
            "key_id": key_id
        })))
    } else {
        Err(ApiError::BadRequest(
            "API key not found or already revoked".to_string(),
        ))
    }
}

/// DELETE /api/api-keys/{id}/permanent - Permanently delete an API key
#[delete("/api-keys/{id}/permanent")]
pub async fn delete_api_key(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let key_id = path.into_inner();

    // Require authentication
    let user_id = session
        .get::<String>("user_id")
        .context("Session read error")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Authentication required".to_string()))?;

    // Get database connection
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let key_id_clone = key_id.clone();
    let user_id_clone = user_id.clone();
    let deleted = web::block(move || ApiKey::delete(&mut conn, &key_id_clone, &user_id_clone))
        .await
        .context("Database operation failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if deleted {
        info!(
            user_id = %user_id,
            key_id = %key_id,
            "API key permanently deleted"
        );
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "API key permanently deleted",
            "key_id": key_id
        })))
    } else {
        Err(ApiError::BadRequest("API key not found".to_string()))
    }
}

/// Request to update API key tier (admin only)
#[derive(Debug, Deserialize)]
pub struct UpdateTierRequest {
    pub tier: String,
}

/// PUT /api/admin/api-keys/{id}/tier - Update API key tier (admin only)
#[put("/api-keys/{id}/tier")]
pub async fn update_api_key_tier(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
    req: web::Json<UpdateTierRequest>,
) -> Result<HttpResponse, ApiError> {
    let key_id = path.into_inner();

    // Require admin authentication
    let role = session
        .get::<String>("role")
        .context("Session read error")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Authentication required".to_string()))?;

    if role != "admin" {
        return Err(ApiError::Forbidden("Admin access required".to_string()));
    }

    // Parse tier
    let new_tier = ApiKeyTier::from_str(&req.tier).ok_or_else(|| {
        ApiError::BadRequest("Invalid tier. Use: free, pro, or enterprise".to_string())
    })?;

    // Get database connection
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let key_id_clone = key_id.clone();
    let updated = web::block(move || ApiKey::update_tier(&mut conn, &key_id_clone, new_tier))
        .await
        .context("Database operation failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if updated {
        info!(
            key_id = %key_id,
            new_tier = %req.tier,
            "API key tier updated by admin"
        );
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "API key tier updated",
            "key_id": key_id,
            "tier": req.tier,
            "new_rate_limit": new_tier.default_rate_limit()
        })))
    } else {
        Err(ApiError::BadRequest("API key not found".to_string()))
    }
}

/// GET /api/api-keys/test - Test API key authentication
/// This endpoint is useful for B2B clients to verify their key works
#[get("/api-keys/test")]
pub async fn test_api_key(req: HttpRequest) -> Result<HttpResponse, ApiError> {
    use crate::middleware::api_key_auth::ApiKeyContext;
    use actix_web::HttpMessage;

    // Get API key context from request extensions
    let extensions = req.extensions();
    let ctx = extensions.get::<ApiKeyContext>().cloned().ok_or_else(|| {
        ApiError::Unauthorized("API key authentication required for this endpoint".to_string())
    })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "API key is valid",
        "key_id": ctx.key_id,
        "tier": ctx.tier,
        "rate_limit": ctx.rate_limit,
        "user_id": ctx.user_id
    })))
}

/// Configure API key routes
pub fn configure_api_key_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(create_api_key)
        .service(list_api_keys)
        .service(get_api_key)
        .service(revoke_api_key)
        .service(delete_api_key);
}

/// Configure admin API key routes
pub fn configure_admin_api_key_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(update_api_key_tier);
}
