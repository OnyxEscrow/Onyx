//! API Key Authentication Middleware for B2B EaaS
//!
//! Provides authentication via:
//! - `Authorization: Bearer nxs_xxx` header
//! - `X-API-Key: nxs_xxx` header
//!
//! Features:
//! - SHA256 key validation (never stores plaintext)
//! - Tiered rate limiting (Free: 60/min, Pro: 300/min, Enterprise: 1000/min)
//! - Expiration checking
//! - Usage tracking (last_used_at, total_requests)

use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::collections::HashMap;
use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::db::DbPool;
use crate::models::api_key::ApiKey;

/// Authenticated API key context attached to request extensions
#[derive(Clone, Debug)]
pub struct ApiKeyContext {
    pub key_id: String,
    pub user_id: String,
    pub tier: String,
    pub rate_limit: u32,
    pub scopes: Vec<String>,
}

/// Rate limit info attached to request for response headers
#[derive(Clone, Debug)]
pub struct RateLimitInfo {
    pub limit: u32,
    pub remaining: u32,
    pub reset: u64,
}

/// Rate limit storage: key_id -> Vec<timestamp>
pub type ApiKeyRateLimitStorage = Arc<Mutex<HashMap<String, Vec<u64>>>>;

/// Create a new shared rate limit storage
pub fn new_api_key_rate_limit_storage() -> ApiKeyRateLimitStorage {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Middleware that authenticates requests via API key
///
/// # Usage
/// ```rust
/// use actix_web::web;
/// use server::middleware::api_key_auth::RequireApiKey;
///
/// web::scope("/api/v1")
///     .wrap(RequireApiKey::new(pool, rate_storage))
///     .route("/escrow", web::post().to(create_escrow))
/// ```
///
/// # Headers
/// - `Authorization: Bearer nxs_xxx` (preferred)
/// - `X-API-Key: nxs_xxx` (alternative)
///
/// # Behavior
/// 1. Extracts API key from header
/// 2. Validates key against database (hash comparison)
/// 3. Checks key is active and not expired
/// 4. Enforces tier-based rate limiting
/// 5. Updates usage statistics
/// 6. Attaches ApiKeyContext to request extensions
///
/// # Access Context in Handler
/// ```rust
/// use actix_web::{web, HttpRequest, HttpResponse};
/// use server::middleware::api_key_auth::ApiKeyContext;
///
/// async fn handler(req: HttpRequest) -> HttpResponse {
///     let ctx = req.extensions()
///         .get::<ApiKeyContext>()
///         .expect("ApiKeyContext not found");
///     HttpResponse::Ok().json(serde_json::json!({
///         "user_id": ctx.user_id,
///         "tier": ctx.tier
///     }))
/// }
/// ```
pub struct RequireApiKey {
    pool: actix_web::web::Data<DbPool>,
    rate_storage: ApiKeyRateLimitStorage,
}

impl RequireApiKey {
    pub fn new(pool: actix_web::web::Data<DbPool>, rate_storage: ApiKeyRateLimitStorage) -> Self {
        Self { pool, rate_storage }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequireApiKey
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = RequireApiKeyMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequireApiKeyMiddleware {
            service: Rc::new(service),
            pool: self.pool.clone(),
            rate_storage: self.rate_storage.clone(),
        }))
    }
}

pub struct RequireApiKeyMiddleware<S> {
    service: Rc<S>,
    pool: actix_web::web::Data<DbPool>,
    rate_storage: ApiKeyRateLimitStorage,
}

impl<S, B> Service<ServiceRequest> for RequireApiKeyMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let pool = self.pool.clone();
        let rate_storage = self.rate_storage.clone();

        Box::pin(async move {
            // 1. Extract API key from headers
            let api_key = extract_api_key(&req);

            let raw_key = match api_key {
                Some(key) => key,
                None => {
                    return Ok(req.into_response(
                        HttpResponse::Unauthorized()
                            .json(serde_json::json!({
                                "error": "API key required",
                                "message": "Provide API key via 'Authorization: Bearer nxs_xxx' or 'X-API-Key: nxs_xxx' header"
                            }))
                    ).map_into_right_body());
                }
            };

            // Validate key format
            if !raw_key.starts_with("nxs_") {
                warn!("Invalid API key format received");
                return Ok(req.into_response(
                    HttpResponse::Unauthorized()
                        .json(serde_json::json!({
                            "error": "Invalid API key format",
                            "message": "API key must start with 'nxs_'"
                        }))
                ).map_into_right_body());
            }

            // 2. Validate key against database
            let mut conn = match pool.get() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Database connection error: {}", e);
                    return Ok(req.into_response(
                        HttpResponse::InternalServerError()
                            .json(serde_json::json!({
                                "error": "Internal server error",
                                "message": "Database unavailable"
                            }))
                    ).map_into_right_body());
                }
            };

            let key_record = match ApiKey::validate(&mut conn, &raw_key) {
                Ok(Some(key)) => key,
                Ok(None) => {
                    warn!("Invalid or expired API key used");
                    return Ok(req.into_response(
                        HttpResponse::Unauthorized()
                            .json(serde_json::json!({
                                "error": "Invalid API key",
                                "message": "API key is invalid, inactive, or expired"
                            }))
                    ).map_into_right_body());
                }
                Err(e) => {
                    tracing::error!("API key validation error: {}", e);
                    return Ok(req.into_response(
                        HttpResponse::InternalServerError()
                            .json(serde_json::json!({
                                "error": "Internal server error",
                                "message": "Key validation failed"
                            }))
                    ).map_into_right_body());
                }
            };

            // 3. Check rate limit
            let rate_limit = key_record.effective_rate_limit();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let is_rate_limited = {
                let mut storage = match rate_storage.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };

                let requests = storage.entry(key_record.id.clone()).or_insert_with(Vec::new);

                // Clean old requests outside 60-second window
                requests.retain(|&timestamp| now - timestamp < 60);

                if requests.len() >= rate_limit as usize {
                    true
                } else {
                    requests.push(now);
                    false
                }
            };

            // Calculate reset time (start of next 60-second window)
            let reset_timestamp = now + 60 - (now % 60);

            if is_rate_limited {
                warn!(
                    key_id = %key_record.id,
                    tier = %key_record.tier,
                    limit = rate_limit,
                    "API key rate limit exceeded"
                );
                return Ok(req.into_response(
                    HttpResponse::TooManyRequests()
                        .insert_header(("Retry-After", "60"))
                        .insert_header(("X-RateLimit-Limit", rate_limit.to_string()))
                        .insert_header(("X-RateLimit-Remaining", "0"))
                        .insert_header(("X-RateLimit-Reset", reset_timestamp.to_string()))
                        .json(serde_json::json!({
                            "error": "Rate limit exceeded",
                            "message": format!("Exceeded {} requests per minute for {} tier", rate_limit, key_record.tier),
                            "tier": key_record.tier,
                            "limit": rate_limit,
                            "retry_after": 60,
                            "reset_at": reset_timestamp
                        }))
                ).map_into_right_body());
            }

            // 4. Record usage (async, don't block response)
            let key_id_for_usage = key_record.id.clone();
            let pool_for_usage = pool.clone();
            tokio::spawn(async move {
                if let Ok(mut conn) = pool_for_usage.get() {
                    if let Err(e) = ApiKey::record_usage(&mut conn, &key_id_for_usage) {
                        tracing::error!("Failed to record API key usage: {}", e);
                    }
                }
            });

            // 5. Parse scopes from metadata JSON (fallback to wildcard)
            let scopes = key_record.metadata.as_ref()
                .and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok())
                .and_then(|v| v.get("scopes").cloned())
                .and_then(|s| serde_json::from_value::<Vec<String>>(s).ok())
                .unwrap_or_else(|| vec!["*".to_string()]);

            // 6. Attach context to request
            let ctx = ApiKeyContext {
                key_id: key_record.id.clone(),
                user_id: key_record.user_id.clone(),
                tier: key_record.tier.clone(),
                rate_limit,
                scopes,
            };

            req.extensions_mut().insert(ctx);

            // 6. Calculate remaining requests for headers
            let remaining = {
                let storage = match rate_storage.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let used = storage.get(&key_record.id).map(|v| v.len()).unwrap_or(0);
                rate_limit.saturating_sub(used as u32)
            };

            // Store rate limit info in extensions for response headers
            req.extensions_mut().insert(RateLimitInfo {
                limit: rate_limit,
                remaining,
                reset: reset_timestamp,
            });

            // Call next service
            let mut res = svc.call(req).await?;

            // Add rate limit headers to successful response
            let headers = res.headers_mut();
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-ratelimit-limit"),
                actix_web::http::header::HeaderValue::from_str(&rate_limit.to_string()).unwrap(),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-ratelimit-remaining"),
                actix_web::http::header::HeaderValue::from_str(&remaining.to_string()).unwrap(),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-ratelimit-reset"),
                actix_web::http::header::HeaderValue::from_str(&reset_timestamp.to_string()).unwrap(),
            );

            Ok(res.map_into_left_body())
        })
    }
}

/// Extract API key from request headers
/// Supports both `Authorization: Bearer xxx` and `X-API-Key: xxx`
fn extract_api_key(req: &ServiceRequest) -> Option<String> {
    // Try Authorization: Bearer xxx first
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Some(auth_str[7..].to_string());
            }
        }
    }

    // Try X-API-Key header
    if let Some(api_key_header) = req.headers().get("X-API-Key") {
        if let Ok(key_str) = api_key_header.to_str() {
            return Some(key_str.to_string());
        }
    }

    None
}

/// Optional API key authentication - allows both authenticated and unauthenticated requests
/// If API key is present and valid, attaches ApiKeyContext
/// If API key is absent, continues without context
/// If API key is present but invalid, returns 401
pub struct OptionalApiKey {
    pool: actix_web::web::Data<DbPool>,
    rate_storage: ApiKeyRateLimitStorage,
}

impl OptionalApiKey {
    pub fn new(pool: actix_web::web::Data<DbPool>, rate_storage: ApiKeyRateLimitStorage) -> Self {
        Self { pool, rate_storage }
    }
}

impl<S, B> Transform<S, ServiceRequest> for OptionalApiKey
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = OptionalApiKeyMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(OptionalApiKeyMiddleware {
            service: Rc::new(service),
            pool: self.pool.clone(),
            rate_storage: self.rate_storage.clone(),
        }))
    }
}

pub struct OptionalApiKeyMiddleware<S> {
    service: Rc<S>,
    pool: actix_web::web::Data<DbPool>,
    rate_storage: ApiKeyRateLimitStorage,
}

impl<S, B> Service<ServiceRequest> for OptionalApiKeyMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let pool = self.pool.clone();
        let rate_storage = self.rate_storage.clone();

        Box::pin(async move {
            // Try to extract API key
            let api_key = extract_api_key(&req);

            // If no key provided, continue without authentication
            if api_key.is_none() {
                let res = svc.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            let raw_key = api_key.unwrap();

            // Validate key format
            if !raw_key.starts_with("nxs_") {
                return Ok(req.into_response(
                    HttpResponse::Unauthorized()
                        .json(serde_json::json!({
                            "error": "Invalid API key format"
                        }))
                ).map_into_right_body());
            }

            // Validate against database
            let mut conn = match pool.get() {
                Ok(c) => c,
                Err(_) => {
                    let res = svc.call(req).await?;
                    return Ok(res.map_into_left_body());
                }
            };

            let key_record = match ApiKey::validate(&mut conn, &raw_key) {
                Ok(Some(key)) => key,
                Ok(None) => {
                    return Ok(req.into_response(
                        HttpResponse::Unauthorized()
                            .json(serde_json::json!({
                                "error": "Invalid API key"
                            }))
                    ).map_into_right_body());
                }
                Err(_) => {
                    let res = svc.call(req).await?;
                    return Ok(res.map_into_left_body());
                }
            };

            // Rate limiting (same as RequireApiKey)
            let rate_limit = key_record.effective_rate_limit();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let is_rate_limited = {
                let mut storage = match rate_storage.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let requests = storage.entry(key_record.id.clone()).or_insert_with(Vec::new);
                requests.retain(|&timestamp| now - timestamp < 60);
                if requests.len() >= rate_limit as usize {
                    true
                } else {
                    requests.push(now);
                    false
                }
            };

            if is_rate_limited {
                return Ok(req.into_response(
                    HttpResponse::TooManyRequests()
                        .insert_header(("Retry-After", "60"))
                        .json(serde_json::json!({
                            "error": "Rate limit exceeded"
                        }))
                ).map_into_right_body());
            }

            // Parse scopes from metadata JSON (fallback to wildcard)
            let scopes = key_record.metadata.as_ref()
                .and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok())
                .and_then(|v| v.get("scopes").cloned())
                .and_then(|s| serde_json::from_value::<Vec<String>>(s).ok())
                .unwrap_or_else(|| vec!["*".to_string()]);

            // Attach context
            let ctx = ApiKeyContext {
                key_id: key_record.id.clone(),
                user_id: key_record.user_id.clone(),
                tier: key_record.tier.clone(),
                rate_limit,
                scopes,
            };
            req.extensions_mut().insert(ctx);

            let res = svc.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
