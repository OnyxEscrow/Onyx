//! Webhook API Handlers
//!
//! REST API endpoints for managing webhooks and viewing delivery history.
//! All endpoints require API key authentication.
//!
//! Endpoints:
//! - POST   /api/webhooks          - Register a new webhook
//! - GET    /api/webhooks          - List all webhooks for API key
//! - GET    /api/webhooks/{id}     - Get webhook details
//! - PATCH  /api/webhooks/{id}     - Update webhook
//! - DELETE /api/webhooks/{id}     - Delete webhook
//! - POST   /api/webhooks/{id}/activate   - Activate webhook
//! - POST   /api/webhooks/{id}/deactivate - Deactivate webhook
//! - POST   /api/webhooks/{id}/rotate-secret - Rotate HMAC secret
//! - GET    /api/webhooks/{id}/deliveries - Get delivery history
//! - POST   /api/webhooks/deliveries/{id}/retry - Retry a delivery
//! - GET    /api/webhooks/{id}/stats - Get delivery statistics

use actix_web::{delete, get, patch, post, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use url::Url;

use crate::db::DbPool;
use crate::models::webhook::{NewWebhook, Webhook, WebhookEventType, WebhookResponse};
use crate::models::webhook_delivery::{WebhookDelivery, WebhookDeliveryResponse};
use crate::services::webhook_dispatcher::WebhookDispatcher;

/// Request body for creating a webhook
#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    pub description: Option<String>,
}

/// Request body for updating a webhook
#[derive(Debug, Deserialize)]
pub struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub description: Option<String>,
}

/// Response for webhook creation (includes secret)
#[derive(Debug, Serialize)]
pub struct CreateWebhookResponse {
    pub webhook: WebhookResponse,
    /// Secret for HMAC signing - only shown once on creation
    pub secret: String,
}

/// Response for secret rotation
#[derive(Debug, Serialize)]
pub struct RotateSecretResponse {
    pub webhook_id: String,
    /// New secret for HMAC signing
    pub secret: String,
    pub message: String,
}

/// Validate URL is HTTPS and not pointing to private/reserved IPs (SSRF protection)
fn validate_webhook_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("Webhook URL must use HTTPS".to_string());
    }
    if url.len() > 2048 {
        return Err("URL too long (max 2048 characters)".to_string());
    }

    let parsed = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;
    let host = parsed.host_str().ok_or("URL must have a host")?;

    // Block localhost variants
    let blocked_hosts = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
    if blocked_hosts.iter().any(|&h| host.eq_ignore_ascii_case(h)) {
        return Err("Localhost URLs are not allowed".to_string());
    }

    // Resolve and check IP ranges
    let port = parsed.port().unwrap_or(443);
    let socket_addrs = format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?;

    for addr in socket_addrs {
        if is_private_or_reserved_ip(&addr.ip()) {
            return Err(format!("IP {} is private/reserved", addr.ip()));
        }
    }
    Ok(())
}

/// Check if an IP address is private, loopback, link-local, or reserved
fn is_private_or_reserved_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || (ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254) // AWS metadata
                || (ipv4.octets()[0] == 100 && ipv4.octets()[1] >= 64 && ipv4.octets()[1] <= 127)
            // Carrier-grade NAT
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
    }
}

/// Generate a secure random secret for HMAC signing
fn generate_webhook_secret() -> String {
    let mut rng = rand::thread_rng();
    let secret: [u8; 32] = rng.gen();
    hex::encode(secret)
}

/// Extract API key ID from request (set by auth middleware)
fn get_api_key_id(req: &HttpRequest) -> Option<String> {
    req.extensions()
        .get::<crate::middleware::api_key_auth::ApiKeyContext>()
        .map(|ctx| ctx.key_id.clone())
}

/// POST /api/webhooks - Register a new webhook
#[post("/webhooks")]
pub async fn create_webhook(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    body: web::Json<CreateWebhookRequest>,
) -> impl Responder {
    // Get API key from middleware
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    // Validate URL
    if let Err(e) = validate_webhook_url(&body.url) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": e
        }));
    }

    // Parse event types
    let events: Vec<WebhookEventType> = body
        .events
        .iter()
        .filter_map(|s| WebhookEventType::from_str(s))
        .collect();

    // Generate secret
    let secret = generate_webhook_secret();

    // Create webhook
    let new_webhook = NewWebhook::new(
        api_key_id,
        body.url.clone(),
        secret.clone(),
        events,
        body.description.clone(),
    );

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    match Webhook::create(new_webhook, &mut conn) {
        Ok(webhook) => {
            tracing::info!(
                webhook_id = %webhook.id,
                url = %webhook.url,
                "Webhook created"
            );

            HttpResponse::Created().json(CreateWebhookResponse {
                webhook: WebhookResponse::from(webhook),
                secret,
            })
        }
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("UNIQUE constraint failed") {
                tracing::warn!("Duplicate webhook: {}", err_str);
                HttpResponse::Conflict().json(serde_json::json!({
                    "error": "A webhook with this URL already exists for your API key"
                }))
            } else {
                tracing::error!("Failed to create webhook: {}", err_str);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to create webhook"
                }))
            }
        }
    }
}

/// GET /api/webhooks - List all webhooks for API key
#[get("/webhooks")]
pub async fn list_webhooks(pool: web::Data<DbPool>, req: HttpRequest) -> impl Responder {
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    match Webhook::get_by_api_key(&api_key_id, &mut conn) {
        Ok(webhooks) => {
            let responses: Vec<WebhookResponse> =
                webhooks.into_iter().map(WebhookResponse::from).collect();

            HttpResponse::Ok().json(serde_json::json!({
                "webhooks": responses,
                "count": responses.len()
            }))
        }
        Err(e) => {
            tracing::error!("Failed to list webhooks: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list webhooks"
            }))
        }
    }
}

/// GET /api/webhooks/{id} - Get webhook details
#[get("/webhooks/{id}")]
pub async fn get_webhook(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let webhook_id = path.into_inner();
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    match Webhook::find_by_id(&webhook_id, &mut conn) {
        Ok(Some(webhook)) if webhook.api_key_id == api_key_id => {
            HttpResponse::Ok().json(WebhookResponse::from(webhook))
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to access this webhook"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Webhook not found"
        })),
        Err(e) => {
            tracing::error!("Failed to get webhook: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get webhook"
            }))
        }
    }
}

/// PATCH /api/webhooks/{id} - Update webhook
#[patch("/webhooks/{id}")]
pub async fn update_webhook(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<UpdateWebhookRequest>,
) -> impl Responder {
    let webhook_id = path.into_inner();
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    // Validate URL if provided
    if let Some(ref url) = body.url {
        if let Err(e) = validate_webhook_url(url) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": e
            }));
        }
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Verify ownership
    match Webhook::find_by_id(&webhook_id, &mut conn) {
        Ok(Some(webhook)) if webhook.api_key_id == api_key_id => {
            // Convert events if provided
            let events_str = body.events.as_ref().map(|events| {
                if events.is_empty() || events.contains(&"*".to_string()) {
                    "*".to_string()
                } else {
                    events.join(",")
                }
            });

            if let Err(e) = Webhook::update(
                &webhook_id,
                body.url.clone(),
                events_str,
                body.description.clone(),
                &mut conn,
            ) {
                tracing::error!("Failed to update webhook: {:?}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update webhook"
                }));
            }

            // Fetch updated webhook
            match Webhook::find_by_id(&webhook_id, &mut conn) {
                Ok(Some(updated)) => HttpResponse::Ok().json(WebhookResponse::from(updated)),
                _ => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to fetch updated webhook"
                })),
            }
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to update this webhook"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Webhook not found"
        })),
        Err(e) => {
            tracing::error!("Failed to get webhook: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get webhook"
            }))
        }
    }
}

/// DELETE /api/webhooks/{id} - Delete webhook
#[delete("/webhooks/{id}")]
pub async fn delete_webhook(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let webhook_id = path.into_inner();
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Verify ownership
    match Webhook::find_by_id(&webhook_id, &mut conn) {
        Ok(Some(webhook)) if webhook.api_key_id == api_key_id => {
            if let Err(e) = Webhook::delete(&webhook_id, &mut conn) {
                tracing::error!("Failed to delete webhook: {:?}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to delete webhook"
                }));
            }

            tracing::info!(webhook_id = %webhook_id, "Webhook deleted");

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Webhook deleted"
            }))
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to delete this webhook"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Webhook not found"
        })),
        Err(e) => {
            tracing::error!("Failed to get webhook: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get webhook"
            }))
        }
    }
}

/// POST /api/webhooks/{id}/activate - Activate webhook
#[post("/webhooks/{id}/activate")]
pub async fn activate_webhook(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let webhook_id = path.into_inner();
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    match Webhook::find_by_id(&webhook_id, &mut conn) {
        Ok(Some(webhook)) if webhook.api_key_id == api_key_id => {
            if let Err(e) = Webhook::activate(&webhook_id, &mut conn) {
                tracing::error!("Failed to activate webhook: {:?}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to activate webhook"
                }));
            }

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Webhook activated"
            }))
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Webhook not found"
        })),
        Err(e) => {
            tracing::error!("Failed to get webhook: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }))
        }
    }
}

/// POST /api/webhooks/{id}/deactivate - Deactivate webhook
#[post("/webhooks/{id}/deactivate")]
pub async fn deactivate_webhook(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let webhook_id = path.into_inner();
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    match Webhook::find_by_id(&webhook_id, &mut conn) {
        Ok(Some(webhook)) if webhook.api_key_id == api_key_id => {
            if let Err(e) = Webhook::deactivate(&webhook_id, &mut conn) {
                tracing::error!("Failed to deactivate webhook: {:?}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to deactivate webhook"
                }));
            }

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Webhook deactivated"
            }))
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Webhook not found"
        })),
        Err(e) => {
            tracing::error!("Failed to get webhook: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }))
        }
    }
}

/// POST /api/webhooks/{id}/rotate-secret - Rotate HMAC secret
#[post("/webhooks/{id}/rotate-secret")]
pub async fn rotate_webhook_secret(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let webhook_id = path.into_inner();
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    match Webhook::find_by_id(&webhook_id, &mut conn) {
        Ok(Some(webhook)) if webhook.api_key_id == api_key_id => {
            let new_secret = generate_webhook_secret();

            if let Err(e) = Webhook::rotate_secret(&webhook_id, &new_secret, &mut conn) {
                tracing::error!("Failed to rotate secret: {:?}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to rotate secret"
                }));
            }

            tracing::info!(webhook_id = %webhook_id, "Webhook secret rotated");

            HttpResponse::Ok().json(RotateSecretResponse {
                webhook_id,
                secret: new_secret,
                message:
                    "Secret rotated successfully. Update your integration with the new secret."
                        .to_string(),
            })
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Webhook not found"
        })),
        Err(e) => {
            tracing::error!("Failed to get webhook: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }))
        }
    }
}

/// GET /api/webhooks/{id}/deliveries - Get delivery history
#[get("/webhooks/{id}/deliveries")]
pub async fn get_webhook_deliveries(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<String>,
    query: web::Query<DeliveriesQuery>,
) -> impl Responder {
    let webhook_id = path.into_inner();
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    let limit = query.limit.unwrap_or(50).min(100);

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Verify ownership
    match Webhook::find_by_id(&webhook_id, &mut conn) {
        Ok(Some(webhook)) if webhook.api_key_id == api_key_id => {
            match WebhookDelivery::get_by_webhook(&webhook_id, limit, &mut conn) {
                Ok(deliveries) => {
                    let responses: Vec<WebhookDeliveryResponse> = deliveries
                        .into_iter()
                        .map(WebhookDeliveryResponse::from)
                        .collect();

                    HttpResponse::Ok().json(serde_json::json!({
                        "deliveries": responses,
                        "count": responses.len()
                    }))
                }
                Err(e) => {
                    tracing::error!("Failed to get deliveries: {:?}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to get deliveries"
                    }))
                }
            }
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Webhook not found"
        })),
        Err(e) => {
            tracing::error!("Failed to get webhook: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DeliveriesQuery {
    pub limit: Option<i64>,
}

/// POST /api/webhooks/deliveries/{id}/retry - Retry a failed delivery
#[post("/webhooks/deliveries/{id}/retry")]
pub async fn retry_delivery(
    pool: web::Data<DbPool>,
    dispatcher: web::Data<Arc<WebhookDispatcher>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let delivery_id = path.into_inner();
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Get delivery and verify ownership
    let delivery = match WebhookDelivery::find_by_id(&delivery_id, &mut conn) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Delivery not found"
            }));
        }
        Err(e) => {
            tracing::error!("Failed to get delivery: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    // Verify webhook ownership
    match Webhook::find_by_id(&delivery.webhook_id, &mut conn) {
        Ok(Some(webhook)) if webhook.api_key_id == api_key_id => {
            // Trigger retry
            match dispatcher.retry_delivery(&delivery_id).await {
                Ok(()) => HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "Retry initiated"
                })),
                Err(e) => {
                    tracing::error!("Retry failed: {:?}", e);
                    HttpResponse::BadRequest().json(serde_json::json!({
                        "error": e.to_string()
                    }))
                }
            }
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Webhook not found"
        })),
        Err(e) => {
            tracing::error!("Failed to get webhook: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }))
        }
    }
}

/// GET /api/webhooks/{id}/stats - Get delivery statistics
#[get("/webhooks/{id}/stats")]
pub async fn get_webhook_stats(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let webhook_id = path.into_inner();
    let api_key_id = match get_api_key_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "API key required"
            }));
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Verify ownership
    match Webhook::find_by_id(&webhook_id, &mut conn) {
        Ok(Some(webhook)) if webhook.api_key_id == api_key_id => {
            match WebhookDelivery::get_stats(&webhook_id, &mut conn) {
                Ok(stats) => HttpResponse::Ok().json(stats),
                Err(e) => {
                    tracing::error!("Failed to get stats: {:?}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to get statistics"
                    }))
                }
            }
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Webhook not found"
        })),
        Err(e) => {
            tracing::error!("Failed to get webhook: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }))
        }
    }
}

/// Configure webhook routes
pub fn configure_webhook_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(create_webhook)
        .service(list_webhooks)
        .service(get_webhook)
        .service(update_webhook)
        .service(delete_webhook)
        .service(activate_webhook)
        .service(deactivate_webhook)
        .service(rotate_webhook_secret)
        .service(get_webhook_deliveries)
        .service(retry_delivery)
        .service(get_webhook_stats);
}
