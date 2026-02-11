//! Client fee management endpoints for B2B EaaS
//!
//! Provides:
//! - GET /api/v1/client/fees — current fee config for authenticated client
//! - GET /api/v1/client/fees/estimate — estimate fees for a given amount
//! - Admin CRUD for client fee overrides

use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::error::ApiError;
use crate::handlers::auth_helpers::get_authenticated_identity;
use crate::models::marketplace_client::MarketplaceClient;
use crate::services::fee_resolver::{resolve_fees, FeeSource};

#[derive(Debug, Serialize)]
struct FeeConfigResponse {
    fee_bps: u64,
    fee_percent: f64,
    source: String,
    client_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FeeEstimateQuery {
    pub amount_atomic: u64,
    #[serde(default)]
    pub is_refund: bool,
}

#[derive(Debug, Serialize)]
struct FeeEstimateResponse {
    amount_atomic: u64,
    fee_bps: u64,
    fee_atomic: u64,
    net_amount_atomic: u64,
    fee_percent: f64,
    source: String,
}

/// GET /api/v1/client/fees — Get current fee configuration for the authenticated client
pub async fn get_client_fees(
    req: HttpRequest,
    session: Session,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, ApiError> {
    let auth = get_authenticated_identity(&req, &session)?;
    let user_id = auth.user_id().to_string();

    let mut conn = pool
        .get()
        .map_err(|e| ApiError::Internal(format!("DB connection error: {e}")))?;

    // Find client record for this user
    let clients = web::block(move || MarketplaceClient::find_by_api_user_id(&mut conn, &user_id))
        .await
        .map_err(|e| ApiError::Internal(format!("DB query error: {e}")))?
        .map_err(|e| ApiError::Internal(format!("Client query error: {e}")))?;

    let client_id = clients.first().map(|c| c.id.as_str());

    let mut conn2 = pool
        .get()
        .map_err(|e| ApiError::Internal(format!("DB connection error: {e}")))?;

    let resolved = resolve_fees(&mut conn2, client_id, false)
        .map_err(|e| ApiError::Internal(format!("Fee resolution error: {e}")))?;

    let (source_str, cid) = match &resolved.source {
        FeeSource::GlobalDefault => ("global_default".to_string(), None),
        FeeSource::Client { client_id } => ("client_override".to_string(), Some(client_id.clone())),
    };

    Ok(HttpResponse::Ok().json(FeeConfigResponse {
        fee_bps: resolved.fee_bps,
        fee_percent: resolved.fee_bps as f64 / 100.0,
        source: source_str,
        client_id: cid,
    }))
}

/// GET /api/v1/client/fees/estimate — Estimate fees for a given amount
pub async fn estimate_fees(
    req: HttpRequest,
    session: Session,
    pool: web::Data<DbPool>,
    query: web::Query<FeeEstimateQuery>,
) -> Result<HttpResponse, ApiError> {
    let auth = get_authenticated_identity(&req, &session)?;
    let user_id = auth.user_id().to_string();

    let mut conn = pool
        .get()
        .map_err(|e| ApiError::Internal(format!("DB connection error: {e}")))?;

    let clients = web::block(move || MarketplaceClient::find_by_api_user_id(&mut conn, &user_id))
        .await
        .map_err(|e| ApiError::Internal(format!("DB query error: {e}")))?
        .map_err(|e| ApiError::Internal(format!("Client query error: {e}")))?;

    let client_id = clients.first().map(|c| c.id.as_str());

    let mut conn2 = pool
        .get()
        .map_err(|e| ApiError::Internal(format!("DB connection error: {e}")))?;

    let resolved = resolve_fees(&mut conn2, client_id, query.is_refund)
        .map_err(|e| ApiError::Internal(format!("Fee resolution error: {e}")))?;

    let fee_atomic = (query.amount_atomic * resolved.fee_bps) / 10000;
    let net_amount = query.amount_atomic.saturating_sub(fee_atomic);

    let source_str = match &resolved.source {
        FeeSource::GlobalDefault => "global_default",
        FeeSource::Client { .. } => "client_override",
    };

    Ok(HttpResponse::Ok().json(FeeEstimateResponse {
        amount_atomic: query.amount_atomic,
        fee_bps: resolved.fee_bps,
        fee_atomic,
        net_amount_atomic: net_amount,
        fee_percent: resolved.fee_bps as f64 / 100.0,
        source: source_str.to_string(),
    }))
}

/// Configure client fee routes for /api/v1 scope
pub fn configure_client_fee_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/client/fees")
            .route("", web::get().to(get_client_fees))
            .route("/estimate", web::get().to(estimate_fees)),
    );
}
