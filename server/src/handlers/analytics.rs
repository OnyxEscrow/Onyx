//! Analytics endpoints for B2B API usage tracking
//!
//! Provides:
//! - GET /api/v1/analytics/usage — API usage stats with period filtering

use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::error::ApiError;
use crate::handlers::auth_helpers::get_authenticated_identity;
use crate::schema::{api_keys, escrows};

#[derive(Debug, Deserialize)]
pub struct UsageQuery {
    /// Period filter: "24h", "7d", "30d", "all" (default: "30d")
    #[serde(default = "default_period")]
    pub period: String,
}

fn default_period() -> String {
    "30d".to_string()
}

#[derive(Debug, Serialize)]
struct UsageResponse {
    period: String,
    total_escrows: i64,
    active_escrows: i64,
    completed_escrows: i64,
    disputed_escrows: i64,
    total_volume_atomic: i64,
    api_keys_count: i64,
    total_api_requests: i64,
}

/// GET /api/v1/analytics/usage — Get usage analytics for the authenticated client
pub async fn get_usage_analytics(
    req: HttpRequest,
    session: Session,
    pool: web::Data<DbPool>,
    query: web::Query<UsageQuery>,
) -> Result<HttpResponse, ApiError> {
    let auth = get_authenticated_identity(&req, &session)?;
    let user_id = auth.user_id().to_string();
    let period = query.period.clone();

    let cutoff = match period.as_str() {
        "24h" => Some(chrono::Utc::now() - chrono::Duration::hours(24)),
        "7d" => Some(chrono::Utc::now() - chrono::Duration::days(7)),
        "30d" => Some(chrono::Utc::now() - chrono::Duration::days(30)),
        "all" | _ => None,
    };

    let user_id_clone = user_id.clone();
    let user_id_clone2 = user_id.clone();
    let pool_clone = pool.clone();

    // Query escrow stats
    let mut conn = pool
        .get()
        .map_err(|e| ApiError::Internal(format!("DB connection error: {}", e)))?;

    let escrow_stats = web::block(
        move || -> Result<(i64, i64, i64, i64, i64), anyhow::Error> {
            let mut query = escrows::table
                .filter(
                    escrows::buyer_id
                        .eq(&user_id_clone)
                        .or(escrows::vendor_id.eq(&user_id_clone)),
                )
                .into_boxed();

            if let Some(cutoff_ts) = cutoff {
                let cutoff_str = cutoff_ts.naive_utc();
                query = query.filter(escrows::created_at.ge(cutoff_str));
            }

            let all: Vec<(String, i64)> = query
                .select((escrows::status, escrows::amount))
                .load::<(String, i64)>(&mut conn)?;

            let total = all.len() as i64;
            let active = all
                .iter()
                .filter(|(s, _)| {
                    matches!(
                        s.as_str(),
                        "created" | "funded" | "in_progress" | "shipped" | "signing"
                    )
                })
                .count() as i64;
            let completed = all
                .iter()
                .filter(|(s, _)| s == "released" || s == "completed")
                .count() as i64;
            let disputed = all.iter().filter(|(s, _)| s == "disputed").count() as i64;
            let volume: i64 = all.iter().map(|(_, a)| a).sum();

            Ok((total, active, completed, disputed, volume))
        },
    )
    .await
    .map_err(|e| ApiError::Internal(format!("DB query error: {}", e)))?
    .map_err(|e| ApiError::Internal(format!("Escrow stats error: {}", e)))?;

    // Query API key stats
    let mut conn2 = pool_clone
        .get()
        .map_err(|e| ApiError::Internal(format!("DB connection error: {}", e)))?;

    let api_stats = web::block(move || -> Result<(i64, i64), anyhow::Error> {
        let keys: Vec<(i32,)> = api_keys::table
            .filter(api_keys::user_id.eq(&user_id_clone2))
            .filter(api_keys::is_active.eq(1))
            .select((api_keys::total_requests,))
            .load(&mut conn2)?;

        let count = keys.len() as i64;
        let total_reqs: i64 = keys.iter().map(|(r,)| *r as i64).sum();

        Ok((count, total_reqs))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("DB query error: {}", e)))?
    .map_err(|e| ApiError::Internal(format!("API key stats error: {}", e)))?;

    Ok(HttpResponse::Ok().json(UsageResponse {
        period: query.period.clone(),
        total_escrows: escrow_stats.0,
        active_escrows: escrow_stats.1,
        completed_escrows: escrow_stats.2,
        disputed_escrows: escrow_stats.3,
        total_volume_atomic: escrow_stats.4,
        api_keys_count: api_stats.0,
        total_api_requests: api_stats.1,
    }))
}

/// Configure analytics routes for /api/v1 scope
pub fn configure_analytics_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/analytics").route("/usage", web::get().to(get_usage_analytics)));
}
