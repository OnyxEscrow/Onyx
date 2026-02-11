// FROST CLSAG Signing API Handlers
//!
//! API endpoints for FROST 2-of-3 threshold CLSAG signing:
//! - POST /api/escrow/frost/{id}/sign/init           - Initialize signing session
//! - POST /api/escrow/frost/{id}/sign/nonces         - Submit nonce commitment
//! - GET  /api/escrow/frost/{id}/sign/nonces         - Get aggregated nonces
//! - POST /api/escrow/frost/{id}/sign/partial        - Submit partial signature
//! - GET  /api/escrow/frost/{id}/sign/status         - Get signing status
//! - POST /api/escrow/frost/{id}/sign/complete       - Aggregate and broadcast
//! - GET  /api/escrow/frost/{id}/sign/tx-data        - Get TX data for signing

use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::SqliteConnection;
use serde::Deserialize;
use tracing::{error, info};

use crate::handlers::auth_helpers::get_authenticated_identity;
use crate::handlers::frost_escrow::ApiResponse;
use crate::services::frost_signing_coordinator::{FrostSigningCoordinator, TxSigningData};

type DbPool = Pool<ConnectionManager<SqliteConnection>>;

/// Request to submit nonce commitment
#[derive(Debug, Deserialize)]
pub struct SubmitNonceRequest {
    pub role: String,
    pub r_public: String,
    pub r_prime_public: String,
    pub commitment_hash: String,
}

/// Request to submit partial signature
#[derive(Debug, Deserialize)]
pub struct SubmitPartialRequest {
    pub role: String,
    pub partial_signature: String, // JSON-encoded CLSAG signature
    pub partial_key_image: String,
}

/// Initialize signing session
///
/// POST /api/escrow/frost/{id}/sign/init
pub async fn init_frost_signing(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    // Dual auth: API key or session
    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostSigningCoordinator::init_signing(&mut conn, &escrow_id).await {
        Ok(tx_data) => {
            info!(escrow_id = %escrow_id, "FROST signing session initialized");
            HttpResponse::Ok().json(ApiResponse::success(tx_data))
        }
        Err(e) => {
            error!("Failed to init signing: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(&format!("Failed to init: {e}")))
        }
    }
}

/// Submit nonce commitment
///
/// POST /api/escrow/frost/{id}/sign/nonces
pub async fn submit_nonce_commitment(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<SubmitNonceRequest>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostSigningCoordinator::submit_nonce_commitment(
        &mut conn,
        &escrow_id,
        &body.role,
        &body.r_public,
        &body.r_prime_public,
    ) {
        Ok(both_submitted) => {
            info!(
                escrow_id = %escrow_id,
                role = %body.role,
                both_submitted = both_submitted,
                "Nonce commitment submitted"
            );
            HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "both_submitted": both_submitted,
                "message": if both_submitted {
                    "Both nonces submitted and aggregated"
                } else {
                    "Nonce submitted, waiting for peer"
                }
            })))
        }
        Err(e) => {
            error!("Failed to submit nonce: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(&format!("Failed to submit: {e}")))
        }
    }
}

/// Get nonce commitments
///
/// GET /api/escrow/frost/{id}/sign/nonces
pub async fn get_nonce_commitments(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    use crate::schema::frost_signing_state;
    use diesel::prelude::*;

    match frost_signing_state::table
        .filter(frost_signing_state::escrow_id.eq(&escrow_id))
        .select((
            frost_signing_state::buyer_r_public,
            frost_signing_state::buyer_r_prime_public,
            frost_signing_state::vendor_r_public,
            frost_signing_state::vendor_r_prime_public,
            frost_signing_state::aggregated_r,
            frost_signing_state::aggregated_r_prime,
        ))
        .first::<(
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        )>(&mut conn)
    {
        Ok(data) => HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
            "buyer": if data.0.is_some() {
                Some(serde_json::json!({
                    "r_public": data.0,
                    "r_prime_public": data.1
                }))
            } else {
                None
            },
            "vendor": if data.2.is_some() {
                Some(serde_json::json!({
                    "r_public": data.2,
                    "r_prime_public": data.3
                }))
            } else {
                None
            },
            "aggregated": if data.4.is_some() {
                Some(serde_json::json!({
                    "r": data.4,
                    "r_prime": data.5
                }))
            } else {
                None
            }
        }))),
        Err(e) => {
            error!("Failed to get nonces: {}", e);
            HttpResponse::NotFound().json(ApiResponse::<()>::error("Signing session not found"))
        }
    }
}

/// Submit partial signature
///
/// POST /api/escrow/frost/{id}/sign/partial
pub async fn submit_partial_signature(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<SubmitPartialRequest>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Also store partial key image in escrows table
    use crate::schema::escrows;
    use diesel::prelude::*;

    let update_result = match body.role.as_str() {
        "buyer" => diesel::update(escrows::table.find(&escrow_id))
            .set(escrows::buyer_partial_key_image.eq(&body.partial_key_image))
            .execute(&mut conn),
        "vendor" => diesel::update(escrows::table.find(&escrow_id))
            .set(escrows::vendor_partial_key_image.eq(&body.partial_key_image))
            .execute(&mut conn),
        "arbiter" => diesel::update(escrows::table.find(&escrow_id))
            .set(escrows::arbiter_partial_key_image.eq(&body.partial_key_image))
            .execute(&mut conn),
        _ => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid role"));
        }
    };

    if let Err(e) = update_result {
        error!("Failed to store partial key image: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to store key image"));
    }

    match FrostSigningCoordinator::submit_partial_signature(
        &mut conn,
        &escrow_id,
        &body.role,
        &body.partial_signature,
    ) {
        Ok(all_submitted) => {
            info!(
                escrow_id = %escrow_id,
                role = %body.role,
                all_submitted = all_submitted,
                "Partial signature submitted"
            );

            // Auto-trigger aggregation when both buyer + vendor partials are in
            // In 2-of-3 FROST CLSAG, buyer + vendor = quorum (arbiter only for disputes)
            if all_submitted {
                let pool_clone = pool.clone();
                let eid = escrow_id.clone();
                tokio::spawn(async move {
                    info!(escrow_id = %eid, "Auto-triggering CLSAG aggregation + broadcast");
                    let mut agg_conn = match pool_clone.get() {
                        Ok(c) => c,
                        Err(e) => {
                            error!("DB connection error for auto-aggregate: {}", e);
                            return;
                        }
                    };
                    match FrostSigningCoordinator::aggregate_and_broadcast(&mut agg_conn, &eid)
                        .await
                    {
                        Ok(tx_hash) => {
                            info!(escrow_id = %eid, tx_hash = %tx_hash, "TX aggregated and broadcasted automatically");
                        }
                        Err(e) => {
                            error!(escrow_id = %eid, "Auto-aggregate failed: {}", e);
                        }
                    }
                });
            }

            HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "all_submitted": all_submitted,
                "message": if all_submitted {
                    "All signatures ready - aggregation triggered"
                } else {
                    "Signature submitted, waiting for peers"
                }
            })))
        }
        Err(e) => {
            error!("Failed to submit partial signature: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(&format!("Failed to submit: {e}")))
        }
    }
}

/// Get signing status
///
/// GET /api/escrow/frost/{id}/sign/status
pub async fn get_signing_status(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostSigningCoordinator::get_status(&mut conn, &escrow_id) {
        Ok(status) => HttpResponse::Ok().json(ApiResponse::success(status)),
        Err(e) => {
            error!("Failed to get signing status: {}", e);
            HttpResponse::NotFound().json(ApiResponse::<()>::error("Signing session not found"))
        }
    }
}

/// Complete signing and broadcast transaction
///
/// POST /api/escrow/frost/{id}/sign/complete
pub async fn complete_and_broadcast(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostSigningCoordinator::aggregate_and_broadcast(&mut conn, &escrow_id).await {
        Ok(tx_hash) => {
            info!(
                escrow_id = %escrow_id,
                tx_hash = %tx_hash,
                "TX aggregated and broadcasted"
            );
            HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "tx_hash": tx_hash,
                "message": "Transaction broadcasted successfully"
            })))
        }
        Err(e) => {
            error!("Failed to complete signing: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(&format!(
                "Failed to complete: {e}"
            )))
        }
    }
}

/// Get TX data for signing
///
/// GET /api/escrow/frost/{id}/sign/tx-data
pub async fn get_tx_data(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    use crate::schema::frost_signing_state;
    use diesel::prelude::*;

    match frost_signing_state::table
        .filter(frost_signing_state::escrow_id.eq(&escrow_id))
        .select((
            frost_signing_state::tx_prefix_hash,
            frost_signing_state::clsag_message_hash,
            frost_signing_state::ring_data_json,
            frost_signing_state::pseudo_out,
            frost_signing_state::recipient_address,
            frost_signing_state::amount_atomic,
        ))
        .first::<(String, String, String, Option<String>, String, String)>(&mut conn)
    {
        Ok(data) => {
            // Get escrow fields for signing
            use crate::schema::escrows;
            let escrow_opt: Option<crate::models::escrow::Escrow> =
                escrows::table.find(&escrow_id).first(&mut conn).ok();

            let multisig_pubkey = escrow_opt
                .as_ref()
                .and_then(|e| e.frost_group_pubkey.clone())
                .unwrap_or_default();

            // Compute pseudo_out_mask from stored params
            use crate::schema::frost_signing_state;
            let pseudo_out_mask = frost_signing_state::table
                .filter(frost_signing_state::escrow_id.eq(&escrow_id))
                .select(frost_signing_state::ring_indices_json)
                .first::<Option<String>>(&mut conn)
                .ok()
                .flatten()
                .and_then(|json| {
                    let params: serde_json::Value = serde_json::from_str(&json).ok()?;
                    let mask_0_hex = params.get("mask_0")?.as_str()?;
                    let mask_1_hex = params.get("mask_1")?.as_str()?;
                    let m0 = hex::decode(mask_0_hex).ok()?;
                    let m1 = hex::decode(mask_1_hex).ok()?;
                    if m0.len() != 32 || m1.len() != 32 {
                        return None;
                    }
                    let mut a0 = [0u8; 32];
                    a0.copy_from_slice(&m0);
                    let mut a1 = [0u8; 32];
                    a1.copy_from_slice(&m1);
                    let s = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(a0)
                        + curve25519_dalek::scalar::Scalar::from_bytes_mod_order(a1);
                    Some(hex::encode(s.to_bytes()))
                });

            HttpResponse::Ok().json(ApiResponse::success(TxSigningData {
                tx_prefix_hash: data.0,
                clsag_message_hash: data.1,
                ring_data_json: data.2,
                pseudo_out: data.3,
                recipient_address: data.4,
                amount_atomic: data.5,
                multisig_pubkey,
                pseudo_out_mask,
                funding_commitment_mask: escrow_opt
                    .as_ref()
                    .and_then(|e| e.funding_commitment_mask.clone()),
                multisig_view_key: escrow_opt
                    .as_ref()
                    .and_then(|e| e.multisig_view_key.clone()),
                funding_tx_pubkey: escrow_opt
                    .as_ref()
                    .and_then(|e| e.funding_tx_pubkey.clone()),
                funding_output_index: escrow_opt.as_ref().and_then(|e| e.funding_output_index),
            }))
        }
        Err(e) => {
            error!("Failed to get TX data: {}", e);
            HttpResponse::NotFound().json(ApiResponse::<()>::error("TX data not found"))
        }
    }
}

/// Get first signer data (for Round-Robin CLSAG)
///
/// GET /api/escrow/frost/{id}/sign/first-signer-data
///
/// Returns buyer's c1, s_values, D, mu_p, mu_c, pseudo_out so vendor can
/// sign as second signer (reuse decoys). Returns 204 if buyer hasn't signed yet.
pub async fn get_first_signer_data(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    session: Session,
) -> HttpResponse {
    let escrow_id = path.into_inner();

    if get_authenticated_identity(&req, &session).is_err() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Not authenticated"));
    }

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("DB connection error: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    match FrostSigningCoordinator::get_first_signer_data(&mut conn, &escrow_id) {
        Ok(Some(data)) => HttpResponse::Ok().json(ApiResponse::success(data)),
        Ok(None) => HttpResponse::NoContent().finish(),
        Err(e) => {
            error!("Failed to get first signer data: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(&format!("Failed: {e}")))
        }
    }
}

/// Configure FROST signing routes
pub fn configure_signing_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/escrow/frost")
            .route("/{id}/sign/init", web::post().to(init_frost_signing))
            .route("/{id}/sign/nonces", web::post().to(submit_nonce_commitment))
            .route("/{id}/sign/nonces", web::get().to(get_nonce_commitments))
            .route(
                "/{id}/sign/partial",
                web::post().to(submit_partial_signature),
            )
            .route("/{id}/sign/status", web::get().to(get_signing_status))
            .route(
                "/{id}/sign/complete",
                web::post().to(complete_and_broadcast),
            )
            .route("/{id}/sign/tx-data", web::get().to(get_tx_data))
            .route(
                "/{id}/sign/first-signer-data",
                web::get().to(get_first_signer_data),
            ),
    );
}
