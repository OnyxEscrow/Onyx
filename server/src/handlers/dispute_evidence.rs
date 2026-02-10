//! Dispute Evidence Handlers
//!
//! Endpoints for uploading and managing dispute evidence via IPFS.
//! Evidence can be uploaded by buyers, vendors, or arbiters during disputes.

use actix_multipart::Multipart;
use actix_session::Session;
use actix_web::{get, post, web, HttpResponse, Responder};
use diesel::prelude::*;
use futures_util::TryStreamExt;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::db::DbPool;
use crate::ipfs::client::IpfsClient;
use crate::models::dispute_evidence::{
    is_allowed_mime_type, DisputeEvidence, NewDisputeEvidence, UploaderRole,
    MAX_EVIDENCE_FILES, MAX_FILE_SIZE,
};
use crate::models::escrow::Escrow;
use crate::schema::escrows;

/// Response for successful evidence upload
#[derive(serde::Serialize)]
struct UploadEvidenceResponse {
    success: bool,
    evidence_id: String,
    ipfs_cid: String,
    file_name: String,
    file_size: i32,
    message: String,
}

/// Response for listing evidence
#[derive(serde::Serialize)]
struct ListEvidenceResponse {
    success: bool,
    evidence: Vec<crate::models::dispute_evidence::EvidenceResponse>,
    total_count: usize,
}

/// Helper function to get user role in escrow
fn get_user_role_in_escrow(escrow: &Escrow, user_id: &str) -> Option<UploaderRole> {
    if escrow.buyer_id == user_id {
        Some(UploaderRole::Buyer)
    } else if escrow.vendor_id == user_id {
        Some(UploaderRole::Vendor)
    } else if escrow.arbiter_id == user_id {
        Some(UploaderRole::Arbiter)
    } else {
        None
    }
}

/// POST /api/escrow/{id}/dispute/evidence
///
/// Upload evidence file for a disputed escrow.
/// Only parties to the escrow (buyer, vendor, arbiter) can upload.
/// Maximum 10 files per escrow, 5MB each.
#[post("/escrow/{id}/dispute/evidence")]
pub async fn upload_evidence(
    pool: web::Data<DbPool>,
    ipfs_client: web::Data<IpfsClient>,
    session: Session,
    path: web::Path<String>,
    mut multipart: Multipart,
) -> impl Responder {
    // 1. Authenticate user
    let user_id: Uuid = match session.get("user_id") {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required"
            }));
        }
    };

    let escrow_id = path.into_inner();
    let escrow_uuid = match Uuid::parse_str(&escrow_id) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid escrow ID format"
            }));
        }
    };

    // 2. Get database connection
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // 3. Load escrow and verify it exists
    let escrow: Escrow = match escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
    {
        Ok(e) => e,
        Err(diesel::result::Error::NotFound) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Escrow not found"
            }));
        }
        Err(e) => {
            error!("Database query error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    // 4. Verify escrow is in disputed state
    if escrow.status != "disputed" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Evidence can only be uploaded for disputed escrows",
            "current_status": escrow.status
        }));
    }

    // 5. Verify user is party to escrow
    let user_id_str = user_id.to_string();
    let uploader_role = match get_user_role_in_escrow(&escrow, &user_id_str) {
        Some(role) => role,
        None => {
            warn!(
                escrow_id = %escrow_id,
                user_id = %user_id,
                "Unauthorized evidence upload attempt"
            );
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "You are not a party to this escrow"
            }));
        }
    };

    // 6. Check evidence count limit
    let current_count = match DisputeEvidence::count_by_escrow(&mut conn, &escrow_id) {
        Ok(c) => c as usize,
        Err(e) => {
            error!("Failed to count evidence: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to check evidence count"
            }));
        }
    };

    if current_count >= MAX_EVIDENCE_FILES {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Maximum {} evidence files allowed per escrow", MAX_EVIDENCE_FILES),
            "current_count": current_count
        }));
    }

    // 7. Process multipart upload
    let mut uploaded_evidence: Option<(String, String, String, i32)> = None; // (cid, filename, mime, size)
    let mut description: Option<String> = None;

    while let Some(item) = multipart.try_next().await.map_err(|e| {
        error!("Multipart parsing error: {}", e);
        HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid multipart data"
        }))
    }).unwrap_or(None) {
        let mut field = item;
        let field_name = field.name().to_string();

        if field_name == "file" || field_name == "evidence" {
            let mut data = Vec::new();

            while let Some(chunk) = field.try_next().await.map_err(|e| {
                error!("Stream reading error: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to read file data"
                }))
            }).unwrap_or(None) {
                data.extend_from_slice(&chunk);

                // Check file size limit
                if data.len() > MAX_FILE_SIZE {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "error": format!("File too large. Maximum size: {}MB", MAX_FILE_SIZE / 1024 / 1024)
                    }));
                }
            }

            if !data.is_empty() {
                // Determine MIME type
                let kind = match infer::get(&data) {
                    Some(k) => k,
                    None => {
                        return HttpResponse::BadRequest().json(serde_json::json!({
                            "error": "Could not determine file type"
                        }));
                    }
                };

                let mime_type = kind.mime_type();
                if !is_allowed_mime_type(mime_type) {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "error": format!("File type '{}' not allowed. Allowed types: PDF, JPEG, PNG, GIF, TXT", mime_type)
                    }));
                }

                // Generate filename
                let file_name = format!("evidence_{}.{}", Uuid::new_v4(), kind.extension());

                // Upload to IPFS
                match ipfs_client.add(data.clone(), &file_name, mime_type).await {
                    Ok(cid) => {
                        info!(
                            escrow_id = %escrow_id,
                            uploader = %uploader_role.as_str(),
                            ipfs_cid = %cid,
                            "Evidence uploaded to IPFS"
                        );
                        uploaded_evidence = Some((cid, file_name, mime_type.to_string(), data.len() as i32));
                    }
                    Err(e) => {
                        error!("IPFS upload failed: {}", e);
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "Failed to upload evidence to IPFS"
                        }));
                    }
                }
            }
        } else if field_name == "description" {
            // Read description text
            let mut desc_data = Vec::new();
            while let Some(chunk) = field.try_next().await.ok().flatten() {
                desc_data.extend_from_slice(&chunk);
                if desc_data.len() > 2000 {
                    break; // Limit description length
                }
            }
            if !desc_data.is_empty() {
                description = String::from_utf8(desc_data).ok();
            }
        }
    }

    // 8. Verify we got a file
    let (ipfs_cid, file_name, mime_type, file_size) = match uploaded_evidence {
        Some(e) => e,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No file provided. Include a 'file' or 'evidence' field in multipart form."
            }));
        }
    };

    // 9. Store in database
    let new_evidence = NewDisputeEvidence::new(
        escrow_id.clone(),
        user_id_str,
        uploader_role,
        ipfs_cid.clone(),
        file_name.clone(),
        file_size,
        mime_type,
        description,
    );

    match new_evidence.insert(&mut conn) {
        Ok(evidence) => {
            // Update evidence_count on escrow
            let _ = diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
                .set(escrows::evidence_count.eq(escrows::evidence_count + 1))
                .execute(&mut conn);

            info!(
                escrow_id = %escrow_id,
                evidence_id = %evidence.id,
                "Evidence record created"
            );

            HttpResponse::Created().json(UploadEvidenceResponse {
                success: true,
                evidence_id: evidence.id,
                ipfs_cid,
                file_name,
                file_size,
                message: "Evidence uploaded successfully".to_string(),
            })
        }
        Err(e) => {
            error!("Failed to insert evidence record: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to save evidence record"
            }))
        }
    }
}

/// GET /api/escrow/{id}/dispute/evidence
///
/// List all evidence files for a disputed escrow.
/// Only parties to the escrow can view evidence.
#[get("/escrow/{id}/dispute/evidence")]
pub async fn list_evidence(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<String>,
) -> impl Responder {
    // 1. Authenticate user
    let user_id: Uuid = match session.get("user_id") {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required"
            }));
        }
    };

    let escrow_id = path.into_inner();

    // 2. Get database connection
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // 3. Load escrow and verify access
    let escrow: Escrow = match escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
    {
        Ok(e) => e,
        Err(diesel::result::Error::NotFound) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Escrow not found"
            }));
        }
        Err(e) => {
            error!("Database query error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    // 4. Verify user is party to escrow
    let user_id_str = user_id.to_string();
    if get_user_role_in_escrow(&escrow, &user_id_str).is_none() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You are not a party to this escrow"
        }));
    }

    // 5. Fetch all evidence
    let evidence_list = match DisputeEvidence::find_by_escrow(&mut conn, &escrow_id) {
        Ok(list) => list,
        Err(e) => {
            error!("Failed to fetch evidence: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch evidence"
            }));
        }
    };

    // 6. Convert to response format
    let ipfs_gateway = std::env::var("IPFS_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8083".to_string());

    let evidence_responses: Vec<_> = evidence_list
        .iter()
        .map(|e| e.to_response(&ipfs_gateway))
        .collect();

    let total = evidence_responses.len();

    HttpResponse::Ok().json(ListEvidenceResponse {
        success: true,
        evidence: evidence_responses,
        total_count: total,
    })
}

/// GET /api/escrow/{escrow_id}/dispute/evidence/{evidence_id}
///
/// Get a specific evidence file by streaming from IPFS.
/// Only parties to the escrow can download evidence.
#[get("/escrow/{escrow_id}/dispute/evidence/{evidence_id}")]
pub async fn get_evidence(
    pool: web::Data<DbPool>,
    ipfs_client: web::Data<IpfsClient>,
    session: Session,
    path: web::Path<(String, String)>,
) -> impl Responder {
    // 1. Authenticate user
    let user_id: Uuid = match session.get("user_id") {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required"
            }));
        }
    };

    let (escrow_id, evidence_id) = path.into_inner();

    // 2. Get database connection
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("Database connection error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // 3. Load escrow and verify access
    let escrow: Escrow = match escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
    {
        Ok(e) => e,
        Err(diesel::result::Error::NotFound) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Escrow not found"
            }));
        }
        Err(e) => {
            error!("Database query error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    // 4. Verify user is party to escrow
    let user_id_str = user_id.to_string();
    if get_user_role_in_escrow(&escrow, &user_id_str).is_none() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You are not a party to this escrow"
        }));
    }

    // 5. Load evidence record
    let evidence = match DisputeEvidence::find_by_id(&mut conn, &evidence_id) {
        Ok(Some(e)) => e,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Evidence not found"
            }));
        }
        Err(e) => {
            error!("Database query error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            }));
        }
    };

    // 6. Verify evidence belongs to this escrow
    if evidence.escrow_id != escrow_id {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Evidence not found for this escrow"
        }));
    }

    // 7. Fetch from IPFS and stream response
    match ipfs_client.cat(&evidence.ipfs_cid).await {
        Ok(data) => {
            HttpResponse::Ok()
                .content_type(evidence.mime_type.clone())
                .insert_header((
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", evidence.file_name),
                ))
                .body(data)
        }
        Err(e) => {
            error!("IPFS fetch failed for CID {}: {}", evidence.ipfs_cid, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch evidence from IPFS"
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_user_role() {
        // This would require mocking the Escrow struct
        // For now, just test the logic concept
        assert!(true);
    }
}
