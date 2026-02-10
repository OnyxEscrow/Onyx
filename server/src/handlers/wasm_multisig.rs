use crate::crypto::view_key::validate_view_key_matches_address;
use crate::db::DbPool;
use crate::handlers::error_codes;
use crate::logging::sanitize::{sanitize_address, sanitize_escrow_id, sanitize_view_key};
use crate::models::escrow::Escrow;
use crate::models::wasm_multisig_info::{SqliteWasmMultisigStore, WasmMultisigInfoRow};
use actix_web::{get, post, web, HttpResponse};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// Re-export SQLite store for use in main.rs
pub use crate::models::wasm_multisig_info::SqliteWasmMultisigStore as WasmMultisigStoreSqlite;

/// Participant data for multisig coordination
#[derive(Clone)]
pub struct MultisigParticipant {
    pub role: String,
    pub multisig_info: String,
    pub view_key_component: Option<String>, // Private view key for b_shared = sum(b_i)
}

impl From<WasmMultisigInfoRow> for MultisigParticipant {
    fn from(row: WasmMultisigInfoRow) -> Self {
        Self {
            role: row.role,
            multisig_info: row.multisig_info,
            view_key_component: row.view_key_component,
        }
    }
}

/// DEPRECATED: In-memory WasmMultisigStore - use SqliteWasmMultisigStore instead
///
/// This struct is kept for backward compatibility during migration.
/// All new code should use `SqliteWasmMultisigStore` from `crate::models::wasm_multisig_info`.
#[deprecated(
    since = "0.6.0",
    note = "Use SqliteWasmMultisigStore for persistent storage. In-memory store loses data on restart."
)]
pub struct WasmMultisigStore {
    // Map: escrow_id -> Vec<MultisigParticipant>
    infos: std::sync::Mutex<std::collections::HashMap<String, Vec<MultisigParticipant>>>,
}

#[allow(deprecated)]
impl WasmMultisigStore {
    pub fn new() -> Arc<Self> {
        tracing::warn!(
            "WasmMultisigStore::new() is deprecated. Use SqliteWasmMultisigStore::new(pool) instead."
        );
        Arc::new(Self {
            infos: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    pub fn submit(&self, escrow_id: &str, role: &str, info: &str, view_key: Option<&str>) -> usize {
        let mut infos = self.infos.lock().unwrap();
        let entry = infos.entry(escrow_id.to_string()).or_insert_with(Vec::new);

        let participant = MultisigParticipant {
            role: role.to_string(),
            multisig_info: info.to_string(),
            view_key_component: view_key.map(|s| s.to_string()),
        };

        // Check if this role already submitted
        if let Some(pos) = entry.iter().position(|p| p.role == role) {
            entry[pos] = participant;
        } else {
            entry.push(participant);
        }

        entry.len()
    }

    pub fn get_peer_infos(&self, escrow_id: &str, my_role: &str) -> Vec<MultisigParticipant> {
        let infos = self.infos.lock().unwrap();
        if let Some(entry) = infos.get(escrow_id) {
            let mut peers: Vec<_> = entry
                .iter()
                .filter(|p| p.role != my_role)
                .cloned()
                .collect();

            peers.sort_by(|a, b| a.role.cmp(&b.role));
            peers
        } else {
            Vec::new()
        }
    }
}

#[derive(Deserialize)]
pub struct SubmitInfoRequest {
    pub escrow_id: String,
    pub role: String, // "buyer", "vendor", or "arbiter"
    pub multisig_info: String,
    /// Private view key component for this participant (64 hex chars)
    /// Required for Monero multisig: b_shared = b_buyer + b_vendor + b_arbiter (mod l)
    pub view_key_component: Option<String>,
}

#[derive(Serialize)]
pub struct SubmitInfoResponse {
    pub count: usize,
}

#[derive(Serialize)]
pub struct PeerInfo {
    pub role: String,
    pub multisig_info: String,
    /// Private view key component from this peer (for b_shared calculation)
    pub view_key_component: Option<String>,
}

#[derive(Serialize)]
pub struct PeerInfosResponse {
    pub count: usize,
    pub peer_infos: Vec<PeerInfo>,
}

/// Submit multisig info using SQLite-backed store (recommended)
#[post("/wasm-multisig/submit")]
pub async fn submit_multisig_info(
    req: web::Json<SubmitInfoRequest>,
    store: web::Data<Arc<SqliteWasmMultisigStore>>,
) -> HttpResponse {
    // Validate view_key_component if provided (must be 64 hex chars)
    if let Some(ref vk) = req.view_key_component {
        if vk.len() != 64 || !vk.chars().all(|c| c.is_ascii_hexdigit()) {
            return error_codes::invalid_key_format();
        }
        tracing::info!(
            "🔑 [WASM Submit] Escrow {} - Role {} with view key: {}",
            sanitize_escrow_id(&req.escrow_id),
            req.role,
            sanitize_view_key(vk)
        );
    }

    match store.submit(
        &req.escrow_id,
        &req.role,
        &req.multisig_info,
        req.view_key_component.as_deref(),
    ) {
        Ok(count) => HttpResponse::Ok().json(SubmitInfoResponse { count }),
        Err(e) => {
            tracing::error!(
                "❌ [WASM Submit] Failed to store info for escrow {}: {}",
                sanitize_escrow_id(&req.escrow_id),
                e
            );
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Failed to store multisig info"
            }))
        }
    }
}

/// Get peer infos using SQLite-backed store (recommended)
#[get("/wasm-multisig/peer-infos/{escrow_id}/{role}")]
pub async fn get_peer_infos(
    path: web::Path<(String, String)>,
    store: web::Data<Arc<SqliteWasmMultisigStore>>,
) -> HttpResponse {
    let (escrow_id, role) = path.into_inner();

    match store.get_peer_infos(&escrow_id, &role) {
        Ok(peers) => {
            let count = peers.len();

            // Convert to structured response with roles and view keys
            let peer_infos: Vec<PeerInfo> = peers
                .into_iter()
                .map(|row| PeerInfo {
                    role: row.role,
                    multisig_info: row.multisig_info,
                    view_key_component: row.view_key_component,
                })
                .collect();

            HttpResponse::Ok().json(PeerInfosResponse { count, peer_infos })
        }
        Err(e) => {
            tracing::error!(
                "❌ [WASM Peer Infos] Failed to get peer infos for escrow {}: {}",
                sanitize_escrow_id(&escrow_id),
                e
            );
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Failed to retrieve peer infos"
            }))
        }
    }
}

// ============================================================================
// FINALIZATION ENDPOINT - Saves multisig address to database
// ============================================================================

#[derive(Deserialize)]
pub struct FinalizeMultisigRequest {
    pub escrow_id: String,
    pub role: String,
    pub multisig_address: String,
    /// Shared private view key for server-side balance monitoring (64 hex chars)
    /// All 3 participants generate the same key deterministically
    pub shared_view_key: Option<String>,
}

#[derive(Serialize)]
pub struct FinalizeMultisigResponse {
    pub success: bool,
    pub message: String,
}

/// Finalize WASM multisig - saves the generated address to the database
///
/// This endpoint is called by the frontend after make_multisig() completes.
/// Only the public multisig address is transmitted (no private keys).
#[post("/wasm-multisig/finalize")]
pub async fn finalize_multisig(
    req: web::Json<FinalizeMultisigRequest>,
    pool: web::Data<DbPool>,
) -> HttpResponse {
    tracing::info!(
        "🔐 [WASM Finalize] Escrow {} - Role {} submitting address: {}",
        sanitize_escrow_id(&req.escrow_id),
        req.role,
        sanitize_address(&req.multisig_address)
    );

    // Validate Monero address format (mainnet: 4/8, stagenet: 5/7, testnet: 9/A/B)
    let first_char = req.multisig_address.chars().next().unwrap_or('0');
    if !matches!(first_char, '4' | '5' | '7' | '8' | '9' | 'A' | 'B') {
        tracing::warn!(
            "❌ [WASM Finalize] Invalid address format for escrow {}: starts with '{}'",
            sanitize_escrow_id(&req.escrow_id),
            first_char
        );
        return error_codes::invalid_address_format();
    }

    // Validate address length (Monero addresses are 95 characters)
    if req.multisig_address.len() != 95 {
        tracing::warn!(
            "❌ [WASM Finalize] Invalid address length for escrow {}: {} chars (expected 95)",
            sanitize_escrow_id(&req.escrow_id),
            req.multisig_address.len()
        );
        return error_codes::invalid_address_format();
    }

    // Validate shared view key if provided (must be 64 hex characters)
    if let Some(ref view_key) = req.shared_view_key {
        if view_key.len() != 64 {
            tracing::warn!(
                "❌ [WASM Finalize] Invalid view key length for escrow {}: {} chars (expected 64)",
                sanitize_escrow_id(&req.escrow_id),
                view_key.len()
            );
            return error_codes::invalid_key_format();
        }
        if !view_key.chars().all(|c| c.is_ascii_hexdigit()) {
            tracing::warn!(
                "❌ [WASM Finalize] Invalid view key format for escrow {}: not hex",
                sanitize_escrow_id(&req.escrow_id)
            );
            return error_codes::invalid_key_format();
        }
        tracing::info!(
            "🔑 [WASM Finalize] Escrow {} - View key provided: {}",
            sanitize_escrow_id(&req.escrow_id),
            sanitize_view_key(view_key)
        );

        // CRITICAL: Cryptographic validation - view key must derive to address's view public key
        match validate_view_key_matches_address(view_key, &req.multisig_address) {
            Ok(true) => {
                tracing::info!(
                    "✅ [WASM Finalize] View key VALIDATED for escrow {} - matches address cryptographically",
                    sanitize_escrow_id(&req.escrow_id)
                );
            }
            Ok(false) => {
                tracing::error!(
                    "🚨 [WASM Finalize] VIEW KEY MISMATCH for escrow {}! Key does NOT derive to address",
                    sanitize_escrow_id(&req.escrow_id)
                );
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid view key - does not match multisig address",
                    "code": "VIEW_KEY_MISMATCH"
                }));
            }
            Err(e) => {
                tracing::error!(
                    "❌ [WASM Finalize] View key validation error for escrow {}: {}",
                    sanitize_escrow_id(&req.escrow_id),
                    e
                );
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": format!("View key validation failed: {}", e),
                    "code": "VIEW_KEY_VALIDATION_ERROR"
                }));
            }
        }
    }

    // Check if address is already set (idempotency - allow multiple submissions)
    let escrow_id_for_query = req.escrow_id.clone();
    let pool_for_query = pool.clone();

    let existing_escrow = match tokio::task::spawn_blocking(move || {
        let mut conn = pool_for_query
            .get()
            .context("Failed to get DB connection")?;

        use crate::schema::escrows::dsl::*;
        use diesel::prelude::*;

        escrows
            .filter(id.eq(escrow_id_for_query))
            .select(multisig_address)
            .first::<Option<String>>(&mut conn)
            .context("Failed to query escrow")
    })
    .await
    {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => {
            tracing::error!(
                "❌ [WASM Finalize] Failed to query escrow {}: {}",
                sanitize_escrow_id(&req.escrow_id),
                e
            );
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to query escrow: {}", e)
            }));
        }
        Err(e) => {
            tracing::error!("❌ [WASM Finalize] Task join error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Internal server error"
            }));
        }
    };

    // If address already set, verify it matches (all 3 roles should generate same address)
    if let Some(existing_addr) = existing_escrow {
        if existing_addr != req.multisig_address {
            tracing::error!(
                "❌ [WASM Finalize] ADDRESS MISMATCH for escrow {}! Existing: {}, New: {}",
                sanitize_escrow_id(&req.escrow_id),
                sanitize_address(&existing_addr),
                sanitize_address(&req.multisig_address)
            );
            return HttpResponse::Conflict().json(serde_json::json!({
                "success": false,
                "error": "Address mismatch - deterministic generation failed"
            }));
        }

        // Address matches - but still need to save view key if provided
        if let Some(ref view_key) = req.shared_view_key {
            let escrow_id_for_view_key = req.escrow_id.clone();
            let view_key_for_update = view_key.clone();
            let pool_for_view_key = pool.clone();

            match tokio::task::spawn_blocking(move || {
                let mut conn = pool_for_view_key
                    .get()
                    .context("Failed to get DB connection")?;
                Escrow::update_multisig_view_key(
                    &mut conn,
                    escrow_id_for_view_key,
                    &view_key_for_update,
                )?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            {
                Ok(Ok(_)) => {
                    tracing::info!(
                        "✅ [WASM Finalize] View key updated for escrow {} (address was already set)",
                        sanitize_escrow_id(&req.escrow_id)
                    );
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        "⚠️ [WASM Finalize] Failed to update view key for escrow {}: {}",
                        sanitize_escrow_id(&req.escrow_id),
                        e
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "❌ [WASM Finalize] Task join error updating view key: {}",
                        e
                    );
                }
            }
        }

        tracing::info!(
            "✅ [WASM Finalize] Address already set for escrow {} - idempotent success",
            sanitize_escrow_id(&req.escrow_id)
        );
        return HttpResponse::Ok().json(FinalizeMultisigResponse {
            success: true,
            message: "Address already saved (idempotent)".to_string(),
        });
    }

    // Update multisig address in database
    let escrow_id_clone = req.escrow_id.clone();
    let address_clone = req.multisig_address.clone();
    let view_key_clone = req.shared_view_key.clone();
    let pool_for_update = pool.clone();

    match tokio::task::spawn_blocking(move || {
        let mut conn = pool_for_update
            .get()
            .context("Failed to get DB connection")?;

        // Save address
        Escrow::update_multisig_address(&mut conn, escrow_id_clone.clone(), &address_clone)?;

        // Save view key if provided (only first submitter's key is stored, all are identical)
        if let Some(ref view_key) = view_key_clone {
            Escrow::update_multisig_view_key(&mut conn, escrow_id_clone, view_key)?;
        }

        Ok::<_, anyhow::Error>(())
    })
    .await
    {
        Ok(Ok(_)) => {
            let view_key_msg = if req.shared_view_key.is_some() {
                " + view key"
            } else {
                ""
            };

            tracing::info!(
                "✅ [WASM Finalize] Multisig address{} saved for escrow {} by role {}: {}",
                view_key_msg,
                sanitize_escrow_id(&req.escrow_id),
                req.role,
                sanitize_address(&req.multisig_address)
            );

            HttpResponse::Ok().json(FinalizeMultisigResponse {
                success: true,
                message: format!("Multisig address{} saved successfully", view_key_msg),
            })
        }
        Ok(Err(e)) => {
            tracing::error!(
                "❌ [WASM Finalize] Failed to save address for escrow {}: {}",
                sanitize_escrow_id(&req.escrow_id),
                e
            );

            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to save address: {}", e)
            }))
        }
        Err(e) => {
            tracing::error!(
                "❌ [WASM Finalize] Task join error for escrow {}: {}",
                sanitize_escrow_id(&req.escrow_id),
                e
            );

            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Internal server error"
            }))
        }
    }
}
