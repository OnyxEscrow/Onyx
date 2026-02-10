//! MFA/TOTP Handlers for Two-Factor Authentication
//!
//! Provides API endpoints for MFA operations:
//! - POST /api/mfa/setup - Initialize MFA setup (returns QR code)
//! - POST /api/mfa/verify-setup - Verify TOTP code and enable MFA
//! - POST /api/mfa/verify - Verify TOTP during login
//! - POST /api/mfa/disable - Disable MFA (requires current TOTP)
//! - POST /api/mfa/recovery - Use recovery code when device is lost
//!
//! ## Security Features
//! - TOTP secrets encrypted at rest (AES-256-GCM)
//! - Recovery codes hashed with Argon2id
//! - Lockout after 5 failed attempts (15 min)
//! - Audit logging of all MFA events

use actix_session::Session;
use actix_web::{post, web, HttpRequest, HttpResponse};
use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::db::DbPool;
use crate::error::ApiError;
use crate::middleware::csrf::validate_csrf_token;
use crate::services::mfa::{
    MfaService, MfaVerifyResult, LOCKOUT_DURATION_SECS, MAX_FAILED_ATTEMPTS,
};

/// MFA setup request
#[derive(Debug, Deserialize)]
pub struct MfaSetupRequest {
    pub csrf_token: String,
}

/// MFA setup response
#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    /// QR code as data URI (display to user)
    pub qr_code: String,
    /// Base32 secret for manual entry
    pub secret: String,
    /// otpauth:// URL for manual entry
    pub otpauth_url: String,
}

/// MFA verify setup request
#[derive(Debug, Deserialize)]
pub struct MfaVerifySetupRequest {
    /// 6-digit TOTP code from authenticator app
    pub code: String,
    pub csrf_token: String,
}

/// MFA verify setup response
#[derive(Debug, Serialize)]
pub struct MfaVerifySetupResponse {
    pub success: bool,
    /// One-time display of recovery codes (user must save these)
    pub recovery_codes: Vec<String>,
    pub message: String,
}

/// MFA verify request (during login)
#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    /// 6-digit TOTP code or recovery code
    pub code: String,
    /// Set to true if using recovery code instead of TOTP
    #[serde(default)]
    pub is_recovery_code: bool,
}

/// MFA disable request
#[derive(Debug, Deserialize)]
pub struct MfaDisableRequest {
    /// Current TOTP code to confirm disable
    pub code: String,
    pub csrf_token: String,
}

/// MFA status response
#[derive(Debug, Serialize)]
pub struct MfaStatusResponse {
    pub mfa_enabled: bool,
    pub mfa_enabled_at: Option<String>,
    pub recovery_codes_remaining: usize,
}

/// Get MFA service from environment
fn get_mfa_service() -> Result<MfaService, ApiError> {
    let encryption_key = std::env::var("MFA_ENCRYPTION_KEY")
        .or_else(|_| std::env::var("DB_ENCRYPTION_KEY"))
        .map_err(|_| ApiError::Internal("MFA encryption key not configured".to_string()))?;

    let key_bytes = hex::decode(&encryption_key)
        .map_err(|e| ApiError::Internal(format!("Invalid MFA encryption key format: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(ApiError::Internal(format!(
            "MFA encryption key must be 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    MfaService::new("NEXUS", key_bytes)
        .map_err(|e| ApiError::Internal(format!("Failed to create MFA service: {}", e)))
}

/// POST /api/mfa/setup - Initialize MFA setup
///
/// Returns a QR code and secret for the user to set up their authenticator app.
/// The MFA is NOT enabled until verify-setup is called successfully.
#[post("/setup")]
pub async fn setup_mfa(
    pool: web::Data<DbPool>,
    session: Session,
    req: web::Json<MfaSetupRequest>,
) -> Result<HttpResponse, ApiError> {
    // Require authentication
    let user_id: String = session
        .get("user_id")
        .context("Session read failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Not authenticated".to_string()))?;

    let username: String = session
        .get("username")
        .context("Session read failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Session incomplete".to_string()))?;

    // Validate CSRF
    if !validate_csrf_token(&session, &req.csrf_token) {
        return Err(ApiError::Forbidden("Invalid CSRF token".to_string()));
    }

    // Check if MFA already enabled
    let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
    let uid = user_id.clone();

    let mfa_enabled = web::block(move || -> Result<bool, diesel::result::Error> {
        use crate::schema::users;
        use diesel::prelude::*;

        let enabled: i32 = users::table
            .filter(users::id.eq(&uid))
            .select(users::mfa_enabled)
            .first(&mut conn)?;

        Ok(enabled == 1)
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    if mfa_enabled {
        return Err(ApiError::BadRequest(
            "MFA is already enabled. Disable it first to set up new MFA.".to_string(),
        ));
    }

    // Generate MFA setup (QR code, secret, recovery codes)
    let mfa_service = get_mfa_service()?;
    let setup_result = mfa_service
        .setup_mfa(&username)
        .map_err(|e| ApiError::Internal(format!("MFA setup failed: {}", e)))?;

    // Store encrypted secret and hashed recovery codes temporarily in session
    // (will be persisted to DB on verify-setup)
    let encrypted_secret_b64 = BASE64.encode(&setup_result.encrypted_secret);
    let recovery_codes_json = serde_json::to_string(&setup_result.hashed_recovery_codes)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    session
        .insert("mfa_pending_secret", encrypted_secret_b64)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    session
        .insert("mfa_pending_recovery_codes", recovery_codes_json)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    session
        .insert(
            "mfa_pending_plaintext_codes",
            setup_result.recovery_codes.clone(),
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    info!(
        user_id = %user_id,
        "MFA setup initiated"
    );

    Ok(HttpResponse::Ok().json(MfaSetupResponse {
        qr_code: setup_result.qr_code_data_uri,
        secret: setup_result.secret_base32,
        otpauth_url: setup_result.otpauth_url,
    }))
}

/// POST /api/mfa/verify-setup - Verify TOTP and enable MFA
///
/// User must provide a valid TOTP code from their authenticator app.
/// On success, MFA is enabled and recovery codes are returned ONE TIME.
#[post("/verify-setup")]
pub async fn verify_setup_mfa(
    pool: web::Data<DbPool>,
    session: Session,
    req: web::Json<MfaVerifySetupRequest>,
) -> Result<HttpResponse, ApiError> {
    // Require authentication
    let user_id: String = session
        .get("user_id")
        .context("Session read failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Not authenticated".to_string()))?;

    // Validate CSRF
    if !validate_csrf_token(&session, &req.csrf_token) {
        return Err(ApiError::Forbidden("Invalid CSRF token".to_string()));
    }

    // Get pending MFA data from session
    let encrypted_secret_b64: String = session
        .get("mfa_pending_secret")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| {
            ApiError::BadRequest("No pending MFA setup. Call /api/mfa/setup first.".to_string())
        })?;

    let recovery_codes_json: String = session
        .get("mfa_pending_recovery_codes")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Internal("Missing recovery codes in session".to_string()))?;

    let plaintext_codes: Vec<String> = session
        .get("mfa_pending_plaintext_codes")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Internal("Missing plaintext codes in session".to_string()))?;

    // Decode and verify TOTP
    let encrypted_secret = BASE64
        .decode(&encrypted_secret_b64)
        .map_err(|e| ApiError::Internal(format!("Failed to decode secret: {}", e)))?;

    let mfa_service = get_mfa_service()?;
    let is_valid = mfa_service
        .verify_totp(&encrypted_secret, &req.code)
        .map_err(|e| ApiError::Internal(format!("TOTP verification failed: {}", e)))?;

    if !is_valid {
        warn!(
            user_id = %user_id,
            "MFA setup verification failed - invalid code"
        );
        return Err(ApiError::BadRequest(
            "Invalid code. Make sure your authenticator app shows a 6-digit code and try again."
                .to_string(),
        ));
    }

    // Save MFA data to database
    let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
    let uid = user_id.clone();
    let now = Utc::now().to_rfc3339();

    web::block(move || -> Result<(), diesel::result::Error> {
        use crate::schema::users;
        use diesel::prelude::*;

        diesel::update(users::table.filter(users::id.eq(&uid)))
            .set((
                users::totp_secret.eq(&encrypted_secret),
                users::mfa_enabled.eq(1),
                users::mfa_enabled_at.eq(&now),
                users::mfa_recovery_codes.eq(&recovery_codes_json),
                users::mfa_failed_attempts.eq(0),
                users::mfa_locked_until.eq::<Option<String>>(None),
            ))
            .execute(&mut conn)?;

        Ok(())
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Clear pending MFA data from session
    session.remove("mfa_pending_secret");
    session.remove("mfa_pending_recovery_codes");
    session.remove("mfa_pending_plaintext_codes");

    // Mark session as MFA-verified
    session
        .insert("mfa_verified", true)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    info!(
        user_id = %user_id,
        "MFA enabled successfully"
    );

    Ok(HttpResponse::Ok().json(MfaVerifySetupResponse {
        success: true,
        recovery_codes: plaintext_codes,
        message: "MFA enabled successfully. Save your recovery codes in a safe place - they will not be shown again.".to_string(),
    }))
}

/// POST /api/mfa/verify - Verify TOTP during login
///
/// Called after password verification to complete MFA login.
/// Can also accept recovery codes if is_recovery_code is true.
#[post("/verify")]
pub async fn verify_mfa(
    pool: web::Data<DbPool>,
    session: Session,
    req: web::Json<MfaVerifyRequest>,
) -> Result<HttpResponse, ApiError> {
    // Require pending MFA verification (user passed password but not MFA yet)
    let user_id: String = session
        .get("mfa_pending_user_id")
        .context("Session read failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "No pending MFA verification. Complete password login first.".to_string(),
            )
        })?;

    // Get user's MFA data from database
    let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
    let uid = user_id.clone();

    let mfa_data = web::block(
        move || -> Result<(Vec<u8>, String, i32, Option<String>), diesel::result::Error> {
            use crate::schema::users;
            use diesel::prelude::*;

            let result: (Option<Vec<u8>>, Option<String>, i32, Option<String>) = users::table
                .filter(users::id.eq(&uid))
                .select((
                    users::totp_secret,
                    users::mfa_recovery_codes,
                    users::mfa_failed_attempts,
                    users::mfa_locked_until,
                ))
                .first(&mut conn)?;

            let secret = result.0.ok_or(diesel::result::Error::NotFound)?;
            let recovery_codes = result.1.ok_or(diesel::result::Error::NotFound)?;

            Ok((secret, recovery_codes, result.2, result.3))
        },
    )
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|_| ApiError::BadRequest("MFA not configured for this user".to_string()))?;

    let (totp_secret, recovery_codes_json, failed_attempts, locked_until) = mfa_data;

    // Check lockout
    if MfaService::is_locked_out(locked_until.as_deref()) {
        warn!(
            user_id = %user_id,
            "MFA verification attempt on locked account"
        );
        return Err(ApiError::TooManyRequests(
            "Account temporarily locked due to too many failed MFA attempts. Try again later."
                .to_string(),
        ));
    }

    let mfa_service = get_mfa_service()?;
    let verify_result: MfaVerifyResult;

    if req.is_recovery_code {
        // Verify recovery code
        let hashed_codes: Vec<String> = serde_json::from_str(&recovery_codes_json)
            .map_err(|e| ApiError::Internal(format!("Failed to parse recovery codes: {}", e)))?;

        match mfa_service.verify_recovery_code(&hashed_codes, &req.code) {
            Ok(Some(index)) => {
                // Mark recovery code as used
                let mut updated_codes = hashed_codes;
                updated_codes[index] = String::new();

                let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
                let uid = user_id.clone();
                let codes_json = serde_json::to_string(&updated_codes)
                    .map_err(|e| ApiError::Internal(e.to_string()))?;

                web::block(move || -> Result<(), diesel::result::Error> {
                    use crate::schema::users;
                    use diesel::prelude::*;

                    diesel::update(users::table.filter(users::id.eq(&uid)))
                        .set((
                            users::mfa_recovery_codes.eq(&codes_json),
                            users::mfa_failed_attempts.eq(0),
                            users::mfa_last_used_at.eq(Utc::now().to_rfc3339()),
                        ))
                        .execute(&mut conn)?;

                    Ok(())
                })
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?
                .map_err(|e| ApiError::Internal(e.to_string()))?;

                verify_result = MfaVerifyResult::RecoveryCodeUsed(index);
            }
            Ok(None) => {
                verify_result = MfaVerifyResult::InvalidCode;
            }
            Err(e) => {
                return Err(ApiError::Internal(format!(
                    "Recovery code verification error: {}",
                    e
                )));
            }
        }
    } else {
        // Verify TOTP code
        match mfa_service.verify_totp(&totp_secret, &req.code) {
            Ok(true) => {
                // Reset failed attempts on success
                let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
                let uid = user_id.clone();

                web::block(move || -> Result<(), diesel::result::Error> {
                    use crate::schema::users;
                    use diesel::prelude::*;

                    diesel::update(users::table.filter(users::id.eq(&uid)))
                        .set((
                            users::mfa_failed_attempts.eq(0),
                            users::mfa_last_used_at.eq(Utc::now().to_rfc3339()),
                        ))
                        .execute(&mut conn)?;

                    Ok(())
                })
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?
                .map_err(|e| ApiError::Internal(e.to_string()))?;

                verify_result = MfaVerifyResult::Success;
            }
            Ok(false) => {
                verify_result = MfaVerifyResult::InvalidCode;
            }
            Err(e) => {
                return Err(ApiError::Internal(format!(
                    "TOTP verification error: {}",
                    e
                )));
            }
        }
    }

    // Handle verification result
    match verify_result {
        MfaVerifyResult::Success | MfaVerifyResult::RecoveryCodeUsed(_) => {
            // Complete login - move pending user to active session
            let username: String = session
                .get("mfa_pending_username")
                .map_err(|e| ApiError::Internal(e.to_string()))?
                .unwrap_or_default();
            let role: String = session
                .get("mfa_pending_role")
                .map_err(|e| ApiError::Internal(e.to_string()))?
                .unwrap_or_default();

            session.remove("mfa_pending_user_id");
            session.remove("mfa_pending_username");
            session.remove("mfa_pending_role");

            session
                .insert("user_id", user_id.clone())
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            session
                .insert("username", username.clone())
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            session
                .insert("role", role.clone())
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            session
                .insert("mfa_verified", true)
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            let msg = match verify_result {
                MfaVerifyResult::RecoveryCodeUsed(idx) => {
                    info!(
                        user_id = %user_id,
                        recovery_code_index = idx,
                        "MFA verified using recovery code"
                    );
                    format!(
                        "Logged in using recovery code. {} codes remaining.",
                        9 - idx
                    )
                }
                _ => {
                    info!(user_id = %user_id, "MFA verified successfully");
                    "MFA verification successful".to_string()
                }
            };

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": msg,
                "user_id": user_id,
                "username": username,
                "role": role
            })))
        }
        MfaVerifyResult::InvalidCode => {
            // Increment failed attempts
            let new_attempts = failed_attempts + 1;
            let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
            let uid = user_id.clone();

            if new_attempts >= MAX_FAILED_ATTEMPTS {
                // Lock account
                let lockout_until = MfaService::calculate_lockout_time();

                web::block(move || -> Result<(), diesel::result::Error> {
                    use crate::schema::users;
                    use diesel::prelude::*;

                    diesel::update(users::table.filter(users::id.eq(&uid)))
                        .set((
                            users::mfa_failed_attempts.eq(new_attempts),
                            users::mfa_locked_until.eq(Some(&lockout_until)),
                        ))
                        .execute(&mut conn)?;

                    Ok(())
                })
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?
                .map_err(|e| ApiError::Internal(e.to_string()))?;

                warn!(
                    user_id = %user_id,
                    attempts = new_attempts,
                    "MFA account locked after too many failed attempts"
                );

                Err(ApiError::TooManyRequests(format!(
                    "Too many failed attempts. Account locked for {} minutes.",
                    LOCKOUT_DURATION_SECS / 60
                )))
            } else {
                web::block(move || -> Result<(), diesel::result::Error> {
                    use crate::schema::users;
                    use diesel::prelude::*;

                    diesel::update(users::table.filter(users::id.eq(&uid)))
                        .set(users::mfa_failed_attempts.eq(new_attempts))
                        .execute(&mut conn)?;

                    Ok(())
                })
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?
                .map_err(|e| ApiError::Internal(e.to_string()))?;

                let remaining = MAX_FAILED_ATTEMPTS - new_attempts;
                warn!(
                    user_id = %user_id,
                    attempts = new_attempts,
                    remaining = remaining,
                    "Invalid MFA code"
                );

                Err(ApiError::Unauthorized(format!(
                    "Invalid code. {} attempts remaining.",
                    remaining
                )))
            }
        }
        MfaVerifyResult::LockedOut { until } => Err(ApiError::TooManyRequests(format!(
            "Account locked until {}",
            until
        ))),
        MfaVerifyResult::NowLocked { until } => Err(ApiError::TooManyRequests(format!(
            "Account now locked until {}",
            until
        ))),
    }
}

/// POST /api/mfa/disable - Disable MFA
///
/// Requires current TOTP code to confirm.
#[post("/disable")]
pub async fn disable_mfa(
    pool: web::Data<DbPool>,
    session: Session,
    req: web::Json<MfaDisableRequest>,
) -> Result<HttpResponse, ApiError> {
    // Require authentication
    let user_id: String = session
        .get("user_id")
        .context("Session read failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Not authenticated".to_string()))?;

    // Validate CSRF
    if !validate_csrf_token(&session, &req.csrf_token) {
        return Err(ApiError::Forbidden("Invalid CSRF token".to_string()));
    }

    // Get user's MFA secret
    let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
    let uid = user_id.clone();

    let totp_secret = web::block(move || -> Result<Vec<u8>, diesel::result::Error> {
        use crate::schema::users;
        use diesel::prelude::*;

        let secret: Option<Vec<u8>> = users::table
            .filter(users::id.eq(&uid))
            .select(users::totp_secret)
            .first(&mut conn)?;

        secret.ok_or(diesel::result::Error::NotFound)
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|_| ApiError::BadRequest("MFA is not enabled".to_string()))?;

    // Verify TOTP code
    let mfa_service = get_mfa_service()?;
    let is_valid = mfa_service
        .verify_totp(&totp_secret, &req.code)
        .map_err(|e| ApiError::Internal(format!("TOTP verification failed: {}", e)))?;

    if !is_valid {
        warn!(
            user_id = %user_id,
            "MFA disable attempt with invalid code"
        );
        return Err(ApiError::BadRequest(
            "Invalid code. Enter the current code from your authenticator app.".to_string(),
        ));
    }

    // Disable MFA
    let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
    let uid = user_id.clone();

    web::block(move || -> Result<(), diesel::result::Error> {
        use crate::schema::users;
        use diesel::prelude::*;

        diesel::update(users::table.filter(users::id.eq(&uid)))
            .set((
                users::totp_secret.eq::<Option<Vec<u8>>>(None),
                users::mfa_enabled.eq(0),
                users::mfa_enabled_at.eq::<Option<String>>(None),
                users::mfa_recovery_codes.eq::<Option<String>>(None),
                users::mfa_failed_attempts.eq(0),
                users::mfa_locked_until.eq::<Option<String>>(None),
            ))
            .execute(&mut conn)?;

        Ok(())
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    session.remove("mfa_verified");

    info!(
        user_id = %user_id,
        "MFA disabled successfully"
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "MFA has been disabled"
    })))
}

/// GET /api/mfa/status - Get MFA status for current user
#[allow(dead_code)]
pub async fn mfa_status(
    pool: web::Data<DbPool>,
    session: Session,
) -> Result<HttpResponse, ApiError> {
    // Require authentication
    let user_id: String = session
        .get("user_id")
        .context("Session read failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Not authenticated".to_string()))?;

    let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
    let uid = user_id.clone();

    let status = web::block(
        move || -> Result<(bool, Option<String>, usize), diesel::result::Error> {
            use crate::schema::users;
            use diesel::prelude::*;

            let result: (i32, Option<String>, Option<String>) = users::table
                .filter(users::id.eq(&uid))
                .select((
                    users::mfa_enabled,
                    users::mfa_enabled_at,
                    users::mfa_recovery_codes,
                ))
                .first(&mut conn)?;

            let recovery_codes_remaining = if let Some(ref codes_json) = result.2 {
                let codes: Vec<String> = serde_json::from_str(codes_json).unwrap_or_default();
                codes.iter().filter(|c| !c.is_empty()).count()
            } else {
                0
            };

            Ok((result.0 == 1, result.1, recovery_codes_remaining))
        },
    )
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(MfaStatusResponse {
        mfa_enabled: status.0,
        mfa_enabled_at: status.1,
        recovery_codes_remaining: status.2,
    }))
}

/// Configure MFA routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/mfa")
            .service(setup_mfa)
            .service(verify_setup_mfa)
            .service(verify_mfa)
            .service(disable_mfa),
    );
}
