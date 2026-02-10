//! Authentication handlers for the Monero Marketplace API
//!
//! Provides secure authentication endpoints with production-grade security:
//! - Argon2id password hashing (time cost ≥ 2)
//! - Rate limiting (5 failed logins per IP per hour)
//! - Session management with secure cookies
//! - CSRF token validation
//! - Input validation at API boundary
//! - Structured logging without sensitive data

use actix_session::Session;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use bip39;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use uuid::Uuid;
use validator::Validate;

use crate::config::get_configured_network;
use crate::crypto::address_validation::validate_address_for_network;
use crate::db::DbPool;
use crate::error::ApiError;
use crate::middleware::csrf::validate_csrf_token;
use crate::middleware::registration_rate_limit::{
    check_registration_rate_limit, record_registration_attempt, RegistrationRateLimitStorage,
};
use crate::models::login_attempt::{LoginAttempt, AttemptType, MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_SECS};
use crate::models::user::{NewUser, User};
use crate::validation::password::{validate_password_strength, format_validation_error};

/// Helper function to check if request is from HTMX
/// Note: Actix-web normalizes headers to lowercase, so we check "hx-request" not "HX-Request"
fn is_htmx_request(req: &HttpRequest) -> bool {
    req.headers()
        .get("hx-request")  // lowercase to match what browsers actually send
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Helper function to create HTMX error response
fn htmx_error_response(message: &str) -> HttpResponse {
    HttpResponse::Ok().content_type("text/html").body(format!(
        r#"<div class="alert alert-error">{}</div>"#,
        message
    ))
}

/// Helper function to create HTMX success response with redirect
fn htmx_success_redirect(location: &str) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("HX-Redirect", location))
        .content_type("text/html")
        .body("")
}

#[derive(Debug, Validate, Deserialize)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    pub role: String,
    pub wallet_address: Option<String>,
    pub csrf_token: String,
}

/// Validate Monero address with full cryptographic checksum verification
///
/// Uses the production-grade `validate_address_for_network` function from
/// `crypto::address_validation` module which:
/// - Decodes Base58-Monero encoding
/// - Verifies Keccak256 checksum
/// - Ensures address matches configured network (mainnet/stagenet/testnet)
///
/// CRITICAL: This prevents loss of funds from invalid or wrong-network addresses
fn validate_monero_address(addr: &str) -> Result<(), String> {
    let network = get_configured_network()
        .map_err(|e| format!("Network configuration error: {}", e))?;

    validate_address_for_network(addr, network)
        .map_err(|e| format!("{}", e))
}

#[post("/register")]
pub async fn register(
    pool: web::Data<DbPool>,
    req: web::Form<RegisterRequest>,
    http_req: HttpRequest,
    session: Session,
    rate_limiter: web::Data<RegistrationRateLimitStorage>,
) -> Result<HttpResponse, ApiError> {
    let is_htmx = is_htmx_request(&http_req);

    // P0 Security: Check registration rate limit per IP
    let client_ip = http_req
        .connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string();

    if let Err(seconds_remaining) = check_registration_rate_limit(&rate_limiter, &client_ip) {
        warn!(
            ip = %client_ip,
            retry_after = seconds_remaining,
            "Registration rate limit exceeded"
        );
        return if is_htmx {
            Ok(htmx_error_response(&format!(
                "Too many registration attempts. Please try again in {} minutes.",
                seconds_remaining / 60 + 1
            )))
        } else {
            Err(ApiError::TooManyRequests(format!(
                "Too many registration attempts. Retry after {} seconds.",
                seconds_remaining
            )))
        };
    }

    // Validate CSRF token
    if !validate_csrf_token(&session, &req.csrf_token) {
        return if is_htmx {
            Ok(htmx_error_response("Invalid CSRF token"))
        } else {
            Err(ApiError::Forbidden("Invalid CSRF token".to_string()))
        };
    }

    // Validate input
    if let Err(e) = req.0.validate() {
        return if is_htmx {
            Ok(htmx_error_response(&format!("Validation error: {}", e)))
        } else {
            Err(ApiError::from(e))
        };
    }

    // P0 Security: Validate password strength with zxcvbn
    let pwd_validation = validate_password_strength(&req.password, &[&req.username]);
    if !pwd_validation.is_valid {
        let error_msg = format_validation_error(&pwd_validation);
        return if is_htmx {
            Ok(htmx_error_response(&error_msg))
        } else {
            Err(ApiError::BadRequest(error_msg))
        };
    }

    // Validate that vendors have wallet address (optional but recommended)
    // Note: We don't make it strictly required here to allow vendors to set it later in Settings
    // But we log a warning if missing
    if req.role == "vendor" && req.wallet_address.is_none() {
        warn!(
            username = %req.username,
            "Vendor registered without wallet address - will need to configure before shipping orders"
        );
    }

    // If wallet_address is provided, validate with full checksum verification
    if let Some(ref addr) = req.wallet_address {
        if let Err(e) = validate_monero_address(addr) {
            return if is_htmx {
                Ok(htmx_error_response(&format!("Invalid Monero address: {}", e)))
            } else {
                Err(ApiError::BadRequest(format!("Invalid Monero address: {}", e)))
            };
        }
    }

    let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;

    // 1. Check if username exists (normalize to lowercase for case-insensitive comparison)
    let req_username = req.username.to_lowercase();
    let username_exists =
        web::block(move || User::username_exists(&mut conn, &req_username)).await??;
    if username_exists {
        return if is_htmx {
            Ok(htmx_error_response("Username already taken"))
        } else {
            Err(ApiError::Conflict("Username already taken".to_string()))
        };
    }

    // 2. Hash password using Argon2id with PasswordHasher trait
    let password = req.password.clone();
    let password_hash = web::block(move || -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string())
    })
    .await??;

    // 3. Create user (use normalized lowercase username)
    let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
    let new_user = NewUser {
        id: Uuid::new_v4().to_string(),
        username: req.username.to_lowercase(),  // Store lowercase for case-insensitive login
        password_hash,
        wallet_address: req.wallet_address.clone(),
        wallet_id: None,
        role: req.role.clone(),
    };

    let user = web::block(move || User::create(&mut conn, new_user)).await??;

    // P0 Security: Record successful registration for rate limiting
    record_registration_attempt(&rate_limiter, &client_ip);

    info!(
        user_id = %user.id,
        username = %user.username,
        role = %user.role,
        "User registered successfully"
    );

    // For HTMX: create session and redirect to homepage
    if is_htmx {
        session
            .insert("user_id", user.id.clone())
            .context("Failed to create session")
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        session
            .insert("username", user.username.clone())
            .context("Failed to store username in session")
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        session
            .insert("role", user.role.clone())
            .context("Failed to store role in session")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        Ok(htmx_success_redirect("/"))
    } else {
        // Create session for standard form submission too
        session
            .insert("user_id", user.id.clone())
            .context("Failed to create session")
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        session
            .insert("username", user.username.clone())
            .context("Failed to store username in session")
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        session
            .insert("role", user.role.clone())
            .context("Failed to store role in session")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        Ok(HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish())
    }
}

/// Login request structure with validation
#[derive(Debug, Validate, Deserialize)]
pub struct LoginRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    pub csrf_token: String,
}

/// User response (without password_hash)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            role: user.role,
        }
    }
}

// ============================================================================
// JSON API Endpoints (for React/SPA frontends)
// No CSRF token required - SameSite cookies provide CSRF protection
// ============================================================================

/// JSON Login request (no CSRF token)
#[derive(Debug, Validate, Deserialize)]
pub struct LoginJsonRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

/// JSON Register request (no CSRF token)
#[derive(Debug, Validate, Deserialize)]
pub struct RegisterJsonRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    pub role: String,
    pub wallet_address: Option<String>,
}

/// JSON Login endpoint for SPA/React frontends
#[post("/login-json")]
pub async fn login_json(
    pool: web::Data<DbPool>,
    session: Session,
    req: web::Json<LoginJsonRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    // Validate input
    if let Err(e) = req.0.validate() {
        return Err(ApiError::from(e));
    }

    let username = req.username.to_lowercase();
    let password = req.password.clone();

    // Extract IP for logging
    let client_ip = http_req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string());

    // Check per-username lockout
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let username_for_lockout = username.clone();
    let lockout_result = web::block(move || {
        LoginAttempt::is_locked_out(&mut conn, &username_for_lockout)
    })
    .await
    .context("Lockout check failed")
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    if let Ok(is_locked) = lockout_result {
        if is_locked {
            return Err(ApiError::TooManyRequests(
                "Account temporarily locked due to too many failed attempts".to_string()
            ));
        }
    }

    // Find user by username
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let username_for_lookup = username.clone();
    let user_result = web::block(move || User::find_by_username(&mut conn, &username_for_lookup))
        .await
        .context("Database query failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let user = match user_result {
        Ok(u) => u,
        Err(_) => {
            // Record failed attempt
            let mut conn = pool
                .get()
                .context("Failed to get database connection")
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            let username_for_record = username.clone();
            let ip_for_record = client_ip.clone();
            let _ = web::block(move || {
                LoginAttempt::record(&mut conn, &username_for_record, ip_for_record.as_deref(), AttemptType::Failed)
            }).await;

            return Err(ApiError::Unauthorized("Invalid credentials".to_string()));
        }
    };

    // Verify password
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| ApiError::Internal("Invalid password hash".to_string()))?;

    if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_err() {
        // Record failed attempt
        let mut conn = pool
            .get()
            .context("Failed to get database connection")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let username_for_record = username.clone();
        let ip_for_record = client_ip.clone();
        let _ = web::block(move || {
            LoginAttempt::record(&mut conn, &username_for_record, ip_for_record.as_deref(), AttemptType::Failed)
        }).await;

        return Err(ApiError::Unauthorized("Invalid credentials".to_string()));
    }

    // Success - record and create session
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let username_for_record = username.clone();
    let ip_for_record = client_ip.clone();
    let _ = web::block(move || {
        LoginAttempt::record(&mut conn, &username_for_record, ip_for_record.as_deref(), AttemptType::Success)
    }).await;

    // Set session
    session.insert("user_id", &user.id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    session.insert("username", &user.username)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    session.insert("role", &user.role)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    info!(username = %user.username, role = %user.role, "User logged in via JSON API");

    Ok(HttpResponse::Ok().json(UserResponse::from(user)))
}

/// JSON Register endpoint for SPA/React frontends
#[post("/register-json")]
pub async fn register_json(
    pool: web::Data<DbPool>,
    session: Session,
    req: web::Json<RegisterJsonRequest>,
    http_req: HttpRequest,
    rate_limiter: web::Data<RegistrationRateLimitStorage>,
) -> Result<HttpResponse, ApiError> {
    // Check registration rate limit per IP
    let client_ip = http_req
        .connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string();

    if let Err(seconds_remaining) = check_registration_rate_limit(&rate_limiter, &client_ip) {
        return Err(ApiError::TooManyRequests(format!(
            "Too many registration attempts. Retry after {} seconds.",
            seconds_remaining
        )));
    }

    // Validate input
    if let Err(e) = req.0.validate() {
        return Err(ApiError::from(e));
    }

    // Validate role
    let valid_roles = ["buyer", "vendor", "arbiter"];
    if !valid_roles.contains(&req.role.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "Invalid role. Must be one of: {}",
            valid_roles.join(", ")
        )));
    }

    // Validate password strength
    let pwd_validation = validate_password_strength(&req.password, &[&req.username]);
    if !pwd_validation.is_valid {
        return Err(ApiError::BadRequest(format_validation_error(&pwd_validation)));
    }

    // Validate wallet address if provided
    if let Some(ref addr) = req.wallet_address {
        if !addr.is_empty() {
            let network = get_configured_network()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            validate_address_for_network(addr, network)
                .map_err(|e| ApiError::BadRequest(format!("Invalid wallet address: {}", e)))?;
        }
    }

    // Check if username exists
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let username_lower = req.username.to_lowercase();
    let username_check = username_lower.clone();
    let exists = web::block(move || User::find_by_username(&mut conn, &username_check))
        .await
        .context("Database query failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if exists.is_ok() {
        return Err(ApiError::Conflict("Username already taken".to_string()));
    }

    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| ApiError::Internal(format!("Password hashing failed: {}", e)))?
        .to_string();

    // Create user
    let new_user = NewUser {
        id: Uuid::new_v4().to_string(),
        username: username_lower.clone(),
        password_hash,
        role: req.role.clone(),
        wallet_address: req.wallet_address.clone(),
        wallet_id: None,
    };

    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let user = web::block(move || User::create(&mut conn, new_user)).await??;

    // Record successful registration
    record_registration_attempt(&rate_limiter, &client_ip);

    // Set session
    session.insert("user_id", &user.id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    session.insert("username", &user.username)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    session.insert("role", &user.role)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    info!(username = %user.username, role = %user.role, "User registered via JSON API");

    Ok(HttpResponse::Created().json(UserResponse::from(user)))
}

/// Login endpoint
///
/// # Security Features
/// - Argon2id password verification (constant-time comparison)
/// - Rate limiting: 5 failed attempts per IP per hour (middleware)
/// - Per-username lockout: 5 failed attempts → 15 minute lockout (P0 Security)
/// - Session token: cryptographically random, HttpOnly cookie
/// - Session ID rotation on successful login
/// - Structured logging without password exposure
#[post("/login")]
pub async fn login(
    pool: web::Data<DbPool>,
    session: Session,
    req: web::Form<LoginRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let is_htmx = is_htmx_request(&http_req);

    // 1. Validate CSRF token
    if !validate_csrf_token(&session, &req.csrf_token) {
        return if is_htmx {
            Ok(htmx_error_response("Invalid CSRF token"))
        } else {
            Err(ApiError::Forbidden("Invalid CSRF token".to_string()))
        };
    }

    // 2. Validate input
    if let Err(e) = req.0.validate() {
        return if is_htmx {
            Ok(htmx_error_response(&format!("Validation error: {}", e)))
        } else {
            Err(ApiError::from(e))
        };
    }

    let username = req.username.to_lowercase();  // Normalize to lowercase for case-insensitive login
    let password = req.password.clone();

    // Extract IP for logging (never log full IP, just for tracking)
    let client_ip = http_req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string());

    // 3. Check per-username lockout BEFORE any password verification
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let username_for_lockout = username.clone();
    let lockout_result = web::block(move || {
        LoginAttempt::is_locked_out(&mut conn, &username_for_lockout)
    })
    .await
    .context("Lockout check failed")
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    if let Ok(is_locked) = lockout_result {
        if is_locked {
            // Get remaining lockout time
            let mut conn2 = pool
                .get()
                .context("Failed to get database connection")
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            let username_for_remaining = username.clone();
            let remaining = web::block(move || {
                LoginAttempt::lockout_remaining_secs(&mut conn2, &username_for_remaining)
            })
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(LOCKOUT_DURATION_SECS);

            let minutes = (remaining / 60) + 1;

            warn!(
                username = %username,
                remaining_secs = remaining,
                "Login attempt on locked account"
            );

            let error_msg = format!(
                "Account temporarily locked due to too many failed attempts. Try again in {} minute{}.",
                minutes,
                if minutes == 1 { "" } else { "s" }
            );

            return if is_htmx {
                Ok(htmx_error_response(&error_msg))
            } else {
                Err(ApiError::TooManyRequests(error_msg))
            };
        }
    }

    // 4. Find user by username
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let username_for_lookup = username.clone();
    let user_result = web::block(move || User::find_by_username(&mut conn, &username_for_lookup))
        .await
        .context("Database query failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let user = match user_result {
        Ok(u) => u,
        Err(_) => {
            // Record failed attempt even for non-existent user (prevents enumeration timing)
            let mut conn = pool
                .get()
                .context("Failed to get database connection")
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            let username_for_record = username.clone();
            let ip_for_record = client_ip.clone();
            let _ = web::block(move || {
                LoginAttempt::record(
                    &mut conn,
                    &username_for_record,
                    ip_for_record.as_deref(),
                    AttemptType::Failed,
                )
            })
            .await;

            warn!(
                username = %username,
                "Login attempt with non-existent username"
            );
            return if is_htmx {
                Ok(htmx_error_response("Invalid credentials"))
            } else {
                Err(ApiError::Unauthorized("Invalid credentials".to_string()))
            };
        }
    };

    // 5. Verify password using PasswordVerifier trait (constant-time comparison)
    let password_hash_str = user.password_hash.clone();
    let user_id = user.id.clone();
    let user_username = user.username.clone();

    let password_valid = web::block(move || -> Result<bool, argon2::password_hash::Error> {
        let parsed_hash = PasswordHash::new(&password_hash_str)?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    })
    .await
    .context("Password verification task failed")
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|e| {
        warn!(
            user_id = %user_id,
            error = %e,
            "Argon2 password verification failed"
        );
        ApiError::Internal("Password verification error".to_string())
    })?;

    if !password_valid {
        // Record failed attempt
        let mut conn = pool
            .get()
            .context("Failed to get database connection")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let username_for_record = username.clone();
        let ip_for_record = client_ip.clone();
        let _ = web::block(move || {
            LoginAttempt::record(
                &mut conn,
                &username_for_record,
                ip_for_record.as_deref(),
                AttemptType::Failed,
            )
        })
        .await;

        // Check how many attempts remain
        let mut conn2 = pool
            .get()
            .context("Failed to get database connection")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let username_for_count = username.clone();
        let failed_count = web::block(move || {
            LoginAttempt::count_recent_failed(&mut conn2, &username_for_count)
        })
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);

        let remaining_attempts = MAX_FAILED_ATTEMPTS - failed_count;

        warn!(
            user_id = %user_id,
            username = %user_username,
            failed_count = failed_count,
            remaining_attempts = remaining_attempts,
            "Failed login attempt - invalid password"
        );

        let error_msg = if remaining_attempts <= 0 {
            "Account locked due to too many failed attempts. Try again in 15 minutes.".to_string()
        } else if remaining_attempts <= 2 {
            format!("Invalid credentials. {} attempt{} remaining before lockout.",
                remaining_attempts,
                if remaining_attempts == 1 { "" } else { "s" }
            )
        } else {
            "Invalid credentials".to_string()
        };

        return if is_htmx {
            Err(ApiError::Unauthorized(error_msg))
        } else {
            Err(ApiError::Unauthorized(error_msg))
        };
    }

    // 6. Successful login - record success and rotate session
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let username_for_success = username.clone();
    let ip_for_success = client_ip.clone();
    let _ = web::block(move || {
        LoginAttempt::record_success(&mut conn, &username_for_success, ip_for_success.as_deref())
    })
    .await;

    // Session ID rotation: clear old session and create new one (prevents session fixation)
    session.purge();

    // 7. Create new session with fresh ID
    session
        .insert("user_id", user.id.clone())
        .context("Failed to create session")
        .map_err(|e| {
            warn!(
                user_id = %user.id,
                error = %e,
                "Failed to insert user_id into session"
            );
            ApiError::Internal("Session creation failed".to_string())
        })?;
    session
        .insert("username", user.username.clone())
        .context("Failed to store username in session")
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    session
        .insert("role", user.role.clone())
        .context("Failed to store role in session")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    info!(
        user_id = %user.id,
        username = %user.username,
        role = %user.role,
        "User logged in successfully (session rotated)"
    );

    // 8. Return appropriate response - redirect to home
    if is_htmx {
        Ok(htmx_success_redirect("/"))
    } else {
        Ok(HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish())
    }
}

/// Whoami endpoint - get current authenticated user
///
/// # Security
/// - Requires valid session
/// - Returns 401 if not authenticated
#[get("/whoami")]
pub async fn whoami(pool: web::Data<DbPool>, session: Session) -> Result<HttpResponse, ApiError> {
    // 1. Extract user_id from session
    let user_id: String = session
        .get("user_id")
        .context("Failed to read session")
        .map_err(|e| {
            warn!(error = %e, "Session read error");
            ApiError::Internal("Session error".to_string())
        })?
        .ok_or_else(|| ApiError::Unauthorized("Not authenticated".to_string()))?;

    // 2. Load user from database
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let user_id_for_lookup = user_id.clone();
    let user_id_for_warn = user_id.clone();
    let user = web::block(move || User::find_by_id(&mut conn, user_id_for_lookup))
        .await
        .context("Database query failed")
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|_| {
            warn!(
                user_id = %user_id_for_warn,
                "Session refers to non-existent user"
            );
            ApiError::Unauthorized("Invalid session".to_string())
        })?;

    // 3. Return user info with CSRF token for SPA
    use crate::middleware::csrf::get_csrf_token;
    let csrf_token = get_csrf_token(&session);
    let user_resp = UserResponse::from(user);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": user_resp.id,
        "username": user_resp.username,
        "role": user_resp.role,
        "csrf_token": csrf_token
    })))
}

/// Logout endpoint - clear session
#[post("/logout")]
pub async fn logout(session: Session) -> Result<HttpResponse, ApiError> {
    // Extract user_id for logging before clearing session
    let user_id: Option<String> = session.get("user_id").unwrap_or(None);

    // Clear session
    session.clear();

    if let Some(user_id) = user_id {
        info!(
            user_id = %user_id,
            "User logged out successfully, redirecting to homepage"
        );
    }

    // Redirect to homepage instead of returning JSON
    Ok(HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish())
}

/// POST /api/settings/update-wallet - Update user's Monero wallet address
#[derive(Debug, Deserialize)]
pub struct UpdateWalletRequest {
    pub wallet_address: String,
    pub csrf_token: String,
}

#[post("/update-wallet")]
pub async fn update_wallet_address(
    pool: web::Data<DbPool>,
    req: web::Form<UpdateWalletRequest>,
    http_req: HttpRequest,
    session: Session,
) -> Result<HttpResponse, ApiError> {
    use diesel::prelude::*;
    use crate::schema::users;

    let is_htmx = is_htmx_request(&http_req);

    // Require authentication
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => uid,
        _ => {
            return if is_htmx {
                Ok(htmx_error_response("Not authenticated"))
            } else {
                Err(ApiError::Unauthorized("Not authenticated".to_string()))
            };
        }
    };

    // Validate CSRF token
    if !validate_csrf_token(&session, &req.csrf_token) {
        return if is_htmx {
            Ok(htmx_error_response("Invalid CSRF token"))
        } else {
            Err(ApiError::Forbidden("Invalid CSRF token".to_string()))
        };
    }

    // Validate wallet address with full checksum verification
    if let Err(e) = validate_monero_address(&req.wallet_address) {
        return if is_htmx {
            Ok(htmx_error_response(&format!("Invalid Monero address: {}", e)))
        } else {
            Err(ApiError::BadRequest(format!("Invalid Monero address: {}", e)))
        };
    }

    // Update wallet address in database
    let mut conn = pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;

    let wallet_addr = req.wallet_address.clone();
    let wallet_addr_for_display = wallet_addr.clone(); // Clone for later use in HTML response
    let uid = user_id.clone();

    info!("DEBUG: Attempting to update wallet for user_id: {}", uid);
    info!("DEBUG: Wallet address to save: {}", wallet_addr);

    let update_result = web::block(move || -> Result<usize, diesel::result::Error> {
        let rows_affected = diesel::update(users::table.filter(users::id.eq(&uid)))
            .set(users::wallet_address.eq(Some(&wallet_addr)))
            .execute(&mut conn)?;

        info!("DEBUG: Rows affected by UPDATE: {}", rows_affected);
        Ok(rows_affected)
    }).await;

    match update_result {
        Ok(Ok(rows_affected)) => {
            if rows_affected == 0 {
                error!("CRITICAL: UPDATE affected 0 rows! User ID not found: {}", user_id);
                return if is_htmx {
                    Ok(htmx_error_response("User not found in database"))
                } else {
                    Err(ApiError::Internal("User not found".to_string()))
                };
            }

            info!(
                user_id = %user_id,
                rows = rows_affected,
                "Wallet address updated successfully"
            );

            if is_htmx {
                // Return updated wallet display HTML + success message with copy button
                let html = format!(
                    r#"<div class="alert alert-success" style="padding: 1rem; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 4px; color: #22c55e; margin-bottom: 1rem;">
                        ✅ Wallet address updated successfully!
                    </div>
                    <div class="wallet-address-display" style="margin-top: 1rem; padding: 1rem; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 8px;">
                        <label class="label" style="color: hsl(142, 76%, 60%); display: block; margin-bottom: 0.75rem; font-weight: 600;">
                            ✅ Current Wallet Address
                        </label>
                        <div class="address-text" style="font-family: monospace; font-size: 0.875rem; color: hsl(142, 76%, 70%); word-break: break-all; line-height: 1.6; margin-bottom: 1rem; padding: 0.75rem; background: rgba(0, 0, 0, 0.2); border-radius: 4px;">
                            {}
                        </div>
                        <div style="display: flex; gap: 0.75rem;">
                            <button
                                type="button"
                                onclick="navigator.clipboard.writeText('{}'); this.innerHTML='<span style=\'margin-right: 0.5rem;\'>✓</span>Copied!'; setTimeout(() => this.innerHTML='<span style=\'margin-right: 0.5rem;\'>📋</span>Copy Address', 2000);"
                                style="flex: 1; padding: 0.75rem 1rem; background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.4); border-radius: 4px; color: hsl(142, 76%, 70%); cursor: pointer; font-size: 0.875rem; font-weight: 600; transition: all 0.2s;"
                                onmouseover="this.style.background='rgba(34, 197, 94, 0.3)'"
                                onmouseout="this.style.background='rgba(34, 197, 94, 0.2)'"
                                title="Copy address to clipboard"
                            >
                                <span style="margin-right: 0.5rem;">📋</span>Copy Address
                            </button>
                        </div>
                        <p style="margin-top: 0.75rem; font-size: 0.75rem; color: hsl(142, 76%, 60%); opacity: 0.8;">
                            💡 Tip: This address will be used to receive payments from completed orders
                        </p>
                    </div>"#,
                    wallet_addr_for_display,
                    wallet_addr_for_display
                );
                Ok(HttpResponse::Ok().content_type("text/html").body(html))
            } else{
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "message": "Wallet address updated successfully"
                })))
            }
        }
        Ok(Err(e)) => {
            error!("Failed to update wallet address: {}", e);
            if is_htmx {
                Ok(htmx_error_response("Failed to update wallet address"))
            } else {
                Err(ApiError::Internal("Failed to update wallet address".to_string()))
            }
        }
        Err(e) => {
            error!("Database operation failed: {}", e);
            if is_htmx {
                Ok(htmx_error_response("Database error"))
            } else {
                Err(ApiError::Internal(e.to_string()))
            }
        }
    }
}

/// Display the login/signup page
pub async fn show_auth_page(
    session: Session,
    tmpl: web::Data<tera::Tera>,
) -> Result<HttpResponse, ApiError> {
    use crate::middleware::csrf::get_csrf_token;

    // Check if already logged in, redirect to home
    if let Ok(Some(_user_id)) = session.get::<String>("user_id") {
        return Ok(HttpResponse::Found()
            .insert_header(("Location", "/"))
            .finish());
    }

    // Get CSRF token
    let csrf_token = get_csrf_token(&session);

    let mut ctx = tera::Context::new();
    ctx.insert("csrf_token", &csrf_token);
    ctx.insert("logged_in", &false);

    let rendered = tmpl
        .render("auth/login-new.html", &ctx)
        .map_err(|e| ApiError::Internal(format!("Template error: {}", e)))?;

    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

// ============================================================================
// Account Recovery (v0.67)
// ============================================================================

/// Display the account recovery page
pub async fn show_recovery_page(
    session: Session,
    tmpl: web::Data<tera::Tera>,
) -> Result<HttpResponse, ApiError> {
    use crate::middleware::csrf::get_csrf_token;

    // Get CSRF token
    let csrf_token = get_csrf_token(&session);

    let mut ctx = tera::Context::new();
    ctx.insert("csrf_token", &csrf_token);
    ctx.insert("logged_in", &false);

    let rendered = tmpl
        .render("auth/recovery.html", &ctx)
        .map_err(|e| ApiError::Internal(format!("Template error: {}", e)))?;

    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Account recovery request payload
#[derive(Debug, Deserialize)]
pub struct RecoveryRequest {
    pub username: String,
    pub recovery_phrase: String,
    pub new_password: String,
    pub csrf_token: String,
}

/// POST /api/auth/recover - Reset password using recovery phrase
///
/// # Security
/// - Validates CSRF token
/// - Verifies 12-word BIP39 mnemonic matches stored phrase
/// - Re-encrypts wallet seed with new password
/// - Generates new recovery phrase (optional, for extra security)
pub async fn recover_account(
    pool: web::Data<DbPool>,
    req: web::Json<RecoveryRequest>,
    session: Session,
) -> Result<HttpResponse, ApiError> {
    use diesel::prelude::*;
    use crate::schema::users;
    use crate::crypto::encryption::{derive_key_from_password, encrypt_bytes, generate_random_salt};

    // Validate CSRF token
    if !validate_csrf_token(&session, &req.csrf_token) {
        return Err(ApiError::Forbidden("Invalid CSRF token".to_string()));
    }

    // Validate input
    let username = req.username.trim();
    let recovery_phrase = req.recovery_phrase.trim().to_lowercase();
    let new_password = &req.new_password;

    if username.is_empty() {
        return Err(ApiError::BadRequest("Username is required".to_string()));
    }

    // P0 Security: Validate password strength with zxcvbn
    let pwd_validation = validate_password_strength(new_password, &[username]);
    if !pwd_validation.is_valid {
        let error_msg = format_validation_error(&pwd_validation);
        return Err(ApiError::BadRequest(error_msg));
    }

    // Validate recovery phrase word count
    let words: Vec<&str> = recovery_phrase.split_whitespace().collect();
    if words.len() != 12 {
        warn!(
            username = %username,
            word_count = words.len(),
            "Recovery attempt with invalid word count"
        );
        return Err(ApiError::BadRequest(format!(
            "Recovery phrase must be exactly 12 words (got {})",
            words.len()
        )));
    }

    // Get database connection
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Find user by username
    let username_clone = username.to_string();
    let user = web::block(move || {
        users::table
            .filter(users::username.eq(&username_clone))
            .first::<User>(&mut conn)
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|_| {
        warn!(username = %username, "Recovery attempt for non-existent user");
        ApiError::BadRequest("Invalid username or recovery phrase".to_string())
    })?;

    // Check if user has a recovery phrase
    let stored_phrase = match &user.bip39_backup_seed {
        Some(phrase) => phrase.trim().to_lowercase(),
        None => {
            warn!(
                user_id = %user.id,
                "Recovery attempt for user without backup seed"
            );
            return Err(ApiError::BadRequest("Account recovery not available. No recovery phrase was set up.".to_string()));
        }
    };

    // Verify recovery phrase matches
    if recovery_phrase != stored_phrase {
        warn!(
            user_id = %user.id,
            "Recovery attempt with incorrect phrase"
        );
        return Err(ApiError::BadRequest("Invalid username or recovery phrase".to_string()));
    }

    info!(
        user_id = %user.id,
        "Recovery phrase verified successfully"
    );

    // Verify user has encrypted seed data (required for recovery)
    // Note: We don't need the old encrypted data - we regenerate from mnemonic
    match (&user.encrypted_wallet_seed, &user.wallet_seed_salt) {
        (Some(_), Some(_)) => {} // Has seed data - can proceed
        _ => {
            warn!(
                user_id = %user.id,
                "Recovery attempt but no encrypted seed found"
            );
            return Err(ApiError::Internal("Account data incomplete".to_string()));
        }
    }

    // We need the original password to decrypt the seed, but we don't have it.
    // For BIP39 recovery, we can regenerate the seed from the mnemonic.
    // Convert mnemonic back to entropy
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &recovery_phrase)
        .map_err(|e| {
            error!(error = %e, "Failed to parse mnemonic");
            ApiError::Internal("Invalid mnemonic format".to_string())
        })?;

    let master_seed = mnemonic.to_entropy();

    // Generate new salt and encrypt seed with new password
    let new_salt = generate_random_salt(16)
        .map_err(|e| ApiError::Internal(format!("Failed to generate salt: {}", e)))?;

    let encryption_key = derive_key_from_password(new_password, &new_salt)
        .map_err(|e| ApiError::Internal(format!("Failed to derive key: {}", e)))?;

    let new_encrypted_seed = encrypt_bytes(&master_seed, &encryption_key)
        .map_err(|e| ApiError::Internal(format!("Failed to encrypt seed: {}", e)))?;

    // Hash the new password
    let salt_string = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let new_password_clone = new_password.clone();
    let new_password_hash = web::block(move || {
        argon2
            .hash_password(new_password_clone.as_bytes(), &salt_string)
            .map(|h| h.to_string())
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|e| ApiError::Internal(format!("Password hashing failed: {}", e)))?;

    // Update user in database
    let mut conn = pool
        .get()
        .context("Failed to get database connection")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let user_id = user.id.clone();
    let user_id_log = user.id.clone();

    web::block(move || {
        diesel::update(users::table.filter(users::id.eq(&user_id)))
            .set((
                users::password_hash.eq(&new_password_hash),
                users::encrypted_wallet_seed.eq(&new_encrypted_seed),
                users::wallet_seed_salt.eq(&new_salt),
                users::updated_at.eq(diesel::dsl::now),
            ))
            .execute(&mut conn)
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(|e| {
        error!(error = %e, "Failed to update user password");
        ApiError::Internal("Failed to update password".to_string())
    })?;

    info!(
        user_id = %user_id_log,
        "Account recovered successfully - password reset"
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Password reset successfully. You can now log in with your new password."
    })))
}

// =============================================================================
// TEST LOGIN ENDPOINT (DEBUG BUILDS ONLY)
// =============================================================================
// This endpoint allows E2E tests to establish a valid session without
// password verification. It is COMPLETELY REMOVED in release builds.
//
// Usage:
// POST /api/auth/test-login
// Body: { "user_id": "uuid", "username": "test", "role": "buyer" }
//
// Security: This code does NOT exist in production binaries.
// =============================================================================

#[cfg(debug_assertions)]
#[derive(Debug, Deserialize)]
pub struct TestLoginRequest {
    pub user_id: String,
    pub username: String,
    pub role: String,
}

#[cfg(debug_assertions)]
#[post("/login")]
pub async fn test_login(
    session: Session,
    body: web::Json<TestLoginRequest>,
) -> Result<HttpResponse, ApiError> {
    // Only allow in debug builds with TEST_AUTH_BYPASS enabled
    let bypass_enabled = std::env::var("TEST_AUTH_BYPASS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if !bypass_enabled {
        warn!("⚠️  test-login called but TEST_AUTH_BYPASS not enabled");
        return Err(ApiError::Forbidden(
            "Test login only available when TEST_AUTH_BYPASS=1".to_string(),
        ));
    }

    // Validate UUID format
    if uuid::Uuid::parse_str(&body.user_id).is_err() {
        return Err(ApiError::BadRequest("Invalid user_id UUID format".to_string()));
    }

    // Validate role
    let valid_roles = ["buyer", "vendor", "arbiter", "admin"];
    if !valid_roles.contains(&body.role.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "Invalid role. Must be one of: {:?}",
            valid_roles
        )));
    }

    // Create session
    session
        .insert("user_id", body.user_id.clone())
        .map_err(|e| ApiError::Internal(format!("Session insert failed: {}", e)))?;
    session
        .insert("username", body.username.clone())
        .map_err(|e| ApiError::Internal(format!("Session insert failed: {}", e)))?;
    session
        .insert("role", body.role.clone())
        .map_err(|e| ApiError::Internal(format!("Session insert failed: {}", e)))?;

    warn!(
        user_id = %body.user_id,
        username = %body.username,
        role = %body.role,
        "⚠️  TEST LOGIN: Session created via test endpoint"
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Test session created",
        "user_id": body.user_id,
        "username": body.username,
        "role": body.role
    })))
}
