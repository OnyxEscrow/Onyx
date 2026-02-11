#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    deprecated,
    unused_assignments
)]
use actix::{Actor, Addr};
use actix_cors::Cors;
use actix_files as fs;
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::Key, middleware::Logger, web, App, Error, HttpRequest, HttpResponse, HttpServer,
    Responder,
};
use actix_web_actors::ws;
use anyhow::{Context, Result};
use monero_marketplace_common::types::MoneroConfig;
use server::coordination::{DbMultisigCoordinator, EscrowCoordinator};
use server::db::{create_pool, DatabaseConfig, DatabaseManager};
use server::handlers::{
    analytics, api_keys, auth, batch, client_fees, dispute_evidence, docs, encrypted_relay, escrow,
    escrow_chat, fees, frost_escrow, monero_validator, monitoring, multisig, multisig_challenge,
    multisig_wallet, noncustodial, notifications, secure_messages, sync, user, wallet,
    wasm_multisig, webhooks,
};
use server::middleware::{
    admin_auth::AdminAuth,
    idempotency::IdempotencyMiddleware,
    new_api_key_rate_limit_storage,
    rate_limit::RateLimitMiddleware,
    registration_rate_limit::new_registration_rate_limit_storage,
    security_headers::{CspNonceMiddleware, SecurityHeadersMiddleware},
    ConnectionManager, RequestIdMiddleware, RequireApiKey,
};
use server::services::escrow::EscrowOrchestrator;
use server::services::sync_proxy::SyncProxyService;
use server::services::webhook_dispatcher::{WebhookDispatcher, WebhookRetryWorker};
use server::wallet_manager::WalletManager;
use server::watchdog::WalletRpcWatchdog;
use server::websocket::{WebSocketServer, WebSocketSession};
mod dependencies;
mod security;
use crate::security::placeholder_validator;
use server::config::XmrUsdRate;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tera::Tera;
use time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

/// Serve React SPA for all frontend routes (EaaS UI)
async fn serve_spa() -> impl Responder {
    actix_files::NamedFile::open_async("./static/app/index.html")
        .await
        .map_err(|e| {
            tracing::error!("Failed to serve SPA: {}", e);
            actix_web::error::ErrorNotFound("SPA not found")
        })
}

// =============================================================================
// DEBUG ENDPOINTS - Only compiled when `debug-endpoints` feature is enabled
// =============================================================================
// Build commands:
//   Production (no debug): cargo build --release
//   Development (with debug): cargo build --features debug-endpoints
// =============================================================================

#[cfg(feature = "debug-endpoints")]
mod debug_endpoints {
    use actix_web::{web, HttpResponse};
    use server::db::DbPool;
    use server::error::ApiError;
    use server::models::user::{NewUser, User};

    #[derive(serde::Deserialize)]
    pub struct DebugTestLoginRequest {
        pub user_id: String,
        pub username: String,
        pub role: String,
    }

    /// Test login endpoint for E2E tests (DEBUG ONLY)
    ///
    /// Creates a session without password verification.
    /// Only works when TEST_AUTH_BYPASS=1 environment variable is set.
    pub async fn debug_test_login(
        session: actix_session::Session,
        pool: web::Data<DbPool>,
        body: web::Json<DebugTestLoginRequest>,
    ) -> Result<HttpResponse, ApiError> {
        // Only allow when TEST_AUTH_BYPASS=1
        let bypass_enabled = std::env::var("TEST_AUTH_BYPASS")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        if !bypass_enabled {
            tracing::warn!("debug/test-login called but TEST_AUTH_BYPASS not enabled");
            return Err(ApiError::Forbidden(
                "Test login only available when TEST_AUTH_BYPASS=1".to_string(),
            ));
        }

        // Validate UUID format
        if uuid::Uuid::parse_str(&body.user_id).is_err() {
            return Err(ApiError::BadRequest(
                "Invalid user_id UUID format".to_string(),
            ));
        }

        // Validate role
        let valid_roles = ["buyer", "vendor", "arbiter", "admin"];
        if !valid_roles.contains(&body.role.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "Invalid role. Must be one of: {:?}",
                valid_roles
            )));
        }

        // Create user in DB if doesn't exist
        let mut conn = pool
            .get()
            .map_err(|e| ApiError::Internal(format!("DB connection error: {}", e)))?;
        let user_id_clone = body.user_id.clone();
        let username_clone = body.username.clone();
        let role_clone = body.role.clone();

        // Check if user exists - if so, just create session, don't try to create user
        let existing_user =
            actix_web::web::block(move || User::find_by_id(&mut conn, user_id_clone))
                .await
                .map_err(|e| ApiError::Internal(format!("DB query error: {}", e)))?;

        match existing_user {
            Ok(_user) => {
                tracing::info!(
                    user_id = %body.user_id,
                    "DEBUG TEST LOGIN: Using existing user"
                );
            }
            Err(_) => {
                let mut conn = pool
                    .get()
                    .map_err(|e| ApiError::Internal(format!("DB connection error: {}", e)))?;
                let user_id = body.user_id.clone();
                let username = body.username.clone();
                let role = body.role.clone();

                actix_web::web::block(move || {
                    let new_user = NewUser {
                        id: user_id,
                        username,
                        password_hash: "<test-bypass-no-password>".to_string(),
                        role,
                        wallet_address: None,
                        wallet_id: None,
                    };
                    User::create(&mut conn, new_user)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("DB insert error: {}", e)))?
                .map_err(|e| ApiError::Internal(format!("User creation error: {}", e)))?;

                tracing::warn!(
                    user_id = %body.user_id,
                    "DEBUG TEST LOGIN: Created new test user in DB"
                );
            }
        }

        // Create session
        session
            .insert("user_id", body.user_id.clone())
            .map_err(|e| ApiError::Internal(format!("Session insert failed: {}", e)))?;
        session
            .insert("username", username_clone)
            .map_err(|e| ApiError::Internal(format!("Session insert failed: {}", e)))?;
        session
            .insert("role", role_clone)
            .map_err(|e| ApiError::Internal(format!("Session insert failed: {}", e)))?;

        tracing::warn!(
            user_id = %body.user_id,
            username = %body.username,
            role = %body.role,
            "DEBUG TEST LOGIN: Session created"
        );

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Test session created",
            "user_id": body.user_id,
            "username": body.username,
            "role": body.role
        })))
    }
}

/// Configure debug routes - only when `debug-endpoints` feature is enabled
#[cfg(feature = "debug-endpoints")]
fn configure_debug_routes(cfg: &mut web::ServiceConfig) {
    use server::handlers::escrow;

    cfg.service(
        web::scope("/api/debug")
            .route("/escrow/{id}", web::get().to(escrow::debug_escrow_info))
            .route(
                "/escrow/{id}/reset-status",
                web::post().to(escrow::debug_reset_escrow_status),
            )
            .route(
                "/escrow/{id}/broadcast",
                web::post().to(escrow::debug_broadcast_transaction),
            )
            .route(
                "/escrow/{id}/broadcast_cli",
                web::post().to(escrow::broadcast_via_cli),
            )
            .route(
                "/escrow/{id}/broadcast_dispute_cli",
                web::post().to(escrow::broadcast_dispute_cli),
            )
            .route(
                "/test-login",
                web::post().to(debug_endpoints::debug_test_login),
            ),
    );
    tracing::warn!("DEBUG ENDPOINTS ENABLED - These routes are exposed:");
    tracing::warn!("  - GET  /api/debug/escrow/{{id}}");
    tracing::warn!("  - POST /api/debug/escrow/{{id}}/reset-status");
    tracing::warn!("  - POST /api/debug/escrow/{{id}}/broadcast");
    tracing::warn!("  - POST /api/debug/escrow/{{id}}/broadcast_cli");
    tracing::warn!("  - POST /api/debug/escrow/{{id}}/broadcast_dispute_cli");
    tracing::warn!("  - POST /api/debug/test-login");
}

/// No-op when debug-endpoints feature is disabled (production builds)
#[cfg(not(feature = "debug-endpoints"))]
fn configure_debug_routes(_cfg: &mut web::ServiceConfig) {
    // Debug endpoints are disabled in production builds
}

/// Get Monero network configuration from MONERO_NETWORK environment variable
///
/// Returns (wallet_rpc_base_port, daemon_rpc_port, network_name)
///
/// Networks:
/// - stagenet: 38083-38085 (wallet RPCs), 38081 (daemon)
/// - testnet: 18082-18084 (wallet RPCs), 28081 (daemon)
/// - mainnet: 18082-18084 (wallet RPCs), 18081 (daemon) [DEFAULT]
fn get_monero_network_config() -> (u16, u16, &'static str) {
    let network = env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
    match network.to_lowercase().as_str() {
        "stagenet" => (38083, 38081, "stagenet"), // 38083-38085 for wallets, 38081 for daemon
        "testnet" => (18082, 28081, "testnet"),
        _ => (18082, 18081, "mainnet"), // Default to mainnet
    }
}

async fn ws_route(
    req: HttpRequest,
    stream: web::Payload,
    srv: web::Data<Addr<WebSocketServer>>,
    session: actix_session::Session,
    conn_mgr: web::Data<server::middleware::ConnectionManager>,
) -> Result<HttpResponse, Error> {
    // Get authenticated user ID from session
    let user_id = match session.get::<String>("user_id") {
        Ok(Some(uid)) => match Uuid::parse_str(&uid) {
            Ok(uuid) => uuid,
            Err(_) => {
                tracing::error!("Invalid user_id UUID in session: {}", uid);
                return Ok(HttpResponse::Unauthorized().body("Invalid session"));
            }
        },
        _ => {
            tracing::warn!("WebSocket connection attempted without authentication");
            return Ok(HttpResponse::Unauthorized().body("Authentication required"));
        }
    };

    // Check connection limits before accepting WebSocket
    let user_id_str = user_id.to_string();
    if let Err(e) = conn_mgr.try_acquire(&user_id_str) {
        tracing::warn!("WebSocket connection rejected for user {}: {}", user_id, e);
        return Ok(HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "Too many WebSocket connections",
            "message": "Maximum 3 connections per user",
            "limit": 3,
            "current": conn_mgr.current_user_connections(&user_id_str)
        })));
    }

    tracing::info!(
        "WebSocket connection established for user: {} (connections: {})",
        user_id,
        conn_mgr.current_user_connections(&user_id_str)
    );

    ws::start(
        WebSocketSession {
            id: Uuid::new_v4(),
            user_id,
            hb: std::time::Instant::now(),
            server: srv.get_ref().clone(),
            conn_mgr: conn_mgr.clone(),
            user_id_str: user_id_str.clone(),
        },
        &req,
        stream,
    )
}

#[actix_web::main]
async fn main() -> Result<()> {
    // 1. Load environment variables
    dotenvy::dotenv().ok();

    // 2. Initialize unified telemetry (logging + Sentry + Jaeger)
    // OPS-001: Sentry error tracking (if SENTRY_DSN is set)
    // OPS-002: Jaeger distributed tracing (if ENABLE_JAEGER=true)
    let _telemetry_guard =
        server::telemetry::init_telemetry().context("Failed to initialize telemetry")?;

    info!("Starting Monero Marketplace Server");

    // 2.2 Load XMR/USD exchange rate (admin-configured, no external API)
    let xmr_usd_rate = XmrUsdRate::from_env();

    if xmr_usd_rate.is_enabled() {
        info!("XMR/USD rate configured: ${:.2}", xmr_usd_rate.rate());
    } else {
        info!("XMR/USD display disabled (rate = 0 or not configured)");
    }

    // 2.5 Start wallet-rpc processes with watchdog supervision
    let watchdog = Arc::new(WalletRpcWatchdog::new(
        server::watchdog::WatchdogConfig::from_env(),
    ));

    watchdog
        .start_all_processes()
        .await
        .context("Failed to start wallet-rpc processes")?;

    // Spawn watchdog monitoring loop (auto-restart on crash)
    let watchdog_handle = watchdog.clone();
    tokio::spawn(async move {
        watchdog_handle.start_monitoring().await;
    });

    info!("WalletRpcWatchdog started - supervising 4 wallet-rpc processes");

    // 2.6 CRITICAL SECURITY: Validate environment variables for placeholder patterns
    // This prevents deployment with .env.example values (e.g., "your-xxx-here")
    // In production, this will PANIC if placeholders are detected
    placeholder_validator::validate_all_critical_env_vars();

    // 2.7 CRITICAL SECURITY: Validate platform wallet configuration on startup
    // This ensures:
    // - PLATFORM_FEE_WALLET is set and has valid checksum
    // - Address matches configured network (mainnet address for mainnet)
    // - Server PANICS if validation fails (prevents fund loss)
    use server::config::validate_platform_wallet_on_startup;
    validate_platform_wallet_on_startup();
    info!("✅ Platform wallet configuration validated");

    // 3. Database connection pool with SQLCipher encryption
    let database_url =
        env::var("DATABASE_URL").context("DATABASE_URL must be set in environment")?;

    // TM-002 MITIGATION: Shamir 3-of-5 secret sharing for DB encryption key
    // If DB_ENCRYPTION_KEY is NOT set in .env → interactive Shamir reconstruction
    // If DB_ENCRYPTION_KEY IS set in .env → development mode (insecure, warns user)
    let db_encryption_key = server::crypto::shamir_startup::get_db_encryption_key()
        .context("Failed to get DB encryption key (Shamir or .env)")?;

    let pool = create_pool(&database_url, &db_encryption_key)
        .context("Failed to create database connection pool")?;

    info!("Database connection pool created with SQLCipher encryption");

    // 3.5 Initialize Database Manager for automatic backups and recovery
    let db_config =
        DatabaseConfig::from_env().context("Failed to load database backup configuration")?;

    let db_manager =
        DatabaseManager::new(db_config.clone()).context("Failed to initialize DatabaseManager")?;

    // Verify database integrity at startup (can be skipped for development)
    let skip_integrity = std::env::var("SKIP_DB_INTEGRITY_CHECK")
        .ok()
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if skip_integrity {
        tracing::warn!(
            "⚠️  SKIP_DB_INTEGRITY_CHECK=true - Skipping database integrity verification"
        );
    } else {
        db_manager
            .verify_integrity(&db_config.database_path)
            .context("Database integrity check failed at startup")?;
        info!("✅ Database integrity verified");
    }

    // Create initial backup (reason: startup)
    let backup_path = db_manager
        .create_backup("startup")
        .context("Failed to create startup backup")?;
    info!("✅ Startup backup created: {}", backup_path.display());

    // Get backup statistics
    let backup_stats = db_manager
        .get_backup_stats()
        .context("Failed to get backup statistics")?;
    let oldest_backup_display = backup_stats
        .oldest_backup
        .as_ref()
        .map(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        })
        .unwrap_or_else(|| "N/A".to_string());
    info!(
        "📊 Backup stats - Total: {}, Size: {}MB, Oldest: {}",
        backup_stats.backup_count, backup_stats.total_size_mb, oldest_backup_display
    );

    // Spawn periodic cleanup task (every 24 hours)
    let db_manager_cleanup = db_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // 24 hours
        loop {
            interval.tick().await;
            match db_manager_cleanup.cleanup_old_backups() {
                Ok(_) => {
                    info!("✅ Backup rotation completed");
                }
                Err(e) => {
                    tracing::error!("❌ Backup rotation failed: {}", e);
                }
            }
        }
    });
    info!("✅ Backup cleanup task spawned (runs every 24 hours)");

    // 4. Session secret key
    // IMPORTANT: In production, load from secure environment variable
    // This should be a 64-byte cryptographically random key
    let session_secret = env::var("SESSION_SECRET_KEY").unwrap_or_else(|_| {
        if cfg!(debug_assertions) {
            tracing::warn!("SESSION_SECRET_KEY not set, using development key (dev mode only)");
            "development_key_do_not_use_in_production_minimum_64_bytes_required".to_string()
        } else {
            panic!("❌ FATAL: SESSION_SECRET_KEY environment variable MUST be set in production!");
        }
    });

    let secret_key = Key::from(session_secret.as_bytes());

    // 5. Initialize WebSocket server actor
    let websocket_server = WebSocketServer::default().start();

    // 5.5 Determine network configuration
    let network = env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
    let (base_port, daemon_port) = match network.as_str() {
        "stagenet" => (38082, 38081),
        "testnet" => (28082, 28081),
        _ => (18083, 18081), // Mainnet (default) - 18083 because monerod uses 18082
    };
    info!(
        "Configured for network: {} (Base RPC Port: {}, Daemon Port: {})",
        network, base_port, daemon_port
    );

    // 5.6 Initialize Daemon Pool for fee estimation and high-availability
    use monero_marketplace_wallet::{DaemonConfig, DaemonPool};

    let daemon_config = DaemonConfig {
        urls: vec![format!("http://127.0.0.1:{}", daemon_port)],
        health_check_interval_secs: 30,
        request_timeout_secs: 10,
        max_failures: 3,
    };

    let daemon_pool = Arc::new(
        DaemonPool::new(daemon_config)
            .await
            .context("Failed to initialize DaemonPool")?,
    );

    // Start background health checks (every 30 seconds)
    daemon_pool.start_health_checks();
    info!("✅ DaemonPool initialized with health monitoring (30s interval)");

    // 6. Initialize Wallet Manager with persistence and automatic recovery
    let encryption_key =
        hex::decode(&db_encryption_key).context("Failed to hex decode DB_ENCRYPTION_KEY")?;
    let wallet_manager = {
        // Configure 3 RPC instances (one per role: buyer, vendor, arbiter)
        // NOTE: URL should NOT include /json_rpc suffix - it's added by the RPC client
        let rpc_configs = vec![
            MoneroConfig {
                rpc_url: format!("http://127.0.0.1:{base_port}"), // Buyer
                rpc_user: None,
                rpc_password: None,
                timeout_seconds: 120,
            },
            MoneroConfig {
                rpc_url: format!("http://127.0.0.1:{}", base_port + 1), // Vendor
                rpc_user: None,
                rpc_password: None,
                timeout_seconds: 120,
            },
            MoneroConfig {
                rpc_url: format!("http://127.0.0.1:{}", base_port + 2), // Arbiter
                rpc_user: None,
                rpc_password: None,
                timeout_seconds: 120,
            },
        ];

        let mut wm =
            WalletManager::new_with_persistence(rpc_configs, pool.clone(), encryption_key.clone())?;

        // Enable wallet pool for production-ready wallet rotation
        let wallet_dir = std::path::PathBuf::from("./testnet-wallets");
        wm.enable_wallet_pool(wallet_dir)?;
        info!("WalletPool enabled for production-ready wallet management");

        // Attempt automatic recovery of active escrows
        info!("Attempting automatic recovery of active escrows...");
        match wm.recover_active_escrows().await {
            Ok(recovered_escrows) => {
                if recovered_escrows.is_empty() {
                    info!("No escrows found for recovery");
                } else {
                    info!(
                        "✅ Successfully recovered {} escrow wallet(s): {:?}",
                        recovered_escrows.len(),
                        recovered_escrows
                    );

                    // Emit MultisigRecovered WebSocket events for each recovered escrow
                    for escrow_id_str in &recovered_escrows {
                        if let Ok(escrow_id) = Uuid::parse_str(escrow_id_str) {
                            use server::websocket::WsEvent;
                            websocket_server.do_send(WsEvent::MultisigRecovered {
                                escrow_id,
                                recovered_wallets: vec![
                                    "buyer".to_string(),
                                    "vendor".to_string(),
                                    "arbiter".to_string(),
                                ],
                                phase: "Recovered from persistence".to_string(),
                                recovered_at: chrono::Utc::now().timestamp(),
                            });
                            info!("Sent MultisigRecovered event for escrow {}", escrow_id);
                        }
                    }
                }
            }
            Err(e) => {
                // Log error but don't fail startup - recovery is best-effort
                tracing::error!("⚠️  Escrow recovery encountered errors: {}", e);
                info!("Server will continue with fresh wallet state");
            }
        }

        Arc::new(Mutex::new(wm))
    };

    // 7. Ensure system arbiter exists
    {
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Argon2,
        };
        use server::models::user::{NewUser, User};

        let mut conn = pool.get().context("Failed to get DB connection")?;
        let arbiter_exists = web::block(move || {
            use diesel::prelude::*;
            use server::schema::users::dsl::*;
            users
                .filter(role.eq("arbiter"))
                .first::<User>(&mut conn)
                .optional()
        })
        .await
        .context("Failed to check for arbiter")??;

        // Generate new password for arbiter (create if not exists, update if exists)
        let should_reset_password = std::env::var("RESET_ARBITER_PASSWORD").is_ok();

        if arbiter_exists.is_none() || should_reset_password {
            info!("Creating/updating system arbiter...");

            // Generate random 16-character password
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let password: String = (0..16)
                .map(|_| {
                    let idx = rng.gen_range(0..62);
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                        .chars()
                        .nth(idx)
                        .unwrap()
                })
                .collect();

            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .context("Failed to hash password")?
                .to_string();

            let mut conn = pool.get().context("Failed to get DB connection")?;

            if arbiter_exists.is_some() {
                // Update existing arbiter password
                let hash_clone = password_hash.clone();
                web::block(move || {
                    use diesel::prelude::*;
                    use server::schema::users::dsl::{password_hash, username, users};
                    diesel::update(users.filter(username.eq("arbiter_system")))
                        .set(password_hash.eq(hash_clone))
                        .execute(&mut conn)
                })
                .await
                .context("Failed to update arbiter password")??;
                info!("⚠️  ✅ System arbiter password RESET");
            } else {
                // Create new arbiter
                let new_arbiter = NewUser {
                    id: Uuid::new_v4().to_string(),
                    username: "arbiter_system".to_string(),
                    password_hash,
                    wallet_address: None,
                    wallet_id: None,
                    role: "arbiter".to_string(),
                };

                web::block(move || User::create(&mut conn, new_arbiter))
                    .await
                    .context("Failed to create arbiter")??;
                info!("⚠️  ✅ System arbiter created successfully");
            }
            info!("📋 SAVE THIS IMMEDIATELY - Arbiter credentials:");
            info!("   Username: arbiter_system");
            info!("   Password: {}", password);
            info!("⚠️  This password will NOT be shown again. Change it immediately after first login.");
            info!("🔐 NOTE: Arbiter must generate/restore wallet on first escrow participation via /escrow/setup");
        } else {
            info!("System arbiter already exists");
        }
    }

    // 8. Initialize Escrow Orchestrator
    let escrow_orchestrator = Arc::new(EscrowOrchestrator::new(
        wallet_manager.clone(),
        pool.clone(),
        websocket_server.clone(),
        encryption_key.clone(),
    ));

    // 8b. Initialize Non-Custodial Escrow Coordinator (Haveno-inspired) - v0.4.0 Stateless Design
    let escrow_coordinator = Arc::new(EscrowCoordinator::new(
        Arc::new(pool.clone()),
        encryption_key.clone(),
        websocket_server.clone(),
    ));

    info!("✅ Non-custodial EscrowCoordinator initialized (stateless design - reads from escrows + wallet_rpc_configs)");

    // 8c. Initialize DbMultisigCoordinator (database-backed multisig coordination)
    let multisig_coordinator = Arc::new(DbMultisigCoordinator::new(
        Arc::new(pool.clone()),
        Some(3600), // 1 hour session timeout
    ));
    info!("✅ DbMultisigCoordinator initialized with database persistence");

    // 8c2. Initialize WasmMultisigStore (SQLite-backed store for WASM multisig coordination)
    use server::models::wasm_multisig_info::SqliteWasmMultisigStore;
    let wasm_multisig_store = Arc::new(SqliteWasmMultisigStore::new(pool.clone()));
    info!("✅ SqliteWasmMultisigStore initialized with database persistence");

    // 8d. Initialize SyncProxyService (Light Wallet Server for WASM wallets)
    let sync_proxy = Arc::new(
        SyncProxyService::new(
            format!("http://127.0.0.1:{}/json_rpc", base_port + 1), // vendor wallet-rpc
            format!("http://127.0.0.1:{daemon_port}/json_rpc"),     // daemon
        )
        .context("Failed to initialize SyncProxyService")?,
    );
    let sync_proxy_data = web::Data::from(sync_proxy);
    info!("✅ SyncProxyService initialized for Light Wallet Server functionality");

    // 9. Initialize and start Timeout Monitor (background service)
    use server::config::TimeoutConfig;
    use server::services::timeout_monitor::TimeoutMonitor;

    let timeout_config = TimeoutConfig::from_env();
    info!(
        "TimeoutConfig loaded: multisig_setup={}s, funding={}s, tx_confirmation={}s",
        timeout_config.multisig_setup_timeout_secs,
        timeout_config.funding_timeout_secs,
        timeout_config.transaction_confirmation_timeout_secs
    );

    let timeout_monitor = Arc::new(TimeoutMonitor::new_with_persistence(
        pool.clone(),
        websocket_server.clone(),
        timeout_config,
        encryption_key.clone(),
    ));

    // Spawn TimeoutMonitor in background
    let timeout_monitor_handle = timeout_monitor.clone();
    tokio::spawn(async move {
        timeout_monitor_handle.start_monitoring().await;
    });
    info!("TimeoutMonitor background service started");

    // Initialize and start BlockchainMonitor for automatic payment detection
    use server::services::blockchain_monitor::{BlockchainMonitor, MonitorConfig};
    let blockchain_monitor = Arc::new(BlockchainMonitor::new(
        wallet_manager.clone(),
        pool.clone(),
        websocket_server.clone(),
        MonitorConfig::default(), // poll_interval: 30s, required_confirmations: 10
        encryption_key.clone(),
    ));

    let blockchain_monitor_handle = blockchain_monitor.clone();
    tokio::spawn(async move {
        blockchain_monitor_handle.start_monitoring().await;
    });
    info!("BlockchainMonitor background service started (30s polling interval)");

    // Initialize and start MultisigAutoCoordinator for automatic setup
    use server::services::multisig_auto_coordinator::MultisigAutoCoordinator;
    let auto_coordinator = Arc::new(MultisigAutoCoordinator::new(
        pool.clone(),
        websocket_server.clone(),
        Some(5), // Poll every 5 seconds
    ));

    let auto_coordinator_handle = auto_coordinator.clone();
    tokio::spawn(async move {
        auto_coordinator_handle.start_monitoring().await;
    });
    info!("MultisigAutoCoordinator background service started (5s polling interval)");

    // 9.5. Initialize Redis pool and ArbiterAutoDkg for automated arbiter DKG
    use secrecy::SecretString;
    use server::redis_pool::init_redis_pool;
    use server::services::arbiter_auto_dkg::ArbiterAutoDkg;
    use server::services::arbiter_watchdog::ArbiterKeyVault;

    let arbiter_auto_dkg: Option<Arc<ArbiterAutoDkg>> = match init_redis_pool() {
        Ok(redis_pool) => {
            info!("✅ Redis pool initialized");

            // Get arbiter vault master password (optional for auto-DKG)
            match std::env::var("ARBITER_VAULT_MASTER_PASSWORD") {
                Ok(password) => {
                    match ArbiterKeyVault::new(redis_pool.clone(), SecretString::new(password)) {
                        Ok(key_vault) => {
                            let auto_dkg = Arc::new(ArbiterAutoDkg::new(pool.clone(), key_vault));
                            info!("✅ ArbiterAutoDkg initialized - arbiter will auto-generate DKG packages");
                            Some(auto_dkg)
                        }
                        Err(e) => {
                            warn!(
                                "ArbiterKeyVault init failed: {} - arbiter auto-DKG disabled",
                                e
                            );
                            None
                        }
                    }
                }
                Err(_) => {
                    warn!("ARBITER_VAULT_MASTER_PASSWORD not set - arbiter auto-DKG disabled");
                    warn!("  Set this env var to enable automatic arbiter DKG package generation");
                    None
                }
            }
        }
        Err(e) => {
            warn!("Redis pool init failed: {} - arbiter auto-DKG disabled", e);
            warn!("  Ensure Redis is running on REDIS_URL (default: redis://127.0.0.1:6379)");
            None
        }
    };

    // 9.5 Initialize ArbiterWatchdog for auto-signing
    use server::services::arbiter_watchdog::{ArbiterWatchdog, WatchdogConfig};

    match init_redis_pool() {
        Ok(redis_pool) => match WatchdogConfig::from_env() {
            Ok(watchdog_config) => {
                match ArbiterWatchdog::new(pool.clone(), redis_pool, watchdog_config).await {
                    Ok(watchdog) => {
                        let watchdog_arc = Arc::new(watchdog);
                        tokio::spawn(async move {
                            watchdog_arc.run().await;
                        });
                        info!("✅ ArbiterWatchdog started - monitoring for auto-signing");
                    }
                    Err(e) => {
                        warn!("ArbiterWatchdog init failed: {} - auto-signing disabled", e);
                    }
                }
            }
            Err(e) => {
                warn!("WatchdogConfig init failed: {} - auto-signing disabled", e);
            }
        },
        Err(e) => {
            warn!("Redis not available - ArbiterWatchdog disabled: {}", e);
        }
    }

    // 10. Initialize Tera template engine
    let tera = Tera::new("templates/**/*.html").context("Failed to initialize Tera templates")?;
    info!("Tera template engine initialized");

    // 11. Initialize IPFS client for reputation export
    use server::ipfs::client::IpfsClient;
    let ipfs_client = IpfsClient::new_local().context("Failed to initialize IPFS client")?;
    info!("IPFS client initialized (local node at 127.0.0.1:5001)");

    // 11.5 Initialize Webhook Dispatcher for B2B webhook delivery
    let webhook_dispatcher = Arc::new(WebhookDispatcher::new(pool.clone()));

    // Start webhook retry worker (polls every 30 seconds for failed deliveries)
    let webhook_retry_worker = WebhookRetryWorker::new(webhook_dispatcher.clone(), 30);
    tokio::spawn(async move {
        webhook_retry_worker.start().await;
    });
    info!("WebhookDispatcher initialized with retry worker (30s polling interval)");

    info!("Starting HTTP server on http://127.0.0.1:8080");

    // 12. Start HTTP server
    // Create shared state for rate limiting across workers
    let auth_rate_limit_storage = Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Initialize ConnectionManager for WebSocket DoS protection
    // - Max 3 concurrent connections per user (default)
    // - Max 1000 global concurrent connections (default)
    let conn_mgr = web::Data::new(ConnectionManager::new());
    info!("WebSocket ConnectionManager initialized (3 per user, 1000 global)");

    // P0 Security: Registration rate limiting (5 per IP per hour)
    let registration_rate_limit = web::Data::new(new_registration_rate_limit_storage());
    info!("Registration rate limiter initialized (5 per IP per hour)");

    // B2B API Key rate limiting (tier-based: Free 60/min, Pro 300/min, Enterprise 1000/min)
    let api_key_rate_limit = new_api_key_rate_limit_storage();
    info!("API key rate limiter initialized (tier-based)");

    // Initialize Redis pool for idempotency middleware (shared across workers)
    // Pool creation is lazy — actual Redis connections happen on first use.
    // The IdempotencyMiddleware fails-open if Redis is unreachable at runtime.
    let idempotency_redis_pool: server::redis_pool::RedisPool =
        init_redis_pool().unwrap_or_else(|e| {
            warn!(
                "Redis pool init warning (idempotency will fail-open): {}",
                e
            );
            // Create pool with default URL anyway — middleware degrades gracefully
            let cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:6379");
            cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("Failed to create fallback Redis pool config")
        });

    // Build CORS configuration from environment
    let cors_origins = env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();

    HttpServer::new(move || {
        // CORS middleware (outermost — must wrap everything for preflight handling)
        let cors = if cors_origins.is_empty() {
            Cors::default()
                .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
                .allowed_headers(vec![
                    actix_web::http::header::AUTHORIZATION,
                    actix_web::http::header::CONTENT_TYPE,
                    actix_web::http::header::ACCEPT,
                ])
                .allowed_header("X-API-Key")
                .allowed_header("X-Request-ID")
                .allowed_header("X-Idempotency-Key")
                .allowed_header("Idempotency-Key")
                .max_age(3600)
        } else {
            let mut cors = Cors::default();
            for origin in cors_origins.split(',') {
                let trimmed = origin.trim();
                if !trimmed.is_empty() {
                    cors = cors.allowed_origin(trimmed);
                }
            }
            cors.allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
                .allowed_headers(vec![
                    actix_web::http::header::AUTHORIZATION,
                    actix_web::http::header::CONTENT_TYPE,
                    actix_web::http::header::ACCEPT,
                ])
                .allowed_header("X-API-Key")
                .allowed_header("X-Request-ID")
                .allowed_header("X-Idempotency-Key")
                .allowed_header("Idempotency-Key")
                .max_age(3600)
        };

        App::new()
            // CORS (OUTERMOST - handles preflight before other middleware)
            .wrap(cors)
            // Request ID tracing (assigns UUID to each request)
            .wrap(RequestIdMiddleware)
            // Security headers (INNER - runs SECOND on request, reads nonce)
            .wrap(SecurityHeadersMiddleware)
            // CSP nonce injection (OUTER - runs FIRST on request, sets nonce)
            .wrap(CspNonceMiddleware)
            // Logging middleware (logs all requests)
            .wrap(Logger::default())
            // Global rate limiter (100 req/min per IP)
            .wrap(RateLimitMiddleware::new(100, 60))
            // Session middleware
            // Security features:
            // - HttpOnly: prevents JavaScript access
            // - Secure: HTTPS only in release builds
            // - SameSite::Strict: CSRF protection
            // - Max age: 24 hours
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_name("monero_marketplace_session".to_string())
                    .cookie_http_only(true)
                    .cookie_secure(!cfg!(debug_assertions))
                    .cookie_same_site(actix_web::cookie::SameSite::Strict)
                    .session_lifecycle(
                        PersistentSession::default().session_ttl(Duration::hours(24)),
                    )
                    .build(),
            )
            // Shared app state
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(wallet_manager.clone()))
            .app_data(web::Data::from(escrow_orchestrator.clone()))
            .app_data(web::Data::from(escrow_coordinator.clone()))
            .app_data(web::Data::from(multisig_coordinator.clone()))
            .app_data(web::Data::new(wasm_multisig_store.clone()))
            .app_data(web::Data::new(websocket_server.clone()))
            .app_data(web::Data::new(tera.clone()))
            .app_data(web::Data::new(ipfs_client.clone()))
            .app_data(web::Data::new(encryption_key.clone()))
            .app_data(sync_proxy_data.clone())
            .app_data(conn_mgr.clone())
            .app_data(registration_rate_limit.clone())
            .app_data(web::Data::new(xmr_usd_rate))
            .app_data(web::Data::new(daemon_pool.clone()))
            .app_data(web::Data::new(webhook_dispatcher.clone()))
            .app_data(web::Data::new(api_key_rate_limit.clone()))
            .app_data(web::Data::new(arbiter_auto_dkg.clone()))
            // Custom JSON config with error logging
            .app_data(
                web::JsonConfig::default()
                    .limit(1024 * 1024) // 1MB limit
                    .error_handler(|err, req| {
                        let err_msg = format!("{err}");
                        let path = req.path().to_string();
                        tracing::error!("[JSON-PARSE] Error: {} - Path: {}", err_msg, path);
                        actix_web::error::InternalError::from_response(
                            err,
                            actix_web::HttpResponse::BadRequest().json(serde_json::json!({
                                "error": format!("JSON parse error: {}", err_msg),
                                "path": path
                            })),
                        )
                        .into()
                    }),
            )
            // Static files (serve CSS, JS, images, WASM)
            .service(fs::Files::new("/static", "./static").show_files_listing())
            // Swagger UI static files
            .service(fs::Files::new("/swagger", "./server/static/swagger").index_file("index.html"))
            // Developer Portal
            .service(
                fs::Files::new("/developers", "./docs/developer-portal").index_file("index.html"),
            )
            // SPA assets (React build output)
            .service(fs::Files::new("/assets", "./static/app/assets"))
            // EaaS SPA: Serve React app for all frontend routes
            // The React app handles routing client-side
            .route("/", web::get().to(serve_spa))
            .route("/dashboard", web::get().to(serve_spa))
            .route("/escrow/{id}", web::get().to(serve_spa))
            .route("/docs", web::get().to(serve_spa))
            .route("/login", web::get().to(serve_spa))
            .route("/register", web::get().to(serve_spa))
            // API Routes
            .route("/api/health", web::get().to(health_check))
            // WebSocket route
            .route("/ws", web::get().to(ws_route))
            // Auth endpoints with rate limiting (50 req/60s per IP for dev, reduce to 5 for production)
            .service(
                web::scope("/api/auth")
                    .wrap(RateLimitMiddleware::new_with_storage(
                        auth_rate_limit_storage.clone(),
                        50,
                        60,
                    ))
                    .service(auth::register)
                    .service(auth::login)
                    .service(auth::login_json) // JSON API for SPA
                    .service(auth::register_json) // JSON API for SPA
                    .service(auth::whoami)
                    .service(auth::logout)
                    .route("/recover", web::post().to(auth::recover_account)),
            )
            // Settings endpoints
            .service(web::scope("/api/settings").service(auth::update_wallet_address))
            // Light Wallet Server endpoints (WASM client sync API)
            // NOTE: Must be BEFORE generic /api scope to avoid route shadowing
            .service(
                web::scope("/api/sync")
                    .route("/scan", web::post().to(sync::scan_outputs))
                    .route("/broadcast", web::post().to(sync::broadcast_transaction)),
            )
            // DEBUG ENDPOINTS - Only available when compiled with --features debug-endpoints
            // Production builds (cargo build --release) will NOT include these routes
            .configure(configure_debug_routes)
            // ============================================================================
            // B2B API v1 - API Key authenticated endpoints for marketplace integrations
            // ============================================================================
            .service(
                web::scope("/api/v1")
                    .wrap(RequireApiKey::new(
                        web::Data::new(pool.clone()),
                        api_key_rate_limit.clone(),
                    ))
                    .wrap(IdempotencyMiddleware::new(idempotency_redis_pool.clone()))
                    // Escrow CRUD (scoped to API key owner)
                    .route("/escrows/create", web::post().to(user::create_escrow))
                    .route("/escrows/{id}", web::get().to(escrow::get_escrow))
                    .route("/escrows/{id}/join", web::post().to(user::join_escrow))
                    .route(
                        "/escrows/{id}/deliver",
                        web::post().to(user::mark_delivered),
                    )
                    .route(
                        "/escrows/{id}/confirm",
                        web::post().to(user::confirm_delivery),
                    )
                    .route(
                        "/escrows/{id}/dispute",
                        web::post().to(escrow::initiate_dispute),
                    )
                    .route(
                        "/escrows/{id}/resolve",
                        web::post().to(escrow::resolve_dispute),
                    )
                    .route(
                        "/escrows/{id}/release",
                        web::post().to(escrow::release_funds),
                    )
                    .route("/escrows/{id}/refund", web::post().to(escrow::refund_funds))
                    .route(
                        "/escrows/{id}/funding-notification",
                        web::post().to(escrow::notify_funding),
                    )
                    // Batch operations (B2B)
                    .route("/escrows/batch", web::post().to(batch::batch_operations))
                    // FROST DKG + Signing (B2B path)
                    .configure(frost_escrow::configure_frost_routes)
                    // Webhook management
                    .configure(webhooks::configure_webhook_routes)
                    // Client fee config + estimation
                    .configure(client_fees::configure_client_fee_routes)
                    // Analytics
                    .configure(analytics::configure_analytics_routes)
                    // User escrow listing
                    .route("/user/escrows", web::get().to(user::get_user_escrows)),
            )
            // ============================================================================
            // EaaS Core API - Escrow-as-a-Service Endpoints (Session + API Key dual-auth)
            // ============================================================================
            .service(
                web::scope("/api")
                    // API Documentation (Swagger UI)
                    .service(docs::serve_openapi_spec)
                    .service(docs::redirect_to_swagger)
                    // Dispute Evidence (IPFS uploads)
                    .service(dispute_evidence::upload_evidence)
                    .service(dispute_evidence::list_evidence)
                    .service(dispute_evidence::get_evidence)
                    // Escrow Core
                    .route("/escrow/{id}", web::get().to(escrow::get_escrow))
                    .service(escrow::get_escrow_status)
                    .service(escrow::check_escrow_balance)
                    // NON-CUSTODIAL: Client wallet registration
                    .route(
                        "/escrow/register-wallet-rpc",
                        web::post().to(escrow::register_wallet_rpc),
                    )
                    // v0.5.0: WASM Wallet Registration
                    .route(
                        "/escrow/register-wasm-wallet",
                        web::post().to(escrow::register_wasm_wallet),
                    )
                    .route(
                        "/escrow/{id}/prepare",
                        web::post().to(escrow::prepare_multisig),
                    )
                    .route(
                        "/escrow/{id}/release",
                        web::post().to(escrow::release_funds),
                    )
                    .route("/escrow/{id}/refund", web::post().to(escrow::refund_funds))
                    .route(
                        "/escrow/{id}/dispute",
                        web::post().to(escrow::initiate_dispute),
                    )
                    // NON-CUSTODIAL: Get multisig address for escrow
                    .route(
                        "/escrow/{id}/multisig-address",
                        web::get().to(escrow::get_multisig_address),
                    )
                    // NON-CUSTODIAL: Buyer funding notification with commitment data
                    .route(
                        "/escrow/{id}/funding-notification",
                        web::post().to(escrow::notify_funding),
                    )
                    .route(
                        "/escrow/{id}/resolve",
                        web::post().to(escrow::resolve_dispute),
                    )
                    // Dispute auto-claim: winning party submits FROST share
                    .route(
                        "/escrow/{id}/submit-dispute-share",
                        web::post().to(escrow::broadcast_dispute_cli),
                    )
                    // Dispute signing pair (v0.66.3)
                    .service(escrow::set_dispute_signing_pair)
                    // Escrow Messaging endpoints
                    .route(
                        "/escrow/{id}/messages",
                        web::post().to(escrow::send_message),
                    )
                    .route("/escrow/{id}/messages", web::get().to(escrow::get_messages))
                    // NON-CUSTODIAL V2: Haveno-inspired pure coordinator
                    .route(
                        "/v2/escrow/register-wallet",
                        web::post().to(noncustodial::register_client_wallet),
                    )
                    .route(
                        "/v2/escrow/coordinate-exchange",
                        web::post().to(noncustodial::coordinate_multisig_exchange),
                    )
                    .route(
                        "/v2/escrow/coordination-status/{escrow_id}",
                        web::get().to(noncustodial::get_coordination_status),
                    )
                    // NON-CUSTODIAL V2: Multisig sync round coordination
                    .route(
                        "/v2/escrow/sync-round",
                        web::post().to(noncustodial::coordinate_sync_round),
                    )
                    // NON-CUSTODIAL V2: Funds received notification
                    .route(
                        "/v2/escrow/funds-received",
                        web::post().to(noncustodial::funds_received_notification),
                    )
                    // TM-003: Challenge-Response multisig validation
                    .service(multisig_challenge::request_multisig_challenge)
                    .service(multisig_challenge::submit_multisig_info_with_signature)
                    .service(multisig_challenge::cleanup_expired_challenges)
                    // Client-side wallet registration (Zero-Trust)
                    .service(wallet::get_wallet_status)
                    .service(wallet::register_wallet)
                    // Multisig Coordination API (Non-Custodial)
                    .service(multisig::init_multisig_session)
                    .service(multisig::submit_multisig_info)
                    .service(multisig::get_peer_info)
                    .service(multisig::get_multisig_status)
                    // WASM Multisig (simple in-memory coordination for v0.5.0)
                    .service(wasm_multisig::submit_multisig_info)
                    .service(wasm_multisig::get_peer_infos)
                    .service(wasm_multisig::finalize_multisig)
                    // FROST DKG + Signing 2-of-3 threshold CLSAG (RFC 9591)
                    // All FROST routes merged into single scope to avoid Actix routing conflicts
                    .configure(frost_escrow::configure_frost_routes)
                    // Phase 2: 100% Non-Custodial Encrypted Relay
                    .configure(encrypted_relay::configure_encrypted_relay_routes)
                    // Fee estimation and daemon health endpoints
                    .configure(fees::configure_fee_routes)
                    // B2B Webhooks API (HMAC-SHA256 signed event delivery)
                    .configure(webhooks::configure_webhook_routes)
                    // Monero address validation via RPC
                    .service(monero_validator::validate_address)
                    // Multisig wallet coordination
                    .service(multisig_wallet::coordinate_multisig_setup)
                    .service(multisig_wallet::get_multisig_status)
                    .service(multisig_wallet::finalize_multisig)
                    // Notification endpoints (persistent notifications for header icon)
                    .service(notifications::get_notifications)
                    .service(notifications::get_unread_count)
                    .service(notifications::mark_notification_read)
                    .service(notifications::mark_all_notifications_read)
                    .service(notifications::mark_read_by_link)
                    // Secure E2E Messaging endpoints (X25519 ECDH + ChaCha20Poly1305)
                    // NOTE: Static routes MUST come before wildcard {id} routes
                    .route(
                        "/secure-messages/keypair",
                        web::post().to(secure_messages::create_keypair),
                    )
                    .route(
                        "/secure-messages/keypair",
                        web::get().to(secure_messages::get_own_keypair),
                    )
                    .route(
                        "/secure-messages/pubkey/{user_id}",
                        web::get().to(secure_messages::get_user_pubkey),
                    )
                    .route(
                        "/secure-messages/send",
                        web::post().to(secure_messages::send_message),
                    )
                    .route(
                        "/secure-messages/conversations",
                        web::get().to(secure_messages::list_conversations),
                    )
                    .route(
                        "/secure-messages/unread-count",
                        web::get().to(secure_messages::get_unread_count),
                    )
                    .route(
                        "/secure-messages/conversation/{user_id}",
                        web::get().to(secure_messages::get_conversation),
                    )
                    .route(
                        "/secure-messages/{id}/read",
                        web::post().to(secure_messages::mark_message_read),
                    )
                    .route(
                        "/secure-messages/{id}",
                        web::delete().to(secure_messages::delete_message),
                    )
                    // User endpoints
                    .route("/user/escrows", web::get().to(user::get_user_escrows))
                    .route(
                        "/user/escrows/dashboard",
                        web::get().to(user::get_user_escrows_dashboard),
                    )
                    // Escrow creation and state transitions
                    .route("/escrows/create", web::post().to(user::create_escrow))
                    // EaaS endpoints
                    .route(
                        "/escrows/{id}/public",
                        web::get().to(user::get_escrow_public),
                    )
                    .route("/escrows/{id}/join", web::post().to(user::join_escrow))
                    .route(
                        "/escrows/{id}/lobby-status",
                        web::get().to(user::get_lobby_status),
                    )
                    .route("/escrows/{id}/start-dkg", web::post().to(user::start_dkg))
                    .route("/escrow/{id}/deliver", web::post().to(user::mark_delivered))
                    .route(
                        "/escrow/{id}/confirm",
                        web::post().to(user::confirm_delivery),
                    )
                    // Arbiter endpoints
                    .route(
                        "/arbiter/disputes",
                        web::get().to(user::get_arbiter_disputes),
                    )
                    .route(
                        "/arbiter/disputes/{id}",
                        web::get().to(user::get_arbiter_dispute_detail),
                    )
                    // Escrow signing
                    .route(
                        "/v2/escrow/{id}/sign-action",
                        web::post().to(escrow::sign_action),
                    )
                    // WASM CLSAG signing preparation and broadcast
                    .route(
                        "/v2/escrow/{id}/prepare-sign",
                        web::get().to(escrow::prepare_sign),
                    )
                    .route(
                        "/v2/escrow/{id}/submit-signature",
                        web::post().to(escrow::submit_signature),
                    )
                    .route(
                        "/v2/escrow/{id}/broadcast-tx",
                        web::post().to(escrow::broadcast_transaction),
                    )
                    // MuSig2 nonce aggregation
                    .route(
                        "/v2/escrow/{id}/nonce-status",
                        web::get().to(escrow::get_nonce_status),
                    )
                    .route(
                        "/v2/escrow/{id}/submit-nonce-commitment",
                        web::post().to(escrow::submit_nonce_commitment),
                    )
                    // Round-robin CLSAG signing
                    .route("/v2/escrow/{id}", web::get().to(escrow::get_escrow_details))
                    // Partial key image submission (MUST be called before signing)
                    .route(
                        "/v2/escrow/{id}/submit-partial-key-image",
                        web::post().to(escrow::submit_partial_key_image),
                    )
                    // Set vendor payout address (before shipping)
                    .route(
                        "/v2/escrow/{id}/set-payout-address",
                        web::post().to(escrow::set_payout_address),
                    )
                    // Set buyer refund address (v0.66.3 - for dispute refunds)
                    .service(escrow::set_refund_address)
                    .route(
                        "/v2/escrow/{id}/sign/init",
                        web::post().to(escrow::sign_init),
                    )
                    .route(
                        "/v2/escrow/{id}/sign/partial",
                        web::get().to(escrow::get_partial_tx),
                    )
                    .route(
                        "/v2/escrow/{id}/sign/complete",
                        web::post().to(escrow::sign_complete),
                    )
                    // Round-robin signing (100% NON-CUSTODIAL - fixes 2-of-3 key overlap)
                    .route(
                        "/escrow/{id}/initiate-round-robin-signing",
                        web::post().to(escrow::initiate_round_robin_signing),
                    )
                    .route(
                        "/escrow/{id}/submit-multisig-txset",
                        web::post().to(escrow::submit_multisig_txset),
                    )
                    .route(
                        "/escrow/{id}/submit-round-robin-signature",
                        web::post().to(escrow::submit_round_robin_signature),
                    )
                    .route(
                        "/escrow/{id}/confirm-round-robin-broadcast",
                        web::post().to(escrow::confirm_round_robin_broadcast),
                    )
                    .route(
                        "/escrow/{id}/round-robin-status",
                        web::get().to(escrow::get_round_robin_status),
                    )
                    // B2B API Key management (session authenticated)
                    .service(api_keys::create_api_key)
                    .service(api_keys::list_api_keys)
                    .service(api_keys::get_api_key)
                    .service(api_keys::revoke_api_key)
                    .service(api_keys::delete_api_key)
                    // Webhook management
                    .configure(webhooks::configure_webhook_routes)
                    // Escrow E2EE Chat (X25519 ECDH + ChaCha20Poly1305)
                    .configure(escrow_chat::configure_escrow_chat_routes),
            )
            // Admin-only endpoints (requires admin role)
            .service(
                web::scope("/admin")
                    .wrap(AdminAuth)
                    .service(monitoring::get_escrow_health)
                    .service(monitoring::get_escrow_status)
                    .service(api_keys::update_api_key_tier),
            )
    })
    .bind(("127.0.0.1", 8080))
    .context("Failed to bind to 127.0.0.1:8080")?
    .run()
    .await
    .context("HTTP server error")?;

    Ok(())
}
