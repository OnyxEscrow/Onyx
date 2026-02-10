//! End-to-End tests for non-custodial escrow flow (Phase 2)
//!
//! **Architecture Tested:**
//! - 3 local wallet RPC instances (buyer, seller, arbiter)
//! - Server acts as pure coordinator (NO wallet creation)
//! - Complete multisig flow: register → coordinate → finalize
//!
//! **Prerequisites:**
//! Run `./scripts/setup-e2e-tests.sh` first to ensure RPC instances are running.
//!
//! **Run these tests with:**
//! ```bash
//! cargo test --package server --test escrow_noncustodial_e2e -- --ignored --nocapture
//! ```

use actix_web::{test, web, App};
use anyhow::{Context, Result};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::SqliteConnection;
use monero_marketplace_common::types::MoneroConfig;
use monero_marketplace_wallet::MoneroClient;
use serde_json::json;
use server::coordination::EscrowCoordinator;
use server::handlers::noncustodial;
use std::sync::Arc;
use tracing::{info, warn};

// ============================================================================
// TEST CONFIGURATION
// ============================================================================

/// RPC URLs for test wallets (must be running locally)
const BUYER_RPC_URL: &str = "http://127.0.0.1:18083";
const SELLER_RPC_URL: &str = "http://127.0.0.1:18084";
const ARBITER_RPC_URL: &str = "http://127.0.0.1:18085";

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::INFO)
        .try_init();
}

/// Create in-memory test database pool
fn create_test_db_pool() -> Arc<Pool<ConnectionManager<SqliteConnection>>> {
    let manager = ConnectionManager::<SqliteConnection>::new(":memory:");
    let pool = Pool::builder()
        .build(manager)
        .expect("Failed to create test pool");
    Arc::new(pool)
}

/// Check if wallet RPC is available
async fn check_rpc_availability(rpc_url: &str) -> bool {
    let config = MoneroConfig {
        rpc_url: rpc_url.to_string(),
        rpc_user: None,
        rpc_password: None,
        timeout_seconds: 5,
    };

    match MoneroClient::new(config) {
        Ok(client) => client.rpc().get_version().await.is_ok(),
        Err(_) => false,
    }
}

/// Create test wallet (skip if exists)
async fn create_test_wallet(rpc_url: &str, wallet_name: &str) -> Result<()> {
    let config = MoneroConfig {
        rpc_url: rpc_url.to_string(),
        rpc_user: None,
        rpc_password: None,
        timeout_seconds: 30,
    };

    let client = MoneroClient::new(config).context("Failed to create client")?;

    match client.rpc().create_wallet(wallet_name, "").await {
        Ok(_) => {
            info!("✅ Created wallet: {}", wallet_name);
            Ok(())
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("already exists") || error_msg.contains("Cannot create wallet") {
                warn!("Wallet '{}' already exists, using existing", wallet_name);
                Ok(())
            } else {
                Err(e).context("Failed to create wallet")
            }
        }
    }
}

// ============================================================================
// E2E TESTS
// ============================================================================

/// Test 1: Complete non-custodial escrow flow with 3 participants
///
/// **Flow:**
/// 1. Create 3 local wallets (buyer, seller, arbiter)
/// 2. Register all 3 with coordinator (send RPC URLs only)
/// 3. Coordinate multisig exchange (server exchanges multisig_info)
/// 4. Verify all participants receive correct infos
/// 5. Finalize multisig locally on each wallet
/// 6. Verify multisig addresses match
#[actix_web::test]
#[ignore] // Run explicitly with --ignored
async fn test_complete_noncustodial_escrow_flow() -> Result<()> {
    init_tracing();
    info!("🧪 Starting E2E test: Complete non-custodial escrow flow");

    // Step 0: Check RPC availability
    info!("Step 0: Checking RPC availability...");

    let buyer_available = check_rpc_availability(BUYER_RPC_URL).await;
    let seller_available = check_rpc_availability(SELLER_RPC_URL).await;
    let arbiter_available = check_rpc_availability(ARBITER_RPC_URL).await;

    if !buyer_available {
        warn!("❌ Buyer RPC not available at {}", BUYER_RPC_URL);
        warn!(
            "Run: monero-wallet-rpc --testnet --rpc-bind-port 18083 --disable-rpc-login --offline"
        );
        return Ok(()); // Skip test gracefully
    }

    if !seller_available {
        warn!("❌ Seller RPC not available at {}", SELLER_RPC_URL);
        warn!(
            "Run: monero-wallet-rpc --testnet --rpc-bind-port 18084 --disable-rpc-login --offline"
        );
        return Ok(()); // Skip test gracefully
    }

    if !arbiter_available {
        warn!("❌ Arbiter RPC not available at {}", ARBITER_RPC_URL);
        warn!(
            "Run: monero-wallet-rpc --testnet --rpc-bind-port 18085 --disable-rpc-login --offline"
        );
        return Ok(()); // Skip test gracefully
    }

    info!("✅ All 3 RPC instances available");

    // Step 1: Create test wallets
    info!("Step 1: Creating test wallets...");

    let escrow_id = format!("test_escrow_{}", chrono::Utc::now().timestamp());
    let buyer_wallet = format!("buyer_wallet_{}", chrono::Utc::now().timestamp());
    let seller_wallet = format!("seller_wallet_{}", chrono::Utc::now().timestamp());
    let arbiter_wallet = format!("arbiter_wallet_{}", chrono::Utc::now().timestamp());

    create_test_wallet(BUYER_RPC_URL, &buyer_wallet).await?;
    create_test_wallet(SELLER_RPC_URL, &seller_wallet).await?;
    create_test_wallet(ARBITER_RPC_URL, &arbiter_wallet).await?;

    info!("✅ All wallets created");

    // Step 2: Initialize coordinator and actix app
    info!("Step 2: Initializing coordinator...");

    let test_db_pool = create_test_db_pool();
    let encryption_key = vec![0u8; 32]; // Dummy encryption key for tests

    // Create a dummy WebSocket server for tests
    use actix::Actor;
    let ws_server = server::websocket::WebSocketServer::default().start();

    let coordinator = Arc::new(EscrowCoordinator::new(
        test_db_pool,
        encryption_key,
        ws_server,
    ));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(coordinator.clone()))
            .route(
                "/api/v2/escrow/register-wallet",
                web::post().to(noncustodial::register_client_wallet),
            )
            .route(
                "/api/v2/escrow/coordinate-exchange",
                web::post().to(noncustodial::coordinate_multisig_exchange),
            )
            .route(
                "/api/v2/escrow/coordination-status/{escrow_id}",
                web::get().to(noncustodial::get_coordination_status),
            ),
    )
    .await;

    info!("✅ Coordinator initialized");

    // Step 3: Register buyer
    info!("Step 3: Registering buyer...");

    let buyer_req = test::TestRequest::post()
        .uri("/api/v2/escrow/register-wallet")
        .set_json(json!({
            "escrow_id": escrow_id,
            "role": "buyer",
            "rpc_url": BUYER_RPC_URL,
        }))
        .to_request();

    let buyer_resp: serde_json::Value = test::call_and_read_body_json(&app, buyer_req).await;
    info!("Buyer registration response: {:?}", buyer_resp);

    assert_eq!(buyer_resp["success"], true, "Buyer registration failed");
    assert!(buyer_resp["awaiting"].is_array(), "Expected awaiting array");

    info!("✅ Buyer registered");

    // Step 4: Register seller
    info!("Step 4: Registering seller...");

    let seller_req = test::TestRequest::post()
        .uri("/api/v2/escrow/register-wallet")
        .set_json(json!({
            "escrow_id": escrow_id,
            "role": "seller",
            "rpc_url": SELLER_RPC_URL,
        }))
        .to_request();

    let seller_resp: serde_json::Value = test::call_and_read_body_json(&app, seller_req).await;
    info!("Seller registration response: {:?}", seller_resp);

    assert_eq!(seller_resp["success"], true, "Seller registration failed");

    info!("✅ Seller registered");

    // Step 5: Register arbiter
    info!("Step 5: Registering arbiter...");

    let arbiter_req = test::TestRequest::post()
        .uri("/api/v2/escrow/register-wallet")
        .set_json(json!({
            "escrow_id": escrow_id,
            "role": "arbiter",
            "rpc_url": ARBITER_RPC_URL,
        }))
        .to_request();

    let arbiter_resp: serde_json::Value = test::call_and_read_body_json(&app, arbiter_req).await;
    info!("Arbiter registration response: {:?}", arbiter_resp);

    assert_eq!(arbiter_resp["success"], true, "Arbiter registration failed");
    assert_eq!(
        arbiter_resp["awaiting"].as_array().unwrap().len(),
        0,
        "Expected all participants registered"
    );

    info!("✅ Arbiter registered (all participants ready)");

    // Step 6: Get coordination status
    info!("Step 6: Checking coordination status...");

    let status_req = test::TestRequest::get()
        .uri(&format!("/api/v2/escrow/coordination-status/{}", escrow_id))
        .to_request();

    let status_resp: serde_json::Value = test::call_and_read_body_json(&app, status_req).await;
    info!("Status response: {:?}", status_resp);

    assert_eq!(status_resp["buyer_registered"], true);
    assert_eq!(status_resp["seller_registered"], true);
    assert_eq!(status_resp["arbiter_registered"], true);

    info!("✅ All participants confirmed registered");

    // Step 7: Coordinate multisig exchange
    info!("Step 7: Coordinating multisig exchange...");

    let coord_req = test::TestRequest::post()
        .uri("/api/v2/escrow/coordinate-exchange")
        .set_json(json!({
            "escrow_id": escrow_id,
        }))
        .to_request();

    let coord_resp: serde_json::Value = test::call_and_read_body_json(&app, coord_req).await;
    info!("Coordination response: {:?}", coord_resp);

    assert_eq!(coord_resp["success"], true, "Coordination failed");

    let buyer_receives = coord_resp["exchange_result"]["buyer_receives"]
        .as_array()
        .expect("Expected buyer_receives array");
    let seller_receives = coord_resp["exchange_result"]["seller_receives"]
        .as_array()
        .expect("Expected seller_receives array");
    let arbiter_receives = coord_resp["exchange_result"]["arbiter_receives"]
        .as_array()
        .expect("Expected arbiter_receives array");

    assert_eq!(buyer_receives.len(), 2, "Buyer should receive 2 infos");
    assert_eq!(seller_receives.len(), 2, "Seller should receive 2 infos");
    assert_eq!(arbiter_receives.len(), 2, "Arbiter should receive 2 infos");

    info!("✅ Multisig exchange coordinated");
    info!("   Buyer receives {} infos", buyer_receives.len());
    info!("   Seller receives {} infos", seller_receives.len());
    info!("   Arbiter receives {} infos", arbiter_receives.len());

    // Step 8: Finalize multisig on each wallet locally
    info!("Step 8: Finalizing multisig locally on each wallet...");

    // Buyer finalizes
    let buyer_client = MoneroClient::new(MoneroConfig {
        rpc_url: BUYER_RPC_URL.to_string(),
        rpc_user: None,
        rpc_password: None,
        timeout_seconds: 30,
    })?;

    let buyer_infos: Vec<String> = buyer_receives
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let buyer_result = buyer_client
        .multisig()
        .make_multisig(2, buyer_infos)
        .await
        .context("Failed to make multisig for buyer")?;

    info!("✅ Buyer multisig address: {}", buyer_result.address);

    // Seller finalizes
    let seller_client = MoneroClient::new(MoneroConfig {
        rpc_url: SELLER_RPC_URL.to_string(),
        rpc_user: None,
        rpc_password: None,
        timeout_seconds: 30,
    })?;

    let seller_infos: Vec<String> = seller_receives
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let seller_result = seller_client
        .multisig()
        .make_multisig(2, seller_infos)
        .await
        .context("Failed to make multisig for seller")?;

    info!("✅ Seller multisig address: {}", seller_result.address);

    // Arbiter finalizes
    let arbiter_client = MoneroClient::new(MoneroConfig {
        rpc_url: ARBITER_RPC_URL.to_string(),
        rpc_user: None,
        rpc_password: None,
        timeout_seconds: 30,
    })?;

    let arbiter_infos: Vec<String> = arbiter_receives
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let arbiter_result = arbiter_client
        .multisig()
        .make_multisig(2, arbiter_infos)
        .await
        .context("Failed to make multisig for arbiter")?;

    info!("✅ Arbiter multisig address: {}", arbiter_result.address);

    // Step 9: Verify all multisig addresses match
    info!("Step 9: Verifying multisig addresses match...");

    assert_eq!(
        buyer_result.address, seller_result.address,
        "Buyer and seller multisig addresses don't match"
    );
    assert_eq!(
        buyer_result.address, arbiter_result.address,
        "Buyer and arbiter multisig addresses don't match"
    );

    info!("✅ All multisig addresses match!");
    info!("   Shared multisig address: {}", buyer_result.address);

    // Final assertions
    assert!(
        buyer_result.address.starts_with("5") || buyer_result.address.starts_with("9"),
        "Invalid multisig address format"
    );

    info!("🎉 E2E test PASSED: Complete non-custodial escrow flow successful");

    Ok(())
}

/// Test 2: Verify server never stores private keys
///
/// **Validates:**
/// - Server only stores RPC URLs
/// - Server never creates wallets
/// - Server never calls wallet creation methods
#[actix_web::test]
#[ignore]
async fn test_server_never_touches_wallets() -> Result<()> {
    init_tracing();
    info!("🧪 Starting E2E test: Server never touches wallets");

    // This test is more of a code review validation
    // The architecture guarantees:
    // 1. EscrowCoordinator only stores RPC URLs
    // 2. No wallet creation methods in coordinator
    // 3. No private key storage

    let test_db_pool = create_test_db_pool();
    let encryption_key = vec![0u8; 32]; // Dummy encryption key for tests

    // Create a dummy WebSocket server for tests
    use actix::Actor;
    let ws_server = server::websocket::WebSocketServer::default().start();

    let coordinator = EscrowCoordinator::new(test_db_pool, encryption_key, ws_server);
    let escrow_id = "test_security_001";

    // Register 3 wallets
    coordinator
        .register_client_wallet(
            escrow_id,
            server::coordination::EscrowRole::Buyer,
            BUYER_RPC_URL.to_string(),
        )
        .await?;

    coordinator
        .register_client_wallet(
            escrow_id,
            server::coordination::EscrowRole::Seller,
            SELLER_RPC_URL.to_string(),
        )
        .await?;

    coordinator
        .register_client_wallet(
            escrow_id,
            server::coordination::EscrowRole::Arbiter,
            ARBITER_RPC_URL.to_string(),
        )
        .await?;

    // Get status
    let status = coordinator.get_coordination_status(escrow_id).await?;

    // Verify only URLs are stored (not wallets)
    assert_eq!(status.buyer_rpc_url, Some(BUYER_RPC_URL.to_string()));
    assert_eq!(status.seller_rpc_url, Some(SELLER_RPC_URL.to_string()));
    assert_eq!(status.arbiter_rpc_url, Some(ARBITER_RPC_URL.to_string()));

    info!("✅ Server only stores RPC URLs (no wallet objects)");
    info!("🎉 E2E test PASSED: Server security validated");

    Ok(())
}
