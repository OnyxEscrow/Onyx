//! Integration tests for escrow operations

use actix_web::{test, web, App};
use diesel::r2d2::{self, ConnectionManager};
use diesel::SqliteConnection;
use server::db::create_pool;
use server::handlers::escrow;
use server::services::escrow::EscrowOrchestrator;
use server::wallet_manager::WalletManager;
use server::websocket::WebSocketServer;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

/// Helper to create test database pool
fn create_test_pool() -> DbPool {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "test_marketplace.db".to_string());
    let encryption_key = std::env::var("DB_ENCRYPTION_KEY")
        .unwrap_or_else(|_| "test_encryption_key_32_bytes!!!!!!!".to_string());
    create_pool(&database_url, &encryption_key).expect("Failed to create test pool")
}

/// Test getting escrow details (requires authentication)
#[actix_web::test]
async fn test_get_escrow_unauthenticated() -> Result<(), Box<dyn std::error::Error>> {
    let pool = create_test_pool();
    let escrow_id = Uuid::new_v4();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/api/escrow/{id}", web::get().to(escrow::get_escrow)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri(&format!("/api/escrow/{}", escrow_id))
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Should return 401 Unauthorized when not authenticated
    assert_eq!(resp.status(), 401);

    Ok(())
}

/// Test prepare multisig validation
#[actix_web::test]
async fn test_prepare_multisig_validation() -> Result<(), Box<dyn std::error::Error>> {
    let pool = create_test_pool();
    let escrow_id = Uuid::new_v4();

    // Create mock orchestrator components
    let monero_config = monero_marketplace_common::types::MoneroConfig::default();
    let wallet_manager = Arc::new(Mutex::new(
        WalletManager::new(vec![monero_config]).expect("Failed to create WalletManager"),
    ));

    let websocket_server = actix::Actor::start(WebSocketServer::default());
    let encryption_key = vec![0u8; 32]; // Test key

    let escrow_orchestrator = EscrowOrchestrator::new(
        wallet_manager,
        pool.clone(),
        websocket_server,
        encryption_key,
    );

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(escrow_orchestrator))
            .route(
                "/api/escrow/{id}/prepare",
                web::post().to(escrow::prepare_multisig),
            ),
    )
    .await;

    // Test with multisig_info that's too short (< 100 chars)
    let short_payload = serde_json::json!({
        "multisig_info": "too_short"
    });

    let req = test::TestRequest::post()
        .uri(&format!("/api/escrow/{}/prepare", escrow_id))
        .set_json(&short_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Should return 400 Bad Request for validation failure
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let error_msg = body["error"]
        .as_str()
        .expect("Response should contain 'error' field with string value");
    assert!(
        error_msg.contains("Validation failed"),
        "Expected validation error, got: {}",
        error_msg
    );

    Ok(())
}

/// Test release funds validation
#[actix_web::test]
async fn test_release_funds_validation() -> Result<(), Box<dyn std::error::Error>> {
    let pool = create_test_pool();
    let escrow_id = Uuid::new_v4();

    let monero_config = monero_marketplace_common::types::MoneroConfig::default();
    let wallet_manager = Arc::new(Mutex::new(
        WalletManager::new(vec![monero_config]).expect("Failed to create WalletManager"),
    ));

    let websocket_server = actix::Actor::start(WebSocketServer::default());
    let encryption_key = vec![0u8; 32];

    let escrow_orchestrator = EscrowOrchestrator::new(
        wallet_manager,
        pool.clone(),
        websocket_server,
        encryption_key,
    );

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(escrow_orchestrator))
            .route(
                "/api/escrow/{id}/release",
                web::post().to(escrow::release_funds),
            ),
    )
    .await;

    // Test with invalid Monero address (not 95 characters)
    let invalid_payload = serde_json::json!({
        "vendor_address": "invalid_address"
    });

    let req = test::TestRequest::post()
        .uri(&format!("/api/escrow/{}/release", escrow_id))
        .set_json(&invalid_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Should return 400 Bad Request for validation failure
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let error_msg = body["error"]
        .as_str()
        .expect("Response should contain 'error' field with string value");
    assert!(
        error_msg.contains("Validation failed"),
        "Expected validation error, got: {}",
        error_msg
    );

    Ok(())
}

/// Test dispute initiation validation
#[actix_web::test]
async fn test_initiate_dispute_validation() -> Result<(), Box<dyn std::error::Error>> {
    let pool = create_test_pool();
    let escrow_id = Uuid::new_v4();

    let monero_config = monero_marketplace_common::types::MoneroConfig::default();
    let wallet_manager = Arc::new(Mutex::new(
        WalletManager::new(vec![monero_config]).expect("Failed to create WalletManager"),
    ));

    let websocket_server = actix::Actor::start(WebSocketServer::default());
    let encryption_key = vec![0u8; 32];

    let escrow_orchestrator = EscrowOrchestrator::new(
        wallet_manager,
        pool.clone(),
        websocket_server,
        encryption_key,
    );

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(escrow_orchestrator))
            .route(
                "/api/escrow/{id}/dispute",
                web::post().to(escrow::initiate_dispute),
            ),
    )
    .await;

    // Test with reason that's too short (< 10 chars)
    let short_reason = serde_json::json!({
        "reason": "short"
    });

    let req = test::TestRequest::post()
        .uri(&format!("/api/escrow/{}/dispute", escrow_id))
        .set_json(&short_reason)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Should return 400 Bad Request for validation failure
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let error_msg = body["error"]
        .as_str()
        .expect("Response should contain 'error' field with string value");
    assert!(
        error_msg.contains("Validation failed"),
        "Expected validation error, got: {}",
        error_msg
    );

    Ok(())
}

/// Test dispute resolution validation
#[actix_web::test]
async fn test_resolve_dispute_validation() -> Result<(), Box<dyn std::error::Error>> {
    let pool = create_test_pool();
    let escrow_id = Uuid::new_v4();

    let monero_config = monero_marketplace_common::types::MoneroConfig::default();
    let wallet_manager = Arc::new(Mutex::new(
        WalletManager::new(vec![monero_config]).expect("Failed to create WalletManager"),
    ));

    let websocket_server = actix::Actor::start(WebSocketServer::default());
    let encryption_key = vec![0u8; 32];

    let escrow_orchestrator = EscrowOrchestrator::new(
        wallet_manager,
        pool.clone(),
        websocket_server,
        encryption_key,
    );

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(escrow_orchestrator))
            .route(
                "/api/escrow/{id}/resolve",
                web::post().to(escrow::resolve_dispute),
            ),
    )
    .await;

    // Test with invalid resolution (not 'buyer' or 'vendor')
    let invalid_resolution = serde_json::json!({
        "resolution": "invalid_party"
    });

    let req = test::TestRequest::post()
        .uri(&format!("/api/escrow/{}/resolve", escrow_id))
        .set_json(&invalid_resolution)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Should return 400 Bad Request for validation failure
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let error_msg = body["error"]
        .as_str()
        .expect("Response should contain 'error' field with string value");
    assert!(
        error_msg.contains("Validation failed"),
        "Expected validation error, got: {}",
        error_msg
    );

    Ok(())
}
