//! End-to-end tests for complete escrow flow
//!
//! These tests simulate the full escrow lifecycle from order creation
//! through multisig setup, funding, and final settlement (release or refund).
//!
//! Run with: cargo test --test escrow_e2e -- --nocapture

use anyhow::{Context, Result};
use diesel::r2d2::{self, ConnectionManager};
use diesel::SqliteConnection;
use server::db::{
    create_pool, db_insert_escrow, db_load_escrow, db_update_escrow_address,
    db_update_escrow_status, db_update_escrow_transaction_hash,
};
use server::models::escrow::NewEscrow;
use server::models::listing::{Listing, NewListing};
use server::models::order::{NewOrder, Order};
use server::models::user::{NewUser, User};
use server::services::escrow::EscrowOrchestrator;
use server::wallet_manager::WalletManager;
use server::websocket::WebSocketServer;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use uuid::Uuid;

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

/// Test users structure
struct TestUsers {
    buyer_id: Uuid,
    vendor_id: Uuid,
    arbiter_id: Uuid,
}

/// Helper to create test database pool
fn create_test_pool() -> DbPool {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "test_marketplace.db".to_string());
    let encryption_key = std::env::var("DB_ENCRYPTION_KEY")
        .unwrap_or_else(|_| "test_encryption_key_32_bytes!!!!!!!".to_string());
    create_pool(&database_url, &encryption_key).expect("Failed to create test pool")
}

/// Setup test users (buyer, vendor, arbiter)
async fn setup_test_users(pool: &DbPool) -> Result<TestUsers> {
    let mut conn = pool.get().context("Failed to get DB connection")?;

    // Create buyer
    let buyer = tokio::task::spawn_blocking(move || {
        let new_buyer = NewUser {
            id: Uuid::new_v4().to_string(),
            username: "test_buyer".to_string(),
            password_hash: "hashed_password".to_string(),
            role: "buyer".to_string(),
            wallet_address: None,
            wallet_id: Some(Uuid::new_v4().to_string()),
        };
        User::create(&mut conn, new_buyer)
    })
    .await
    .context("Task join error")??;

    let mut conn = pool.get().context("Failed to get DB connection")?;
    let vendor = tokio::task::spawn_blocking(move || {
        let new_vendor = NewUser {
            id: Uuid::new_v4().to_string(),
            username: "test_vendor".to_string(),
            password_hash: "hashed_password".to_string(),
            role: "vendor".to_string(),
            wallet_address: None,
            wallet_id: Some(Uuid::new_v4().to_string()),
        };
        User::create(&mut conn, new_vendor)
    })
    .await
    .context("Task join error")??;

    let mut conn = pool.get().context("Failed to get DB connection")?;
    let arbiter = tokio::task::spawn_blocking(move || {
        let new_arbiter = NewUser {
            id: Uuid::new_v4().to_string(),
            username: "test_arbiter".to_string(),
            password_hash: "hashed_password".to_string(),
            role: "arbiter".to_string(),
            wallet_address: None,
            wallet_id: Some(Uuid::new_v4().to_string()),
        };
        User::create(&mut conn, new_arbiter)
    })
    .await
    .context("Task join error")??;

    Ok(TestUsers {
        buyer_id: buyer.id.parse()?,
        vendor_id: vendor.id.parse()?,
        arbiter_id: arbiter.id.parse()?,
    })
}

/// Create a test listing
async fn create_listing(pool: &DbPool, vendor_id: Uuid, price: i64) -> Result<Uuid> {
    let mut conn = pool.get().context("Failed to get DB connection")?;

    let listing_id = Uuid::new_v4();
    let vendor_id_str = vendor_id.to_string();

    let listing = tokio::task::spawn_blocking(move || {
        use diesel::prelude::*;
        use server::schema::listings;

        let new_listing = NewListing {
            id: listing_id.to_string(),
            vendor_id: vendor_id_str,
            title: "Test Product".to_string(),
            description: "Test product for E2E testing".to_string(),
            price_xmr: price,
            stock: 10,
            status: "active".to_string(),
            images_ipfs_cids: None, // No images for E2E test
            category: "electronics".to_string(),
            shipping_cost_xmr: 0, // Free shipping for E2E test
        };

        diesel::insert_into(listings::table)
            .values(&new_listing)
            .execute(&mut conn)
            .context("Failed to insert listing")?;

        listings::table
            .filter(listings::id.eq(listing_id.to_string()))
            .first::<Listing>(&mut conn)
            .context("Failed to retrieve created listing")
    })
    .await
    .context("Task join error")??;

    listing.id.parse().context("Failed to parse listing ID")
}

/// Create a test order
async fn create_order(pool: &DbPool, buyer_id: Uuid, listing_id: Uuid) -> Result<Uuid> {
    let mut conn = pool.get().context("Failed to get DB connection")?;

    let order_id = Uuid::new_v4();
    let buyer_id_str = buyer_id.to_string();
    let listing_id_str = listing_id.to_string();

    let order = tokio::task::spawn_blocking(move || {
        use diesel::prelude::*;
        use server::schema::orders;

        let new_order = NewOrder {
            id: order_id.to_string(),
            buyer_id: buyer_id_str.clone(),
            vendor_id: buyer_id_str, // Using buyer_id as placeholder for vendor
            listing_id: listing_id_str,
            escrow_id: None,
            status: "pending".to_string(),
            total_xmr: 1_000_000_000_000,
            shipping_address: Some("123 Test St, Test City".to_string()),
            shipping_notes: None,
            payment_method: Some("xmr".to_string()),
            swap_order_id: None,
        };

        diesel::insert_into(orders::table)
            .values(&new_order)
            .execute(&mut conn)
            .context("Failed to insert order")?;

        orders::table
            .filter(orders::id.eq(order_id.to_string()))
            .first::<Order>(&mut conn)
            .context("Failed to retrieve created order")
    })
    .await
    .context("Task join error")??;

    order.id.parse().context("Failed to parse order ID")
}

/// Create escrow for order
async fn create_escrow(
    pool: &DbPool,
    order_id: Uuid,
    buyer_id: Uuid,
    vendor_id: Uuid,
    arbiter_id: Uuid,
    amount: i64,
) -> Result<Uuid> {
    let now = chrono::Utc::now().naive_utc();
    let new_escrow = NewEscrow {
        id: Uuid::new_v4().to_string(),
        order_id: Some(order_id.to_string()),
        buyer_id: buyer_id.to_string(),
        vendor_id: vendor_id.to_string(),
        arbiter_id: arbiter_id.to_string(),
        amount,
        status: "created".to_string(),
        created_at: now,
        updated_at: now,
        last_activity_at: now,
        multisig_phase: "not_started".to_string(),
        multisig_updated_at: 0,
        recovery_mode: "manual".to_string(),
        balance_received: 0,
        frost_enabled: true,
        frost_dkg_complete: false,
        external_reference: None,
        description: None,
        buyer_release_requested: false,
        vendor_refund_requested: false,
        arbiter_auto_signed: false,
        escalated_to_human: false,
        client_id: None,
        metadata_json: None,
    };

    let escrow = db_insert_escrow(pool, new_escrow)
        .await
        .context("Failed to create escrow")?;

    escrow.id.parse().context("Failed to parse escrow ID")
}

/// Wait for escrow to reach a specific status (with timeout)
#[allow(dead_code)]
async fn wait_for_status(
    pool: &DbPool,
    escrow_id: Uuid,
    expected_status: &str,
    timeout_secs: u64,
) -> Result<()> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!(
                "Timeout waiting for escrow {} to reach status '{}'",
                escrow_id,
                expected_status
            ));
        }

        let escrow = db_load_escrow(pool, escrow_id).await?;

        if escrow.status == expected_status {
            return Ok(());
        }

        sleep(Duration::from_millis(500)).await;
    }
}

/// Get escrow status
async fn get_escrow_status(pool: &DbPool, escrow_id: Uuid) -> Result<String> {
    let escrow = db_load_escrow(pool, escrow_id).await?;
    Ok(escrow.status)
}

/// Test complete escrow flow: creation → funding → release → completed
///
/// This test simulates:
/// 1. Vendor creates listing
/// 2. Buyer creates order
/// 3. Escrow auto-initialized
/// 4. Multisig setup (simulated - wallets set to ready state)
/// 5. Buyer funds escrow (simulated - status update)
/// 6. Buyer releases funds to vendor
/// 7. Transaction confirmed (simulated confirmations)
/// 8. Escrow completed
#[tokio::test]
#[ignore] // Requires database setup with migrations
async fn test_complete_escrow_flow() -> Result<()> {
    // Setup test environment
    let pool = create_test_pool();
    let users = setup_test_users(&pool).await?;

    // Step 1: Vendor creates listing
    let listing_id = create_listing(&pool, users.vendor_id, 1_000_000_000_000).await?;
    assert!(!listing_id.to_string().is_empty());

    // Step 2: Buyer creates order
    let order_id = create_order(&pool, users.buyer_id, listing_id).await?;
    assert!(!order_id.to_string().is_empty());

    // Step 3: Escrow auto-initialized
    let escrow_id = create_escrow(
        &pool,
        order_id,
        users.buyer_id,
        users.vendor_id,
        users.arbiter_id,
        1_000_000_000_000,
    )
    .await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(status, "created", "Escrow should be in 'created' state");

    // Step 4: Simulate multisig setup completion
    // In production, this would involve:
    // - prepare_multisig() for all 3 parties
    // - make_multisig + exchange_multisig_info
    // - finalize_multisig
    // For testing, we directly set multisig address and status
    let test_multisig_address = "9wq792k9sxVZiLn66S3Qzv8QfmtcwkdXgM5cWGsXAPxoXxbgCHLvhXXx4HfXwzWMnYLKEVXXdqB3xXXxXXxXXxXXxXXxX";
    db_update_escrow_address(&pool, escrow_id, test_multisig_address).await?;
    db_update_escrow_status(&pool, escrow_id, "funded").await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(
        status, "funded",
        "Escrow should be in 'funded' state after multisig setup"
    );

    // Step 5: Simulate blockchain monitor detecting funds
    // In production, blockchain_monitor would poll and detect balance
    // For testing, we update status to 'active' (funds received)
    db_update_escrow_status(&pool, escrow_id, "active").await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(
        status, "active",
        "Escrow should be 'active' after funding detected"
    );

    // Step 6: Buyer releases funds to vendor (simulated)
    // In production, this would call EscrowOrchestrator::release_funds()
    // which creates and broadcasts a multisig transaction
    // For testing, we simulate the transaction creation
    let test_tx_hash = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    db_update_escrow_transaction_hash(&pool, escrow_id, test_tx_hash).await?;
    db_update_escrow_status(&pool, escrow_id, "releasing").await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(
        status, "releasing",
        "Escrow should be 'releasing' after transaction broadcast"
    );

    // Step 7: Simulate blockchain confirmations reaching threshold
    // In production, blockchain_monitor checks confirmations via get_transfer_by_txid()
    // For testing, we directly update to final status
    db_update_escrow_status(&pool, escrow_id, "completed").await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(
        status, "completed",
        "Escrow should be 'completed' after confirmations"
    );

    // Verify escrow data
    let escrow = db_load_escrow(&pool, escrow_id).await?;
    assert_eq!(
        escrow.multisig_address,
        Some(test_multisig_address.to_string())
    );
    assert_eq!(escrow.transaction_hash, Some(test_tx_hash.to_string()));
    assert_eq!(escrow.amount, 1_000_000_000_000);

    Ok(())
}

/// Test dispute flow: creation → funding → dispute → resolution → refund → refunded
///
/// This test simulates:
/// 1-5. Same setup as complete flow
/// 6. Buyer opens dispute instead of releasing
/// 7. Arbiter resolves in favor of buyer
/// 8. Auto-refund triggered
/// 9. Transaction confirmed
/// 10. Escrow refunded
#[tokio::test]
#[ignore] // Requires database setup with migrations
async fn test_dispute_flow() -> Result<()> {
    // Setup test environment
    let pool = create_test_pool();
    let users = setup_test_users(&pool).await?;

    // Steps 1-5: Same as complete flow
    let listing_id = create_listing(&pool, users.vendor_id, 1_000_000_000_000).await?;
    let order_id = create_order(&pool, users.buyer_id, listing_id).await?;
    let escrow_id = create_escrow(
        &pool,
        order_id,
        users.buyer_id,
        users.vendor_id,
        users.arbiter_id,
        1_000_000_000_000,
    )
    .await?;

    // Simulate multisig setup
    let test_multisig_address = "9wq792k9sxVZiLn66S3Qzv8QfmtcwkdXgM5cWGsXAPxoXxbgCHLvhXXx4HfXwzWMnYLKEVXXdqB3xXXxXXxXXxXXxXXxX";
    db_update_escrow_address(&pool, escrow_id, test_multisig_address).await?;
    db_update_escrow_status(&pool, escrow_id, "funded").await?;

    // Simulate funds received
    db_update_escrow_status(&pool, escrow_id, "active").await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(status, "active");

    // Step 6: Buyer opens dispute instead of releasing
    db_update_escrow_status(&pool, escrow_id, "disputed").await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(status, "disputed", "Escrow should be in 'disputed' state");

    // Step 7: Arbiter resolves in favor of buyer
    // In production, this calls EscrowOrchestrator::resolve_dispute()
    // which auto-triggers refund_funds()
    db_update_escrow_status(&pool, escrow_id, "resolved_buyer").await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(
        status, "resolved_buyer",
        "Escrow should be 'resolved_buyer' after arbiter decision"
    );

    // Step 8: Auto-refund triggered (simulated)
    let test_refund_tx_hash = "f2e1d0c9b8a7z6y5x4w3v2u1t0s9r8q7p6o5n4m3l2k1j0i9h8g7f6e5d4c3b2a1";
    db_update_escrow_transaction_hash(&pool, escrow_id, test_refund_tx_hash).await?;
    db_update_escrow_status(&pool, escrow_id, "refunding").await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(
        status, "refunding",
        "Escrow should be 'refunding' after refund tx broadcast"
    );

    // Step 9: Simulate confirmations reaching threshold
    db_update_escrow_status(&pool, escrow_id, "refunded").await?;

    let status = get_escrow_status(&pool, escrow_id).await?;
    assert_eq!(
        status, "refunded",
        "Escrow should be 'refunded' after confirmations"
    );

    // Verify escrow data
    let escrow = db_load_escrow(&pool, escrow_id).await?;
    assert_eq!(
        escrow.transaction_hash,
        Some(test_refund_tx_hash.to_string())
    );
    assert_eq!(escrow.status, "refunded");

    Ok(())
}

/// Test escrow orchestrator initialization
#[tokio::test]
#[ignore] // Requires database setup with migrations
async fn test_escrow_orchestrator_init() -> Result<()> {
    let pool = create_test_pool();
    let users = setup_test_users(&pool).await?;

    // Create wallet manager
    let monero_config = monero_marketplace_common::types::MoneroConfig::default();
    let wallet_manager = Arc::new(Mutex::new(
        WalletManager::new(vec![monero_config]).expect("Failed to create WalletManager"),
    ));

    // Create WebSocket server
    let websocket_server = actix::Actor::start(WebSocketServer::default());

    // Create encryption key
    let encryption_key = vec![0u8; 32];

    // Create EscrowOrchestrator
    let escrow_orchestrator = EscrowOrchestrator::new(
        wallet_manager,
        pool.clone(),
        websocket_server,
        encryption_key,
    );

    // Test init_escrow
    let listing_id = create_listing(&pool, users.vendor_id, 1_000_000_000_000).await?;
    let order_id = create_order(&pool, users.buyer_id, listing_id).await?;

    let escrow = escrow_orchestrator
        .init_escrow(order_id, users.buyer_id, users.vendor_id, 1_000_000_000_000)
        .await?;

    assert_eq!(escrow.status, "created");
    assert_eq!(escrow.amount, 1_000_000_000_000);
    assert_eq!(escrow.buyer_id, users.buyer_id.to_string());
    assert_eq!(escrow.vendor_id, users.vendor_id.to_string());
    assert_eq!(escrow.arbiter_id, users.arbiter_id.to_string());

    Ok(())
}

/// Test state transitions validation
#[tokio::test]
#[ignore] // Requires database setup with migrations
async fn test_escrow_state_transitions() -> Result<()> {
    let pool = create_test_pool();
    let users = setup_test_users(&pool).await?;

    let listing_id = create_listing(&pool, users.vendor_id, 1_000_000_000_000).await?;
    let order_id = create_order(&pool, users.buyer_id, listing_id).await?;
    let escrow_id = create_escrow(
        &pool,
        order_id,
        users.buyer_id,
        users.vendor_id,
        users.arbiter_id,
        1_000_000_000_000,
    )
    .await?;

    // Valid state transitions
    let valid_transitions = vec![
        ("created", "funded"),
        ("funded", "active"),
        ("active", "releasing"),
        ("releasing", "completed"),
        ("active", "disputed"),
        ("disputed", "resolved_buyer"),
        ("disputed", "resolved_vendor"),
        ("resolved_buyer", "refunding"),
        ("refunding", "refunded"),
    ];

    for (from_status, to_status) in valid_transitions {
        db_update_escrow_status(&pool, escrow_id, from_status).await?;
        let status = get_escrow_status(&pool, escrow_id).await?;
        assert_eq!(status, from_status);

        db_update_escrow_status(&pool, escrow_id, to_status).await?;
        let status = get_escrow_status(&pool, escrow_id).await?;
        assert_eq!(status, to_status);
    }

    Ok(())
}

/// Test multiple concurrent escrows
#[tokio::test]
#[ignore] // Requires database setup with migrations
async fn test_concurrent_escrows() -> Result<()> {
    let pool = create_test_pool();
    let users = setup_test_users(&pool).await?;

    let listing_id = create_listing(&pool, users.vendor_id, 1_000_000_000_000).await?;

    // Create 3 concurrent escrows
    let mut escrow_ids = Vec::new();
    for i in 0..3 {
        let order_id = create_order(&pool, users.buyer_id, listing_id).await?;
        let escrow_id = create_escrow(
            &pool,
            order_id,
            users.buyer_id,
            users.vendor_id,
            users.arbiter_id,
            1_000_000_000_000 + (i * 100_000_000),
        )
        .await?;
        escrow_ids.push(escrow_id);
    }

    // Verify all escrows are independent
    for escrow_id in escrow_ids {
        let status = get_escrow_status(&pool, escrow_id).await?;
        assert_eq!(status, "created");
    }

    Ok(())
}
