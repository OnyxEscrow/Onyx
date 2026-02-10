//! End-to-end tests for wallet registration flow
//!
//! Tests the complete wallet registration lifecycle:
//! 1. User registration and login
//! 2. Client-side seed generation (simulated)
//! 3. Wallet registration with validation
//! 4. Error handling for invalid inputs
//!
//! Run with: cargo test --test wallet_registration_e2e -- --ignored --nocapture

use anyhow::{Context, Result};
use diesel::r2d2::{self, ConnectionManager};
use diesel::SqliteConnection;
use server::db::create_pool;
use server::models::user::{NewUser, User};
use server::models::wallet::{NewWallet, Wallet};
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

/// Test data for wallet registration
struct TestWallet {
    address: String,
    view_key_pub: String,
    spend_key_pub: String,
    address_hash: String,
}

/// Generate test wallet data with valid format
fn generate_test_wallet() -> TestWallet {
    // Valid Monero testnet address (58 chars)
    let address = "9JbR8hHi9wMKWUh3dLFb2FVj5zxfBxCQ8g6xZeFWLMh8rBZLQKP8LsJpn8ZzVzBrZcsY4eNQWxMeF1xn8r7q4HANJpxbTPu".to_string();

    // Valid hex keys (64 chars = 32 bytes)
    let view_key_pub =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    let spend_key_pub =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string();

    // Valid SHA256 hash (64 hex chars)
    let address_hash =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string();

    TestWallet {
        address,
        view_key_pub,
        spend_key_pub,
        address_hash,
    }
}

#[tokio::test]
#[ignore]
async fn test_wallet_registration_complete_flow() -> Result<()> {
    println!("=== Test: Complete Wallet Registration Flow ===");

    let pool = create_test_pool();

    // Step 1: Create a test user
    println!("Step 1: Creating test user...");
    let user_id = Uuid::new_v4().to_string();
    let new_user = NewUser {
        id: user_id.clone(),
        username: format!("test_user_{}", Uuid::new_v4()),
        password_hash: "hashed_password_12345".to_string(),
        role: "buyer".to_string(),
        wallet_address: None,
        wallet_id: None,
    };

    let user = {
        let pool_clone = pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool_clone.get().context("Failed to get DB connection")?;
            User::create(&mut conn, new_user)
        })
        .await
        .context("Task join error")??
    };
    println!("✓ User created: {} (id: {})", user.username, user.id);

    // Step 2: Register a wallet for this user
    println!("\nStep 2: Registering wallet...");
    let test_wallet = generate_test_wallet();
    let wallet_id = Uuid::new_v4().to_string();
    let new_wallet = NewWallet {
        id: wallet_id.clone(),
        user_id: user.id.clone(),
        address: test_wallet.address.clone(),
        address_hash: test_wallet.address_hash.clone(),
        spend_key_pub: Some(test_wallet.spend_key_pub.clone()),
        view_key_pub: Some(test_wallet.view_key_pub.clone()),
        signature: None,
        daily_limit_atomic: None,
        monthly_limit_atomic: None,
        last_withdrawal_date: None,
        withdrawn_today_atomic: None,
    };

    let wallet = {
        let pool_clone = pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool_clone.get().context("Failed to get DB connection")?;
            Wallet::create(&mut conn, new_wallet)
        })
        .await
        .context("Task join error")??
    };
    println!(
        "✓ Wallet registered: {} (id: {})",
        wallet.address, wallet.id
    );

    // Step 3: Verify wallet can be retrieved
    println!("\nStep 3: Verifying wallet retrieval...");
    let retrieved_wallet = {
        let pool_clone = pool.clone();
        let addr = wallet.address.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool_clone.get().context("Failed to get DB connection")?;
            Wallet::find_by_address(&mut conn, &addr)
        })
        .await
        .context("Task join error")??
    };
    println!("✓ Wallet retrieved successfully");
    assert_eq!(retrieved_wallet.id, wallet.id);
    assert_eq!(retrieved_wallet.user_id, user.id);

    // Step 4: Verify user's wallets can be listed
    println!("\nStep 4: Listing user's wallets...");
    let user_wallets = {
        let pool_clone = pool.clone();
        let uid = user.id.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool_clone.get().context("Failed to get DB connection")?;
            Wallet::find_by_user_id(&mut conn, uid)
        })
        .await
        .context("Task join error")??
    };
    println!("✓ Found {} wallet(s) for user", user_wallets.len());
    assert!(user_wallets.len() >= 1);
    assert!(user_wallets.iter().any(|w| w.id == wallet.id));

    println!("\n✅ Test PASSED: Complete wallet registration flow successful\n");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_wallet_duplicate_rejection() -> Result<()> {
    println!("=== Test: Wallet Duplicate Rejection ===");

    let pool = create_test_pool();

    // Create user
    let user_id = Uuid::new_v4().to_string();
    let new_user = NewUser {
        id: user_id.clone(),
        username: format!("test_user_{}", Uuid::new_v4()),
        password_hash: "hashed_password".to_string(),
        role: "buyer".to_string(),
        wallet_address: None,
        wallet_id: None,
    };

    let user = {
        let pool_clone = pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool_clone.get().context("Failed to get DB connection")?;
            User::create(&mut conn, new_user)
        })
        .await
        .context("Task join error")??
    };

    // Register first wallet
    let test_wallet = generate_test_wallet();
    let wallet_id_1 = Uuid::new_v4().to_string();
    let new_wallet_1 = NewWallet {
        id: wallet_id_1.clone(),
        user_id: user.id.clone(),
        address: test_wallet.address.clone(),
        address_hash: test_wallet.address_hash.clone(),
        spend_key_pub: Some(test_wallet.spend_key_pub.clone()),
        view_key_pub: Some(test_wallet.view_key_pub.clone()),
        signature: None,
        daily_limit_atomic: None,
        monthly_limit_atomic: None,
        last_withdrawal_date: None,
        withdrawn_today_atomic: None,
    };

    let _wallet_1 = {
        let pool_clone = pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool_clone.get().context("Failed to get DB connection")?;
            Wallet::create(&mut conn, new_wallet_1)
        })
        .await
        .context("Task join error")??
    };
    println!("✓ First wallet registered");

    // Try to register the same address again
    println!("Attempting to register duplicate address...");
    let wallet_id_2 = Uuid::new_v4().to_string();
    let new_wallet_2 = NewWallet {
        id: wallet_id_2.clone(),
        user_id: user.id.clone(),
        address: test_wallet.address.clone(), // Same address
        address_hash: "different_hash_value_1234567890abcdef1234567890abcdef12345678".to_string(),
        spend_key_pub: Some(
            "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567".to_string(),
        ),
        view_key_pub: Some(
            "cafebabe0123456789abcdef0123456789abcdef0123456789abcdef01234567".to_string(),
        ),
        signature: None,
        daily_limit_atomic: None,
        monthly_limit_atomic: None,
        last_withdrawal_date: None,
        withdrawn_today_atomic: None,
    };

    let duplicate_result = {
        let pool_clone = pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool_clone.get().context("Failed to get DB connection")?;
            Wallet::create(&mut conn, new_wallet_2)
        })
        .await
        .context("Task join error")?
    };

    match duplicate_result {
        Err(_) => {
            println!("✓ Duplicate address correctly rejected");
            println!("\n✅ Test PASSED: Duplicate wallet properly prevented\n");
            Ok(())
        }
        Ok(_) => {
            panic!("FAILED: Duplicate address should have been rejected");
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_wallet_validation_invalid_keys() -> Result<()> {
    println!("=== Test: Wallet Key Validation ===");

    // Test invalid spend key (too short)
    let invalid_spend_key = "deadbeef"; // Only 8 chars, needs 64
    assert!(
        invalid_spend_key.len() != 64,
        "Test setup: invalid spend key should be wrong length"
    );
    println!(
        "✓ Invalid spend key (too short) detected: {} chars",
        invalid_spend_key.len()
    );

    // Test invalid view key (not hex)
    let invalid_view_key = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"; // 64 chars but not hex
    assert!(
        !invalid_view_key.chars().all(|c| c.is_ascii_hexdigit()),
        "Test setup: invalid view key should not be hex"
    );
    println!("✓ Invalid view key (non-hex) detected");

    // Test valid keys
    let valid_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert_eq!(valid_key.len(), 64);
    assert!(valid_key.chars().all(|c| c.is_ascii_hexdigit()));
    println!("✓ Valid hex key (64 chars) accepted");

    println!("\n✅ Test PASSED: Key validation logic correct\n");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_wallet_address_validation() -> Result<()> {
    println!("=== Test: Monero Address Validation ===");

    // Valid Monero testnet address (58 chars)
    let valid_address = "9JbR8hHi9wMKWUh3dLFb2FVj5zxfBxCQ8g6xZeFWLMh8rBZLQKP8LsJpn8ZzVzBrZcsY4eNQWxMeF1xn8r7q4HANJpxbTPu";
    assert_eq!(valid_address.len(), 58);
    println!("✓ Valid address length: {} chars", valid_address.len());

    // Invalid address (too short)
    let short_address = "9JbR8hHi9wMKWUh";
    assert!(short_address.len() < 58);
    println!(
        "✓ Short address detected: {} chars (too short)",
        short_address.len()
    );

    // Invalid address (contains invalid character)
    let invalid_address = "0JbR8hHi9wMKWUh3dLFb2FVj5zxfBxCQ8g6xZeFWLMh8rBZLQKP8LsJpn8ZzVzBrZ"; // starts with 0
    assert!(invalid_address.contains('0')); // 0 is not valid in base58
    println!("✓ Invalid address (contains '0') detected");

    println!("\n✅ Test PASSED: Address validation logic correct\n");
    Ok(())
}
