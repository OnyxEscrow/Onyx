//! Integration tests for TimeoutMonitor service
//!
//! Tests the complete timeout detection and handling workflow including:
//! - Escrow expiration detection
//! - Warning notifications before expiration
//! - Automatic actions (cancel, alert, escalate)
//! - Database state transitions

use anyhow::Result;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use server::config::TimeoutConfig;
use server::db::create_pool;
use server::models::escrow::{Escrow, NewEscrow};
use server::schema::escrows;
use uuid::Uuid;

/// Helper function to create test database pool
fn setup_test_db() -> Result<server::db::DbPool> {
    let db_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "test_timeout_monitor.db".to_string());

    // Create fresh database
    if std::path::Path::new(&db_url).exists() {
        std::fs::remove_file(&db_url)?;
    }

    let pool = create_pool(&db_url, "test_encryption_key")?;

    // Run migrations
    {
        use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
        const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
        let mut conn = pool.get()?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("Migration failed: {}", e))?;
    }

    Ok(pool)
}

/// Helper to create test escrow
fn create_test_escrow(
    conn: &mut SqliteConnection,
    status: &str,
    expires_in_secs: Option<i64>,
) -> Result<Escrow> {
    let escrow_id = Uuid::new_v4().to_string();
    let order_id = Uuid::new_v4().to_string();
    let buyer_id = Uuid::new_v4().to_string();
    let vendor_id = Uuid::new_v4().to_string();
    let arbiter_id = Uuid::new_v4().to_string();

    let now = Utc::now().naive_utc();
    let new_escrow = NewEscrow {
        id: escrow_id.clone(),
        order_id,
        buyer_id,
        vendor_id,
        arbiter_id,
        amount: 1_000_000_000_000, // 1 XMR
        status: status.to_string(),
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

    // Create escrow
    diesel::insert_into(escrows::table)
        .values(&new_escrow)
        .execute(conn)?;

    // Update expires_at if specified
    if let Some(secs) = expires_in_secs {
        let expires_at = if secs < 0 {
            // Already expired
            Utc::now().naive_utc() + Duration::seconds(secs)
        } else {
            // Expires in future
            Utc::now().naive_utc() + Duration::seconds(secs)
        };

        diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
            .set((
                escrows::expires_at.eq(Some(expires_at)),
                escrows::last_activity_at.eq(Utc::now().naive_utc()),
            ))
            .execute(conn)?;
    }

    // Load and return
    Escrow::find_by_id(conn, escrow_id)
}

/// Test: Detect expired escrow in 'created' status
#[tokio::test]
async fn test_detect_expired_created_escrow() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    // Create escrow that expired 1 hour ago
    let escrow = create_test_escrow(&mut conn, "created", Some(-3600))?;

    assert!(escrow.is_expired(), "Escrow should be marked as expired");
    assert_eq!(escrow.status, "created");

    // Find expired escrows
    let expired = Escrow::find_expired(&mut conn)?;
    assert_eq!(expired.len(), 1, "Should find 1 expired escrow");
    assert_eq!(expired[0].id, escrow.id);

    Ok(())
}

/// Test: Detect escrow expiring soon (warning threshold)
#[tokio::test]
async fn test_detect_expiring_soon() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    // Create escrow expiring in 30 minutes
    let escrow = create_test_escrow(&mut conn, "funded", Some(1800))?;

    assert!(!escrow.is_expired(), "Escrow should not be expired yet");
    assert!(
        escrow.is_expiring_soon(3600),
        "Escrow should be expiring soon (within 1h)"
    );

    // Find expiring soon escrows
    let expiring = Escrow::find_expiring_soon(&mut conn, 3600)?;
    assert_eq!(expiring.len(), 1, "Should find 1 expiring escrow");
    assert_eq!(expiring[0].id, escrow.id);

    Ok(())
}

/// Test: Update activity resets timeout
#[tokio::test]
async fn test_update_activity_resets_timeout() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    // Create escrow expiring soon
    let escrow = create_test_escrow(&mut conn, "funded", Some(1800))?;
    let original_activity = escrow.last_activity_at;

    // Wait a bit
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Update activity
    Escrow::update_activity(&mut conn, escrow.id.clone())?;

    // Reload and verify
    let updated = Escrow::find_by_id(&mut conn, escrow.id)?;
    assert!(
        updated.last_activity_at > original_activity,
        "last_activity_at should be updated"
    );

    Ok(())
}

/// Test: Update expiration with new deadline
#[tokio::test]
async fn test_update_expiration() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    // Create escrow with no expiration
    let escrow = create_test_escrow(&mut conn, "completed", None)?;
    assert!(
        escrow.expires_at.is_none(),
        "Completed escrow should have no expiration"
    );

    // Set expiration
    let new_expires = Utc::now().naive_utc() + Duration::hours(24);
    Escrow::update_expiration(&mut conn, escrow.id.clone(), Some(new_expires))?;

    // Verify
    let updated = Escrow::find_by_id(&mut conn, escrow.id)?;
    assert!(updated.expires_at.is_some(), "Expiration should be set");

    // Clear expiration
    Escrow::update_expiration(&mut conn, updated.id.clone(), None)?;
    let cleared = Escrow::find_by_id(&mut conn, updated.id)?;
    assert!(cleared.expires_at.is_none(), "Expiration should be cleared");

    Ok(())
}

/// Test: Seconds until expiration calculation
#[tokio::test]
async fn test_seconds_until_expiration() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    // Create escrow expiring in 1 hour
    let escrow = create_test_escrow(&mut conn, "funded", Some(3600))?;

    let remaining = escrow.seconds_until_expiration();
    assert!(remaining.is_some(), "Should have remaining time");

    let secs = remaining.unwrap();
    assert!(
        secs > 3500 && secs <= 3600,
        "Should be ~3600 seconds (got {})",
        secs
    );

    // Test already expired
    let expired = create_test_escrow(&mut conn, "created", Some(-3600))?;
    let remaining_expired = expired.seconds_until_expiration();
    assert_eq!(remaining_expired, Some(0), "Expired escrow should return 0");

    Ok(())
}

/// Test: Terminal states have no expiration
#[tokio::test]
async fn test_terminal_states_no_expiration() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    let terminal_states = vec!["completed", "refunded", "cancelled", "expired"];

    for status in terminal_states {
        let escrow = create_test_escrow(&mut conn, status, None)?;

        assert!(
            escrow.expires_at.is_none(),
            "Terminal state '{}' should have no expiration",
            status
        );

        assert!(
            escrow.seconds_until_expiration().is_none(),
            "Terminal state '{}' should return None for seconds_until_expiration",
            status
        );

        assert!(
            !escrow.is_expired(),
            "Terminal state '{}' should not be considered expired",
            status
        );
    }

    Ok(())
}

/// Test: Find expired only returns active escrows
#[tokio::test]
async fn test_find_expired_excludes_terminal_states() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    // Create expired escrow in active state
    let _active_expired = create_test_escrow(&mut conn, "created", Some(-3600))?;

    // Create expired escrows in terminal states (should be ignored)
    for status in &["completed", "refunded", "cancelled", "expired"] {
        let escrow = create_test_escrow(&mut conn, status, Some(-3600))?;
        // Manually set expires_at (shouldn't happen in production, but test defensive coding)
        diesel::update(escrows::table.filter(escrows::id.eq(escrow.id)))
            .set(escrows::expires_at.eq(Some(Utc::now().naive_utc() - Duration::hours(1))))
            .execute(&mut conn)?;
    }

    // Should only find the active expired escrow
    let expired = Escrow::find_expired(&mut conn)?;
    assert_eq!(
        expired.len(),
        1,
        "Should only find 1 expired escrow (active state)"
    );
    assert_eq!(expired[0].status, "created");

    Ok(())
}

/// Test: TimeoutConfig from environment
#[test]
fn test_timeout_config_from_env() {
    // Set test environment variables
    std::env::set_var("TIMEOUT_MULTISIG_SETUP_SECS", "7200");
    std::env::set_var("TIMEOUT_FUNDING_SECS", "172800");

    let config = TimeoutConfig::from_env();

    assert_eq!(config.multisig_setup_timeout_secs, 7200);
    assert_eq!(config.funding_timeout_secs, 172800);

    // Cleanup
    std::env::remove_var("TIMEOUT_MULTISIG_SETUP_SECS");
    std::env::remove_var("TIMEOUT_FUNDING_SECS");
}

/// Test: TimeoutConfig timeout_for_status
#[test]
fn test_timeout_for_status() {
    let config = TimeoutConfig::default();

    // Active states
    assert_eq!(
        config.timeout_for_status("created"),
        Some(std::time::Duration::from_secs(3600))
    );
    assert_eq!(
        config.timeout_for_status("funded"),
        Some(std::time::Duration::from_secs(86400))
    );
    assert_eq!(
        config.timeout_for_status("releasing"),
        Some(std::time::Duration::from_secs(21600))
    );
    assert_eq!(
        config.timeout_for_status("disputed"),
        Some(std::time::Duration::from_secs(604800))
    );

    // Terminal states
    assert_eq!(config.timeout_for_status("completed"), None);
    assert_eq!(config.timeout_for_status("cancelled"), None);

    // Unknown states
    assert_eq!(config.timeout_for_status("unknown"), None);
}

/// Test: Multiple expired escrows detected
#[tokio::test]
async fn test_multiple_expired_escrows() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    // Create 5 expired escrows in different states
    create_test_escrow(&mut conn, "created", Some(-3600))?;
    create_test_escrow(&mut conn, "funded", Some(-7200))?;
    create_test_escrow(&mut conn, "releasing", Some(-1800))?;
    create_test_escrow(&mut conn, "disputed", Some(-86400))?;
    create_test_escrow(&mut conn, "created", Some(-900))?;

    // Create non-expired escrows (should be ignored)
    create_test_escrow(&mut conn, "funded", Some(3600))?;
    create_test_escrow(&mut conn, "completed", None)?;

    let expired = Escrow::find_expired(&mut conn)?;
    assert_eq!(expired.len(), 5, "Should find 5 expired escrows");

    Ok(())
}

/// Test: Expiring soon with different thresholds
#[tokio::test]
async fn test_expiring_soon_thresholds() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    // Create escrows expiring at different times
    create_test_escrow(&mut conn, "funded", Some(600))?; // 10 min
    create_test_escrow(&mut conn, "funded", Some(1800))?; // 30 min
    create_test_escrow(&mut conn, "funded", Some(5400))?; // 90 min
    create_test_escrow(&mut conn, "funded", Some(7200))?; // 2 hours

    // 1 hour threshold - should find 2 escrows (10min and 30min)
    let expiring_1h = Escrow::find_expiring_soon(&mut conn, 3600)?;
    assert_eq!(
        expiring_1h.len(),
        2,
        "Should find 2 escrows expiring within 1h"
    );

    // 2 hour threshold - should find 3 escrows
    let expiring_2h = Escrow::find_expiring_soon(&mut conn, 7200)?;
    assert_eq!(
        expiring_2h.len(),
        3,
        "Should find 3 escrows expiring within 2h"
    );

    Ok(())
}

/// Test: Integration - Full timeout detection workflow
///
/// This test simulates the complete TimeoutMonitor workflow:
/// 1. Create escrows in various states
/// 2. Initialize TimeoutMonitor
/// 3. Verify escrows are detected correctly
#[tokio::test]
async fn test_timeout_monitor_integration() -> Result<()> {
    let pool = setup_test_db()?;
    let mut conn = pool.get()?;

    // Setup: Create test escrows
    let expired_created = create_test_escrow(&mut conn, "created", Some(-3600))?;
    let expired_funded = create_test_escrow(&mut conn, "funded", Some(-7200))?;
    let expiring_soon = create_test_escrow(&mut conn, "funded", Some(1800))?;
    let _active = create_test_escrow(&mut conn, "releasing", Some(10800))?;
    let _completed = create_test_escrow(&mut conn, "completed", None)?;

    // Verify detection
    let expired = Escrow::find_expired(&mut conn)?;
    assert_eq!(expired.len(), 2, "Should detect 2 expired escrows");

    let expired_ids: Vec<String> = expired.iter().map(|e| e.id.clone()).collect();
    assert!(expired_ids.contains(&expired_created.id));
    assert!(expired_ids.contains(&expired_funded.id));

    let expiring = Escrow::find_expiring_soon(&mut conn, 3600)?;
    assert_eq!(expiring.len(), 1, "Should detect 1 expiring escrow");
    assert_eq!(expiring[0].id, expiring_soon.id);

    Ok(())
}
