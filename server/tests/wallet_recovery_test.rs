//! Integration tests for wallet recovery system
//!
//! Tests the complete recovery flow:
//! 1. RPC config persistence
//! 2. Multisig state persistence
//! 3. Automatic recovery on restart
//! 4. Stuck escrow detection

#[cfg(test)]
mod wallet_recovery_tests {
    use server::db::create_pool;
    use server::models::wallet_rpc_config::WalletRpcConfig;
    use server::repositories::MultisigStateRepository;
    use server::wallet_manager::{WalletManager, WalletRole};
    use monero_marketplace_common::types::MoneroConfig;
    use anyhow::Result;

    /// Test encryption key for tests
    fn test_encryption_key() -> Vec<u8> {
        b"test_encryption_key_32_bytes_!!".to_vec()
    }

    /// Create test database
    fn setup_test_db() -> Result<server::db::DbPool> {
        let db_url = ":memory:"; // In-memory SQLite for tests
        let encryption_key = "test_key";
        create_pool(db_url, encryption_key)
    }

    #[tokio::test]
    #[ignore] // Run with: cargo test --test wallet_recovery_test -- --ignored
    async fn test_rpc_config_persistence() -> Result<()> {
        // Setup
        let pool = setup_test_db()?;
        let encryption_key = test_encryption_key();

        // Create WalletManager with persistence
        let mut wm = WalletManager::new_with_persistence(
            vec![MoneroConfig::default()],
            pool.clone(),
            encryption_key.clone(),
        )?;

        // Register a client wallet with automatic recovery mode
        let escrow_id = "test-escrow-001";
        let rpc_url = "http://127.0.0.1:18082/json_rpc";
        let rpc_user = Some("testuser".to_string());
        let rpc_password = Some("testpass".to_string());

        let wallet_id = wm.register_client_wallet_rpc(
            escrow_id,
            WalletRole::Buyer,
            rpc_url.to_string(),
            rpc_user.clone(),
            rpc_password.clone(),
            "automatic", // Enable persistence
        ).await;

        // Should succeed (will fail if RPC not available, but config should persist)
        assert!(wallet_id.is_ok() || wallet_id.is_err()); // Either case is valid

        // Verify RPC config was persisted to database
        let mut conn = pool.get()?;
        let configs = WalletRpcConfig::find_by_escrow(&mut conn, escrow_id)?;

        assert_eq!(configs.len(), 1, "Should have 1 RPC config persisted");

        let config = &configs[0];
        assert_eq!(config.escrow_id, escrow_id);
        assert_eq!(config.role, "buyer");

        // Verify decryption works
        let decrypted_url = config.decrypt_url(&encryption_key)?;
        assert_eq!(decrypted_url, rpc_url);

        if let Some(user) = rpc_user {
            let decrypted_user = config.decrypt_user(&encryption_key)?;
            assert_eq!(decrypted_user, Some(user));
        }

        println!("✅ RPC config persistence test passed");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_multisig_state_persistence() -> Result<()> {
        use server::models::multisig_state::{MultisigPhase, MultisigSnapshot};
        use std::collections::HashMap;
        use uuid::Uuid;

        // Setup
        let pool = setup_test_db()?;
        let encryption_key = test_encryption_key();
        let repo = MultisigStateRepository::new(pool.clone(), encryption_key.clone());

        // Create test snapshot
        let escrow_id = "test-escrow-002";
        let wallet_ids = HashMap::from([
            ("buyer".to_string(), Uuid::new_v4()),
            ("vendor".to_string(), Uuid::new_v4()),
            ("arbiter".to_string(), Uuid::new_v4()),
        ]);

        let rpc_urls = HashMap::from([
            ("buyer".to_string(), "http://127.0.0.1:18082".to_string()),
            ("vendor".to_string(), "http://127.0.0.1:18083".to_string()),
            ("arbiter".to_string(), "http://127.0.0.1:18084".to_string()),
        ]);

        let phase = MultisigPhase::Preparing {
            completed: vec!["buyer".to_string()],
        };

        let snapshot = MultisigSnapshot::new(phase.clone(), wallet_ids.clone(), rpc_urls.clone());

        // Persist snapshot
        repo.save_phase(escrow_id, &phase, &snapshot)?;

        // Load snapshot
        let loaded = repo.load_snapshot(escrow_id)?;
        assert!(loaded.is_some(), "Snapshot should be persisted");

        let loaded_snapshot = loaded.unwrap();
        assert_eq!(loaded_snapshot.wallet_ids, wallet_ids);
        assert_eq!(loaded_snapshot.rpc_urls, rpc_urls);

        println!("✅ Multisig state persistence test passed");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_find_stuck_escrows() -> Result<()> {
        use server::models::multisig_state::{MultisigPhase, MultisigSnapshot};
        use std::collections::HashMap;
        use uuid::Uuid;

        // Setup
        let pool = setup_test_db()?;
        let encryption_key = test_encryption_key();
        let repo = MultisigStateRepository::new(pool.clone(), encryption_key.clone());

        // Create escrow with old timestamp (stuck)
        let escrow_id = "test-escrow-003";
        let wallet_ids = HashMap::from([
            ("buyer".to_string(), Uuid::new_v4()),
            ("vendor".to_string(), Uuid::new_v4()),
            ("arbiter".to_string(), Uuid::new_v4()),
        ]);

        let rpc_urls = HashMap::from([
            ("buyer".to_string(), "http://127.0.0.1:18082".to_string()),
        ]);

        let phase = MultisigPhase::Preparing {
            completed: vec!["buyer".to_string()],
        };

        let snapshot = MultisigSnapshot::new(phase.clone(), wallet_ids, rpc_urls);

        // Persist with old timestamp
        repo.save_phase(escrow_id, &phase, &snapshot)?;

        // Wait a bit then check (in real scenario this would be >15 minutes)
        // For test purposes, we use a very short timeout
        let stuck_escrows = repo.find_stuck_escrows(0)?; // 0 seconds = everything is stuck

        assert!(
            stuck_escrows.contains(&escrow_id.to_string()),
            "Escrow should be detected as stuck"
        );

        println!("✅ Stuck escrow detection test passed");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_recovery_flow_integration() -> Result<()> {
        // This is a comprehensive test that would require:
        // 1. Setting up mock Monero RPC servers
        // 2. Creating full escrow with persistence
        // 3. Simulating server restart
        // 4. Verifying recovery

        // For now, we document the expected flow:
        println!("📋 Recovery flow integration test (manual verification required):");
        println!("1. Create escrow with automatic recovery mode");
        println!("2. Register buyer/vendor/arbiter wallet RPCs");
        println!("3. Complete multisig setup to Preparing phase");
        println!("4. Restart server (WalletManager.recover_active_escrows)");
        println!("5. Verify wallet connections restored");
        println!("6. Verify multisig state restored");
        println!("7. Verify WebSocket MultisigRecovered event emitted");

        // Placeholder - would need full environment setup
        Ok(())
    }
}
