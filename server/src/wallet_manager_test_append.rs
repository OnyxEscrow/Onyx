
    /// Test finalize_multisig with multiple concurrent escrows (Regression Test)
    #[tokio::test]
    async fn test_finalize_multisig_with_multiple_escrows() {
        // Setup WalletManager
        let config = MoneroConfig::default();
        let mut manager = WalletManager::new(vec![config.clone()]).expect("Failed to create manager");

        // Create two escrow IDs
        let escrow1_id = Uuid::new_v4();
        let escrow2_id = Uuid::new_v4();

        // Helper to create a mock wallet instance
        let create_mock_wallet = |role: WalletRole, escrow_id: Uuid, address: &str| -> WalletInstance {
            WalletInstance {
                id: Uuid::new_v4(),
                role,
                rpc_client: MoneroClient::new(config.clone()).unwrap(), // Dummy client
                address: "individual_address".to_string(),
                multisig_state: MultisigState::Ready {
                    address: address.to_string(),
                },
                rpc_port: None,
                escrow_id: Some(escrow_id),
            }
        };

        // Populate manager with wallets for Escrow 1 (Address: "multisig_addr_1")
        let wallets1 = vec![
            create_mock_wallet(WalletRole::Buyer, escrow1_id, "multisig_addr_1"),
            create_mock_wallet(WalletRole::Vendor, escrow1_id, "multisig_addr_1"),
            create_mock_wallet(WalletRole::Arbiter, escrow1_id, "multisig_addr_1"),
        ];

        // Populate manager with wallets for Escrow 2 (Address: "multisig_addr_2")
        let wallets2 = vec![
            create_mock_wallet(WalletRole::Buyer, escrow2_id, "multisig_addr_2"),
            create_mock_wallet(WalletRole::Vendor, escrow2_id, "multisig_addr_2"),
            create_mock_wallet(WalletRole::Arbiter, escrow2_id, "multisig_addr_2"),
        ];

        // Insert all into manager
        for w in wallets1.into_iter().chain(wallets2.into_iter()) {
            manager.wallets.insert(w.id, w);
        }

        // TEST 1: Finalize Escrow 1
        // Should only see wallets for escrow1_id and return "multisig_addr_1"
        let result1 = manager.finalize_multisig(escrow1_id).await;
        assert!(result1.is_ok(), "Finalize escrow 1 failed");
        assert_eq!(result1.unwrap(), "multisig_addr_1");

        // TEST 2: Finalize Escrow 2
        // Should only see wallets for escrow2_id and return "multisig_addr_2"
        let result2 = manager.finalize_multisig(escrow2_id).await;
        assert!(result2.is_ok(), "Finalize escrow 2 failed");
        assert_eq!(result2.unwrap(), "multisig_addr_2");
    }
}
