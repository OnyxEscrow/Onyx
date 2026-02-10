//! E2E Tests for Transaction Flow (Milestone 1.2)
//!
//! These tests verify the complete transaction flow:
//! 1. Create multisig transaction (unsigned)
//! 2. Sign transaction with 2-of-3 signatures
//! 3. Finalize transaction
//! 4. Broadcast to network
//! 5. Monitor confirmations
//!
//! Prerequisites:
//! - Run scripts/setup-3-wallets-testnet.sh to create 3 wallets
//! - Ensure wallets are synchronized and have testnet funds

use monero_marketplace_common::{
    error::Result,
    types::{MoneroConfig, TransferDestination},
    utils::xmr_to_atomic,
};
use monero_marketplace_wallet::MoneroClient;

/// Helper to create client for each wallet
fn create_wallet_client(_wallet_name: &str, port: u16) -> Result<MoneroClient> {
    let config = MoneroConfig {
        rpc_url: format!("http://127.0.0.1:{}/json_rpc", port),
        rpc_user: None,
        rpc_password: None,
        timeout_seconds: 30,
    };
    MoneroClient::new(config)
}

#[tokio::test]
#[ignore] // Run only with: cargo test --test transaction_e2e -- --ignored
async fn test_complete_transaction_flow() -> Result<()> {
    tracing::info!("Transaction E2E Test (Milestone 1.2)");

    // Step 0: Create clients for buyer, vendor, arbiter wallets
    tracing::info!("Step 0: Creating wallet clients");
    let buyer_client = create_wallet_client("buyer", 18082)?;
    let vendor_client = create_wallet_client("vendor", 18083)?;
    let _arbiter_client = create_wallet_client("arbiter", 18084)?;

    // Verify wallets are multisig
    tracing::info!("Verifying wallets are in multisig mode");
    let buyer_status = buyer_client.get_wallet_status().await?;
    assert!(buyer_status.is_multisig, "Buyer wallet is not multisig");
    assert_eq!(
        buyer_status.multisig_threshold,
        Some(2),
        "Buyer wallet threshold is not 2"
    );
    assert_eq!(
        buyer_status.multisig_total,
        Some(3),
        "Buyer wallet total is not 3"
    );

    tracing::info!("Buyer wallet: 2-of-3 multisig");
    tracing::info!("Balance: {} XMR", buyer_status.balance as f64 / 1e12);

    // Task 1.2.1: Create unsigned multisig transaction
    tracing::info!("Task 1.2.1: Create Transaction");
    let recipient_address = "9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8"; // Example testnet address
    let amount = xmr_to_atomic(0.1)?; // 0.1 XMR

    let destinations = vec![TransferDestination {
        address: recipient_address.to_string(),
        amount,
    }];

    tracing::info!("Creating unsigned transaction");
    tracing::info!("To: {}", recipient_address);
    tracing::info!("Amount: 0.1 XMR");

    let create_result = buyer_client
        .transaction()
        .create_transaction(destinations)
        .await?;

    tracing::info!("Transaction created");
    tracing::info!("TX Hash: {}", create_result.tx_hash);
    tracing::info!("Fee: {} XMR", create_result.fee as f64 / 1e12);
    tracing::info!(
        "Total: {} XMR",
        (create_result.amount + create_result.fee) as f64 / 1e12
    );

    // Task 1.2.2: Sign transaction (Buyer signature)
    tracing::info!("Task 1.2.2: Sign Transaction (Buyer)");
    let tx_data_hex = create_result.multisig_txset.clone();

    tracing::info!("Buyer signing transaction");
    let buyer_sign_result = buyer_client
        .transaction()
        .sign_multisig_transaction(tx_data_hex.clone())
        .await?;

    tracing::info!("Buyer signature added");
    tracing::info!("TX hashes: {:?}", buyer_sign_result.tx_hash_list);

    // Task 1.2.2: Sign transaction (Vendor signature - 2nd of 2 required)
    tracing::info!("Task 1.2.2: Sign Transaction (Vendor)");
    tracing::info!("Vendor signing transaction");
    let vendor_sign_result = vendor_client
        .transaction()
        .sign_multisig_transaction(buyer_sign_result.tx_data_hex.clone())
        .await?;

    tracing::info!("Vendor signature added");
    tracing::info!("TX hashes: {:?}", vendor_sign_result.tx_hash_list);
    tracing::info!("Transaction now has 2-of-3 signatures (ready to broadcast)");

    // Task 1.2.3 + 1.2.4: Finalize and broadcast transaction
    tracing::info!("Task 1.2.3 + 1.2.4: Finalize and Broadcast");
    tracing::info!("Finalizing and broadcasting transaction");
    let submit_result = buyer_client
        .transaction()
        .finalize_and_broadcast_transaction(vendor_sign_result.tx_data_hex)
        .await?;

    tracing::info!("Transaction broadcast to network");
    tracing::info!("TX hashes: {:?}", submit_result.tx_hash_list);

    // Task 1.2.5: Monitor transaction (get confirmations)
    tracing::info!("Task 1.2.5: Monitor Transaction");
    let tx_hash = submit_result.tx_hash_list.first().ok_or_else(|| {
        monero_marketplace_common::error::Error::InvalidInput("No TX hash".to_string())
    })?;

    tracing::info!("Querying transaction status");
    let tx_info = buyer_client
        .transaction()
        .get_transaction_info(tx_hash.clone())
        .await?;

    tracing::info!("Transaction info retrieved");
    tracing::info!("TX Hash: {}", tx_info.tx_hash);
    tracing::info!("Confirmations: {}", tx_info.confirmations);
    tracing::info!("Block Height: {}", tx_info.block_height);
    tracing::info!("Amount: {} XMR", tx_info.amount as f64 / 1e12);
    tracing::info!("Fee: {} XMR", tx_info.fee as f64 / 1e12);

    tracing::info!("All Milestone 1.2 tasks completed successfully");
    tracing::info!("Task 1.2.1: create_transaction()");
    tracing::info!("Task 1.2.2: sign_multisig_transaction() (2 signatures)");
    tracing::info!("Task 1.2.3: finalize_multisig_transaction()");
    tracing::info!("Task 1.2.4: broadcast_transaction()");
    tracing::info!("Task 1.2.5: get_transaction_info()");

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_transaction_requires_2_of_3_signatures() -> Result<()> {
    tracing::info!("Test: Transaction Requires 2-of-3 Signatures");

    let buyer_client = create_wallet_client("buyer", 18082)?;

    let recipient_address = "9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8";
    let amount = xmr_to_atomic(0.05)?;

    let destinations = vec![TransferDestination {
        address: recipient_address.to_string(),
        amount,
    }];

    tracing::info!("Creating transaction");
    let create_result = buyer_client
        .transaction()
        .create_transaction(destinations)
        .await?;

    tracing::info!("Transaction created");

    // Try to broadcast with only 1 signature (should fail)
    tracing::info!("Attempting to broadcast with only 1 signature");
    let buyer_sign_result = buyer_client
        .transaction()
        .sign_multisig_transaction(create_result.multisig_txset.clone())
        .await?;

    let result = buyer_client
        .transaction()
        .finalize_and_broadcast_transaction(buyer_sign_result.tx_data_hex)
        .await;

    // Should fail because we need 2-of-3 signatures
    assert!(
        result.is_err(),
        "Transaction should fail with only 1 signature"
    );
    tracing::info!("Transaction correctly rejected (needs 2-of-3 signatures)");

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_transaction_with_invalid_address() -> Result<()> {
    tracing::info!("Test: Transaction with Invalid Address");

    let buyer_client = create_wallet_client("buyer", 18082)?;

    let invalid_address = "invalid_monero_address";
    let amount = xmr_to_atomic(0.1)?;

    let destinations = vec![TransferDestination {
        address: invalid_address.to_string(),
        amount,
    }];

    tracing::info!("Attempting to create transaction with invalid address");
    let result = buyer_client
        .transaction()
        .create_transaction(destinations)
        .await;

    assert!(result.is_err(), "Should fail with invalid address");
    tracing::info!("Transaction correctly rejected (invalid address)");

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_transaction_insufficient_balance() -> Result<()> {
    tracing::info!("Test: Transaction with Insufficient Balance");

    let buyer_client = create_wallet_client("buyer", 18082)?;

    let recipient_address = "9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8";
    let huge_amount = xmr_to_atomic(1000000.0)?; // 1 million XMR (way too much)

    let destinations = vec![TransferDestination {
        address: recipient_address.to_string(),
        amount: huge_amount,
    }];

    tracing::info!("Attempting to create transaction with insufficient balance");
    let result = buyer_client
        .transaction()
        .create_transaction(destinations)
        .await;

    assert!(result.is_err(), "Should fail with insufficient balance");
    tracing::info!("Transaction correctly rejected (insufficient balance)");

    Ok(())
}
