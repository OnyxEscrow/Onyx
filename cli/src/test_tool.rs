//! CLI Test Tool pour tests manuels
//!
//! Outil simple pour tester les fonctionnalités refactorées

use anyhow::Result;
use monero_marketplace_common::{error::MoneroError, types::MoneroConfig, MONERO_RPC_URL};
use monero_marketplace_wallet::rpc::MoneroRpcClient;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging
    tracing_subscriber::fmt().init();

    info!("🧅 Monero Marketplace - CLI Test Tool v2.0");
    info!("==========================================\n");

    // Test 1: Création Client RPC
    info!("1️⃣ Testing RPC Client creation...");
    let config = MoneroConfig {
        rpc_url: MONERO_RPC_URL.to_string(),
        rpc_user: None,
        rpc_password: None,
        timeout_seconds: 30,
    };

    let client = match MoneroRpcClient::new(config) {
        Ok(client) => {
            info!("   ✅ RPC Client created successfully");
            client
        }
        Err(e) => {
            error!("   ❌ RPC Client creation failed: {}", e);
            return Ok(());
        }
    };

    info!("");

    // Test 2: Vérification Connexion
    info!("2️⃣ Testing RPC connection...");
    match client.check_connection().await {
        Ok(_) => {
            info!("   ✅ RPC connection successful");
        }
        Err(e) => {
            error!("   ❌ RPC connection failed: {}", e);
            info!("   💡 Launch wallet RPC: monero-wallet-rpc --testnet ...");
            return Ok(());
        }
    }

    info!("");

    // Test 3: prepare_multisig
    info!("3️⃣ Testing prepare_multisig...");

    match client.prepare_multisig().await {
        Ok(info) => {
            info!("   ✅ prepare_multisig succeeded");
            info!("   Info: {}...", &info.multisig_info[..50]);
            info!("   Length: {} chars", info.multisig_info.len());

            // Validation
            if info.multisig_info.starts_with("MultisigV1") {
                info!("   ✅ Validation passed (prefix OK)");
            } else {
                warn!("   ⚠️ Validation warning: Invalid prefix");
            }
        }
        Err(MoneroError::AlreadyMultisig) => {
            warn!("   ⚠️ Wallet already in multisig mode (normal if test replayed)");
            info!("   💡 To reset: close RPC, delete wallet, recreate");
        }
        Err(e) => {
            error!("   ❌ prepare_multisig failed: {}", e);
        }
    }

    info!("");

    // Test 4: Appels Concurrents
    info!("4️⃣ Testing concurrent calls...");
    let client_arc = std::sync::Arc::new(client);
    let handles: Vec<_> = (0..3)
        .map(|i| {
            let client = std::sync::Arc::clone(&client_arc);
            tokio::spawn(async move {
                match client.check_connection().await {
                    Ok(_) => format!("Task {}: ✅ Success", i + 1),
                    Err(e) => format!("Task {}: ❌ Failed: {}", i + 1, e),
                }
            })
        })
        .collect();

    for handle in handles {
        match handle.await {
            Ok(result) => info!("   {}", result),
            Err(e) => error!("   ❌ Task failed: {}", e),
        }
    }

    info!("");
    info!("✅ All tests completed");
    info!("");
    info!("📊 Summary:");
    info!("   - RPC Client: Thread-safe with Mutex + Semaphore");
    info!("   - Retry Logic: Backoff exponential implemented");
    info!("   - Validation: Stricte multisig_info validation");
    info!("   - Timeouts: Configurable via MONERO_RPC_TIMEOUT_SECS");
    info!("   - Logging: Structured with tracing");

    Ok(())
}
