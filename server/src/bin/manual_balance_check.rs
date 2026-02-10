use anyhow::Result;
use server::db::create_pool;
use server::services::escrow::EscrowOrchestrator;
use server::wallet_manager::WalletManager;
use std::env;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔄 Starting direct multisig balance check via lazy sync...");

    // Get database encryption key from environment
    let db_encryption_key = env::var("DB_ENCRYPTION_KEY").expect("DB_ENCRYPTION_KEY must be set");

    // Create database pool
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let pool = create_pool(&database_url, &db_encryption_key)?;

    // Create wallet manager with appropriate RPC configs
    println!("🔐 Initializing WalletManager...");
    let rpc_configs = vec![
        monero_marketplace_common::types::MoneroConfig {
            rpc_url: "http://127.0.0.1:18082".to_string(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 60,
        },
        monero_marketplace_common::types::MoneroConfig {
            rpc_url: "http://127.0.0.1:18083".to_string(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 60,
        },
        monero_marketplace_common::types::MoneroConfig {
            rpc_url: "http://127.0.0.1:18084".to_string(),
            rpc_user: None,
            rpc_password: None,
            timeout_seconds: 60,
        },
    ];

    let mut wallet_manager = WalletManager::new_with_persistence(
        rpc_configs,
        pool.clone(),
        db_encryption_key.as_bytes().to_vec(),
    )?;

    // Enable wallet pool functionality
    if let Err(e) = wallet_manager.enable_wallet_pool(std::path::PathBuf::from("./testnet-wallets"))
    {
        eprintln!("Warning: Failed to enable wallet pool: {}", e);
    }

    // Create dummy websocket server (not used in this test)
    use actix::Actor;
    use server::websocket::WebSocketServer;
    let ws_server = WebSocketServer::default().start();

    // Create orchestrator
    let orchestrator = EscrowOrchestrator::new(
        std::sync::Arc::new(tokio::sync::Mutex::new(wallet_manager)),
        pool,
        ws_server,
        db_encryption_key.as_bytes().to_vec(),
    );

    // Specific escrow ID to check
    let escrow_id_str = "11959eae-dda8-4f46-bf31-05ecf6a82f20";
    let escrow_id = escrow_id_str.parse::<Uuid>()?;

    println!("🔍 Checking balance for escrow: {}", escrow_id_str);

    // Call the lazy sync function directly
    match orchestrator.sync_and_get_balance(escrow_id).await {
        Ok((balance_atomic, unlocked_balance_atomic)) => {
            let balance_xmr = balance_atomic as f64 / 1_000_000_000_000.0;
            let unlocked_xmr = unlocked_balance_atomic as f64 / 1_000_000_000_000.0;

            println!("✅ Balance check successful!");
            println!(
                "💰 Balance: {} atomic units ({:.12} XMR)",
                balance_atomic, balance_xmr
            );
            println!(
                "🔓 Unlocked: {} atomic units ({:.12} XMR)",
                unlocked_balance_atomic, unlocked_xmr
            );

            // Expected transaction amount: 0.000000000246 XMR = 246 atomic units
            let expected_atomic = 246u64;
            if balance_atomic >= expected_atomic {
                println!("🎉 SUCCESS: Expected amount or more detected!");
                println!("✅ Transaction confirmed in multisig address");
                println!("✅ Lazy sync multisig system working correctly");
            } else if balance_atomic > 0 {
                println!(
                    "ℹ️  Partial amount detected: {} atomic units",
                    balance_atomic
                );
                println!("⚠️  Expected at least: {} atomic units", expected_atomic);
            } else {
                println!("⚠️  Balance still showing 0 - transaction may still be confirming");
                println!("💡 This could be due to blockchain confirmation time");
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to check balance: {}", e);
            eprintln!("💡 This might be due to:");
            eprintln!("   - RPC instances not responding");
            eprintln!("   - Wallet files not properly created");
            eprintln!("   - Multisig setup not fully completed");
            eprintln!("   - Temporary network/RPC issues");
            return Err(e);
        }
    }

    Ok(())
}
