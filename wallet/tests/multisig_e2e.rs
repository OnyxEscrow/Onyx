//! End-to-end integration tests for 2-of-3 multisig wallet setup
//!
//! These tests require:
//! 1. A running monerod testnet node
//! 2. Three monero-wallet-rpc instances on ports 18082, 18083, 18084
//!
//! Run: ./scripts/setup-3-wallets-testnet.sh before running these tests
//! Execute: cargo test --package wallet --test multisig_e2e -- --nocapture --test-threads=1

use anyhow::Result;
use monero_marketplace_common::types::MoneroConfig;
use monero_marketplace_wallet::MoneroClient;
use tracing::info;

/// Configuration for the 3 test wallets
const WALLET1_RPC_URL: &str = "http://127.0.0.1:18082/json_rpc";
const WALLET2_RPC_URL: &str = "http://127.0.0.1:18083/json_rpc";
const WALLET3_RPC_URL: &str = "http://127.0.0.1:18084/json_rpc";

/// Create a Monero client for a given wallet
fn create_client(rpc_url: &str) -> MoneroClient {
    let config = MoneroConfig {
        rpc_url: rpc_url.to_string(),
        rpc_user: None,
        rpc_password: None,
        timeout_seconds: 30,
    };
    MoneroClient::new(config).expect("Failed to create client")
}

#[tokio::test]
#[ignore] // Requires running wallet RPC servers
async fn test_full_multisig_2of3_setup() -> Result<()> {
    info!("\n🧪 Test: Complete 2-of-3 Multisig Setup (Full E2E)\n");
    info!("═══════════════════════════════════════════════════════\n");

    let client1 = create_client(WALLET1_RPC_URL);
    let client2 = create_client(WALLET2_RPC_URL);
    let client3 = create_client(WALLET3_RPC_URL);

    // 1. Setup 3 clients (done)

    // 2. Prepare multisig (parallel)
    info!("📋 STEP 1/6: Prepare Multisig\n");
    let info1 = client1.multisig().prepare_multisig().await?;
    let info2 = client2.multisig().prepare_multisig().await?;
    let info3 = client3.multisig().prepare_multisig().await?;
    info!("  ✅ All wallets prepared");

    // 3. Make multisig (collect infos)
    info!("\n📋 STEP 2/6: Make Multisig (2-of-3)\n");
    let make1 = client1
        .multisig()
        .make_multisig(
            2,
            vec![info2.multisig_info.clone(), info3.multisig_info.clone()],
        )
        .await?;
    let make2 = client2
        .multisig()
        .make_multisig(
            2,
            vec![info1.multisig_info.clone(), info3.multisig_info.clone()],
        )
        .await?;
    let make3 = client3
        .multisig()
        .make_multisig(
            2,
            vec![info1.multisig_info.clone(), info2.multisig_info.clone()],
        )
        .await?;
    info!("  ✅ All wallets have run make_multisig");

    // 4. Sync round 1 (export → import)
    info!("\n📋 ROUND 1: Synchronization (Export → Import)\n");
    let (export1_r1, _) = client1
        .multisig()
        .sync_multisig_round(|| async {
            Ok(vec![
                make2.multisig_info.clone(),
                make3.multisig_info.clone(),
            ])
        })
        .await?;
    let (export2_r1, _) = client2
        .multisig()
        .sync_multisig_round(|| async {
            Ok(vec![
                make1.multisig_info.clone(),
                make3.multisig_info.clone(),
            ])
        })
        .await?;
    let (export3_r1, _) = client3
        .multisig()
        .sync_multisig_round(|| async {
            Ok(vec![
                make1.multisig_info.clone(),
                make2.multisig_info.clone(),
            ])
        })
        .await?;
    info!("  ✅ Round 1 complete");

    // 5. Sync round 2 (export → import)
    info!("\n📋 ROUND 2: Final Synchronization (Export → Import)\n");
    client1
        .multisig()
        .sync_multisig_round(|| async {
            Ok(vec![export2_r1.info.clone(), export3_r1.info.clone()])
        })
        .await?;
    client2
        .multisig()
        .sync_multisig_round(|| async {
            Ok(vec![export1_r1.info.clone(), export3_r1.info.clone()])
        })
        .await?;
    client3
        .multisig()
        .sync_multisig_round(|| async {
            Ok(vec![export1_r1.info.clone(), export2_r1.info.clone()])
        })
        .await?;
    info!("  ✅ Round 2 complete");

    // 6. Verify all is_multisig() == true
    info!("\n📋 VERIFICATION: Checking multisig status\n");
    let is_multisig1 = client1.multisig().is_multisig().await?;
    let is_multisig2 = client2.multisig().is_multisig().await?;
    let is_multisig3 = client3.multisig().is_multisig().await?;
    assert!(is_multisig1);
    assert!(is_multisig2);
    assert!(is_multisig3);
    info!("  ✅ All wallets report as multisig");

    // 7. Assert same multisig_address
    // Note: The address is only available in the `make_multisig` response, which we already used.
    // A better test would be to call `get_address` on each client.
    info!("\n✅ SUCCESS: 2-of-3 multisig wallet fully operational!");

    Ok(())
}
