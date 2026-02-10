#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    deprecated,
    unused_assignments
)]
//! Module de gestion des dépendances externes
//!
//! Ce module s'occupe de vérifier et de démarrer automatiquement les services
//! dépendants (Monero daemon et wallet RPCs) avant que le serveur ne commence
//! à traiter les requêtes.

use anyhow::{Context, Result};
use std::env;
use std::process::Command;
use tokio::time::{sleep, Duration};
use tracing::info;

/// Configuration réseau Monero
struct NetworkConfig {
    name: &'static str,
    wallet_base_port: u16,
    daemon_port: u16,
    network_flag: &'static str,
    wallet_dir: &'static str,
    monitor_rpc_port: u16, // Port for blockchain monitor view-only wallet RPC
}

/// Obtient la configuration réseau basée sur MONERO_NETWORK
fn get_network_config() -> NetworkConfig {
    let network = env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());

    match network.to_lowercase().as_str() {
        "stagenet" => NetworkConfig {
            name: "stagenet",
            wallet_base_port: 38083,
            daemon_port: 38081,
            network_flag: "--stagenet",
            wallet_dir: "./stagenet-wallets",
            monitor_rpc_port: 38086, // Blockchain monitor RPC
        },
        "mainnet" => NetworkConfig {
            name: "mainnet",
            wallet_base_port: 18082,
            daemon_port: 18081,
            network_flag: "--mainnet",
            wallet_dir: "./mainnet-wallets",
            monitor_rpc_port: 18086, // Blockchain monitor RPC
        },
        _ => NetworkConfig {
            // testnet by default
            name: "testnet",
            wallet_base_port: 18082,
            daemon_port: 28081,
            network_flag: "--testnet",
            wallet_dir: "./testnet-wallets",
            monitor_rpc_port: 28086, // Blockchain monitor RPC
        },
    }
}

/// Vérifie si un processus est en cours d'exécution
fn is_process_running(process_name: &str) -> bool {
    let output = Command::new("pgrep")
        .args(["-f", process_name])
        .output()
        .ok();

    match output {
        Some(output) => output.status.success() && !output.stdout.is_empty(),
        None => false,
    }
}

/// Vérifie si les RPCs sont disponibles en envoyant une requête simple
async fn check_rpc_availability() -> Result<bool> {
    use reqwest::Client;

    let config = get_network_config();

    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("Failed to build HTTP client")?;

    // Tester les 3 RPCs (base_port, base_port+1, base_port+2)
    let rpc_urls = [
        format!("http://127.0.0.1:{}/json_rpc", config.wallet_base_port),
        format!("http://127.0.0.1:{}/json_rpc", config.wallet_base_port + 1),
        format!("http://127.0.0.1:{}/json_rpc", config.wallet_base_port + 2),
    ];

    for url in &rpc_urls {
        let response = client
            .post(url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "health_check",
                "method": "get_version"
            }))
            .send()
            .await;

        match response {
            Ok(_) => continue,          // OK, ce RPC est accessible
            Err(_) => return Ok(false), // Un RPC est inaccessible
        }
    }

    Ok(true)
}

/// Démarre les instances de wallet RPC (buyer, vendor, arbiter + monitor)
pub fn start_wallet_rpcs() -> Result<()> {
    let config = get_network_config();

    info!(
        "🚀 Starting 4 Monero Wallet RPC instances ({})...",
        config.name
    );
    info!(
        "   - Buyer/Vendor/Arbiter: ports {}-{}",
        config.wallet_base_port,
        config.wallet_base_port + 2
    );
    info!("   - Blockchain Monitor: port {}", config.monitor_rpc_port);

    std::thread::sleep(Duration::from_millis(1000));

    // Créer le répertoire des wallets s'il n'existe pas
    std::fs::create_dir_all(config.wallet_dir)
        .context(format!("Failed to create {} directory", config.wallet_dir))?;

    let daemon_addr = format!("127.0.0.1:{}", config.daemon_port);

    // Démarrer le Buyer RPC
    let port1 = config.wallet_base_port.to_string();
    let _output1 = Command::new("monero-wallet-rpc")
        .args([
            "--rpc-bind-port",
            &port1,
            "--disable-rpc-login",
            "--wallet-dir",
            config.wallet_dir,
            "--daemon-address",
            &daemon_addr,
            config.network_flag,
            "--log-level",
            "2",
        ])
        .spawn()
        .context("Failed to start buyer RPC")?;

    // Démarrer le Vendor RPC
    let port2 = (config.wallet_base_port + 1).to_string();
    let _output2 = Command::new("monero-wallet-rpc")
        .args([
            "--rpc-bind-port",
            &port2,
            "--disable-rpc-login",
            "--wallet-dir",
            config.wallet_dir,
            "--daemon-address",
            &daemon_addr,
            config.network_flag,
            "--log-level",
            "2",
        ])
        .spawn()
        .context("Failed to start vendor RPC")?;

    // Démarrer le Arbiter RPC
    let port3 = (config.wallet_base_port + 2).to_string();
    let _output3 = Command::new("monero-wallet-rpc")
        .args([
            "--rpc-bind-port",
            &port3,
            "--disable-rpc-login",
            "--wallet-dir",
            config.wallet_dir,
            "--daemon-address",
            &daemon_addr,
            config.network_flag,
            "--log-level",
            "2",
        ])
        .spawn()
        .context("Failed to start arbiter RPC")?;

    // Démarrer le Blockchain Monitor RPC (for view-only wallet management)
    let monitor_port = config.monitor_rpc_port.to_string();
    let _output4 = Command::new("monero-wallet-rpc")
        .args([
            "--rpc-bind-port",
            &monitor_port,
            "--disable-rpc-login",
            "--wallet-dir",
            config.wallet_dir,
            "--daemon-address",
            &daemon_addr,
            config.network_flag,
            "--log-level",
            "1", // Lower log level for monitor
        ])
        .spawn()
        .context("Failed to start blockchain monitor RPC")?;

    // Attendre un peu pour que les processus démarrent
    std::thread::sleep(Duration::from_millis(500));

    // Vérifier que les processus sont bien lancés
    let port1_check = format!("monero-wallet-rpc.*{}", config.wallet_base_port);
    let port2_check = format!("monero-wallet-rpc.*{}", config.wallet_base_port + 1);
    let port3_check = format!("monero-wallet-rpc.*{}", config.wallet_base_port + 2);
    let monitor_check = format!("monero-wallet-rpc.*{}", config.monitor_rpc_port);

    if !is_process_running(&port1_check) {
        return Err(anyhow::anyhow!(
            "Failed to start buyer RPC on port {}",
            config.wallet_base_port
        ));
    }
    if !is_process_running(&port2_check) {
        return Err(anyhow::anyhow!(
            "Failed to start vendor RPC on port {}",
            config.wallet_base_port + 1
        ));
    }
    if !is_process_running(&port3_check) {
        return Err(anyhow::anyhow!(
            "Failed to start arbiter RPC on port {}",
            config.wallet_base_port + 2
        ));
    }
    if !is_process_running(&monitor_check) {
        return Err(anyhow::anyhow!(
            "Failed to start blockchain monitor RPC on port {}",
            config.monitor_rpc_port
        ));
    }

    info!("✅ All 4 Wallet RPC instances running:");
    info!("   - Buyer:    port {}", config.wallet_base_port);
    info!("   - Vendor:   port {}", config.wallet_base_port + 1);
    info!("   - Arbiter:  port {}", config.wallet_base_port + 2);
    info!("   - Monitor:  port {}", config.monitor_rpc_port);
    Ok(())
}

/// Vérifie et démarre automatiquement les dépendances nécessaires
pub async fn ensure_dependencies() -> Result<()> {
    let config = get_network_config();

    info!("🔍 Checking dependencies ({})...", config.name);

    // Vérifier si le daemon est en cours d'exécution
    let daemon_check = format!("monerod.*{}", config.name);
    if !is_process_running(&daemon_check) {
        info!("🚀 Starting Monero daemon in {} mode...", config.name);
        let data_dir = format!("./{}-data", config.name);
        let daemon_result = std::process::Command::new("monerod")
            .args([config.network_flag, "--detach", "--data-dir", &data_dir])
            .status()
            .context("Failed to start monerod daemon")?;

        if !daemon_result.success() {
            return Err(anyhow::anyhow!("Failed to start monerod daemon"));
        }

        // Attendre un peu pour que le daemon démarre
        tokio::time::sleep(Duration::from_secs(3)).await;

        info!("✅ Monero daemon started in {} mode", config.name);
    } else {
        info!("✅ Monero daemon is running ({})", config.name);
    }

    // Vérifier si les RPCs sont accessibles
    if check_rpc_availability().await.unwrap_or(false) {
        info!("✅ All RPC instances are accessible");
    } else {
        info!("⚠️ RPC instances not accessible, starting them...");
        start_wallet_rpcs()?;

        // Attendre suffisamment que les RPC soient prêts
        // Les RPCs prennent quelques secondes pour être opérationnels après le démarrage
        let mut success = false;
        for attempt in 1..=10 {
            sleep(Duration::from_secs(2)).await;
            if check_rpc_availability().await.unwrap_or(false) {
                info!("✅ All RPC instances started and accessible");
                success = true;
                break;
            }
            info!(
                "⏳ Waiting for RPC instances to be ready... (attempt {}/10)",
                attempt
            );
        }

        if !success {
            return Err(anyhow::anyhow!(
                "Failed to start RPC instances - timeout waiting for them to become responsive"
            ));
        }
    }

    info!("✅ All dependencies verified!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_process_running() {
        // Test with a known process
        let running = is_process_running("systemd");
        // This might not always be true depending on the environment
        // But the function should execute without panicking
        info!("systemd running: {}", running);
    }
}
