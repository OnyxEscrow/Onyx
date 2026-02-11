#![allow(dead_code, unused_imports)]
//! Monero Marketplace CLI
//!
//! Command-line interface for the Monero Marketplace

mod checkpoint;
mod crypto;
mod noncustodial_wallet;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use monero_marketplace_common::{
    types::{MoneroConfig, WorkflowStep},
    MONERO_RPC_URL,
};
use monero_marketplace_wallet::MoneroClient;
use tracing::{error, info, warn};

/// Monero Marketplace CLI
#[derive(Parser)]
#[command(name = "monero-marketplace")]
#[command(about = "Monero Marketplace - Secure Escrow Platform")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Monero RPC URL
    #[arg(long, default_value = MONERO_RPC_URL)]
    rpc_url: String,

    /// RPC timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,
}

#[derive(Subcommand)]
enum Commands {
    /// Get wallet status
    Status,
    /// Get complete wallet information
    Info,
    /// Multisig operations
    Multisig {
        #[command(subcommand)]
        command: MultisigCommands,
    },
    /// Manage checkpoints for multisig workflows
    Checkpoint {
        #[command(subcommand)]
        command: CheckpointCommands,
    },
    /// Non-custodial escrow operations (Phase 2)
    Noncustodial {
        #[command(subcommand)]
        command: NoncustodialCommands,
    },
    /// Wallet operations (generate seeds, register wallets)
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    /// Test RPC connection
    Test,
}

#[derive(Subcommand)]
enum MultisigCommands {
    /// Prepare multisig (initial step)
    Prepare {
        /// Session ID for the workflow
        #[arg(long)]
        session: Option<String>,
    },
    /// Create the multisig wallet from prepared info
    Make {
        /// Session ID for the workflow
        #[arg(long)]
        session: Option<String>,
        /// Threshold (number of signatures required, e.g., 2 for 2-of-3)
        #[arg(short, long, default_value = "2")]
        threshold: u32,
        /// Multisig info from other participants
        #[arg(short, long)]
        info: Vec<String>,
    },
    /// Export multisig info for other participants
    Export {
        /// Session ID for the workflow
        #[arg(long)]
        session: Option<String>,
    },
    /// Import multisig info from other participants
    Import {
        /// Session ID for the workflow
        #[arg(long)]
        session: Option<String>,
        /// Multisig info to import
        #[arg(short, long)]
        info: Vec<String>,
    },
    /// Check if wallet is multisig
    Check,
}

#[derive(Subcommand)]
enum CheckpointCommands {
    /// List all saved checkpoints
    List,
    /// Show details of a specific checkpoint
    Show {
        /// The session ID of the checkpoint to show
        session_id: String,
    },
    /// Delete a specific checkpoint
    Delete {
        /// The session ID of the checkpoint to delete
        session_id: String,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Generate a new 24-word BIP39 mnemonic
    Generate {
        /// Optional server URL for registration (if provided, registers wallet after generation)
        #[arg(long)]
        server_url: Option<String>,
    },
    /// Recover a wallet from a mnemonic phrase
    Recover {
        /// Mnemonic phrase (24 words)
        #[arg(long)]
        mnemonic: String,
        /// Optional server URL for registration
        #[arg(long)]
        server_url: Option<String>,
    },
    /// Register a wallet with the server
    Register {
        /// Server URL
        #[arg(long, default_value = "http://localhost:8080")]
        server_url: String,
        /// Mnemonic phrase (24 words)
        #[arg(long)]
        mnemonic: String,
    },
}

#[derive(Subcommand)]
enum NoncustodialCommands {
    /// Initialize non-custodial escrow (Phase 2 flow)
    InitEscrow {
        /// Escrow ID
        #[arg(long)]
        escrow_id: String,
        /// Role (buyer, seller, or arbiter)
        #[arg(long)]
        role: String,
        /// Local wallet name
        #[arg(long, default_value = "noncustodial_wallet")]
        wallet_name: String,
        /// Local wallet RPC URL
        #[arg(long, default_value = "http://127.0.0.1:18083")]
        local_rpc_url: String,
        /// Server coordinator URL
        #[arg(long, default_value = "http://localhost:8080")]
        server_url: String,
    },
    /// Check local wallet status
    WalletInfo {
        /// Local wallet RPC URL
        #[arg(long, default_value = "http://127.0.0.1:18083")]
        local_rpc_url: String,
        /// Role (for display)
        #[arg(long, default_value = "buyer")]
        role: String,
        /// Server URL (for API calls)
        #[arg(long, default_value = "http://localhost:8080")]
        server_url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Create Monero client
    let config = MoneroConfig {
        rpc_url: cli.rpc_url,
        rpc_user: None,
        rpc_password: None,
        timeout_seconds: cli.timeout,
    };

    let client = MoneroClient::new(config)?;

    // Execute command
    match cli.command {
        Commands::Status => {
            info!("Getting wallet status...");
            let status = client.get_wallet_status().await?;
            info!("Wallet Status:");
            info!("  Multisig: {}", status.is_multisig);
            if let Some(threshold) = status.multisig_threshold {
                if let Some(total) = status.multisig_total {
                    info!("  Threshold: {}/{}", threshold, total);
                } else {
                    info!("  Threshold: {}/?", threshold);
                }
            }
            info!("  Balance: {} XMR", status.balance as f64 / 1e12);
            info!("  Unlocked: {} XMR", status.unlocked_balance as f64 / 1e12);
        }

        Commands::Info => {
            info!("Getting complete wallet information...");
            let wallet_info = client.get_wallet_info().await?;
            info!("Wallet Information:");
            info!("  Version: {}", wallet_info.version);
            info!("  Balance: {} XMR", wallet_info.balance as f64 / 1e12);
            info!(
                "  Unlocked: {} XMR",
                wallet_info.unlocked_balance as f64 / 1e12
            );
            info!("  Multisig: {}", wallet_info.is_multisig);
            if let Some(threshold) = wallet_info.multisig_threshold {
                if let Some(total) = wallet_info.multisig_total {
                    info!("  Threshold: {}/{}", threshold, total);
                } else {
                    info!("  Threshold: {}/?", threshold);
                }
            }
            info!("  Block Height: {}", wallet_info.block_height);
            info!("  Daemon Block Height: {}", wallet_info.daemon_block_height);
        }

        Commands::Multisig { command } => match command {
            MultisigCommands::Prepare { session } => {
                if let Some(session_id) = session {
                    let mut checkpoint = checkpoint::load_checkpoint(&session_id)?;
                    info!("Preparing multisig for session '{}'...", session_id);

                    let result = client.multisig().prepare_multisig().await?;
                    info!("Multisig info: {}", result.multisig_info);

                    checkpoint.current_step = WorkflowStep::Prepared;
                    checkpoint.local_multisig_info = Some(result.multisig_info);
                    checkpoint::save_checkpoint(&checkpoint)?;
                    info!("Checkpoint '{}' saved.", session_id);
                } else {
                    info!("Preparing multisig (stateless)...");
                    let result = client.multisig().prepare_multisig().await?;
                    info!("Multisig info: {}", result.multisig_info);
                }
            }

            MultisigCommands::Make {
                session,
                threshold,
                mut info,
            } => {
                if let Some(session_id) = session {
                    let mut checkpoint = checkpoint::load_checkpoint(&session_id)?;
                    info!("Making multisig for session '{}'...", session_id);

                    // Combine infos from command line and checkpoint
                    info.extend(checkpoint.remote_multisig_infos.clone());
                    info.dedup(); // Remove duplicates

                    let total_participants = info.len() + 1;
                    info!(
                        "Making {}-of-{} multisig with {} remote infos...",
                        threshold,
                        total_participants,
                        info.len()
                    );

                    let result = client
                        .multisig()
                        .make_multisig(threshold, info.clone())
                        .await?;
                    info!("Multisig address: {}", result.address);
                    info!("Multisig info for sync: {}", result.multisig_info);

                    checkpoint.current_step = WorkflowStep::Made;
                    checkpoint.multisig_address = Some(result.address);
                    checkpoint.local_multisig_info = Some(result.multisig_info);
                    checkpoint.remote_multisig_infos = info;
                    checkpoint.required_signatures = Some(threshold);
                    checkpoint::save_checkpoint(&checkpoint)?;
                    info!("Checkpoint '{}' saved.", session_id);
                } else {
                    info!(
                        "Making {}-of-{} multisig with {} infos...",
                        threshold,
                        info.len() + 1,
                        info.len()
                    );
                    let result = client.multisig().make_multisig(threshold, info).await?;
                    info!("Multisig address: {}", result.address);
                    info!("Multisig info: {}", result.multisig_info);
                }
            }

            MultisigCommands::Export { session } => {
                if let Some(session_id) = session {
                    let checkpoint = checkpoint::load_checkpoint(&session_id)?;
                    info!("Exporting multisig info for session '{}'...", session_id);
                    if let Some(info) = checkpoint.local_multisig_info {
                        info!("Multisig info: {}", info);
                    } else {
                        warn!("No local multisig info found in checkpoint. Run 'prepare' or 'make' first.");
                    }
                } else {
                    info!("Exporting multisig info (stateless)...");
                    let info = client.multisig().export_multisig_info().await?;
                    info!("Multisig info: {}", info.info);
                }
            }

            MultisigCommands::Import { session, info } => {
                if let Some(session_id) = session {
                    let mut checkpoint = checkpoint::load_checkpoint(&session_id)?;
                    info!(
                        "Importing {} multisig info(s) for session '{}'...",
                        info.len(),
                        session_id
                    );

                    let result = client.multisig().import_multisig_info(info.clone()).await?;
                    info!("Imported multisig info, {} outputs", result.n_outputs);

                    checkpoint.remote_multisig_infos.extend(info);
                    checkpoint.remote_multisig_infos.dedup();
                    // A simple heuristic to advance the step
                    if checkpoint.current_step == WorkflowStep::Made {
                        checkpoint.current_step = WorkflowStep::SyncedRound1;
                    } else if checkpoint.current_step == WorkflowStep::SyncedRound1 {
                        checkpoint.current_step = WorkflowStep::SyncedRound2;
                    }

                    checkpoint::save_checkpoint(&checkpoint)?;
                    info!("Checkpoint '{}' saved.", session_id);
                } else {
                    info!("Importing {} multisig infos (stateless)...", info.len());
                    let result = client.multisig().import_multisig_info(info).await?;
                    info!("Imported multisig info, {} outputs", result.n_outputs);
                }
            }

            MultisigCommands::Check => {
                let is_multisig = client.multisig().is_multisig().await?;
                info!("Wallet is multisig: {}", is_multisig);
            }
        },

        Commands::Checkpoint { command } => match command {
            CheckpointCommands::List => {
                info!("Listing all checkpoints...");
                let checkpoints = checkpoint::list_checkpoints()?;
                if checkpoints.is_empty() {
                    info!("No checkpoints found.");
                } else {
                    for cp in checkpoints {
                        info!(
                            "  - Session: {}, Step: {:?}, Updated: {}",
                            cp.session_id, cp.current_step, cp.last_updated
                        );
                    }
                }
            }
            CheckpointCommands::Show { session_id } => {
                info!("Showing details for checkpoint '{}'...", session_id);
                let checkpoint = checkpoint::load_checkpoint(&session_id)?;
                let pretty_json = serde_json::to_string_pretty(&checkpoint)?;
                info!("\n{}", pretty_json);
            }
            CheckpointCommands::Delete { session_id } => {
                info!("Deleting checkpoint '{}'...", session_id);
                checkpoint::delete_checkpoint(&session_id)?;
                info!("Checkpoint '{}' deleted.", session_id);
            }
        },

        Commands::Noncustodial { command } => match command {
            NoncustodialCommands::InitEscrow {
                escrow_id,
                role,
                wallet_name,
                local_rpc_url,
                server_url,
            } => {
                info!("🔐 Starting non-custodial escrow initialization");
                info!("Escrow ID: {}", escrow_id);
                info!("Role: {}", role);
                info!("Local RPC: {}", local_rpc_url);
                info!("Server: {}", server_url);

                // Parse role
                let escrow_role = noncustodial_wallet::parse_role(&role).context("Invalid role")?;

                // Create non-custodial client
                let noncustodial_client = noncustodial_wallet::NonCustodialClient::new(
                    local_rpc_url.clone(),
                    server_url.clone(),
                    escrow_role,
                )?;

                // Initialize escrow
                let multisig_address = noncustodial_client
                    .init_escrow(&escrow_id, &wallet_name)
                    .await?;

                info!("✅ Non-custodial escrow initialized successfully!");
                info!("Multisig address: {}", multisig_address);
            }

            NoncustodialCommands::WalletInfo {
                local_rpc_url,
                role,
                server_url,
            } => {
                info!("Getting wallet info for {} at {}", role, local_rpc_url);

                // Parse role
                let escrow_role = noncustodial_wallet::parse_role(&role).context("Invalid role")?;

                // Create non-custodial client
                let noncustodial_client = noncustodial_wallet::NonCustodialClient::new(
                    local_rpc_url,
                    server_url,
                    escrow_role,
                )?;

                // Get wallet info
                noncustodial_client.get_wallet_info().await?;
            }
        },

        Commands::Wallet { command } => match command {
            WalletCommands::Generate { server_url } => {
                handle_wallet_generate(server_url).await?;
            }
            WalletCommands::Recover {
                mnemonic,
                server_url,
            } => {
                handle_wallet_recover(&mnemonic, server_url).await?;
            }
            WalletCommands::Register {
                server_url,
                mnemonic,
            } => {
                handle_wallet_register(&server_url, &mnemonic).await?;
            }
        },

        Commands::Test => {
            info!("Testing RPC connection...");
            match client.rpc().get_version().await {
                Ok(version) => {
                    info!("✅ RPC connection successful");
                    info!("Monero version: {}", version);
                }
                Err(e) => {
                    error!("❌ RPC connection failed: {}", e);
                    return Err(anyhow::anyhow!("RPC connection failed: {e}"));
                }
            }
        }
    }

    Ok(())
}

// ===== Wallet Command Handlers =====

/// Handle `wallet generate` command: Generate new BIP39 mnemonic
async fn handle_wallet_generate(server_url: Option<String>) -> Result<()> {
    use crate::crypto::traits::DefaultSeedManager;

    info!("🔐 Generating new 24-word BIP39 mnemonic...");

    let seed = DefaultSeedManager::generate_new().context("Failed to generate new seed")?;

    info!("✅ New seed generated successfully!");

    // SECURITY: Use println! instead of info! to avoid logging mnemonic to files
    println!();
    println!("⚠️  IMPORTANT: Write down these 24 words in order:");
    println!("========================================");
    println!("{}", seed.mnemonic_phrase);
    println!("========================================");
    println!();
    println!("⚠️  SECURITY WARNINGS:");
    println!("   - Never share these words with anyone");
    println!("   - Never type them into untrusted software");
    println!("   - Store them securely (encrypted, offline)");
    println!("   - If anyone learns these words, they can control your wallet");
    println!();

    // Optionally register with server
    if let Some(url) = server_url {
        info!("Registering wallet with server at {}...", url);
        let _keys =
            DefaultSeedManager::derive_keys(&seed).context("Failed to derive keys from seed")?;

        // Registration logic would go here (next step)
        warn!("Address derivation not yet implemented - skipping registration");
    }

    Ok(())
}

/// Handle `wallet recover` command: Recover from mnemonic phrase
async fn handle_wallet_recover(mnemonic: &str, server_url: Option<String>) -> Result<()> {
    use crate::crypto::traits::DefaultSeedManager;

    info!("🔐 Recovering wallet from mnemonic phrase...");

    let seed =
        DefaultSeedManager::recover_from_mnemonic(mnemonic).context("Invalid mnemonic phrase")?;

    info!("✅ Wallet recovered successfully!");
    info!(
        "Seed recovered from: {} words",
        seed.mnemonic_phrase.split_whitespace().count()
    );

    // Optionally register with server
    if let Some(url) = server_url {
        info!("Registering recovered wallet with server at {}...", url);
        let _keys =
            DefaultSeedManager::derive_keys(&seed).context("Failed to derive keys from seed")?;

        // Registration logic would go here
        warn!("Address derivation not yet implemented - skipping registration");
    }

    Ok(())
}

/// Handle `wallet register` command: Register wallet with server
async fn handle_wallet_register(server_url: &str, mnemonic: &str) -> Result<()> {
    use crate::crypto::traits::DefaultSeedManager;

    info!("🔐 Registering wallet with server at {}...", server_url);

    let seed =
        DefaultSeedManager::recover_from_mnemonic(mnemonic).context("Invalid mnemonic phrase")?;

    let keys = DefaultSeedManager::derive_keys(&seed).context("Failed to derive keys from seed")?;

    // Create registration request (public keys only, no private keys)
    let request = keys
        .to_registration_request()
        .context("Failed to create registration request")?;

    info!("📮 Sending registration request to {}...", server_url);

    // TODO: Implement actual HTTP POST to server
    // For now, just print the request details
    info!("Registration request:");
    info!("  Address: {}", request.address);
    info!("  View Key (pub): {}", request.view_key_pub);
    info!("  Spend Key (pub): {}", request.spend_key_pub);

    warn!("HTTP registration not yet implemented");

    Ok(())
}
