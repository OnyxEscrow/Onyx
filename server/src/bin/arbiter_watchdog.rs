//! Arbiter Watchdog Daemon
//!
//! Standalone service that monitors escrows and automatically signs
//! for the arbiter when both parties have agreed (release or refund).
//!
//! ## Usage
//!
//! ```bash
//! # Required: Set vault master password
//! export ARBITER_VAULT_MASTER_PASSWORD="your_secure_password_here"
//!
//! # Optional: Configure polling and notifications
//! export ARBITER_WATCHDOG_POLL_INTERVAL_SECS=30
//! export ARBITER_TELEGRAM_BOT_TOKEN="your_bot_token"
//! export ARBITER_TELEGRAM_CHAT_ID="your_chat_id"
//!
//! # Run the daemon
//! cargo run --bin arbiter_watchdog
//! ```
//!
//! ## Environment Variables
//!
//! ### Required
//! - `ARBITER_VAULT_MASTER_PASSWORD` - Master password for encrypting arbiter keys
//! - `DATABASE_URL` - Path to SQLite database
//! - `DB_ENCRYPTION_KEY` - Database encryption key
//!
//! ### Optional
//! - `ARBITER_WATCHDOG_POLL_INTERVAL_SECS` - Poll interval (default: 30)
//! - `ARBITER_AUTO_SIGN_ENABLED` - Enable auto-signing (default: true)
//! - `ARBITER_REQUIRE_BOTH_SIGNATURES` - Require both parties signed (default: true)
//! - `ARBITER_TELEGRAM_BOT_TOKEN` - Telegram bot token
//! - `ARBITER_TELEGRAM_CHAT_ID` - Telegram chat ID
//! - `ARBITER_ALERT_EMAIL` - Email for alerts
//! - `ARBITER_WEBHOOK_URL` - Webhook URL for notifications
//! - `REDIS_URL` - Redis URL (default: redis://127.0.0.1:6379)

use anyhow::{Context, Result};
use std::env;
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use server::db::create_pool;
use server::redis_pool::init_redis_pool;
use server::services::arbiter_watchdog::{ArbiterWatchdog, WatchdogConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    init_tracing();

    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║           ONYX ARBITER WATCHDOG SERVICE v0.70.0               ║");
    info!("╠═══════════════════════════════════════════════════════════════╣");
    info!("║  Automated arbiter signing for non-disputed escrows          ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    // Load environment
    if let Err(e) = dotenvy::dotenv() {
        warn!("No .env file found: {}", e);
    }

    // Load configuration
    let config = WatchdogConfig::from_env().context("Failed to load watchdog configuration")?;

    info!(
        poll_interval_secs = config.poll_interval.as_secs(),
        auto_sign_enabled = config.auto_sign_enabled,
        require_both_signatures = config.require_both_signatures,
        has_telegram = config.has_telegram(),
        has_email = config.has_email(),
        has_webhook = config.has_webhook(),
        "Configuration loaded"
    );

    // Initialize database pool
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let db_encryption_key =
        env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY environment variable required")?;

    let db_pool =
        create_pool(&database_url, &db_encryption_key).context("Failed to create database pool")?;
    info!("Database pool initialized");

    // Initialize Redis pool
    let redis_pool = init_redis_pool().context("Failed to initialize Redis pool")?;
    info!("Redis pool initialized");

    // Create watchdog instance
    let watchdog = ArbiterWatchdog::new(db_pool, redis_pool, config)
        .await
        .context("Failed to create ArbiterWatchdog")?;
    let watchdog = Arc::new(watchdog);

    info!("ArbiterWatchdog ready - starting monitoring loop");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Handle shutdown signals
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received shutdown signal");
        std::process::exit(0);
    });

    // Run the watchdog
    watchdog.run().await;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,server=debug,arbiter_watchdog=debug"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();
}
