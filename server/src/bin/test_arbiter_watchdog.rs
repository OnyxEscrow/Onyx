use anyhow::Result;
use std::sync::Arc;
use tracing::{error, info};

use server::db::create_pool;
use server::redis_pool::init_redis_pool;
use server::services::arbiter_watchdog::{ArbiterWatchdog, WatchdogConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting ArbiterWatchdog manual test");

    // Load environment
    dotenvy::dotenv().ok();

    // Initialize database pool
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default();
    let db_pool = create_pool(&database_url, &encryption_key)?;
    info!("Database pool initialized");

    // Initialize Redis pool
    let redis_pool = match init_redis_pool() {
        Ok(pool) => {
            info!("Redis pool initialized");
            pool
        }
        Err(e) => {
            error!("Failed to initialize Redis pool: {}", e);
            return Err(e);
        }
    };

    // Load watchdog config from environment
    let config = match WatchdogConfig::from_env() {
        Ok(cfg) => {
            info!("Watchdog config loaded");
            cfg
        }
        Err(e) => {
            error!("Failed to load watchdog config: {}", e);
            return Err(e.into());
        }
    };

    // Initialize ArbiterWatchdog
    let watchdog = match ArbiterWatchdog::new(db_pool, redis_pool, config).await {
        Ok(wd) => {
            info!("ArbiterWatchdog initialized");
            Arc::new(wd)
        }
        Err(e) => {
            error!("Failed to initialize ArbiterWatchdog: {}", e);
            return Err(e);
        }
    };

    // Run the watchdog
    info!("Starting watchdog monitoring loop (Press Ctrl+C to stop)");
    watchdog.run().await;

    Ok(())
}
