//! Database initialization tool for SQLCipher
//!
//! This tool creates an encrypted SQLite database using SQLCipher
//! and applies all Diesel migrations.

use anyhow::{Context, Result};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::env;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

fn main() -> Result<()> {
    println!("🔐 SQLCipher Database Initialization Tool");
    println!("==========================================\n");

    // Load environment variables from .env
    dotenvy::dotenv().ok();

    // Get database URL and encryption key
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be set in .env file")?;
    let encryption_key =
        env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY must be set in .env file")?;

    println!("📁 Database: {database_url}");
    println!("🔑 Using encryption key from .env\n");

    // Create connection pool with SQLCipher using server's create_pool function
    let pool = server::db::create_pool(&database_url, &encryption_key)
        .context("Failed to create database connection pool")?;

    println!("✅ Created SQLCipher connection pool");

    // Get connection and run migrations
    let mut conn = pool.get().context("Failed to get database connection")?;

    println!("🔄 Running migrations...\n");

    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("Migration error: {e}"))?;

    println!("\n✅ All migrations applied successfully!");
    println!("🎉 Database is ready to use\n");

    Ok(())
}
