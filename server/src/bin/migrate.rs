//! Standalone migration runner for SQLCipher database
//!
//! Does not depend on server lib, only on diesel_migrations and libsqlcipher.

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::env;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

type SqlCipherConnectionManager = ConnectionManager<SqliteConnection>;
type DbPool = Pool<SqlCipherConnectionManager>;

fn create_sqlcipher_pool(database_url: &str, encryption_key: &str) -> Result<DbPool> {
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(SqlCipherCustomizer::new(encryption_key)))
        .build(manager)
        .context("Failed to create connection pool")?;
    Ok(pool)
}

#[derive(Debug)]
struct SqlCipherCustomizer {
    key: String,
}

impl SqlCipherCustomizer {
    fn new(key: &str) -> Self {
        Self {
            key: key.to_string(),
        }
    }
}

impl diesel::r2d2::CustomizeConnection<SqliteConnection, diesel::r2d2::Error>
    for SqlCipherCustomizer
{
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        // Set SQLCipher pragmas
        diesel::sql_query(format!("PRAGMA key = '{}'", self.key))
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        diesel::sql_query("PRAGMA cipher_compatibility = 4")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        diesel::sql_query("PRAGMA foreign_keys = ON")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        Ok(())
    }
}

fn main() -> Result<()> {
    println!("🔐 Onyx Database Migration Tool");
    println!("================================\n");

    // Load environment variables from .env
    dotenvy::dotenv().ok();

    // Get database URL and encryption key
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be set in .env file")?;
    let encryption_key =
        env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY must be set in .env file")?;

    println!("📁 Database: {database_url}");
    println!("🔑 Using encryption key from .env\n");

    // Create connection pool with SQLCipher
    let pool = create_sqlcipher_pool(&database_url, &encryption_key)
        .context("Failed to create database connection pool")?;

    println!("✅ Created SQLCipher connection pool");

    // Get connection and run migrations
    let mut conn = pool.get().context("Failed to get database connection")?;

    println!("🔄 Running migrations...\n");

    // List pending migrations
    let pending = conn
        .pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("Failed to list pending migrations: {e}"))?;

    if pending.is_empty() {
        println!("✅ All migrations are already applied!");
    } else {
        println!("📋 Pending migrations:");
        for m in &pending {
            println!("   - {}", m.name());
        }
        println!();

        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("Migration error: {e}"))?;

        println!("\n✅ All migrations applied successfully!");
    }

    println!("🎉 Database is ready to use\n");

    Ok(())
}
