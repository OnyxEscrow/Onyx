//! Migration utility for applying API keys table
//!
//! This utility applies the api_keys migration to an encrypted SQLCipher database
//! by connecting with the same encryption key used by the server.
//!
//! Usage:
//!   DB_ENCRYPTION_KEY=xxx cargo run --bin apply_api_keys_migration

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use dotenvy::dotenv;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("API Keys Migration Utility");
    println!("{}", "=".repeat(70));

    // Load environment variables
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());

    println!("Database: {database_url}");

    // Get encryption key from environment
    let encryption_key = env::var("DB_ENCRYPTION_KEY")
        .expect("DB_ENCRYPTION_KEY not set! Set it to the same value used by the server.");

    println!("Using encryption key from DB_ENCRYPTION_KEY environment variable");

    // Create connection pool with SQLCipher
    let manager = ConnectionManager::<SqliteConnection>::new(&database_url);
    let pool = r2d2::Pool::builder().max_size(1).build(manager)?;

    let mut conn = pool.get()?;

    // Set encryption key
    diesel::sql_query(format!("PRAGMA key = '{encryption_key}';")).execute(&mut conn)?;

    println!("Successfully connected to encrypted database");
    println!();

    // Check if table already exists
    println!("Checking if api_keys table already exists...");
    let check_result = diesel::sql_query("SELECT id FROM api_keys LIMIT 1").execute(&mut conn);

    if check_result.is_ok() {
        println!("api_keys table already exists! Migration was already applied.");
        println!("Nothing to do.");
        return Ok(());
    }

    println!("Table does not exist - proceeding with migration...");
    println!();

    // Apply migration SQL
    println!("Step 1/4: Creating api_keys table...");
    diesel::sql_query(
        r#"
        CREATE TABLE api_keys (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'enterprise')),
            rate_limit_override INTEGER,
            is_active INTEGER NOT NULL DEFAULT 1,
            expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_used_at TEXT,
            total_requests INTEGER NOT NULL DEFAULT 0,
            metadata TEXT
        )
        "#,
    )
    .execute(&mut conn)?;
    println!("   api_keys table created");

    println!("Step 2/4: Creating index on key_hash...");
    diesel::sql_query("CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash)")
        .execute(&mut conn)?;
    println!("   idx_api_keys_key_hash created");

    println!("Step 3/4: Creating index on user_id...");
    diesel::sql_query("CREATE INDEX idx_api_keys_user_id ON api_keys(user_id)")
        .execute(&mut conn)?;
    println!("   idx_api_keys_user_id created");

    println!("Step 4/4: Creating index on is_active...");
    diesel::sql_query(
        "CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = 1",
    )
    .execute(&mut conn)?;
    println!("   idx_api_keys_active created");

    println!();
    println!("{}", "=".repeat(70));
    println!("MIGRATION COMPLETED SUCCESSFULLY!");
    println!();
    println!("api_keys table created with:");
    println!("   - SHA256 key hash storage (never plaintext)");
    println!("   - Tiered rate limiting (free/pro/enterprise)");
    println!("   - Expiration support");
    println!("   - Usage tracking");
    println!();
    println!("You can now restart the server and use API key authentication!");
    println!("{}", "=".repeat(70));

    Ok(())
}
