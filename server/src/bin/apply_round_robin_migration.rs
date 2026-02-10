#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case
)]
//! Migration utility for adding round-robin signing columns (v0.8.0)
//!
//! This utility applies the round-robin signing migration to an encrypted SQLCipher database
//! by connecting with the same encryption key used by the server.

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use dotenvy::dotenv;
use std::env;

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Round-Robin Signing Migration (v0.8.0)");
    println!("{}", "=".repeat(70));

    // Load environment variables
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());

    println!("📂 Database: {}", database_url);

    // Get encryption key from environment (same as server uses)
    let encryption_key = env::var("DB_ENCRYPTION_KEY")
        .expect("❌ DB_ENCRYPTION_KEY not set! Set it to the same value used by the server.");

    println!("🔐 Using encryption key from DB_ENCRYPTION_KEY environment variable");

    // Create connection pool with SQLCipher
    let manager = ConnectionManager::<SqliteConnection>::new(&database_url);
    let pool = r2d2::Pool::builder().max_size(1).build(manager)?;

    let mut conn = pool.get()?;

    // Set encryption key (same as server does)
    diesel::sql_query(format!("PRAGMA key = '{}';", encryption_key)).execute(&mut conn)?;

    println!("✅ Successfully connected to encrypted database");
    println!();

    // Check if columns already exist
    println!("🔍 Checking if round-robin columns already exist...");
    let check_result =
        diesel::sql_query("SELECT partial_tx FROM escrows LIMIT 1").execute(&mut conn);

    if check_result.is_ok() {
        println!("⚠️  Round-robin columns already exist! Migration was already applied.");
        println!("   Nothing to do.");
        return Ok(());
    }

    println!("📝 Columns do not exist - proceeding with migration...");
    println!();

    // Apply migration SQL statements
    println!("🔨 Step 1/5: Adding partial_tx column...");
    diesel::sql_query("ALTER TABLE escrows ADD COLUMN partial_tx TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ partial_tx added");

    println!("🔨 Step 2/5: Adding partial_tx_initiator column...");
    diesel::sql_query("ALTER TABLE escrows ADD COLUMN partial_tx_initiator TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ partial_tx_initiator added");

    println!("🔨 Step 3/5: Adding completed_clsag column...");
    diesel::sql_query("ALTER TABLE escrows ADD COLUMN completed_clsag TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ completed_clsag added");

    println!("🔨 Step 4/5: Adding signing_started_at column...");
    diesel::sql_query("ALTER TABLE escrows ADD COLUMN signing_started_at INTEGER DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ signing_started_at added");

    println!("🔨 Step 5/5: Adding signing_phase column...");
    diesel::sql_query(
        "ALTER TABLE escrows ADD COLUMN signing_phase TEXT DEFAULT 'awaiting_initiation'",
    )
    .execute(&mut conn)?;
    println!("   ✅ signing_phase added");

    println!();
    println!("{}", "=".repeat(70));
    println!("🎉 ROUND-ROBIN MIGRATION COMPLETED SUCCESSFULLY!");
    println!();
    println!("✅ All v0.8.0 round-robin signing columns added:");
    println!("   • partial_tx - Stores PartialTx JSON from Signer 1");
    println!("   • partial_tx_initiator - Who started signing (buyer/vendor/arbiter)");
    println!("   • completed_clsag - Stores CompletedClsag JSON from Signer 2");
    println!("   • signing_started_at - Timestamp when signing was initiated");
    println!("   • signing_phase - Current phase of round-robin signing");
    println!();
    println!("🚀 Now regenerate schema.rs and rebuild the server!");
    println!("   diesel print-schema > src/schema.rs");
    println!("   cargo build --release --package server");
    println!("{}", "=".repeat(70));

    Ok(())
}
