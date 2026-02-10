#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case
)]
//! Manual migration utility for applying Phase 1 temp wallet columns
//!
//! This utility applies the missing migration to an encrypted SQLCipher database
//! by connecting with the same encryption key used by the server.

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use dotenvy::dotenv;
use std::env;

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Phase 1 Migration Utility - Adding temp wallet columns");
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
    println!("🔍 Checking if columns already exist...");
    let check_result =
        diesel::sql_query("SELECT buyer_temp_wallet_id FROM escrows LIMIT 1").execute(&mut conn);

    if check_result.is_ok() {
        println!("⚠️  Columns already exist! Migration was already applied.");
        println!("   Nothing to do.");
        return Ok(());
    }

    println!("📝 Columns do not exist - proceeding with migration...");
    println!();

    // Apply migration SQL statements
    println!("🔨 Step 1/4: Adding buyer_temp_wallet_id column...");
    diesel::sql_query("ALTER TABLE escrows ADD COLUMN buyer_temp_wallet_id TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ buyer_temp_wallet_id added");

    println!("🔨 Step 2/4: Adding vendor_temp_wallet_id column...");
    diesel::sql_query("ALTER TABLE escrows ADD COLUMN vendor_temp_wallet_id TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ vendor_temp_wallet_id added");

    println!("🔨 Step 3/4: Adding arbiter_temp_wallet_id column...");
    diesel::sql_query("ALTER TABLE escrows ADD COLUMN arbiter_temp_wallet_id TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ arbiter_temp_wallet_id added");

    println!("🔨 Step 4/4: Creating indexes for performance...");

    diesel::sql_query(
        "CREATE INDEX idx_escrows_buyer_temp_wallet ON escrows(buyer_temp_wallet_id)",
    )
    .execute(&mut conn)?;
    println!("   ✅ idx_escrows_buyer_temp_wallet created");

    diesel::sql_query(
        "CREATE INDEX idx_escrows_vendor_temp_wallet ON escrows(vendor_temp_wallet_id)",
    )
    .execute(&mut conn)?;
    println!("   ✅ idx_escrows_vendor_temp_wallet created");

    diesel::sql_query(
        "CREATE INDEX idx_escrows_arbiter_temp_wallet ON escrows(arbiter_temp_wallet_id)",
    )
    .execute(&mut conn)?;
    println!("   ✅ idx_escrows_arbiter_temp_wallet created");

    println!();
    println!("{}", "=".repeat(70));
    println!("🎉 MIGRATION COMPLETED SUCCESSFULLY!");
    println!();
    println!("✅ All Phase 1 temp wallet columns added:");
    println!("   • buyer_temp_wallet_id");
    println!("   • vendor_temp_wallet_id");
    println!("   • arbiter_temp_wallet_id");
    println!();
    println!("✅ All indexes created for performance");
    println!();
    println!("🚀 You can now restart the server and escrow initialization will work!");
    println!("{}", "=".repeat(70));

    Ok(())
}
