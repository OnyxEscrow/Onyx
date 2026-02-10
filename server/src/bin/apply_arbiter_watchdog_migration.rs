//! Migration utility for Arbiter Watchdog fields
//!
//! This utility applies the arbiter watchdog migration to an encrypted SQLCipher database
//! by connecting with the same encryption key used by the server.

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use dotenvy::dotenv;
use std::env;

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Arbiter Watchdog Migration Utility");
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
    println!("🔍 Checking if arbiter watchdog columns already exist...");
    let check_result =
        diesel::sql_query("SELECT buyer_release_requested FROM escrows LIMIT 1").execute(&mut conn);

    if check_result.is_ok() {
        println!("⚠️  Columns already exist! Migration was already applied.");
        println!("   Nothing to do.");
        return Ok(());
    }

    println!("📝 Columns do not exist - proceeding with migration...");
    println!();

    // Apply migration SQL statements
    println!("🔨 Step 1/6: Adding buyer_release_requested column...");
    diesel::sql_query(
        "ALTER TABLE escrows ADD COLUMN buyer_release_requested BOOLEAN DEFAULT FALSE NOT NULL",
    )
    .execute(&mut conn)?;
    println!("   ✅ buyer_release_requested added");

    println!("🔨 Step 2/6: Adding vendor_refund_requested column...");
    diesel::sql_query(
        "ALTER TABLE escrows ADD COLUMN vendor_refund_requested BOOLEAN DEFAULT FALSE NOT NULL",
    )
    .execute(&mut conn)?;
    println!("   ✅ vendor_refund_requested added");

    println!("🔨 Step 3/6: Adding arbiter_auto_signed column...");
    diesel::sql_query(
        "ALTER TABLE escrows ADD COLUMN arbiter_auto_signed BOOLEAN DEFAULT FALSE NOT NULL",
    )
    .execute(&mut conn)?;
    println!("   ✅ arbiter_auto_signed added");

    println!("🔨 Step 4/6: Adding arbiter_auto_signed_at column...");
    diesel::sql_query("ALTER TABLE escrows ADD COLUMN arbiter_auto_signed_at TIMESTAMP NULL")
        .execute(&mut conn)?;
    println!("   ✅ arbiter_auto_signed_at added");

    println!("🔨 Step 5/6: Adding escalated_to_human column...");
    diesel::sql_query(
        "ALTER TABLE escrows ADD COLUMN escalated_to_human BOOLEAN DEFAULT FALSE NOT NULL",
    )
    .execute(&mut conn)?;
    println!("   ✅ escalated_to_human added");

    println!("🔨 Step 6/6: Adding arbiter_frost_partial_sig column...");
    diesel::sql_query("ALTER TABLE escrows ADD COLUMN arbiter_frost_partial_sig TEXT NULL")
        .execute(&mut conn)?;
    println!("   ✅ arbiter_frost_partial_sig added");

    println!();
    println!("{}", "=".repeat(70));
    println!("🎉 ARBITER WATCHDOG MIGRATION COMPLETED SUCCESSFULLY!");
    println!();
    println!("✅ All arbiter watchdog columns added:");
    println!("   • buyer_release_requested (BOOLEAN)");
    println!("   • vendor_refund_requested (BOOLEAN)");
    println!("   • arbiter_auto_signed (BOOLEAN)");
    println!("   • arbiter_auto_signed_at (TIMESTAMP)");
    println!("   • escalated_to_human (BOOLEAN)");
    println!("   • arbiter_frost_partial_sig (TEXT)");
    println!();
    println!("🚀 You can now run the arbiter_watchdog daemon!");
    println!("   cargo run --bin arbiter_watchdog");
    println!("{}", "=".repeat(70));

    Ok(())
}
