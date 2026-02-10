//! Migration utility for adding partial key image columns to the escrows table
//!
//! This utility applies the v0.7.0 migration for CLSAG partial signing support.
//!
//! New columns:
//!   - buyer_partial_key_image: Buyer's pKI = x_buyer * Hp(P_multisig)
//!   - vendor_partial_key_image: Vendor's pKI = x_vendor * Hp(P_multisig)
//!   - arbiter_partial_key_image: Arbiter's pKI (for disputes)
//!   - aggregated_key_image: KI_total = pKI_buyer + pKI_vendor (Edwards point sum)

use diesel::prelude::*;
use diesel::sql_query;
use dotenvy::dotenv;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 v0.7.0 Migration - Adding partial key image columns for CLSAG multisig");
    println!("{}", "=".repeat(70));

    // Load environment variables
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());

    println!("📂 Database: {}", database_url);

    // Connect directly (database is not encrypted in dev mode)
    let mut conn = SqliteConnection::establish(&database_url)?;

    // Set up basic SQLite pragmas for safety
    sql_query("PRAGMA journal_mode = WAL;").execute(&mut conn)?;
    sql_query("PRAGMA busy_timeout = 5000;").execute(&mut conn)?;

    println!("✅ Successfully connected to database");
    println!();

    // Check if columns already exist
    println!("🔍 Checking if partial key image columns already exist...");
    let check_result =
        sql_query("SELECT buyer_partial_key_image FROM escrows LIMIT 1").execute(&mut conn);

    if check_result.is_ok() {
        println!("⚠️  Columns already exist! Migration was already applied.");
        println!("   Nothing to do.");
        return Ok(());
    }

    println!("📝 Columns do not exist - proceeding with migration...");
    println!();

    // Apply migration SQL statements
    println!("🔨 Step 1/4: Adding buyer_partial_key_image column...");
    sql_query("ALTER TABLE escrows ADD COLUMN buyer_partial_key_image TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ buyer_partial_key_image added");

    println!("🔨 Step 2/4: Adding vendor_partial_key_image column...");
    sql_query("ALTER TABLE escrows ADD COLUMN vendor_partial_key_image TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ vendor_partial_key_image added");

    println!("🔨 Step 3/4: Adding arbiter_partial_key_image column...");
    sql_query("ALTER TABLE escrows ADD COLUMN arbiter_partial_key_image TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ arbiter_partial_key_image added");

    println!("🔨 Step 4/4: Adding aggregated_key_image column...");
    sql_query("ALTER TABLE escrows ADD COLUMN aggregated_key_image TEXT DEFAULT NULL")
        .execute(&mut conn)?;
    println!("   ✅ aggregated_key_image added");

    println!();
    println!("{}", "=".repeat(70));
    println!("🎉 v0.7.0 MIGRATION COMPLETED SUCCESSFULLY!");
    println!();
    println!("✅ All partial key image columns added:");
    println!("   • buyer_partial_key_image  - pKI = x_buyer * Hp(P_multisig)");
    println!("   • vendor_partial_key_image - pKI = x_vendor * Hp(P_multisig)");
    println!("   • arbiter_partial_key_image - For dispute resolution");
    println!("   • aggregated_key_image     - KI_total = sum(pKI_i)");
    println!();
    println!("🚀 CLSAG partial signing for multisig is now enabled!");
    println!("{}", "=".repeat(70));

    Ok(())
}
