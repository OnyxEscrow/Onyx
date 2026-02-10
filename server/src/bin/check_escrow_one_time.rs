//! Quick check of one_time_pubkey for escrow
//!
//! Usage: cargo run --release --bin check_escrow_one_time

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use diesel::sql_query;

diesel::table! {
    escrows (id) {
        id -> Text,
        funding_output_pubkey -> Nullable<Text>,
        funding_tx_pubkey -> Nullable<Text>,
        funding_output_index -> Nullable<Integer>,
        frost_group_pubkey -> Nullable<Text>,
        multisig_view_key -> Nullable<Text>,
        frost_enabled -> Nullable<Bool>,
    }
}

#[derive(Debug, Clone)]
struct SqlCipherConnectionCustomizer {
    encryption_key: String,
}

impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqlCipherConnectionCustomizer {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> std::result::Result<(), diesel::r2d2::Error> {
        sql_query(format!("PRAGMA key = '{}'", self.encryption_key))
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let escrow_id = std::env::args().nth(1).unwrap_or_else(|| "ef57f177-f873-40c3-a175-4ab87c195ad8".to_string());
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default();

    let manager = ConnectionManager::<SqliteConnection>::new(&database_url);

    let pool = if encryption_key.is_empty() {
        r2d2::Pool::builder().max_size(1).build(manager).context("Failed to create pool")?
    } else {
        r2d2::Pool::builder()
            .max_size(1)
            .connection_customizer(Box::new(SqlCipherConnectionCustomizer { encryption_key }))
            .build(manager)
            .context("Failed to create encrypted pool")?
    };

    let mut conn = pool.get().context("Failed to get connection")?;

    #[derive(Queryable, Debug)]
    struct EscrowData {
        id: String,
        funding_output_pubkey: Option<String>,
        funding_tx_pubkey: Option<String>,
        funding_output_index: Option<i32>,
        frost_group_pubkey: Option<String>,
        multisig_view_key: Option<String>,
        frost_enabled: Option<bool>,
    }

    let escrow: EscrowData = escrows::table
        .filter(escrows::id.eq(&escrow_id))
        .first(&mut conn)
        .context("Failed to find escrow")?;

    println!("=== ESCROW ONE-TIME PUBKEY CHECK ===\n");
    println!("Escrow ID: {}", escrow.id);
    println!("FROST Enabled: {:?}", escrow.frost_enabled);
    println!("\nFROST Group Pubkey: {:?}", escrow.frost_group_pubkey);
    println!("Multisig View Key: {:?}", escrow.multisig_view_key);
    println!("\nFunding TX Pubkey (R): {:?}", escrow.funding_tx_pubkey);
    println!("Funding Output Index: {:?}", escrow.funding_output_index);
    println!("\n>>> funding_output_pubkey (one_time_pubkey):");
    println!("    {:?}", escrow.funding_output_pubkey);

    // Expected from validation script (with output_index=1):
    // one_time_pubkey: ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0
    println!("\n>>> Expected (from validation script):");
    println!("    ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0");

    if let Some(ref pubkey) = escrow.funding_output_pubkey {
        if pubkey == "ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0" {
            println!("\n✅ funding_output_pubkey MATCHES expected value!");
        } else {
            println!("\n❌ MISMATCH! DB value differs from expected.");
        }
    } else {
        println!("\n⚠️  funding_output_pubkey is NULL - need to check blockchain_monitor");
    }

    Ok(())
}
