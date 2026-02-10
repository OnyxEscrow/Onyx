//! Fix escrow data - update output_index, amount, and mask
//!
//! Usage:
//!   cargo run --package server --bin fix_escrow -- <escrow_id>

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use diesel::sql_query;

diesel::table! {
    escrows (id) {
        id -> Text,
        funding_output_index -> Nullable<Integer>,
        funding_commitment_mask -> Nullable<Text>,
        amount -> BigInt,
    }
}

#[derive(Debug, Clone)]
struct SqlCipherConnectionCustomizer {
    encryption_key: String,
}

impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqlCipherConnectionCustomizer {
    fn on_acquire(
        &self,
        conn: &mut SqliteConnection,
    ) -> std::result::Result<(), diesel::r2d2::Error> {
        sql_query(format!("PRAGMA key = '{}';", self.encryption_key))
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: fix_escrow <escrow_id>");
        std::process::exit(1);
    }

    let escrow_id = &args[1];

    // Correct values discovered through verify_commitment tool analysis
    // For escrow 0f41a60e-9d67-4f13-9efa-cceb19f16dee:
    // - Output index: 1 (NOT 0 as was stored)
    // - Global index: 9647632 (correct)
    // - Mask: derived from tx_pub_key c3725cf1289a79e3034cc7b9024ffcce704c347866c923f3b632ae6c3d28b5ce at output_index 1
    let correct_output_index = 1i32;
    let correct_amount = 3000000000i64; // 0.003 XMR
    let correct_mask = "408126310ce0de53c918bbb6a993897eb92f753b0828fe6430d30dabcf1fb904";

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = std::env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY not set")?;

    println!("Connecting to database: {}", db_url);
    println!("Escrow ID: {}", escrow_id);
    println!();
    println!("Will update to:");
    println!("  funding_output_index: {}", correct_output_index);
    println!("  amount: {} (0.003 XMR)", correct_amount);
    println!("  funding_commitment_mask: {}", correct_mask);

    let manager = ConnectionManager::<SqliteConnection>::new(&db_url);
    let customizer = SqlCipherConnectionCustomizer { encryption_key };
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(customizer))
        .build(manager)?;

    let mut conn = pool.get()?;

    // Update all three fields
    let updated = diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
        .set((
            escrows::funding_output_index.eq(correct_output_index),
            escrows::funding_commitment_mask.eq(correct_mask),
            escrows::amount.eq(correct_amount),
        ))
        .execute(&mut conn)
        .context("Failed to update escrow")?;

    if updated == 0 {
        eprintln!("No rows updated - escrow ID not found: {}", escrow_id);
        std::process::exit(1);
    }

    // Verify update
    let result: Vec<(String, Option<i32>, Option<String>, i64)> = escrows::table
        .filter(escrows::id.eq(escrow_id))
        .select((
            escrows::id,
            escrows::funding_output_index,
            escrows::funding_commitment_mask,
            escrows::amount,
        ))
        .load(&mut conn)?;

    if let Some((id, idx, mask, amt)) = result.into_iter().next() {
        println!();
        println!("✅ Successfully updated escrow!");
        println!("Verified values:");
        println!("  id: {}", id);
        println!("  funding_output_index: {:?}", idx);
        println!("  funding_commitment_mask: {:?}", mask);
        println!("  amount: {} ({} XMR)", amt, amt as f64 / 1e12);
    }

    Ok(())
}
