//! Utility to update commitment mask for escrow
//!
//! Usage:
//!   cargo run --package server --bin update_mask -- <escrow_id> <new_mask>
//!
//! Example:
//!   cargo run --package server --bin update_mask -- 80c90464-6f4a-42ee-8c2e-9579c56b3ce9 860664bf22cbd961d99d1949181b1c96b04ed8c25e6a713e92eafb2c3c412306

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use diesel::sql_query;

diesel::table! {
    escrows (id) {
        id -> Text,
        funding_commitment_mask -> Nullable<Text>,
    }
}

/// Custom connection customizer that sets the SQLCipher encryption key
#[derive(Debug, Clone)]
struct SqlCipherConnectionCustomizer {
    encryption_key: String,
}

impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqlCipherConnectionCustomizer {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> std::result::Result<(), diesel::r2d2::Error> {
        sql_query(format!("PRAGMA key = '{}';", self.encryption_key))
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
}

fn main() -> Result<()> {
    // Load .env
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: update_mask <escrow_id> <new_mask>");
        eprintln!("Example: update_mask 80c90464-6f4a-42ee-8c2e-9579c56b3ce9 860664bf22cbd961...");
        std::process::exit(1);
    }

    let escrow_id = &args[1];
    let new_mask = &args[2];

    // Get database config from env
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = std::env::var("DB_ENCRYPTION_KEY")
        .context("DB_ENCRYPTION_KEY environment variable not set")?;

    println!("Connecting to database: {}", db_url);
    println!("Escrow ID: {}", escrow_id);
    println!("New mask: {}", new_mask);

    // Create pool with encryption
    let manager = ConnectionManager::<SqliteConnection>::new(&db_url);
    let customizer = SqlCipherConnectionCustomizer { encryption_key };
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(customizer))
        .build(manager)
        .context("Failed to create database pool")?;

    // Get connection
    let mut conn = pool.get().context("Failed to get connection")?;

    // Update the mask
    let updated = diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
        .set(escrows::funding_commitment_mask.eq(new_mask))
        .execute(&mut conn)
        .context("Failed to update funding_commitment_mask")?;

    if updated == 0 {
        eprintln!("No rows updated - escrow ID not found: {}", escrow_id);
        std::process::exit(1);
    }

    // Verify update
    let mask: String = escrows::table
        .filter(escrows::id.eq(escrow_id))
        .select(escrows::funding_commitment_mask)
        .first::<Option<String>>(&mut conn)?
        .unwrap_or_default();

    println!("✅ Successfully updated funding_commitment_mask!");
    println!("Verified mask in DB: {}", mask);

    Ok(())
}
