//! Utility to reset escrow status for re-broadcasting
use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use diesel::sql_query;
use std::env;

diesel::table! {
    escrows (id) {
        id -> Text,
        status -> Text,
        buyer_signature -> Nullable<Text>,
        vendor_signature -> Nullable<Text>,
        buyer_partial_key_image -> Nullable<Text>,
        vendor_partial_key_image -> Nullable<Text>,
        aggregated_key_image -> Nullable<Text>,
        ring_data_json -> Nullable<Text>,
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

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: reset_escrow_status <escrow_id>");
        std::process::exit(1);
    }
    let escrow_id = &args[1];

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY not set")?;

    let manager = ConnectionManager::<SqliteConnection>::new(&database_url);
    let customizer = SqlCipherConnectionCustomizer { encryption_key };
    let pool = r2d2::Pool::builder()
        .connection_customizer(Box::new(customizer))
        .build(manager)
        .context("Failed to create pool")?;

    let mut conn = pool.get().context("Failed to get connection")?;

    // Update status and clear signatures for re-signing
    // v0.26.0: Also clear ring_data_json to prevent stale key_image issues
    diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
        .set((
            escrows::status.eq("created"), // Back to created state for monitoring
            escrows::buyer_signature.eq::<Option<String>>(None),
            escrows::vendor_signature.eq::<Option<String>>(None),
            escrows::buyer_partial_key_image.eq::<Option<String>>(None),
            escrows::vendor_partial_key_image.eq::<Option<String>>(None),
            escrows::aggregated_key_image.eq::<Option<String>>(None),
            // v0.26.0 CRITICAL: Clear ring_data_json to prevent stale key_image
            escrows::ring_data_json.eq::<Option<String>>(None),
        ))
        .execute(&mut conn)
        .context("Failed to update escrow")?;

    println!(
        "✅ Escrow {} reset to 'funded' state (signatures cleared)",
        escrow_id
    );

    // Verify
    let result: Vec<(String, String)> = escrows::table
        .select((escrows::id, escrows::status))
        .filter(escrows::id.eq(escrow_id))
        .load(&mut conn)
        .context("Failed to query")?;

    for (id, status) in result {
        println!("ID: {}", id);
        println!("Status: {}", status);
        println!("Signatures: cleared (need re-signing with updated WASM)");
    }

    Ok(())
}
