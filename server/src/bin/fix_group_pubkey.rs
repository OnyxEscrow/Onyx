//! Fix frost_group_pubkey mismatch bug
//!
//! The frost_group_pubkey stored in DB doesn't match the spend pubkey
//! encoded in the multisig address. This binary fixes it.

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use std::env;

#[derive(Debug, Clone)]
struct SqlCipherConnectionCustomizer {
    encryption_key: String,
}

impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqlCipherConnectionCustomizer {
    fn on_acquire(
        &self,
        conn: &mut SqliteConnection,
    ) -> std::result::Result<(), diesel::r2d2::Error> {
        diesel::sql_query(format!("PRAGMA key = '{}';", self.encryption_key))
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
}

fn establish_connection() -> Result<r2d2::PooledConnection<ConnectionManager<SqliteConnection>>> {
    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY not set")?;

    let manager = ConnectionManager::<SqliteConnection>::new(&database_url);
    let customizer = SqlCipherConnectionCustomizer { encryption_key };
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(customizer))
        .build(manager)?;

    pool.get().context("Failed to get database connection")
}

/// Decode Monero base58 address to extract spend pubkey
fn decode_monero_address(address: &str) -> Result<[u8; 32]> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    fn b58_decode_block(block: &str, size: usize) -> Result<Vec<u8>> {
        let mut n: u128 = 0;
        for c in block.chars() {
            let idx = ALPHABET
                .iter()
                .position(|&x| x == c as u8)
                .ok_or_else(|| anyhow::anyhow!("Invalid base58 character: {}", c))?;
            n = n * 58 + idx as u128;
        }
        let bytes = n.to_be_bytes();
        // Take the last `size` bytes
        Ok(bytes[16 - size..].to_vec())
    }

    // Monero address: 8 blocks of 11 chars (8 bytes each) + 1 block of 7 chars (5 bytes)
    let mut result = Vec::new();

    for i in 0..8 {
        let block = &address[i * 11..(i + 1) * 11];
        result.extend(b58_decode_block(block, 8)?);
    }

    let last_block = &address[88..];
    result.extend(b58_decode_block(last_block, 5)?);

    if result.len() != 69 {
        anyhow::bail!("Invalid address length: {} (expected 69)", result.len());
    }

    // Spend pubkey is bytes 1-33 (after network byte)
    let mut spend_pubkey = [0u8; 32];
    spend_pubkey.copy_from_slice(&result[1..33]);

    Ok(spend_pubkey)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <escrow_id> [--dry-run]", args[0]);
        println!(
            "\nFixes frost_group_pubkey by extracting correct spend pubkey from multisig_address"
        );
        return Ok(());
    }

    let escrow_id = &args[1];
    let dry_run = args.get(2).map(|s| s == "--dry-run").unwrap_or(false);

    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║     FIX frost_group_pubkey MISMATCH                                      ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝\n");

    if dry_run {
        println!("⚠️  DRY RUN MODE - No changes will be made\n");
    }

    // Connect to DB
    let mut conn = establish_connection()?;

    // Get current values
    #[derive(diesel::QueryableByName, Debug)]
    struct EscrowRow {
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        multisig_address: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        frost_group_pubkey: Option<String>,
    }

    let query = format!(
        "SELECT multisig_address, frost_group_pubkey FROM escrows WHERE id = '{}'",
        escrow_id
    );

    let rows: Vec<EscrowRow> = diesel::sql_query(&query)
        .load(&mut *conn)
        .context("Failed to query escrow")?;

    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Escrow not found: {}", escrow_id))?;

    let address = row
        .multisig_address
        .ok_or_else(|| anyhow::anyhow!("No multisig_address set"))?;

    let current_pubkey = row
        .frost_group_pubkey
        .unwrap_or_else(|| "NOT SET".to_string());

    println!("Escrow ID: {}", escrow_id);
    println!(
        "Multisig Address: {}...{}",
        &address[..12],
        &address[address.len() - 8..]
    );
    println!();
    println!("Current frost_group_pubkey: {}", current_pubkey);

    // Decode address to get correct spend pubkey
    let correct_pubkey = decode_monero_address(&address)?;
    let correct_pubkey_hex = hex::encode(correct_pubkey);

    println!("Correct spend pubkey:       {}", correct_pubkey_hex);
    println!();

    if current_pubkey == correct_pubkey_hex {
        println!("✅ frost_group_pubkey is already correct! No fix needed.");
        return Ok(());
    }

    println!("❌ MISMATCH DETECTED!");
    println!();
    println!("Difference:");
    println!("  Current: {}", current_pubkey);
    println!("  Correct: {}", correct_pubkey_hex);

    // Find where they diverge
    let current_bytes = current_pubkey.as_bytes();
    let correct_bytes = correct_pubkey_hex.as_bytes();
    let mut diverge_pos = 0;
    for (i, (a, b)) in current_bytes.iter().zip(correct_bytes.iter()).enumerate() {
        if a != b {
            diverge_pos = i;
            break;
        }
    }
    println!(
        "  Diverge at position: {} (first {} chars match)",
        diverge_pos, diverge_pos
    );
    println!();

    if dry_run {
        println!("🔍 DRY RUN: Would update frost_group_pubkey to correct value");
        println!("   Run without --dry-run to apply fix");
        return Ok(());
    }

    // Apply fix
    println!("🔧 Applying fix...");

    let update_query = format!(
        "UPDATE escrows SET frost_group_pubkey = '{}' WHERE id = '{}'",
        correct_pubkey_hex, escrow_id
    );

    diesel::sql_query(&update_query)
        .execute(&mut *conn)
        .context("Failed to update frost_group_pubkey")?;

    println!("✅ frost_group_pubkey FIXED!");
    println!();
    println!("New value: {}", correct_pubkey_hex);
    println!();
    println!("You can now rerun the offline broadcast test.");

    Ok(())
}
