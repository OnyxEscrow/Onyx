//! Apply restore migration directly via SQLCipher connection
//! Handles "duplicate column" errors gracefully

use anyhow::{Context, Result};
use diesel::prelude::*;
use std::env;

fn main() -> Result<()> {
    println!("Restore Migration Tool - Adding missing escrow columns");
    println!("=======================================================\n");

    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let encryption_key = env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY must be set")?;

    let pool = server::db::create_pool(&database_url, &encryption_key)
        .context("Failed to create connection pool")?;

    let mut conn = pool.get().context("Failed to get connection")?;

    let alter_statements = vec![
        "ALTER TABLE escrows ADD COLUMN funding_output_pubkey TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN funding_tx_pubkey TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN vendor_nonce_commitment TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN buyer_nonce_commitment TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN vendor_nonce_public TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN buyer_nonce_public TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN nonce_aggregated TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN first_signer_role TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN mu_p TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN mu_c TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN first_signer_had_r_agg INTEGER DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN multisig_txset TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN signing_round INTEGER DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN current_signer_id TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN partial_signed_txset TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN signing_initiated_at TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN broadcast_tx_hash TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN evidence_count INTEGER DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN auto_escalated_at TIMESTAMP DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN escalation_reason TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN dispute_signing_pair TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN buyer_release_requested BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE escrows ADD COLUMN vendor_refund_requested BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE escrows ADD COLUMN arbiter_auto_signed BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE escrows ADD COLUMN arbiter_auto_signed_at TIMESTAMP DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN escalated_to_human BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE escrows ADD COLUMN arbiter_frost_partial_sig TEXT DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN shipped_at TIMESTAMP DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN auto_release_at TIMESTAMP DEFAULT NULL",
        "ALTER TABLE escrows ADD COLUMN shipping_tracking TEXT DEFAULT NULL",
        // Missing from original restore: frost_dkg_state column
        "ALTER TABLE escrows ADD COLUMN frost_dkg_state TEXT DEFAULT 'pending'",
    ];

    // Also create frost_dkg_state table if missing
    let create_frost_dkg = r#"
        CREATE TABLE IF NOT EXISTS frost_dkg_state (
            escrow_id TEXT PRIMARY KEY NOT NULL REFERENCES escrows(id),
            buyer_round1_package TEXT,
            vendor_round1_package TEXT,
            arbiter_round1_package TEXT,
            round1_complete BOOLEAN NOT NULL DEFAULT FALSE,
            buyer_to_vendor_round2 TEXT,
            buyer_to_arbiter_round2 TEXT,
            vendor_to_buyer_round2 TEXT,
            vendor_to_arbiter_round2 TEXT,
            arbiter_to_buyer_round2 TEXT,
            arbiter_to_vendor_round2 TEXT,
            round2_complete BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    "#;

    match diesel::sql_query(create_frost_dkg).execute(&mut conn) {
        Ok(_) => println!("\n  + frost_dkg_state table created"),
        Err(e) => {
            if e.to_string().contains("already exists") {
                println!("\n  = frost_dkg_state (already exists)");
            } else {
                println!("\n  ! frost_dkg_state: {}", e);
            }
        }
    }

    // Also create frost_signing_state table if missing
    let create_frost = r#"
        CREATE TABLE IF NOT EXISTS frost_signing_state (
            escrow_id TEXT PRIMARY KEY,
            tx_prefix_hash TEXT,
            clsag_message_hash TEXT,
            ring_data_json TEXT,
            pseudo_out TEXT,
            recipient_address TEXT,
            amount_atomic TEXT,
            buyer_nonce_commitment TEXT,
            buyer_r_public TEXT,
            buyer_r_prime_public TEXT,
            vendor_nonce_commitment TEXT,
            vendor_r_public TEXT,
            vendor_r_prime_public TEXT,
            aggregated_r TEXT,
            aggregated_r_prime TEXT,
            buyer_partial_submitted BOOLEAN DEFAULT FALSE,
            vendor_partial_submitted BOOLEAN DEFAULT FALSE,
            arbiter_partial_submitted BOOLEAN DEFAULT FALSE,
            aggregated_key_image TEXT,
            final_clsag_json TEXT,
            broadcasted_tx_hash TEXT,
            status TEXT NOT NULL DEFAULT 'initialized',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    "#;

    let mut added = 0;
    let mut skipped = 0;

    for stmt in &alter_statements {
        let col_name = stmt
            .split("ADD COLUMN ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("unknown");

        match diesel::sql_query(*stmt).execute(&mut conn) {
            Ok(_) => {
                println!("  + {}", col_name);
                added += 1;
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("duplicate column") {
                    println!("  = {} (already exists)", col_name);
                    skipped += 1;
                } else {
                    println!("  ! {} ERROR: {}", col_name, err_str);
                }
            }
        }
    }

    // Create frost_signing_state
    match diesel::sql_query(create_frost).execute(&mut conn) {
        Ok(_) => println!("\n  + frost_signing_state table created"),
        Err(e) => {
            if e.to_string().contains("already exists") {
                println!("\n  = frost_signing_state (already exists)");
            } else {
                println!("\n  + frost_signing_state: {}", e);
            }
        }
    }

    // Add new columns to frost_signing_state for real TX build (v0.75.0)
    let frost_signing_alters = vec![
        "ALTER TABLE frost_signing_state ADD COLUMN bulletproof_bytes TEXT DEFAULT NULL",
        "ALTER TABLE frost_signing_state ADD COLUMN pseudo_out_hex TEXT DEFAULT NULL",
        "ALTER TABLE frost_signing_state ADD COLUMN tx_secret_key TEXT DEFAULT NULL",
        "ALTER TABLE frost_signing_state ADD COLUMN ring_indices_json TEXT DEFAULT NULL",
    ];

    for stmt in &frost_signing_alters {
        let col_name = stmt
            .split("ADD COLUMN ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("unknown");

        match diesel::sql_query(*stmt).execute(&mut conn) {
            Ok(_) => {
                println!("  + frost_signing_state.{}", col_name);
                added += 1;
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("duplicate column") {
                    println!("  = frost_signing_state.{} (already exists)", col_name);
                    skipped += 1;
                } else {
                    println!("  ! frost_signing_state.{} ERROR: {}", col_name, err_str);
                }
            }
        }
    }

    println!("\nResult: {} added, {} already existed", added, skipped);
    println!("Done.\n");

    Ok(())
}
