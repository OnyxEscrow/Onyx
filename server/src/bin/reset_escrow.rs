//! Reset escrow to active status and clear Round-Robin signatures
//!
//! Usage:
//!   cargo run --package server --bin reset_escrow -- <escrow_id>

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use diesel::sql_query;

diesel::table! {
    escrows (id) {
        id -> Text,
        status -> Text,
        partial_tx -> Nullable<Text>,
        partial_tx_initiator -> Nullable<Text>,
        completed_clsag -> Nullable<Text>,
        signing_started_at -> Nullable<Integer>,
        signing_phase -> Nullable<Text>,
        buyer_partial_key_image -> Nullable<Text>,
        vendor_partial_key_image -> Nullable<Text>,
        arbiter_partial_key_image -> Nullable<Text>,
        aggregated_key_image -> Nullable<Text>,
        ring_data_json -> Nullable<Text>,
        vendor_signature -> Nullable<Text>,
        buyer_signature -> Nullable<Text>,
        vendor_signed_at -> Nullable<Integer>,
        buyer_signed_at -> Nullable<Integer>,
        // Nonce commitment fields (MuSig2)
        vendor_nonce_commitment -> Nullable<Text>,
        buyer_nonce_commitment -> Nullable<Text>,
        vendor_nonce_public -> Nullable<Text>,
        buyer_nonce_public -> Nullable<Text>,
        nonce_aggregated -> Nullable<Text>,
        first_signer_role -> Nullable<Text>,
        // v0.37.0: mu_p/mu_c for CLSAG consistency
        mu_p -> Nullable<Text>,
        mu_c -> Nullable<Text>,
        // v0.41.0: first_signer_had_r_agg for TOCTOU fix
        first_signer_had_r_agg -> Nullable<Integer>,
    }
}

diesel::table! {
    frost_signing_state (escrow_id) {
        escrow_id -> Nullable<Text>,
        status -> Text,
        buyer_nonce_commitment -> Nullable<Text>,
        buyer_r_public -> Nullable<Text>,
        buyer_r_prime_public -> Nullable<Text>,
        vendor_nonce_commitment -> Nullable<Text>,
        vendor_r_public -> Nullable<Text>,
        vendor_r_prime_public -> Nullable<Text>,
        aggregated_r -> Nullable<Text>,
        aggregated_r_prime -> Nullable<Text>,
        buyer_partial_submitted -> Nullable<Bool>,
        vendor_partial_submitted -> Nullable<Bool>,
        arbiter_partial_submitted -> Nullable<Bool>,
        aggregated_key_image -> Nullable<Text>,
        final_clsag_json -> Nullable<Text>,
        broadcasted_tx_hash -> Nullable<Text>,
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
    let escrow_id = if args.len() >= 2 {
        &args[1]
    } else {
        "51cbf336-6c09-4f94-a64f-ed4d25a91dba"
    };

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default();

    println!("Connecting to database: {}", database_url);
    println!("Resetting escrow: {}", escrow_id);

    let manager = ConnectionManager::<SqliteConnection>::new(&database_url);

    let pool = if encryption_key.is_empty() {
        r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .context("Failed to create pool")?
    } else {
        r2d2::Pool::builder()
            .max_size(1)
            .connection_customizer(Box::new(SqlCipherConnectionCustomizer {
                encryption_key: encryption_key.clone(),
            }))
            .build(manager)
            .context("Failed to create encrypted pool")?
    };

    let mut conn = pool.get().context("Failed to get connection")?;

    // v0.23.0: CLEAR ring_data_json - it contains key_image and tx_prefix_hash
    // which are session-specific. The tx_pubkey will be re-fetched from blockchain
    // during prepare_sign. Without clearing, key_image mismatch causes CLSAG failures.
    let updated = diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
        .set((
            escrows::status.eq("active"),
            escrows::partial_tx.eq::<Option<String>>(None),
            escrows::partial_tx_initiator.eq::<Option<String>>(None),
            escrows::completed_clsag.eq::<Option<String>>(None),
            escrows::signing_started_at.eq::<Option<i32>>(None),
            escrows::signing_phase.eq::<Option<String>>(None),
            escrows::buyer_partial_key_image.eq::<Option<String>>(None),
            escrows::vendor_partial_key_image.eq::<Option<String>>(None),
            escrows::arbiter_partial_key_image.eq::<Option<String>>(None),
            escrows::aggregated_key_image.eq::<Option<String>>(None),
            // v0.23.0: CLEAR ring_data_json (contains stale key_image/tx_prefix_hash)
            escrows::ring_data_json.eq::<Option<String>>(None),
            escrows::vendor_signature.eq::<Option<String>>(None),
            escrows::buyer_signature.eq::<Option<String>>(None),
            escrows::vendor_signed_at.eq::<Option<i32>>(None),
            escrows::buyer_signed_at.eq::<Option<i32>>(None),
            // MuSig2 nonce fields - CRITICAL: must clear to allow new nonce generation
            escrows::vendor_nonce_commitment.eq::<Option<String>>(None),
            escrows::buyer_nonce_commitment.eq::<Option<String>>(None),
            escrows::vendor_nonce_public.eq::<Option<String>>(None),
            escrows::buyer_nonce_public.eq::<Option<String>>(None),
            escrows::nonce_aggregated.eq::<Option<String>>(None),
            escrows::first_signer_role.eq::<Option<String>>(None),
            // v0.37.0: Clear mu_p/mu_c - CRITICAL for fresh CLSAG signing
            escrows::mu_p.eq::<Option<String>>(None),
            escrows::mu_c.eq::<Option<String>>(None),
            // v0.41.0: Clear first_signer_had_r_agg
            escrows::first_signer_had_r_agg.eq::<Option<i32>>(None),
        ))
        .execute(&mut conn)
        .context("Failed to update escrow")?;

    if updated > 0 {
        println!("✅ Escrow reset to 'active' (ready for new signing flow)");
        println!("   - status: active");
        println!("   - signing_phase: NULL");
        println!("   - partial_tx: NULL");
        println!("   - completed_clsag: NULL");
        println!("   - buyer_partial_key_image: NULL");
        println!("   - vendor_partial_key_image: NULL");
        println!("   - arbiter_partial_key_image: NULL");
        println!("   - aggregated_key_image: NULL");
        println!("   - ring_data_json: CLEARED (v0.23.0 - will be rebuilt in prepare_sign)");
        println!("   - vendor_signature: NULL");
        println!("   - buyer_signature: NULL");
        println!("   - vendor_signed_at: NULL");
        println!("   - buyer_signed_at: NULL");
        println!("   - vendor_nonce_commitment: NULL (fresh nonces required)");
        println!("   - buyer_nonce_commitment: NULL");
        println!("   - vendor_nonce_public: NULL");
        println!("   - buyer_nonce_public: NULL");
        println!("   - nonce_aggregated: NULL");
        println!("   - first_signer_role: NULL");
        println!("   - mu_p: NULL (v0.37.0 - fresh CLSAG mu computation)");
        println!("   - mu_c: NULL (v0.37.0 - fresh CLSAG mu computation)");
        println!("   - first_signer_had_r_agg: NULL (v0.41.0)");

        // Also delete frost_signing_state row (will be recreated on next prepare_sign)
        let fss_deleted = diesel::delete(
            frost_signing_state::table.filter(frost_signing_state::escrow_id.eq(escrow_id)),
        )
        .execute(&mut conn)
        .context("Failed to delete frost_signing_state")?;

        if fss_deleted > 0 {
            println!("✅ frost_signing_state row deleted (will be recreated on prepare_sign)");
        } else {
            println!(
                "⚠️ No frost_signing_state row found for escrow_id: {}",
                escrow_id
            );
        }
    } else {
        println!("⚠️ No escrow found with ID: {}", escrow_id);
    }

    Ok(())
}
