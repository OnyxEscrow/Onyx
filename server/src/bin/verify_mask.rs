#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case
)]
//! Verify funding mask and pseudo_out for any escrow
//! Usage: cargo run --release --bin verify_mask <escrow_id>

use anyhow::{Context, Result};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use diesel::sql_query;
use std::env;

// Diesel schema
diesel::table! {
    escrows (id) {
        id -> Text,
        status -> Text,
        amount -> BigInt,
        funding_commitment_mask -> Nullable<Text>,
        ring_data_json -> Nullable<Text>,
        vendor_signature -> Nullable<Text>,
    }
}

// SqlCipher connection customizer
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

// H generator point (Monero's alternate base point for amount commitments)
const H_POINT_HEX: &str = "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94";

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let args: Vec<String> = env::args().collect();
    let escrow_id = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("1bacd695-7587-418d-94d3-9373065145cd");

    println!("=== Mask Verification for Escrow {escrow_id} ===\n");

    // Connect to encrypted database
    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY not set")?;

    let manager = ConnectionManager::<SqliteConnection>::new(&db_url);
    let customizer = SqlCipherConnectionCustomizer { encryption_key };
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(customizer))
        .build(manager)?;

    let mut conn = pool.get()?;

    // Query escrow
    use self::escrows::dsl::*;
    let escrow: (
        String,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = escrows
        .filter(id.like(format!("{escrow_id}%")))
        .select((
            id,
            status,
            amount,
            funding_commitment_mask,
            ring_data_json,
            vendor_signature,
        ))
        .first(&mut conn)
        .context("Escrow not found")?;

    println!("Found escrow: {}", escrow.0);
    println!("Status: {}", escrow.1);
    println!(
        "Amount: {} atomic ({} XMR)",
        escrow.2,
        escrow.2 as f64 / 1e12
    );

    let funding_mask_hex = escrow.3.as_ref().context("No funding_commitment_mask")?;
    println!("\nFunding Mask: {funding_mask_hex}");

    // Parse ring_data_json to get ring_commitments and signer_index
    let ring_data: serde_json::Value =
        serde_json::from_str(escrow.4.as_ref().context("No ring_data_json")?)?;

    let signer_index = ring_data["signer_index"]
        .as_u64()
        .context("No signer_index")? as usize;
    let ring_commitments = ring_data["ring_commitments"]
        .as_array()
        .context("No ring_commitments")?;
    let c_signer = ring_commitments[signer_index]
        .as_str()
        .context("No C[signer]")?;
    let pseudo_out_ring = ring_data["pseudo_out"].as_str();

    println!("Signer Index: {signer_index}");
    println!("C[{signer_index}] (signer commitment): {c_signer}");

    // Parse vendor signature to get pseudo_out
    let vendor_sig: serde_json::Value =
        serde_json::from_str(escrow.5.as_ref().context("No vendor_signature")?)?;
    let pseudo_out_hex = vendor_sig["pseudo_out"]
        .as_str()
        .context("No pseudo_out in signature")?;
    println!("Pseudo_out (from signature): {pseudo_out_hex}");
    if let Some(p) = pseudo_out_ring {
        println!("Pseudo_out (from ring_data):  {p}");
        if p != pseudo_out_hex {
            println!("  ⚠️  MISMATCH between ring_data and signature!");
        }
    }

    println!();

    // Parse H point
    let h_bytes: [u8; 32] = hex::decode(H_POINT_HEX)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid H point length"))?;
    let h_point = CompressedEdwardsY(h_bytes)
        .decompress()
        .context("Invalid H point")?;

    // Parse funding_mask
    let mask_bytes: [u8; 32] = hex::decode(funding_mask_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid mask length"))?;
    let funding_mask = Scalar::from_canonical_bytes(mask_bytes)
        .into_option()
        .context("Invalid mask scalar")?;

    // Compute expected C[signer] = funding_mask * G + amount * H
    let escrow_amount = escrow.2 as u64;
    let amount_scalar = Scalar::from(escrow_amount);
    let computed_commitment = &funding_mask * ED25519_BASEPOINT_TABLE + amount_scalar * h_point;
    let computed_c_hex = hex::encode(computed_commitment.compress().as_bytes());

    println!("=== Funding Commitment Verification ===");
    println!("C[{signer_index}] computed: {computed_c_hex}");
    println!("C[{signer_index}] on-chain: {c_signer}");
    if computed_c_hex == c_signer {
        println!("  ✅ MATCH! funding_mask is CORRECT");
    } else {
        println!("  ❌ MISMATCH! funding_mask is WRONG");
    }
    println!();

    // Parse pseudo_out
    let pseudo_bytes: [u8; 32] = hex::decode(pseudo_out_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid pseudo_out length"))?;
    let pseudo_point = CompressedEdwardsY(pseudo_bytes)
        .decompress()
        .context("Invalid pseudo_out point")?;

    // Parse C[signer]
    let c_signer_bytes: [u8; 32] = hex::decode(c_signer)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid C[signer] length"))?;
    let c_signer_point = CompressedEdwardsY(c_signer_bytes)
        .decompress()
        .context("Invalid C[signer] point")?;

    // Compute C[signer] - pseudo_out
    let c_minus_pseudo = c_signer_point - pseudo_point;
    let c_minus_pseudo_hex = hex::encode(c_minus_pseudo.compress().as_bytes());

    println!("=== C[signer] - pseudo_out Verification ===");
    println!("C[{signer_index}] - pseudo_out = {c_minus_pseudo_hex}");

    // For the L equation to close properly:
    // L[signer] = s*G + c_p*P[signer] + c_c*(C[signer] - pseudo_out)
    // At signer index, we need: L[signer] = alpha_total * G
    // So: (C[signer] - pseudo_out) should equal (funding_mask - pseudo_out_mask) * G
    //
    // pseudo_out = pseudo_out_mask * G + amount * H
    // C[signer] = funding_mask * G + amount * H
    // C[signer] - pseudo_out = (funding_mask - pseudo_out_mask) * G
    //
    // This works only if both use the SAME amount!

    // Let's verify by computing (funding_mask * G + amount * H) - pseudo_out
    let expected_delta = computed_commitment - pseudo_point;
    let expected_delta_hex = hex::encode(expected_delta.compress().as_bytes());

    println!("Expected (funding_mask*G + amount*H - pseudo_out): {expected_delta_hex}");

    if c_minus_pseudo_hex == expected_delta_hex {
        println!("  ✅ MATCH! Delta computation is consistent");
    } else {
        println!("  ❌ MISMATCH! There's an issue with the commitment");
    }

    // Now extract the mask delta
    // If C[signer] - pseudo_out = mask_delta * G, then we need to find mask_delta
    // We can't directly extract the scalar, but we can verify if this equals
    // (funding_mask - pseudo_out_mask) * G by computing mask_delta * G
    //
    // The WASM computes pseudo_out = pseudo_out_mask * G + amount * H
    // where pseudo_out_mask = sum of output masks
    //
    // For balance: C[signer] = pseudo_out + (change_C or fee_adjustment)
    // In our case: C[signer] = pseudo_out + mask_delta * G (no amount diff if pseudo_out uses same amount)
    //
    // Let me compute what pseudo_out_mask should be:
    // pseudo_out - amount * H = pseudo_out_mask * G

    let pseudo_minus_aH = pseudo_point - amount_scalar * h_point;
    let pseudo_minus_aH_hex = hex::encode(pseudo_minus_aH.compress().as_bytes());

    println!();
    println!("=== Pseudo_out Mask Extraction ===");
    println!("pseudo_out - amount*H = {pseudo_minus_aH_hex}");
    println!("This should equal pseudo_out_mask * G");

    // Compute funding_mask * G to compare
    let funding_mask_G = &funding_mask * ED25519_BASEPOINT_TABLE;
    let funding_mask_G_hex = hex::encode(funding_mask_G.compress().as_bytes());
    println!("funding_mask * G = {funding_mask_G_hex}");

    // If pseudo_out uses the funding_mask, then pseudo_out - amount*H should equal funding_mask * G
    if pseudo_minus_aH_hex == funding_mask_G_hex {
        println!("  ✅ pseudo_out uses funding_mask (expected for single-input TX)");
    } else {
        println!("  ❌ pseudo_out uses DIFFERENT mask!");
        println!();
        println!("  This means the WASM is computing pseudo_out with a different mask.");
        println!("  The mask delta won't cancel in the L equation, causing CLSAG failure.");
    }

    Ok(())
}
