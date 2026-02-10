//! NEXUS CLSAG Debug Script v0.38.9
//!
//! Comprehensive debugging tool for tracing the entire CLSAG signing flow.
//! Identifies exactly where/when/why `c_computed != c_expected`.
//!
//! Usage:
//!   cargo build --release --bin debug_signing_flow
//!   ./target/release/debug_signing_flow <escrow_id>
//!   ./target/release/debug_signing_flow --create-test  # Create new escrow for testing
//!
//! Phases:
//! 1. Setup: Load escrow data, parse all fields
//! 2. PKI Analysis: Verify partial key image aggregation
//! 3. First Signer Trace: Replay CLSAG computation
//! 4. Second Signer Trace: Verify challenge propagation
//! 5. Verification: Step-by-step verification loop
//! 6. Diagnosis: Identify exact divergence point

use anyhow::{Context, Result, bail};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use diesel::sql_query;
use monero_generators_mirror::hash_to_point;
use sha3::{Digest, Keccak256};
use std::env;

// ===========================================================================
// Database Schema (local definition to avoid import issues)
// ===========================================================================

diesel::table! {
    escrows (id) {
        id -> Text,
        multisig_address -> Nullable<Text>,
        multisig_view_key -> Nullable<Text>,
        funding_tx_hash -> Nullable<Text>,
        funding_output_index -> Nullable<Integer>,
        funding_global_index -> Nullable<Integer>,
        funding_commitment_mask -> Nullable<Text>,
        funding_tx_pubkey -> Nullable<Text>,
        amount -> BigInt,
        buyer_signature -> Nullable<Text>,
        vendor_signature -> Nullable<Text>,
        vendor_payout_address -> Nullable<Text>,
        status -> Text,
        buyer_partial_key_image -> Nullable<Text>,
        vendor_partial_key_image -> Nullable<Text>,
        arbiter_partial_key_image -> Nullable<Text>,
        aggregated_key_image -> Nullable<Text>,
        ring_data_json -> Nullable<Text>,
        vendor_nonce_public -> Nullable<Text>,
        buyer_nonce_public -> Nullable<Text>,
        nonce_aggregated -> Nullable<Text>,
        vendor_signed_at -> Nullable<Integer>,
        buyer_signed_at -> Nullable<Integer>,
        first_signer_role -> Nullable<Text>,
        first_signer_had_r_agg -> Nullable<Integer>,
        mu_p -> Nullable<Text>,
        mu_c -> Nullable<Text>,
    }
}

// ===========================================================================
// Database Connection
// ===========================================================================

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

// ===========================================================================
// Constants
// ===========================================================================

const CLSAG_DOMAIN: &[u8] = b"CLSAG_round";
const CLSAG_AGG_0: &[u8] = b"CLSAG_agg_0";
const CLSAG_AGG_1: &[u8] = b"CLSAG_agg_1";

const H_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

// ===========================================================================
// Helper Functions
// ===========================================================================

fn parse_hex_32(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("Invalid hex")?;
    if bytes.len() != 32 {
        bail!("Expected 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_point(hex_str: &str) -> Result<EdwardsPoint> {
    let arr = parse_hex_32(hex_str)?;
    CompressedEdwardsY(arr)
        .decompress()
        .context("Failed to decompress point")
}

fn short_hex(bytes: &[u8]) -> String {
    if bytes.len() >= 8 {
        format!("{}...", hex::encode(&bytes[..8]))
    } else {
        hex::encode(bytes)
    }
}

fn full_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ===========================================================================
// CLSAG Computation Functions (replicated from verifier)
// ===========================================================================

fn compute_mixing_coefficients(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    // mu_P = H(CLSAG_agg_0 || ring_keys || ring_commitments || I || D || pseudo_out)
    let mut hasher_p = Keccak256::new();
    let mut domain_agg_0 = [0u8; 32];
    domain_agg_0[..CLSAG_AGG_0.len()].copy_from_slice(CLSAG_AGG_0);
    hasher_p.update(&domain_agg_0);

    for key in ring_keys {
        hasher_p.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher_p.update(commitment.compress().as_bytes());
    }
    hasher_p.update(key_image.compress().as_bytes());
    hasher_p.update(d_inv8.compress().as_bytes());
    hasher_p.update(pseudo_out.compress().as_bytes());

    let mu_p_hash = hasher_p.finalize();
    let mut mu_p_bytes = [0u8; 32];
    mu_p_bytes.copy_from_slice(&mu_p_hash);
    let mu_p = Scalar::from_bytes_mod_order(mu_p_bytes);

    // mu_C = H(CLSAG_agg_1 || ...)
    let mut hasher_c = Keccak256::new();
    let mut domain_agg_1 = [0u8; 32];
    domain_agg_1[..CLSAG_AGG_1.len()].copy_from_slice(CLSAG_AGG_1);
    hasher_c.update(&domain_agg_1);

    for key in ring_keys {
        hasher_c.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher_c.update(commitment.compress().as_bytes());
    }
    hasher_c.update(key_image.compress().as_bytes());
    hasher_c.update(d_inv8.compress().as_bytes());
    hasher_c.update(pseudo_out.compress().as_bytes());

    let mu_c_hash = hasher_c.finalize();
    let mut mu_c_bytes = [0u8; 32];
    mu_c_bytes.copy_from_slice(&mu_c_hash);
    let mu_c = Scalar::from_bytes_mod_order(mu_c_bytes);

    (mu_p, mu_c)
}

fn compute_round_hash(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    pseudo_out: &EdwardsPoint,
    tx_prefix_hash: &[u8; 32],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    l_point: &EdwardsPoint,
    r_point: &EdwardsPoint,
) -> Scalar {
    let mut hasher = Keccak256::new();

    let mut domain_sep = [0u8; 32];
    domain_sep[..CLSAG_DOMAIN.len()].copy_from_slice(CLSAG_DOMAIN);
    hasher.update(&domain_sep);

    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher.update(commitment.compress().as_bytes());
    }
    hasher.update(pseudo_out.compress().as_bytes());
    hasher.update(tx_prefix_hash);
    hasher.update(key_image.compress().as_bytes());
    hasher.update(d_inv8.compress().as_bytes());
    hasher.update(l_point.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());

    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order(hash_bytes)
}

// ===========================================================================
// Escrow Data Structures
// ===========================================================================

#[derive(Debug)]
struct EscrowData {
    id: String,
    status: String,
    multisig_address: Option<String>,
    funding_tx_hash: Option<String>,
    funding_output_index: Option<i32>,
    funding_commitment_mask: Option<String>,
    amount: i64,
    buyer_partial_ki: Option<String>,
    vendor_partial_ki: Option<String>,
    arbiter_partial_ki: Option<String>,
    aggregated_ki: Option<String>,
    ring_data_json: Option<String>,
    buyer_signature: Option<String>,
    vendor_signature: Option<String>,
    first_signer_role: Option<String>,
    first_signer_had_r_agg: Option<i32>,
    mu_p: Option<String>,
    mu_c: Option<String>,
    vendor_nonce_public: Option<String>,
    buyer_nonce_public: Option<String>,
    nonce_aggregated: Option<String>,
}

#[derive(Debug)]
struct SignatureData {
    c1: String,
    s_values: Vec<String>,
    d: Option<String>,
    pseudo_out: Option<String>,
    mu_p: Option<String>,
    mu_c: Option<String>,
}

#[derive(Debug)]
struct RingData {
    ring_keys: Vec<String>,
    ring_commitments: Vec<String>,
    tx_prefix_hash: String,
    signer_index: usize,
    key_image: String,
    stealth_address: Option<String>,
    tx_pubkey: Option<String>,
}

// ===========================================================================
// Phase 1: Setup - Load Escrow Data
// ===========================================================================

fn phase1_setup(conn: &mut SqliteConnection, escrow_id: &str) -> Result<EscrowData> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║           PHASE 1: SETUP - Loading Escrow Data                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let result: Vec<(
        String, Option<String>, Option<String>, Option<String>, Option<i32>,
        Option<i32>, Option<String>, Option<String>, i64, Option<String>,
        Option<String>, Option<String>, String, Option<String>, Option<String>,
        Option<String>, Option<String>, Option<String>, Option<String>,
        Option<String>, Option<String>, Option<i32>, Option<i32>, Option<String>,
        Option<i32>, Option<String>, Option<String>,  // first_signer_had_r_agg is i32, mu_p/mu_c are String
    )> = escrows::table
        .filter(escrows::id.eq(escrow_id))
        .select((
            escrows::id,
            escrows::multisig_address,
            escrows::multisig_view_key,
            escrows::funding_tx_hash,
            escrows::funding_output_index,
            escrows::funding_global_index,
            escrows::funding_commitment_mask,
            escrows::funding_tx_pubkey,
            escrows::amount,
            escrows::buyer_signature,
            escrows::vendor_signature,
            escrows::vendor_payout_address,
            escrows::status,
            escrows::buyer_partial_key_image,
            escrows::vendor_partial_key_image,
            escrows::arbiter_partial_key_image,
            escrows::aggregated_key_image,
            escrows::ring_data_json,
            escrows::vendor_nonce_public,
            escrows::buyer_nonce_public,
            escrows::nonce_aggregated,
            escrows::vendor_signed_at,
            escrows::buyer_signed_at,
            escrows::first_signer_role,
            escrows::first_signer_had_r_agg,
            escrows::mu_p,
            escrows::mu_c,
        ))
        .load(conn)?;

    if result.is_empty() {
        bail!("Escrow {} not found", escrow_id);
    }

    let row = &result[0];

    let escrow = EscrowData {
        id: row.0.clone(),
        status: row.12.clone(),
        multisig_address: row.1.clone(),
        funding_tx_hash: row.3.clone(),
        funding_output_index: row.4,
        funding_commitment_mask: row.6.clone(),
        amount: row.8,
        buyer_partial_ki: row.13.clone(),
        vendor_partial_ki: row.14.clone(),
        arbiter_partial_ki: row.15.clone(),
        aggregated_ki: row.16.clone(),
        ring_data_json: row.17.clone(),
        buyer_signature: row.9.clone(),
        vendor_signature: row.10.clone(),
        first_signer_role: row.23.clone(),
        first_signer_had_r_agg: row.24,
        mu_p: row.25.clone(),
        mu_c: row.26.clone(),
        vendor_nonce_public: row.18.clone(),
        buyer_nonce_public: row.19.clone(),
        nonce_aggregated: row.20.clone(),
    };

    println!("✓ Escrow ID: {}", escrow.id);
    println!("✓ Status: {}", escrow.status);
    println!("✓ Multisig Address: {}", escrow.multisig_address.as_deref().unwrap_or("NOT SET"));
    println!("✓ Amount: {} atomic ({:.6} XMR)", escrow.amount, escrow.amount as f64 / 1e12);
    println!("✓ Funding TX: {}", escrow.funding_tx_hash.as_deref().unwrap_or("NOT FUNDED"));
    println!("✓ First Signer Role: {}", escrow.first_signer_role.as_deref().unwrap_or("NONE"));

    println!("\n--- Partial Key Images ---");
    println!("  Buyer PKI:   {}", escrow.buyer_partial_ki.as_deref()
        .map(|s| if s.len() > 16 { format!("{}...", &s[..16]) } else { s.to_string() })
        .unwrap_or_else(|| "NONE".to_string()));
    println!("  Vendor PKI:  {}", escrow.vendor_partial_ki.as_deref()
        .map(|s| if s.len() > 16 { format!("{}...", &s[..16]) } else { s.to_string() })
        .unwrap_or_else(|| "NONE".to_string()));
    println!("  Aggregated:  {}", escrow.aggregated_ki.as_deref()
        .map(|s| if s.len() > 16 { format!("{}...", &s[..16]) } else { s.to_string() })
        .unwrap_or_else(|| "NONE".to_string()));

    println!("\n--- MuSig2 Nonces ---");
    println!("  Vendor Nonce: {}", if escrow.vendor_nonce_public.is_some() { "✓ PRESENT" } else { "✗ MISSING" });
    println!("  Buyer Nonce:  {}", if escrow.buyer_nonce_public.is_some() { "✓ PRESENT" } else { "✗ MISSING" });
    println!("  Aggregated:   {}", if escrow.nonce_aggregated.is_some() { "✓ AGGREGATED" } else { "✗ NOT YET" });

    println!("\n--- Stored mu Values (v0.37.0) ---");
    println!("  mu_p: {}", escrow.mu_p.as_deref()
        .map(|s| if s.len() > 16 { format!("{}...", &s[..16]) } else { s.to_string() })
        .unwrap_or_else(|| "NOT STORED".to_string()));
    println!("  mu_c: {}", escrow.mu_c.as_deref()
        .map(|s| if s.len() > 16 { format!("{}...", &s[..16]) } else { s.to_string() })
        .unwrap_or_else(|| "NOT STORED".to_string()));

    println!("\n--- First Signer Timing (v0.41.0) ---");
    println!("  first_signer_had_r_agg: {}", match escrow.first_signer_had_r_agg {
        Some(1) => "TRUE (used R_agg)".to_string(),
        Some(0) => "FALSE (used individual nonce)".to_string(),
        _ => "NOT SET".to_string(),
    });

    println!("\n--- Signatures ---");
    println!("  Buyer Signature:  {}", if escrow.buyer_signature.is_some() { "✓ PRESENT" } else { "✗ MISSING" });
    println!("  Vendor Signature: {}", if escrow.vendor_signature.is_some() { "✓ PRESENT" } else { "✗ MISSING" });

    Ok(escrow)
}

// ===========================================================================
// Phase 2: PKI Analysis
// ===========================================================================

fn phase2_pki_analysis(escrow: &EscrowData) -> Result<()> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║           PHASE 2: PKI Analysis - Key Image Aggregation          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let buyer_pki = match &escrow.buyer_partial_ki {
        Some(s) if !s.is_empty() => s,
        _ => {
            println!("⚠ Buyer PKI not found - cannot analyze");
            return Ok(());
        }
    };

    let vendor_pki = match &escrow.vendor_partial_ki {
        Some(s) if !s.is_empty() => s,
        _ => {
            println!("⚠ Vendor PKI not found - cannot analyze");
            return Ok(());
        }
    };

    let aggregated_ki = match &escrow.aggregated_ki {
        Some(s) if !s.is_empty() => s,
        _ => {
            println!("⚠ Aggregated Key Image not found - cannot analyze");
            return Ok(());
        }
    };

    // Parse as points
    println!("Parsing partial key images...");

    let buyer_pki_point = parse_point(buyer_pki)
        .context("Failed to parse buyer PKI as point")?;
    let vendor_pki_point = parse_point(vendor_pki)
        .context("Failed to parse vendor PKI as point")?;
    let aggregated_ki_point = parse_point(aggregated_ki)
        .context("Failed to parse aggregated KI as point")?;

    println!("  ✓ Buyer PKI:      {}", short_hex(&buyer_pki_point.compress().to_bytes()));
    println!("  ✓ Vendor PKI:     {}", short_hex(&vendor_pki_point.compress().to_bytes()));
    println!("  ✓ Aggregated KI:  {}", short_hex(&aggregated_ki_point.compress().to_bytes()));

    // Compute expected aggregation: buyer_pki + vendor_pki
    let expected_aggregated = buyer_pki_point + vendor_pki_point;
    let expected_hex = full_hex(&expected_aggregated.compress().to_bytes());

    println!("\n--- PKI Aggregation Check ---");
    println!("  Expected (buyer + vendor): {}", short_hex(&expected_aggregated.compress().to_bytes()));
    println!("  Stored Aggregated KI:      {}", short_hex(&aggregated_ki_point.compress().to_bytes()));

    if expected_hex == *aggregated_ki {
        println!("  ✅ PKI AGGREGATION CORRECT: buyer_pki + vendor_pki = aggregated_ki");
    } else {
        println!("  ❌ PKI AGGREGATION MISMATCH!");
        println!("     Expected: {}", expected_hex);
        println!("     Stored:   {}", aggregated_ki);
        println!("\n  DIAGNOSIS: This indicates that either:");
        println!("    1. First signer re-submitted PKI with derivation (double-counted derivation)");
        println!("    2. Both signers submitted PKI with derivation (should only be first signer)");
        println!("    3. PKI values were computed with different base points");
    }

    Ok(())
}

// ===========================================================================
// Phase 3: Parse Signatures
// ===========================================================================

fn parse_signature(sig_json: &str) -> Result<SignatureData> {
    let v: serde_json::Value = serde_json::from_str(sig_json)?;
    let sig = v.get("signature").context("Missing 'signature' field")?;

    let c1 = sig.get("c1")
        .and_then(|v| v.as_str())
        .context("Missing c1")?
        .to_string();

    let s_values: Vec<String> = sig.get("s")
        .and_then(|v| v.as_array())
        .context("Missing s array")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let d = sig.get("D").and_then(|v| v.as_str()).map(String::from);

    // Note: pseudo_out is at TOP LEVEL of stored JSON, not inside "signature" object
    // The stored format is: { "signature": {...}, "key_image": "...", "pseudo_out": "..." }
    let pseudo_out = v.get("pseudo_out").and_then(|v| v.as_str()).map(String::from);

    // mu_p and mu_c may be inside the signature or at top level - check both
    let mu_p = sig.get("mu_p").and_then(|v| v.as_str()).map(String::from)
        .or_else(|| v.get("mu_p").and_then(|v| v.as_str()).map(String::from));
    let mu_c = sig.get("mu_c").and_then(|v| v.as_str()).map(String::from)
        .or_else(|| v.get("mu_c").and_then(|v| v.as_str()).map(String::from));

    Ok(SignatureData { c1, s_values, d, pseudo_out, mu_p, mu_c })
}

fn parse_ring_data(ring_json: &str) -> Result<RingData> {
    let v: serde_json::Value = serde_json::from_str(ring_json)?;

    // Note: Field name in stored JSON is "ring_public_keys" not "ring_member_keys"
    let ring_keys: Vec<String> = v.get("ring_public_keys")
        .and_then(|v| v.as_array())
        .context("Missing ring_public_keys")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    // Note: Field name in stored JSON is "ring_commitments" not "ring_member_commitments"
    let ring_commitments: Vec<String> = v.get("ring_commitments")
        .and_then(|v| v.as_array())
        .context("Missing ring_commitments")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let tx_prefix_hash = v.get("tx_prefix_hash")
        .and_then(|v| v.as_str())
        .context("Missing tx_prefix_hash")?
        .to_string();

    let signer_index = v.get("signer_index")
        .and_then(|v| v.as_u64())
        .context("Missing signer_index")? as usize;

    let key_image = v.get("key_image")
        .and_then(|v| v.as_str())
        .context("Missing key_image")?
        .to_string();

    let stealth_address = v.get("stealth_address").and_then(|v| v.as_str()).map(String::from);
    let tx_pubkey = v.get("tx_pubkey").and_then(|v| v.as_str()).map(String::from);

    Ok(RingData {
        ring_keys,
        ring_commitments,
        tx_prefix_hash,
        signer_index,
        key_image,
        stealth_address,
        tx_pubkey,
    })
}

// ===========================================================================
// Phase 3: First Signer Trace
// ===========================================================================

fn phase3_first_signer_trace(escrow: &EscrowData) -> Result<Option<(SignatureData, RingData)>> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║           PHASE 3: First Signer CLSAG Trace                      ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Determine which signature is first
    let first_role = escrow.first_signer_role.as_deref().unwrap_or("unknown");
    println!("First signer role: {}", first_role);

    let first_sig_json = match first_role {
        "vendor" => &escrow.vendor_signature,
        "buyer" => &escrow.buyer_signature,
        _ => {
            // Try to determine from timestamps or existence
            if escrow.vendor_signature.is_some() {
                &escrow.vendor_signature
            } else if escrow.buyer_signature.is_some() {
                &escrow.buyer_signature
            } else {
                println!("⚠ No signatures found yet");
                return Ok(None);
            }
        }
    };

    let sig_json = match first_sig_json {
        Some(s) => s,
        None => {
            println!("⚠ First signer ({}) has not signed yet", first_role);
            return Ok(None);
        }
    };

    let ring_json = match &escrow.ring_data_json {
        Some(s) => s,
        None => {
            println!("⚠ Ring data not found");
            return Ok(None);
        }
    };

    println!("\n--- Parsing First Signer Signature ---");
    let sig = parse_signature(sig_json)?;
    let ring = parse_ring_data(ring_json)?;

    println!("  c1: {}", short_hex(&hex::decode(&sig.c1)?));
    println!("  s_values count: {}", sig.s_values.len());
    println!("  D: {}", sig.d.as_deref().map(|s| short_hex(&hex::decode(s).unwrap_or_default())).unwrap_or_else(|| "NOT SET".to_string()));
    println!("  pseudo_out: {}", sig.pseudo_out.as_deref().map(|s| short_hex(&hex::decode(s).unwrap_or_default())).unwrap_or_else(|| "NOT SET".to_string()));
    println!("  mu_p (in sig): {}", sig.mu_p.as_deref().map(|s| short_hex(&hex::decode(s).unwrap_or_default())).unwrap_or_else(|| "NOT IN SIGNATURE".to_string()));
    println!("  mu_c (in sig): {}", sig.mu_c.as_deref().map(|s| short_hex(&hex::decode(s).unwrap_or_default())).unwrap_or_else(|| "NOT IN SIGNATURE".to_string()));

    println!("\n--- Ring Data ---");
    println!("  Ring size: {}", ring.ring_keys.len());
    println!("  Signer index: {}", ring.signer_index);
    println!("  TX prefix hash: {}", short_hex(&hex::decode(&ring.tx_prefix_hash)?));
    println!("  Key image: {}", short_hex(&hex::decode(&ring.key_image)?));

    // Show s[signer_index] specifically
    if ring.signer_index < sig.s_values.len() {
        println!("\n--- Critical s-value at signer position ---");
        println!("  s[{}] (first signer): {}", ring.signer_index, &sig.s_values[ring.signer_index]);
    }

    Ok(Some((sig, ring)))
}

// ===========================================================================
// Phase 4: Second Signer Trace
// ===========================================================================

fn phase4_second_signer_trace(escrow: &EscrowData, first_sig: &SignatureData, ring: &RingData) -> Result<Option<SignatureData>> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║           PHASE 4: Second Signer CLSAG Trace                     ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let first_role = escrow.first_signer_role.as_deref().unwrap_or("vendor");
    let second_role = if first_role == "vendor" { "buyer" } else { "vendor" };
    println!("Second signer role: {}", second_role);

    let second_sig_json = match second_role {
        "vendor" => &escrow.vendor_signature,
        "buyer" => &escrow.buyer_signature,
        _ => &escrow.buyer_signature,
    };

    let sig_json = match second_sig_json {
        Some(s) => s,
        None => {
            println!("⚠ Second signer ({}) has not signed yet", second_role);
            return Ok(None);
        }
    };

    println!("\n--- Parsing Second Signer Signature ---");
    let sig = parse_signature(sig_json)?;

    println!("  c1: {}", short_hex(&hex::decode(&sig.c1)?));
    println!("  s_values count: {}", sig.s_values.len());

    // Compare c1 values
    println!("\n--- c1 Comparison ---");
    println!("  First signer c1:  {}", &first_sig.c1);
    println!("  Second signer c1: {}", &sig.c1);
    if first_sig.c1 == sig.c1 {
        println!("  ✅ c1 VALUES MATCH - Second signer used first signer's c1");
    } else {
        println!("  ❌ c1 VALUES DIFFER!");
        println!("     This indicates the second signer recomputed c1 instead of using first signer's value");
    }

    // Compare s-values at signer index
    if ring.signer_index < first_sig.s_values.len() && ring.signer_index < sig.s_values.len() {
        println!("\n--- s[{}] Comparison (signer position) ---", ring.signer_index);
        println!("  First signer s[{}]:  {}", ring.signer_index, &first_sig.s_values[ring.signer_index]);
        println!("  Second signer s[{}]: {}", ring.signer_index, &sig.s_values[ring.signer_index]);

        if first_sig.s_values[ring.signer_index] == sig.s_values[ring.signer_index] {
            println!("  ⚠ s-values are IDENTICAL - Second signer should have ADDED their contribution!");
        } else {
            println!("  ✓ s-values differ (expected - second signer added contribution)");

            // Try to compute the difference
            let s1_bytes = parse_hex_32(&first_sig.s_values[ring.signer_index])?;
            let s2_bytes = parse_hex_32(&sig.s_values[ring.signer_index])?;
            let s1 = Scalar::from_bytes_mod_order(s1_bytes);
            let s2 = Scalar::from_bytes_mod_order(s2_bytes);
            let diff = s2 - s1;
            println!("  Contribution (s2 - s1): {}", full_hex(&diff.to_bytes()));
        }
    }

    // Check first signer timing flag (v0.41.0 TOCTOU fix)
    println!("\n--- First Signer Timing Check (v0.41.0) ---");
    println!("  first_signer_had_r_agg: {}", match escrow.first_signer_had_r_agg {
        Some(1) => "TRUE (first signer used R_agg)",
        Some(0) => "FALSE (first signer used individual nonce)",
        _ => "NOT SET (first signer not yet signed?)",
    });
    println!("  nonce_aggregated is_some(): {}", escrow.nonce_aggregated.is_some());
    println!("  ✓ v0.41.0 FIX: first_signer_had_r_agg is now STORED at signing time");
    println!("  First sig c1: {}", &first_sig.c1);

    Ok(Some(sig))
}

// ===========================================================================
// Phase 5: Verification Loop
// ===========================================================================

fn phase5_verification(escrow: &EscrowData, sig: &SignatureData, ring: &RingData) -> Result<()> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║           PHASE 5: Step-by-Step CLSAG Verification               ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Parse all necessary data
    let c1_bytes = parse_hex_32(&sig.c1)?;
    let key_image = parse_point(&ring.key_image)?;

    let d_hex = sig.d.as_ref().context("Missing D in signature")?;
    let d_inv8 = parse_point(d_hex)?;

    let pseudo_out_hex = sig.pseudo_out.as_ref().context("Missing pseudo_out")?;
    let pseudo_out = parse_point(pseudo_out_hex)?;

    let tx_prefix_hash = parse_hex_32(&ring.tx_prefix_hash)?;

    // Parse ring keys and commitments
    let mut ring_keys: Vec<EdwardsPoint> = Vec::new();
    let mut ring_commitments: Vec<EdwardsPoint> = Vec::new();

    for (i, key_hex) in ring.ring_keys.iter().enumerate() {
        let key = parse_point(key_hex)
            .context(format!("Failed to parse ring_key[{}]", i))?;
        ring_keys.push(key);
    }

    for (i, commit_hex) in ring.ring_commitments.iter().enumerate() {
        let commit = parse_point(commit_hex)
            .context(format!("Failed to parse ring_commitment[{}]", i))?;
        ring_commitments.push(commit);
    }

    // Parse s values
    let mut s_scalars: Vec<Scalar> = Vec::new();
    for s_hex in &sig.s_values {
        let s_bytes = parse_hex_32(s_hex)?;
        s_scalars.push(Scalar::from_bytes_mod_order(s_bytes));
    }

    let ring_size = ring_keys.len();
    println!("Ring size: {}", ring_size);
    println!("Signer index: {}", ring.signer_index);

    // Compute mixing coefficients
    println!("\n--- Computing Mixing Coefficients ---");
    let (mu_p, mu_c) = compute_mixing_coefficients(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );

    let computed_mu_p_hex = full_hex(&mu_p.to_bytes());
    let computed_mu_c_hex = full_hex(&mu_c.to_bytes());

    println!("  Computed mu_P: {}", &computed_mu_p_hex);
    println!("  Computed mu_C: {}", &computed_mu_c_hex);

    // Compare with stored mu values
    if let Some(stored_mu_p) = &escrow.mu_p {
        println!("\n  Stored mu_P:   {}", stored_mu_p);
        if &computed_mu_p_hex == stored_mu_p {
            println!("  ✅ mu_P MATCH");
        } else {
            println!("  ❌ mu_P MISMATCH!");
        }
    }

    if let Some(stored_mu_c) = &escrow.mu_c {
        println!("  Stored mu_C:   {}", stored_mu_c);
        if &computed_mu_c_hex == stored_mu_c {
            println!("  ✅ mu_C MATCH");
        } else {
            println!("  ❌ mu_C MISMATCH!");
        }
    }

    // D_original = D_inv8 * 8
    let d_original = d_inv8 * Scalar::from(8u64);
    println!("\n--- D Point ---");
    println!("  D_inv8:     {}", short_hex(&d_inv8.compress().to_bytes()));
    println!("  D_original: {}", short_hex(&d_original.compress().to_bytes()));

    // Precompute Hp(P[i])
    let mut hp_values: Vec<EdwardsPoint> = Vec::new();
    for key in &ring_keys {
        hp_values.push(hash_to_point(key.compress().to_bytes()));
    }

    // Verification loop
    println!("\n--- Verification Loop ---");
    let mut c = Scalar::from_bytes_mod_order(c1_bytes);

    for i in 0..ring_size {
        let s = s_scalars[i];
        let p_i = ring_keys[i];
        let c_i = ring_commitments[i];
        let hp_i = hp_values[i];

        let c_p = mu_p * c;
        let c_c = mu_c * c;

        // L[i] = s*G + c_p*P[i] + c_c*(C[i] - pseudo_out)
        let c_adjusted = c_i - pseudo_out;
        let l_point = &s * ED25519_BASEPOINT_TABLE + c_p * p_i + c_c * c_adjusted;

        // R[i] = s*Hp(P[i]) + c_p*I + c_c*D_original
        let r_point = s * hp_i + c_p * key_image + c_c * d_original;

        // Compute next challenge
        let c_next = compute_round_hash(
            &ring_keys,
            &ring_commitments,
            &pseudo_out,
            &tx_prefix_hash,
            &key_image,
            &d_inv8,
            &l_point,
            &r_point,
        );

        // Log critical rounds
        if i == 0 || i == ring.signer_index || i == ring_size - 1 {
            println!("\n  Round {}{}:", i, if i == ring.signer_index { " (SIGNER)" } else { "" });
            println!("    c_input: {}", short_hex(&c.to_bytes()));
            println!("    s[{}]:    {}", i, short_hex(&s.to_bytes()));
            println!("    c_p:     {}", short_hex(&c_p.to_bytes()));
            println!("    c_c:     {}", short_hex(&c_c.to_bytes()));
            println!("    L:       {}", short_hex(&l_point.compress().to_bytes()));
            println!("    R:       {}", short_hex(&r_point.compress().to_bytes()));
            println!("    c_next:  {}", short_hex(&c_next.to_bytes()));
        }

        c = c_next;
    }

    // Final comparison
    let c_computed = c.to_bytes();
    let valid = c_computed == c1_bytes;

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     VERIFICATION RESULT                          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!("\n  c_computed: {}", full_hex(&c_computed));
    println!("  c_expected: {}", full_hex(&c1_bytes));

    if valid {
        println!("\n  ✅ CLSAG VERIFICATION PASSED: c_computed == c1");
    } else {
        println!("\n  ❌ CLSAG VERIFICATION FAILED: c_computed != c1");
    }

    Ok(())
}

// ===========================================================================
// Phase 6: Diagnosis
// ===========================================================================

fn phase6_diagnosis(escrow: &EscrowData, first_sig: Option<&SignatureData>, second_sig: Option<&SignatureData>) {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    PHASE 6: DIAGNOSIS                            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    println!("--- Known Bugs Checklist ---\n");

    // Bug v0.38.9: first_signer_used_r_agg timing
    println!("❓ v0.38.9 TIMING BUG (first_signer_used_r_agg):");
    println!("   - first_signer_used_r_agg is NOT stored in database");
    println!("   - It's computed dynamically from nonce_aggregated.is_some()");
    println!("   - If first signer signed BEFORE nonces aggregated, but second signer");
    println!("     signs AFTER aggregation, the flag is WRONG");
    println!("   Current state:");
    println!("     nonce_aggregated: {}", if escrow.nonce_aggregated.is_some() { "PRESENT (true)" } else { "ABSENT (false)" });
    println!("     first_signer_role: {:?}", escrow.first_signer_role);
    println!("   FIX: Store first_signer_used_r_agg when first signer submits signature\n");

    // Bug v0.38.8: mu race condition
    println!("❓ v0.38.8 MU RACE CONDITION:");
    println!("   - If both signers call prepare-sign before either submits");
    println!("   - Both compute mu locally with potentially different values");
    println!("   - The retry loop (5 × 2s) should wait for stored mu values");
    println!("   Current state:");
    println!("     stored mu_p: {}", escrow.mu_p.as_deref().unwrap_or("NOT STORED"));
    println!("     stored mu_c: {}", escrow.mu_c.as_deref().unwrap_or("NOT STORED"));
    if escrow.mu_p.is_none() || escrow.mu_c.is_none() {
        println!("   ⚠ mu values not stored - possible race condition!\n");
    } else {
        println!("   ✓ mu values stored\n");
    }

    // v0.41.0: First signer timing flag (TOCTOU fix)
    println!("✅ v0.41.0 TOCTOU FIX:");
    println!("   - first_signer_had_r_agg is STORED at signing time (not computed dynamically)");
    println!("   Current state:");
    println!("     first_signer_had_r_agg: {}", match escrow.first_signer_had_r_agg {
        Some(1) => "1 (TRUE - first signer used R_agg)",
        Some(0) => "0 (FALSE - first signer used individual nonce)",
        _ => "NOT SET",
    });
    println!("     first_signer_role: {:?}", escrow.first_signer_role);
    if first_sig.is_some() {
        println!("   ✓ First signature present\n");
    } else {
        println!("   ⚠ No first signature yet\n");
    }

    // s-value aggregation check
    if let (Some(fs), Some(ss)) = (first_sig, second_sig) {
        println!("❓ S-VALUE AGGREGATION:");
        println!("   Expected: s_final[π] = s_first[π] + contribution");
        if fs.s_values.len() == ss.s_values.len() {
            for i in 0..fs.s_values.len() {
                if fs.s_values[i] != ss.s_values[i] {
                    println!("   s[{}] differs (expected for signer index)", i);
                }
            }
        }
        println!();
    }

    // Summary
    println!("--- MOST LIKELY CAUSES (v0.41.2) ---\n");
    println!("1. funding_mask doesn't match on-chain commitment C[signer]");
    println!("   → CHECK: C = mask*G + amount*H should equal on-chain commitment\n");
    println!("2. pseudo_out uses wrong mask or amount");
    println!("   → CHECK: pseudo_out = pseudo_out_mask*G + funding_amount*H\n");
    println!("3. Output index mismatch in mask derivation");
    println!("   → CHECK: funding_output_index matches actual blockchain output\n");
    println!("4. L/R point computation using wrong alpha");
    println!("   → The alpha (nonce) used must match between signing and verification\n");
}

// ===========================================================================
// Main
// ===========================================================================

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: debug_signing_flow <escrow_id>");
        eprintln!("       debug_signing_flow --create-test");
        std::process::exit(1);
    }

    let escrow_id = &args[1];

    if escrow_id == "--create-test" {
        println!("Test escrow creation not yet implemented.");
        println!("Please use an existing escrow ID.");
        std::process::exit(0);
    }

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║         NEXUS CLSAG Debug Script v0.38.9                         ║");
    println!("║         Comprehensive Signing Flow Analysis                      ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!("\nEscrow ID: {}", escrow_id);

    // Connect to database
    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY not set")?;

    let manager = ConnectionManager::<SqliteConnection>::new(&db_url);
    let customizer = SqlCipherConnectionCustomizer { encryption_key };
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(customizer))
        .build(manager)?;

    let mut conn = pool.get()?;

    // Phase 1: Setup
    let escrow = phase1_setup(&mut conn, escrow_id)?;

    // Phase 2: PKI Analysis
    phase2_pki_analysis(&escrow)?;

    // Phase 3: First Signer Trace
    let first_signer_data = phase3_first_signer_trace(&escrow)?;

    // Phase 4: Second Signer Trace (if first signer data available)
    let second_sig = if let Some((ref first_sig, ref ring)) = first_signer_data {
        phase4_second_signer_trace(&escrow, first_sig, ring)?
    } else {
        None
    };

    // Phase 5: Verification (use the latest/aggregated signature)
    if let Some((ref sig, ref ring)) = first_signer_data {
        // Use second signature if available (it has aggregated s-values)
        let sig_to_verify = second_sig.as_ref().unwrap_or(sig);
        phase5_verification(&escrow, sig_to_verify, ring)?;
    }

    // Phase 6: Diagnosis
    let first_sig_ref = first_signer_data.as_ref().map(|(s, _)| s);
    phase6_diagnosis(&escrow, first_sig_ref, second_sig.as_ref());

    println!("\n✓ Debug analysis complete");

    Ok(())
}
