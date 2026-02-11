#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    non_snake_case,
    unused_comparisons
)]
//! FROST Signing Flow E2E Test
//!
//! Simulates the complete flow: PKI → prepare-sign → sign → broadcast
//! Without browser, to identify bugs directly.
//!
//! Usage:
//!   1. Start server with TEST_AUTH_BYPASS=1
//!   2. cargo run --release --bin test_frost_flow
//!
//! Escrow: ef57f177-f873-40c3-a175-4ab87c195ad8

use anyhow::{Context, Result};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use reqwest::cookie::Jar;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::sync::Arc;

// Use monero's correct hash_to_point (ge_fromfe_frombytes_vartime)
use monero_generators::hash_to_point as monero_hash_to_point;
use monero_generators::H;

// ============================================================================
// KNOWN VALUES FROM ESCROW #ef57f177-f873-40c3-a175-4ab87c195ad8
// From validate_escrow_crypto.rs
// ============================================================================

const ESCROW_ID: &str = "ef57f177-f873-40c3-a175-4ab87c195ad8";
const SERVER_URL: &str = "http://127.0.0.1:8080";

// Transaction data
const TX_SECRET_KEY: &str = "54d48a7b6f680a88fd04b4cf56b18f09e01c66ab3aa5ec9aabb33a258de43704";

// FROST keys
const GROUP_PUBKEY: &str = "8fe544aed04ac3a92dff7d2fb076689b83db5d8eba175bf8853e123b2f0e0fef";
const VIEW_KEY_PRIV: &str = "f2fcd78c14a49e707e4a7f4dfc24f5cfbfddfff5f94837bcddd72d88d963e808";
const VENDOR_SHARE: &str = "7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e";
const BUYER_SHARE: &str = "916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b";

// Expected output index from DB
const OUTPUT_INDEX: u64 = 1;

// Expected values (computed by validate_escrow_crypto.rs)
const EXPECTED_ONE_TIME_PUBKEY: &str =
    "ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0";
const EXPECTED_TX_PUBKEY: &str = "75ee30c8278cd0da2e081f0dbd22bd8c884d83da2f061c013175fb5612009da9";

// ============================================================================
// HELPER FUNCTIONS (copied from validate_escrow_crypto.rs)
// ============================================================================

fn hex_to_bytes(h: &str) -> Vec<u8> {
    hex::decode(h).expect("Invalid hex")
}

fn hex_to_scalar(h: &str) -> Scalar {
    let bytes = hex_to_bytes(h);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Scalar::from_bytes_mod_order(arr)
}

fn try_hex_to_scalar(h: &str) -> Option<Scalar> {
    if h.is_empty() || h.len() != 64 {
        return None;
    }
    let bytes = hex::decode(h).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Scalar::from_bytes_mod_order(arr))
}

fn hex_to_point(h: &str) -> EdwardsPoint {
    let bytes = hex_to_bytes(h);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .expect("Invalid Edwards point")
}

fn try_hex_to_point(h: &str) -> Option<EdwardsPoint> {
    if h.is_empty() || h.len() != 64 {
        return None;
    }
    let bytes = hex::decode(h).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr).decompress()
}

fn encode_varint(value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut n = value;
    while n >= 0x80 {
        result.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    result.push(n as u8);
    result
}

/// Hash to point (Monero's hash_to_ec)
fn hash_to_point(data: [u8; 32]) -> EdwardsPoint {
    let mut counter = 0u8;
    loop {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.update([counter]);
        let hash: [u8; 32] = hasher.finalize().into();

        if let Some(point) = CompressedEdwardsY(hash).decompress() {
            return point.mul_by_cofactor();
        }
        counter += 1;
        if counter > 255 {
            panic!("hash_to_point failed after 256 attempts");
        }
    }
}

/// Compute derivation scalar: d = H_s(8 * a * R || varint(idx))
fn compute_derivation(view_key: &Scalar, tx_pub_key: &EdwardsPoint, output_index: u64) -> Scalar {
    // Compute shared secret: 8 * a * R (with cofactor)
    let shared_secret = (*view_key * tx_pub_key).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    // Hash to derivation scalar
    let mut hasher = Keccak256::new();
    hasher.update(shared_secret_bytes);
    hasher.update(encode_varint(output_index));
    let derivation_hash: [u8; 32] = hasher.finalize().into();

    Scalar::from_bytes_mod_order(derivation_hash)
}

// ============================================================================
// API TYPES
// ============================================================================

#[derive(Debug, Serialize)]
struct TestLoginRequest {
    user_id: String,
    username: String,
    role: String,
}

#[derive(Debug, Serialize)]
struct SubmitPkiRequest {
    role: String,
    partial_key_image: String,
}

#[derive(Debug, Deserialize)]
struct SubmitPkiResponse {
    success: bool,
    aggregated_key_image: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrepareSignResponse {
    inputs: Vec<SigningInput>,
}

#[derive(Debug, Deserialize)]
struct SigningInput {
    ring: Vec<(String, String)>,
    signer_index: u32,
    offsets: Vec<u64>,
    tx_prefix_hash: String,
    key_image: String,
    peer_nonce_public: Option<String>,
    my_signer_index: u32,
    other_signer_index: u32,
    first_signer_c1: Option<String>,
    first_signer_s_values: Option<Vec<String>>,
    first_signer_mu_p: Option<String>,
    first_signer_mu_c: Option<String>,
}

// ============================================================================
// CLSAG SIGNING STRUCTURES
// ============================================================================

#[derive(Debug, Serialize)]
struct PartialTx {
    ring_size: u8,
    signer_index: u8,
    s_values: Vec<String>,
    c1: String,
    d: String,
    pseudo_out: String,
    key_image: String,
    alpha_encrypted: String,
    signer1_public: String,
    c_p: String,
    c_c: String,
    mu_p: String,
    mu_c: String,
}

#[derive(Debug, Serialize)]
struct SignInitRequest {
    role: String,
    partial_tx: String,
}

#[derive(Debug, Serialize)]
struct SignCompleteRequest {
    role: String,
    completed_clsag: String,
}

#[derive(Debug, Serialize)]
struct CompletedClsag {
    s_values: Vec<String>,
    c1: String,
    d: String,
    key_image: String,
    pseudo_out: String,
}

/// Hash to scalar (Monero's H_s)
fn keccak256_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

/// Compute CLSAG aggregate hash for domain separation
/// Reference: clsag_hash_agg() in rctSigs.cpp
/// mu_P = H(CLSAG_agg_0 || ring_keys || ring_commitments || I || D_inv8 || pseudo_out)
/// CRITICAL: Domain separator MUST be 32-byte padded, and D_inv8 (NOT message!) is included
fn clsag_agg_0(
    ring: &[EdwardsPoint],
    commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> Scalar {
    let mut hasher = Keccak256::new();

    // CRITICAL: Domain separator must be 32-byte padded (Monero uses 32-byte key slots)
    let mut domain_sep = [0u8; 32];
    domain_sep[..11].copy_from_slice(b"CLSAG_agg_0");
    hasher.update(domain_sep);

    for p in ring {
        hasher.update(p.compress().as_bytes());
    }
    for c in commitments {
        hasher.update(c.compress().as_bytes());
    }
    hasher.update(key_image.compress().as_bytes());
    hasher.update(d_inv8.compress().as_bytes()); // D/8, not D!
    hasher.update(pseudo_out.compress().as_bytes());
    // NO message in mu computation!

    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

/// Compute CLSAG_agg_1 for mu_C
fn clsag_agg_1(
    ring: &[EdwardsPoint],
    commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> Scalar {
    let mut hasher = Keccak256::new();

    let mut domain_sep = [0u8; 32];
    domain_sep[..11].copy_from_slice(b"CLSAG_agg_1");
    hasher.update(domain_sep);

    for p in ring {
        hasher.update(p.compress().as_bytes());
    }
    for c in commitments {
        hasher.update(c.compress().as_bytes());
    }
    hasher.update(key_image.compress().as_bytes());
    hasher.update(d_inv8.compress().as_bytes());
    hasher.update(pseudo_out.compress().as_bytes());

    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

/// Compute CLSAG round hash
fn clsag_round(
    prefix: &[u8],
    p: &EdwardsPoint,
    c: &EdwardsPoint,
    l: &EdwardsPoint,
    r: &EdwardsPoint,
) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(prefix);
    hasher.update(p.compress().as_bytes());
    hasher.update(c.compress().as_bytes());
    hasher.update(l.compress().as_bytes());
    hasher.update(r.compress().as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

async fn create_session(role: &str) -> Result<Client> {
    let jar = Arc::new(Jar::default());
    let client = Client::builder()
        .cookie_store(true)
        .cookie_provider(jar.clone())
        .build()?;

    // Real user IDs from escrow #ef57f177
    let user_id = match role {
        "vendor" => "26f85626-229e-4f97-8f58-2e03f3f6e96d",
        "buyer" => "0623164e-a1e9-4e3f-a2f4-4dca78d50782",
        _ => "067d8db1-a365-4204-b452-14fa55e936c7", // arbiter
    };

    let login_req = TestLoginRequest {
        user_id: user_id.to_string(),
        username: format!("test_{role}"),
        role: role.to_string(),
    };

    let resp = client
        .post(format!("{SERVER_URL}/api/debug/test-login"))
        .json(&login_req)
        .send()
        .await
        .context("Failed to connect to server")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Login failed ({status}): {body}");
    }

    Ok(client)
}

// ============================================================================
// PKI COMPUTATION
// ============================================================================

fn compute_pki_with_derivation(
    share: &str,
    derivation: &Scalar,
    one_time_pubkey: &str,
    lambda: Scalar,
) -> String {
    // PKI = (derivation + λ × share) × Hp(P)
    // CRITICAL: Must use monero_hash_to_point for consistency with CLSAG!
    let share_scalar = hex_to_scalar(share);
    let weighted = lambda * share_scalar;
    let x_eff = *derivation + weighted;

    let p_bytes = hex_to_bytes(one_time_pubkey);
    let mut p_arr = [0u8; 32];
    p_arr.copy_from_slice(&p_bytes);
    // Use Monero's hash_to_point (ge_fromfe_frombytes_vartime)
    let hp_p = monero_hash_to_point(p_arr);

    let pki = x_eff * hp_p;
    hex::encode(pki.compress().as_bytes())
}

fn compute_pki_no_derivation(share: &str, one_time_pubkey: &str, lambda: Scalar) -> String {
    // PKI = λ × share × Hp(P) (NO derivation)
    // CRITICAL: Must use monero_hash_to_point for consistency with CLSAG!
    let share_scalar = hex_to_scalar(share);
    let weighted = lambda * share_scalar;

    let p_bytes = hex_to_bytes(one_time_pubkey);
    let mut p_arr = [0u8; 32];
    p_arr.copy_from_slice(&p_bytes);
    // Use Monero's hash_to_point (ge_fromfe_frombytes_vartime)
    let hp_p = monero_hash_to_point(p_arr);

    let pki = weighted * hp_p;
    hex::encode(pki.compress().as_bytes())
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== FROST SIGNING FLOW E2E TEST ===");
    println!("Escrow: {ESCROW_ID}\n");

    // ========================================================================
    // STEP 1: Compute expected values
    // ========================================================================
    println!("[1/6] Computing expected crypto values...");

    let view_key = hex_to_scalar(VIEW_KEY_PRIV);
    let tx_secret_key = hex_to_scalar(TX_SECRET_KEY);
    let tx_pub_key = &tx_secret_key * ED25519_BASEPOINT_TABLE;
    let tx_pub_key_hex = hex::encode(tx_pub_key.compress().as_bytes());

    println!("  TX Public Key (R): {tx_pub_key_hex}");
    if tx_pub_key_hex != EXPECTED_TX_PUBKEY {
        println!("  ❌ MISMATCH! Expected: {EXPECTED_TX_PUBKEY}");
        anyhow::bail!("TX pubkey mismatch - check TX_SECRET_KEY");
    }
    println!("  ✓ TX pubkey matches expected\n");

    // Compute derivation
    let derivation = compute_derivation(&view_key, &tx_pub_key, OUTPUT_INDEX);
    println!("  Derivation (d): {}", hex::encode(derivation.as_bytes()));

    // Compute one-time pubkey: P = d*G + B
    let group_pubkey = hex_to_point(GROUP_PUBKEY);
    let d_point = &derivation * ED25519_BASEPOINT_TABLE;
    let one_time_pubkey = d_point + group_pubkey;
    let one_time_pubkey_hex = hex::encode(one_time_pubkey.compress().as_bytes());

    println!("  One-time pubkey (P): {one_time_pubkey_hex}");
    if one_time_pubkey_hex != EXPECTED_ONE_TIME_PUBKEY {
        println!("  ❌ MISMATCH! Expected: {EXPECTED_ONE_TIME_PUBKEY}");
        anyhow::bail!("One-time pubkey mismatch");
    }
    println!("  ✓ One-time pubkey matches expected\n");

    // Lagrange coefficients for buyer(1) + vendor(2)
    let lambda_buyer = Scalar::from(2u64);
    let lambda_vendor = -Scalar::ONE;

    // Compute expected PKIs
    // VENDOR is FIRST submitter → includes derivation
    let expected_vendor_pki = compute_pki_with_derivation(
        VENDOR_SHARE,
        &derivation,
        &one_time_pubkey_hex,
        lambda_vendor,
    );

    // BUYER is SECOND submitter → NO derivation
    let expected_buyer_pki =
        compute_pki_no_derivation(BUYER_SHARE, &one_time_pubkey_hex, lambda_buyer);

    // Compute expected aggregated key image
    let vendor_pki_point = hex_to_point(&expected_vendor_pki);
    let buyer_pki_point = hex_to_point(&expected_buyer_pki);
    let expected_ki = vendor_pki_point + buyer_pki_point;
    let expected_ki_hex = hex::encode(expected_ki.compress().as_bytes());

    println!("  Expected vendor PKI: {expected_vendor_pki}");
    println!("  Expected buyer PKI:  {expected_buyer_pki}");
    println!("  Expected KI:         {expected_ki_hex}");
    println!();

    // ========================================================================
    // STEP 2: Setup sessions
    // ========================================================================
    println!("[2/6] Setup sessions...");

    let vendor_client = match create_session("vendor").await {
        Ok(c) => {
            println!("  ✓ Vendor login OK");
            c
        }
        Err(e) => {
            println!("  ❌ Vendor login FAILED: {e}");
            println!("\n  HINT: Make sure server is running with TEST_AUTH_BYPASS=1");
            println!("        TEST_AUTH_BYPASS=1 cargo run --release");
            anyhow::bail!("Vendor login failed");
        }
    };

    let buyer_client = match create_session("buyer").await {
        Ok(c) => {
            println!("  ✓ Buyer login OK");
            c
        }
        Err(e) => {
            println!("  ❌ Buyer login FAILED: {e}");
            anyhow::bail!("Buyer login failed");
        }
    };
    println!();

    // ========================================================================
    // STEP 3: Submit Vendor PKI (first submitter, WITH derivation)
    // ========================================================================
    println!("[3/6] Submit Vendor PKI (first submitter, WITH derivation)...");
    println!("  PKI: {expected_vendor_pki}");

    let submit_url = format!("{SERVER_URL}/api/v2/escrow/{ESCROW_ID}/submit-partial-key-image");
    let pki_req = SubmitPkiRequest {
        role: "vendor".to_string(),
        partial_key_image: expected_vendor_pki.clone(),
    };

    let resp = vendor_client
        .post(&submit_url)
        .json(&pki_req)
        .send()
        .await
        .context("Failed to submit vendor PKI")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    let submit_resp: Value = serde_json::from_str(&body).unwrap_or_default();

    if status.is_success() {
        println!("  ✓ Vendor PKI submitted successfully");
        if let Some(agg) = submit_resp["aggregated_key_image"].as_str() {
            println!("  ⚠️  Aggregated immediately (unexpected): {agg}");
        }
    } else if status.as_u16() == 409 {
        // PKI already submitted - check if it matches
        if let Some(existing) = submit_resp["existing_pki_prefix"].as_str() {
            if expected_vendor_pki.starts_with(existing) {
                println!("  ✓ Vendor PKI already submitted (same value, OK)");
            } else {
                println!("  ❌ PKI conflict: existing prefix {existing} doesn't match");
                anyhow::bail!("Vendor PKI conflict");
            }
        } else {
            println!("  ⚠️  PKI already submitted (409): {body}");
        }
    } else {
        println!("  ❌ Submit FAILED ({status}): {body}");
        anyhow::bail!("Vendor PKI submission failed");
    }
    println!();

    // ========================================================================
    // STEP 4: Submit Buyer PKI (second submitter, NO derivation)
    // ========================================================================
    println!("[4/6] Submit Buyer PKI (second submitter, NO derivation)...");
    println!("  PKI: {expected_buyer_pki}");

    let pki_req = SubmitPkiRequest {
        role: "buyer".to_string(),
        partial_key_image: expected_buyer_pki.clone(),
    };

    let resp = buyer_client
        .post(&submit_url)
        .json(&pki_req)
        .send()
        .await
        .context("Failed to submit buyer PKI")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    let submit_resp: Value = serde_json::from_str(&body).unwrap_or_default();

    if status.is_success() {
        println!("  ✓ Buyer PKI submitted successfully");

        // Check aggregated key image
        if let Some(agg) = submit_resp["aggregated_key_image"].as_str() {
            println!("\n  === AGGREGATED KEY IMAGE ===");
            println!("  Got:      {agg}");
            println!("  Expected: {expected_ki_hex}");

            if agg == expected_ki_hex {
                println!("  ✅ MATCH! Key image is correct!");
            } else {
                println!("  ❌ MISMATCH! Key image is WRONG!");
                println!("\n  This means PKI computation has a bug.");
                println!("  Check:");
                println!("    1. First submitter included derivation?");
                println!("    2. Second submitter did NOT include derivation?");
                println!("    3. Lagrange coefficients correct?");
            }
        } else {
            println!("  ⚠️  No aggregated_key_image in response");
        }
    } else if status.as_u16() == 409 {
        // PKI already submitted - check if it matches
        if let Some(existing) = submit_resp["existing_pki_prefix"].as_str() {
            if expected_buyer_pki.starts_with(existing) {
                println!("  ✓ Buyer PKI already submitted (same value, OK)");
                // Verify the aggregated KI from DB
                println!("\n  === KEY IMAGE (from previous aggregation) ===");
                println!("  Expected: {expected_ki_hex}");
            } else {
                println!("  ❌ PKI conflict: existing prefix {existing} doesn't match");
                anyhow::bail!("Buyer PKI conflict");
            }
        } else {
            println!("  ⚠️  PKI already submitted (409): {body}");
        }
    } else {
        println!("  ❌ Submit FAILED ({status}): {body}");
        anyhow::bail!("Buyer PKI submission failed");
    }
    println!();

    // ========================================================================
    // STEP 5: Prepare Signing (get ring data)
    // ========================================================================
    println!("[5/6] Prepare signing (vendor)...");

    let prepare_url = format!("{SERVER_URL}/api/v2/escrow/{ESCROW_ID}/prepare-sign");
    let resp = vendor_client
        .get(&prepare_url)
        .send()
        .await
        .context("Failed to call prepare-sign")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        // Print raw response for debugging
        let resp_json: Value = serde_json::from_str(&body).unwrap_or_default();

        // Check if inputs exist
        if let Some(inputs) = resp_json.get("inputs").and_then(|i| i.as_array()) {
            if let Some(input) = inputs.first() {
                println!("  ✓ prepare-sign OK");

                if let Some(ring) = input.get("ring").and_then(|r| r.as_array()) {
                    println!("    Ring size: {}", ring.len());
                }
                if let Some(idx) = input.get("signer_index") {
                    println!("    Signer index: {idx}");
                }
                if let Some(ki) = input.get("key_image").and_then(|k| k.as_str()) {
                    println!("    Key image: {ki}");
                }
                if let Some(tph) = input.get("message_hash").and_then(|m| m.as_str()) {
                    println!("    Message hash: {}...", &tph[..16.min(tph.len())]);
                }

                if input.get("first_signer_c1").is_some() {
                    println!("    ⚠️  first_signer_c1 present (I'm second signer)");
                } else {
                    println!("    ✓ No first_signer_c1 (I'm first signer)");
                }
            }
        } else {
            println!("  ⚠️  Response format unexpected:");
            println!("    {}", &body[..500.min(body.len())]);
        }
    } else {
        println!("  ❌ prepare-sign FAILED ({status}): {body}");
        println!("\n  This might be expected if ring data is not ready.");
    }
    println!();

    // ========================================================================
    // STEP 6: VENDOR CLSAG SIGNING (First Signer)
    // ========================================================================
    println!("\n[6/9] Vendor CLSAG signing (first signer)...");

    // Re-parse the prepare response to get data
    let prepare_resp: Value = serde_json::from_str(&body)?;

    // DEBUG: Print all available fields (FORCE print to ensure visibility)
    eprintln!("\n  +++ DEBUG: prepare-sign response fields +++");
    if let Some(inputs) = prepare_resp.get("inputs").and_then(|i| i.as_array()) {
        if let Some(input) = inputs.first() {
            if let Some(obj) = input.as_object() {
                for (key, val) in obj.iter() {
                    let val_preview = match val {
                        Value::String(s) if s.len() > 32 => {
                            format!("{}... (len={})", &s[..32], s.len())
                        }
                        Value::String(s) => format!("{} (len={})", s.clone(), s.len()),
                        Value::Array(a) => format!("[{} items]", a.len()),
                        Value::Number(n) => format!("{n}"),
                        _ => format!("{val}"),
                    };
                    eprintln!("    {key}: {val_preview}");
                }
            }
        }
    } else {
        eprintln!("    ERROR: No inputs array in response!");
        eprintln!("    Full response: {}", &body[..1000.min(body.len())]);
        anyhow::bail!("Invalid prepare-sign response");
    }
    eprintln!("  +++ END DEBUG inputs[0] +++");

    // Also print important top-level fields
    eprintln!("  +++ TOP LEVEL FIELDS +++");
    if let Some(tph) = prepare_resp.get("tx_prefix_hash").and_then(|v| v.as_str()) {
        eprintln!(
            "    tx_prefix_hash: {}... (len={})",
            &tph[..32.min(tph.len())],
            tph.len()
        );
    } else {
        eprintln!("    tx_prefix_hash: NOT FOUND!");
    }
    if let Some(ki) = prepare_resp.get("key_image").and_then(|v| v.as_str()) {
        eprintln!(
            "    key_image: {}... (len={})",
            &ki[..32.min(ki.len())],
            ki.len()
        );
    } else {
        eprintln!("    key_image: NOT FOUND!");
    }
    if let Some(mu_p) = prepare_resp.get("mu_p").and_then(|v| v.as_str()) {
        eprintln!("    mu_p: {}...", &mu_p[..16.min(mu_p.len())]);
    }
    if let Some(mu_c) = prepare_resp.get("mu_c").and_then(|v| v.as_str()) {
        eprintln!("    mu_c: {}...", &mu_c[..16.min(mu_c.len())]);
    }
    eprintln!("  +++ END TOP LEVEL +++\n");

    // Extract signing data
    let input = prepare_resp["inputs"]
        .as_array()
        .and_then(|arr| arr.first())
        .context("No inputs in prepare response")?;

    let ring_json = input["ring"].as_array().context("No ring")?;
    let signer_index = input["signer_index"].as_u64().unwrap_or(0) as usize;

    // tx_prefix_hash is at TOP LEVEL of response, not in inputs[0]!
    let tx_prefix_hash = prepare_resp["tx_prefix_hash"]
        .as_str()
        .or_else(|| input["tx_prefix_hash"].as_str())
        .unwrap_or("");

    // Try multiple field names for masks
    let commitment_mask_hex = input["commitment_mask"]
        .as_str()
        .or_else(|| input["pseudo_out_mask"].as_str())
        .or_else(|| input["mask"].as_str())
        .unwrap_or("");

    let funding_mask_hex = input["funding_mask"]
        .as_str()
        .or_else(|| input["output_mask"].as_str())
        .or_else(|| input["z"].as_str())
        .unwrap_or("");

    // key_image is at both TOP LEVEL and in inputs[0]
    let key_image_hex = input["key_image"]
        .as_str()
        .or_else(|| prepare_resp["key_image"].as_str())
        .unwrap_or("");
    let amount = input["commitment_amount"]
        .as_u64()
        .or_else(|| input["amount"].as_u64())
        .unwrap_or(0);

    // Check if we have required fields
    if commitment_mask_hex.is_empty() {
        println!("  ⚠️  commitment_mask is empty!");
        println!("      The prepare-sign response doesn't include mask data.");
        println!("      This may be because escrow status doesn't support signing yet.");
        println!("\n  Continuing with computed values from known crypto data...\n");
    }

    println!(
        "  Ring size: {}, Signer idx: {}",
        ring_json.len(),
        signer_index
    );
    println!("  Amount: {amount} piconero");

    // Parse ring members
    let mut ring_keys: Vec<EdwardsPoint> = Vec::new();
    let mut ring_commitments: Vec<EdwardsPoint> = Vec::new();

    for member in ring_json {
        if let Some(arr) = member.as_array() {
            if arr.len() >= 2 {
                let pk_hex = arr[0].as_str().unwrap_or("");
                let cm_hex = arr[1].as_str().unwrap_or("");
                ring_keys.push(hex_to_point(pk_hex));
                ring_commitments.push(hex_to_point(cm_hex));
            }
        }
    }

    // Parse key image
    let key_image = if !key_image_hex.is_empty() {
        hex_to_point(key_image_hex)
    } else {
        // Use expected key image
        hex_to_point(&expected_ki_hex)
    };

    // Parse masks - if not provided by server, we need to compute/use fallback values
    let (commitment_mask, funding_mask, real_amount) = if let (Some(cm), Some(fm)) = (
        try_hex_to_scalar(commitment_mask_hex),
        try_hex_to_scalar(funding_mask_hex),
    ) {
        println!("  Using masks from prepare-sign response");
        (cm, fm, amount)
    } else {
        // Masks not provided - we can't sign without them!
        // The server needs to provide these values.
        println!("  ⚠️  Masks not provided by server!");
        println!("      This test requires the prepare-sign endpoint to return:");
        println!("      - commitment_mask (or pseudo_out_mask)");
        println!("      - funding_mask (or output_mask or z)");
        println!("\n  Checking what data we have from the escrow DB...\n");

        // Try to get masks from escrow record directly via a debug endpoint
        // For now, just abort with clear error message
        anyhow::bail!(
            "Cannot proceed with signing: masks not provided by prepare-sign.\n\
            The server needs to return commitment_mask and funding_mask in the prepare-sign response.\n\
            Check server/src/handlers/escrow.rs prepare_sign() function."
        );
    };

    // Compute pseudo_out = commitment_mask * G + amount * H
    let pseudo_out = ED25519_BASEPOINT_TABLE * &commitment_mask + *H * Scalar::from(real_amount);
    let pseudo_out_hex = hex::encode(pseudo_out.compress().as_bytes());
    println!("  Pseudo_out: {}...", &pseudo_out_hex[..16]);

    // Parse message (tx_prefix_hash)
    if tx_prefix_hash.is_empty() {
        anyhow::bail!("tx_prefix_hash is empty - cannot proceed with signing");
    }
    let message = hex_to_bytes(tx_prefix_hash);

    // Compute D point: D = (z - y) * Hp(P_π)
    // where z = funding_mask, y = commitment_mask, P_π is signer's public key
    // NOTE: D uses hash_to_point of the signer's pubkey, NOT the H generator!
    let mask_delta = funding_mask - commitment_mask;
    let signer_pubkey = ring_keys[signer_index];
    let hp_signer = monero_hash_to_point(signer_pubkey.compress().to_bytes());
    let d_point = mask_delta * hp_signer;
    let d_hex = hex::encode(d_point.compress().as_bytes());
    println!("  D point: {}...", &d_hex[..16]);
    println!("  (D = mask_delta * Hp(P_{signer_index}) )");

    // Compute D_inv8 = D / 8 (multiply by inverse of 8)
    // This is what the server uses in mu computation per clsag_verifier.rs
    let eight_inv = Scalar::from(8u64).invert();
    let d_inv8 = d_point * eight_inv;
    let d_inv8_hex = hex::encode(d_inv8.compress().as_bytes());
    println!("  D_inv8: {}...", &d_inv8_hex[..16]);

    // Compute mu_p and mu_c using CORRECT server-compatible functions
    // CRITICAL: Use d_inv8 (NOT message!), 32-byte padded domain separator
    let mu_p = clsag_agg_0(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );
    let mu_p_hex = hex::encode(mu_p.as_bytes());

    let mu_c = clsag_agg_1(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );
    let mu_c_hex = hex::encode(mu_c.as_bytes());

    println!("  mu_p: {}...", &mu_p_hex[..16]);
    println!("  mu_c: {}...", &mu_c_hex[..16]);

    // Compute derivation for vendor's signing key
    let view_key = hex_to_scalar(VIEW_KEY_PRIV);
    let tx_pubkey = hex_to_point(EXPECTED_TX_PUBKEY);
    let derivation = compute_derivation(&view_key, &tx_pubkey, OUTPUT_INDEX);

    // Vendor's effective secret: x_eff = d + λ_vendor * s_vendor
    // λ_vendor = -1 (for 2-of-3 with buyer+vendor)
    let vendor_share = hex_to_scalar(VENDOR_SHARE);
    let lambda_vendor = -Scalar::ONE;
    let x_vendor_weighted = lambda_vendor * vendor_share;
    let x_eff_vendor = derivation + x_vendor_weighted;

    println!("  Vendor x_eff computed");

    // Generate random alpha (nonce)
    let alpha = Scalar::random(&mut OsRng);

    // Compute R = alpha * G
    let r_public = ED25519_BASEPOINT_TABLE * &alpha;

    // Compute R' = alpha * Hp(P) where P is our public key (ring_keys[signer_index])
    let p_bytes = ring_keys[signer_index].compress().to_bytes();
    let hp_p = monero_hash_to_point(p_bytes);
    let r_prime = alpha * hp_p;

    println!("  Alpha nonce generated");
    println!(
        "  L_π (alpha*G): {}...",
        hex::encode(&r_public.compress().as_bytes()[..8])
    );
    println!(
        "  R_π (alpha*Hp(P)): {}...",
        hex::encode(&r_prime.compress().as_bytes()[..8])
    );

    // CLSAG RING COMPUTATION (first signer partial)
    // Start at signer_index+1, go around the ring
    let n = ring_keys.len();
    let mut s_values: Vec<Scalar> = vec![Scalar::ZERO; n];
    let mut c = Scalar::ZERO;

    // Compute c_{π+1}
    // CLSAG_hash = Hs(prefix || P || C || L || R)
    // where L = alpha*G, R = alpha*Hp(P)

    // Build prefix for round hashes
    // CRITICAL: CLSAG_round hash uses D/8 (d_inv8), NOT D!
    // v0.57.0 FIX: Domain separator MUST be 32 bytes padded (Monero uses rct::key = 32 bytes)
    let mut prefix = Vec::new();
    let mut domain_round = [0u8; 32];
    domain_round[..11].copy_from_slice(b"CLSAG_round");
    prefix.extend_from_slice(&domain_round);
    for p in &ring_keys {
        prefix.extend_from_slice(p.compress().as_bytes());
    }
    for cm in &ring_commitments {
        prefix.extend_from_slice(cm.compress().as_bytes());
    }
    prefix.extend_from_slice(pseudo_out.compress().as_bytes());
    prefix.extend_from_slice(&message);
    prefix.extend_from_slice(key_image.compress().as_bytes());
    prefix.extend_from_slice(d_inv8.compress().as_bytes());

    // c_{π+1} = H(prefix || L_π || R_π) where L_π = α*G, R_π = α*Hp(P_π)
    let l_pi = r_public;
    let r_pi = r_prime;

    let mut round_hasher = Keccak256::new();
    round_hasher.update(&prefix);
    round_hasher.update(l_pi.compress().as_bytes());
    round_hasher.update(r_pi.compress().as_bytes());
    let c_next: [u8; 32] = round_hasher.finalize().into();
    c = Scalar::from_bytes_mod_order(c_next);

    // CLSAG stores c_1 (challenge AFTER processing index 0, going INTO index 1)
    // The c we have NOW is c_0 (output from signer at π=15).
    // We'll save c1 AFTER the first iteration of the loop (when idx=0 is processed).
    let mut c1 = Scalar::ZERO; // Will be set in loop

    // Go around the ring from (signer_index+1) to (signer_index-1)
    for i in 1..n {
        let idx = (signer_index + i) % n;

        // Generate random s for this position
        s_values[idx] = Scalar::random(&mut OsRng);
        let s = s_values[idx];

        // L = s*G + c*(mu_p*P + mu_c*(C - pseudo_out))
        let p_point = ring_keys[idx];
        let c_point = ring_commitments[idx];
        let c_minus_pseudo = c_point - pseudo_out;

        let combined = mu_p * p_point + mu_c * c_minus_pseudo;
        let l_point = ED25519_BASEPOINT_TABLE * &s + c * combined;

        // R = s*Hp(P) + c*(mu_p*I + mu_c*D)
        let hp_pi = monero_hash_to_point(p_point.compress().to_bytes());
        let combined_r = mu_p * key_image + mu_c * d_point;
        let r_point = s * hp_pi + c * combined_r;

        // c_{next}
        let mut round_hasher = Keccak256::new();
        round_hasher.update(&prefix);
        round_hasher.update(l_point.compress().as_bytes());
        round_hasher.update(r_point.compress().as_bytes());
        let c_next_arr: [u8; 32] = round_hasher.finalize().into();
        c = Scalar::from_bytes_mod_order(c_next_arr);

        // Save c1 AFTER processing idx=0 (when i=1)
        // This is c_1 = challenge going INTO index 1
        if idx == 0 {
            c1 = c;
            println!(
                "  Saved c1 after processing idx=0: {}...",
                hex::encode(&c1.as_bytes()[..8])
            );
        }
    }

    // The c we have now is c_π (at our position)
    // s_π = alpha - c_π * (mu_p * x_eff + mu_c * (z - mask))
    let c_pi = c;
    println!(
        "  c_π (for s_pi computation): {}...",
        hex::encode(&c_pi.as_bytes()[..8])
    );
    let s_pi = alpha - c_pi * (mu_p * x_eff_vendor + mu_c * mask_delta);
    s_values[signer_index] = s_pi;
    println!(
        "  s_π (vendor partial): {}...",
        hex::encode(&s_pi.as_bytes()[..8])
    );

    let c1_hex = hex::encode(c1.as_bytes());

    println!("  c1: {}...", &c1_hex[..16]);

    // ========================================================================
    // LOCAL CLSAG VERIFICATION (before submitting to server)
    // ========================================================================
    println!("\n  === LOCAL CLSAG VERIFICATION ===");

    // For vendor-only partial signature, we can't fully verify yet
    // But we CAN verify the ring computation is consistent

    // Recompute c1 by going around the ring starting from c_{π+1}
    let mut verify_c = Scalar::ZERO;

    // Start from position (signer_index + 1)
    // First, compute c_{π+1} using our L_π and R_π
    let mut verify_hasher = Keccak256::new();
    verify_hasher.update(&prefix);
    verify_hasher.update(l_pi.compress().as_bytes());
    verify_hasher.update(r_pi.compress().as_bytes());
    let verify_c_next: [u8; 32] = verify_hasher.finalize().into();
    verify_c = Scalar::from_bytes_mod_order(verify_c_next);

    println!(
        "    Starting verification from c_{} = {}...",
        (signer_index + 1) % n,
        hex::encode(&verify_c.as_bytes()[..8])
    );

    let mut verify_c1: Option<Scalar> = None;

    for i in 1..n {
        let idx = (signer_index + i) % n;
        let s = s_values[idx];

        // L = s*G + c*(mu_p*P + mu_c*(C - pseudo_out))
        let p_point = ring_keys[idx];
        let c_point = ring_commitments[idx];
        let c_minus_pseudo = c_point - pseudo_out;

        let combined = mu_p * p_point + mu_c * c_minus_pseudo;
        let l_point = ED25519_BASEPOINT_TABLE * &s + verify_c * combined;

        // R = s*Hp(P) + c*(mu_p*I + mu_c*D)
        let hp_pi = monero_hash_to_point(p_point.compress().to_bytes());
        let combined_r = mu_p * key_image + mu_c * d_point;
        let r_point = s * hp_pi + verify_c * combined_r;

        // c_{next}
        let mut round_hasher = Keccak256::new();
        round_hasher.update(&prefix);
        round_hasher.update(l_point.compress().as_bytes());
        round_hasher.update(r_point.compress().as_bytes());
        let c_next_arr: [u8; 32] = round_hasher.finalize().into();
        verify_c = Scalar::from_bytes_mod_order(c_next_arr);

        // Track c1 (challenge at index 1)
        if idx == 0 && verify_c1.is_none() {
            verify_c1 = Some(verify_c);
            println!(
                "    idx=0 processed → c_1 = {}...",
                hex::encode(&verify_c.as_bytes()[..8])
            );
        }
    }

    // Now verify_c should be c_π (the challenge at signer's position)
    println!(
        "    After loop: c_π = {}...",
        hex::encode(&verify_c.as_bytes()[..8])
    );
    println!(
        "    Expected c_π = {}...",
        hex::encode(&c_pi.as_bytes()[..8])
    );

    if verify_c == c_pi {
        println!("    ✓ Ring closure verified - c_π matches!");
    } else {
        println!("    ❌ Ring closure FAILED - c_π mismatch!");
        println!("      This means the s_values or ring computation has a bug.");
    }

    // Verify c1 matches
    if let Some(vc1) = verify_c1 {
        println!(
            "    Verification c1: {}...",
            hex::encode(&vc1.as_bytes()[..8])
        );
        println!(
            "    Stored c1:       {}...",
            hex::encode(&c1.as_bytes()[..8])
        );
        if vc1 == c1 {
            println!("    ✓ c1 matches!");
        } else {
            println!("    ❌ c1 MISMATCH!");
        }
    }

    // Full ring verification: start from c1 and verify we get back to c1
    println!("\n    --- Full ring verification from c1 ---");
    let mut full_c = c1;

    for idx in 0..n {
        let s = s_values[idx];

        // Special case: at signer_index, use the partial s with our alpha
        // For vendor-only, s_pi is partial (doesn't include buyer's key)
        // So full verification will FAIL - that's expected!

        let p_point = ring_keys[idx];
        let c_point = ring_commitments[idx];
        let c_minus_pseudo = c_point - pseudo_out;

        // L = s*G + c*(mu_p*P + mu_c*(C - pseudo_out))
        let combined = mu_p * p_point + mu_c * c_minus_pseudo;
        let l_point = ED25519_BASEPOINT_TABLE * &s + full_c * combined;

        // R = s*Hp(P) + c*(mu_p*I + mu_c*D)
        let hp_pi = monero_hash_to_point(p_point.compress().to_bytes());
        let combined_r = mu_p * key_image + mu_c * d_point;
        let r_point = s * hp_pi + full_c * combined_r;

        // c_{next}
        let mut round_hasher = Keccak256::new();
        round_hasher.update(&prefix);
        round_hasher.update(l_point.compress().as_bytes());
        round_hasher.update(r_point.compress().as_bytes());
        let c_next_arr: [u8; 32] = round_hasher.finalize().into();
        full_c = Scalar::from_bytes_mod_order(c_next_arr);

        if idx == signer_index {
            println!(
                "    idx={} (SIGNER): L={}..., R={}...",
                idx,
                hex::encode(&l_point.compress().as_bytes()[..8]),
                hex::encode(&r_point.compress().as_bytes()[..8])
            );
        }
    }

    // After full loop, full_c should equal c1 for a valid signature
    println!(
        "    After full ring: c = {}...",
        hex::encode(&full_c.as_bytes()[..8])
    );
    println!(
        "    Expected c1:     {}...",
        hex::encode(&c1.as_bytes()[..8])
    );

    if full_c == c1 {
        println!("    ✓ FULL SIGNATURE VERIFIED (vendor-only) - This is unexpected!");
    } else {
        println!("    ⚠️  Full verification fails (expected for partial signature)");
    }

    println!("  === END VERIFICATION ===\n");

    // Create PartialTx
    let s_values_hex: Vec<String> = s_values.iter().map(|s| hex::encode(s.as_bytes())).collect();

    // Encrypt alpha for buyer (simplified - just hex encode for test)
    let alpha_encrypted = hex::encode(alpha.as_bytes());

    let partial_tx = PartialTx {
        ring_size: n as u8,
        signer_index: signer_index as u8,
        s_values: s_values_hex,
        c1: c1_hex.clone(),
        // CRITICAL: Submit D/8 (d_inv8) NOT D - server expects D/8 in CLSAG signature
        d: d_inv8_hex.clone(),
        pseudo_out: pseudo_out_hex.clone(),
        key_image: key_image_hex.to_string(),
        alpha_encrypted,
        signer1_public: hex::encode(ring_keys[signer_index].compress().as_bytes()),
        c_p: hex::encode((c_pi * mu_p).as_bytes()),
        c_c: hex::encode((c_pi * mu_c).as_bytes()),
        mu_p: mu_p_hex.clone(),
        mu_c: mu_c_hex.clone(),
    };

    let partial_tx_json = serde_json::to_string(&partial_tx)?;
    println!("  PartialTx computed");

    // ========================================================================
    // STEP 7: Submit vendor signature
    // ========================================================================
    println!("\n[7/9] Submitting vendor signature...");

    let sign_init_url = format!("{SERVER_URL}/api/v2/escrow/{ESCROW_ID}/sign/init");
    let sign_init_req = SignInitRequest {
        role: "vendor".to_string(),
        partial_tx: partial_tx_json.clone(),
    };

    let resp = vendor_client
        .post(&sign_init_url)
        .json(&sign_init_req)
        .send()
        .await
        .context("Failed to submit vendor signature")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        println!("  ✓ Vendor signature submitted");
    } else {
        println!("  ❌ Vendor sign_init FAILED ({status}): {body}");
    }

    // ========================================================================
    // STEP 8: Buyer completes signature
    // ========================================================================
    println!("\n[8/9] Buyer completing CLSAG...");

    // For buyer, we need to:
    // 1. Get the partial_tx from server (via prepare-sign)
    // 2. Decrypt alpha
    // 3. Add buyer's contribution to s_π
    // This is complex - let's at least call prepare-sign to verify state

    let prepare_url = format!("{SERVER_URL}/api/v2/escrow/{ESCROW_ID}/prepare-sign");
    let resp = buyer_client
        .get(&prepare_url)
        .send()
        .await
        .context("Failed to call prepare-sign for buyer")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        let resp_json: Value = serde_json::from_str(&body)?;
        if resp_json.get("first_signer_c1").is_some() {
            println!("  ✓ Buyer sees first_signer data - ready to complete");

            // Buyer's effective secret: x_eff = λ_buyer * s_buyer (NO derivation)
            let buyer_share = hex_to_scalar(BUYER_SHARE);
            let lambda_buyer = Scalar::from(2u64);
            let x_eff_buyer = lambda_buyer * buyer_share;

            // Buyer needs to add their contribution:
            // s_π_final = s_π - c_π * (mu_p * x_eff_buyer)
            // But we also need the encrypted alpha...

            // For this test, let's create the completed CLSAG directly
            // s_π_complete = s_π + buyer_contribution
            // Actually: s_π_complete = alpha - c_π * (mu_p * (x_eff_vendor + x_eff_buyer) + mu_c * mask_delta)

            // Since we have alpha, we can compute the complete signature
            let x_total = x_eff_vendor + x_eff_buyer;
            let s_pi_complete = alpha - c_pi * (mu_p * x_total + mu_c * mask_delta);

            let mut s_values_complete = s_values.clone();
            s_values_complete[signer_index] = s_pi_complete;

            // =================================================================
            // VERIFY COMPLETE SIGNATURE LOCALLY
            // =================================================================
            println!("\n    === VERIFYING COMPLETE CLSAG (with buyer contribution) ===");

            // Full ring verification with complete s_values
            // IMPORTANT: CLSAG verification starts from c1 and processes indices 1, 2, ..., n-1, 0
            // NOT 0, 1, 2, ..., n-1!
            let mut verify_complete_c = c1;

            for i in 0..n {
                // Process in CLSAG order: 1, 2, 3, ..., n-1, 0
                let idx = (i + 1) % n;
                let s = s_values_complete[idx];
                let c_input = verify_complete_c; // Save c before update

                let p_point = ring_keys[idx];
                let c_point = ring_commitments[idx];
                let c_minus_pseudo = c_point - pseudo_out;

                // L = s*G + c*(mu_p*P + mu_c*(C - pseudo_out))
                let combined = mu_p * p_point + mu_c * c_minus_pseudo;
                let l_point = ED25519_BASEPOINT_TABLE * &s + c_input * combined;

                // R = s*Hp(P) + c*(mu_p*I + mu_c*D)
                let hp_pi = monero_hash_to_point(p_point.compress().to_bytes());
                let combined_r = mu_p * key_image + mu_c * d_point;
                let r_point = s * hp_pi + c_input * combined_r;

                // c_{next}
                let mut round_hasher = Keccak256::new();
                round_hasher.update(&prefix);
                round_hasher.update(l_point.compress().as_bytes());
                round_hasher.update(r_point.compress().as_bytes());
                let c_next_arr: [u8; 32] = round_hasher.finalize().into();
                verify_complete_c = Scalar::from_bytes_mod_order(c_next_arr);

                if idx == signer_index {
                    println!("      idx={idx} (SIGNER):");
                    println!("        s_π = {}...", hex::encode(&s.as_bytes()[..8]));
                    println!(
                        "        c_π (input) = {}...",
                        hex::encode(&c_input.as_bytes()[..8])
                    );
                    println!(
                        "        L (computed) = {}...",
                        hex::encode(&l_point.compress().as_bytes()[..8])
                    );
                    println!(
                        "        R (computed) = {}...",
                        hex::encode(&r_point.compress().as_bytes()[..8])
                    );
                    println!(
                        "        c_next = {}...",
                        hex::encode(&verify_complete_c.as_bytes()[..8])
                    );

                    // Check individual components
                    println!("\n        --- Component check ---");
                    let s_g = ED25519_BASEPOINT_TABLE * &s;
                    println!(
                        "        s*G = {}...",
                        hex::encode(&s_g.compress().as_bytes()[..8])
                    );
                    println!(
                        "        c*combined_L = {}...",
                        hex::encode(&(c_input * combined).compress().as_bytes()[..8])
                    );
                    let s_hp = s * hp_pi;
                    println!(
                        "        s*Hp(P) = {}...",
                        hex::encode(&s_hp.compress().as_bytes()[..8])
                    );
                    println!(
                        "        c*combined_R = {}...",
                        hex::encode(&(c_input * combined_r).compress().as_bytes()[..8])
                    );
                }
            }

            println!(
                "      After full ring: c = {}...",
                hex::encode(&verify_complete_c.as_bytes()[..8])
            );
            println!(
                "      Expected c1:     {}...",
                hex::encode(&c1.as_bytes()[..8])
            );

            if verify_complete_c == c1 {
                println!("      ✅ COMPLETE SIGNATURE VERIFIED LOCALLY!");
            } else {
                println!("      ❌ COMPLETE SIGNATURE VERIFICATION FAILED!");
                println!("         The signature is MATHEMATICALLY INCORRECT.");
                println!("         Debugging:");
                println!("         - Check x_total = x_eff_vendor + x_eff_buyer computation");
                println!("         - Check mask_delta computation");
                println!("         - Check key_image matches the ring computation");

                // Extra debug: Check key relationships
                println!("\n      --- Key relationship check ---");
                let expected_p = &x_total * ED25519_BASEPOINT_TABLE;
                let actual_p = ring_keys[signer_index];
                println!(
                    "        Expected P (x_total*G): {}...",
                    hex::encode(&expected_p.compress().as_bytes()[..16])
                );
                println!(
                    "        Actual P[signer_idx]:   {}...",
                    hex::encode(&actual_p.compress().as_bytes()[..16])
                );
                if expected_p == actual_p {
                    println!("        ✓ Keys match!");
                } else {
                    println!("        ❌ Keys DON'T match - this is the bug!");
                    println!("           x_total doesn't correspond to P[signer_index]");
                }
            }
            println!("    === END COMPLETE VERIFICATION ===\n");

            // v0.57.0 DIAGNOSTIC: Print values in same format as server for comparison
            println!("\n    === v0.57.0 DIAG: VALUES TO COMPARE WITH SERVER ===");
            println!(
                "    s0:              {}",
                hex::encode(s_values_complete[0].as_bytes())
            );
            println!(
                "    s_signer (s15):  {}",
                hex::encode(s_values_complete[15].as_bytes())
            );
            println!("    c1_input:        {c1_hex}");
            println!("    d_inv8:          {d_inv8_hex}");
            println!("    key_image:       {key_image_hex}");
            println!("    pseudo_out:      {pseudo_out_hex}");
            println!("    tx_prefix:       {tx_prefix_hash}");
            println!(
                "    ring_key_0:      {}",
                hex::encode(ring_keys[0].compress().as_bytes())
            );
            println!(
                "    ring_key_15:     {}",
                hex::encode(ring_keys[15].compress().as_bytes())
            );
            println!(
                "    ring_commit_0:   {}",
                hex::encode(ring_commitments[0].compress().as_bytes())
            );
            println!(
                "    ring_commit_15:  {}",
                hex::encode(ring_commitments[15].compress().as_bytes())
            );
            println!("    mu_p FULL:       {mu_p_hex}");
            println!("    mu_c FULL:       {mu_c_hex}");
            println!("    === END v0.57.0 DIAG ===\n");

            let completed = CompletedClsag {
                s_values: s_values_complete
                    .iter()
                    .map(|s| hex::encode(s.as_bytes()))
                    .collect(),
                c1: c1_hex.clone(),
                // CRITICAL: Submit D/8 (d_inv8) NOT D - server expects D/8 in CLSAG signature
                d: d_inv8_hex.clone(),
                key_image: key_image_hex.to_string(),
                pseudo_out: pseudo_out_hex.clone(),
            };

            let completed_json = serde_json::to_string(&completed)?;

            // Submit completed signature
            let sign_complete_url = format!("{SERVER_URL}/api/v2/escrow/{ESCROW_ID}/sign/complete");
            let sign_complete_req = SignCompleteRequest {
                role: "buyer".to_string(),
                completed_clsag: completed_json,
            };

            let resp = buyer_client
                .post(&sign_complete_url)
                .json(&sign_complete_req)
                .send()
                .await
                .context("Failed to submit buyer signature")?;

            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status.is_success() {
                println!("  ✓ Buyer signature submitted - CLSAG complete!");
            } else {
                println!("  ❌ Buyer sign_complete FAILED ({status}): {body}");
            }
        } else {
            println!("  ⚠️  No first_signer data yet");
        }
    } else {
        println!("  ❌ Buyer prepare-sign FAILED ({status}): {body}");
    }

    // ========================================================================
    // STEP 9: Broadcast
    // ========================================================================
    println!("\n[9/9] Broadcasting transaction...");

    let broadcast_url = format!("{SERVER_URL}/api/v2/escrow/{ESCROW_ID}/broadcast-tx");
    let resp = vendor_client
        .post(&broadcast_url)
        .send()
        .await
        .context("Failed to broadcast")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        println!("  ✅ BROADCAST SUCCESS!");
        let resp_json: Value = serde_json::from_str(&body).unwrap_or_default();
        if let Some(tx_hash) = resp_json["tx_hash"].as_str() {
            println!("  TX Hash: {tx_hash}");
        }
    } else {
        println!("  ❌ BROADCAST FAILED ({status})");
        println!("  Response: {body}");
    }

    println!("\n========================================");
    println!("TEST COMPLETE");
    println!("========================================");

    Ok(())
}
