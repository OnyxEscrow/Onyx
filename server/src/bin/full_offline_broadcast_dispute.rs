//! Full Offline Broadcast DISPUTE - FROST CLSAG Signing for Arbiter Resolution
//!
//! This binary is SEPARATE from full_offline_broadcast to preserve the happy path.
//! Used ONLY for dispute resolution when arbiter resolves in favor of buyer or vendor.
//!
//! Key difference: Uses arbiter(index=3) + winner(buyer=1 or vendor=2) Lagrange coefficients
//! instead of buyer(1) + vendor(2) coefficients.
//!
//! Lagrange coefficients for FROST 2-of-3:
//! - buyer(1) + vendor(2): λ_buyer=2, λ_vendor=-1
//! - arbiter(3) + buyer(1): λ_arbiter=-1/2, λ_buyer=3/2
//! - arbiter(3) + vendor(2): λ_arbiter=-2, λ_vendor=3
//!
//! Usage: cargo run --release --bin full_offline_broadcast_dispute <escrow_id> <arbiter_share_hex> <winner_share_hex> <payout_address> <signing_pair> [--broadcast]
//! signing_pair: "arbiter_buyer" or "arbiter_vendor"

use anyhow::{Context, Result, bail};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use monero_generators_mirror::hash_to_point;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::env;

// Platform fee configuration (validated at startup)
use server::config::{get_platform_wallet_address, get_release_fee_bps, get_refund_fee_bps};

// Import transaction builder
use server::services::transaction_builder::{
    MoneroTransactionBuilder, ClsagSignatureJson, ClientSignature, BuildResult,
    parse_monero_address, generate_stealth_address_with_view_tag,
    generate_tx_pubkey, encrypt_amount_ecdh, derive_output_mask,
    compute_pedersen_commitment, validate_frost_pair,
};

// Import ring selection with Gamma distribution (Monero-compliant)
use server::services::ring_selection::RingSelector;

// Network configuration - reads from environment
// MONERO_get_daemon_url(): Full URL to daemon RPC (e.g., "http://127.0.0.1:18081" for mainnet)
// TX_FEE_ATOMIC: Transaction fee in atomic units (default: 50_000_000 = 0.00005 XMR)
const RING_SIZE: usize = 16;

fn get_daemon_url() -> String {
    std::env::var("MONERO_get_daemon_url()")
        .unwrap_or_else(|_| {
            // Fallback based on MONERO_NETWORK
            let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
            match network.as_str() {
                "mainnet" => "http://127.0.0.1:18081".to_string(),
                "testnet" => "http://127.0.0.1:28081".to_string(),
                _ => "http://127.0.0.1:38081".to_string(), // stagenet default
            }
        })
}

fn get_tx_fee() -> u64 {
    std::env::var("TX_FEE_ATOMIC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000_000) // 0.00005 XMR default for mainnet
}

// ============================================================================
// Database connection (SQLCipher encrypted)
// ============================================================================

#[derive(Debug, Clone)]
struct SqlCipherConnectionCustomizer {
    encryption_key: String,
}

impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqlCipherConnectionCustomizer {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> std::result::Result<(), diesel::r2d2::Error> {
        diesel::sql_query(format!("PRAGMA key = '{}';", self.encryption_key))
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
}

fn establish_connection() -> Result<r2d2::PooledConnection<ConnectionManager<SqliteConnection>>> {
    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY not set in .env")?;

    let manager = ConnectionManager::<SqliteConnection>::new(&database_url);
    let customizer = SqlCipherConnectionCustomizer { encryption_key };
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(customizer))
        .build(manager)?;

    pool.get().context("Failed to get database connection")
}

// ============================================================================
// Escrow data from DB
// ============================================================================

#[derive(Debug)]
struct EscrowData {
    id: String,
    // View key (from server - shared among all parties)
    view_key_private: String,
    // Funding info
    funding_tx_hash: String,
    funding_output_index: i32,
    funding_global_index: i64,
    funding_commitment_mask: String,
    funding_tx_pubkey: String,
    // Amount
    amount: i64,
    // FROST group public key (to derive one-time output pubkey)
    frost_group_pubkey: String,
}

fn load_escrow_data(conn: &mut SqliteConnection, escrow_id: &str) -> Result<EscrowData> {
    use diesel::sql_query;
    use diesel::sql_types::Text;

    #[derive(QueryableByName, Debug)]
    struct EscrowRow {
        #[diesel(sql_type = Text)]
        id: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        multisig_view_key: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        funding_tx_hash: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Integer>)]
        funding_output_index: Option<i32>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
        funding_global_index: Option<i64>,
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        funding_commitment_mask: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        funding_tx_pubkey: Option<String>,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        amount: i64,
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        frost_group_pubkey: Option<String>,
    }

    let query = format!(
        "SELECT id, multisig_view_key, \
         funding_tx_hash, funding_output_index, funding_global_index, \
         funding_commitment_mask, funding_tx_pubkey, \
         amount, frost_group_pubkey \
         FROM escrows WHERE id = '{}'",
        escrow_id
    );

    let rows: Vec<EscrowRow> = sql_query(&query)
        .load(conn)
        .context("Failed to query escrow")?;

    let row = rows.into_iter().next()
        .ok_or_else(|| anyhow::anyhow!("Escrow not found: {}", escrow_id))?;

    Ok(EscrowData {
        id: row.id,
        view_key_private: row.multisig_view_key
            .ok_or_else(|| anyhow::anyhow!("Missing multisig_view_key"))?,
        funding_tx_hash: row.funding_tx_hash
            .ok_or_else(|| anyhow::anyhow!("Missing funding_tx_hash"))?,
        funding_output_index: row.funding_output_index
            .ok_or_else(|| anyhow::anyhow!("Missing funding_output_index"))?,
        funding_global_index: row.funding_global_index
            .ok_or_else(|| anyhow::anyhow!("Missing funding_global_index"))?,
        funding_commitment_mask: row.funding_commitment_mask
            .ok_or_else(|| anyhow::anyhow!("Missing funding_commitment_mask"))?,
        funding_tx_pubkey: row.funding_tx_pubkey
            .ok_or_else(|| anyhow::anyhow!("Missing funding_tx_pubkey"))?,
        amount: row.amount,
        frost_group_pubkey: row.frost_group_pubkey
            .ok_or_else(|| anyhow::anyhow!("Missing frost_group_pubkey (DKG not complete?)"))?,
    })
}

// ============================================================================
// Crypto helpers
// ============================================================================

fn hex_to_scalar(hex: &str) -> Result<Scalar> {
    let bytes = hex::decode(hex).context("Invalid hex for scalar")?;
    if bytes.len() != 32 {
        bail!("Scalar must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Scalar::from_bytes_mod_order(arr))
}

fn hex_to_point(hex: &str) -> Result<EdwardsPoint> {
    let bytes = hex::decode(hex).context("Invalid hex for point")?;
    if bytes.len() != 32 {
        bail!("Point must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid Edwards point"))
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

fn compute_lagrange_coefficient(my_index: u8, other_index: u8) -> Scalar {
    let i = Scalar::from(my_index as u64);
    let j = Scalar::from(other_index as u64);
    j * (j - i).invert()
}

fn compute_derivation(view_key: &Scalar, tx_pubkey: &EdwardsPoint, output_index: u64) -> Scalar {
    let shared_secret = (view_key * tx_pubkey).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    hasher.update(&encode_varint(output_index));
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

// ============================================================================
// RPC types
// ============================================================================

#[derive(Serialize)]
struct GetOutsParams {
    outputs: Vec<OutputIndex>,
    get_txid: bool,
}

#[derive(Serialize)]
struct OutputIndex {
    amount: u64,
    index: u64,
}

#[derive(Deserialize)]
struct GetOutsResult {
    outs: Vec<OutEntry>,
    status: String,
}

#[derive(Deserialize, Clone, Debug)]
struct OutEntry {
    key: String,
    mask: String,
    unlocked: bool,
    height: u64,
}

#[derive(Serialize)]
struct SubmitTxParams {
    tx_as_hex: String,
}

#[derive(Deserialize, Debug)]
struct SubmitTxResult {
    status: String,
    reason: Option<String>,
}

// ============================================================================
// Ring fetching with proper decoy selection
// ============================================================================

/// Fetch ring members AND return the indices used
/// CRITICAL (Bug 8.1 fix): Returns indices to ensure CLSAG and TX builder use the SAME ring
async fn fetch_ring_members(client: &reqwest::Client, real_index: u64) -> Result<(Vec<OutEntry>, Vec<u64>, usize)> {
    // Generate decoys using Gamma distribution (Monero-compliant)
    // Parameters: α=19.28, θ=1.61 derived from empirical spend time analysis
    let mut indices: Vec<u64> = Vec::with_capacity(RING_SIZE);

    // Use RingSelector with gamma distribution for EAE-attack resistance
    let selector = RingSelector::new();
    // Estimate total outputs (use real_index * 2 as upper bound for stagenet)
    let total_outputs = real_index.saturating_mul(2).max(1_000_000);
    let decoy_indices = selector.select_decoys_by_offset(real_index, total_outputs, RING_SIZE - 1);

    for idx in decoy_indices {
        if idx != real_index && !indices.contains(&idx) && idx > 0 {
            indices.push(idx);
        }
    }

    // Ensure we have exactly RING_SIZE - 1 unique decoys
    let mut fallback = real_index.saturating_sub(1);
    while indices.len() < RING_SIZE - 1 {
        if fallback != real_index && !indices.contains(&fallback) && fallback > 0 {
            indices.push(fallback);
        }
        fallback = fallback.saturating_sub(1);
        if fallback == 0 {
            bail!("Cannot generate enough unique decoys");
        }
    }

    // Add real output and sort
    indices.push(real_index);
    indices.sort();
    indices.dedup();

    if indices.len() != RING_SIZE {
        bail!("Ring size mismatch: expected {}, got {}", RING_SIZE, indices.len());
    }

    let real_position = indices.iter().position(|&x| x == real_index)
        .ok_or_else(|| anyhow::anyhow!("Real index not in ring"))?;

    println!("Ring indices: {:?}", indices);
    println!("Real output at position: {}", real_position);

    // Fetch outputs from daemon
    let params = GetOutsParams {
        outputs: indices.iter().map(|&i| OutputIndex { amount: 0, index: i }).collect(),
        get_txid: true,
    };

    let response = client
        .post(&format!("{}/get_outs", get_daemon_url()))
        .json(&params)
        .send()
        .await
        .context("Failed to fetch ring members")?;

    let result: GetOutsResult = response.json().await.context("Failed to parse get_outs response")?;

    if result.status != "OK" {
        bail!("get_outs failed: {}", result.status);
    }

    if result.outs.len() != RING_SIZE {
        bail!("Expected {} ring members, got {}", RING_SIZE, result.outs.len());
    }

    // Return indices along with outputs (Bug 8.1 fix)
    Ok((result.outs, indices, real_position))
}

// ============================================================================
// CLSAG Signing (Complete implementation)
// ============================================================================

struct ClsagSignature {
    s: Vec<[u8; 32]>,
    c1: [u8; 32],
    d: [u8; 32],
}

// Monero domain separators (from monero_inflation_checker)
// All padded to 32 bytes with zeros when used in hash
const CLSAG_DOMAIN: &[u8] = b"CLSAG_round";  // Round hash domain (11 bytes)
const CLSAG_AGG_0: &[u8] = b"CLSAG_agg_0";   // mu_P domain (11 bytes)
const CLSAG_AGG_1: &[u8] = b"CLSAG_agg_1";   // mu_C domain (11 bytes)

/// Compute CLSAG mixing coefficients mu_P and mu_C
/// Reference: clsag_hash_agg() in rctSigs.cpp
fn compute_mixing_coefficients(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    // Domain separators ARE padded to 32 bytes with zeros (confirmed from Monero Python impl)
    let mut domain_agg_0 = [0u8; 32];
    domain_agg_0[..CLSAG_AGG_0.len()].copy_from_slice(CLSAG_AGG_0);

    let mut domain_agg_1 = [0u8; 32];
    domain_agg_1[..CLSAG_AGG_1.len()].copy_from_slice(CLSAG_AGG_1);

    // mu_P = H(CLSAG_agg_0 || ring_keys || ring_commitments || I || D/8 || pseudo_out)
    let mut hasher_p = Keccak256::new();
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
    let mu_p = Scalar::from_bytes_mod_order(hasher_p.finalize().into());

    // mu_C = H(CLSAG_agg_1 || ring_keys || ring_commitments || I || D/8 || pseudo_out)
    let mut hasher_c = Keccak256::new();
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
    let mu_c = Scalar::from_bytes_mod_order(hasher_c.finalize().into());

    (mu_p, mu_c)
}

/// Compute CLSAG round hash (challenge for next position)
/// CORRECT ORDER per Monero source: domain || P || C || C_offset || message || L || R
/// NOTE: I (key_image) and D are NOT included in round hash - only in aggregation coefficients
fn compute_round_hash(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    pseudo_out: &EdwardsPoint,
    tx_prefix_hash: &[u8; 32],
    _key_image: &EdwardsPoint,  // Not used in round hash (kept for API compatibility)
    _d_inv8: &EdwardsPoint,     // Not used in round hash (kept for API compatibility)
    l_point: &EdwardsPoint,
    r_point: &EdwardsPoint,
) -> Scalar {
    // Domain separator is padded to 32 bytes with zeros (confirmed from Monero impl)
    let mut domain = [0u8; 32];
    domain[..CLSAG_DOMAIN.len()].copy_from_slice(CLSAG_DOMAIN);

    let mut hasher = Keccak256::new();
    hasher.update(&domain);
    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher.update(commitment.compress().as_bytes());
    }
    hasher.update(pseudo_out.compress().as_bytes());
    hasher.update(tx_prefix_hash);
    // NOTE: I and D are NOT hashed here - only in μ_P and μ_C computation
    hasher.update(l_point.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());

    Scalar::from_bytes_mod_order(hasher.finalize().into())
}

/// Sign CLSAG using FROST 2-of-3 threshold shares
/// Proper CLSAG with mu_P and mu_C aggregation coefficients
fn sign_clsag(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    real_index: usize,
    x_total: &Scalar,           // d + λ₁*b₁ + λ₂*b₂ (full private key)
    z_diff: &Scalar,            // z_input - z_pseudo (commitment mask difference)
    key_image: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
    tx_prefix_hash: &[u8; 32],
) -> Result<ClsagSignature> {
    use rand::RngCore;

    let ring_size = ring_keys.len();
    if ring_size != RING_SIZE {
        bail!("Ring size must be {}, got {}", RING_SIZE, ring_size);
    }

    let p = &ring_keys[real_index];
    let hp_p = hash_to_point(p.compress().to_bytes());

    // D = z_diff * Hp(P) where z_diff is mask difference (or just mask if pseudo_out uses different mask)
    // For our case: pseudo_out = input_commitment (same mask), so z_diff = 0 and D = identity
    // But we still compute it properly
    let d_full = z_diff * hp_p;
    let d_inv8 = d_full * Scalar::from(8u64).invert();  // D/8 for serialization

    // Compute mu_P and mu_C
    let (mu_p, mu_c) = compute_mixing_coefficients(
        ring_keys,
        ring_commitments,
        key_image,
        &d_inv8,
        pseudo_out,
    );

    println!("   mu_P: {}...", hex::encode(&mu_p.to_bytes()[..8]));
    println!("   mu_C: {}...", hex::encode(&mu_c.to_bytes()[..8]));

    // Precompute Hp(P[i]) for all ring members
    let hp_values: Vec<EdwardsPoint> = ring_keys.iter()
        .map(|key| hash_to_point(key.compress().to_bytes()))
        .collect();

    // Generate random nonces α and α_c
    let alpha: Scalar = {
        let mut rng_bytes = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut rng_bytes);
        Scalar::from_bytes_mod_order_wide(&rng_bytes)
    };

    // Initialize all s-values with random scalars
    let mut s_values: Vec<Scalar> = (0..ring_size)
        .map(|_| {
            let mut bytes = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut bytes);
            Scalar::from_bytes_mod_order_wide(&bytes)
        })
        .collect();

    // L[real] = α*G (for key part)
    let l_real = &alpha * ED25519_BASEPOINT_TABLE;
    // R[real] = α*Hp(P) (for key part)
    let r_real = alpha * hp_p;

    // Compute c[(real+1) % n] from L[real], R[real] using proper round hash
    let c_start = compute_round_hash(
        ring_keys,
        ring_commitments,
        pseudo_out,
        tx_prefix_hash,
        key_image,
        &d_inv8,
        &l_real,
        &r_real,
    );

    // Process the ring: start from (real+1), go around to real
    // CLSAG order: real+1, real+2, ..., n-1, 0, 1, ..., real-1, then solve for s[real]
    let mut c_current = c_start;

    for step in 0..(ring_size - 1) {
        let i = (real_index + 1 + step) % ring_size;
        let next = (i + 1) % ring_size;

        let p_i = &ring_keys[i];
        let c_i = &ring_commitments[i];
        let hp_i = &hp_values[i];
        let s_i = s_values[i];

        // c_p = mu_P * c_current
        let c_p = mu_p * c_current;
        // c_c = mu_C * c_current
        let c_c = mu_c * c_current;

        // L[i] = s[i]*G + c_p*P[i] + c_c*(C[i] - pseudo_out)
        let c_adjusted = c_i - pseudo_out;
        let l_i = &s_i * ED25519_BASEPOINT_TABLE + c_p * p_i + c_c * c_adjusted;

        // R[i] = s[i]*Hp(P[i]) + c_p*I + c_c*D
        let r_i = s_i * hp_i + c_p * key_image + c_c * d_full;

        // Compute next challenge
        c_current = compute_round_hash(
            ring_keys,
            ring_commitments,
            pseudo_out,
            tx_prefix_hash,
            key_image,
            &d_inv8,
            &l_i,
            &r_i,
        );

        // Store c[next] for verification (c[0] is what we need for c1)
        if next == 0 {
            // This will be our c1
        }
    }

    // c_current is now c[real] (the challenge going INTO position real)
    let c_real = c_current;

    // Compute s[real] to close the ring
    // s[real] = α - c_p*x - c_c*z_diff
    // where c_p = mu_P * c[real] and c_c = mu_C * c[real]
    let c_p_real = mu_p * c_real;
    let c_c_real = mu_c * c_real;
    s_values[real_index] = alpha - c_p_real * x_total - c_c_real * z_diff;

    // Verify: L[real] should equal s[real]*G + c_p*P[real] + c_c*(C[real] - pseudo_out)
    let p_real = &ring_keys[real_index];
    let c_real_commitment = &ring_commitments[real_index];
    let c_adjusted_real = c_real_commitment - pseudo_out;
    let l_verify = &s_values[real_index] * ED25519_BASEPOINT_TABLE + c_p_real * p_real + c_c_real * c_adjusted_real;

    if l_verify != l_real {
        println!("WARNING: L verification failed at real index!");
        println!("L_verify: {}", hex::encode(l_verify.compress().as_bytes()));
        println!("L_real:   {}", hex::encode(l_real.compress().as_bytes()));
    } else {
        println!("   ✅ L verification passed");
    }

    // Now we need to compute c1 by running through the ring one more time
    // to get the challenge at index 0
    // Actually, we already have c[real+1] as c_start, so c1 is computed during the loop
    // Let me reconsider: c1 is the challenge at index 1, not index 0

    // In CLSAG, c1 is stored as the challenge going INTO index 1
    // We computed: c_start = c[(real+1) % n]
    // If real = 15 (last position), then c_start = c[0] which is c going INTO index 0
    // But we need c going INTO index 1

    // Let me recompute: run the FULL verification loop to get c1
    let mut c_verify = c_start;
    let mut c1_computed = Scalar::ZERO;

    for step in 0..ring_size {
        let i = (real_index + 1 + step) % ring_size;
        let _next = (i + 1) % ring_size;

        // Store c1 when we're at index 0 (c going into index 1)
        if i == 0 {
            // c_verify is now c[0], which means c going INTO index 0
            // Actually for CLSAG c1 convention, we need the challenge after processing index 0
        }

        let p_i = &ring_keys[i];
        let c_i = &ring_commitments[i];
        let hp_i = &hp_values[i];
        let s_i = s_values[i];

        let c_p = mu_p * c_verify;
        let c_c = mu_c * c_verify;

        let c_adjusted = c_i - pseudo_out;
        let l_i = &s_i * ED25519_BASEPOINT_TABLE + c_p * p_i + c_c * c_adjusted;
        let r_i = s_i * hp_i + c_p * key_image + c_c * d_full;

        c_verify = compute_round_hash(
            ring_keys,
            ring_commitments,
            pseudo_out,
            tx_prefix_hash,
            key_image,
            &d_inv8,
            &l_i,
            &r_i,
        );

        // c_verify after processing index 0 is c[1] (challenge going INTO index 1)
        if i == 0 {
            c1_computed = c_verify;
        }
    }

    // After full loop, c_verify should equal c_start (ring closes)
    if c_verify != c_start {
        println!("WARNING: Ring doesn't close!");
        println!("c_final:   {}", hex::encode(c_verify.to_bytes()));
        println!("c_start:   {}", hex::encode(c_start.to_bytes()));
    } else {
        println!("   ✅ Ring closed successfully");
    }

    // Convert to bytes
    let s_bytes: Vec<[u8; 32]> = s_values.iter()
        .map(|s| s.to_bytes())
        .collect();

    // CRITICAL FIX: c1 is the challenge ENTERING index 0, NOT the challenge after processing index 0!
    // c_start is computed from L[real], R[real] and is the challenge entering (real+1) % n = index 0
    // c1_computed was WRONG - it was the challenge entering index 1 (after processing index 0)
    let c1 = c_start.to_bytes();
    let d = d_inv8.compress().to_bytes();  // D/8 is what gets serialized

    Ok(ClsagSignature { s: s_bytes, c1, d })
}

// ============================================================================
// Transaction building
// ============================================================================

async fn broadcast_transaction(client: &reqwest::Client, tx_hex: &str) -> Result<String> {
    let params = SubmitTxParams {
        tx_as_hex: tx_hex.to_string(),
    };

    let response = client
        .post(&format!("{}/sendrawtransaction", get_daemon_url()))
        .json(&params)
        .send()
        .await
        .context("Failed to submit transaction")?;

    let result: SubmitTxResult = response.json().await
        .context("Failed to parse submit response")?;

    if result.status == "OK" {
        Ok("Transaction submitted successfully".to_string())
    } else {
        bail!("Transaction rejected: {} - {:?}", result.status, result.reason)
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        println!("Usage: {} <escrow_id> <arbiter_share_hex> <winner_share_hex> <payout_address> <signing_pair> [--broadcast]", args[0]);
        println!("\nDISPUTE RESOLUTION BINARY - Used only for arbiter resolutions.");
        println!("\nArguments:");
        println!("  arbiter_share_hex: Arbiter's FROST secret share");
        println!("  winner_share_hex:  Winner's (buyer or vendor) FROST secret share");
        println!("  payout_address:    Destination address for funds");
        println!("  signing_pair:      'arbiter_buyer' or 'arbiter_vendor'");
        println!("\nLagrange coefficients:");
        println!("  arbiter_buyer:  λ_arbiter=-1/2, λ_buyer=3/2");
        println!("  arbiter_vendor: λ_arbiter=-2,   λ_vendor=3");
        return Ok(());
    }

    let escrow_id = &args[1];
    let arbiter_share_hex = &args[2];
    let winner_share_hex = &args[3];
    let payout_address = &args[4];
    let signing_pair = &args[5];

    // Validate signing_pair
    if signing_pair != "arbiter_buyer" && signing_pair != "arbiter_vendor" {
        bail!("Invalid signing_pair: '{}'. Must be 'arbiter_buyer' or 'arbiter_vendor'", signing_pair);
    }

    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║     DISPUTE RESOLUTION FROST CLSAG BROADCAST                             ║");
    println!("║     Mode: {} (arbiter + {})                      ║",
        signing_pair,
        if signing_pair == "arbiter_buyer" { "buyer" } else { "vendor" });
    println!("║     Escrow: {}                         ║", &escrow_id[..36.min(escrow_id.len())]);
    println!("╚══════════════════════════════════════════════════════════════════════════╝\n");

    // Step 1: Load escrow data from database
    println!("=== STEP 1: Load Escrow Data from Database ===\n");

    let mut conn = establish_connection()?;
    let escrow = load_escrow_data(&mut *conn, escrow_id)?;

    println!("✅ Escrow loaded: {}", escrow.id);
    println!("   Amount: {} atomic ({:.6} XMR)", escrow.amount, escrow.amount as f64 / 1e12);
    println!("   Funding TX: {}...{}", &escrow.funding_tx_hash[..8], &escrow.funding_tx_hash[56..]);
    println!("   Global index: {}", escrow.funding_global_index);
    println!("   FROST Group Pubkey: {}...", &escrow.frost_group_pubkey[..16]);
    println!("   Destination: {}...{}", &payout_address[..8], &payout_address[payout_address.len()-8..]);

    // Step 2: Parse crypto data
    println!("\n=== STEP 2: Parse Cryptographic Data ===\n");

    let view_key = hex_to_scalar(&escrow.view_key_private)?;
    let tx_pubkey = hex_to_point(&escrow.funding_tx_pubkey)?;
    let b_arbiter = hex_to_scalar(arbiter_share_hex)?;
    let b_winner = hex_to_scalar(winner_share_hex)?;
    let funding_mask = hex_to_scalar(&escrow.funding_commitment_mask)?;
    let group_pubkey = hex_to_point(&escrow.frost_group_pubkey)?;

    println!("Arbiter share: {}...", &arbiter_share_hex[..16]);
    println!("Winner share:  {}...", &winner_share_hex[..16]);
    println!("Signing pair:  {}", signing_pair);

    // Step 2.5: FROST Share Validation (CRITICAL FOR DISPUTE RESOLUTION)
    println!("\n=== STEP 2.5: Validate FROST Shares Against Group Pubkey ===\n");

    let (arbiter_index, winner_index): (u16, u16) = match signing_pair.as_str() {
        "arbiter_buyer" => (3, 1),   // arbiter=3, buyer=1
        "arbiter_vendor" => (3, 2),  // arbiter=3, vendor=2
        _ => bail!("Invalid signing_pair"),
    };

    // Validate that provided shares reconstruct to the stored group pubkey
    match validate_frost_pair(
        arbiter_share_hex,
        winner_share_hex,
        arbiter_index,
        winner_index,
        &escrow.frost_group_pubkey,
    ) {
        Ok(true) => {
            println!("✅ FROST share validation PASSED");
            println!("   Shares reconstruct to correct group pubkey");
            println!("   Indices: arbiter={}, winner={}", arbiter_index, winner_index);
        }
        Ok(false) => {
            println!("❌ FROST share validation FAILED!");
            println!("   The provided shares do NOT reconstruct to the stored group pubkey.");
            println!("   This typically means:");
            println!("   1. The shares are from a different DKG session");
            println!("   2. The shares were not generated correctly during DKG");
            println!("   3. The polynomial constraint is not satisfied");
            println!("\n   Expected group pubkey: {}...", &escrow.frost_group_pubkey[..16]);
            println!("   Signing pair: {} (arbiter=3, winner={})", signing_pair, winner_index);
            bail!("FROST share validation failed - shares don't match group pubkey. Cannot proceed with signing.");
        }
        Err(e) => {
            println!("❌ FROST share validation error: {}", e);
            bail!("FROST share validation error: {}", e);
        }
    }

    // FROST participant indices:
    // buyer=1, vendor=2, arbiter=3
    //
    // Lagrange coefficient formula: λ_i = Π_{j≠i} (j / (j - i))
    // For 2-of-3, with participants i and j:
    // λ_i = j / (j - i)
    // λ_j = i / (i - j)
    //
    // arbiter(3) + buyer(1):
    //   λ_arbiter = 1 / (1 - 3) = 1 / (-2) = -1/2
    //   λ_buyer   = 3 / (3 - 1) = 3 / 2   = 3/2
    //
    // arbiter(3) + vendor(2):
    //   λ_arbiter = 2 / (2 - 3) = 2 / (-1) = -2
    //   λ_vendor  = 3 / (3 - 2) = 3 / 1   = 3
    let (lambda_arbiter, lambda_winner, _winner_index) = match signing_pair.as_str() {
        "arbiter_buyer" => {
            // arbiter(3) + buyer(1)
            let lambda_a = compute_lagrange_coefficient(3, 1); // j=1, i=3 -> 1/(1-3) = -1/2
            let lambda_w = compute_lagrange_coefficient(1, 3); // j=3, i=1 -> 3/(3-1) = 3/2
            println!("λ_arbiter = -1/2, λ_buyer = 3/2");
            (lambda_a, lambda_w, 1u8)
        }
        "arbiter_vendor" => {
            // arbiter(3) + vendor(2)
            let lambda_a = compute_lagrange_coefficient(3, 2); // j=2, i=3 -> 2/(2-3) = -2
            let lambda_w = compute_lagrange_coefficient(2, 3); // j=3, i=2 -> 3/(3-2) = 3
            println!("λ_arbiter = -2, λ_vendor = 3");
            (lambda_a, lambda_w, 2u8)
        }
        _ => bail!("Invalid signing_pair"),
    };

    // Log the actual scalar values for debugging
    println!("λ_arbiter scalar: {}...", hex::encode(&lambda_arbiter.to_bytes()[..8]));
    println!("λ_winner scalar:  {}...", hex::encode(&lambda_winner.to_bytes()[..8]));

    // Compute derivation and full private key
    // x_total = d + λ_arbiter * b_arbiter + λ_winner * b_winner
    let d = compute_derivation(&view_key, &tx_pubkey, escrow.funding_output_index as u64);
    let x_total = d + lambda_arbiter * b_arbiter + lambda_winner * b_winner;
    println!("Derivation d: {}...", hex::encode(&d.to_bytes()[..8]));

    // Compute expected one-time output public key: P = d*G + B (where B = group_pubkey)
    let d_g = &d * ED25519_BASEPOINT_TABLE;
    let p_expected = d_g + group_pubkey;
    println!("One-time output pubkey P: {}", hex::encode(p_expected.compress().as_bytes()));

    // Verify x_total * G = P
    let p_computed = &x_total * ED25519_BASEPOINT_TABLE;
    if p_computed != p_expected {
        println!("WARNING: x_total * G != P - checking intermediate values...");
        println!("  d*G:           {}", hex::encode(d_g.compress().as_bytes()));
        println!("  B (group):     {}", hex::encode(group_pubkey.compress().as_bytes()));
        println!("  x_total * G:   {}", hex::encode(p_computed.compress().as_bytes()));
        println!("  P expected:    {}", hex::encode(p_expected.compress().as_bytes()));

        // Check if the Lagrange aggregation matches group pubkey
        // For dispute: λ_arbiter * b_arbiter + λ_winner * b_winner should equal group secret key
        let lagrange_sum = &(lambda_arbiter * b_arbiter + lambda_winner * b_winner) * ED25519_BASEPOINT_TABLE;
        println!("  (λ_arbiter*b_arbiter + λ_winner*b_winner)*G: {}", hex::encode(lagrange_sum.compress().as_bytes()));
        println!("  Signing pair: {} (indices: arbiter=3, winner={})", signing_pair,
            if signing_pair == "arbiter_buyer" { 1 } else { 2 });

        if lagrange_sum != group_pubkey {
            bail!("CRITICAL: Lagrange shares don't match group pubkey! Verify shares and signing_pair are correct.");
        }
    } else {
        println!("✅ x_total * G = P verified (dispute mode: {})", signing_pair);
    }

    // Compute key image
    let hp_p = hash_to_point(p_expected.compress().to_bytes());
    let key_image = x_total * hp_p;
    println!("✅ Key image: {}", hex::encode(key_image.compress().as_bytes()));

    // Step 3: Fetch ring members
    println!("\n=== STEP 3: Fetch Ring Members from Daemon ===\n");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // =========================================================================
    // v0.73.0: Platform Fee Calculation (2 REAL outputs) - DISPUTE PATH
    // =========================================================================
    let input_amount = escrow.amount as u64;

    // For disputes: arbiter_buyer = refund (3%), arbiter_vendor = release to vendor (5%)
    let is_refund = signing_pair == "arbiter_buyer";

    // Platform fee configuration (validated via config module)
    let platform_wallet = get_platform_wallet_address()
        .context("Platform wallet not configured - check PLATFORM_FEE_WALLET in .env")?;

    let platform_fee_bps: u64 = if is_refund {
        get_refund_fee_bps()
    } else {
        get_release_fee_bps()
    };

    // Transaction fee from environment (default 0.00005 XMR for mainnet)
    let tx_fee = get_tx_fee();

    // Calculate amounts
    let platform_fee = (input_amount * platform_fee_bps) / 10000;
    let recipient_amount = input_amount.saturating_sub(platform_fee).saturating_sub(tx_fee);

    println!("[v0.73.0-DISPUTE] Platform Fee Configuration:");
    println!("   Type: {} (fee: {}%)", if is_refund { "REFUND" } else { "RELEASE" }, platform_fee_bps as f64 / 100.0);
    println!("   Platform wallet: {}...{}", &platform_wallet[..8], &platform_wallet[platform_wallet.len()-8..]);
    println!("Input amount:     {} atomic ({:.12} XMR)", input_amount, input_amount as f64 / 1e12);
    println!("Platform fee:     {} atomic ({:.12} XMR)", platform_fee, platform_fee as f64 / 1e12);
    println!("TX fee:           {} atomic ({:.12} XMR)", tx_fee, tx_fee as f64 / 1e12);
    println!("Recipient amount: {} atomic ({:.12} XMR)", recipient_amount, recipient_amount as f64 / 1e12);

    // Parse platform wallet address
    let (platform_spend_pub, platform_view_pub) = parse_monero_address(&platform_wallet)
        .context("Failed to parse platform wallet address")?;

    // Bug 8.1 fix: fetch_ring_members now returns indices to ensure CLSAG and TX use same ring
    let (ring_members, ring_indices, real_position) = fetch_ring_members(&client, escrow.funding_global_index as u64).await?;

    // Verify real output matches the derived one-time pubkey
    let real_key = &ring_members[real_position].key;
    let p_expected_hex = hex::encode(p_expected.compress().as_bytes());
    if real_key != &p_expected_hex {
        println!("WARNING: Ring member key doesn't match derived one-time pubkey!");
        println!("  Expected (derived): {}", p_expected_hex);
        println!("  From daemon:        {}", real_key);
    } else {
        println!("✅ Real output verified at position {}", real_position);
    }

    // Parse ring data
    let ring_keys: Vec<EdwardsPoint> = ring_members.iter()
        .map(|o| hex_to_point(&o.key))
        .collect::<Result<Vec<_>>>()?;

    let ring_commitments: Vec<EdwardsPoint> = ring_members.iter()
        .map(|o| hex_to_point(&o.mask))
        .collect::<Result<Vec<_>>>()?;

    // CRITICAL: Verify funding_mask matches on-chain commitment before proceeding
    // This catches the Bug 2.20: Wrong output_index causing CLSAG invalid_input
    println!("\n=== MASK VERIFICATION (Bug 2.20 Prevention) ===\n");
    let h_bytes_check: [u8; 32] = [
        0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
        0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
        0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
        0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
    ];
    let h_point_check = CompressedEdwardsY(h_bytes_check).decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid H point for mask verification"))?;

    let expected_commitment = &funding_mask * ED25519_BASEPOINT_TABLE
        + Scalar::from(escrow.amount as u64) * h_point_check;
    let onchain_commitment = ring_commitments[real_position];

    if expected_commitment != onchain_commitment {
        println!("❌ CRITICAL ERROR: Funding mask does not match on-chain commitment!");
        println!("   Expected C = funding_mask * G + amount * H:");
        println!("   {} ", hex::encode(expected_commitment.compress().as_bytes()));
        println!("   On-chain commitment (from daemon):");
        println!("   {}", hex::encode(onchain_commitment.compress().as_bytes()));
        println!();
        println!("   This is Bug 2.20: The stored funding_commitment_mask was derived");
        println!("   using the WRONG output_index. The mask is unique per output.");
        println!();
        println!("   FIX: Re-derive the mask with the correct output_index:");
        println!("   1. Run: ./target/release/verify_commitment to find correct values");
        println!("   2. Update DB: ./target/release/fix_escrow <escrow_id>");
        println!("   3. Or re-fund the escrow with a new transaction");
        bail!("Mask verification failed - cannot create valid CLSAG signature");
    }
    println!("✅ Funding mask verified: C = funding_mask * G + amount * H matches on-chain");

    // Step 4: Parse destination address and generate TX keys
    println!("\n=== STEP 4: Parse Destination & Generate TX Keys ===\n");

    // Parse payout address to get spend/view pubkeys
    let (recipient_spend_pub, recipient_view_pub) = parse_monero_address(payout_address)
        .context("Failed to parse payout address")?;

    println!("Recipient spend pubkey: {}...", hex::encode(&recipient_spend_pub[..8]));
    println!("Recipient view pubkey:  {}...", hex::encode(&recipient_view_pub[..8]));

    // Generate random TX secret key (r)
    let tx_secret_key: [u8; 32] = {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        // Reduce to valid scalar
        let scalar = Scalar::from_bytes_mod_order(bytes);
        scalar.to_bytes()
    };

    // TX public key R = r * G
    let tx_pubkey = generate_tx_pubkey(&tx_secret_key);
    println!("TX pubkey (R): {}", hex::encode(&tx_pubkey));

    // Step 5: Generate output stealth addresses and commitments (2 REAL outputs)
    println!("\n=== STEP 5: Generate Outputs (2 REAL) ===\n");

    // Output 0: Real output to recipient (winner of dispute)
    let output_index_0: u64 = 0;
    let (stealth_address_0, view_tag_0) = generate_stealth_address_with_view_tag(
        &tx_secret_key,
        &recipient_spend_pub,
        &recipient_view_pub,
        output_index_0,
    ).context("Failed to generate stealth address")?;

    println!("Output 0 (recipient): stealth_address = {}...", hex::encode(&stealth_address_0[..8]));
    println!("Output 0 (recipient): view_tag = 0x{:02x}", view_tag_0);

    // Derive mask for output 0
    let mask_0 = derive_output_mask(&tx_secret_key, &recipient_view_pub, output_index_0)
        .context("Failed to derive output mask")?;

    // Commitment for output 0: C = mask*G + recipient_amount*H
    let commitment_0 = compute_pedersen_commitment(&mask_0, recipient_amount)
        .context("Failed to compute commitment")?;

    // Encrypt amount for output 0 (using RECIPIENT's view key)
    let encrypted_amount_0 = encrypt_amount_ecdh(
        &tx_secret_key,
        &recipient_view_pub,
        output_index_0,
        recipient_amount,
    ).context("Failed to encrypt amount")?;

    println!("Output 0 (recipient): commitment = {}...", hex::encode(&commitment_0[..8]));
    println!("Output 0 (recipient): amount = {} atomic", recipient_amount);

    // Output 1: Platform fee (REAL output, NOT dummy!)
    let output_index_1: u64 = 1;
    let (stealth_address_1, view_tag_1) = generate_stealth_address_with_view_tag(
        &tx_secret_key,
        &platform_spend_pub,
        &platform_view_pub,
        output_index_1,
    ).context("Failed to generate platform stealth address")?;

    // Derive mask for output 1 using PLATFORM's view key (critical for platform to decrypt!)
    let mask_1 = derive_output_mask(&tx_secret_key, &platform_view_pub, output_index_1)
        .context("Failed to derive platform output mask")?;

    // Commitment for output 1: C = mask*G + platform_fee*H
    let commitment_1 = compute_pedersen_commitment(&mask_1, platform_fee)
        .context("Failed to compute platform commitment")?;

    // Encrypt amount for output 1 (using PLATFORM's view key)
    let encrypted_amount_1 = encrypt_amount_ecdh(
        &tx_secret_key,
        &platform_view_pub,
        output_index_1,
        platform_fee,
    ).context("Failed to encrypt platform amount")?;

    println!("Output 1 (platform): stealth_address = {}...", hex::encode(&stealth_address_1[..8]));
    println!("Output 1 (platform): view_tag = 0x{:02x}", view_tag_1);
    println!("Output 1 (platform): commitment = {}...", hex::encode(&commitment_1[..8]));
    println!("Output 1 (platform): amount = {} atomic", platform_fee);

    // =========================================================================
    // Commitment Balance with 2 REAL outputs (v0.73.0-DISPUTE)
    // =========================================================================
    // pseudo_out = pseudo_mask * G + input_amount * H
    // out0 = mask_0 * G + recipient_amount * H
    // out1 = mask_1 * G + platform_fee * H
    // fee_commitment = 0 * G + fee * H (implicit)
    //
    // Balance: pseudo_out = out0 + out1 + fee * H
    //   pseudo_mask * G + input_amount * H = mask_0 * G + recipient_amount * H + mask_1 * G + platform_fee * H + fee * H
    //   Since input_amount = recipient_amount + platform_fee + fee:
    //   pseudo_mask = mask_0 + mask_1
    // =========================================================================

    // Step 6: Compute pseudo_out and build transaction prefix
    println!("\n=== STEP 6: Build Transaction Prefix ===\n");

    let h_bytes: [u8; 32] = [
        0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
        0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
        0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
        0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
    ];
    let h_point = CompressedEdwardsY(h_bytes).decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid H point"))?;

    // ==========================================================================
    // BUG FIX v0.73.0-DISPUTE: DO NOT use random pseudo_mask!
    // ==========================================================================
    // Use pseudo_mask = mask_0 + mask_1 (same as happy path v0.72.0)
    // This ensures the platform wallet can verify and scan the output.
    //
    // z_diff = funding_mask - pseudo_mask is naturally non-zero because
    // funding_mask (from escrow funding) is independent of our output masks
    // ==========================================================================

    let mask_0_scalar = Scalar::from_bytes_mod_order(mask_0);
    let mask_1_scalar = Scalar::from_bytes_mod_order(mask_1);

    // pseudo_mask = mask_0 + mask_1 (for commitment balance)
    // NO random offset - it was breaking the platform output verification!
    let pseudo_mask = mask_0_scalar + mask_1_scalar;

    // Use original commitment_1 and mask_1 (NOT adjusted!)
    // The wallet expects: commitment_1 = mask_1 * G + platform_fee * H
    let commitment_1_final = commitment_1;
    let mask_1_final = mask_1;

    println!("[v0.73.0-DISPUTE-FIX] Using ORIGINAL masks (no random offset)");
    println!("[v0.73.0-DISPUTE-FIX] z_diff will be non-zero because funding_mask != pseudo_mask");

    let pseudo_out = &pseudo_mask * ED25519_BASEPOINT_TABLE + Scalar::from(input_amount) * h_point;
    let pseudo_out_bytes = pseudo_out.compress().to_bytes();
    println!("pseudo_out (deterministic mask): {}", hex::encode(&pseudo_out_bytes));

    // Verify commitment balance
    let out0_point = CompressedEdwardsY(commitment_0).decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid commitment_0"))?;
    let out1_point = CompressedEdwardsY(commitment_1_final).decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid commitment_1"))?;
    let fee_h = Scalar::from(tx_fee) * h_point;

    let expected_pseudo = out0_point + out1_point + fee_h;
    if expected_pseudo.compress() == pseudo_out.compress() {
        println!("✅ Commitment balance verified: pseudo_out == out0 + out1 + fee*H");
    } else {
        println!("WARNING: Commitment balance mismatch!");
        println!("  Expected: {}", hex::encode(expected_pseudo.compress().as_bytes()));
        println!("  Actual:   {}", hex::encode(pseudo_out.compress().as_bytes()));
    }

    // Build MoneroTransactionBuilder for proper tx_prefix
    let mut tx_builder = MoneroTransactionBuilder::new();
    tx_builder.set_fee(tx_fee);

    // Use the SAME ring indices that were used for CLSAG signing (critical!)
    tx_builder.add_input(
        key_image.compress().to_bytes(),
        &ring_indices,
    ).context("Failed to add input")?;

    // Add output 0 (recipient - REAL)
    tx_builder.add_output(
        stealth_address_0,
        commitment_0,
        encrypted_amount_0,
        mask_0,
        recipient_amount,
        view_tag_0,
    );

    // Add output 1 (platform fee - REAL)
    tx_builder.add_output(
        stealth_address_1,
        commitment_1_final,
        encrypted_amount_1,
        mask_1_final,
        platform_fee,
        view_tag_1,
    );

    // Set TX pubkey
    tx_builder.set_tx_pubkey(&tx_pubkey);

    println!("[v0.73.0-DISPUTE] Added 2 REAL outputs: recipient ({} atomic) + platform ({} atomic)", recipient_amount, platform_fee);

    // Step 7: Prepare for signing and compute full CLSAG message
    println!("\n=== STEP 7: Prepare Signing & Compute CLSAG Message ===\n");

    // Generate Bulletproof+ BEFORE computing the CLSAG message
    // This is required because the CLSAG message includes the hash of the BP+ data
    tx_builder.prepare_for_signing()
        .context("Failed to prepare transaction for signing")?;
    println!("✅ Bulletproof+ generated");

    // Compute the FULL CLSAG message (get_pre_mlsag_hash)
    // This is: hash(tx_prefix_hash || ss_hash || pseudo_outs_hash)
    let clsag_message = tx_builder.compute_clsag_message(&[pseudo_out_bytes])
        .context("Failed to compute CLSAG message")?;

    println!("CLSAG message (get_pre_mlsag_hash): {}", hex::encode(&clsag_message));
    println!("NOTE: This is NOT just tx_prefix_hash, but includes BP+ and pseudo_outs hashes");

    // Step 8: Sign CLSAG with the FULL message
    println!("\n=== STEP 8: CLSAG Signature ===\n");

    // z_diff = z_input - z_pseudo = funding_mask - pseudo_mask (non-zero!)
    // This creates a valid D point: D = z_diff * Hp(P) != identity
    let z_diff = funding_mask - pseudo_mask;
    println!("z_diff (mask difference): {}...", hex::encode(&z_diff.to_bytes()[..8]));

    let signature = sign_clsag(
        &ring_keys,
        &ring_commitments,
        real_position,
        &x_total,
        &z_diff,
        &key_image,
        &pseudo_out,
        &clsag_message,  // Use FULL CLSAG message, not just tx_prefix_hash
    )?;

    println!("✅ CLSAG signature computed");
    println!("   c1: {}...", hex::encode(&signature.c1[..8]));
    println!("   s[0]: {}...", hex::encode(&signature.s[0][..8]));
    println!("   s[real]: {}...", hex::encode(&signature.s[real_position][..8]));
    println!("   D/8: {}...", hex::encode(&signature.d[..8]));

    // Step 9: Attach signature and build complete transaction
    println!("\n=== STEP 9: Build Complete Transaction ===\n");

    // Convert CLSAG signature to ClientSignature format
    let clsag_json = ClsagSignatureJson {
        d: hex::encode(&signature.d),
        s: signature.s.iter().map(|s| hex::encode(s)).collect(),
        c1: hex::encode(&signature.c1),
    };

    let client_sig = ClientSignature {
        signature: clsag_json,
        key_image: hex::encode(key_image.compress().as_bytes()),
        partial_key_image: None,
        pseudo_out: hex::encode(&pseudo_out_bytes),
    };

    // Attach CLSAG to builder
    tx_builder.attach_clsag(&client_sig)
        .context("Failed to attach CLSAG signature")?;

    // Build complete transaction (generates Bulletproof+ and serializes)
    println!("Building transaction with Bulletproof+ range proof...");
    let build_result: BuildResult = tx_builder.build()
        .context("Failed to build transaction")?;

    let tx_hex = &build_result.tx_hex;
    let tx_hash = build_result.tx_hash;
    let tx_size = tx_hex.len() / 2; // hex is 2 chars per byte
    println!("✅ Transaction built successfully!");
    println!("   Size: {} bytes ({} hex chars)", tx_size, tx_hex.len());
    println!("   TX hex (first 64 chars): {}...", &tx_hex[..64.min(tx_hex.len())]);
    println!("   TX hash (correct): {}", hex::encode(&tx_hash));
    println!("   Hash components: prefix={}, base={}, prunable={}",
        hex::encode(&build_result.prefix_hash[..8]),
        hex::encode(&build_result.base_hash[..8]),
        hex::encode(&build_result.prunable_hash[..8])
    );

    // Save TX to file for debugging
    let tx_file = format!("/tmp/frost_tx_{}.hex", &escrow_id[..8]);
    std::fs::write(&tx_file, &tx_hex).context("Failed to write TX file")?;
    println!("   TX saved to: {}", tx_file);

    // Step 9: Broadcast (if flag provided)
    let should_broadcast = args.get(6).map(|s| s == "--broadcast").unwrap_or(false);

    println!("\n╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║                         TRANSACTION READY                                ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝\n");

    println!("Transaction details:");
    println!("  Escrow ID:      {}", escrow_id);
    println!("  Input:          {} atomic ({:.12} XMR)", input_amount, input_amount as f64 / 1e12);
    println!("  Recipient:      {} atomic ({:.12} XMR)", recipient_amount, recipient_amount as f64 / 1e12);
    println!("  Platform fee:   {} atomic ({:.12} XMR)", platform_fee, platform_fee as f64 / 1e12);
    println!("  TX fee:         {} atomic ({:.12} XMR)", tx_fee, tx_fee as f64 / 1e12);
    println!("  Key image:      {}...", hex::encode(&key_image.compress().as_bytes()[..8]));
    println!("  TX hash:        {}", hex::encode(&tx_hash));
    println!("  TX file:        {}", tx_file);
    println!("  Platform wallet: {}...{}", &platform_wallet[..8], &platform_wallet[platform_wallet.len()-8..]);
    println!();

    if should_broadcast {
        println!("=== STEP 10: Broadcasting to {} ===\n", get_daemon_url());

        match broadcast_transaction(&client, &tx_hex).await {
            Ok(msg) => {
                println!("✅ {}", msg);
                println!("\n🎉 TRANSACTION BROADCAST SUCCESSFUL!");
                println!("   TX hash: {}", hex::encode(&tx_hash));
                println!("   Check on block explorer after confirmation.");
            }
            Err(e) => {
                println!("❌ Broadcast failed: {}", e);
                println!("\n   TX saved to {} for manual inspection.", tx_file);
                println!("   You can try broadcasting manually with:");
                println!("   curl -X POST {}/sendrawtransaction -d '{{\"tx_as_hex\": \"{}\"}}' -H 'Content-Type: application/json'",
                    get_daemon_url(), &tx_hex[..64.min(tx_hex.len())]);
            }
        }
    } else {
        println!("⚠️  DRY RUN - Transaction NOT broadcast");
        println!("   Add --broadcast flag to actually broadcast:");
        println!("   cargo run --release --bin full_offline_broadcast_dispute {} {} {} {} {} --broadcast",
            escrow_id, arbiter_share_hex, winner_share_hex, payout_address, signing_pair);
    }

    Ok(())
}

// fetch_ring_indices removed - Bug 8.1 fix: indices now returned by fetch_ring_members
// to ensure CLSAG signature and TX builder use the SAME ring indices
