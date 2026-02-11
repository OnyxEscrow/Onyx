// FROST Signing Coordinator Service
//!
//! Coordinates CLSAG signing for FROST 2-of-3 multisig escrow.
//!
//! ## Atomic Signing Flow (from 835ccd0 — PROVEN WORKING on mainnet):
//! ```text
//! 1. Both parties submit their FROST secret shares to the server
//! 2. Server reconstructs x_total = d + λ₁*b₁ + λ₂*b₂
//! 3. Server signs CLSAG atomically (single call, identical to full_offline_broadcast.rs)
//! 4. Server builds TX with MoneroTransactionBuilder
//! 5. Server broadcasts via sendrawtransaction
//! ```
//!
//! This approach is identical to commit 835ccd0 which produced the first confirmed
//! mainnet FROST 2-of-3 escrow transaction (TX: 80c131432ac6ae44...).

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use diesel::prelude::*;
use monero_generators::hash_to_point;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tracing::{debug, error, info, warn};

use crate::config::{get_platform_wallet_address, get_refund_fee_bps, get_release_fee_bps};
use crate::schema::{escrows, frost_signing_state};
use crate::services::ring_selection::RingSelector;
use crate::services::transaction_builder::{
    compute_pedersen_commitment, derive_output_mask, encrypt_amount_ecdh,
    generate_stealth_address_with_view_tag, generate_tx_pubkey, parse_monero_address,
    ClientSignature, ClsagSignatureJson, MoneroTransactionBuilder,
};

const RING_SIZE: usize = 16;

/// TX signing data for client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSigningData {
    pub tx_prefix_hash: String,
    pub clsag_message_hash: String,
    pub ring_data_json: String,
    pub pseudo_out: Option<String>,
    pub recipient_address: String,
    pub amount_atomic: String,
    pub multisig_pubkey: String,
    /// pseudo_out_mask = mask_0 + mask_1 (hex) — needed by WASM as commitment_mask
    pub pseudo_out_mask: Option<String>,
    /// Input's commitment mask (z) from funding output — WASM needs as funding_mask
    pub funding_commitment_mask: Option<String>,
    /// Shared multisig view key (hex) — WASM needs for derivation: H_s(a·R || idx)
    pub multisig_view_key: Option<String>,
    /// TX public key from funding transaction (hex) — WASM needs for derivation
    pub funding_tx_pubkey: Option<String>,
    /// Output index in funding transaction — WASM needs for derivation
    pub funding_output_index: Option<i32>,
}

/// Nonce commitment (MuSig2-style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceCommitment {
    pub r_public: String,
    pub r_prime_public: String,
    pub commitment_hash: String,
}

/// Signing status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningStatus {
    pub status: String,
    pub buyer_nonce_submitted: bool,
    pub vendor_nonce_submitted: bool,
    pub buyer_partial_submitted: bool,
    pub vendor_partial_submitted: bool,
    pub arbiter_partial_submitted: bool,
    pub tx_hash: Option<String>,
}

// ============================================================================
// RPC types for daemon communication
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

#[derive(Deserialize, Clone, Debug, Serialize)]
struct OutEntry {
    key: String,
    mask: String,
    #[allow(dead_code)]
    unlocked: bool,
    #[allow(dead_code)]
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
    #[serde(default)]
    double_spend: bool,
    #[serde(default)]
    fee_too_low: bool,
    #[serde(default)]
    invalid_input: bool,
    #[serde(default)]
    invalid_output: bool,
    #[serde(default)]
    low_mixin: bool,
    #[serde(default)]
    not_relayed: bool,
    #[serde(default)]
    overspend: bool,
    #[serde(default)]
    sanity_check_failed: bool,
    #[serde(default)]
    too_big: bool,
    #[serde(default)]
    too_few_outputs: bool,
    #[serde(default)]
    tx_extra_too_big: bool,
}

// ============================================================================
// Helper functions
// ============================================================================

fn get_daemon_url() -> String {
    std::env::var("MONERO_DAEMON_URL").unwrap_or_else(|_| {
        let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        match network.as_str() {
            "mainnet" => "http://127.0.0.1:18081".to_string(),
            "testnet" => "http://127.0.0.1:28081".to_string(),
            _ => "http://127.0.0.1:38081".to_string(),
        }
    })
}

fn get_tx_fee() -> u64 {
    std::env::var("TX_FEE_ATOMIC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000_000) // 0.00005 XMR default
}

/// Decode hex to 32-byte array
fn hex_to_32(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("Invalid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("Expected 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Fetch ring members from daemon using gamma-distribution decoy selection
async fn fetch_ring_members(
    client: &reqwest::Client,
    real_index: u64,
) -> Result<(Vec<OutEntry>, Vec<u64>, usize)> {
    let selector = RingSelector::new();
    let total_outputs = real_index.saturating_mul(2).max(1_000_000);
    let decoy_indices = selector.select_decoys_by_offset(real_index, total_outputs, RING_SIZE - 1);

    let mut indices: Vec<u64> = Vec::with_capacity(RING_SIZE);
    for idx in decoy_indices {
        if idx != real_index && !indices.contains(&idx) && idx > 0 {
            indices.push(idx);
        }
    }

    // Ensure exactly RING_SIZE - 1 unique decoys
    let mut fallback = real_index.saturating_sub(1);
    while indices.len() < RING_SIZE - 1 {
        if fallback != real_index && !indices.contains(&fallback) && fallback > 0 {
            indices.push(fallback);
        }
        fallback = fallback.saturating_sub(1);
        if fallback == 0 {
            anyhow::bail!("Cannot generate enough unique decoys");
        }
    }

    indices.push(real_index);
    indices.sort();
    indices.dedup();

    if indices.len() != RING_SIZE {
        anyhow::bail!(
            "Ring size mismatch: expected {}, got {}",
            RING_SIZE,
            indices.len()
        );
    }

    let real_position = indices
        .iter()
        .position(|&x| x == real_index)
        .ok_or_else(|| anyhow::anyhow!("Real index not in ring"))?;

    let params = GetOutsParams {
        outputs: indices
            .iter()
            .map(|&i| OutputIndex {
                amount: 0,
                index: i,
            })
            .collect(),
        get_txid: true,
    };

    let response = client
        .post(format!("{}/get_outs", get_daemon_url()))
        .json(&params)
        .send()
        .await
        .context("Failed to fetch ring members from daemon")?;

    let result: GetOutsResult = response
        .json()
        .await
        .context("Failed to parse get_outs response")?;

    if result.status != "OK" {
        anyhow::bail!("get_outs failed: {}", result.status);
    }

    if result.outs.len() != RING_SIZE {
        anyhow::bail!(
            "Expected {} ring members, got {}",
            RING_SIZE,
            result.outs.len()
        );
    }

    Ok((result.outs, indices, real_position))
}

/// Check daemon connectivity before broadcast.
/// Returns (is_fully_synced, peer_count) for broadcast routing decisions.
async fn check_daemon_connectivity(
    client: &reqwest::Client,
    daemon_url: &str,
) -> Result<(bool, u32)> {
    #[derive(Deserialize)]
    struct GetInfoResult {
        #[serde(default)]
        incoming_connections_count: u32,
        #[serde(default)]
        outgoing_connections_count: u32,
        #[serde(default)]
        height: u64,
        #[serde(default)]
        height_without_bootstrap: u64,
        #[serde(default)]
        target_height: u64,
        #[serde(default)]
        synchronized: bool,
        #[serde(default)]
        untrusted: bool,
    }

    #[derive(Deserialize)]
    struct RpcResponse {
        result: Option<GetInfoResult>,
    }

    let response = client
        .post(format!("{daemon_url}/json_rpc"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_info"
        }))
        .send()
        .await
        .context("Failed to reach daemon for connectivity check")?;

    let rpc: RpcResponse = response
        .json()
        .await
        .context("Failed to parse daemon get_info response")?;

    let info = rpc.result.context("Missing result in get_info response")?;

    let total = info.outgoing_connections_count + info.incoming_connections_count;
    let local_behind = info.height_without_bootstrap > 0
        && info.height_without_bootstrap < info.height.saturating_sub(10);
    let is_synced = !local_behind && info.synchronized;

    if local_behind {
        warn!(
            height = info.height,
            height_without_bootstrap = info.height_without_bootstrap,
            blocks_behind = info.height.saturating_sub(info.height_without_bootstrap),
            "Local daemon NOT synced — using bootstrap proxy (height {} vs local {})",
            info.height,
            info.height_without_bootstrap
        );
    }

    if total == 0 {
        warn!(
            height = info.height,
            target_height = info.target_height,
            "Daemon {} reports 0 peer connections",
            daemon_url
        );
    } else {
        info!(
            outgoing = info.outgoing_connections_count,
            incoming = info.incoming_connections_count,
            height = info.height,
            synced = is_synced,
            "Daemon {} connectivity OK",
            daemon_url
        );
    }

    Ok((is_synced, total))
}

/// Get list of broadcast nodes: local first, then public fallbacks.
fn get_broadcast_nodes() -> Vec<String> {
    let local = get_daemon_url();
    let mut nodes = vec![local];

    // Public mainnet nodes as fallback for broadcasting
    // These are well-known community nodes with high uptime
    if let Ok(extra) = std::env::var("BROADCAST_FALLBACK_NODES") {
        for node in extra.split(',') {
            let trimmed = node.trim().to_string();
            if !trimmed.is_empty() {
                nodes.push(trimmed);
            }
        }
    } else {
        // Default public mainnet fallback nodes
        let network = std::env::var("MONERO_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        if network == "mainnet" {
            nodes.push("http://node.monero.world:18089".to_string());
            nodes.push("http://xmr-node.cakewallet.com:18081".to_string());
            nodes.push("http://node.community.rino.io:18081".to_string());
        }
    }
    nodes
}

/// Submit TX to a single node. Returns Ok(()) on success, Err on failure.
async fn submit_to_node(client: &reqwest::Client, node_url: &str, tx_hex: &str) -> Result<()> {
    let params = SubmitTxParams {
        tx_as_hex: tx_hex.to_string(),
    };

    let max_retries = 3;
    for attempt in 0..max_retries {
        let response = client
            .post(format!("{node_url}/sendrawtransaction"))
            .json(&params)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context(format!("Failed to reach {node_url}"))?;

        let result: SubmitTxResult = response
            .json()
            .await
            .context(format!("Failed to parse response from {node_url}"))?;

        // Log full response for debugging
        info!(
            node = node_url,
            status = %result.status,
            reason = ?result.reason,
            double_spend = result.double_spend,
            fee_too_low = result.fee_too_low,
            invalid_input = result.invalid_input,
            invalid_output = result.invalid_output,
            not_relayed = result.not_relayed,
            overspend = result.overspend,
            sanity_check_failed = result.sanity_check_failed,
            too_big = result.too_big,
            "sendrawtransaction response from {}", node_url
        );

        if result.status == "OK" {
            if result.not_relayed {
                warn!(
                    "TX accepted but NOT RELAYED by {} — will try other nodes",
                    node_url
                );
                return Err(anyhow::anyhow!(
                    "TX accepted but not_relayed=true on {node_url}"
                ));
            }
            info!(
                "TX accepted and relayed by {} (attempt {})",
                node_url,
                attempt + 1
            );
            return Ok(());
        }

        if result.status == "BUSY" {
            let delay = std::time::Duration::from_secs(2u64.pow(attempt as u32));
            warn!(attempt = attempt + 1, "Node {} BUSY, retrying", node_url);
            tokio::time::sleep(delay).await;
            continue;
        }

        // Permanent rejection — build detailed error
        let mut reasons = Vec::new();
        if result.double_spend {
            reasons.push("DOUBLE_SPEND");
        }
        if result.fee_too_low {
            reasons.push("FEE_TOO_LOW");
        }
        if result.invalid_input {
            reasons.push("INVALID_INPUT");
        }
        if result.invalid_output {
            reasons.push("INVALID_OUTPUT");
        }
        if result.overspend {
            reasons.push("OVERSPEND");
        }
        if result.sanity_check_failed {
            reasons.push("SANITY_CHECK_FAILED");
        }
        if result.too_big {
            reasons.push("TOO_BIG");
        }
        if result.too_few_outputs {
            reasons.push("TOO_FEW_OUTPUTS");
        }
        if result.low_mixin {
            reasons.push("LOW_MIXIN");
        }
        if result.tx_extra_too_big {
            reasons.push("TX_EXTRA_TOO_BIG");
        }

        let detail = if reasons.is_empty() {
            result.reason.unwrap_or_else(|| "unknown".to_string())
        } else {
            format!("{} (reason: {:?})", reasons.join(", "), result.reason)
        };

        anyhow::bail!(
            "TX rejected by {}: status={}, {}",
            node_url,
            result.status,
            detail
        );
    }

    anyhow::bail!("Node {node_url} BUSY after {max_retries} retries")
}

/// Broadcast raw transaction to daemon with multi-node fallback.
/// Tries local daemon first, then public nodes if local fails.
/// A permanent rejection (invalid_input, double_spend, etc.) is NOT retried on other nodes.
async fn broadcast_transaction(client: &reqwest::Client, tx_hex: &str) -> Result<()> {
    let nodes = get_broadcast_nodes();
    let local_url = get_daemon_url();

    // Check local daemon status first
    let (local_synced, local_peers) = check_daemon_connectivity(client, &local_url)
        .await
        .unwrap_or((false, 0));

    // Order: if local is synced with peers, try it first. Otherwise, try public nodes first.
    let ordered_nodes: Vec<&str> = if local_synced && local_peers > 0 {
        info!(
            "Local daemon synced with {} peers — broadcasting locally first",
            local_peers
        );
        nodes.iter().map(|s| s.as_str()).collect()
    } else {
        warn!(
            local_synced = local_synced,
            local_peers = local_peers,
            "Local daemon not ideal — trying public nodes first"
        );
        // Public nodes first, local last
        let mut ordered: Vec<&str> = nodes.iter().skip(1).map(|s| s.as_str()).collect();
        ordered.push(&local_url);
        ordered
    };

    let mut last_err = None;
    let mut accepted_count = 0u32;

    for node_url in &ordered_nodes {
        match submit_to_node(client, node_url, tx_hex).await {
            Ok(()) => {
                accepted_count += 1;
                info!(
                    "TX accepted by {} ({}/{})",
                    node_url,
                    accepted_count,
                    ordered_nodes.len()
                );
                // Try to submit to at least 2 nodes for redundancy
                if accepted_count >= 2 {
                    break;
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                // Permanent rejections = stop immediately (TX is invalid)
                if err_str.contains("DOUBLE_SPEND")
                    || err_str.contains("INVALID_INPUT")
                    || err_str.contains("INVALID_OUTPUT")
                    || err_str.contains("OVERSPEND")
                    || err_str.contains("SANITY_CHECK_FAILED")
                {
                    error!("TX permanently rejected by {}: {}", node_url, err_str);
                    return Err(e);
                }
                warn!("Node {} failed: {} — trying next", node_url, err_str);
                last_err = Some(e);
            }
        }
    }

    if accepted_count > 0 {
        info!("TX broadcast to {} node(s) successfully", accepted_count);
        return Ok(());
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("No broadcast nodes available")))
}

// ============================================================================
// CLSAG Atomic Signing — EXACT copy from 835ccd0 full_offline_broadcast.rs
// This is the PROVEN WORKING implementation that produced the first mainnet TX.
// ============================================================================

/// CLSAG signature structure
struct ClsagSignature {
    s: Vec<[u8; 32]>,
    c1: [u8; 32],
    d: [u8; 32],
}

// Monero domain separators (from monero source code)
const CLSAG_DOMAIN: &[u8] = b"CLSAG_round";
const CLSAG_AGG_0: &[u8] = b"CLSAG_agg_0";
const CLSAG_AGG_1: &[u8] = b"CLSAG_agg_1";

/// Compute CLSAG mixing coefficients mu_P and mu_C
/// Reference: clsag_hash_agg() in rctSigs.cpp
fn compute_mixing_coefficients(
    ring_keys: &[curve25519_dalek::edwards::EdwardsPoint],
    ring_commitments: &[curve25519_dalek::edwards::EdwardsPoint],
    key_image: &curve25519_dalek::edwards::EdwardsPoint,
    d_inv8: &curve25519_dalek::edwards::EdwardsPoint,
    pseudo_out: &curve25519_dalek::edwards::EdwardsPoint,
) -> (Scalar, Scalar) {
    let mut domain_agg_0 = [0u8; 32];
    domain_agg_0[..CLSAG_AGG_0.len()].copy_from_slice(CLSAG_AGG_0);
    let mut domain_agg_1 = [0u8; 32];
    domain_agg_1[..CLSAG_AGG_1.len()].copy_from_slice(CLSAG_AGG_1);

    let mut hasher_p = Keccak256::new();
    hasher_p.update(domain_agg_0);
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

    let mut hasher_c = Keccak256::new();
    hasher_c.update(domain_agg_1);
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
fn compute_round_hash(
    ring_keys: &[curve25519_dalek::edwards::EdwardsPoint],
    ring_commitments: &[curve25519_dalek::edwards::EdwardsPoint],
    pseudo_out: &curve25519_dalek::edwards::EdwardsPoint,
    tx_prefix_hash: &[u8; 32],
    _key_image: &curve25519_dalek::edwards::EdwardsPoint,
    _d_inv8: &curve25519_dalek::edwards::EdwardsPoint,
    l_point: &curve25519_dalek::edwards::EdwardsPoint,
    r_point: &curve25519_dalek::edwards::EdwardsPoint,
) -> Scalar {
    let mut domain = [0u8; 32];
    domain[..CLSAG_DOMAIN.len()].copy_from_slice(CLSAG_DOMAIN);

    let mut hasher = Keccak256::new();
    hasher.update(domain);
    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }
    for commitment in ring_commitments {
        hasher.update(commitment.compress().as_bytes());
    }
    hasher.update(pseudo_out.compress().as_bytes());
    hasher.update(tx_prefix_hash);
    hasher.update(l_point.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());

    Scalar::from_bytes_mod_order(hasher.finalize().into())
}

/// Compute derivation: d = H_s(8*v*R || output_index) (Monero one-time key derivation)
fn compute_key_derivation(
    view_key: &Scalar,
    tx_pubkey: &curve25519_dalek::edwards::EdwardsPoint,
    output_index: u64,
) -> Scalar {
    let shared_secret = (view_key * tx_pubkey).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(shared_secret_bytes);
    hasher.update(encode_varint_bytes(output_index));
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

/// Compute Lagrange coefficient for participant i given other participant j
fn compute_lagrange_coefficient(my_index: u8, other_index: u8) -> Scalar {
    let i = Scalar::from(my_index as u64);
    let j = Scalar::from(other_index as u64);
    j * (j - i).invert()
}

fn encode_varint_bytes(value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut n = value;
    while n >= 0x80 {
        result.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    result.push(n as u8);
    result
}

fn hex_to_scalar(hex_str: &str) -> Result<Scalar> {
    let bytes = hex::decode(hex_str).context("Invalid hex for scalar")?;
    if bytes.len() != 32 {
        anyhow::bail!("Scalar must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Scalar::from_bytes_mod_order(arr))
}

fn hex_to_point(hex_str: &str) -> Result<curve25519_dalek::edwards::EdwardsPoint> {
    let bytes = hex::decode(hex_str).context("Invalid hex for point")?;
    if bytes.len() != 32 {
        anyhow::bail!("Point must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid Edwards point"))
}

/// Sign CLSAG atomically using FROST 2-of-3 threshold shares
/// EXACT copy from 835ccd0 full_offline_broadcast.rs — PROVEN WORKING on mainnet
fn sign_clsag(
    ring_keys: &[curve25519_dalek::edwards::EdwardsPoint],
    ring_commitments: &[curve25519_dalek::edwards::EdwardsPoint],
    real_index: usize,
    x_total: &Scalar,
    z_diff: &Scalar,
    key_image: &curve25519_dalek::edwards::EdwardsPoint,
    pseudo_out: &curve25519_dalek::edwards::EdwardsPoint,
    tx_prefix_hash: &[u8; 32],
) -> Result<ClsagSignature> {
    use rand::RngCore;

    let ring_size = ring_keys.len();
    if ring_size != RING_SIZE {
        anyhow::bail!("Ring size must be {RING_SIZE}, got {ring_size}");
    }

    let p = &ring_keys[real_index];
    let hp_p = hash_to_point(p.compress().to_bytes());

    // D = z_diff * Hp(P)
    let d_full = z_diff * hp_p;
    let d_inv8 = d_full * Scalar::from(8u64).invert();

    // Compute mu_P and mu_C
    let (mu_p, mu_c) =
        compute_mixing_coefficients(ring_keys, ring_commitments, key_image, &d_inv8, pseudo_out);

    debug!(
        mu_p_prefix = %hex::encode(&mu_p.to_bytes()[..8]),
        mu_c_prefix = %hex::encode(&mu_c.to_bytes()[..8]),
        "CLSAG mixing coefficients computed"
    );

    // Precompute Hp(P[i]) for all ring members
    let hp_values: Vec<curve25519_dalek::edwards::EdwardsPoint> = ring_keys
        .iter()
        .map(|key| hash_to_point(key.compress().to_bytes()))
        .collect();

    // Generate random nonce alpha
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

    // L[real] = alpha*G, R[real] = alpha*Hp(P)
    let l_real = &alpha * ED25519_BASEPOINT_TABLE;
    let r_real = alpha * hp_p;

    // Compute c[(real+1) % n]
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

    // Process the ring
    let mut c_current = c_start;
    for step in 0..(ring_size - 1) {
        let i = (real_index + 1 + step) % ring_size;
        let p_i = &ring_keys[i];
        let c_i = &ring_commitments[i];
        let hp_i = &hp_values[i];
        let s_i = s_values[i];

        let c_p = mu_p * c_current;
        let c_c = mu_c * c_current;

        let c_adjusted = c_i - pseudo_out;
        let l_i = &s_i * ED25519_BASEPOINT_TABLE + c_p * p_i + c_c * c_adjusted;
        let r_i = s_i * hp_i + c_p * key_image + c_c * d_full;

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
    }

    // c_current is now c[real]
    let c_real = c_current;
    let c_p_real = mu_p * c_real;
    let c_c_real = mu_c * c_real;
    s_values[real_index] = alpha - c_p_real * x_total - c_c_real * z_diff;

    // Verify ring closure
    let p_real = &ring_keys[real_index];
    let c_real_commitment = &ring_commitments[real_index];
    let c_adjusted_real = c_real_commitment - pseudo_out;
    let l_verify = &s_values[real_index] * ED25519_BASEPOINT_TABLE
        + c_p_real * p_real
        + c_c_real * c_adjusted_real;

    if l_verify != l_real {
        warn!("CLSAG L verification failed at real index");
    }

    // Compute c1 by running full verification loop
    let mut c_verify = c_start;
    let mut c1_value = Scalar::ZERO;
    for step in 0..ring_size {
        let i = (real_index + 1 + step) % ring_size;
        let p_i = &ring_keys[i];
        let c_i = &ring_commitments[i];
        let hp_i = &hp_values[i];
        let s_i = s_values[i];

        if i == 0 {
            // c_verify entering index 0
        }

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

        if i == 0 {
            c1_value = c_verify;
        }
    }

    // After full loop, ring should close
    if c_verify != c_start {
        warn!(
            c_final = %hex::encode(c_verify.to_bytes()),
            c_start = %hex::encode(c_start.to_bytes()),
            "CLSAG ring doesn't close"
        );
    } else {
        info!("CLSAG ring closed successfully");
    }

    let s_bytes: Vec<[u8; 32]> = s_values.iter().map(|s| s.to_bytes()).collect();

    // c1 is the challenge ENTERING index 0 (= c_start, NOT c1_value which enters index 1)
    let c1 = c_start.to_bytes();
    let d_bytes = d_inv8.compress().to_bytes();

    Ok(ClsagSignature {
        s: s_bytes,
        c1,
        d: d_bytes,
    })
}

// ============================================================================

/// Build a MoneroTransactionBuilder with the given parameters.
/// Used by both init_signing (to compute CLSAG message) and atomic_sign_and_broadcast
/// (to reconstruct the identical TX). The builder is parameterized identically to ensure
/// TX prefix hash matches what the client signed.
fn build_tx_builder(
    key_image: [u8; 32],
    ring_indices: &[u64],
    stealth_address_0: [u8; 32],
    commitment_0: [u8; 32],
    encrypted_amount_0: [u8; 8],
    mask_0: [u8; 32],
    recipient_amount: u64,
    view_tag_0: u8,
    stealth_address_1: [u8; 32],
    commitment_1: [u8; 32],
    encrypted_amount_1: [u8; 8],
    mask_1: [u8; 32],
    platform_fee: u64,
    view_tag_1: u8,
    tx_pubkey: &[u8; 32],
    tx_fee: u64,
) -> Result<MoneroTransactionBuilder> {
    let mut tx_builder = MoneroTransactionBuilder::new();
    tx_builder.set_fee(tx_fee);

    tx_builder
        .add_input(key_image, ring_indices)
        .context("Failed to add input to TX builder")?;

    tx_builder.add_output(
        stealth_address_0,
        commitment_0,
        encrypted_amount_0,
        mask_0,
        recipient_amount,
        view_tag_0,
    );

    tx_builder.add_output(
        stealth_address_1,
        commitment_1,
        encrypted_amount_1,
        mask_1,
        platform_fee,
        view_tag_1,
    );

    tx_builder.set_tx_pubkey(tx_pubkey);

    Ok(tx_builder)
}

// ============================================================================
// Stored parameters needed to reconstruct TX at broadcast time
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct StoredTxParams {
    key_image: String,
    ring_indices: Vec<u64>,
    stealth_address_0: String,
    commitment_0: String,
    encrypted_amount_0: String,
    mask_0: String,
    recipient_amount: u64,
    view_tag_0: u8,
    stealth_address_1: String,
    commitment_1: String,
    encrypted_amount_1: String,
    mask_1: String,
    platform_fee: u64,
    view_tag_1: u8,
    tx_pubkey: String,
    tx_fee: u64,
    pseudo_out: String,
}

pub struct FrostSigningCoordinator;

impl FrostSigningCoordinator {
    /// Initialize signing session (async - fetches ring from daemon)
    ///
    /// Builds real TX data: ring selection, outputs, BP+, CLSAG message.
    /// Stores BP+ bytes and TX parameters for identical reconstruction at broadcast.
    pub async fn init_signing(
        conn: &mut SqliteConnection,
        escrow_id: &str,
    ) -> Result<TxSigningData> {
        // ====================================================================
        // 0. Idempotency: return existing signing state if already initialized
        // ====================================================================
        let existing: Option<(String, String, String, Option<String>, String, String)> =
            frost_signing_state::table
                .filter(frost_signing_state::escrow_id.eq(escrow_id))
                .select((
                    frost_signing_state::tx_prefix_hash,
                    frost_signing_state::clsag_message_hash,
                    frost_signing_state::ring_data_json,
                    frost_signing_state::pseudo_out,
                    frost_signing_state::recipient_address,
                    frost_signing_state::amount_atomic,
                ))
                .first(conn)
                .optional()
                .context("Failed to query signing state")?;

        if let Some((
            tx_prefix_hash,
            clsag_message_hash,
            ring_data_json,
            pseudo_out,
            recipient_address,
            amount_atomic,
        )) = existing
        {
            let escrow: crate::models::escrow::Escrow = escrows::table
                .find(escrow_id)
                .first(conn)
                .context("Escrow not found")?;
            let multisig_pubkey = escrow.frost_group_pubkey.clone().unwrap_or_default();

            // Compute pseudo_out_mask from stored TX params
            let pseudo_out_mask = frost_signing_state::table
                .filter(frost_signing_state::escrow_id.eq(escrow_id))
                .select(frost_signing_state::ring_indices_json)
                .first::<Option<String>>(conn)
                .ok()
                .flatten()
                .and_then(|json| {
                    let params: StoredTxParams = serde_json::from_str(&json).ok()?;
                    let mask_0_bytes = hex::decode(&params.mask_0).ok()?;
                    let mask_1_bytes = hex::decode(&params.mask_1).ok()?;
                    if mask_0_bytes.len() != 32 || mask_1_bytes.len() != 32 {
                        return None;
                    }
                    let mut m0 = [0u8; 32];
                    m0.copy_from_slice(&mask_0_bytes);
                    let mut m1 = [0u8; 32];
                    m1.copy_from_slice(&mask_1_bytes);
                    let pseudo_mask = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(m0)
                        + curve25519_dalek::scalar::Scalar::from_bytes_mod_order(m1);
                    Some(hex::encode(pseudo_mask.to_bytes()))
                });

            info!(escrow_id = %escrow_id, "Returning existing FROST signing session (idempotent)");
            return Ok(TxSigningData {
                tx_prefix_hash,
                clsag_message_hash,
                ring_data_json,
                pseudo_out,
                recipient_address,
                amount_atomic,
                multisig_pubkey,
                pseudo_out_mask,
                funding_commitment_mask: escrow.funding_commitment_mask.clone(),
                multisig_view_key: escrow.multisig_view_key.clone(),
                funding_tx_pubkey: escrow.funding_tx_pubkey.clone(),
                funding_output_index: escrow.funding_output_index,
            });
        }

        // ====================================================================
        // 1. Validate escrow state and load required fields
        // ====================================================================
        let escrow: crate::models::escrow::Escrow = escrows::table
            .find(escrow_id)
            .first(conn)
            .context("Escrow not found")?;

        if escrow.status != "releasing" {
            anyhow::bail!(
                "Invalid escrow status: expected 'releasing', got '{}'",
                escrow.status
            );
        }

        let view_key_hex = escrow
            .multisig_view_key
            .as_ref()
            .context("multisig_view_key not set")?;
        let funding_tx_hash = escrow
            .funding_tx_hash
            .as_ref()
            .context("funding_tx_hash not set")?;
        let funding_output_index = escrow
            .funding_output_index
            .context("funding_output_index not set")?;
        let funding_global_index = escrow
            .funding_global_index
            .context("funding_global_index not set")?;
        let funding_commitment_mask_hex = escrow
            .funding_commitment_mask
            .as_ref()
            .context("funding_commitment_mask not set")?;
        let funding_tx_pubkey_hex = escrow
            .funding_tx_pubkey
            .as_ref()
            .context("funding_tx_pubkey not set")?;
        let frost_group_pubkey_hex = escrow
            .frost_group_pubkey
            .as_ref()
            .context("frost_group_pubkey not set (DKG incomplete?)")?;
        let multisig_address = escrow
            .multisig_address
            .as_ref()
            .context("Multisig address not set")?;

        // Determine recipient address (vendor for release, buyer for refund)
        let is_refund = escrow.dispute_signing_pair.as_deref() == Some("arbiter_buyer");
        let recipient_address = if is_refund {
            escrow
                .buyer_refund_address
                .as_ref()
                .context("Buyer refund address not set for dispute refund")?
                .clone()
        } else {
            escrow
                .vendor_payout_address
                .as_ref()
                .context("Vendor payout address not set")?
                .clone()
        };

        let input_amount = escrow.amount as u64;

        // Use aggregated key image from DKG if available
        let key_image_hex = escrow
            .aggregated_key_image
            .as_ref()
            .context("aggregated_key_image not set - complete key image aggregation first")?;

        info!(
            escrow_id = %escrow_id,
            input_amount = input_amount,
            is_refund = is_refund,
            "Initializing FROST signing session"
        );

        // ====================================================================
        // 2. Fetch ring members from daemon
        // ====================================================================
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        let (ring_members, ring_indices, real_position) =
            fetch_ring_members(&http_client, funding_global_index as u64).await?;

        info!(
            escrow_id = %escrow_id,
            ring_size = ring_members.len(),
            real_position = real_position,
            "Ring members fetched from daemon"
        );

        // Serialize ring data for client
        let ring_data = serde_json::json!({
            "ring_members": ring_members.iter().enumerate().map(|(i, m)| {
                serde_json::json!({
                    "index": ring_indices[i],
                    "key": m.key,
                    "mask": m.mask,
                })
            }).collect::<Vec<_>>(),
            "real_position": real_position,
            "ring_indices": ring_indices,
        });
        let ring_data_json =
            serde_json::to_string(&ring_data).context("Failed to serialize ring data")?;

        // ====================================================================
        // 3. Generate deterministic TX secret key (must match at broadcast)
        // ====================================================================
        let tx_secret_key: [u8; 32] = {
            let mut hasher = Keccak256::new();
            hasher.update(b"NEXUS_TX_SECRET_V1");
            hasher.update(escrow_id.as_bytes());
            hasher.update(input_amount.to_le_bytes());
            hasher.finalize().into()
        };

        let tx_pubkey = generate_tx_pubkey(&tx_secret_key);

        // ====================================================================
        // 4. Compute platform fee and recipient amount
        // ====================================================================
        let platform_wallet = get_platform_wallet_address()
            .context("Platform wallet not configured - check PLATFORM_FEE_WALLET in .env")?;

        let platform_fee_bps: u64 = if is_refund {
            get_refund_fee_bps()
        } else {
            get_release_fee_bps()
        };

        let tx_fee = get_tx_fee();
        let platform_fee = (input_amount * platform_fee_bps) / 10000;
        let recipient_amount = input_amount
            .saturating_sub(platform_fee)
            .saturating_sub(tx_fee);

        info!(
            escrow_id = %escrow_id,
            input_amount = input_amount,
            platform_fee = platform_fee,
            tx_fee = tx_fee,
            recipient_amount = recipient_amount,
            fee_type = if is_refund { "refund" } else { "release" },
            "Fee calculation complete"
        );

        // ====================================================================
        // 5. Generate 2 real outputs
        // ====================================================================
        let (recipient_spend_pub, recipient_view_pub) = parse_monero_address(&recipient_address)
            .context("Failed to parse recipient address")?;
        let (platform_spend_pub, platform_view_pub) = parse_monero_address(&platform_wallet)
            .context("Failed to parse platform wallet address")?;

        // Output 0: Recipient
        let output_index_0: u64 = 0;
        let (stealth_address_0, view_tag_0) = generate_stealth_address_with_view_tag(
            &tx_secret_key,
            &recipient_spend_pub,
            &recipient_view_pub,
            output_index_0,
        )
        .context("Failed to generate recipient stealth address")?;

        let mask_0 = derive_output_mask(&tx_secret_key, &recipient_view_pub, output_index_0)
            .context("Failed to derive recipient output mask")?;
        let commitment_0 = compute_pedersen_commitment(&mask_0, recipient_amount)
            .context("Failed to compute recipient commitment")?;
        let encrypted_amount_0 = encrypt_amount_ecdh(
            &tx_secret_key,
            &recipient_view_pub,
            output_index_0,
            recipient_amount,
        )
        .context("Failed to encrypt recipient amount")?;

        // Output 1: Platform fee
        let output_index_1: u64 = 1;
        let (stealth_address_1, view_tag_1) = generate_stealth_address_with_view_tag(
            &tx_secret_key,
            &platform_spend_pub,
            &platform_view_pub,
            output_index_1,
        )
        .context("Failed to generate platform stealth address")?;

        let mask_1 = derive_output_mask(&tx_secret_key, &platform_view_pub, output_index_1)
            .context("Failed to derive platform output mask")?;
        let commitment_1 = compute_pedersen_commitment(&mask_1, platform_fee)
            .context("Failed to compute platform commitment")?;
        let encrypted_amount_1 = encrypt_amount_ecdh(
            &tx_secret_key,
            &platform_view_pub,
            output_index_1,
            platform_fee,
        )
        .context("Failed to encrypt platform amount")?;

        // ====================================================================
        // 6. Compute pseudo_out
        // ====================================================================
        let mask_0_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(mask_0);
        let mask_1_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(mask_1);
        let pseudo_mask = mask_0_scalar + mask_1_scalar;

        let h_bytes: [u8; 32] = [
            0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad,
            0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d,
            0xd3, 0x9c, 0x1f, 0x94,
        ];
        let h_point = CompressedEdwardsY(h_bytes)
            .decompress()
            .ok_or_else(|| anyhow::anyhow!("Invalid H point"))?;

        let pseudo_out = &pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
            + curve25519_dalek::scalar::Scalar::from(input_amount) * h_point;
        let pseudo_out_bytes = pseudo_out.compress().to_bytes();
        let pseudo_out_hex = hex::encode(pseudo_out_bytes);

        // ====================================================================
        // 7. Build TX and compute CLSAG message
        // ====================================================================
        let key_image_bytes = hex_to_32(key_image_hex)?;

        let mut tx_builder = build_tx_builder(
            key_image_bytes,
            &ring_indices,
            stealth_address_0,
            commitment_0,
            encrypted_amount_0,
            mask_0,
            recipient_amount,
            view_tag_0,
            stealth_address_1,
            commitment_1,
            encrypted_amount_1,
            mask_1,
            platform_fee,
            view_tag_1,
            &tx_pubkey,
            tx_fee,
        )?;

        // Generate BP+ for CLSAG message computation
        tx_builder
            .prepare_for_signing()
            .context("Failed to generate Bulletproof+")?;

        // Export BP+ bytes for storage (needed to reconstruct identical TX at broadcast)
        let bp_bytes = tx_builder
            .export_bulletproof_bytes()
            .context("Failed to export BP+ bytes")?;
        let bp_bytes_b64 = BASE64.encode(&bp_bytes);

        // Compute the FULL CLSAG message (get_pre_mlsag_hash)
        let clsag_message = tx_builder
            .compute_clsag_message(&[pseudo_out_bytes])
            .context("Failed to compute CLSAG message")?;

        let tx_prefix_hash = hex::encode(clsag_message); // This IS the signing message
        let clsag_message_hash = hex::encode(clsag_message);

        info!(
            escrow_id = %escrow_id,
            clsag_message = %clsag_message_hash,
            bp_bytes_len = bp_bytes.len(),
            "TX construction complete - CLSAG message computed"
        );

        // ====================================================================
        // 8. Store TX parameters for reconstruction at broadcast
        // ====================================================================
        let stored_params = StoredTxParams {
            key_image: key_image_hex.clone(),
            ring_indices: ring_indices.clone(),
            stealth_address_0: hex::encode(stealth_address_0),
            commitment_0: hex::encode(commitment_0),
            encrypted_amount_0: hex::encode(encrypted_amount_0),
            mask_0: hex::encode(mask_0),
            recipient_amount,
            view_tag_0,
            stealth_address_1: hex::encode(stealth_address_1),
            commitment_1: hex::encode(commitment_1),
            encrypted_amount_1: hex::encode(encrypted_amount_1),
            mask_1: hex::encode(mask_1),
            platform_fee,
            view_tag_1,
            tx_pubkey: hex::encode(tx_pubkey),
            tx_fee,
            pseudo_out: pseudo_out_hex.clone(),
        };

        let ring_indices_json =
            serde_json::to_string(&stored_params).context("Failed to serialize TX params")?;

        // ====================================================================
        // 9. Store signing state in DB
        // ====================================================================
        diesel::insert_into(frost_signing_state::table)
            .values((
                frost_signing_state::escrow_id.eq(escrow_id),
                frost_signing_state::tx_prefix_hash.eq(&tx_prefix_hash),
                frost_signing_state::clsag_message_hash.eq(&clsag_message_hash),
                frost_signing_state::ring_data_json.eq(&ring_data_json),
                frost_signing_state::pseudo_out.eq(&pseudo_out_hex),
                frost_signing_state::recipient_address.eq(&recipient_address),
                frost_signing_state::amount_atomic.eq(&input_amount.to_string()),
                frost_signing_state::status.eq("initialized"),
                frost_signing_state::bulletproof_bytes.eq(&bp_bytes_b64),
                frost_signing_state::pseudo_out_hex.eq(&pseudo_out_hex),
                frost_signing_state::tx_secret_key.eq(hex::encode(tx_secret_key)),
                frost_signing_state::ring_indices_json.eq(&ring_indices_json),
            ))
            .execute(conn)
            .context("Failed to create signing state")?;

        info!(
            escrow_id = %escrow_id,
            "FROST signing session initialized with real TX data"
        );

        // Compute pseudo_out_mask for client
        let pseudo_mask_hex = {
            let mask_0_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(mask_0);
            let mask_1_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(mask_1);
            hex::encode((mask_0_scalar + mask_1_scalar).to_bytes())
        };

        Ok(TxSigningData {
            tx_prefix_hash,
            clsag_message_hash,
            ring_data_json,
            pseudo_out: Some(pseudo_out_hex),
            recipient_address,
            amount_atomic: input_amount.to_string(),
            multisig_pubkey: frost_group_pubkey_hex.clone(),
            pseudo_out_mask: Some(pseudo_mask_hex),
            funding_commitment_mask: Some(funding_commitment_mask_hex.clone()),
            multisig_view_key: Some(view_key_hex.clone()),
            funding_tx_pubkey: Some(funding_tx_pubkey_hex.clone()),
            funding_output_index: Some(funding_output_index),
        })
    }

    /// Submit nonce commitment (Round 1)
    ///
    /// When both buyer and vendor have submitted, aggregates nonces via
    /// Edwards point addition: R_agg = R_buyer + R_vendor.
    /// Returns true if both have submitted.
    pub fn submit_nonce_commitment(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        role: &str,
        r_public: &str,
        r_prime_public: &str,
    ) -> Result<bool> {
        let now = chrono::Utc::now().naive_utc();

        // Update appropriate column based on role
        match role {
            "buyer" => {
                diesel::update(
                    frost_signing_state::table.filter(frost_signing_state::escrow_id.eq(escrow_id)),
                )
                .set((
                    frost_signing_state::buyer_r_public.eq(r_public),
                    frost_signing_state::buyer_r_prime_public.eq(r_prime_public),
                    frost_signing_state::updated_at.eq(now),
                ))
                .execute(conn)?;
            }
            "vendor" => {
                diesel::update(
                    frost_signing_state::table.filter(frost_signing_state::escrow_id.eq(escrow_id)),
                )
                .set((
                    frost_signing_state::vendor_r_public.eq(r_public),
                    frost_signing_state::vendor_r_prime_public.eq(r_prime_public),
                    frost_signing_state::updated_at.eq(now),
                ))
                .execute(conn)?;
            }
            _ => anyhow::bail!("Invalid role for nonce commitment: {role}"),
        }

        // Check if both submitted
        let state: (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = frost_signing_state::table
            .filter(frost_signing_state::escrow_id.eq(escrow_id))
            .select((
                frost_signing_state::buyer_r_public,
                frost_signing_state::vendor_r_public,
                frost_signing_state::buyer_r_prime_public,
                frost_signing_state::vendor_r_prime_public,
            ))
            .first(conn)?;

        let both_submitted = state.0.is_some() && state.1.is_some();

        if both_submitted {
            // Real Edwards point addition for nonce aggregation
            let buyer_r_hex = state
                .0
                .as_ref()
                .context("Buyer R_public missing after check")?;
            let vendor_r_hex = state
                .1
                .as_ref()
                .context("Vendor R_public missing after check")?;
            let buyer_rp_hex = state
                .2
                .as_ref()
                .context("Buyer R'_public missing after check")?;
            let vendor_rp_hex = state
                .3
                .as_ref()
                .context("Vendor R'_public missing after check")?;

            let aggregated_r = aggregate_edwards_points(buyer_r_hex, vendor_r_hex)
                .context("Failed to aggregate R nonces")?;
            let aggregated_r_prime = aggregate_edwards_points(buyer_rp_hex, vendor_rp_hex)
                .context("Failed to aggregate R' nonces")?;

            diesel::update(
                frost_signing_state::table.filter(frost_signing_state::escrow_id.eq(escrow_id)),
            )
            .set((
                frost_signing_state::aggregated_r.eq(&aggregated_r),
                frost_signing_state::aggregated_r_prime.eq(&aggregated_r_prime),
                frost_signing_state::status.eq("nonces_aggregated"),
            ))
            .execute(conn)?;

            info!(
                escrow_id = %escrow_id,
                "Both nonces submitted and aggregated via Edwards point addition"
            );
        }

        Ok(both_submitted)
    }

    /// Submit partial signature (Round 2)
    ///
    /// Stores partial signature in escrows table and updates signing state.
    /// Returns true if all required signatures (buyer + vendor) submitted.
    pub fn submit_partial_signature(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        role: &str,
        partial_sig_json: &str,
    ) -> Result<bool> {
        let now = chrono::Utc::now().naive_utc();

        // Store signature in escrows table (existing columns)
        match role {
            "buyer" => {
                diesel::update(escrows::table.find(escrow_id))
                    .set(escrows::buyer_signature.eq(partial_sig_json))
                    .execute(conn)?;

                diesel::update(
                    frost_signing_state::table.filter(frost_signing_state::escrow_id.eq(escrow_id)),
                )
                .set((
                    frost_signing_state::buyer_partial_submitted.eq(true),
                    frost_signing_state::updated_at.eq(now),
                ))
                .execute(conn)?;
            }
            "vendor" => {
                diesel::update(escrows::table.find(escrow_id))
                    .set(escrows::vendor_signature.eq(partial_sig_json))
                    .execute(conn)?;

                diesel::update(
                    frost_signing_state::table.filter(frost_signing_state::escrow_id.eq(escrow_id)),
                )
                .set((
                    frost_signing_state::vendor_partial_submitted.eq(true),
                    frost_signing_state::updated_at.eq(now),
                ))
                .execute(conn)?;
            }
            "arbiter" => {
                diesel::update(
                    frost_signing_state::table.filter(frost_signing_state::escrow_id.eq(escrow_id)),
                )
                .set((
                    frost_signing_state::arbiter_partial_submitted.eq(true),
                    frost_signing_state::updated_at.eq(now),
                ))
                .execute(conn)?;
            }
            _ => anyhow::bail!("Invalid role for partial signature: {role}"),
        }

        // Check if buyer + vendor both submitted (arbiter may come later)
        let state: (Option<bool>, Option<bool>, Option<bool>) = frost_signing_state::table
            .filter(frost_signing_state::escrow_id.eq(escrow_id))
            .select((
                frost_signing_state::buyer_partial_submitted,
                frost_signing_state::vendor_partial_submitted,
                frost_signing_state::arbiter_partial_submitted,
            ))
            .first(conn)?;

        let all_submitted = state.0.unwrap_or(false) && state.1.unwrap_or(false);

        if all_submitted {
            diesel::update(
                frost_signing_state::table.filter(frost_signing_state::escrow_id.eq(escrow_id)),
            )
            .set(frost_signing_state::status.eq("ready_for_aggregation"))
            .execute(conn)?;

            info!(
                escrow_id = %escrow_id,
                "All required partial signatures submitted"
            );
        }

        Ok(all_submitted)
    }

    /// Get first signer (vendor/seller) data for Round-Robin CLSAG
    ///
    /// Flow: Seller confirms shipped (FIRST signer) → Buyer confirms receipt (SECOND signer)
    ///
    /// Returns c1, s_values, D, mu_p, mu_c, pseudo_out from the vendor's
    /// partial signature so buyer can sign as second signer (reusing decoys).
    ///
    /// Returns None if vendor hasn't submitted yet.
    pub fn get_first_signer_data(
        conn: &mut SqliteConnection,
        escrow_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        // Check if vendor (first signer) has submitted
        let vendor_submitted: Option<bool> = frost_signing_state::table
            .filter(frost_signing_state::escrow_id.eq(escrow_id))
            .select(frost_signing_state::vendor_partial_submitted)
            .first(conn)
            .optional()?
            .flatten();

        if vendor_submitted != Some(true) {
            return Ok(None);
        }

        // Load vendor's stored signature JSON from escrows table
        let vendor_sig_json: Option<String> = escrows::table
            .find(escrow_id)
            .select(escrows::vendor_signature)
            .first::<Option<String>>(conn)?;

        let sig_json = match vendor_sig_json {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(None),
        };

        // Parse the stored JSON to extract first-signer fields
        let stored: serde_json::Value =
            serde_json::from_str(&sig_json).context("Failed to parse vendor signature JSON")?;

        let signature = stored
            .get("signature")
            .context("Missing 'signature' in vendor signature")?;

        let c1 = signature
            .get("c1")
            .and_then(|v| v.as_str())
            .context("Missing c1 in vendor signature")?;

        let s_values = signature
            .get("s")
            .context("Missing s in vendor signature")?;

        let d = signature
            .get("D")
            .and_then(|v| v.as_str())
            .context("Missing D in vendor signature")?;

        let pseudo_out = stored
            .get("pseudo_out")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mu_p = stored.get("mu_p").and_then(|v| v.as_str()).unwrap_or("");

        let mu_c = stored.get("mu_c").and_then(|v| v.as_str()).unwrap_or("");

        info!(
            escrow_id = %escrow_id,
            c1_prefix = %&c1[..c1.len().min(16)],
            s_count = s_values.as_array().map(|a| a.len()).unwrap_or(0),
            has_mu_p = !mu_p.is_empty(),
            has_mu_c = !mu_c.is_empty(),
            "Returning first signer data for second signer"
        );

        Ok(Some(serde_json::json!({
            "c1": c1,
            "s_values": s_values,
            "d": d,
            "pseudo_out": pseudo_out,
            "mu_p": mu_p,
            "mu_c": mu_c
        })))
    }

    /// Atomic CLSAG signing and broadcast — IDENTICAL to 835ccd0 full_offline_broadcast.rs
    ///
    /// Flow:
    /// 1. Load FROST secret shares from buyer/vendor submissions
    /// 2. Reconstruct x_total = d + λ₁*b₁ + λ₂*b₂
    /// 3. Compute CORRECT key image: KI = x_total * Hp(P)
    /// 4. Rebuild TX with correct KI (browser PKI aggregation was missing 'd' term)
    /// 5. Sign CLSAG atomically (single call, proven on mainnet)
    /// 6. Broadcast to daemon
    ///
    /// Returns the real TX hash from the broadcast.
    pub async fn aggregate_and_broadcast(
        conn: &mut SqliteConnection,
        escrow_id: &str,
    ) -> Result<String> {
        // ====================================================================
        // 1. Load escrow and FROST secret shares
        // ====================================================================
        let escrow: crate::models::escrow::Escrow = escrows::table.find(escrow_id).first(conn)?;

        let buyer_sig_json = escrow
            .buyer_signature
            .as_ref()
            .context("Buyer FROST share missing")?;
        let vendor_sig_json = escrow
            .vendor_signature
            .as_ref()
            .context("Vendor FROST share missing")?;

        let buyer_data: serde_json::Value = serde_json::from_str(buyer_sig_json)
            .context("Failed to parse buyer submission JSON")?;
        let vendor_data: serde_json::Value = serde_json::from_str(vendor_sig_json)
            .context("Failed to parse vendor submission JSON")?;

        let buyer_share_hex = buyer_data
            .get("frost_share")
            .and_then(|v| v.as_str())
            .context("Missing frost_share in buyer submission")?;
        let vendor_share_hex = vendor_data
            .get("frost_share")
            .and_then(|v| v.as_str())
            .context("Missing frost_share in vendor submission")?;

        let buyer_share = hex_to_scalar(buyer_share_hex).context("Invalid buyer FROST share")?;
        let vendor_share = hex_to_scalar(vendor_share_hex).context("Invalid vendor FROST share")?;

        // ====================================================================
        // 2. Reconstruct x_total = d + λ_buyer*b_buyer + λ_vendor*b_vendor
        //    (EXACT same math as 835ccd0 full_offline_broadcast.rs)
        // ====================================================================
        let view_key_hex = escrow
            .multisig_view_key
            .as_ref()
            .context("multisig_view_key not set")?;
        let funding_tx_pubkey_hex = escrow
            .funding_tx_pubkey
            .as_ref()
            .context("funding_tx_pubkey not set")?;
        let funding_output_index = escrow
            .funding_output_index
            .context("funding_output_index not set")?;
        let frost_group_pubkey_hex = escrow
            .frost_group_pubkey
            .as_ref()
            .context("frost_group_pubkey not set")?;
        let funding_commitment_mask_hex = escrow
            .funding_commitment_mask
            .as_ref()
            .context("funding_commitment_mask not set")?;

        let view_key = hex_to_scalar(view_key_hex)?;
        let funding_tx_pubkey_point = hex_to_point(funding_tx_pubkey_hex)?;
        let d = compute_key_derivation(
            &view_key,
            &funding_tx_pubkey_point,
            funding_output_index as u64,
        );

        // Lagrange coefficients: buyer=participant_1, vendor=participant_2
        let lambda_buyer = compute_lagrange_coefficient(1, 2); // = 2
        let lambda_vendor = compute_lagrange_coefficient(2, 1); // = -1

        let x_total = d + lambda_buyer * buyer_share + lambda_vendor * vendor_share;

        // P = d*G + B (one-time public key = derivation + group public key)
        let group_pubkey = hex_to_point(frost_group_pubkey_hex)?;
        let p = &d * ED25519_BASEPOINT_TABLE + group_pubkey;

        // Key image: KI = x_total * Hp(P) — CORRECT (includes 'd' term)
        let hp_p = hash_to_point(p.compress().to_bytes());
        let key_image_point = x_total * hp_p;
        let key_image_bytes = key_image_point.compress().to_bytes();
        let key_image_hex = hex::encode(key_image_bytes);

        info!(
            escrow_id = %escrow_id,
            ki_prefix = %&key_image_hex[..16],
            d_prefix = %hex::encode(&d.to_bytes()[..8]),
            "x_total reconstructed from FROST shares (atomic 835ccd0 approach)"
        );

        // ====================================================================
        // 3. Load stored TX parameters
        // ====================================================================
        let (bp_bytes_b64, stored_params_json, ring_data_json_str): (
            Option<String>,
            Option<String>,
            String,
        ) = frost_signing_state::table
            .filter(frost_signing_state::escrow_id.eq(escrow_id))
            .select((
                frost_signing_state::bulletproof_bytes,
                frost_signing_state::ring_indices_json,
                frost_signing_state::ring_data_json,
            ))
            .first(conn)?;

        let bp_bytes_b64 = bp_bytes_b64.context("bulletproof_bytes not stored")?;
        let stored_params_json =
            stored_params_json.context("ring_indices_json (tx params) not stored")?;

        let bp_bytes = BASE64
            .decode(&bp_bytes_b64)
            .context("Failed to decode BP+ bytes")?;

        let stored_params: StoredTxParams = serde_json::from_str(&stored_params_json)
            .context("Failed to deserialize stored TX params")?;

        // ====================================================================
        // 4. Rebuild TX with CORRECT key image (from x_total, not browser PKI)
        // ====================================================================
        let stealth_address_0 = hex_to_32(&stored_params.stealth_address_0)?;
        let commitment_0 = hex_to_32(&stored_params.commitment_0)?;
        let encrypted_amount_0_bytes = hex::decode(&stored_params.encrypted_amount_0)
            .context("Invalid encrypted_amount_0 hex")?;
        let mut encrypted_amount_0 = [0u8; 8];
        encrypted_amount_0.copy_from_slice(&encrypted_amount_0_bytes);
        let mask_0 = hex_to_32(&stored_params.mask_0)?;

        let stealth_address_1 = hex_to_32(&stored_params.stealth_address_1)?;
        let commitment_1 = hex_to_32(&stored_params.commitment_1)?;
        let encrypted_amount_1_bytes = hex::decode(&stored_params.encrypted_amount_1)
            .context("Invalid encrypted_amount_1 hex")?;
        let mut encrypted_amount_1 = [0u8; 8];
        encrypted_amount_1.copy_from_slice(&encrypted_amount_1_bytes);
        let mask_1 = hex_to_32(&stored_params.mask_1)?;

        let tx_pubkey = hex_to_32(&stored_params.tx_pubkey)?;

        // Build TX with CORRECT key image (x_total * Hp(P), NOT browser aggregation)
        let mut tx_builder = build_tx_builder(
            key_image_bytes,
            &stored_params.ring_indices,
            stealth_address_0,
            commitment_0,
            encrypted_amount_0,
            mask_0,
            stored_params.recipient_amount,
            stored_params.view_tag_0,
            stealth_address_1,
            commitment_1,
            encrypted_amount_1,
            mask_1,
            stored_params.platform_fee,
            stored_params.view_tag_1,
            &tx_pubkey,
            stored_params.tx_fee,
        )?;

        // Import stored BP+ bytes (valid — BP+ doesn't depend on key image)
        tx_builder
            .import_bulletproof_bytes(&bp_bytes)
            .context("Failed to import stored BP+ bytes")?;

        // Recompute CLSAG message with the CORRECT key image
        let pseudo_out_bytes = hex_to_32(&stored_params.pseudo_out)?;
        let clsag_message = tx_builder
            .compute_clsag_message(&[pseudo_out_bytes])
            .context("Failed to compute CLSAG message")?;

        info!(
            escrow_id = %escrow_id,
            clsag_msg = %hex::encode(clsag_message),
            "TX rebuilt with correct key image, CLSAG message recomputed"
        );

        // ====================================================================
        // 5. Parse ring data for CLSAG signing
        // ====================================================================
        let ring_data: serde_json::Value =
            serde_json::from_str(&ring_data_json_str).context("Failed to parse ring data JSON")?;

        let real_position = ring_data
            .get("real_position")
            .and_then(|v| v.as_u64())
            .context("Missing real_position in ring data")? as usize;

        let ring_members = ring_data
            .get("ring_members")
            .and_then(|v| v.as_array())
            .context("Missing ring_members in ring data")?;

        let mut ring_keys: Vec<curve25519_dalek::edwards::EdwardsPoint> =
            Vec::with_capacity(RING_SIZE);
        let mut ring_commitments: Vec<curve25519_dalek::edwards::EdwardsPoint> =
            Vec::with_capacity(RING_SIZE);

        for member in ring_members {
            let key_hex = member
                .get("key")
                .and_then(|v| v.as_str())
                .context("Missing key in ring member")?;
            let mask_hex = member
                .get("mask")
                .and_then(|v| v.as_str())
                .context("Missing mask in ring member")?;
            ring_keys.push(hex_to_point(key_hex)?);
            ring_commitments.push(hex_to_point(mask_hex)?);
        }

        if ring_keys.len() != RING_SIZE {
            anyhow::bail!(
                "Ring size mismatch: expected {}, got {}",
                RING_SIZE,
                ring_keys.len()
            );
        }

        // ====================================================================
        // 6. Compute z_diff = pseudo_mask - funding_mask
        // ====================================================================
        let mask_0_scalar = Scalar::from_bytes_mod_order(mask_0);
        let mask_1_scalar = Scalar::from_bytes_mod_order(mask_1);
        let pseudo_mask = mask_0_scalar + mask_1_scalar;

        let funding_mask = hex_to_scalar(funding_commitment_mask_hex)?;
        let z_diff = funding_mask - pseudo_mask;

        let pseudo_out_point = hex_to_point(&stored_params.pseudo_out)?;

        // ====================================================================
        // 7. ATOMIC CLSAG SIGNING (single call — identical to 835ccd0)
        // ====================================================================
        let clsag_sig = sign_clsag(
            &ring_keys,
            &ring_commitments,
            real_position,
            &x_total,
            &z_diff,
            &key_image_point,
            &pseudo_out_point,
            &clsag_message,
        )
        .context("CLSAG atomic signing failed")?;

        info!(
            escrow_id = %escrow_id,
            c1_prefix = %hex::encode(&clsag_sig.c1[..8]),
            s_count = clsag_sig.s.len(),
            "CLSAG signed atomically (835ccd0 approach)"
        );

        // ====================================================================
        // 8. Attach CLSAG to TX and build
        // ====================================================================
        let clsag_json = ClsagSignatureJson {
            d: hex::encode(clsag_sig.d),
            s: clsag_sig.s.iter().map(hex::encode).collect(),
            c1: hex::encode(clsag_sig.c1),
        };

        let client_sig = ClientSignature {
            signature: clsag_json,
            key_image: key_image_hex.clone(),
            partial_key_image: None,
            pseudo_out: stored_params.pseudo_out.clone(),
        };

        tx_builder
            .attach_clsag(&client_sig)
            .context("Failed to attach atomic CLSAG")?;

        let build_result = tx_builder
            .build()
            .context("Failed to build final transaction")?;

        let tx_hex = &build_result.tx_hex;
        let tx_hash = hex::encode(build_result.tx_hash);

        info!(
            escrow_id = %escrow_id,
            tx_hash = %tx_hash,
            tx_size_bytes = tx_hex.len() / 2,
            "Transaction built with atomic CLSAG"
        );

        // ====================================================================
        // 9. Save TX hex for manual retry, then broadcast
        // ====================================================================
        let tx_file = format!(
            "/tmp/frost_tx_{}.hex",
            &escrow_id[..escrow_id.len().min(16)]
        );
        if let Err(e) = std::fs::write(&tx_file, tx_hex) {
            warn!(error = %e, "Failed to save TX hex to {}", tx_file);
        } else {
            info!(escrow_id = %escrow_id, path = %tx_file, "TX hex saved for manual retry");
        }

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("Failed to create HTTP client")?;

        if let Err(e) = broadcast_transaction(&http_client, tx_hex).await {
            error!(
                escrow_id = %escrow_id,
                tx_hash = %tx_hash,
                error = %e,
                "Daemon rejected transaction"
            );
            return Err(e.context("Failed to broadcast transaction"));
        }

        info!(
            escrow_id = %escrow_id,
            tx_hash = %tx_hash,
            "TX broadcast successful (atomic CLSAG — 835ccd0 approach)"
        );

        // ====================================================================
        // 10. Update DB with real TX hash
        // ====================================================================
        diesel::update(
            frost_signing_state::table.filter(frost_signing_state::escrow_id.eq(escrow_id)),
        )
        .set((
            frost_signing_state::aggregated_key_image.eq(&key_image_hex),
            frost_signing_state::broadcasted_tx_hash.eq(&tx_hash),
            frost_signing_state::status.eq("broadcasted"),
        ))
        .execute(conn)?;

        diesel::update(escrows::table.find(escrow_id))
            .set((
                escrows::status.eq("completed"),
                escrows::transaction_hash.eq(&tx_hash),
            ))
            .execute(conn)?;

        info!(
            escrow_id = %escrow_id,
            tx_hash = %tx_hash,
            "Escrow completed — TX broadcasted (atomic 835ccd0 signing)"
        );

        Ok(tx_hash)
    }

    /// Get signing status
    pub fn get_status(conn: &mut SqliteConnection, escrow_id: &str) -> Result<SigningStatus> {
        #[derive(Queryable)]
        struct State {
            buyer_r_public: Option<String>,
            vendor_r_public: Option<String>,
            buyer_partial_submitted: Option<bool>,
            vendor_partial_submitted: Option<bool>,
            arbiter_partial_submitted: Option<bool>,
            status: String,
            broadcasted_tx_hash: Option<String>,
        }

        let state: State = frost_signing_state::table
            .filter(frost_signing_state::escrow_id.eq(escrow_id))
            .select((
                frost_signing_state::buyer_r_public,
                frost_signing_state::vendor_r_public,
                frost_signing_state::buyer_partial_submitted,
                frost_signing_state::vendor_partial_submitted,
                frost_signing_state::arbiter_partial_submitted,
                frost_signing_state::status,
                frost_signing_state::broadcasted_tx_hash,
            ))
            .first(conn)
            .context("Signing state not found")?;

        Ok(SigningStatus {
            status: state.status,
            buyer_nonce_submitted: state.buyer_r_public.is_some(),
            vendor_nonce_submitted: state.vendor_r_public.is_some(),
            buyer_partial_submitted: state.buyer_partial_submitted.unwrap_or(false),
            vendor_partial_submitted: state.vendor_partial_submitted.unwrap_or(false),
            arbiter_partial_submitted: state.arbiter_partial_submitted.unwrap_or(false),
            tx_hash: state.broadcasted_tx_hash,
        })
    }
}

/// Aggregate two Edwards points given as hex strings.
/// P_agg = P_1 + P_2 (Edwards point addition on Curve25519)
fn aggregate_edwards_points(hex_a: &str, hex_b: &str) -> Result<String> {
    let bytes_a = hex::decode(hex_a).context("Invalid hex for point A")?;
    let bytes_b = hex::decode(hex_b).context("Invalid hex for point B")?;

    if bytes_a.len() != 32 || bytes_b.len() != 32 {
        anyhow::bail!(
            "Points must be 32 bytes each, got {} and {}",
            bytes_a.len(),
            bytes_b.len()
        );
    }

    let mut arr_a = [0u8; 32];
    arr_a.copy_from_slice(&bytes_a);
    let mut arr_b = [0u8; 32];
    arr_b.copy_from_slice(&bytes_b);

    let point_a = CompressedEdwardsY(arr_a)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid Edwards point A"))?;
    let point_b = CompressedEdwardsY(arr_b)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid Edwards point B"))?;

    let sum = point_a + point_b;
    Ok(hex::encode(sum.compress().to_bytes()))
}
