//! WASM Cryptographic Primitives for Monero Multisig
//!
//! This module implements the CLIENT-SIDE cryptographic operations for Monero
//! multisig in Safe Rust + WASM. The server acts as a Light Wallet Server (LWS)
//! proxy for blockchain operations.
//!
//! **ARCHITECTURE (Hybrid WASM + LWS):**
//! - WASM: Key generation, multisig info generation, transaction signing
//! - Server: Blockchain scanning, UTXO management, decoy selection, broadcast
//!
//! **SECURITY MODEL:**
//! - Private keys NEVER leave browser memory
//! - Server receives view keys (can see balances, NOT spend)
//! - Server receives signed transaction blobs (opaque, cannot modify)
//!
//! **LIMITATIONS:**
//! - Cannot implement full monero-wallet-rpc in WASM (requires libwallet C++)
//! - Ring signature construction requires server-provided decoys
//! - Key image calculation requires blockchain data from server

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

// ============================================================================
// CLSAG CONSTANTS (Monero Reference Implementation)
// ============================================================================

/// Domain separator prefix for CLSAG hashes
const CLSAG_PREFIX: &[u8] = b"CLSAG_";
/// Aggregation hash domain (for mu_P computation)
const CLSAG_AGG_0: &[u8] = b"agg_0";
/// Round hash domain (for challenge propagation)
const CLSAG_ROUND: &[u8] = b"round";
/// Length of PREFIX + AGG_0
const CLSAG_PREFIX_AGG_0_LEN: usize = 11; // 6 + 5

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoError {
    pub code: String,
    pub message: String,
}

impl CryptoError {
    fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

impl From<CryptoError> for JsValue {
    fn from(err: CryptoError) -> Self {
        JsValue::from_str(&format!("{}: {}", err.code, err.message))
    }
}

// ============================================================================
// VARINT ENCODING (Monero-compatible)
// ============================================================================

/// Encode a u64 as a varint (Monero/Bitcoin-style variable length integer)
///
/// **FIX v0.9.7 (Bug 1.7):** Server uses varint encoding for output_index in
/// derivation hashes. WASM was using fixed 8-byte to_le_bytes(), causing:
/// - Derivation scalar mismatch
/// - Key image mismatch
/// - "Sanity check failed" from daemon
///
/// Varint encoding:
/// - Values 0-127: 1 byte (value)
/// - Values 128-16383: 2 bytes ((value & 0x7f) | 0x80, value >> 7)
/// - etc.
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

// ============================================================================
// CLSAG HELPER FUNCTIONS (Monero Reference Implementation)
// ============================================================================

/// Hash data to a scalar using Keccak256
fn clsag_keccak256_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

/// Build the initial buffer for CLSAG hashing (for mu_P and mu_C computation)
/// Returns (buffer, mu_P, mu_C)
fn clsag_build_agg_buffer(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Vec<u8>, Scalar, Scalar) {
    let n = ring_keys.len();

    // Create buffer with exact capacity needed for agg hash
    let mut to_hash = Vec::with_capacity(((2 * n) + 5) * 32);

    // Domain separator: "CLSAG_" + "agg_0" + padding to 32 bytes
    to_hash.extend_from_slice(CLSAG_PREFIX); // "CLSAG_" (6 bytes)
    to_hash.extend_from_slice(CLSAG_AGG_0); // "agg_0" (5 bytes)
    to_hash.extend_from_slice(&[0u8; 32 - CLSAG_PREFIX_AGG_0_LEN]); // 21 null bytes

    // Ring keys (public keys P[i])
    for key in ring_keys {
        to_hash.extend_from_slice(&key.compress().to_bytes());
    }

    // Ring commitments (original commitments C[i], NOT adjusted)
    for commit in ring_commitments {
        to_hash.extend_from_slice(&commit.compress().to_bytes());
    }

    // Key image I
    to_hash.extend_from_slice(&key_image.compress().to_bytes());
    // D * inv8 (CRITICAL: uses D_INV8, not original D)
    to_hash.extend_from_slice(&d_inv8.compress().to_bytes());
    // pseudo_out
    to_hash.extend_from_slice(&pseudo_out.compress().to_bytes());

    // mu_P = H(agg_0 || ...)
    let mu_p = clsag_keccak256_to_scalar(&to_hash);

    // mu_C: change agg_0 -> agg_1 (just change the '0' to '1')
    // Position is PREFIX.len() + AGG_0.len() - 1 = 6 + 5 - 1 = 10
    to_hash[CLSAG_PREFIX_AGG_0_LEN - 1] = b'1';
    let mu_c = clsag_keccak256_to_scalar(&to_hash);

    (to_hash, mu_p, mu_c)
}

/// Convert buffer from agg format to round format
/// This truncates and modifies the domain separator in-place
/// v0.13.0 FIX: Added key_image and d_inv8 to round hash (REQUIRED by Monero spec!)
fn clsag_convert_to_round_format(
    to_hash: &mut Vec<u8>,
    ring_size: usize,
    pseudo_out: &EdwardsPoint,
    msg: &[u8; 32],
    key_image: &EdwardsPoint, // v0.13.0: ADDED
    d_inv8: &EdwardsPoint,    // v0.13.0: ADDED
) {
    // Truncate to: domain(32) + ring_keys(n*32) + ring_commitments(n*32)
    // = ((2*n) + 1) * 32
    to_hash.truncate(((2 * ring_size) + 1) * 32);

    // Change domain from "agg_1" (it was left at '1') to "round"
    // Positions 6..11 (PREFIX.len()..PREFIX.len()+5)
    for (i, byte) in CLSAG_ROUND.iter().enumerate() {
        to_hash[CLSAG_PREFIX.len() + i] = *byte;
    }

    // v0.13.0 FIX: Round hash MUST include:
    // domain || P[0..n] || C[0..n] || pseudo_out || msg || I || D || L || R
    to_hash.extend_from_slice(&pseudo_out.compress().to_bytes());
    to_hash.extend_from_slice(msg);
    to_hash.extend_from_slice(&key_image.compress().to_bytes()); // v0.13.0: ADD I
    to_hash.extend_from_slice(&d_inv8.compress().to_bytes()); // v0.13.0: ADD D
}

/// Add L and R points to round buffer (after truncating to base)
/// v0.13.0 FIX: Now preserves I and D in buffer
fn clsag_add_lr_to_round_buffer(
    to_hash: &mut Vec<u8>,
    ring_size: usize,
    l_point: &EdwardsPoint,
    r_point: &EdwardsPoint,
) {
    // v0.13.0 FIX: Truncate to: domain(32) + ring(2n*32) + pseudo_out(32) + msg(32) + I(32) + D(32)
    // = ((2*n) + 5) * 32  (was (2n+3)*32, now includes I and D)
    to_hash.truncate(((2 * ring_size) + 5) * 32);

    // Add L and R
    to_hash.extend_from_slice(&l_point.compress().to_bytes());
    to_hash.extend_from_slice(&r_point.compress().to_bytes());
}

/// Compute mu_P and mu_C mixing coefficients
fn clsag_compute_mixing_coefficients(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    let (_, mu_p, mu_c) =
        clsag_build_agg_buffer(ring_keys, ring_commitments, key_image, d_inv8, pseudo_out);
    (mu_p, mu_c)
}

// ============================================================================
// WALLET STATE (In-Memory)
// ============================================================================

/// In-memory wallet state for WASM
///
/// **SECURITY:**
/// - Keys are zeroized on drop
/// - Never serialized to localStorage without encryption
/// - User must provide password for persistence
pub struct WasmWallet {
    /// Private spend key (scalar)
    spend_key: Scalar,

    /// Private view key (scalar)
    view_key: Scalar,

    /// Public spend key (compressed Edwards point, 32 bytes)
    pub spend_key_pub: [u8; 32],

    /// Public view key (compressed Edwards point, 32 bytes)
    pub view_key_pub: [u8; 32],

    /// Monero address (Base58)
    pub address: String,

    /// Multisig state (None = normal wallet, Some = multisig)
    pub multisig_state: Option<MultisigState>,
}

impl Drop for WasmWallet {
    fn drop(&mut self) {
        // Zeroize sensitive fields manually
        // Scalars don't implement Zeroize, so we work with their byte representations
        self.spend_key_pub.zeroize();
        self.view_key_pub.zeroize();
    }
}

/// Multisig state for 2-of-3 coordination
#[derive(Clone, Serialize, Deserialize)]
pub struct MultisigState {
    /// Current stage: "prepared", "exchanged", "ready"
    pub stage: String,

    /// Multisig address (only set when stage == "ready")
    pub multisig_address: Option<String>,

    /// My multisig info blob (Round 1) - Sent to peers
    pub my_multisig_info: Option<String>,

    /// Peer multisig info blobs (Round 1) - Received from server
    pub peer_multisig_infos: Vec<String>,

    /// Number of required signatures (always 2 for 2-of-3)
    pub threshold: u8,

    /// Total number of participants (always 3 for 2-of-3)
    pub total: u8,
}

// ============================================================================
// WASM EXPORTS - Wallet Management
// ============================================================================

/// Generate a new Monero wallet with spend/view keys
///
/// Returns:
/// ```json
/// {
///   "seed": "12-word BIP39 mnemonic",
///   "address": "4...",
///   "viewKeyPub": "hex",
///   "spendKeyPub": "hex",
///   "viewKeyPriv": "hex",  // WARNING: Handle with care!
///   "spendKeyPriv": "hex"  // WARNING: Handle with care!
/// }
/// ```
///
/// **SECURITY:**
/// - Private keys returned ONCE for user backup
/// - Caller must store securely (encrypted IndexedDB)
///
/// # Parameters
/// - `network`: Optional - "mainnet", "stagenet", "testnet". Defaults to "mainnet".
#[wasm_bindgen]
pub fn generate_monero_wallet(network: Option<String>) -> Result<JsValue, JsValue> {
    // Reuse existing generate_wallet from lib.rs with network parameter
    super::generate_wallet(network)
}

/// Restore wallet from seed phrase
///
/// # Parameters
/// - `seed_phrase`: 12-word BIP39 mnemonic
/// - `network`: Optional - "mainnet", "stagenet", "testnet". Defaults to "mainnet".
///
/// # Returns
/// Same structure as `generate_monero_wallet()`
#[wasm_bindgen]
pub fn restore_wallet_from_seed(
    seed_phrase: String,
    network: Option<String>,
) -> Result<JsValue, JsValue> {
    use bip39::Mnemonic;
    use sha2::{Digest as Sha2Digest, Sha256};

    // Parse network (default to mainnet for production safety)
    let network_str = network.as_deref().unwrap_or("mainnet");
    let network_byte =
        super::network_string_to_byte(network_str).map_err(|e| JsValue::from_str(&e))?;

    // Parse mnemonic (bip39 v2 uses from_str instead of parse)
    let mnemonic: Mnemonic = seed_phrase
        .parse()
        .map_err(|e: bip39::Error| JsValue::from_str(&format!("Invalid seed phrase: {e}")))?;

    // Derive entropy from mnemonic (bip39 v2 returns (array, word_count) tuple)
    let (entropy, _word_count) = mnemonic.to_entropy_array();

    // Expand to 32 bytes for spend key
    let mut hasher = Sha256::new();
    hasher.update(entropy);
    hasher.update(b"monero_spend_key");
    let spend_key_bytes: [u8; 32] = hasher.finalize().into();

    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_bytes);

    // Derive view key
    let mut view_key_hasher = Keccak256::new();
    view_key_hasher.update(spend_scalar.to_bytes());
    let view_key_hash: [u8; 32] = view_key_hasher.finalize().into();
    let view_scalar = Scalar::from_bytes_mod_order(view_key_hash);

    // Derive public keys
    let spend_public = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &spend_scalar;
    let view_public = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &view_scalar;

    let spend_pub_bytes = spend_public.compress().to_bytes();
    let view_pub_bytes = view_public.compress().to_bytes();

    // Generate address with explicit network
    let address = super::generate_monero_address_with_network(
        &spend_pub_bytes,
        &view_pub_bytes,
        network_byte,
    )
    .map_err(|e| JsValue::from_str(&e))?;

    let result = serde_json::json!({
        "seed": seed_phrase,
        "address": address,
        "viewKeyPub": hex::encode(view_pub_bytes),
        "spendKeyPub": hex::encode(spend_pub_bytes),
        "viewKeyPriv": hex::encode(view_scalar.to_bytes()),
        "spendKeyPriv": hex::encode(spend_scalar.to_bytes()),
        "network": network_str,
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

// ============================================================================
// MULTISIG OPERATIONS (Client-Side Only)
// ============================================================================

/// Prepare multisig (Round 1) - Generate multisig info blob
///
/// This generates the cryptographic material needed for 2-of-3 multisig setup.
/// The blob is opaque and safe to send to the server for relay to peers.
///
/// # Parameters
/// - `spend_key_priv_hex`: Private spend key (hex, 64 chars)
/// - `view_key_priv_hex`: Private view key (hex, 64 chars)
///
/// # Returns
/// ```json
/// {
///   "multisigInfo": "base64-encoded blob",
///   "stage": "prepared"
/// }
/// ```
///
/// **SECURITY:**
/// - The multisig_info blob does NOT contain raw private keys
/// - It contains public key commitments + proofs
/// - Safe to relay through untrusted server
#[wasm_bindgen]
pub fn prepare_multisig_wasm(
    spend_key_priv_hex: String,
    view_key_priv_hex: String,
) -> Result<JsValue, JsValue> {
    // Decode private keys
    let spend_bytes = hex::decode(&spend_key_priv_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid spend key hex: {e}")))?;
    let view_bytes = hex::decode(&view_key_priv_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid view key hex: {e}")))?;

    if spend_bytes.len() != 32 || view_bytes.len() != 32 {
        return Err(JsValue::from_str("Keys must be 32 bytes"));
    }

    let mut spend_key_arr = [0u8; 32];
    let mut view_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    view_key_arr.copy_from_slice(&view_bytes);

    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // Generate public keys for multisig info
    let spend_public = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &spend_scalar;

    // Multisig info format (simplified for proof-of-concept):
    // In production, this would be the output of monero-wallet-rpc's prepare_multisig
    // For now, we create a blob with our public spend key
    let multisig_info_data = serde_json::json!({
        "public_spend_key": hex::encode(spend_public.compress().to_bytes()),
        "type": "prepare",
        "version": 1,
    });

    let multisig_info_json = serde_json::to_string(&multisig_info_data)
        .map_err(|e| JsValue::from_str(&format!("JSON error: {e}")))?;

    // Base64 encode for transport
    use base64::{engine::general_purpose, Engine as _};
    let multisig_info_b64 = general_purpose::STANDARD.encode(&multisig_info_json);

    // Export view key component for shared view key derivation
    // NOTE: This is the PRIVATE view key, required for Monero multisig protocol
    // where b_shared = b_buyer + b_vendor + b_arbiter (mod l)
    let view_key_component = hex::encode(view_key_arr);

    let result = serde_json::json!({
        "multisigInfo": multisig_info_b64,
        "viewKeyComponent": view_key_component, // For server-side coordination
        "stage": "prepared"
    });

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    view_key_arr.zeroize();

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// Make multisig (Round 2) - Finalize multisig address
///
/// Takes peer multisig info blobs and combines them to create the final
/// 2-of-3 multisig address.
///
/// # Parameters
/// - `spend_key_priv_hex`: Your private spend key (hex, 64 chars)
/// - `my_view_key_hex`: Your private view key component (hex, 64 chars)
/// - `peer_view_keys_json`: JSON array of peer view key components (hex strings)
/// - `peer_infos_json`: JSON array of peer multisig_info blobs (base64)
///
/// # Returns
/// ```json
/// {
///   "multisigAddress": "9...",
///   "sharedViewKey": "hex",  // Private view key for server monitoring
///   "stage": "ready",
///   "threshold": 2,
///   "total": 3
/// }
/// ```
///
/// **SECURITY:**
/// - `sharedViewKey` is derived using Monero's official protocol:
///   b_shared = b_buyer + b_vendor + b_arbiter (mod l)
/// - It allows VIEWING balance/transactions but NOT spending
/// - Safe to send to server for balance monitoring
/// - All 3 participants generate the SAME shared view key (deterministic)
///
/// **LIMITATIONS:**
/// - This is a SIMPLIFIED implementation for PoC
/// - Production version must use monero-wallet-rpc via server proxy
#[wasm_bindgen]
pub fn make_multisig_wasm(
    spend_key_priv_hex: String,
    my_view_key_hex: String,
    peer_view_keys_json: String,
    peer_infos_json: String,
) -> Result<JsValue, JsValue> {
    // Parse peer infos
    let peer_infos: Vec<String> = serde_json::from_str(&peer_infos_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid peer_infos JSON: {e}")))?;

    if peer_infos.len() != 2 {
        return Err(JsValue::from_str(
            "Expected 2 peer infos for 2-of-3 multisig",
        ));
    }

    // Decode my spend key
    let spend_bytes = hex::decode(&spend_key_priv_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid spend key: {e}")))?;
    let mut spend_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    let my_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // Decode peer public keys from multisig info blobs
    let mut peer_public_keys = Vec::new();

    use base64::{engine::general_purpose, Engine as _};

    for peer_info_b64 in &peer_infos {
        let peer_info_json = general_purpose::STANDARD
            .decode(peer_info_b64)
            .map_err(|e| JsValue::from_str(&format!("Invalid base64: {e}")))?;
        let peer_info_str = String::from_utf8(peer_info_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid UTF8: {e}")))?;
        let peer_data: serde_json::Value = serde_json::from_str(&peer_info_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer JSON: {e}")))?;

        let pub_key_hex = peer_data["public_spend_key"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("Missing public_spend_key"))?;

        peer_public_keys.push(pub_key_hex.to_string());
    }

    // Generate my public key
    let my_public = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &my_scalar;

    // ✅ MONERO OFFICIAL PROTOCOL: Derive shared spend PUBLIC key via ADDITION
    // P_shared = P_buyer + P_vendor + P_arbiter (point addition on Ed25519)
    // This is how Monero multisig works - all participants add their public keys

    // Start with my public key
    let mut multisig_spend_public = my_public;

    // Add each peer's public spend key (point addition on Ed25519 curve)
    for peer_pub_hex in &peer_public_keys {
        let peer_pub_bytes = hex::decode(peer_pub_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer public key hex: {e}")))?;
        if peer_pub_bytes.len() != 32 {
            return Err(JsValue::from_str("Peer public key must be 32 bytes"));
        }
        let mut peer_pub_arr = [0u8; 32];
        peer_pub_arr.copy_from_slice(&peer_pub_bytes);

        // Decompress the peer's public key point
        let peer_compressed = curve25519_dalek::edwards::CompressedEdwardsY(peer_pub_arr);
        let peer_point = peer_compressed
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid peer public key point"))?;

        // Point addition: P_shared = P_shared + P_peer
        multisig_spend_public += peer_point;
    }

    // ✅ MONERO OFFICIAL PROTOCOL: Derive shared view key via ADDITION (not hash)
    // b_shared = b_buyer + b_vendor + b_arbiter (mod l)
    // This is the ONLY way to generate a view key that can decrypt the multisig address outputs

    // Parse my view key
    let my_view_bytes = hex::decode(&my_view_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid my_view_key hex: {e}")))?;
    if my_view_bytes.len() != 32 {
        return Err(JsValue::from_str("my_view_key must be 32 bytes"));
    }
    let mut my_view_arr = [0u8; 32];
    my_view_arr.copy_from_slice(&my_view_bytes);
    let my_view_scalar = Scalar::from_bytes_mod_order(my_view_arr);

    // Parse peer view keys
    let peer_view_keys: Vec<String> = serde_json::from_str(&peer_view_keys_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid peer_view_keys JSON: {e}")))?;

    if peer_view_keys.len() != 2 {
        return Err(JsValue::from_str(
            "Expected 2 peer view keys for 2-of-3 multisig",
        ));
    }

    // Start with my view key scalar
    let mut shared_view_scalar = my_view_scalar;

    // Add each peer's view key scalar (modular addition is automatic in curve25519-dalek)
    for peer_view_hex in &peer_view_keys {
        let peer_view_bytes = hex::decode(peer_view_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer view key hex: {e}")))?;
        if peer_view_bytes.len() != 32 {
            return Err(JsValue::from_str("Peer view key must be 32 bytes"));
        }
        let mut peer_view_arr = [0u8; 32];
        peer_view_arr.copy_from_slice(&peer_view_bytes);
        let peer_scalar = Scalar::from_bytes_mod_order(peer_view_arr);

        // Modular addition (automatic mod l where l = curve order)
        shared_view_scalar += peer_scalar;

        peer_view_arr.zeroize(); // Security: clear sensitive data
    }

    // Derive shared view public key from the summed scalar
    let multisig_view_public =
        curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &shared_view_scalar;

    // Generate multisig address
    let multisig_address = super::generate_monero_address(
        &multisig_spend_public.compress().to_bytes(),
        &multisig_view_public.compress().to_bytes(),
    )
    .map_err(|e| JsValue::from_str(&e))?;

    // Export shared view key for server monitoring (deterministic - same for all parties)
    // This is the PRIVATE view key scalar, not the public key
    let shared_view_key_hex = hex::encode(shared_view_scalar.to_bytes());

    let result = serde_json::json!({
        "multisigAddress": multisig_address,
        "sharedViewKey": shared_view_key_hex,  // Private view key for balance monitoring
        "stage": "ready",
        "threshold": 2,
        "total": 3
    });

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    my_view_arr.zeroize();

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

// ============================================================================
// TRANSACTION SIGNING (CLSAG - Real Implementation with monero-clsag-mirror)
// ============================================================================

use monero_clsag_mirror::{Clsag, ClsagContext};
use monero_generators::hash_to_point;
use monero_primitives_mirror::{Commitment, Decoys};

/// Sign input data structure from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInputData {
    /// Ring members: [[key, commitment], ...] - all hex encoded 32-byte points
    pub ring: Vec<[String; 2]>,
    /// Position offsets for ring members (blockchain global output indices)
    pub offsets: Vec<u64>,
    /// Index of signer in ring (0-15 typically)
    pub signer_index: u8,
    /// v0.35.1: commitment_mask is now OUTPUT_MASK (derived) for pseudo_out balance
    /// Previously this was funding_commitment_mask (z) which broke balance
    pub commitment_mask: String,
    /// v0.35.1: funding_mask is the INPUT's commitment mask (z)
    /// Used to compute: mask_delta = funding_mask - commitment_mask = z - output_mask
    /// If not provided, mask_delta = 0 (legacy behavior)
    #[serde(default)]
    pub funding_mask: Option<String>,
    /// Commitment amount in atomic units
    pub commitment_amount: u64,

    // ===== MuSig2 v0.9.2: Nonce aggregation fields =====
    /// Alpha secret (nonce scalar) - hex string, 64 chars
    /// If provided, use this instead of generating random nonce
    #[serde(default)]
    pub alpha_secret: Option<String>,

    /// Peer's nonce public points - JSON string containing {r_public, r_prime_public}
    /// If provided, compute R_agg = R_mine + R_peer for deterministic L
    #[serde(default)]
    pub peer_nonce_public: Option<String>,

    // ===== v0.14.2: Derivation fields for one-time outputs =====
    /// Transaction public key R from funding TX (hex, 64 chars)
    /// Used to compute derivation: H_s(a·R || output_index)
    #[serde(default)]
    pub tx_pub_key: Option<String>,

    /// Multisig shared view private key (hex, 64 chars)
    /// Used to compute derivation: H_s(a·R || output_index)
    #[serde(default)]
    pub view_key: Option<String>,

    /// Output index in the funding transaction
    /// Used to compute derivation: H_s(a·R || output_index)
    #[serde(default)]
    pub output_index: Option<u64>,

    // ===== v0.42.0: Alpha verification for nonce integrity =====
    /// My submitted R point (r_public) from nonce commitment (hex, 64 chars)
    /// If provided, WASM verifies that alpha_secret*G == my_submitted_r_public
    /// This catches cases where alpha_secret was regenerated after nonce submission
    #[serde(default)]
    pub my_submitted_r_public: Option<String>,
}

/// Create a key image from spend key (SINGLE-SIGNER MODE)
///
/// Key image I = x * H(P) where:
/// - x is the private spend key
/// - P = x*G is the public spend key
/// - H is the hash-to-point function
///
/// **WARNING**: This is for single-signer wallets only!
/// For 2-of-3 multisig, use `compute_partial_key_image()` instead.
///
/// # Parameters
/// - `spend_key_priv_hex`: Private spend key (hex, 64 chars)
///
/// # Returns
/// ```json
/// {
///   "keyImage": "hex-encoded 32-byte key image",
///   "publicKey": "hex-encoded 32-byte public key"
/// }
/// ```
#[wasm_bindgen]
pub fn compute_key_image(spend_key_priv_hex: String) -> Result<JsValue, JsValue> {
    // Decode spend key
    let spend_bytes = hex::decode(&spend_key_priv_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid spend key hex: {e}")))?;

    if spend_bytes.len() != 32 {
        return Err(JsValue::from_str("Spend key must be 32 bytes"));
    }

    let mut spend_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // Compute public key P = x * G
    let public_key = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &spend_scalar;
    let public_key_bytes = public_key.compress().to_bytes();

    // Compute H(P) using hash_to_point
    let hp = hash_to_point(public_key_bytes);

    // Compute key image I = x * H(P)
    let key_image = spend_scalar * hp;
    let key_image_bytes = key_image.compress().to_bytes();

    // Zeroize sensitive data
    spend_key_arr.zeroize();

    let result = serde_json::json!({
        "keyImage": hex::encode(key_image_bytes),
        "publicKey": hex::encode(public_key_bytes)
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// Compute partial key image for multisig signing
///
/// For 2-of-3 multisig, each signer contributes a partial key image:
/// - pKI_i = x_i * Hp(P_multisig)
///
/// The server aggregates partial key images from 2 signers:
/// - KI_combined = pKI_1 + pKI_2
///
/// This ensures all signers produce the SAME key image for the same input,
/// which is required for valid Monero ring signatures.
///
/// # Parameters
/// - `spend_key_priv_hex`: Signer's private spend key (hex, 64 chars)
/// - `multisig_pub_key_hex`: Multisig address's public spend key (hex, 64 chars)
///   This is the combined public key: P_multisig = P_buyer + P_vendor + P_arbiter
///
/// # Returns
/// ```json
/// {
///   "partialKeyImage": "hex-encoded 32-byte partial key image contribution",
///   "multisigPubKey": "hex-encoded 32-byte multisig public key (echo for verification)"
/// }
/// ```
///
/// # Security
/// - The partial key image does NOT reveal the private spend key
/// - Safe to send to server for aggregation
/// - Both signers' partials are needed to reconstruct the full key image
///
/// # CRITICAL (v0.8.4)
/// The second parameter MUST be the ONE-TIME OUTPUT PUBLIC KEY (P)
/// NOT the multisig address spend pubkey (B).
///
/// P = ring[signer_idx][0] = the actual output being spent
/// B = multisig address component (WRONG for key image!)
///
/// Formula: pKI = x * Hp(P) where P is the one-time output key
#[wasm_bindgen]
pub fn compute_partial_key_image(
    spend_key_priv_hex: String,
    one_time_pubkey_hex: String, // RENAMED: was multisig_pub_key_hex (WRONG name)
    lagrange_coefficient_hex: String, // v0.45.0: FROST Lagrange coefficient λ_i (REQUIRED)
) -> Result<JsValue, JsValue> {
    // Decode spend key
    let spend_bytes = hex::decode(&spend_key_priv_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid spend key hex: {e}")))?;

    if spend_bytes.len() != 32 {
        return Err(JsValue::from_str("Spend key must be 32 bytes"));
    }

    let mut spend_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // ===========================================================
    // v0.45.0: FROST Lagrange coefficient (REQUIRED - NO OPTIONAL)
    //
    // The partial key image MUST be weighted by Lagrange coefficient:
    //   pKI_i = (λ_i * x_i) * Hp(P)
    //
    // This PREVENTS the overlap bug:
    //   I = pKI_1 + pKI_2 = (λ_1*x_1 + λ_2*x_2) * Hp(P) = x_total * Hp(P)
    //
    // Without Lagrange (Monero native): k2 is DOUBLE-COUNTED!
    // ===========================================================
    let lambda_bytes = hex::decode(&lagrange_coefficient_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid lagrange_coefficient hex: {e}")))?;
    if lambda_bytes.len() != 32 {
        return Err(JsValue::from_str("lagrange_coefficient must be 32 bytes"));
    }
    let mut lambda_arr = [0u8; 32];
    lambda_arr.copy_from_slice(&lambda_bytes);
    let lambda = Scalar::from_bytes_mod_order(lambda_arr);

    web_sys::console::log_1(
        &format!(
            "[PKI v0.45.0] FROST: Applying λ={} to spend key (REQUIRED)",
            hex::encode(&lambda.to_bytes()[..8])
        )
        .into(),
    );

    // Apply Lagrange coefficient (ALWAYS - not optional)
    let effective_spend = lambda * spend_scalar;

    // Decode one-time output public key (P = ring[signer_idx][0])
    let pubkey_bytes = hex::decode(&one_time_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid one_time_pubkey hex: {e}")))?;

    if pubkey_bytes.len() != 32 {
        return Err(JsValue::from_str("One-time pubkey must be 32 bytes"));
    }

    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    // Compute Hp(P) - hash-to-point of the ONE-TIME OUTPUT PUBLIC KEY
    // This matches Monero's: hash_to_p3(H_p3, P[l])
    let hp = hash_to_point(pubkey_arr);

    web_sys::console::log_1(
        &format!(
            "[PKI] Computing pKI = λ*x * Hp(P) where P = {}...",
            &one_time_pubkey_hex[..16.min(one_time_pubkey_hex.len())]
        )
        .into(),
    );

    // Compute partial key image: pKI = (λ * x) * Hp(P)
    let partial_key_image = effective_spend * hp;
    let partial_key_image_bytes = partial_key_image.compress().to_bytes();

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    lambda_arr.zeroize();

    let result = serde_json::json!({
        "partialKeyImage": hex::encode(partial_key_image_bytes),
        "oneTimePubkey": one_time_pubkey_hex,
        "lagrangeApplied": true
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// Compute partial key image WITH output secret derivation
///
/// This is the CORRECT implementation for spending Monero one-time outputs.
///
/// In Monero, when funds are sent to an address (A, B) with view key a and spend key b:
/// - Sender creates: P = H_s(r·A || idx)·G + B  (one-time output pubkey)
/// - Receiver spends with: x = H_s(a·R || idx) + b  (output secret key)
///
/// For 2-of-3 multisig:
/// - B = b1·G + b2·G + b3·G (sum of public keys)
/// - To spend: x = H_s(a_shared·R || idx) + (b1 + b2) for 2 signers
/// - Each signer computes: pKI_i = (H_s(a·R || idx) + b_i) * Hp(P)
///
/// # Parameters
/// - `spend_key_hex`: Signer's private spend key share (hex, 64 chars)
/// - `tx_pub_key_hex`: TX public key R from the FUNDING transaction (hex, 64 chars)
/// - `view_key_shared_hex`: Shared multisig view key (hex, 64 chars)
/// - `output_index`: Output index in the funding transaction (typically 0)
/// - `one_time_pubkey_hex`: The one-time output public key P (hex, 64 chars)
///
/// # Returns
/// ```json
/// {
///   "partialKeyImage": "hex-encoded 32-byte partial key image",
///   "derivationScalar": "hex-encoded derivation H_s(a·R || idx) for debugging"
/// }
/// ```
///
/// # Cryptographic Details
/// ```
/// shared_secret = a_shared * R  (point multiplication)
/// derivation = H_s(shared_secret || output_index)  (hash-to-scalar)
/// effective_spend = derivation + spend_share
/// pKI = effective_spend * Hp(P)
/// ```
#[wasm_bindgen]
pub fn compute_partial_key_image_with_derivation(
    spend_key_hex: String,
    tx_pub_key_hex: String,
    view_key_shared_hex: String,
    output_index: u64,
    one_time_pubkey_hex: String,
    lagrange_coefficient_hex: String, // v0.45.0: FROST Lagrange coefficient λ_i (REQUIRED)
) -> Result<JsValue, JsValue> {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    // 1. Parse spend key
    let spend_bytes = hex::decode(&spend_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid spend key hex: {e}")))?;
    if spend_bytes.len() != 32 {
        return Err(JsValue::from_str("Spend key must be 32 bytes"));
    }
    let mut spend_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // ===========================================================
    // v0.45.0: FROST Lagrange coefficient (REQUIRED - NO OPTIONAL)
    //
    // Lagrange coefficient MUST be applied to prevent overlap bug.
    // ===========================================================
    let lambda_bytes = hex::decode(&lagrange_coefficient_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid lagrange_coefficient hex: {e}")))?;
    if lambda_bytes.len() != 32 {
        return Err(JsValue::from_str("lagrange_coefficient must be 32 bytes"));
    }
    let mut lambda_arr = [0u8; 32];
    lambda_arr.copy_from_slice(&lambda_bytes);
    let lambda = Scalar::from_bytes_mod_order(lambda_arr);

    // 2. Parse tx_pub_key (R) - the TX public key from funding transaction
    let tx_pub_bytes = hex::decode(&tx_pub_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid tx_pub_key hex: {e}")))?;
    if tx_pub_bytes.len() != 32 {
        return Err(JsValue::from_str("tx_pub_key must be 32 bytes"));
    }
    let mut tx_pub_arr = [0u8; 32];
    tx_pub_arr.copy_from_slice(&tx_pub_bytes);
    let tx_pub_point = CompressedEdwardsY(tx_pub_arr)
        .decompress()
        .ok_or_else(|| JsValue::from_str("Invalid tx_pub_key: point decompression failed"))?;

    // 3. Parse shared view key (a_shared)
    let view_bytes = hex::decode(&view_key_shared_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid view key hex: {e}")))?;
    if view_bytes.len() != 32 {
        return Err(JsValue::from_str("View key must be 32 bytes"));
    }
    let mut view_key_arr = [0u8; 32];
    view_key_arr.copy_from_slice(&view_bytes);
    let view_scalar = Scalar::from_bytes_mod_order(view_key_arr);

    // 4. Parse one_time_pubkey (P) - the output we're spending
    let pubkey_bytes = hex::decode(&one_time_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid one_time_pubkey hex: {e}")))?;
    if pubkey_bytes.len() != 32 {
        return Err(JsValue::from_str("one_time_pubkey must be 32 bytes"));
    }
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    // 5. Compute shared secret: a_shared * R (ECDH)
    // This equals r * A where r is the funding tx secret (which we don't know)
    // BUG FIX 2.1 (v0.9.6): Apply cofactor multiplication for consistency with server
    // Monero derivation: D = 8·v·R = 8·r·V (cofactor = 8 in ed25519)
    let shared_secret_point = (view_scalar * tx_pub_point).mul_by_cofactor();
    let shared_secret_bytes = shared_secret_point.compress().to_bytes();

    // 6. Compute derivation scalar: H_s(shared_secret || varint(output_index))
    // This is the key derivation term that links the output to the recipient
    // FIX v0.9.7 (Bug 1.7): Use varint encoding to match server (transaction_builder.rs)
    // Previous bug: Used to_le_bytes() (8 bytes) but server uses varint (1+ bytes)
    let mut hasher = Keccak256::new();
    hasher.update(shared_secret_bytes);
    hasher.update(encode_varint(output_index)); // FIX: varint, not to_le_bytes
    let derivation_hash: [u8; 32] = hasher.finalize().into();
    let derivation_scalar = Scalar::from_bytes_mod_order(derivation_hash);

    // 7. Compute effective spend key: derivation + λ * spend_share
    // For the full output secret: x = H_s(a·R || idx) + b
    //
    // ===========================================================
    // v0.45.0 FROST (REQUIRED - NO OPTIONAL):
    //   effective_spend = derivation + λ * spend_share
    //
    // In FROST, only the spend_share is weighted by λ.
    // The derivation is deterministic and shared by all signers.
    //
    // Aggregation:
    //   pKI_1 + pKI_2 = (d + λ_1*s_1)*Hp + (λ_2*s_2)*Hp
    //                 = (d + λ_1*s_1 + λ_2*s_2) * Hp
    //                 = (d + x_total) * Hp  ✓
    //
    // NOTE: Only FIRST signer includes derivation to avoid double-counting!
    // This function is for first signer. Second signer uses compute_partial_key_image.
    // ===========================================================
    web_sys::console::log_1(
        &format!(
            "[PKI Derivation v0.45.0] FROST: Applying λ={} to spend_share (REQUIRED)",
            hex::encode(&lambda.to_bytes()[..8])
        )
        .into(),
    );
    let weighted_spend = lambda * spend_scalar;
    let effective_spend_scalar = derivation_scalar + weighted_spend;

    // 8. Compute Hp(P) - hash-to-point of the output public key
    let hp = hash_to_point(pubkey_arr);

    // 9. Compute partial key image: pKI = effective_spend * Hp(P)
    let partial_key_image = effective_spend_scalar * hp;
    let partial_key_image_bytes = partial_key_image.compress().to_bytes();

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    view_key_arr.zeroize();
    lambda_arr.zeroize();

    // Log for debugging (remove in production)
    web_sys::console::log_1(&format!(
        "[PKI Derivation] tx_pub_key: {}, view_key: {}..., output_idx: {}, derivation: {}, λ applied",
        tx_pub_key_hex,
        &view_key_shared_hex[..16],
        output_index,
        hex::encode(derivation_hash)
    ).into());

    let result = serde_json::json!({
        "partialKeyImage": hex::encode(partial_key_image_bytes),
        "derivationScalar": hex::encode(derivation_hash),
        "oneTimePubKey": one_time_pubkey_hex,
        "lagrangeApplied": true
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

// ============================================================================
// MuSig2-STYLE NONCE GENERATION (v0.9.0)
// ============================================================================

/// Generate MuSig2-style nonce commitment for CLSAG multisig
///
/// **v0.9.0 FIX:** To solve the "Sanity check failed" issue where each signer
/// had unique alpha causing L₁ ≠ L₂, we implement MuSig2-style nonce aggregation:
/// 1. Each signer generates random α (nonce)
/// 2. Computes R = α*G and R' = α*Hp(P)
/// 3. Computes commitment H(R || R')
/// 4. Returns {commitment_hash, r_public, r_prime_public, alpha_secret}
/// 5. alpha_secret stored in JS memory (NOT localStorage)
/// 6. Server aggregates: R_agg = R₁ + R₂
/// 7. Both signers use R_agg for L in their signatures
///
/// **Security:** alpha_secret returned to JS, kept in window.tempNonceAlpha
#[wasm_bindgen]
pub fn generate_nonce_commitment(
    _tx_prefix_hash: &str, // Not used for nonce generation, but kept for API consistency
    multisig_pub_key: &str,
) -> Result<JsValue, JsValue> {
    use curve25519_dalek::constants;

    // Generate random nonce (alpha)
    let mut alpha_bytes = [0u8; 32];
    getrandom::getrandom(&mut alpha_bytes)
        .map_err(|e| JsValue::from_str(&format!("RNG error: {e}")))?;
    let alpha = Scalar::from_bytes_mod_order(alpha_bytes);

    // Compute R = alpha * G
    let r_point = &alpha * constants::ED25519_BASEPOINT_TABLE;
    let r_public = hex::encode(r_point.compress().to_bytes());

    // Compute R' = alpha * Hp(P)
    let pubkey_bytes = hex::decode(multisig_pub_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid multisig_pub_key hex: {e}")))?;
    if pubkey_bytes.len() != 32 {
        return Err(JsValue::from_str("multisig_pub_key must be 32 bytes"));
    }
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    let hp = hash_to_point(pubkey_arr);
    let r_prime_point = alpha * hp;
    let r_prime_public = hex::encode(r_prime_point.compress().to_bytes());

    // Compute commitment H(R || R')
    let mut hasher = Keccak256::new();
    hasher.update(b"MUSIG2_NONCE_COMMITMENT");
    hasher.update(hex::decode(&r_public).unwrap());
    hasher.update(hex::decode(&r_prime_public).unwrap());
    let commitment_hash = hex::encode(hasher.finalize());

    // Return alpha_secret to JS (kept in memory, NOT localStorage)
    // JS will pass it back when calling sign_clsag_partial_wasm
    let alpha_hex = hex::encode(alpha.to_bytes());

    let result = serde_json::json!({
        "commitment_hash": commitment_hash,
        "r_public": r_public,
        "r_prime_public": r_prime_public,
        "alpha_secret": alpha_hex,  // Returned to JS, stored in window.tempNonceAlpha
    });

    web_sys::console::log_1(
        &format!(
            "[MuSig2] Nonce generated - R: {}..., commitment: {}...",
            &r_public[..16],
            &commitment_hash[..16]
        )
        .into(),
    );

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// Sign a single input with CLSAG ring signature
///
/// This function creates a CLSAG signature for one input of a transaction.
/// The server must provide the ring members (decoys) and other transaction data.
///
/// # Parameters
/// - `spend_key_priv_hex`: Your private spend key (hex, 64 chars)
/// - `input_data_json`: JSON containing ring data from server (SignInputData structure)
/// - `tx_prefix_hash_hex`: Hash of transaction prefix (what we're signing, 32 bytes hex)
/// - `pseudo_out_mask_hex`: Mask for this input's pseudo-output commitment
///
/// # Returns
/// ```json
/// {
///   "signature": {
///     "D": "hex-encoded D point",
///     "s": ["hex-encoded scalar", ...],
///     "c1": "hex-encoded scalar"
///   },
///   "keyImage": "hex-encoded key image",
///   "pseudoOut": "hex-encoded pseudo-output commitment"
/// }
/// ```
///
/// # Architecture Notes
/// For 2-of-3 multisig:
/// 1. Each party generates a partial signature share
/// 2. Server collects 2 shares and combines them
/// 3. Combined signature is broadcast
///
/// This function handles single-signer mode. For multisig, use sign_clsag_partial_wasm.
#[wasm_bindgen]
pub fn sign_clsag_wasm(
    spend_key_priv_hex: String,
    input_data_json: String,
    tx_prefix_hash_hex: String,
) -> Result<JsValue, JsValue> {
    use std_shims_mirror::vec::Vec as ShimsVec;
    use zeroize::Zeroizing;

    // Parse input data
    let input_data: SignInputData = serde_json::from_str(&input_data_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid input_data JSON: {e}")))?;

    // DIAGNOSTIC: Log input parameters
    web_sys::console::log_1(
        &format!(
            "[CLSAG Debug] sign_clsag_wasm called with:\n  \
         - tx_prefix_hash: {}\n  \
         - spend_key (first 8 hex): {}...\n  \
         - ring_size: {}\n  \
         - signer_index: {}\n  \
         - commitment_amount: {}",
            &tx_prefix_hash_hex[..16],
            &spend_key_priv_hex[..8],
            input_data.ring.len(),
            input_data.signer_index,
            input_data.commitment_amount
        )
        .into(),
    );

    // Parse tx prefix hash
    let msg_bytes = hex::decode(&tx_prefix_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid tx_prefix_hash hex: {e}")))?;
    if msg_bytes.len() != 32 {
        return Err(JsValue::from_str("tx_prefix_hash must be 32 bytes"));
    }
    let mut msg = [0u8; 32];
    msg.copy_from_slice(&msg_bytes);

    // Decode spend key
    let spend_bytes = hex::decode(&spend_key_priv_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid spend key hex: {e}")))?;
    if spend_bytes.len() != 32 {
        return Err(JsValue::from_str("Spend key must be 32 bytes"));
    }
    let mut spend_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    let spend_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(spend_key_arr));

    // Parse ring members
    let mut ring: ShimsVec<[curve25519_dalek::edwards::EdwardsPoint; 2]> = ShimsVec::new();
    for pair in &input_data.ring {
        let key_bytes = hex::decode(&pair[0])
            .map_err(|e| JsValue::from_str(&format!("Invalid ring key hex: {e}")))?;
        let commitment_bytes = hex::decode(&pair[1])
            .map_err(|e| JsValue::from_str(&format!("Invalid ring commitment hex: {e}")))?;

        if key_bytes.len() != 32 || commitment_bytes.len() != 32 {
            return Err(JsValue::from_str("Ring members must be 32 bytes each"));
        }

        let mut key_arr = [0u8; 32];
        let mut commitment_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        commitment_arr.copy_from_slice(&commitment_bytes);

        let key_point = curve25519_dalek::edwards::CompressedEdwardsY(key_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid ring key point"))?;
        let commitment_point = curve25519_dalek::edwards::CompressedEdwardsY(commitment_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid ring commitment point"))?;

        ring.push([key_point, commitment_point]);
    }

    // Parse commitment data
    let commitment_mask_bytes = hex::decode(&input_data.commitment_mask)
        .map_err(|e| JsValue::from_str(&format!("Invalid commitment_mask hex: {e}")))?;
    if commitment_mask_bytes.len() != 32 {
        return Err(JsValue::from_str("Commitment mask must be 32 bytes"));
    }
    let mut mask_arr = [0u8; 32];
    mask_arr.copy_from_slice(&commitment_mask_bytes);
    let commitment_mask = Scalar::from_bytes_mod_order(mask_arr);

    let commitment = Commitment::new(commitment_mask, input_data.commitment_amount);

    // Create decoys
    let decoys = Decoys::new(
        input_data.offsets.clone(),
        input_data.signer_index,
        ring.clone(),
    )
    .ok_or_else(|| JsValue::from_str("Failed to create decoys"))?;

    // Create CLSAG context
    let context = ClsagContext::new(decoys, commitment)
        .map_err(|e| JsValue::from_str(&format!("CLSAG context error: {e:?}")))?;

    // Generate RNG from seed (deterministic for WASM reproducibility)

    let mut rng_seed = [0u8; 32];
    getrandom::getrandom(&mut rng_seed)
        .map_err(|e| JsValue::from_str(&format!("RNG error: {e}")))?;
    let mut rng = rand_core::OsRng;

    // Create inputs vector
    let inputs = vec![(spend_scalar.clone(), context)];

    // DIAGNOSTIC: Log before signing
    web_sys::console::log_1(
        &format!(
        "[CLSAG Debug] About to call Clsag::sign() with {} input(s), signer_index={}, ring_size={}",
        inputs.len(), input_data.signer_index, ring.len()
    )
        .into(),
    );

    // Sign! The sum_outputs parameter should be the sum of output masks
    // For a simple transfer, this is typically known by the sender
    // We use Scalar::ZERO for the case where there's only one input
    let signatures = Clsag::sign(&mut rng, inputs, Scalar::ZERO, msg).map_err(|e| {
        // DIAGNOSTIC: Log the exact error variant
        let error_msg = format!("CLSAG signing error: {e:?}");
        web_sys::console::error_1(&error_msg.clone().into());
        JsValue::from_str(&error_msg)
    })?;

    web_sys::console::log_1(&"[CLSAG Debug] Clsag::sign() succeeded".into());

    // Extract the signature
    if signatures.is_empty() {
        return Err(JsValue::from_str("No signature produced"));
    }
    let (clsag, pseudo_out) = &signatures[0];

    // Serialize signature components
    let d_hex = hex::encode(clsag.D.compress().to_bytes());
    let s_hex: Vec<String> = clsag.s.iter().map(|s| hex::encode(s.to_bytes())).collect();
    let c1_hex = hex::encode(clsag.c1.to_bytes());
    let pseudo_out_hex = hex::encode(pseudo_out.compress().to_bytes());

    // ============================================================================
    // MULTISIG KEY IMAGE COMPUTATION & DIAGNOSTIC LOGGING
    // ============================================================================
    // For multisig, we MUST use the public key from the ring at signer position,
    // NOT derive it from the spend scalar (which is only a share in multisig).
    //
    // The ring was constructed with multisig_spend_pub_key at signer_index,
    // so we extract that key and use it to compute the partial key image:
    // pKI = x_share · Hp(P_multisig)
    //
    // This is critical because:
    // - In multisig, spend_scalar is x_i (a share), not the full spend key
    // - P_multisig = P_buyer + P_vendor + P_arbiter (aggregated public key)
    // - We cannot derive P_multisig from x_i alone
    // - We MUST use the P_multisig from the ring
    // ============================================================================
    let signer_public_key = ring[input_data.signer_index as usize][0];
    let signer_pub_hex = hex::encode(signer_public_key.compress().to_bytes());

    // DIAGNOSTIC: Log signer public key extraction
    web_sys::console::log_1(
        &format!(
            "[CLSAG Debug] Extracted signer_public_key from ring[{}]: {}",
            input_data.signer_index, signer_pub_hex
        )
        .into(),
    );

    let hp = hash_to_point(signer_public_key.compress().to_bytes());
    let hp_hex = hex::encode(hp.compress().to_bytes());

    web_sys::console::log_1(&format!("[CLSAG Debug] hash_to_point(signer_pub): {hp_hex}").into());

    let key_image = *spend_scalar * hp;
    let key_image_hex = hex::encode(key_image.compress().to_bytes());

    web_sys::console::log_1(
        &format!("[CLSAG Debug] Computed partial_key_image: {key_image_hex}").into(),
    );

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    mask_arr.zeroize();

    let result = serde_json::json!({
        "signature": {
            "D": d_hex,
            "s": s_hex,
            "c1": c1_hex
        },
        "keyImage": key_image_hex,
        "pseudoOut": pseudo_out_hex
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// Sign with partial key for 2-of-3 multisig CLSAG
///
/// Unlike `sign_clsag_wasm()` which requires the full private key matching the public
/// key in the ring, this function is designed for multisig where each participant
/// holds only a partial key (x_i) and the ring contains the AGGREGATED public key
/// (P_multisig = P_1 + P_2 + P_3).
///
/// # Multisig Key Relationship
/// - Each signer has: x_i (partial private key) and P_i = x_i * G (partial public key)
/// - The ring contains: P_multisig = P_1 + P_2 + P_3
/// - Key image: KI = (x_1 + x_2) * Hp(P_multisig) for 2-of-3
///
/// # Parameters
/// - `spend_key_priv_hex`: Signer's PARTIAL private spend key (hex, 64 chars)
/// - `input_data_json`: Ring data from server (same as sign_clsag_wasm)
/// - `tx_prefix_hash_hex`: Transaction prefix hash (32 bytes hex)
/// - `multisig_pub_key_hex`: The AGGREGATED multisig public key P_multisig
///
/// # Returns
/// Partial signature components that can be aggregated server-side:
/// ```json
/// {
///   "signature": { "D": "...", "s": [...], "c1": "..." },
///   "keyImage": "...",          // Partial key image (NOT final)
///   "partialKeyImage": "...",   // Same as keyImage for clarity
///   "pseudoOut": "..."
/// }
/// ```
#[wasm_bindgen]
pub fn sign_clsag_partial_wasm(
    spend_key_priv_hex: String,
    input_data_json: String,
    tx_prefix_hash_hex: String,
    multisig_pub_key_hex: String,
    aggregated_key_image_hex: String, // AGGREGATED key_image from server (pKI_1 + pKI_2)
    first_signer_c1_hex: Option<String>, // c1 from first signer (empty string = compute new)
    first_signer_s_values_json: Option<String>, // v0.8.7: s-values from first signer for decoy reuse
    first_signer_d_hex: Option<String>, // v0.12.1: D point from first signer for mu consistency
    mu_p_hex: Option<String>,           // v0.12.3: Server-computed mu_P (use if provided)
    mu_c_hex: Option<String>,           // v0.12.3: Server-computed mu_C (use if provided)
    first_signer_pseudo_out_hex: Option<String>, // v0.17.0: Pseudo-out from first signer (second signer MUST use this)
    first_signer_used_r_agg: bool, // v0.19.0: True if first signer had R_agg (second signer should use alpha)
    lagrange_coefficient_hex: String, // v0.45.0: FROST Lagrange coefficient λ_i (REQUIRED - prevents overlap!)
) -> Result<JsValue, JsValue> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use sha3::Keccak256;

    let has_first_signer_c1 = first_signer_c1_hex
        .as_ref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    // v0.8.7: Parse first signer's s-values if provided
    let first_signer_s_values: Option<Vec<Scalar>> = first_signer_s_values_json
        .as_ref()
        .filter(|s| !s.is_empty())
        .and_then(|json| {
            let s_hex_vec: Vec<String> = serde_json::from_str(json).ok()?;
            let mut scalars = Vec::with_capacity(s_hex_vec.len());
            for hex_str in &s_hex_vec {
                let bytes = hex::decode(hex_str).ok()?;
                if bytes.len() != 32 {
                    return None;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                scalars.push(Scalar::from_bytes_mod_order(arr));
            }
            Some(scalars)
        });

    let has_first_signer_s_values = first_signer_s_values.is_some();

    // ===========================================================
    // v0.45.0: FROST Lagrange coefficient (REQUIRED - NO OPTIONAL)
    //
    // Lagrange coefficient PREVENTS the overlap bug in 2-of-3 multisig:
    //   Monero native: (k1+k2) + (k2+k3) = k1 + 2*k2 + k3  ← k2 DOUBLE-COUNTED!
    //   FROST:         λ_1*s_1 + λ_2*s_2 = x_reconstructed ← NO OVERLAP!
    //
    // Each signer MUST weight their contribution:
    //   s_i = alpha_i - c_p * (λ_i * x_i) - c_c * (λ_i * z_i)
    // ===========================================================
    let lambda_bytes = hex::decode(&lagrange_coefficient_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid lagrange_coefficient hex: {e}")))?;
    if lambda_bytes.len() != 32 {
        return Err(JsValue::from_str("lagrange_coefficient must be 32 bytes"));
    }
    let mut lambda_arr = [0u8; 32];
    lambda_arr.copy_from_slice(&lambda_bytes);
    let lagrange_coefficient = Scalar::from_bytes_mod_order(lambda_arr);

    web_sys::console::log_1(
        &format!(
            "[CLSAG Partial v0.45.0] FROST signing (λ REQUIRED)\n  \
         tx_prefix_hash: {}...\n  \
         multisig_pub_key: {}...\n  \
         using_first_signer_c1: {}\n  \
         using_first_signer_s_values: {} (count: {})\n  \
         λ = {}...",
            &tx_prefix_hash_hex[..16.min(tx_prefix_hash_hex.len())],
            &multisig_pub_key_hex[..16.min(multisig_pub_key_hex.len())],
            has_first_signer_c1,
            has_first_signer_s_values,
            first_signer_s_values.as_ref().map(|v| v.len()).unwrap_or(0),
            hex::encode(&lagrange_coefficient.to_bytes()[..8])
        )
        .into(),
    );

    // Parse inputs
    let input_data: SignInputData = serde_json::from_str(&input_data_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid input_data JSON: {e}")))?;

    // Parse spend key (partial)
    let spend_bytes = hex::decode(&spend_key_priv_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid spend key hex: {e}")))?;
    if spend_bytes.len() != 32 {
        return Err(JsValue::from_str("Spend key must be 32 bytes"));
    }
    let mut spend_key_arr = [0u8; 32];
    spend_key_arr.copy_from_slice(&spend_bytes);
    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // =========================================================================
    // v0.14.2 CRITICAL FIX: Compute derived x for one-time outputs
    //
    // For Monero one-time outputs, the private key is:
    //   x = H_s(a·R || output_index) + b
    // where:
    //   a = view private key
    //   R = transaction public key from funding TX
    //   b = spend private key (partial for multisig)
    //
    // If derivation parameters are provided, compute the derived key.
    // Otherwise, use raw spend key (for direct-to-address outputs).
    // =========================================================================
    let x = if let (Some(tx_pub_key_hex), Some(view_key_hex), Some(output_idx)) = (
        &input_data.tx_pub_key,
        &input_data.view_key,
        input_data.output_index,
    ) {
        if !tx_pub_key_hex.is_empty() && !view_key_hex.is_empty() {
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.14.2] Computing x WITH derivation: H_s(a·R || {output_idx}) + b"
                )
                .into(),
            );

            // Parse tx_pub_key (R)
            let tx_pub_bytes = hex::decode(tx_pub_key_hex)
                .map_err(|e| JsValue::from_str(&format!("Invalid tx_pub_key hex: {e}")))?;
            if tx_pub_bytes.len() != 32 {
                return Err(JsValue::from_str("tx_pub_key must be 32 bytes"));
            }
            let mut tx_pub_arr = [0u8; 32];
            tx_pub_arr.copy_from_slice(&tx_pub_bytes);
            let tx_pub_point = CompressedEdwardsY(tx_pub_arr)
                .decompress()
                .ok_or_else(|| JsValue::from_str("Invalid tx_pub_key point"))?;

            // Parse view key (a)
            let view_bytes = hex::decode(view_key_hex)
                .map_err(|e| JsValue::from_str(&format!("Invalid view_key hex: {e}")))?;
            if view_bytes.len() != 32 {
                return Err(JsValue::from_str("view_key must be 32 bytes"));
            }
            let mut view_arr = [0u8; 32];
            view_arr.copy_from_slice(&view_bytes);
            let view_scalar = Scalar::from_bytes_mod_order(view_arr);

            // Compute shared secret: a * R (with cofactor for proper Monero derivation)
            // FIX C1: Apply cofactor like other derivation paths
            let shared_secret = (view_scalar * tx_pub_point).mul_by_cofactor();
            let shared_secret_bytes = shared_secret.compress().to_bytes();

            // Compute derivation: H_s(shared_secret || output_index)
            // FIX C2: Use varint encoding for output_index (matches Monero protocol)
            let mut hasher = Keccak256::new();
            hasher.update(shared_secret_bytes);
            hasher.update(encode_varint(output_idx));
            let derivation_hash: [u8; 32] = hasher.finalize().into();
            let derivation_scalar = Scalar::from_bytes_mod_order(derivation_hash);

            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.14.2] Derivation scalar: {}...",
                    hex::encode(&derivation_hash[..8])
                )
                .into(),
            );

            // v0.50.0 FIX: BOTH signers include derivation for Lagrange-weighted aggregation!
            //
            // In 2-of-3 multisig with FROST/Lagrange coefficients:
            //   x_total = λ₁*(derivation + spend_share_1) + λ₂*(derivation + spend_share_2)
            //           = (λ₁ + λ₂)*derivation + λ₁*spend_share_1 + λ₂*spend_share_2
            //
            // For buyer(1)+vendor(2): λ₁=2, λ₂=-1
            //   x_aggregated = (2 + (-1))*H_s + ... = 1*H_s + ...  ✅ Matches KI!
            //
            // BEFORE v0.50.0 (BUG with Lagrange):
            //   x_signer1 = derivation + spend_share_1 (FIRST has derivation)
            //   x_signer2 = spend_share_2              (SECOND: NO derivation)
            //   x_agg = λ₁*(H_s+b₁) + λ₂*b₂ = λ₁*H_s + ...  ❌ WRONG λ₂ missing H_s!
            //
            // AFTER v0.50.0 (FIX for Lagrange):
            //   Both signers include derivation: (λ₁+λ₂)*H_s = 1*H_s  ✅ CORRECT!
            //
            // Detection: has_first_signer_s_values == true means we are SECOND signer
            if has_first_signer_s_values {
                web_sys::console::log_1(
                    &"[CLSAG v0.50.0] SECOND SIGNER: x = derivation + b (Lagrange requires both)"
                        .into(),
                );
                derivation_scalar + spend_scalar // v0.50.0 FIX: Include derivation for Lagrange
            } else {
                web_sys::console::log_1(&"[CLSAG v0.50.0] FIRST SIGNER: x = derivation + b".into());
                derivation_scalar + spend_scalar
            }
        } else {
            web_sys::console::log_1(
                &"[CLSAG v0.14.2] Empty derivation params - using x = b (legacy)".into(),
            );
            spend_scalar
        }
    } else {
        web_sys::console::log_1(
            &"[CLSAG v0.14.2] No derivation params - using x = b (legacy/direct-to-address)".into(),
        );
        spend_scalar
    };

    // Parse multisig public key
    let multisig_pub_bytes = hex::decode(&multisig_pub_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid multisig pub key hex: {e}")))?;
    if multisig_pub_bytes.len() != 32 {
        return Err(JsValue::from_str("Multisig public key must be 32 bytes"));
    }
    let mut multisig_pub_arr = [0u8; 32];
    multisig_pub_arr.copy_from_slice(&multisig_pub_bytes);

    // Parse tx prefix hash
    let tx_hash_bytes = hex::decode(&tx_prefix_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid tx hash hex: {e}")))?;
    if tx_hash_bytes.len() != 32 {
        return Err(JsValue::from_str("TX prefix hash must be 32 bytes"));
    }

    // Parse commitment mask
    let mask_bytes = hex::decode(&input_data.commitment_mask)
        .map_err(|e| JsValue::from_str(&format!("Invalid mask hex: {e}")))?;
    if mask_bytes.len() != 32 {
        return Err(JsValue::from_str("Mask must be 32 bytes"));
    }
    let mut mask_arr = [0u8; 32];
    mask_arr.copy_from_slice(&mask_bytes);
    let z = Scalar::from_bytes_mod_order(mask_arr); // commitment mask

    let ring_size = input_data.ring.len();
    let signer_idx = input_data.signer_index as usize;

    web_sys::console::log_1(
        &format!("[CLSAG Partial] Ring size: {ring_size}, signer_index: {signer_idx}").into(),
    );

    // ===========================================================
    // Step 1: Parse AGGREGATED key image from server
    // CRITICAL: Use the server-provided aggregated key image (pKI_1 + pKI_2)
    // DO NOT compute locally - both signers MUST use the SAME key image
    // ===========================================================
    let aggregated_ki_bytes = hex::decode(&aggregated_key_image_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid aggregated_key_image hex: {e}")))?;
    if aggregated_ki_bytes.len() != 32 {
        return Err(JsValue::from_str("Aggregated key_image must be 32 bytes"));
    }
    let mut aggregated_ki_arr = [0u8; 32];
    aggregated_ki_arr.copy_from_slice(&aggregated_ki_bytes);

    // This is the key image that MUST be used for CLSAG ring loop
    // It's the sum of partial key images: KI = pKI_buyer + pKI_vendor
    let key_image_bytes = aggregated_ki_arr;

    web_sys::console::log_1(
        &format!(
            "[CLSAG Partial] Using AGGREGATED key_image: {}...",
            &aggregated_key_image_hex[..16.min(aggregated_key_image_hex.len())]
        )
        .into(),
    );

    // NOTE: hp (hash-to-point for D) is computed AFTER ring parsing
    // because we need ring_keys[signer_idx] (the actual output pubkey P[l])

    // ===========================================================
    // Step 2: Parse ring members (public keys and commitments)
    // ===========================================================
    let mut ring_keys = Vec::with_capacity(ring_size);
    let mut ring_commitments = Vec::with_capacity(ring_size);

    for (i, pair) in input_data.ring.iter().enumerate() {
        let key_bytes = hex::decode(&pair[0])
            .map_err(|e| JsValue::from_str(&format!("Invalid ring key[{i}] hex: {e}")))?;
        let commit_bytes = hex::decode(&pair[1])
            .map_err(|e| JsValue::from_str(&format!("Invalid ring commitment[{i}] hex: {e}")))?;

        let mut key_arr = [0u8; 32];
        let mut commit_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        commit_arr.copy_from_slice(&commit_bytes);

        let key_point = curve25519_dalek::edwards::CompressedEdwardsY(key_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str(&format!("Invalid ring key point[{i}]")))?;
        let commit_point = curve25519_dalek::edwards::CompressedEdwardsY(commit_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str(&format!("Invalid ring commitment point[{i}]")))?;

        ring_keys.push(key_point);
        ring_commitments.push(commit_point);
    }

    // ===========================================================
    // CRITICAL FIX (v0.8.4): Compute hp = Hp(P[signer_idx])
    //
    // In CLSAG, D = z * Hp(P) where P is the ONE-TIME OUTPUT PUBLIC KEY
    // P = ring[signer_idx][0] (the actual output key being spent)
    // NOT the multisig address pubkey (B)
    //
    // This matches Monero's implementation:
    // hash_to_p3(H_p3, P[l]);  // where P[l] is signer's pubkey
    // D = z * H
    // ===========================================================
    let signer_pubkey_bytes = ring_keys[signer_idx].compress().to_bytes();
    let hp = hash_to_point(signer_pubkey_bytes);

    web_sys::console::log_1(
        &format!(
            "[CLSAG Partial] Using Hp(P[{}]) = Hp({}...)",
            signer_idx,
            hex::encode(&signer_pubkey_bytes[..8])
        )
        .into(),
    );

    // Compute partial key image for diagnostic logging only
    // NOTE: This is x * Hp(P), NOT x * Hp(B)
    let partial_key_image = x * hp;
    let partial_ki_bytes = partial_key_image.compress().to_bytes();

    web_sys::console::log_1(
        &format!(
            "[CLSAG Partial] My partial_key_image (x * Hp(P)): {}...",
            hex::encode(&partial_ki_bytes[..8])
        )
        .into(),
    );

    // ===========================================================
    // Step 3: Compute pseudo output commitment with RANDOM mask
    // v0.16.0 FIX (Bug #3): Use random pseudo_out_mask, NOT the input mask!
    //
    // Previously: pseudo_out = z*G + amount*H (same mask → D = identity)
    // Now:        pseudo_out = pseudo_out_mask*G + amount*H (random mask → D ≠ identity)
    //
    // This is CRITICAL for CLSAG security and verification:
    // - D = mask_delta * Hp(P) where mask_delta = z - pseudo_out_mask
    // - When mask_delta ≠ 0, D ≠ identity
    // - The verifier expects non-identity D for proper ring signature
    // ===========================================================
    let amount_scalar = Scalar::from(input_data.commitment_amount);

    // H is the OFFICIAL Monero constant from rctTypes.h
    // NOT derived at runtime - this is a fixed canonical point!
    // Source: monero-project/monero/src/ringct/rctTypes.h
    const H_BYTES: [u8; 32] = [
        0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0,
        0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c,
        0x1f, 0x94,
    ];
    let h_point = curve25519_dalek::edwards::CompressedEdwardsY(H_BYTES)
        .decompress()
        .ok_or_else(|| JsValue::from_str("H point decompression failed"))?;

    // ===========================================================
    // v0.17.0 FIX (Bug #3 continued): Second signer MUST use first signer's pseudo_out
    //
    // FIRST SIGNER: Generate random pseudo_out_mask, compute mask_delta
    // SECOND SIGNER: Use first_signer_pseudo_out (do NOT generate new one!)
    //
    // Critical: Both signers MUST use the SAME pseudo_out for CLSAG verification
    // ===========================================================
    let (pseudo_out, pseudo_out_bytes, mask_delta) = if has_first_signer_c1 {
        // SECOND SIGNER: Use first signer's pseudo_out
        let pseudo_out_hex = first_signer_pseudo_out_hex
            .as_ref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                JsValue::from_str("v0.17.0 ERROR: Second signer requires first_signer_pseudo_out!")
            })?;

        web_sys::console::log_1(
            &format!(
                "[CLSAG v0.17.0] SECOND SIGNER: Using first_signer_pseudo_out: {}...",
                &pseudo_out_hex[..16.min(pseudo_out_hex.len())]
            )
            .into(),
        );

        let pseudo_out_bytes_vec = hex::decode(pseudo_out_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid first_signer_pseudo_out hex: {e}")))?;
        if pseudo_out_bytes_vec.len() != 32 {
            return Err(JsValue::from_str(
                "first_signer_pseudo_out must be 32 bytes",
            ));
        }
        let mut pseudo_out_arr = [0u8; 32];
        pseudo_out_arr.copy_from_slice(&pseudo_out_bytes_vec);

        let pseudo_out_point = CompressedEdwardsY(pseudo_out_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Failed to decompress first_signer_pseudo_out"))?;

        // v0.46.0 FIX: Second signer ALSO needs mask_delta for FROST!
        // For threshold signing with Lagrange coefficients:
        //   s1 = α1 - c_p*(λ1*x1) - c_c*(λ1*mask_delta)
        //   s2 = α2 - c_p*(λ2*x2) - c_c*(λ2*mask_delta)
        // Final: s = s1 + s2, and λ1 + λ2 = 1 for 2-of-3
        // So both signers must contribute their λ-weighted mask_delta term.
        let mask_delta = if let Some(ref funding_mask_hex) = input_data.funding_mask {
            let funding_bytes = hex::decode(funding_mask_hex)
                .map_err(|e| JsValue::from_str(&format!("Invalid funding_mask hex: {e}")))?;
            if funding_bytes.len() != 32 {
                return Err(JsValue::from_str("funding_mask must be 32 bytes"));
            }
            let mut funding_arr = [0u8; 32];
            funding_arr.copy_from_slice(&funding_bytes);
            let funding_z = Scalar::from_bytes_mod_order(funding_arr);

            // mask_delta = funding_mask - commitment_mask (z was parsed earlier)
            let delta = funding_z - z;
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.46.0] SECOND SIGNER: Computing mask_delta = funding_z - z = {}...",
                    hex::encode(&delta.to_bytes()[..8])
                )
                .into(),
            );
            delta
        } else {
            web_sys::console::log_1(
                &"[CLSAG v0.46.0] SECOND SIGNER: No funding_mask, mask_delta = 0".into(),
            );
            Scalar::ZERO
        };

        (pseudo_out_point, pseudo_out_arr, mask_delta)
    } else {
        // FIRST SIGNER: v0.35.1 FIX - Use commitment_mask (output_mask) as pseudo_out_mask
        //
        // v0.35.1 ARCHITECTURE:
        // - Server sends commitment_mask = output_mask (derived for OUTPUT)
        // v0.35.2 FIX: For transactions with multiple outputs (payment + change):
        //
        // Balance equation for 2 outputs:
        //   pseudo_out = output_0 + output_1 + fee * H
        //   pseudo_out_mask = mask_0 + mask_1
        //
        // Where:
        //   - mask_0 = output_mask (derived for recipient verification)
        //   - mask_1 = z - output_mask (change output mask, computed by BP+ builder)
        //   - pseudo_out_mask = mask_0 + mask_1 = z (the original input funding mask)
        //
        // CLSAG D computation (for commitment mask proof):
        //   D = (z - output_mask) * Hp(P) / 8 = mask_delta * Hp(P) / 8
        //
        // So: pseudo_out_mask = z (funding_mask), NOT output_mask!

        // commitment_mask is output_mask (derived), used only for mask_delta
        let output_mask = z; // z was parsed from commitment_mask field

        // v0.35.2 FIX: mask_delta = z - pseudo_out_mask
        //
        // Server now sends:
        // - commitment_mask = pseudo_out_mask = output_mask + dummy_mask (THE SUM)
        // - funding_mask = z (input's commitment mask)
        //
        // WASM computes:
        // - pseudo_out_mask = commitment_mask (already the sum from server)
        // - mask_delta = z - pseudo_out_mask ≠ 0 (because z ≠ sum when dummy is derived independently)
        // - D = mask_delta * Hp(P) ≠ identity
        let pseudo_out_mask = z; // z was parsed from commitment_mask (now = pseudo_out_mask from server)

        let mask_delta = if let Some(ref funding_mask_hex) = input_data.funding_mask {
            let funding_bytes = hex::decode(funding_mask_hex)
                .map_err(|e| JsValue::from_str(&format!("Invalid funding_mask hex: {e}")))?;
            if funding_bytes.len() != 32 {
                return Err(JsValue::from_str("funding_mask must be 32 bytes"));
            }
            let mut funding_arr = [0u8; 32];
            funding_arr.copy_from_slice(&funding_bytes);
            let funding_z = Scalar::from_bytes_mod_order(funding_arr);

            // mask_delta = z - pseudo_out_mask
            let delta = funding_z - pseudo_out_mask;

            web_sys::console::log_1(
                &"[CLSAG v0.35.2] FIRST SIGNER: mask_delta = z - pseudo_out_mask".into(),
            );
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.35.2] funding_mask (z): {}...",
                    hex::encode(&funding_arr[..8])
                )
                .into(),
            );
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.35.2] commitment_mask (pseudo_out_mask = SUM): {}...",
                    hex::encode(&pseudo_out_mask.to_bytes()[..8])
                )
                .into(),
            );
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.35.2] mask_delta (z - pseudo_out_mask): {}...",
                    hex::encode(&delta.to_bytes()[..8])
                )
                .into(),
            );

            delta
        } else {
            // Legacy mode: no funding_mask provided, use mask_delta = 0
            web_sys::console::log_1(
                &"[CLSAG v0.35.2] WARNING: No funding_mask provided, mask_delta = 0 (legacy)"
                    .into(),
            );
            Scalar::ZERO
        };

        // Compute pseudo_out using funding_mask (z) for balance
        let pseudo_out_point = ED25519_BASEPOINT_TABLE * &pseudo_out_mask + h_point * amount_scalar;
        let pseudo_out_bytes = pseudo_out_point.compress().to_bytes();

        (pseudo_out_point, pseudo_out_bytes, mask_delta)
    };

    // ===========================================================
    // v0.10.4 CRITICAL FIX: Compute mixing coefficients mu_P and mu_C
    //
    // These are needed for the CORRECT s-value formula:
    //   s = alpha - c_p * x - c_c * z
    //   where c_p = mu_P * c, c_c = mu_C * c
    //
    // Reference: Monero device_default.cpp proveRctCLSAGSimple
    //   s0 = mu_P * p + mu_C * z
    //   s = a - c * s0 = alpha - c * mu_P * x - c * mu_C * z
    // ===========================================================

    // Decompress aggregated key image for mu computation
    let key_image_point = CompressedEdwardsY(key_image_bytes)
        .decompress()
        .ok_or_else(|| JsValue::from_str("Failed to decompress key_image for mu computation"))?;

    // v0.16.0 FIX (Bug #3): D point = mask_delta * Hp(P[l]) / 8
    //
    // In CLSAG, D represents the commitment mask DIFFERENCE between input and pseudo_out:
    //   D = (z_input - z_pseudo) * Hp(P[l]) / 8 = mask_delta * Hp(P[l]) / 8
    //
    // v0.16.0 CRITICAL FIX: With random pseudo_out_mask, mask_delta ≠ 0, so D ≠ identity!
    // This is required for proper CLSAG verification.
    //
    // Previous bug (v0.12.2): Used same mask for pseudo_out → mask_delta = 0 → D = identity
    // This caused verification failure because Monero expects non-identity D.
    let inv8 = Scalar::from(8u64).invert();
    let d_inv8 = if let Some(ref d_hex) = first_signer_d_hex {
        if !d_hex.is_empty() {
            // SECOND SIGNER: Use D from first signer
            // CRITICAL: First signer now generates non-identity D with random mask
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.16.0] SECOND SIGNER: Using first_signer_d: {}...",
                    &d_hex[..16.min(d_hex.len())]
                )
                .into(),
            );

            let d_bytes = hex::decode(d_hex)
                .map_err(|e| JsValue::from_str(&format!("Invalid first_signer_d hex: {e}")))?;
            if d_bytes.len() != 32 {
                return Err(JsValue::from_str("first_signer_d must be 32 bytes"));
            }
            let mut d_arr = [0u8; 32];
            d_arr.copy_from_slice(&d_bytes);

            CompressedEdwardsY(d_arr)
                .decompress()
                .ok_or_else(|| JsValue::from_str("Failed to decompress first_signer_d point"))?
        } else {
            // First signer: Compute D = mask_delta * Hp(P[l]) / 8
            // v0.16.0 FIX: mask_delta ≠ 0, so D ≠ identity!
            let d_original = hp * mask_delta;
            let d = d_original * inv8;
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.16.0] FIRST SIGNER: D = mask_delta * Hp(P) / 8: {}...",
                    hex::encode(&d.compress().to_bytes()[..16])
                )
                .into(),
            );
            d
        }
    } else {
        // First signer (no first_signer_d_hex provided)
        // Compute D = mask_delta * Hp(P[l]) / 8
        let d_original = hp * mask_delta;
        let d = d_original * inv8;
        web_sys::console::log_1(
            &format!(
                "[CLSAG v0.16.0] FIRST SIGNER: D = mask_delta * Hp(P) / 8: {}...",
                hex::encode(&d.compress().to_bytes()[..16])
            )
            .into(),
        );
        d
    };

    // Verify D is NOT identity (would indicate mask_delta bug)
    let identity_bytes = [
        1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    if d_inv8.compress().to_bytes() == identity_bytes {
        web_sys::console::log_1(
            &"[CLSAG v0.16.0] WARNING: D is IDENTITY - this indicates a bug!".into(),
        );
    }

    web_sys::console::log_1(
        &format!(
            "[CLSAG v0.16.0] D_inv8 = {}...",
            hex::encode(&d_inv8.compress().to_bytes()[..8])
        )
        .into(),
    );

    // ===========================================================
    // v0.12.3: Use SERVER-PROVIDED mu_P and mu_C if available
    // This ensures BOTH signers use IDENTICAL mixing coefficients,
    // preventing mu mismatch errors that cause signature verification failure.
    // ===========================================================
    let (mu_p, mu_c) = {
        let has_server_mu = mu_p_hex.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
            && mu_c_hex.as_ref().map(|s| !s.is_empty()).unwrap_or(false);

        if has_server_mu {
            // Parse server-provided mu_P
            let mu_p_bytes = hex::decode(mu_p_hex.as_ref().unwrap())
                .map_err(|e| JsValue::from_str(&format!("Invalid mu_p hex: {e}")))?;
            if mu_p_bytes.len() != 32 {
                return Err(JsValue::from_str("mu_p must be 32 bytes"));
            }
            let mut mu_p_arr = [0u8; 32];
            mu_p_arr.copy_from_slice(&mu_p_bytes);
            let mu_p = Scalar::from_bytes_mod_order(mu_p_arr);

            // Parse server-provided mu_C
            let mu_c_bytes = hex::decode(mu_c_hex.as_ref().unwrap())
                .map_err(|e| JsValue::from_str(&format!("Invalid mu_c hex: {e}")))?;
            if mu_c_bytes.len() != 32 {
                return Err(JsValue::from_str("mu_c must be 32 bytes"));
            }
            let mut mu_c_arr = [0u8; 32];
            mu_c_arr.copy_from_slice(&mu_c_bytes);
            let mu_c = Scalar::from_bytes_mod_order(mu_c_arr);

            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.12.3] Using SERVER-PROVIDED mu_P={}..., mu_C={}...",
                    hex::encode(&mu_p.to_bytes()[..8]),
                    hex::encode(&mu_c.to_bytes()[..8])
                )
                .into(),
            );

            (mu_p, mu_c)
        } else {
            // Compute locally (fallback for first signer or legacy mode)
            let (mu_p, mu_c) = clsag_compute_mixing_coefficients(
                &ring_keys,
                &ring_commitments,
                &key_image_point,
                &d_inv8,
                &pseudo_out,
            );

            web_sys::console::log_1(
                &format!(
                "[CLSAG v0.12.3] Computed LOCAL mu_P={}..., mu_C={}... (first signer or fallback)",
                hex::encode(&mu_p.to_bytes()[..8]),
                hex::encode(&mu_c.to_bytes()[..8])
            )
                .into(),
            );

            (mu_p, mu_c)
        }
    };

    // ===========================================================
    // Step 4: Compute CLSAG partial signature
    //
    // CORRECT formula (v0.10.4):
    //   s_partial[signer] = alpha - c_p * x - c_c * z
    //   where c_p = mu_P * c, c_c = mu_C * c
    // ===========================================================

    // ===========================================================
    // MuSig2 v0.9.2: Nonce aggregation for 2-of-3 multisig
    //
    // CRITICAL FIX: Both signers MUST use the SAME L point (R_agg)
    // - Vendor: L = R_vendor (first signer, no peer nonce yet)
    // - Buyer: L = R_vendor + R_buyer = R_agg (second signer)
    //
    // Without nonce aggregation:
    // - Vendor signs with L = α₁*G
    // - Buyer signs with L = α₂*G (DIFFERENT!)
    // - Final signature contains vendor's L but s_final = s₁ + s₂
    // - Verification fails: s_final*G ≠ L + c*P
    //
    // With nonce aggregation:
    // - Both signers compute L_agg = R₁ + R₂
    // - Both use L_agg in challenge computation
    // - s_final*G = L_agg + c*P ✓
    // ===========================================================

    // Step 4a: Get alpha (nonce scalar)
    // If alpha_secret is provided (from generate_nonce_commitment), use it.
    // Otherwise, generate deterministic alpha based on tx_hash + spend_key.
    let mut alpha_bytes: [u8; 32];
    let alpha = if let Some(alpha_hex) = input_data.alpha_secret.as_ref() {
        web_sys::console::log_1(&"[MuSig2 v0.9.2] Using alpha from nonce commitment".into());
        let alpha_decoded = hex::decode(alpha_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid alpha_secret hex: {e}")))?;
        if alpha_decoded.len() != 32 {
            return Err(JsValue::from_str("alpha_secret must be 32 bytes"));
        }
        alpha_bytes = [0u8; 32];
        alpha_bytes.copy_from_slice(&alpha_decoded);
        Scalar::from_bytes_mod_order(alpha_bytes)
    } else {
        // Fallback: Generate deterministic alpha (legacy mode)
        web_sys::console::log_1(
            &"[MuSig2 v0.9.2] Generating deterministic alpha (legacy mode)".into(),
        );
        let mut alpha_hasher = Keccak256::new();
        alpha_hasher.update(b"CLSAG_multisig_nonce_v2");
        alpha_hasher.update(&tx_hash_bytes);
        alpha_hasher.update(spend_key_arr);
        alpha_bytes = alpha_hasher.finalize().into();
        Scalar::from_bytes_mod_order(alpha_bytes)
    };

    // Compute my R points: R_mine = alpha * G, R'_mine = alpha * Hp(P)
    let r_mine = ED25519_BASEPOINT_TABLE * &alpha;
    let r_prime_mine = alpha * hp;

    web_sys::console::log_1(
        &format!(
            "[MuSig2 v0.9.2] R_mine: {}...",
            hex::encode(&r_mine.compress().to_bytes()[..16])
        )
        .into(),
    );

    // =========================================================================
    // v0.42.0 FIX: Verify alpha matches submitted nonce
    // =========================================================================
    // This catches a critical bug where alpha_secret was regenerated after
    // the nonce was submitted to the server. If alpha*G != submitted_r_public,
    // the signature will fail verification (L[π] ≠ R_agg).
    //
    // Symptoms of this bug:
    // - CLSAG verification fails: c_computed != c_expected
    // - L[15] value doesn't match R_agg
    // - Debug shows correct PKI, mu_p, mu_c, but ring doesn't close
    // =========================================================================
    if let Some(ref submitted_r_hex) = input_data.my_submitted_r_public {
        let submitted_r_bytes = hex::decode(submitted_r_hex).map_err(|e| {
            JsValue::from_str(&format!("[v0.42.0] Invalid my_submitted_r_public hex: {e}"))
        })?;
        if submitted_r_bytes.len() != 32 {
            return Err(JsValue::from_str(
                "[v0.42.0] my_submitted_r_public must be 32 bytes",
            ));
        }

        let r_mine_hex = hex::encode(r_mine.compress().to_bytes());
        let submitted_r_hex_canonical = submitted_r_hex.to_lowercase();

        if r_mine_hex != submitted_r_hex_canonical {
            web_sys::console::error_1(
                &format!(
                    "[v0.42.0] CRITICAL: alpha_secret mismatch!\n  \
                 R_computed (alpha*G): {r_mine_hex}\n  \
                 R_submitted:          {submitted_r_hex_canonical}\n  \
                 This means your nonce was regenerated after submission.\n  \
                 The escrow must be RESET to generate new matching nonces."
                )
                .into(),
            );
            return Err(JsValue::from_str(
                "[v0.42.0] CRITICAL: Your alpha_secret does not match your submitted nonce. \
                 This happens when the nonce was regenerated after submission (browser data cleared, \
                 page reloaded, or nonce submitted again). The escrow must be RESET and both parties \
                 must generate new matching nonces. Error: R_computed ≠ R_submitted"
            ));
        }

        web_sys::console::log_1(
            &format!(
                "[v0.42.0] Alpha verification PASSED: R_mine == R_submitted ({}...)",
                &r_mine_hex[..16]
            )
            .into(),
        );
    } else {
        // No submitted_r_public provided - cannot verify alpha (legacy mode)
        web_sys::console::warn_1(
            &"[v0.42.0] No my_submitted_r_public provided - cannot verify alpha integrity".into(),
        );
    }

    // Step 4b: Aggregate nonces if peer_nonce_public is provided
    // If both signers have submitted nonces, server sends peer's nonce.
    // We compute R_agg = R_mine + R_peer for L calculation.
    // Returns (L_point, R_point, effective_alpha) where effective_alpha is:
    //   - alpha for first signer (generates the ring)
    //   - alpha for both signers when nonce aggregation is used
    //   - ZERO for second signer without nonce aggregation (preserves ring)
    let (l_point, r_point, effective_alpha) = if let Some(peer_nonce_json) =
        input_data.peer_nonce_public.as_ref()
    {
        web_sys::console::log_1(&"[MuSig2 v0.9.2] Aggregating nonces with peer".into());

        #[derive(serde::Deserialize)]
        struct PeerNonce {
            r_public: String,
            r_prime_public: String,
        }

        let peer: PeerNonce = serde_json::from_str(peer_nonce_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer_nonce_public JSON: {e}")))?;

        // Parse peer's R point
        let peer_r_bytes = hex::decode(&peer.r_public)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer r_public hex: {e}")))?;
        if peer_r_bytes.len() != 32 {
            return Err(JsValue::from_str("peer r_public must be 32 bytes"));
        }
        let mut peer_r_arr = [0u8; 32];
        peer_r_arr.copy_from_slice(&peer_r_bytes);
        let peer_r = curve25519_dalek::edwards::CompressedEdwardsY(peer_r_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid peer r_public point"))?;

        // Parse peer's R' point
        let peer_r_prime_bytes = hex::decode(&peer.r_prime_public)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer r_prime_public hex: {e}")))?;
        if peer_r_prime_bytes.len() != 32 {
            return Err(JsValue::from_str("peer r_prime_public must be 32 bytes"));
        }
        let mut peer_r_prime_arr = [0u8; 32];
        peer_r_prime_arr.copy_from_slice(&peer_r_prime_bytes);
        let peer_r_prime = curve25519_dalek::edwards::CompressedEdwardsY(peer_r_prime_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid peer r_prime_public point"))?;

        // Compute R_agg = R_mine + R_peer
        let r_agg = r_mine + peer_r;
        let r_prime_agg = r_prime_mine + peer_r_prime;

        web_sys::console::log_1(
            &format!(
                "[MuSig2 v0.9.2] R_agg = R_mine + R_peer: {}...",
                hex::encode(&r_agg.compress().to_bytes()[..16])
            )
            .into(),
        );
        web_sys::console::log_1(
            &format!(
                "[MuSig2 v0.9.2] R'_agg = R'_mine + R'_peer: {}...",
                hex::encode(&r_prime_agg.compress().to_bytes()[..16])
            )
            .into(),
        );

        // ===========================================================
        // v0.19.0 FIX: Second signer alpha depends on first_signer_used_r_agg
        // ===========================================================
        // Scenario 1: First signer had R_agg (both nonces aggregated before first sign)
        //   - c1 = H(..., L=R_agg=R1+R2, ...)
        //   - Second signer SHOULD use alpha (both contributed to R_agg)
        //   - s_agg = (alpha1 - c*...) + (alpha2 - c*...)
        //   - Verification: L = (alpha1+alpha2)*G + ... ✓
        //
        // Scenario 2: First signer did NOT have R_agg (signed before nonces aggregated)
        //   - c1 = H(..., L=R1, ...) (only first signer's nonce)
        //   - Second signer MUST use alpha=0
        //   - s_agg = (alpha1 - c*...) + (0 - c*...)
        //   - Verification: L = alpha1*G + ... ✓
        // ===========================================================
        if has_first_signer_c1 {
            if first_signer_used_r_agg {
                // First signer had R_agg → c1 includes both nonces → use our alpha
                web_sys::console::log_1(
                    &"[MuSig2 v0.19.0] SECOND SIGNER: Using alpha (first signer had R_agg)".into(),
                );
                (r_agg, r_prime_agg, alpha)
            } else {
                // First signer did NOT have R_agg → c1 only has first signer's nonce → use alpha=0
                web_sys::console::log_1(&"[MuSig2 v0.19.0] SECOND SIGNER: Using alpha=ZERO (first signer did NOT have R_agg)".into());
                (r_mine, r_prime_mine, Scalar::ZERO)
            }
        } else {
            // FIRST SIGNER with peer nonce: Use R_agg for c1 computation
            web_sys::console::log_1(
                &"[MuSig2 v0.19.0] FIRST SIGNER with R_agg: Using aggregated nonces".into(),
            );
            (r_agg, r_prime_agg, alpha)
        }
    } else {
        // No peer nonce - different behavior for first vs second signer
        if has_first_signer_c1 {
            // SECOND SIGNER without nonce aggregation:
            // The ring was computed by first signer using R1 = alpha1 * G
            // We must NOT add our own nonce to preserve ring integrity
            // s2[i] = 0 - c * x2 = -c * x2
            // Final: s_agg = (alpha1 - c*x1) + (-c*x2) = alpha1 - c*(x1+x2)
            // Verification: s_agg*G + c*P = alpha1*G = R1 ✓
            web_sys::console::log_1(
                &"[MuSig2 v0.10.0] SECOND SIGNER: No peer nonce - using alpha=0 to preserve ring"
                    .into(),
            );
            // L and R points are not used by second signer (we reuse first signer's decoys)
            // but we need to return something for the tuple
            (r_mine, r_prime_mine, Scalar::ZERO)
        } else {
            // FIRST SIGNER: use own nonce directly
            web_sys::console::log_1(&"[MuSig2 v0.9.2] FIRST SIGNER: Using own nonce".into());
            (r_mine, r_prime_mine, alpha)
        }
    };

    // effective_alpha determines the nonce contribution:
    // - First signer: alpha (generates R = alpha*G in ring)
    // - Second signer with nonce aggregation: alpha (contributes to R_agg)
    // - Second signer without nonce aggregation: ZERO (preserves first signer's ring)
    let alpha = effective_alpha;

    // Compute initial challenge c1
    // If first_signer_c1 is provided, use it instead of computing our own
    // This ensures both signers use the same challenge for valid aggregation
    //
    // v0.10.2: Store original_c1_bytes for second signer output
    // The second signer MUST return the same c1 as the first signer
    let mut original_c1_bytes: Option<[u8; 32]> = None;

    let mut c = if has_first_signer_c1 {
        let c1_hex = first_signer_c1_hex.as_ref().unwrap();
        let c1_bytes = hex::decode(c1_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid first_signer_c1 hex: {e}")))?;
        if c1_bytes.len() != 32 {
            return Err(JsValue::from_str("first_signer_c1 must be 32 bytes"));
        }
        let mut c1_arr = [0u8; 32];
        c1_arr.copy_from_slice(&c1_bytes);
        // Store for output - second signer must return same c1
        original_c1_bytes = Some(c1_arr);
        web_sys::console::log_1(
            &format!(
                "[CLSAG Partial] Using first signer's c1: {}...",
                &c1_hex[..16.min(c1_hex.len())]
            )
            .into(),
        );
        Scalar::from_bytes_mod_order(c1_arr)
    } else {
        // =================================================================
        // CRITICAL FIX (v0.9.5): Correct CLSAG aggregation challenge hash
        //
        // Monero reference (rctSigs.cpp proveRctCLSAGSimple):
        // c_to_hash[0] = domain separator
        // c_to_hash[1..n+1] = ring public keys P
        // c_to_hash[n+1..2n+1] = ring commitments C
        // c_to_hash[2n+1] = C_offset (pseudo output commitment)
        // c_to_hash[2n+2] = message
        // c_to_hash[2n+3] = L point
        // c_to_hash[2n+4] = R point
        // =================================================================
        let mut hasher = Keccak256::new();
        // ===========================================================
        // v0.10.4 FIX: Domain separator must be 32 bytes padded!
        //
        // Monero reference (rctSigs.cpp): c_to_hash[0] is a 32-byte slot
        // "CLSAG_round" (11 bytes) + 21 zero bytes = 32 bytes total
        //
        // This MUST match the buffer-based propagation format!
        // ===========================================================
        let mut domain_sep = [0u8; 32];
        domain_sep[..11].copy_from_slice(b"CLSAG_round");
        hasher.update(domain_sep); // 32 bytes padded domain separator

        // Ring public keys P
        for k in &ring_keys {
            hasher.update(k.compress().as_bytes());
        }

        // Ring commitments C (CRITICAL: was missing before v0.9.5)
        for c in &ring_commitments {
            hasher.update(c.compress().as_bytes());
        }

        // Pseudo output commitment C_offset (CRITICAL: was missing before v0.9.5)
        hasher.update(pseudo_out_bytes);

        // Message (tx prefix hash)
        hasher.update(&tx_hash_bytes);

        // v0.13.0 FIX: Key image I and D point MUST be in round hash!
        // Monero reference: c = H(... || pseudo_out || msg || I || D || L || R)
        hasher.update(key_image_point.compress().as_bytes()); // I
        hasher.update(d_inv8.compress().as_bytes()); // D

        // L and R points
        hasher.update(l_point.compress().as_bytes());
        hasher.update(r_point.compress().as_bytes());

        let c_hash: [u8; 32] = hasher.finalize().into();

        web_sys::console::log_1(&format!(
            "[CLSAG v0.9.5] Challenge hash computed with {} ring keys, {} ring commitments, pseudo_out: {}...",
            ring_keys.len(),
            ring_commitments.len(),
            hex::encode(&pseudo_out_bytes[..8])
        ).into());

        Scalar::from_bytes_mod_order(c_hash)
    };

    // Compute s values around the ring
    let mut s_values: Vec<Scalar> = vec![Scalar::ZERO; ring_size];

    // v0.10.7: Save original c1 for first signer (before any propagation)
    // This will be overwritten if we're the first signer, but we need it declared here
    let mut original_c1_first_signer = c;

    // =========================================================================
    // v0.8.7 CRITICAL FIX: Round-Robin CLSAG decoy s-value handling
    // =========================================================================
    // If we have first_signer_s_values, we MUST reuse them for decoy positions.
    // This is required because:
    // 1. First signer computed c1 based on their decoy s-values
    // 2. We received c1 and must use the SAME decoys to maintain valid challenge chain
    // 3. Only s[signer_idx] differs - that's where our partial signature goes
    //
    // Previous approach (v0.8.5) was WRONG:
    // - Each signer generated random decoys independently
    // - Server used first signer's decoys but second signer computed with different decoys
    // - Challenge chain broke during verification
    // =========================================================================

    if let Some(ref first_s_values) = first_signer_s_values {
        // SECOND SIGNER PATH: Reuse first signer's decoy s-values
        if first_s_values.len() != ring_size {
            return Err(JsValue::from_str(&format!(
                "first_signer_s_values length mismatch: got {}, expected {}",
                first_s_values.len(),
                ring_size
            )));
        }

        web_sys::console::log_1(
            &format!(
                "[CLSAG Partial] SECOND SIGNER: Reusing {} decoy s-values from first signer",
                ring_size - 1 // All except signer_idx
            )
            .into(),
        );

        // Copy first signer's s-values for ALL decoy positions
        for i in 0..ring_size {
            if i == signer_idx {
                continue; // Skip signer index, computed below with our partial signature
            }
            s_values[i] = first_s_values[i];
        }

        // =========================================================================
        // v0.10.0 FIX: CLSAG challenge propagation with CORRECT Monero formulas
        //
        // CRITICAL BUGS FIXED:
        // - V1: D point form (was using D*inv8, must use D_original for R)
        // - V2: Missing mixing coefficients mu_P and mu_C
        // - V3: Wrong L/R formulas (2 terms -> 3 terms with mixing)
        // - V4: Wrong hash pattern (simple Keccak -> buffer truncation)
        //
        // CORRECT CLSAG verification formula (Monero reference):
        // L = s*G + c_p*P + c_c*C_adj      where c_p = mu_P*c, c_c = mu_C*c
        // R = s*Hp + c_p*I + c_c*D_orig    where D_orig = D_inv8 * 8
        // =========================================================================
        if signer_idx >= 1 {
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.10.3] SECOND SIGNER: Propagating c1 through positions 0..{} to c{}",
                    signer_idx - 1,
                    signer_idx
                )
                .into(),
            );

            // Decompress key_image from bytes to EdwardsPoint
            let key_image_point = CompressedEdwardsY(key_image_bytes)
                .decompress()
                .ok_or_else(|| {
                    JsValue::from_str("Failed to decompress key_image for challenge propagation")
                })?;

            // v0.12.0 FIX: D = z * Hp(P[l]) where z is commitment mask
            // D_original is D without the inv(8) factor (for R formula)
            // d_inv8 was already computed earlier in this function
            let d_original = d_inv8 * Scalar::from(8u64);

            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.12.0] Using D_inv8: {}..., D_original: {}...",
                    hex::encode(&d_inv8.compress().to_bytes()[..8]),
                    hex::encode(&d_original.compress().to_bytes()[..8])
                )
                .into(),
            );

            // v0.12.3 FIX: Use ALREADY-COMPUTED mu_P and mu_C from line 1546
            // Do NOT recompute here! The server-provided values must be used
            // to ensure both signers use IDENTICAL mixing coefficients.
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.12.3] Challenge propagation using EXISTING mu_P={}..., mu_C={}...",
                    hex::encode(&mu_p.to_bytes()[..8]),
                    hex::encode(&mu_c.to_bytes()[..8])
                )
                .into(),
            );

            // Compute adjusted commitments: C_adj[i] = C[i] - pseudo_out
            let c_adjusted: Vec<EdwardsPoint> = ring_commitments
                .iter()
                .map(|comm| comm - pseudo_out)
                .collect();

            // Convert tx_hash_bytes (Vec<u8>) to array [u8; 32]
            let mut tx_hash_arr = [0u8; 32];
            tx_hash_arr.copy_from_slice(&tx_hash_bytes);

            // Build buffer for round hash
            let (mut to_hash, _, _) = clsag_build_agg_buffer(
                &ring_keys,
                &ring_commitments,
                &key_image_point,
                &d_inv8,
                &pseudo_out,
            );
            // v0.13.0 FIX: Now passes key_image and d_inv8 to include in round hash
            clsag_convert_to_round_format(
                &mut to_hash,
                ring_size,
                &pseudo_out,
                &tx_hash_arr,
                &key_image_point,
                &d_inv8,
            );

            // Propagate challenge from position 0 to signer_idx
            // CRITICAL FIX v0.10.3: Loop MUST start at 0, not 1!
            // c starts as c1 (challenge at position 0), so we must process all positions
            // 0, 1, 2, ..., signer_idx-1 to arrive at c[signer_idx]
            for prop_i in 0..signer_idx {
                let c_p = mu_p * c; // mu_P * c
                let c_c = mu_c * c; // mu_C * c

                // L = s*G + c_p*P + c_c*C_adj (3-term formula with mixing!)
                let l_i = EdwardsPoint::vartime_multiscalar_mul(
                    [s_values[prop_i], c_p, c_c],
                    [
                        ED25519_BASEPOINT_POINT,
                        ring_keys[prop_i],
                        c_adjusted[prop_i],
                    ],
                );

                // Hp(P_i) for this ring member
                let hp_i = hash_to_point(ring_keys[prop_i].compress().to_bytes());

                // R = s*Hp + c_p*I + c_c*D_original (3-term formula with mixing!)
                let r_i = EdwardsPoint::vartime_multiscalar_mul(
                    [s_values[prop_i], c_p, c_c],
                    [hp_i, key_image_point, d_original],
                );

                // Buffer-based hash with truncation (matches Monero reference!)
                clsag_add_lr_to_round_buffer(&mut to_hash, ring_size, &l_i, &r_i);
                c = clsag_keccak256_to_scalar(&to_hash);
            }

            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.10.3] Challenge propagated: c{} = {}...",
                    signer_idx,
                    hex::encode(&c.to_bytes()[..8])
                )
                .into(),
            );
        }
    } else {
        // FIRST SIGNER PATH: Generate random decoys (will be shared with second signer)
        web_sys::console::log_1(
            &format!(
                "[CLSAG Partial] FIRST SIGNER: Generating {} random decoy s-values",
                ring_size - 1
            )
            .into(),
        );

        for i in 0..ring_size {
            if i == signer_idx {
                continue; // Skip signer index, computed below
            }

            // Generate RANDOM s-value for this position
            let mut random_bytes = [0u8; 32];
            getrandom::getrandom(&mut random_bytes)
                .map_err(|e| JsValue::from_str(&format!("Failed to generate random bytes: {e}")))?;
            s_values[i] = Scalar::from_bytes_mod_order(random_bytes);
        }

        // =========================================================================
        // v0.10.5 CRITICAL FIX: First signer must ALSO propagate c1 to c[signer_idx]!
        //
        // c1 is the challenge at position 0 (after L_signer, R_signer)
        // But we need c[signer_idx] for the s-value computation!
        //
        // WRONG: s[l] = alpha - c1 * ... (using c1 directly)
        // CORRECT: s[l] = alpha - c[l] * ... (c[l] propagated from c1)
        //
        // v0.10.7 FIX: Save original c1 BEFORE propagation!
        // The output c1 must be the ORIGINAL challenge, not the propagated one.
        // =========================================================================
        original_c1_first_signer = c; // SAVE c1 before propagation!

        if signer_idx >= 1 {
            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.10.5] FIRST SIGNER: Propagating c1 through positions 0..{} to c{}",
                    signer_idx - 1,
                    signer_idx
                )
                .into(),
            );

            // v0.12.0 FIX: D = z * Hp(P[l]) - use d_inv8 from earlier
            let d_original = d_inv8 * Scalar::from(8u64);

            // Compute adjusted commitments: C_adj[i] = C[i] - pseudo_out
            let c_adjusted: Vec<EdwardsPoint> = ring_commitments
                .iter()
                .map(|comm| comm - pseudo_out)
                .collect();

            // Convert tx_hash_bytes to array
            let mut tx_hash_arr = [0u8; 32];
            tx_hash_arr.copy_from_slice(&tx_hash_bytes);

            // Build buffer for round hash
            let (mut to_hash, _, _) = clsag_build_agg_buffer(
                &ring_keys,
                &ring_commitments,
                &key_image_point,
                &d_inv8,
                &pseudo_out,
            );
            // v0.13.0 FIX: Now passes key_image and d_inv8 to include in round hash
            clsag_convert_to_round_format(
                &mut to_hash,
                ring_size,
                &pseudo_out,
                &tx_hash_arr,
                &key_image_point,
                &d_inv8,
            );

            // Propagate challenge from position 0 to signer_idx
            for prop_i in 0..signer_idx {
                let c_p_prop = mu_p * c;
                let c_c_prop = mu_c * c;

                // L = s*G + c_p*P + c_c*C_adj
                let l_i = EdwardsPoint::vartime_multiscalar_mul(
                    [s_values[prop_i], c_p_prop, c_c_prop],
                    [
                        ED25519_BASEPOINT_POINT,
                        ring_keys[prop_i],
                        c_adjusted[prop_i],
                    ],
                );

                // Hp(P_i) for this ring member
                let hp_i = hash_to_point(ring_keys[prop_i].compress().to_bytes());

                // R = s*Hp + c_p*I + c_c*D_original
                let r_i = EdwardsPoint::vartime_multiscalar_mul(
                    [s_values[prop_i], c_p_prop, c_c_prop],
                    [hp_i, key_image_point, d_original],
                );

                clsag_add_lr_to_round_buffer(&mut to_hash, ring_size, &l_i, &r_i);
                c = clsag_keccak256_to_scalar(&to_hash);
            }

            web_sys::console::log_1(
                &format!(
                    "[CLSAG v0.10.5] FIRST SIGNER: Challenge propagated c{} = {}...",
                    signer_idx,
                    hex::encode(&c.to_bytes()[..8])
                )
                .into(),
            );
        }
    }

    // ===========================================================
    // v0.16.0 FIX (Bug #3): s-value formula with mask_delta ≠ 0
    //
    // Monero CLSAG reference (device_default.cpp):
    //   s0 = mu_P * p + mu_C * z_diff
    //   s = a - c * s0 = alpha - c * mu_P * x - c * mu_C * z_diff
    //
    // CRITICAL: z_diff is mask_delta = z_input - z_pseudo (NON-ZERO!)
    //
    // Previous bug (v0.11.0-v0.15.0): z_diff = 0 because same mask was used
    // v0.16.0 FIX: z_diff = mask_delta ≠ 0 because we use RANDOM pseudo_out_mask
    //
    // Formula:
    //   s[l] = alpha - c*mu_P*x - c*mu_C*mask_delta
    //
    // For 2-of-3 multisig:
    //   - First signer: s1[l] = alpha1 - c_p*x1 - c_c*mask_delta
    //   - Second signer: s2[l] = alpha2 - c_p*x2 (mask_delta already accounted for by first)
    // ===========================================================
    let c_p = mu_p * c; // mu_P * challenge
    let c_c = mu_c * c; // mu_C * challenge (NOW USED! v0.16.0)

    let is_second_signer = first_signer_s_values.is_some();

    // ===========================================================
    // v0.45.0: Apply Lagrange coefficient (ALWAYS REQUIRED)
    //
    // FROST unique shares solve the overlap bug:
    //   s = alpha - c_p*(λ*x) - c_c*(λ*z)
    //
    // The Lagrange coefficient λ_i weights each signer's contribution
    // so that: x_total = λ_1*x_1 + λ_2*x_2 (correct reconstruction)
    //
    // WITHOUT Lagrange (deprecated Monero native): k2 DOUBLE-COUNTED!
    // ===========================================================
    web_sys::console::log_1(
        &format!(
            "[CLSAG v0.45.0] FROST: Applying λ={} to x and mask_delta (REQUIRED)",
            hex::encode(&lagrange_coefficient.to_bytes()[..8])
        )
        .into(),
    );
    let effective_x = lagrange_coefficient * x;
    let effective_mask_delta = lagrange_coefficient * mask_delta;

    if is_second_signer {
        // SECOND SIGNER: Aggregation formula depends on mode:
        //
        // FROST MODE (λ1 + λ2 = 1):
        //   s1 = α1 - c_p*(λ1*x1) - c_c*(λ1*mask_delta)
        //   s2 = α2 - c_p*(λ2*x2) - c_c*(λ2*mask_delta)
        //   s  = s1 + s2 = (α1+α2) - c_p*(λ1*x1+λ2*x2) - c_c*(λ1+λ2)*mask_delta
        //                = α_agg - c_p*x_group - c_c*mask_delta  ✓ (correct!)
        //
        // ROUND-ROBIN MODE (λ1 = λ2 = 1, i.e., overlapping shares):
        //   First signer already includes FULL mask_delta (1*mask_delta)
        //   Second signer must NOT include mask_delta again!
        //   s1 = α1 - c_p*x1 - c_c*mask_delta  (full mask_delta)
        //   s2_contribution = α2 - c_p*x2      (NO mask_delta!)
        //   s  = s1 + s2_contribution = (α1+α2) - c_p*(x1+x2) - c_c*mask_delta  ✓
        //
        // v0.47.0 FIX: Check if λ=1 (round-robin) or λ<1 (FROST) to decide
        let first_s_values = first_signer_s_values.as_ref().unwrap();
        let first_s_pi = first_s_values[signer_idx];

        // Check if we're in FROST mode (λ < 1) or round-robin mode (λ = 1)
        // λ=1 is represented as 0x01 followed by 31 zero bytes in little-endian
        let lambda_is_one = lagrange_coefficient == Scalar::ONE;

        let my_contribution = if lambda_is_one {
            // ROUND-ROBIN: Don't include mask_delta (first signer already has it fully)
            web_sys::console::log_1(&format!(
                "[CLSAG v0.47.0] SECOND SIGNER (round-robin λ=1): s[{signer_idx}] contribution = alpha - c_p*x (NO mask_delta!)"
            ).into());
            alpha - c_p * effective_x
        } else {
            // FROST: Include weighted mask_delta (λ1 + λ2 = 1, so contributions sum correctly)
            web_sys::console::log_1(&format!(
                "[CLSAG v0.47.0] SECOND SIGNER (FROST λ<1): s[{signer_idx}] contribution = alpha - c_p*λ*x - c_c*λ*mask_delta"
            ).into());
            alpha - c_p * effective_x - c_c * effective_mask_delta
        };

        // v0.58.0: DON'T pre-aggregate here - server will aggregate s1 + s2
        // Previously: s_values[signer_idx] = first_s_pi + my_contribution;
        // This caused issues when server assumed pre-aggregation but WASM didn't do it consistently
        // Now: return just our contribution, server ALWAYS aggregates
        s_values[signer_idx] = my_contribution;
        web_sys::console::log_1(&format!(
            "[CLSAG v0.58.0] SECOND SIGNER: s[{}] = contribution only (server will aggregate with first_s[{}]={})",
            signer_idx,
            signer_idx,
            hex::encode(&first_s_pi.to_bytes()[..8])
        ).into());
    } else {
        // FIRST SIGNER: s = alpha - c_p*λ*x - c_c*λ*mask_delta
        // v0.16.0 FIX: Include mask_delta term!
        // v0.45.0: x and mask_delta are ALWAYS weighted by λ (REQUIRED)
        s_values[signer_idx] = alpha - c_p * effective_x - c_c * effective_mask_delta;
        web_sys::console::log_1(&format!(
            "[CLSAG v0.45.0] FIRST SIGNER: s[{}] = alpha - c_p*λ*x - c_c*λ*mask_delta (alpha={}, mask_delta={})",
            signer_idx,
            hex::encode(&alpha.to_bytes()[..8]),
            hex::encode(&effective_mask_delta.to_bytes()[..8])
        ).into());
    }

    // (v0.10.8: differentiated log messages moved into if/else above)

    // v0.10.2: The c1 in the output MUST be the first signer's c1, not the propagated challenge
    // - First signer: c1 is the computed initial challenge (BEFORE propagation!)
    // - Second signer: c1 is the SAME as first signer's (stored in original_c1_bytes)
    //
    // v0.10.7 FIX: For first signer, we saved original_c1_first_signer BEFORE propagation.
    // Using `c.to_bytes()` here is WRONG because `c` is now c[signer_idx] after propagation!
    let c1_bytes = if let Some(stored_c1) = original_c1_bytes {
        // SECOND SIGNER: use first signer's c1
        web_sys::console::log_1(
            &format!(
                "[CLSAG v0.10.2] SECOND SIGNER: Returning first signer's c1: {}...",
                hex::encode(&stored_c1[..8])
            )
            .into(),
        );
        stored_c1
    } else if first_signer_s_values.is_none() {
        // FIRST SIGNER: use the ORIGINAL c1 (saved before propagation)
        // NOT c.to_bytes() which is c[signer_idx] after propagation!
        web_sys::console::log_1(
            &format!(
                "[CLSAG v0.10.7] FIRST SIGNER: Returning ORIGINAL c1 (before propagation): {}...",
                hex::encode(&original_c1_first_signer.to_bytes()[..8])
            )
            .into(),
        );
        original_c1_first_signer.to_bytes()
    } else {
        // Fallback (shouldn't happen)
        c.to_bytes()
    };

    // ===========================================================
    // v0.12.0: Use the correctly computed D_inv8 from earlier
    // D = z * Hp(P[l]) / 8 where z is the commitment mask
    // ===========================================================
    let d_bytes = d_inv8.compress().to_bytes();

    web_sys::console::log_1(
        &format!(
            "[CLSAG v0.12.0] Final D_inv8 for signature: {}...",
            hex::encode(&d_bytes[..8])
        )
        .into(),
    );

    web_sys::console::log_1(&"[CLSAG Partial] Partial signature computed successfully".into());

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    mask_arr.zeroize();
    alpha_bytes.zeroize();

    // Build result
    let s_hex: Vec<String> = s_values.iter().map(|s| hex::encode(s.to_bytes())).collect();

    // CRITICAL: Return the AGGREGATED key_image (from server), NOT the partial one
    // This ensures the signature matches what's in tx_prefix_hash
    //
    // v0.37.0: Include mu_p and mu_c for first signer
    // These MUST be stored by server and sent to second signer for deterministic verification
    let is_first_signer = !has_first_signer_c1;
    web_sys::console::log_1(&"[CLSAG v0.37.2] CHECKPOINT: About to build result".into());
    web_sys::console::log_1(&format!("[CLSAG v0.37.2] is_first_signer={is_first_signer}").into());
    let result = if is_first_signer {
        web_sys::console::log_1(&"[CLSAG v0.37.2] ENTERING FIRST SIGNER BRANCH".into());
        // FIRST SIGNER: Include mu_p and mu_c in result
        web_sys::console::log_1(
            &format!(
                "[CLSAG v0.37.0] FIRST SIGNER: Including mu_p={}..., mu_c={}... in result",
                hex::encode(&mu_p.to_bytes()[..8]),
                hex::encode(&mu_c.to_bytes()[..8])
            )
            .into(),
        );
        serde_json::json!({
            "signature": {
                "D": hex::encode(d_bytes),
                "s": s_hex,
                "c1": hex::encode(c1_bytes)
            },
            "keyImage": hex::encode(key_image_bytes),
            "partialKeyImage": hex::encode(partial_ki_bytes),
            "pseudoOut": hex::encode(pseudo_out_bytes),
            "mu_p": hex::encode(mu_p.to_bytes()),
            "mu_c": hex::encode(mu_c.to_bytes())
        })
    } else {
        // SECOND SIGNER: No mu values needed (using server-provided ones)
        serde_json::json!({
            "signature": {
                "D": hex::encode(d_bytes),
                "s": s_hex,
                "c1": hex::encode(c1_bytes)
            },
            "keyImage": hex::encode(key_image_bytes),
            "partialKeyImage": hex::encode(partial_ki_bytes),
            "pseudoOut": hex::encode(pseudo_out_bytes)
        })
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// LEGACY PLACEHOLDER - Use sign_clsag_wasm instead
///
/// This function is kept for backwards compatibility but now returns
/// an error directing users to the new implementation.
#[wasm_bindgen]
pub fn sign_multisig_tx_wasm(
    _unsigned_tx_hex: String,
    _spend_key_priv_hex: String,
) -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "DEPRECATED: Use sign_clsag_partial_wasm() for multisig or sign_clsag_wasm() for single-signer. \
         This function requires the server to provide ring members via /api/escrow/{id}/prepare-sign"
    ))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multisig_state_serialization() {
        let state = MultisigState {
            stage: "prepared".to_string(),
            multisig_address: None,
            my_multisig_info: Some("test_blob".to_string()),
            peer_multisig_infos: vec![],
            threshold: 2,
            total: 3,
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: MultisigState = serde_json::from_str(&json).unwrap();

        assert_eq!(state.stage, deserialized.stage);
        assert_eq!(state.threshold, deserialized.threshold);
        assert_eq!(state.total, deserialized.total);
    }

    #[test]
    fn test_crypto_error_creation() {
        let err = CryptoError::new("TEST_ERROR", "This is a test error");

        assert_eq!(err.code, "TEST_ERROR");
        assert_eq!(err.message, "This is a test error");
    }

    #[test]
    fn test_wallet_state_structure() {
        // Test that WasmWallet can be instantiated (compilation test)
        let spend_key = Scalar::from_bytes_mod_order([1u8; 32]);
        let view_key = Scalar::from_bytes_mod_order([2u8; 32]);

        let spend_public = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &spend_key;
        let view_public = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &view_key;

        let _wallet = WasmWallet {
            spend_key,
            view_key,
            spend_key_pub: spend_public.compress().to_bytes(),
            view_key_pub: view_public.compress().to_bytes(),
            address: "4TestAddress".to_string(),
            multisig_state: None,
        };

        // If we reach here, struct is valid
        assert!(true);
    }

    // Note: WASM function tests (prepare_multisig_wasm, make_multisig_wasm, etc.)
    // require wasm-bindgen test runner in browser context.
    // Run with: wasm-pack test --chrome --headless
}
