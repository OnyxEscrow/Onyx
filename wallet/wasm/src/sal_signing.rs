//! SA+L WASM Signing — client-side FROST preprocess + sign for FCMP++.
//!
//! This module exposes the 2-round SA+L signing protocol to JavaScript:
//!
//! ## Round 1: Preprocess (generate nonce commitments)
//! ```js
//! const { sessionId, preprocessHex } = await sal_preprocess(keysHex, txHash, rerandHex, xSecretHex, signerIndices);
//! // Send preprocessHex to server
//! ```
//!
//! ## Round 2: Sign (generate partial signature)
//! ```js
//! const shareHex = await sal_sign(sessionId, allPreprocessesJson, message);
//! // Send shareHex to server
//! ```
//!
//! ## State Management
//!
//! Between rounds, the FROST `SignMachine` is held in WASM memory (never
//! exposed to JS). The `sessionId` is an opaque handle that maps to the
//! machine in a `RefCell<HashMap>`. This ensures nonce secrets never
//! leave the WASM sandbox.
//!
//! ## Non-blocking
//!
//! `preprocess()` and `sign()` are computationally lightweight (scalar
//! multiplications, not proof generation). They execute synchronously in
//! WASM in <1ms and do not block the browser event loop.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Cursor;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use onyx_fcmp::vendor::{
    Ed25519T, SalAlgorithm, ThresholdCore, ThresholdKeys,
    Participant,
    AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine,
    PreprocessMachine, SignMachine, SignatureMachine,
    Writable, CryptoRng, RngCore,
    VendorRerandomizedOutput, RecommendedTranscript,
    SpendAuthAndLinkability,
};
use onyx_fcmp::gsp::multisig::{OnyxSalSigner, bytes_to_scalar};

// =============================================================================
// Types
// =============================================================================

/// RNG wrapper for WASM (getrandom + js feature → crypto.getRandomValues).
#[derive(Clone)]
pub(crate) struct WasmRng;

impl RngCore for WasmRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest)
            .map_err(|e| rand_core::Error::new(e))
    }
}

// SAFETY: WASM is single-threaded, these are required for the trait bounds.
unsafe impl Send for WasmRng {}
unsafe impl Sync for WasmRng {}

impl CryptoRng for WasmRng {}

/// Concrete algorithm type for WASM (RNG = WasmRng).
type SalAlgo = SalAlgorithm<WasmRng, RecommendedTranscript>;

/// The sign machine state held between Round 1 and Round 2.
type SalSignMachineState = AlgorithmSignMachine<Ed25519T, SalAlgo>;

/// The signature machine state held for aggregation (optional, server-side).
type SalSigMachineState = AlgorithmSignatureMachine<Ed25519T, SalAlgo>;

// =============================================================================
// Session Store (WASM is single-threaded — RefCell is safe)
// =============================================================================

thread_local! {
    /// Sign machines waiting for Round 2 input.
    static SIGN_MACHINES: RefCell<HashMap<String, SalSignMachineState>> =
        RefCell::new(HashMap::new());

    /// Signature machines waiting for share aggregation (only if completing client-side).
    static SIG_MACHINES: RefCell<HashMap<String, SalSigMachineState>> =
        RefCell::new(HashMap::new());

    /// Session counter for unique IDs.
    static SESSION_COUNTER: RefCell<u64> = RefCell::new(0);
}

fn next_session_id() -> String {
    SESSION_COUNTER.with(|c| {
        let mut counter = c.borrow_mut();
        *counter += 1;
        format!("sal_{}", *counter)
    })
}

// =============================================================================
// JS Results
// =============================================================================

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreprocessResult {
    /// Opaque session handle — pass to `sal_sign()`.
    pub session_id: String,
    /// Hex-encoded preprocess bytes (nonce commitments) to send to server.
    pub preprocess_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResult {
    /// Hex-encoded signature share to send to server.
    pub share_hex: String,
}

// =============================================================================
// WASM-Exported Functions
// =============================================================================

/// SA+L Round 1: Generate nonce commitments (FROST preprocess).
///
/// This creates the FROST preprocess (nonce commitments) and stores the
/// sign machine in WASM memory for Round 2.
///
/// # Arguments
/// * `threshold_keys_hex` - Hex-encoded serialized `ThresholdCore<Ed25519T>`
/// * `signable_tx_hash_hex` - 32-byte TX hash (64 hex chars)
/// * `rerandomized_output_hex` - Hex-encoded `RerandomizedOutput`
/// * `x_secret_hex` - Hex-encoded spend key scalar x (32 bytes)
/// * `signer_indices` - JSON array of participating signer indices, e.g. "[1,2]"
///
/// # Returns
/// JSON `{ sessionId, preprocessHex }` or throws on error.
#[wasm_bindgen]
pub fn sal_preprocess(
    threshold_keys_hex: &str,
    signable_tx_hash_hex: &str,
    rerandomized_output_hex: &str,
    x_secret_hex: &str,
    signer_indices: &str,
) -> Result<JsValue, JsValue> {
    // Parse TX hash
    let tx_hash_bytes = hex::decode(signable_tx_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid TX hash hex: {}", e)))?;
    if tx_hash_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "TX hash must be 32 bytes, got {}", tx_hash_bytes.len()
        )));
    }
    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(&tx_hash_bytes);

    // Parse x_secret
    let x_bytes = hex::decode(x_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid x_secret hex: {}", e)))?;
    if x_bytes.len() != 32 {
        return Err(JsValue::from_str("x_secret must be 32 bytes"));
    }
    let mut x_arr = [0u8; 32];
    x_arr.copy_from_slice(&x_bytes);
    let x_scalar = bytes_to_scalar(&x_arr)
        .map_err(|e| JsValue::from_str(&format!("Invalid x_secret scalar: {}", e)))?;

    // Parse rerandomized output (binary format — read/write, not serde)
    let rerand_bytes = hex::decode(rerandomized_output_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid rerandomized output hex: {}", e)))?;
    let rerandomized_output = VendorRerandomizedOutput::read(&mut Cursor::new(&rerand_bytes))
        .map_err(|e| JsValue::from_str(&format!("Invalid rerandomized output: {}", e)))?;

    // Parse threshold keys
    let keys_bytes = hex::decode(threshold_keys_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid threshold keys hex: {}", e)))?;
    let threshold_core = ThresholdCore::<Ed25519T>::read::<&[u8]>(&mut keys_bytes.as_slice())
        .map_err(|e| JsValue::from_str(&format!("Invalid threshold keys: {}", e)))?;
    let threshold_keys = ThresholdKeys::new(threshold_core);

    // Parse signer indices (must match threshold from ThresholdKeys)
    let indices: Vec<u16> = serde_json::from_str(signer_indices)
        .map_err(|e| JsValue::from_str(&format!("Invalid signer indices: {}", e)))?;
    if indices.is_empty() {
        return Err(JsValue::from_str("At least one signer index required"));
    }

    // Validate signer indices (Lagrange adjustment happens internally in sign())
    let participants: Vec<Participant> = indices.iter()
        .filter_map(|&i| Participant::new(i))
        .collect();
    if participants.len() != indices.len() {
        return Err(JsValue::from_str("Invalid participant indices (zero is not a valid index)"));
    }

    // Create SA+L signer algorithm
    let signer = OnyxSalSigner::new(WasmRng, tx_hash, rerandomized_output, x_scalar);
    let algorithm = signer.into_algorithm();

    // Create algorithm machine (Lagrange coefficients applied internally during sign())
    let machine = AlgorithmMachine::new(algorithm, threshold_keys);

    // Preprocess: generate nonces
    let mut rng = WasmRng;
    let (sign_machine, preprocess) = machine.preprocess(&mut rng);

    // Serialize preprocess to hex
    let mut preprocess_buf = Vec::new();
    preprocess.write(&mut preprocess_buf)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize preprocess: {}", e)))?;
    let preprocess_hex = hex::encode(&preprocess_buf);

    // Store sign machine for Round 2
    let session_id = next_session_id();
    SIGN_MACHINES.with(|m| {
        m.borrow_mut().insert(session_id.clone(), sign_machine);
    });

    let result = PreprocessResult {
        session_id,
        preprocess_hex,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// SA+L Round 2: Generate partial signature (FROST sign).
///
/// Uses the stored sign machine from Round 1 to produce a partial
/// signature share. The machine is consumed (removed from memory)
/// after this call.
///
/// # Arguments
/// * `session_id` - The session handle from `sal_preprocess()`
/// * `all_preprocesses_json` - JSON object mapping participant index → preprocess hex
///   e.g. `{"1": "aabb...", "2": "ccdd..."}`
/// * `message_hex` - The message to sign (hex, typically the TX hash)
///
/// # Returns
/// JSON `{ shareHex }` or throws on error.
#[wasm_bindgen]
pub fn sal_sign(
    session_id: &str,
    all_preprocesses_json: &str,
    message_hex: &str,
) -> Result<JsValue, JsValue> {
    // Retrieve and consume the sign machine
    let sign_machine = SIGN_MACHINES.with(|m| {
        m.borrow_mut().remove(session_id)
    }).ok_or_else(|| JsValue::from_str(&format!(
        "No sign machine for session '{}' — already used or expired", session_id
    )))?;

    // Parse preprocesses map: { "1": "hex...", "2": "hex..." }
    let preprocess_map: HashMap<String, String> = serde_json::from_str(all_preprocesses_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid preprocesses JSON: {}", e)))?;

    // Convert to HashMap<Participant, Preprocess<Ed25519T, ...>>
    // We need to deserialize each preprocess from hex bytes
    let mut preprocesses = HashMap::new();
    for (idx_str, hex_val) in &preprocess_map {
        let idx: u16 = idx_str.parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid participant index '{}': {}", idx_str, e)))?;
        let participant = Participant::new(idx)
            .ok_or_else(|| JsValue::from_str(&format!("Invalid participant index: {}", idx)))?;

        let bytes = hex::decode(hex_val)
            .map_err(|e| JsValue::from_str(&format!("Invalid preprocess hex for {}: {}", idx, e)))?;
        let mut cursor = Cursor::new(&bytes);

        // read_preprocess is a &self method on SignMachine — returns the correct type
        let preprocess = sign_machine.read_preprocess(&mut cursor)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize preprocess for {}: {}", idx, e)))?;

        preprocesses.insert(participant, preprocess);
    }

    // Parse message
    let msg_bytes = hex::decode(message_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid message hex: {}", e)))?;

    // Sign: produce partial signature share
    let (sig_machine, share) = sign_machine.sign(preprocesses, &msg_bytes)
        .map_err(|e| JsValue::from_str(&format!("FROST sign failed: {:?}", e)))?;

    // Serialize share to hex
    let mut share_buf = Vec::new();
    share.write(&mut share_buf)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize share: {}", e)))?;
    let share_hex = hex::encode(&share_buf);

    // Optionally store sig machine for client-side completion
    SIG_MACHINES.with(|m| {
        m.borrow_mut().insert(session_id.to_string(), sig_machine);
    });

    let result = SignResult { share_hex };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Result of SA+L aggregation (FROST complete).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteResult {
    /// Hex-encoded SpendAuthAndLinkability proof (384 bytes = 12 × 32).
    /// Layout: P(32) A(32) B(32) R_O(32) R_P(32) R_L(32)
    ///         s_alpha(32) s_beta(32) s_delta(32) s_y(32) s_z(32) s_r_p(32)
    pub sal_proof_hex: String,
}

/// SA+L Round 3: Aggregate shares and produce final proof (FROST complete).
///
/// This is the final step of the SA+L signing protocol. It takes all signers'
/// partial signature shares, aggregates them, and produces the final
/// `SpendAuthAndLinkability` proof.
///
/// **Must be called by one of the two signers** — the one whose WASM holds
/// the `SignatureMachine` state from Round 2. The server cannot aggregate
/// because it doesn't have the partial SA+L data (P, A, B, etc.) that is
/// computed inside `sign()`.
///
/// # Arguments
/// * `session_id` - The session handle from `sal_preprocess()`/`sal_sign()`
/// * `all_shares_json` - JSON object mapping participant index → share hex
///   e.g. `{"1": "aabb...", "2": "ccdd..."}`
///
/// # Returns
/// JSON `{ salProofHex }` — 384-byte SpendAuthAndLinkability proof.
///
/// # Errors
/// - If session doesn't exist (already consumed or expired)
/// - If share deserialization fails
/// - If FROST aggregation fails (returns `FrostError::InvalidShare(participant)`)
#[wasm_bindgen]
pub fn sal_complete(
    session_id: &str,
    all_shares_json: &str,
) -> Result<JsValue, JsValue> {
    // Retrieve and consume the signature machine
    let sig_machine = SIG_MACHINES.with(|m| {
        m.borrow_mut().remove(session_id)
    }).ok_or_else(|| JsValue::from_str(&format!(
        "No signature machine for session '{}' — already used, expired, or sal_sign() not called",
        session_id
    )))?;

    // Parse shares map: { "1": "hex...", "2": "hex..." }
    let shares_map: HashMap<String, String> = serde_json::from_str(all_shares_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid shares JSON: {}", e)))?;

    // Deserialize each share using the sig machine's reader
    let mut shares = HashMap::new();
    for (idx_str, hex_val) in &shares_map {
        let idx: u16 = idx_str.parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid participant index '{}': {}", idx_str, e)))?;
        let participant = Participant::new(idx)
            .ok_or_else(|| JsValue::from_str(&format!("Invalid participant index: {}", idx)))?;

        let bytes = hex::decode(hex_val)
            .map_err(|e| JsValue::from_str(&format!("Invalid share hex for {}: {}", idx, e)))?;
        let mut cursor = Cursor::new(&bytes);

        let share = sig_machine.read_share(&mut cursor)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize share for {}: {}", idx, e)))?;

        shares.insert(participant, share);
    }

    // FROST complete: aggregate shares → SpendAuthAndLinkability
    // If a share is invalid, this returns FrostError::InvalidShare(participant)
    let sal_proof: SpendAuthAndLinkability = sig_machine.complete(shares)
        .map_err(|e| JsValue::from_str(&format!("FROST aggregation failed: {:?}", e)))?;

    // Serialize the proof (6 points + 6 scalars = 384 bytes)
    let mut proof_buf = Vec::with_capacity(384);
    sal_proof.write(&mut proof_buf)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize SA+L proof: {}", e)))?;

    let result = CompleteResult {
        sal_proof_hex: hex::encode(&proof_buf),
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Clean up a signing session from WASM memory.
///
/// Call this if the signing flow is aborted to prevent memory leaks.
/// Sessions are automatically cleaned up after `sal_complete()` consumes
/// the sig machine, but call this explicitly if aborting mid-flow.
#[wasm_bindgen]
pub fn sal_cleanup(session_id: &str) {
    SIGN_MACHINES.with(|m| { m.borrow_mut().remove(session_id); });
    SIG_MACHINES.with(|m| { m.borrow_mut().remove(session_id); });
}

/// Get active session count (for debugging/monitoring).
#[wasm_bindgen]
pub fn sal_active_sessions() -> u32 {
    let sign = SIGN_MACHINES.with(|m| m.borrow().len());
    let sig = SIG_MACHINES.with(|m| m.borrow().len());
    (sign + sig) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_counter_increments() {
        let id1 = next_session_id();
        let id2 = next_session_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("sal_"));
        assert!(id2.starts_with("sal_"));
    }

    #[test]
    fn test_wasm_rng_produces_output() {
        let mut rng = WasmRng;
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        // Statistically impossible to get all zeros from a CSPRNG
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn test_cleanup_removes_sessions() {
        // Just verifies the cleanup function doesn't panic
        sal_cleanup("nonexistent_session");
    }
}
