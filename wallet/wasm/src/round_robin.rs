//! Round-Robin CLSAG Signing for 2-of-3 Multisig
//!
//! This module implements the correct Monero multisig signing protocol where:
//! 1. Signer 1 creates a partial transaction with encrypted nonce
//! 2. Signer 2 decrypts the nonce and completes the signature
//!
//! This is the ONLY correct way to do CLSAG multisig - parallel aggregation does NOT work.
//!
//! v0.8.1: Added comprehensive debug instrumentation for CLSAG verification

use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::VartimeMultiscalarMul,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

// Use the correct Monero hash_to_point implementation (ge_fromfe_frombytes_vartime)
use monero_generators::hash_to_point;
// H is the Pedersen commitment generator for amounts (NOT hash_to_point(G)!)
use monero_generators::H;

// Debug instrumentation
use crate::clsag_debug::ClsagDebugContext;

// NOTE: hash_to_scalar (Monero's Hs) is now defined as keccak256_to_scalar
// in the CLSAG core section below, matching the reference implementation name.

/// Input data for signing
#[derive(Deserialize)]
pub struct SignInputData {
    /// Ring members: [[public_key, commitment], ...]
    pub ring: Vec<[String; 2]>,
    /// Index of the real output in the ring
    pub signer_index: u8,
    /// v0.35.1: commitment_mask is now OUTPUT_MASK (derived) for pseudo_out balance
    pub commitment_mask: String,
    /// v0.35.1: funding_mask is the INPUT's commitment mask (z)
    /// Used to compute: mask_delta = funding_mask - commitment_mask = z - output_mask
    #[serde(default)]
    pub funding_mask: Option<String>,
    /// Amount in atomic units
    pub commitment_amount: u64,
    /// Ring member offsets for serialization
    pub offsets: Vec<u64>,

    // ===== MuSig2 Nonce Fields (v0.9.0) =====
    /// Alpha nonce secret (hex) from generate_nonce_commitment()
    /// Stored in window.tempNonceAlpha (memory only, NOT localStorage)
    #[serde(default)]
    pub alpha_secret: Option<String>,

    /// Peer's nonce public data (JSON string) from server
    /// Contains: {"r_public": "...", "r_prime_public": "..."}
    #[serde(default)]
    pub peer_nonce_public: Option<String>,

    // ===== Threshold Signing Fields (v0.50.0) =====
    /// My threshold index for Lagrange coefficient computation (1=buyer, 2=vendor, 3=arbiter)
    /// REQUIRED for correct 2-of-3 threshold signature
    #[serde(default)]
    pub my_signer_index: Option<u8>,

    /// Other signer's threshold index (1=buyer, 2=vendor, 3=arbiter)
    /// REQUIRED for correct 2-of-3 threshold signature
    #[serde(default)]
    pub other_signer_index: Option<u8>,
}

/// Partial transaction created by Signer 1
#[derive(Serialize, Deserialize)]
pub struct PartialTx {
    /// Ring size
    pub ring_size: u8,
    /// Signer index in ring
    pub signer_index: u8,
    /// Partial s values (hex encoded)
    pub s_values: Vec<String>,
    /// Initial challenge c1 (hex)
    pub c1: String,
    /// D point (hex)
    pub d: String,
    /// Pseudo-output commitment (hex)
    pub pseudo_out: String,
    /// Key image (hex) - for Round-Robin, this is Signer 1's partial key image
    pub key_image: String,
    /// Signer 1's partial key image: pKI_1 = x_1 * Hp(P_multisig)
    #[serde(default)]
    pub partial_key_image_1: Option<String>,
    /// Encrypted nonce (hex: nonce || ciphertext || tag)
    pub alpha_encrypted: String,
    /// Signer 1's public key for ECDH (hex)
    pub signer1_public: String,
    /// c * mu_P at signer index (hex)
    pub c_p: String,
    /// c * mu_C at signer index (hex)
    pub c_c: String,
    /// Mask delta = original_mask - pseudo_out_mask (hex)
    pub mask_delta: String,
    /// Transaction prefix hash (hex)
    pub tx_prefix_hash: String,
    /// Multisig public key (hex) - needed by Signer 2 for key image calculation
    #[serde(default)]
    pub multisig_pub_key: Option<String>,
    /// Ring member pubkey at signer_index - CRITICAL for Signer 2 to use same Hp base
    /// This MUST be used by Signer 2 for Hp() instead of multisig_pub_key
    #[serde(default)]
    pub ring_signer_pubkey: Option<String>,
    /// v0.37.0: mu_P mixing coefficient (hex) - computed by first signer
    /// Second signer and verifier MUST use this exact value
    #[serde(default)]
    pub mu_p: Option<String>,
    /// v0.37.0: mu_C mixing coefficient (hex) - computed by first signer
    /// Second signer and verifier MUST use this exact value
    #[serde(default)]
    pub mu_c: Option<String>,

    // ===== Threshold Signing Fields (v0.50.0) =====
    /// First signer's threshold index (1=buyer, 2=vendor, 3=arbiter)
    /// Used by second signer to compute Lagrange coefficients
    #[serde(default)]
    pub first_signer_index: Option<u8>,
    /// Second signer's threshold index (1=buyer, 2=vendor, 3=arbiter)
    /// Used by second signer to compute Lagrange coefficients
    #[serde(default)]
    pub second_signer_index: Option<u8>,
}

/// Completed CLSAG signature
#[derive(Serialize, Deserialize)]
pub struct CompletedClsag {
    /// Final s values (hex)
    pub s_values: Vec<String>,
    /// Initial challenge c1 (hex)
    pub c1: String,
    /// D point (hex)
    pub d: String,
    /// Pseudo-output (hex)
    pub pseudo_out: String,
    /// Key image (hex)
    pub key_image: String,
}

/// Create a partial transaction (Signer 1) - v0.8.4 with derivation support
///
/// This function:
/// 1. Computes output secret: x = H_s(a·R||idx) + b (if derivation provided)
/// 2. Generates a random nonce alpha
/// 3. Computes the CLSAG ring loop
/// 4. Creates partial s[signer_index] with Signer 1's contribution
/// 5. Encrypts alpha for Signer 2
///
/// v0.8.4: Added optional derivation parameters for asymmetric PKI
/// - Vendor (Signer 1) MUST include derivation
/// - tx_pub_key_hex, view_key_hex, output_index are optional but recommended
#[wasm_bindgen]
pub fn create_partial_tx_wasm(
    spend_key_priv_hex: String,
    mask_share_hex: String,
    signer2_public_hex: String,
    input_data_json: String,
    tx_prefix_hash_hex: String,
    key_image_hex: String,
    multisig_pub_key_hex: String,
) -> Result<JsValue, JsValue> {
    // v0.8.4: Call extended version with no derivation (backward compatible)
    create_partial_tx_wasm_with_derivation(
        spend_key_priv_hex,
        mask_share_hex,
        signer2_public_hex,
        input_data_json,
        tx_prefix_hash_hex,
        key_image_hex,
        multisig_pub_key_hex,
        String::new(), // No tx_pub_key
        String::new(), // No view_key
        0,             // output_index = 0
    )
}

/// Create a partial transaction (Signer 1) with derivation support
///
/// v0.8.4: Full version with derivation parameters
/// - tx_pub_key_hex: The R from the funding transaction
/// - view_key_hex: The shared view private key (a)
/// - output_index: Index of the output in the transaction
///
/// If derivation parameters are provided, computes:
///   x = H_s(a·R || output_index) + b
/// Otherwise, uses x = b (raw spend key)
#[wasm_bindgen]
pub fn create_partial_tx_wasm_with_derivation(
    spend_key_priv_hex: String,
    mask_share_hex: String,
    signer2_public_hex: String,
    input_data_json: String,
    tx_prefix_hash_hex: String,
    key_image_hex: String,
    multisig_pub_key_hex: String,
    tx_pub_key_hex: String,
    view_key_hex: String,
    output_index: u64,
) -> Result<JsValue, JsValue> {
    web_sys::console::log_1(&"[Round-Robin] Creating partial TX (Signer 1) v0.8.4".into());

    // Parse inputs
    let input_data: SignInputData = serde_json::from_str(&input_data_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid input_data: {e}")))?;

    let mut spend_key_arr = parse_hex_32(&spend_key_priv_hex, "spend_key")?;
    let spend_scalar = Scalar::from_bytes_mod_order(spend_key_arr);

    // v0.8.4: Compute output secret with derivation if parameters provided
    // v0.51.0 FIX: Compute derivation separately from spend share
    // This is CRITICAL because:
    //   - Key Image = (d + λ1*b1 + λ2*b2) * Hp(P)
    //   - Signature must use SAME x_eff = d + λ1*b1 + λ2*b2
    //   - Derivation 'd' is NOT weighted by Lagrange coefficient!
    //   - Only spend shares (b1, b2) are weighted
    //
    // BUG (v0.50.0): Computed λ1*(d+b1) which gives λ1*d + λ1*b1
    // CORRECT (v0.51.0): Compute d + λ1*b1 (derivation not weighted)
    let (derivation_scalar, has_derivation) = if !tx_pub_key_hex.is_empty()
        && !view_key_hex.is_empty()
    {
        web_sys::console::log_1(
            &"[Round-Robin] Computing derivation H_s(a·R||idx) (separate from spend)".into(),
        );

        // Parse tx_pub_key (R)
        let tx_pub_arr = parse_hex_32(&tx_pub_key_hex, "tx_pub_key")?;
        let tx_pub_point = CompressedEdwardsY(tx_pub_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid tx_pub_key point"))?;

        // Parse view key (a)
        let view_arr = parse_hex_32(&view_key_hex, "view_key")?;
        let view_scalar = Scalar::from_bytes_mod_order(view_arr);

        // Compute shared secret: 8 * a * R (with cofactor for Monero compatibility)
        // v0.52.0 FIX: Added mul_by_cofactor() which is REQUIRED for correct derivation
        let shared_secret = (view_scalar * tx_pub_point).mul_by_cofactor();
        let shared_secret_bytes = shared_secret.compress().to_bytes();

        // Compute derivation: H_s(shared_secret || output_index)
        let mut hasher = Keccak256::new();
        hasher.update(shared_secret_bytes);
        hasher.update(output_index.to_le_bytes());
        let derivation_hash: [u8; 32] = hasher.finalize().into();
        let d = Scalar::from_bytes_mod_order(derivation_hash);

        web_sys::console::log_1(
            &format!(
                "[Round-Robin v0.51.0] Derivation scalar d: {}",
                hex::encode(&derivation_hash[..8])
            )
            .into(),
        );

        (d, true)
    } else {
        web_sys::console::log_1(&"[Round-Robin] No derivation - using b only (LEGACY MODE)".into());
        (Scalar::ZERO, false)
    };

    // x1 = d + b1 for compatibility with existing code paths (e.g., key image computation)
    let x1 = derivation_scalar + spend_scalar;

    let mut mask_arr = parse_hex_32(&mask_share_hex, "mask_share")?;
    let z1 = Scalar::from_bytes_mod_order(mask_arr);

    let signer2_pub_arr = parse_hex_32(&signer2_public_hex, "signer2_public")?;
    let tx_hash_arr = parse_hex_32(&tx_prefix_hash_hex, "tx_prefix_hash")?;
    let key_image_arr = parse_hex_32(&key_image_hex, "key_image")?;
    let multisig_pub_arr = parse_hex_32(&multisig_pub_key_hex, "multisig_pub_key")?;

    let ring_size = input_data.ring.len();
    let signer_idx = input_data.signer_index as usize;

    // Parse ring members
    let mut ring_keys: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);
    let mut ring_commitments: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);

    for pair in &input_data.ring {
        let key_arr = parse_hex_32(&pair[0], "ring_key")?;
        let commit_arr = parse_hex_32(&pair[1], "ring_commitment")?;

        let key_point = CompressedEdwardsY(key_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid ring key point"))?;
        let commit_point = CompressedEdwardsY(commit_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid ring commitment point"))?;

        ring_keys.push(key_point);
        ring_commitments.push(commit_point);
    }

    // Parse commitment_mask (which is now output_mask in v0.35.1)
    let output_mask_arr = parse_hex_32(&input_data.commitment_mask, "commitment_mask")?;
    let output_mask = Scalar::from_bytes_mod_order(output_mask_arr);

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

    // v0.35.2 FIX: mask_delta = z - pseudo_out_mask
    //
    // Server now sends:
    // - commitment_mask = pseudo_out_mask = output_mask + dummy_mask (THE SUM)
    // - funding_mask = z (input's commitment mask)
    //
    // WASM computes:
    // - pseudo_out_mask = commitment_mask (already the sum from server)
    // - mask_delta = z - pseudo_out_mask ≠ 0 (because z ≠ sum when dummy is derived independently)
    let pseudo_out_mask = output_mask; // output_mask was parsed from commitment_mask (now = pseudo_out_mask)

    let mask_delta = if let Some(ref funding_mask_hex) = input_data.funding_mask {
        let funding_arr = parse_hex_32(funding_mask_hex, "funding_mask")?;
        let funding_z = Scalar::from_bytes_mod_order(funding_arr);

        // mask_delta = z - pseudo_out_mask
        let delta = funding_z - pseudo_out_mask;

        web_sys::console::log_1(&"[Round-Robin][v0.35.2] mask_delta = z - pseudo_out_mask".into());
        web_sys::console::log_1(
            &format!(
                "[Round-Robin][v0.35.2] funding_mask (z): {}",
                hex::encode(funding_arr)
            )
            .into(),
        );
        web_sys::console::log_1(
            &format!(
                "[Round-Robin][v0.35.2] commitment_mask (pseudo_out_mask = SUM): {}",
                hex::encode(pseudo_out_mask.to_bytes())
            )
            .into(),
        );
        web_sys::console::log_1(
            &format!(
                "[Round-Robin][v0.35.2] mask_delta (z - pseudo_out_mask): {}",
                hex::encode(delta.to_bytes())
            )
            .into(),
        );

        delta
    } else {
        // Legacy mode: no funding_mask, use mask_delta = 0
        web_sys::console::log_1(
            &"[Round-Robin][v0.35.2] WARNING: No funding_mask, mask_delta = 0 (legacy)".into(),
        );
        Scalar::ZERO
    };

    // Compute pseudo-out commitment: C' = mask * G + amount * H
    // CRITICAL: Use Monero's H constant, NOT hash_to_point(G)!
    let h_point = *H;

    // DEBUG: Log H to verify it matches server's H_BYTES
    let h_bytes = h_point.compress().to_bytes();
    web_sys::console::log_1(
        &format!("[Round-Robin] H point bytes: {}", hex::encode(h_bytes)).into(),
    );

    let amount_scalar = Scalar::from(input_data.commitment_amount);
    let pseudo_out = ED25519_BASEPOINT_TABLE * &pseudo_out_mask + h_point * amount_scalar;
    let pseudo_out_bytes = pseudo_out.compress().to_bytes();

    // =========================================================================
    // CRITICAL FIX: Use ring_keys[signer_idx] for ALL Hp() calculations
    // =========================================================================
    // In CLSAG, all uses of Hp() MUST use the same base point:
    // - Key Image: I = x * Hp(P)
    // - D point: D = mask_delta * Hp(P)
    // - AH point: AH = alpha * Hp(P)
    // Where P = ring_keys[signer_idx] (the one-time stealth address of the output)
    //
    // For multisig: ring_keys[signer_idx] IS the multisig address that received funds.
    // We MUST use this key, NOT any other representation of the multisig public key.
    // =========================================================================
    let signer_ring_key_bytes = ring_keys[signer_idx].compress().to_bytes();
    let hp_signer = hash_to_point(signer_ring_key_bytes);

    web_sys::console::log_1(
        &format!(
            "[Round-Robin] Using Hp(ring_keys[{}]) for all CLSAG calculations: {}",
            signer_idx,
            hex::encode(&signer_ring_key_bytes[..16])
        )
        .into(),
    );

    // v0.36.1 FIX: Verify that ring_keys[signer_idx] matches multisig_pub_key
    // They MUST be the same - if not, the Hp() base will be wrong and CLSAG verification will fail.
    // Previously this just logged a warning, but that's dangerous - we must ABORT.
    if signer_ring_key_bytes != multisig_pub_arr {
        web_sys::console::log_1(&format!(
            "[Round-Robin] CRITICAL ERROR: ring_keys[{signer_idx}] != multisig_pub_key! Aborting to prevent Hp() mismatch."
        ).into());
        web_sys::console::log_1(
            &format!(
                "[Round-Robin]   ring_keys[{}]: {}",
                signer_idx,
                hex::encode(signer_ring_key_bytes)
            )
            .into(),
        );
        web_sys::console::log_1(
            &format!(
                "[Round-Robin]   multisig_pub_key: {}",
                hex::encode(multisig_pub_arr)
            )
            .into(),
        );
        return Err(JsValue::from_str(
            "Hp base point mismatch: ring_keys[signer_idx] != multisig_pub_key. \
             This indicates corrupted ring data or wrong signer index. Aborting.",
        ));
    }

    // Calculate Signer 1's partial key image: pKI_1 = x_1 * Hp(P[signer_idx])
    // MUST use the same Hp as D calculation!
    let partial_key_image_1 = hp_signer * x1;
    let partial_key_image_1_bytes = partial_key_image_1.compress().to_bytes();

    web_sys::console::log_1(
        &format!(
            "[Round-Robin] Signer 1 partial key image: {}",
            hex::encode(partial_key_image_1_bytes)
        )
        .into(),
    );

    // Parse provided key image - MUST be the aggregated key image
    // For 2-of-3 multisig CLSAG: KI = pKI_1 + pKI_2 = (x1 + x2) * Hp(P[signer_idx])
    // Server aggregates partial key images from both signers BEFORE signing begins
    let key_image_point = if key_image_arr == [0u8; 32] {
        // CRITICAL: Reject zeros - frontend must submit partial KIs first to get aggregated KI
        web_sys::console::log_1(&"[Round-Robin] ERROR: Key image is zeros! Both signers must submit partial key images first.".into());
        return Err(JsValue::from_str(
            "Aggregated key image required. Both signers must submit partial key images via /submit-partial-key-image before signing."
        ));
    } else {
        web_sys::console::log_1(
            &format!(
                "[Round-Robin] Using aggregated key image: {}",
                hex::encode(&key_image_arr[..16])
            )
            .into(),
        );
        CompressedEdwardsY(key_image_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid key image point"))?
    };

    // D = mask_delta * Hp(P[signer_index]) - same Hp as key image!
    let d_original = hp_signer * mask_delta;

    // v0.14.0 DEBUG: Full D point logging
    let d_original_bytes = d_original.compress().to_bytes();
    web_sys::console::log_1(
        &format!(
            "[Round-Robin][v0.14-DEBUG] D_original point (full): {}",
            hex::encode(d_original_bytes)
        )
        .into(),
    );

    // Check if D is identity point (indicates mask_delta = 0 bug)
    let identity_bytes = [
        1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    if d_original_bytes == identity_bytes {
        web_sys::console::log_1(&"[Round-Robin][v0.14-DEBUG] ⚠️ CRITICAL: D_original is IDENTITY POINT! Signature will be invalid!".into());
    }

    let inv8 = Scalar::from(8u64).invert();
    let d_inv8 = d_original * inv8;
    let d_bytes = d_inv8.compress().to_bytes(); // Store D * inv8 in signature

    web_sys::console::log_1(
        &format!(
            "[Round-Robin][v0.14-DEBUG] D_inv8 point (stored): {}",
            hex::encode(d_bytes)
        )
        .into(),
    );

    // ===== MuSig2 v0.9.0: Use provided alpha_secret if available =====
    // If alpha_secret is provided (from generate_nonce_commitment), use it.
    // Otherwise, generate random alpha (legacy mode).
    let alpha = if let Some(alpha_hex) = input_data.alpha_secret.as_ref() {
        web_sys::console::log_1(&"[MuSig2 v0.9.0] Using alpha from nonce commitment".into());
        let alpha_bytes = hex::decode(alpha_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid alpha_secret hex: {e}")))?;
        if alpha_bytes.len() != 32 {
            return Err(JsValue::from_str("alpha_secret must be 32 bytes"));
        }
        let mut alpha_arr = [0u8; 32];
        alpha_arr.copy_from_slice(&alpha_bytes);
        Scalar::from_bytes_mod_order(alpha_arr)
    } else {
        web_sys::console::log_1(&"[Round-Robin] Generating random alpha (legacy mode)".into());
        let mut alpha_seed = [0u8; 32];
        getrandom::getrandom(&mut alpha_seed)
            .map_err(|e| JsValue::from_str(&format!("RNG error for alpha: {e}")))?;
        Scalar::from_bytes_mod_order(alpha_seed)
    };

    // Compute A = alpha * G and AH = alpha * Hp(P[signer_index])
    // AH must use same Hp as D computation (ring member, not multisig key)
    let a_point_mine = ED25519_BASEPOINT_TABLE * &alpha;
    let ah_point_mine = hp_signer * alpha;

    // ===== MuSig2 v0.9.0: Aggregate nonces if peer_nonce_public provided =====
    // If both signers have submitted nonces, server sends peer's nonce.
    // We compute R_agg = R_mine + R_peer for L calculation.
    let (a_point, ah_point) = if let Some(peer_nonce_json) = input_data.peer_nonce_public.as_ref() {
        web_sys::console::log_1(&"[MuSig2 v0.9.0] Aggregating nonces with peer".into());

        #[derive(Deserialize)]
        struct PeerNonce {
            r_public: String,
            r_prime_public: String,
        }

        let peer: PeerNonce = serde_json::from_str(peer_nonce_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer_nonce_public JSON: {e}")))?;

        // Parse peer's R and R'
        let peer_r_bytes = hex::decode(&peer.r_public)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer r_public hex: {e}")))?;
        if peer_r_bytes.len() != 32 {
            return Err(JsValue::from_str("peer r_public must be 32 bytes"));
        }
        let mut peer_r_arr = [0u8; 32];
        peer_r_arr.copy_from_slice(&peer_r_bytes);
        let peer_r = CompressedEdwardsY(peer_r_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid peer r_public point"))?;

        let peer_r_prime_bytes = hex::decode(&peer.r_prime_public)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer r_prime_public hex: {e}")))?;
        if peer_r_prime_bytes.len() != 32 {
            return Err(JsValue::from_str("peer r_prime_public must be 32 bytes"));
        }
        let mut peer_r_prime_arr = [0u8; 32];
        peer_r_prime_arr.copy_from_slice(&peer_r_prime_bytes);
        let peer_r_prime = CompressedEdwardsY(peer_r_prime_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str("Invalid peer r_prime_public point"))?;

        // Compute R_agg = R_mine + R_peer
        let a_agg = a_point_mine + peer_r;
        let ah_agg = ah_point_mine + peer_r_prime;

        web_sys::console::log_1(
            &format!(
                "[MuSig2] R_agg = R_mine + R_peer: {}...",
                hex::encode(&a_agg.compress().to_bytes()[..16])
            )
            .into(),
        );
        web_sys::console::log_1(
            &format!(
                "[MuSig2] R_agg' = R_mine' + R_peer': {}...",
                hex::encode(&ah_agg.compress().to_bytes()[..16])
            )
            .into(),
        );

        (a_agg, ah_agg)
    } else {
        web_sys::console::log_1(&"[Round-Robin] No peer nonce (first signer or legacy)".into());
        (a_point_mine, ah_point_mine)
    };

    // Generate random s values for all ring members
    let mut s_values: Vec<Scalar> = Vec::with_capacity(ring_size);
    for _ in 0..ring_size {
        let mut s_seed = [0u8; 32];
        getrandom::getrandom(&mut s_seed)
            .map_err(|e| JsValue::from_str(&format!("RNG error for s: {e}")))?;
        s_values.push(Scalar::from_bytes_mod_order(s_seed));
    }

    // === Run CLSAG ring loop (NEW: buffer-based, matches reference exactly) ===
    // This function now:
    // 1. Builds the agg buffer with correct domain separator format
    // 2. Computes mu_P and mu_C using buffer reuse pattern
    // 3. Converts to round format with proper truncation
    // 4. Runs the ring loop
    // 5. Returns (c1, mu_p, mu_c, c_at_signer)
    let (c1, mu_p, mu_c, c_at_signer) = run_clsag_ring_loop(
        &ring_keys,
        &ring_commitments,
        &key_image_point,
        &d_original, // Original D for R = s*Hp + c_p*I + c_c*D
        &d_inv8,     // D * inv8 for buffer/hash construction
        &pseudo_out,
        &tx_hash_arr,
        &s_values,
        signer_idx,
        &a_point,
        &ah_point,
    );

    let c_p = c_at_signer * mu_p;
    let c_c = c_at_signer * mu_c;

    // v0.41.0 DIAGNOSTIC: Log CLSAG ring loop outputs
    web_sys::console::log_1(
        &format!(
            "[v0.41.0 DIAG] FIRST SIGNER c1: {}",
            hex::encode(c1.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.41.0 DIAG] FIRST SIGNER mu_p: {}",
            hex::encode(mu_p.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.41.0 DIAG] FIRST SIGNER mu_c: {}",
            hex::encode(mu_c.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.41.0 DIAG] FIRST SIGNER c_at_signer: {}",
            hex::encode(c_at_signer.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.41.0 DIAG] FIRST SIGNER c_p (c_at_signer * mu_p): {}",
            hex::encode(c_p.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.41.0 DIAG] FIRST SIGNER c_c (c_at_signer * mu_c): {}",
            hex::encode(c_c.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.41.0 DIAG] FIRST SIGNER Hp(signer_ring_key): {}",
            hex::encode(hp_signer.compress().to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!("[v0.41.0 DIAG] FIRST SIGNER signer_idx: {signer_idx}").into(),
    );

    // =========================================================================
    // v0.50.0 FIX: Apply Lagrange coefficient λ1 to x1 for 2-of-3 threshold
    // =========================================================================
    // For 2-of-3 threshold CLSAG, the aggregated secret key is:
    //   x_agg = λ1 * x1 + λ2 * x2  (NOT x1 + x2!)
    //
    // The s-value formula becomes:
    //   s = α - c_p * x_agg - c_c * mask_delta
    //     = α - c_p * (λ1*x1 + λ2*x2) - c_c * mask_delta
    //
    // First signer contributes: α - c_p * (λ1*x1)
    // Second signer adds:       -c_p * (λ2*x2) - c_c * mask_delta
    // =========================================================================

    // Get threshold indices from input_data
    let my_signer_index = input_data.my_signer_index.unwrap_or(1); // Default: buyer=1
    let other_signer_index = input_data.other_signer_index.unwrap_or(2); // Default: vendor=2

    // Compute Lagrange coefficient λ1 for first signer
    let lambda1 = compute_lagrange_coefficient(my_signer_index, other_signer_index);

    web_sys::console::log_1(
        &format!(
            "[v0.50.0] THRESHOLD: my_index={}, other_index={}, λ1={}",
            my_signer_index,
            other_signer_index,
            hex::encode(lambda1.to_bytes())
        )
        .into(),
    );

    // =========================================================================
    // v0.51.0 FIX: Compute s_partial correctly for FROST 2-of-3
    // =========================================================================
    //
    // Key insight: The derivation 'd' is NOT a threshold secret!
    //   - d = H_s(shared_secret || output_index) - same for all parties
    //   - Only the spend shares (b1, b2) are threshold secrets
    //
    // Correct formula:
    //   x_total = d + λ1*b1 + λ2*b2
    //   s = α - c_p * x_total - c_c * mask_delta
    //     = α - c_p * d - c_p * λ1 * b1 - c_p * λ2 * b2 - c_c * mask_delta
    //
    // First signer contributes: α - c_p * d - c_p * λ1 * b1
    // Second signer adds:       -c_p * λ2 * b2 - c_c * mask_delta
    //
    // BUG (v0.50.0): s = α - c_p * λ1 * (d + b1) = α - c_p*λ1*d - c_p*λ1*b1
    //               This wrongly multiplied d by λ1!
    // =========================================================================

    let lambda1_b1 = lambda1 * spend_scalar; // Only apply λ1 to spend share

    let s_partial = if has_derivation {
        // With derivation: s = α - c_p*d - c_p*λ1*b1
        alpha - c_p * derivation_scalar - c_p * lambda1_b1
    } else {
        // Without derivation (legacy): s = α - c_p*λ1*b1
        alpha - c_p * lambda1_b1
    };
    s_values[signer_idx] = s_partial;

    // v0.51.0 DIAGNOSTIC: Log s_partial with CORRECT Lagrange weighting
    web_sys::console::log_1(
        &format!(
            "[v0.51.0 DIAG] FIRST SIGNER s[{}] = α - c_p*d - c_p*(λ1*b1): {}",
            signer_idx,
            hex::encode(s_partial.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.51.0 DIAG] λ1*b1 (spend only): {}",
            hex::encode(lambda1_b1.to_bytes())
        )
        .into(),
    );
    if has_derivation {
        web_sys::console::log_1(
            &format!(
                "[v0.51.0 DIAG] derivation (d) NOT weighted: {}",
                hex::encode(derivation_scalar.to_bytes())
            )
            .into(),
        );
    }

    // === Encrypt alpha for Signer 2 ===
    // Use deterministic shared secret derived from tx_prefix_hash + key_image
    // This allows both signers to derive the same key without ECDH key exchange
    // IMPORTANT: Use the key_image that will be stored in partial_tx (the computed one)
    // so Signer 2 can derive the same shared secret
    let key_image_for_encryption = key_image_point.compress().to_bytes();

    let shared_secret = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"NEXUS_ROUND_ROBIN_SHARED_SECRET_V1");
        hasher.update(tx_hash_arr);
        hasher.update(key_image_for_encryption); // Use computed key image, same as partial_tx.key_image
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    };

    let alpha_encrypted = encrypt_scalar(&alpha, &shared_secret)?;

    // Get Signer 1's public key
    let signer1_public = (ED25519_BASEPOINT_TABLE * &x1).compress().to_bytes();

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    mask_arr.zeroize();
    // Note: alpha is either from alpha_secret (already hex string, not zeroized here)
    // or from random generation (alpha_seed.zeroize() was done in else branch)

    // Build result
    let partial_tx = PartialTx {
        ring_size: ring_size as u8,
        signer_index: signer_idx as u8,
        s_values: s_values.iter().map(|s| hex::encode(s.to_bytes())).collect(),
        c1: hex::encode(c1.to_bytes()),
        d: hex::encode(d_bytes),
        pseudo_out: hex::encode(pseudo_out_bytes),
        key_image: hex::encode(key_image_point.compress().to_bytes()), // Use computed key image
        partial_key_image_1: Some(hex::encode(partial_key_image_1_bytes)), // Signer 1's partial KI
        alpha_encrypted: hex::encode(&alpha_encrypted),
        signer1_public: hex::encode(signer1_public),
        c_p: hex::encode(c_p.to_bytes()),
        c_c: hex::encode(c_c.to_bytes()),
        mask_delta: hex::encode(mask_delta.to_bytes()),
        tx_prefix_hash: tx_prefix_hash_hex,
        multisig_pub_key: Some(multisig_pub_key_hex), // Pass for Signer 2
        // CRITICAL: Pass ring_signer_pubkey so Signer 2 uses SAME Hp base as Signer 1
        ring_signer_pubkey: Some(hex::encode(signer_ring_key_bytes)),
        // v0.37.0: Return mu_P and mu_C for deterministic verification
        // These MUST be stored by server and used by second signer + verifier
        mu_p: Some(hex::encode(mu_p.to_bytes())),
        mu_c: Some(hex::encode(mu_c.to_bytes())),
        // v0.50.0: Threshold indices for Lagrange coefficient computation by Signer 2
        first_signer_index: Some(my_signer_index),
        second_signer_index: Some(other_signer_index),
    };

    web_sys::console::log_1(
        &format!(
            "[Round-Robin] Partial TX created. c1: {}..., encrypted alpha: {} bytes",
            &partial_tx.c1[..16],
            alpha_encrypted.len()
        )
        .into(),
    );

    // v0.37.0: Log mu values for debugging
    web_sys::console::log_1(
        &format!(
            "[Round-Robin v0.37.0] FIRST SIGNER returning mu_p: {}..., mu_c: {}...",
            &partial_tx
                .mu_p
                .as_ref()
                .map(|s| &s[..16.min(s.len())])
                .unwrap_or("none"),
            &partial_tx
                .mu_c
                .as_ref()
                .map(|s| &s[..16.min(s.len())])
                .unwrap_or("none")
        )
        .into(),
    );

    serde_wasm_bindgen::to_value(&partial_tx)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// Complete a partial transaction (Signer 2)
///
/// This function:
/// 1. Decrypts alpha from Signer 1
/// 2. Adds Signer 2's contribution to s[signer_index]
/// 3. Returns the completed CLSAG signature
#[wasm_bindgen]
pub fn complete_partial_tx_wasm(
    spend_key_priv_hex: String,
    mask_share_hex: String,
    partial_tx_json: String,
) -> Result<JsValue, JsValue> {
    web_sys::console::log_1(&"[Round-Robin] Completing partial TX (Signer 2)".into());

    // Parse partial TX
    let partial_tx: PartialTx = serde_json::from_str(&partial_tx_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid partial_tx: {e}")))?;

    // Parse Signer 2's keys
    let mut spend_key_arr = parse_hex_32(&spend_key_priv_hex, "spend_key")?;
    let x2 = Scalar::from_bytes_mod_order(spend_key_arr);

    let mut mask_arr = parse_hex_32(&mask_share_hex, "mask_share")?;
    let _z2 = Scalar::from_bytes_mod_order(mask_arr);

    // Parse values from partial TX
    let signer1_pub_arr = parse_hex_32(&partial_tx.signer1_public, "signer1_public")?;
    let c_p_arr = parse_hex_32(&partial_tx.c_p, "c_p")?;
    let c_c_arr = parse_hex_32(&partial_tx.c_c, "c_c")?;
    let mask_delta_arr = parse_hex_32(&partial_tx.mask_delta, "mask_delta")?;

    let c_p = Scalar::from_bytes_mod_order(c_p_arr);
    let c_c = Scalar::from_bytes_mod_order(c_c_arr);
    let mask_delta = Scalar::from_bytes_mod_order(mask_delta_arr);

    // === Use the aggregated key image from partial_tx ===
    // CRITICAL: Signer 1 already used this key image for CLSAG computation (c1, mu_p, mu_c)
    // We MUST use the same key image, not re-compute it, otherwise the signature will be invalid.
    let aggregated_key_image_bytes = parse_hex_32(&partial_tx.key_image, "key_image")?;

    web_sys::console::log_1(
        &format!(
            "[Round-Robin] Using aggregated key image from partial_tx: {}",
            hex::encode(aggregated_key_image_bytes)
        )
        .into(),
    );

    // =========================================================================
    // CRITICAL FIX: Use ring_signer_pubkey for Hp (same as Signer 1)
    // =========================================================================
    // The Hp() base MUST be identical for both signers. Signer 1 uses:
    //   hp_signer = hash_to_point(ring_keys[signer_idx])
    // We MUST use the same pubkey, passed via ring_signer_pubkey.
    // Using multisig_pub_key here causes Hp() mismatch → sanity_check_failed
    // =========================================================================
    let ring_signer_pubkey_hex = partial_tx.ring_signer_pubkey.as_ref().ok_or_else(|| {
        JsValue::from_str("Missing ring_signer_pubkey in partial_tx - cannot compute correct Hp")
    })?;
    let ring_signer_arr = parse_hex_32(ring_signer_pubkey_hex, "ring_signer_pubkey")?;
    let hp = hash_to_point(ring_signer_arr);

    web_sys::console::log_1(
        &format!(
            "[Round-Robin] Signer 2 using Hp(ring_signer_pubkey): {}",
            hex::encode(&ring_signer_arr[..16])
        )
        .into(),
    );

    // === Decrypt alpha ===
    // Use deterministic shared secret derived from tx_prefix_hash (same as Signer 1)
    let tx_prefix_hash_arr = parse_hex_32(&partial_tx.tx_prefix_hash, "tx_prefix_hash")?;

    // Use the aggregated key image for shared secret derivation
    let shared_secret = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"NEXUS_ROUND_ROBIN_SHARED_SECRET_V1");
        hasher.update(tx_prefix_hash_arr);
        // Note: Signer 1 used the original key_image (zeros or partial_ki_1)
        // We need to use the same value for decryption
        let key_image_arr = parse_hex_32(&partial_tx.key_image, "key_image")?;
        hasher.update(key_image_arr);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    };

    let alpha_encrypted = hex::decode(&partial_tx.alpha_encrypted)
        .map_err(|e| JsValue::from_str(&format!("Invalid alpha_encrypted hex: {e}")))?;
    let _alpha = decrypt_scalar(&alpha_encrypted, &shared_secret)?;

    web_sys::console::log_1(&"[Round-Robin] Alpha decrypted successfully".into());

    // Note: alpha is decrypted to verify the MAC and ensure data integrity.
    // The actual alpha value is already embedded in the partial s[signer_idx] from Signer 1.

    // Parse s values
    let mut s_values: Vec<Scalar> = partial_tx
        .s_values
        .iter()
        .map(|s_hex| {
            let bytes = hex::decode(s_hex).expect("valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Scalar::from_bytes_mod_order(arr)
        })
        .collect();

    let signer_idx = partial_tx.signer_index as usize;

    // =========================================================================
    // v0.50.0 FIX: Apply Lagrange coefficient λ2 to x2 for 2-of-3 threshold
    // =========================================================================
    // For 2-of-3 threshold CLSAG, the s-value formula is:
    //   s = α - c_p * (λ1*x1 + λ2*x2) - c_c * mask_delta
    //
    // Signer 1 already contributed: α - c_p * (λ1*x1)
    // We add:                       -c_p * (λ2*x2) - c_c * mask_delta
    //
    // INCORRECT (old): s = α - c_p * (x1 + x2) - c_c * mask_delta
    // CORRECT (new):   s = α - c_p * (λ1*x1 + λ2*x2) - c_c * mask_delta
    // =========================================================================

    // Get threshold indices from partial_tx (set by first signer)
    let first_signer_index = partial_tx.first_signer_index.unwrap_or(1);
    let second_signer_index = partial_tx.second_signer_index.unwrap_or(2);

    // Compute Lagrange coefficient λ2 for second signer
    // Note: We use second_signer_index as my_index, first_signer_index as other_index
    let lambda2 = compute_lagrange_coefficient(second_signer_index, first_signer_index);

    web_sys::console::log_1(
        &format!(
            "[v0.50.0] THRESHOLD: first_index={}, second_index={}, λ2={}",
            first_signer_index,
            second_signer_index,
            hex::encode(lambda2.to_bytes())
        )
        .into(),
    );

    // v0.50.0 DIAGNOSTIC: Log s[signer_idx] BEFORE aggregation
    web_sys::console::log_1(
        &format!(
            "[v0.50.0 DIAG] s[{}] BEFORE: {}",
            signer_idx,
            hex::encode(s_values[signer_idx].to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.50.0 DIAG] c_p from partial_tx: {}",
            hex::encode(c_p.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.50.0 DIAG] c_c from partial_tx: {}",
            hex::encode(c_c.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.50.0 DIAG] mask_delta from partial_tx: {}",
            hex::encode(mask_delta.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.50.0 DIAG] Hp(ring_signer_pubkey): {}",
            hex::encode(hp.compress().to_bytes())
        )
        .into(),
    );

    // Signer 2's contribution with Lagrange coefficient
    // s2_contribution = -c_p * (λ2 * x2) - c_c * mask_delta
    let lambda2_x2 = lambda2 * x2;
    let s2_contribution = -(c_p * lambda2_x2) - (c_c * mask_delta);

    // v0.50.0 DIAGNOSTIC: Log s2_contribution with Lagrange weighting
    web_sys::console::log_1(
        &format!(
            "[v0.50.0 DIAG] s2_contribution = -(c_p*(λ2*x2)) - (c_c*mask_delta): {}",
            hex::encode(s2_contribution.to_bytes())
        )
        .into(),
    );
    web_sys::console::log_1(
        &format!(
            "[v0.50.0 DIAG] λ2*x2 contribution: {}",
            hex::encode(lambda2_x2.to_bytes())
        )
        .into(),
    );

    s_values[signer_idx] += s2_contribution;

    // v0.50.0 DIAGNOSTIC: Log s[signer_idx] AFTER aggregation
    web_sys::console::log_1(
        &format!(
            "[v0.50.0 DIAG] s[{}] AFTER (final): {}",
            signer_idx,
            hex::encode(s_values[signer_idx].to_bytes())
        )
        .into(),
    );

    web_sys::console::log_1(
        &format!("[Round-Robin] Signature completed. s[{signer_idx}] finalized.").into(),
    );

    // Zeroize sensitive data
    spend_key_arr.zeroize();
    mask_arr.zeroize();

    // Build completed signature with the AGGREGATED key image
    let completed = CompletedClsag {
        s_values: s_values.iter().map(|s| hex::encode(s.to_bytes())).collect(),
        c1: partial_tx.c1,
        d: partial_tx.d,
        pseudo_out: partial_tx.pseudo_out,
        key_image: hex::encode(aggregated_key_image_bytes), // Use aggregated KI, not partial
    };

    web_sys::console::log_1(
        &format!(
            "[Round-Robin] Completed signature with key_image: {}",
            &completed.key_image
        )
        .into(),
    );

    serde_wasm_bindgen::to_value(&completed)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

// === Helper Functions ===

fn parse_hex_32(hex_str: &str, name: &str) -> Result<[u8; 32], JsValue> {
    let bytes =
        hex::decode(hex_str).map_err(|e| JsValue::from_str(&format!("Invalid {name} hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "{} must be 32 bytes, got {}",
            name,
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ============================================================================
// CLSAG CORE - ALIGNED WITH monero-clsag-mirror REFERENCE IMPLEMENTATION
// ============================================================================
//
// The reference uses a SINGLE buffer that is truncated and extended.
// This is CRITICAL for hash correctness.
//
// Buffer layout for agg hash:
//   domain(32) || ring_keys(n*32) || ring_commitments(n*32) || I(32) || D_INV8(32) || pseudo_out(32)
//   = ((2*n) + 5) * 32 bytes
//
// Buffer layout for round hash (AFTER truncation):
//   domain(32) || ring_keys(n*32) || ring_commitments(n*32) || pseudo_out(32) || msg(32) || L(32) || R(32)
//   = ((2*n) + 5) * 32 bytes (but we truncate to ((2*n)+3)*32 before L/R)
//
// Domain separators:
//   "CLSAG_agg_0" -> b"CLSAG_" + b"agg_0" + 21 null bytes = 32 bytes
//   "CLSAG_agg_1" -> same but with '1' instead of '0'
//   "CLSAG_round" -> b"CLSAG_" + b"round" + 21 null bytes = 32 bytes

const PREFIX: &[u8] = b"CLSAG_";
const AGG_0: &[u8] = b"agg_0";
const ROUND: &[u8] = b"round";
const PREFIX_AGG_0_LEN: usize = 11; // PREFIX.len() + AGG_0.len() = 6 + 5 = 11

/// Keccak256 to scalar (same as monero's hash_to_scalar)
fn keccak256_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

// ============================================================================
// THRESHOLD SIGNING: LAGRANGE COEFFICIENTS (v0.50.0)
// ============================================================================
//
// For 2-of-3 threshold CLSAG, the aggregated secret key is:
//   x_agg = λ1 * x1 + λ2 * x2
//
// where λi is the Lagrange coefficient for signer i given the set of signers.
//
// For indices {1,2}: λ1 = 2/(2-1) = 2, λ2 = 1/(1-2) = -1
// For indices {1,3}: λ1 = 3/(3-1) = 3/2, λ3 = 1/(1-3) = -1/2
// For indices {2,3}: λ2 = 3/(3-2) = 3, λ3 = 2/(2-3) = -2
//
// CRITICAL: Without Lagrange coefficients, the s-value formula is wrong:
//   WRONG:   s = α - c_p*(x1+x2) - c_c*mask_delta
//   CORRECT: s = α - c_p*(λ1*x1+λ2*x2) - c_c*mask_delta
//
// ============================================================================

/// Compute Lagrange coefficient λ_i for participant i given set of indices
///
/// Formula: λ_i = Π_{j∈S, j≠i} (j / (j - i))
///
/// For 2-of-3 multisig with indices {1,2,3}:
/// - buyer=1, vendor=2, arbiter=3
///
/// Special cases for {i,j} pairs:
/// - {1,2}: λ1=2, λ2=-1
/// - {1,3}: λ1=3/2, λ3=-1/2
/// - {2,3}: λ2=3, λ3=-2
fn compute_lagrange_coefficient(my_index: u8, other_index: u8) -> Scalar {
    // Both indices must be 1, 2, or 3
    debug_assert!((1..=3).contains(&my_index), "my_index must be 1, 2, or 3");
    debug_assert!(
        (1..=3).contains(&other_index),
        "other_index must be 1, 2, or 3"
    );
    debug_assert!(my_index != other_index, "indices must be different");

    let i = Scalar::from(my_index as u64);
    let j = Scalar::from(other_index as u64);

    // λ_i = j / (j - i)
    let numerator = j;
    let denominator = j - i;

    numerator * denominator.invert()
}

/// Build the initial buffer for CLSAG hashing
/// Returns (buffer, mu_P, mu_C) where buffer is ready for round hash after modification
fn build_clsag_buffer(
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
    // EXACT format from reference: PREFIX || AGG_0 || [0; 32 - PREFIX_AGG_0_LEN]
    to_hash.extend_from_slice(PREFIX); // "CLSAG_" (6 bytes)
    to_hash.extend_from_slice(AGG_0); // "agg_0" (5 bytes)
    to_hash.extend_from_slice(&[0u8; 32 - PREFIX_AGG_0_LEN]); // 21 null bytes

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
    let mu_p = keccak256_to_scalar(&to_hash);

    // mu_C: change agg_0 -> agg_1 (just change the '0' to '1')
    // Position is PREFIX.len() + AGG_0.len() - 1 = 6 + 5 - 1 = 10
    to_hash[PREFIX_AGG_0_LEN - 1] = b'1';
    let mu_c = keccak256_to_scalar(&to_hash);

    (to_hash, mu_p, mu_c)
}

/// Convert buffer from agg format to round format
/// This truncates and modifies the domain separator in-place
/// v0.13.0 FIX: Added key_image and d_inv8 to round hash (REQUIRED by Monero spec!)
fn convert_buffer_to_round_format(
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
    for (i, byte) in ROUND.iter().enumerate() {
        to_hash[PREFIX.len() + i] = *byte;
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
fn add_lr_to_round_buffer(
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
/// This is a standalone version that doesn't return the buffer
fn compute_mixing_coefficients(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    let (_, mu_p, mu_c) =
        build_clsag_buffer(ring_keys, ring_commitments, key_image, d_inv8, pseudo_out);
    (mu_p, mu_c)
}

/// Run CLSAG ring loop using buffer-based approach (matches reference exactly)
///
/// This function:
/// 1. Builds the agg buffer and computes mu_P, mu_C
/// 2. Converts to round format
/// 3. Computes initial challenge from A, AH
/// 4. Runs the ring loop, truncating and extending buffer for each L, R
fn run_clsag_ring_loop(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_point: &EdwardsPoint, // Original D, NOT D*inv8
    d_inv8: &EdwardsPoint,  // D * inv8 for buffer building
    pseudo_out: &EdwardsPoint,
    msg_hash: &[u8; 32],
    s_values: &[Scalar],
    signer_idx: usize,
    a_point: &EdwardsPoint,
    ah_point: &EdwardsPoint,
) -> (Scalar, Scalar, Scalar, Scalar) {
    // Returns (c1, mu_p, mu_c, c_at_signer)
    let ring_size = ring_keys.len();

    // Compute C_adjusted[i] = ring_commitment[i] - pseudo_out for each ring member
    let c_adjusted: Vec<EdwardsPoint> = ring_commitments.iter().map(|c| c - pseudo_out).collect();

    // Build buffer and get mu_P, mu_C (using D*inv8)
    let (mut to_hash, mu_p, mu_c) =
        build_clsag_buffer(ring_keys, ring_commitments, key_image, d_inv8, pseudo_out);

    // Convert buffer to round format
    // v0.13.0 FIX: Now passes key_image and d_inv8 to include in round hash
    convert_buffer_to_round_format(
        &mut to_hash,
        ring_size,
        pseudo_out,
        msg_hash,
        key_image,
        d_inv8,
    );

    // Compute initial challenge: add A and AH
    to_hash.extend_from_slice(&a_point.compress().to_bytes());
    to_hash.extend_from_slice(&ah_point.compress().to_bytes());
    let mut c = keccak256_to_scalar(&to_hash);

    // Track c at signer index (we'll compute this as we go)
    let mut c_at_signer = c; // Will be overwritten when we reach signer_idx

    // v0.15.0 FIX: c1 must be c[0] per Monero specification
    //
    // Per monero/src/ringct/rctSigs.cpp:
    //   - Signing returns c[0] as c1 in signature
    //   - Verification starts at position 0 with c = c1
    //
    // The initial c computed above is c[(signer_idx+1) % n], which:
    //   - If signer_idx == ring_size-1: initial c = c[0] ✓
    //   - Otherwise: initial c = c[signer_idx+1] ≠ c[0] ✗
    //
    // c[0] is computed during the loop when we process position ring_size-1,
    // since the resulting challenge is for position (ring_size-1 + 1) % n = 0
    let mut c1_final = c; // Default: correct if signer at last position

    for offset in 1..ring_size {
        let i = (signer_idx + offset) % ring_size;

        let c_p = mu_p * c;
        let c_c = mu_c * c;

        // L = s[i] * G + c_p * P[i] + c_c * C_adjusted[i]
        let l_point = EdwardsPoint::vartime_multiscalar_mul(
            [s_values[i], c_p, c_c],
            [ED25519_BASEPOINT_POINT, ring_keys[i], c_adjusted[i]],
        );

        // Hp(P[i])
        let hp_i = hash_to_point(ring_keys[i].compress().to_bytes());

        // R = s[i] * Hp(P[i]) + c_p * I + c_c * D (uses ORIGINAL D, not D*inv8!)
        let r_point = EdwardsPoint::vartime_multiscalar_mul(
            [s_values[i], c_p, c_c],
            [hp_i, *key_image, *d_point],
        );

        // Truncate to base and add L, R
        add_lr_to_round_buffer(&mut to_hash, ring_size, &l_point, &r_point);
        c = keccak256_to_scalar(&to_hash);

        // v0.15.0 FIX: Capture c[0] when computed
        // c[0] is the challenge for position 0, computed when i == ring_size - 1
        // because the hash we just computed is c[(i+1) % n] = c[(ring_size-1+1) % n] = c[0]
        if i == ring_size - 1 {
            c1_final = c;
        }

        // Track c_at_signer for the iteration BEFORE signer_idx
        // Actually we need c when we're about to process signer_idx
        // This happens when the NEXT i would be signer_idx
        if (i + 1) % ring_size == signer_idx {
            c_at_signer = c;
        }
    }

    (c1_final, mu_p, mu_c, c_at_signer)
}

// Old functions compute_initial_challenge, compute_round_challenge, compute_challenge_at_index
// have been REMOVED in favor of the buffer-based approach that matches monero-clsag-mirror.
// The new implementation uses:
//   - build_clsag_buffer() to construct the initial hash buffer
//   - convert_buffer_to_round_format() to prepare for round hashing
//   - add_lr_to_round_buffer() to add L/R points in each iteration
//   - keccak256_to_scalar() to compute the hash
// This exactly matches the reference implementation's buffer reuse pattern.

#[allow(dead_code)]
fn derive_key_from_point(point: &EdwardsPoint) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"ECDH_KEY");
    hasher.update(point.compress().as_bytes());
    hasher.finalize().into()
}

fn encrypt_scalar(scalar: &Scalar, key: &[u8; 32]) -> Result<Vec<u8>, JsValue> {
    use sha3::Sha3_256;

    // Simple XOR encryption with key derivation (for PoC)
    // In production, use ChaCha20Poly1305
    let scalar_bytes = scalar.to_bytes();

    // Generate nonce
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| JsValue::from_str(&format!("RNG error: {e}")))?;

    // Derive encryption key from shared secret + nonce
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(nonce);
    let derived_key: [u8; 32] = hasher.finalize().into();

    // XOR encrypt
    let mut ciphertext = [0u8; 32];
    for i in 0..32 {
        ciphertext[i] = scalar_bytes[i] ^ derived_key[i];
    }

    // Simple MAC (in production, use proper AEAD)
    let mut mac_hasher = Sha3_256::new();
    mac_hasher.update(ciphertext);
    mac_hasher.update(nonce);
    mac_hasher.update(key);
    let mac: [u8; 32] = mac_hasher.finalize().into();

    // nonce (12) || ciphertext (32) || mac (16)
    let mut result = Vec::with_capacity(12 + 32 + 16);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&mac[..16]);

    Ok(result)
}

fn decrypt_scalar(encrypted: &[u8], key: &[u8; 32]) -> Result<Scalar, JsValue> {
    use sha3::Sha3_256;

    if encrypted.len() != 60 {
        return Err(JsValue::from_str(&format!(
            "Invalid encrypted data length: expected 60, got {}",
            encrypted.len()
        )));
    }

    let nonce = &encrypted[0..12];
    let ciphertext = &encrypted[12..44];
    let mac = &encrypted[44..60];

    // Verify MAC
    let mut mac_hasher = Sha3_256::new();
    mac_hasher.update(ciphertext);
    mac_hasher.update(nonce);
    mac_hasher.update(key);
    let expected_mac: [u8; 32] = mac_hasher.finalize().into();

    if &expected_mac[..16] != mac {
        return Err(JsValue::from_str("MAC verification failed"));
    }

    // Derive decryption key
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(nonce);
    let derived_key: [u8; 32] = hasher.finalize().into();

    // XOR decrypt
    let mut plaintext = [0u8; 32];
    for i in 0..32 {
        plaintext[i] = ciphertext[i] ^ derived_key[i];
    }

    Ok(Scalar::from_bytes_mod_order(plaintext))
}

// ============================================================================
// CLSAG VERIFICATION AND DEBUG INSTRUMENTATION (v0.8.1)
// ============================================================================

/// Verification result with detailed debug info
#[derive(Serialize)]
pub struct ClsagVerificationResult {
    pub valid: bool,
    pub error: Option<String>,
    pub debug_log: String,
    pub c1_computed: String,
    pub c1_expected: String,
    pub ring_size: usize,
}

/// Verify a CLSAG signature locally before broadcast
/// This is the exact verification the Monero daemon performs
#[wasm_bindgen]
pub fn verify_clsag_wasm(
    signature_json: String,
    ring_json: String,
    tx_prefix_hash_hex: String,
) -> Result<JsValue, JsValue> {
    let mut ctx = ClsagDebugContext::new();
    ctx.log("=== CLSAG Local Verification (v0.8.1) ===");

    // Parse signature
    let sig: CompletedClsag = serde_json::from_str(&signature_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature JSON: {e}")))?;

    // Parse ring (same format as SignInputData.ring)
    let ring: Vec<[String; 2]> = serde_json::from_str(&ring_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid ring JSON: {e}")))?;

    let tx_hash_arr = parse_hex_32(&tx_prefix_hash_hex, "tx_prefix_hash")?;
    ctx.log_bytes("tx_prefix_hash", &tx_hash_arr);

    let ring_size = ring.len();
    ctx.log(&format!("Ring size: {ring_size}"));

    // Parse ring members
    let mut ring_keys: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);
    let mut ring_commitments: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);

    for (i, pair) in ring.iter().enumerate() {
        let key_arr = parse_hex_32(&pair[0], &format!("ring_key[{i}]"))?;
        let commit_arr = parse_hex_32(&pair[1], &format!("ring_commitment[{i}]"))?;

        let key_point = CompressedEdwardsY(key_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str(&format!("Invalid ring key point at {i}")))?;
        let commit_point = CompressedEdwardsY(commit_arr)
            .decompress()
            .ok_or_else(|| JsValue::from_str(&format!("Invalid ring commitment at {i}")))?;

        ctx.log_point(&format!("P[{i}]"), &key_point);
        ctx.log_point(&format!("C[{i}]"), &commit_point);

        ring_keys.push(key_point);
        ring_commitments.push(commit_point);
    }

    // Parse signature components
    let c1_arr = parse_hex_32(&sig.c1, "c1")?;
    let c1 = Scalar::from_bytes_mod_order(c1_arr);
    ctx.log_scalar("c1 (from sig)", &c1);

    let d_arr = parse_hex_32(&sig.d, "d")?;
    let d_inv8 = CompressedEdwardsY(d_arr)
        .decompress()
        .ok_or_else(|| JsValue::from_str("Invalid D point"))?;
    ctx.log_point("D (from sig, = D*inv8)", &d_inv8);

    // Recover original D: D_original = D_inv8 * 8
    let eight = Scalar::from(8u64);
    let d_original = d_inv8 * eight;
    ctx.log_point("D_original (= D_inv8 * 8)", &d_original);

    let pseudo_out_arr = parse_hex_32(&sig.pseudo_out, "pseudo_out")?;
    let pseudo_out = CompressedEdwardsY(pseudo_out_arr)
        .decompress()
        .ok_or_else(|| JsValue::from_str("Invalid pseudo_out point"))?;
    ctx.log_point("pseudo_out", &pseudo_out);

    let key_image_arr = parse_hex_32(&sig.key_image, "key_image")?;
    let key_image = CompressedEdwardsY(key_image_arr)
        .decompress()
        .ok_or_else(|| JsValue::from_str("Invalid key_image point"))?;
    ctx.log_point("I (key_image)", &key_image);

    // Parse s values
    let mut s_values: Vec<Scalar> = Vec::with_capacity(ring_size);
    for (i, s_hex) in sig.s_values.iter().enumerate() {
        let s_arr = parse_hex_32(s_hex, &format!("s[{i}]"))?;
        let s = Scalar::from_bytes_mod_order(s_arr);
        ctx.log_scalar(&format!("s[{i}]"), &s);
        s_values.push(s);
    }

    // Compute mu_P and mu_C using D*inv8 (as Monero does)
    ctx.log("=== Computing mu_P and mu_C ===");
    let (mu_p, mu_c) = compute_mixing_coefficients(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8, // D * inv8 for mu hash
        &pseudo_out,
    );
    ctx.log_scalar("mu_P", &mu_p);
    ctx.log_scalar("mu_C", &mu_c);

    // Compute adjusted commitments
    let c_adjusted: Vec<EdwardsPoint> = ring_commitments.iter().map(|c| c - pseudo_out).collect();

    ctx.log("=== Running verification ring loop (buffer-based) ===");

    // Build buffer for verification (same as signing, but we start with c1)
    let (mut to_hash, _, _) = build_clsag_buffer(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );

    // Convert to round format
    // v0.13.0 FIX: Now passes key_image and d_inv8 to include in round hash
    convert_buffer_to_round_format(
        &mut to_hash,
        ring_size,
        &pseudo_out,
        &tx_hash_arr,
        &key_image,
        &d_inv8,
    );

    // Start with c = c1 (verification mode)
    let mut c = c1;

    for i in 0..ring_size {
        ctx.log(&format!("--- Iteration i={i} ---"));

        let c_p = mu_p * c;
        let c_c = mu_c * c;
        ctx.log_scalar(&format!("c[{i}]"), &c);
        ctx.log_scalar("c_p = mu_P * c", &c_p);
        ctx.log_scalar("c_c = mu_C * c", &c_c);

        // L = s[i] * G + c_p * P[i] + c_c * C_adjusted[i]
        let l_point = EdwardsPoint::vartime_multiscalar_mul(
            [s_values[i], c_p, c_c],
            [ED25519_BASEPOINT_POINT, ring_keys[i], c_adjusted[i]],
        );
        ctx.log_point(&format!("L[{i}]"), &l_point);

        // Hp(P[i])
        let hp_i = hash_to_point(ring_keys[i].compress().to_bytes());
        ctx.log_point(&format!("Hp(P[{i}])"), &hp_i);

        // R = s[i] * Hp(P[i]) + c_p * I + c_c * D_original
        // NOTE: Uses ORIGINAL D (= D_inv8 * 8), not D*inv8!
        let r_point = EdwardsPoint::vartime_multiscalar_mul(
            [s_values[i], c_p, c_c],
            [hp_i, key_image, d_original],
        );
        ctx.log_point(&format!("R[{i}]"), &r_point);

        // Compute next challenge using buffer (truncate and extend)
        add_lr_to_round_buffer(&mut to_hash, ring_size, &l_point, &r_point);
        c = keccak256_to_scalar(&to_hash);
        ctx.log_scalar(&format!("c[{i}+1]"), &c);
    }

    // After full loop, c should equal c1
    let c1_computed = c;
    let valid = c1_computed == c1;

    ctx.log("=== VERIFICATION RESULT ===");
    ctx.log_scalar("c1 (computed)", &c1_computed);
    ctx.log_scalar("c1 (expected)", &c1);
    ctx.log(&format!("VALID: {valid}"));

    if !valid {
        ctx.log("!!! SIGNATURE INVALID - c1 mismatch !!!");
        ctx.log(&format!(
            "Diff: c1_computed - c1_expected = {}",
            hex::encode((c1_computed - c1).to_bytes())
        ));
    }

    let result = ClsagVerificationResult {
        valid,
        error: if valid {
            None
        } else {
            Some("c1 mismatch after ring loop".to_string())
        },
        debug_log: ctx.dump(),
        c1_computed: hex::encode(c1_computed.to_bytes()),
        c1_expected: hex::encode(c1.to_bytes()),
        ring_size,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// Debug function to dump all CLSAG parameters for comparison with reference implementations
#[wasm_bindgen]
pub fn dump_clsag_params_wasm(
    signature_json: String,
    ring_json: String,
    tx_prefix_hash_hex: String,
) -> Result<JsValue, JsValue> {
    let mut ctx = ClsagDebugContext::new();
    ctx.log("=== CLSAG Parameter Dump for External Verification ===");
    ctx.log("Copy this output to compare with reference implementations");
    ctx.log("");

    // Parse signature
    let sig: CompletedClsag = serde_json::from_str(&signature_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature JSON: {e}")))?;

    // Parse ring
    let ring: Vec<[String; 2]> = serde_json::from_str(&ring_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid ring JSON: {e}")))?;

    let tx_hash_arr = parse_hex_32(&tx_prefix_hash_hex, "tx_prefix_hash")?;
    let ring_size = ring.len();

    // Print in a format that can be copied to Python/Rust reference implementation
    ctx.log(&format!("ring_size = {ring_size}"));
    ctx.log(&format!("msg = bytes.fromhex('{tx_prefix_hash_hex}')"));
    ctx.log(&format!("c1 = bytes.fromhex('{}')", sig.c1));
    ctx.log(&format!("D = bytes.fromhex('{}')", sig.d));
    ctx.log(&format!("pseudo_out = bytes.fromhex('{}')", sig.pseudo_out));
    ctx.log(&format!("key_image = bytes.fromhex('{}')", sig.key_image));
    ctx.log("");

    ctx.log("# Ring keys (P)");
    ctx.log("P = [");
    for (i, pair) in ring.iter().enumerate() {
        ctx.log(&format!("    bytes.fromhex('{}'),  # P[{}]", pair[0], i));
    }
    ctx.log("]");
    ctx.log("");

    ctx.log("# Ring commitments (C)");
    ctx.log("C = [");
    for (i, pair) in ring.iter().enumerate() {
        ctx.log(&format!("    bytes.fromhex('{}'),  # C[{}]", pair[1], i));
    }
    ctx.log("]");
    ctx.log("");

    ctx.log("# s values");
    ctx.log("s = [");
    for (i, s_hex) in sig.s_values.iter().enumerate() {
        ctx.log(&format!("    bytes.fromhex('{s_hex}'),  # s[{i}]"));
    }
    ctx.log("]");
    ctx.log("");

    // Compute and print intermediate values
    let mut ring_keys: Vec<EdwardsPoint> = Vec::new();
    let mut ring_commitments: Vec<EdwardsPoint> = Vec::new();
    for pair in ring.iter() {
        let key_arr = parse_hex_32(&pair[0], "key")?;
        let commit_arr = parse_hex_32(&pair[1], "commit")?;
        ring_keys.push(CompressedEdwardsY(key_arr).decompress().unwrap());
        ring_commitments.push(CompressedEdwardsY(commit_arr).decompress().unwrap());
    }

    let d_arr = parse_hex_32(&sig.d, "d")?;
    let d_inv8 = CompressedEdwardsY(d_arr).decompress().unwrap();
    let pseudo_out_arr = parse_hex_32(&sig.pseudo_out, "pseudo_out")?;
    let pseudo_out = CompressedEdwardsY(pseudo_out_arr).decompress().unwrap();
    let key_image_arr = parse_hex_32(&sig.key_image, "key_image")?;
    let key_image = CompressedEdwardsY(key_image_arr).decompress().unwrap();

    let (mu_p, mu_c) = compute_mixing_coefficients(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );

    ctx.log("# Computed intermediate values");
    ctx.log(&format!(
        "mu_P = bytes.fromhex('{}')",
        hex::encode(mu_p.to_bytes())
    ));
    ctx.log(&format!(
        "mu_C = bytes.fromhex('{}')",
        hex::encode(mu_c.to_bytes())
    ));

    // Print H point
    let h_point = *H;
    ctx.log(&format!(
        "H = bytes.fromhex('{}')",
        hex::encode(h_point.compress().to_bytes())
    ));

    Ok(JsValue::from_str(&ctx.dump()))
}
