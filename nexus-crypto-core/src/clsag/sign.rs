//! CLSAG signature generation for 2-of-3 FROST multisig.
//!
//! This implements the two-phase CLSAG signing protocol:
//! 1. First signer creates partial signature with fake s-values
//! 2. Second signer completes the signature at the real index
//!
//! ## Algorithm Overview
//!
//! **Signer 1 (Partial):**
//! ```text
//! 1. Compute effective spend key: x_eff = derivation + λ₁ * s₁
//! 2. Compute partial key image: pKI₁ = x_eff * Hp(P)
//! 3. Compute D point: D = (mask_delta * Hp(P)) / 8
//! 4. Compute mixing coefficients: (μ_P, μ_C)
//! 5. Generate fake s-values for non-real indices
//! 6. Ring loop to compute c1
//! 7. Compute s[l]_partial = α₁ - c * x_eff
//! ```
//!
//! **Signer 2 (Complete):**
//! ```text
//! 1. Compute signer 2 contribution: x_eff₂ = λ₂ * s₂
//! 2. Compute partial key image: pKI₂ = x_eff₂ * Hp(P)
//! 3. Aggregate key image: KI = pKI₁ + pKI₂
//! 4. Reuse stored μ values from Signer 1
//! 5. Complete s[l] = s[l]_partial + (α₂ - c * x_eff₂)
//! 6. Verify ring loop matches c1
//! ```

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    Scalar,
};
use monero_generators::hash_to_point;
use zeroize::Zeroize;

use super::constants::H_BYTES;
use super::hash::{compute_mixing_coefficients, compute_round_hash};
use super::types::ClsagSignature;
use crate::types::errors::{CryptoError, CryptoResult};

/// Partial CLSAG signature from first signer.
///
/// Contains all state needed for the second signer to complete the signature.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct PartialClsagSignature {
    /// Partial s-values for all ring members (hex, 32 bytes each).
    /// Only s[l] is partial; others are final fake values.
    #[zeroize(skip)]
    pub s_values: Vec<String>,

    /// Initial challenge c1 (hex, 32 bytes).
    #[zeroize(skip)]
    pub c1: String,

    /// D point (hex, 32 bytes compressed).
    #[zeroize(skip)]
    pub d: String,

    /// Pseudo-output commitment (hex, 32 bytes compressed).
    #[zeroize(skip)]
    pub pseudo_out: String,

    /// Partial key image from signer 1 (hex, 32 bytes).
    #[zeroize(skip)]
    pub partial_key_image_1: String,

    /// Mixing coefficient μ_P (hex, 32 bytes).
    /// CRITICAL: Must be reused by signer 2.
    #[zeroize(skip)]
    pub mu_p: String,

    /// Mixing coefficient μ_C (hex, 32 bytes).
    /// CRITICAL: Must be reused by signer 2.
    #[zeroize(skip)]
    pub mu_c: String,

    /// Index of the real spend in the ring.
    #[zeroize(skip)]
    pub real_index: usize,
}

/// Create partial CLSAG signature (first signer).
///
/// This function implements the first phase of 2-of-3 FROST CLSAG signing.
///
/// # Arguments
/// * `spend_share_1_hex` - First signer's private spend share (hex, 32 bytes)
/// * `lagrange_1_hex` - Lagrange coefficient for signer 1 (hex, 32 bytes)
/// * `derivation_scalar_hex` - Output derivation scalar Hs(8*a*R || idx) (hex, 32 bytes)
/// * `partial_key_image_1_hex` - Partial key image from signer 1 (hex, 32 bytes)
/// * `alpha_1_hex` - Random nonce for signer 1 (hex, 32 bytes)
/// * `mask_delta` - Mask delta (output_mask - sum_input_masks)
/// * `ring_keys_bytes` - Public keys in the ring (each 32 bytes)
/// * `ring_commitments_bytes` - Pedersen commitments in the ring (each 32 bytes)
/// * `tx_prefix_hash` - Transaction prefix hash (32 bytes)
/// * `real_index` - Index of the real output being spent
/// * `output_amount` - Amount of the output being spent (atomic units)
///
/// # Returns
/// Partial signature to be sent to second signer
///
/// # Errors
/// - `InvalidLength` if any input has incorrect length
/// - `HexDecodeFailed` if hex parsing fails
/// - `SignerIndexOutOfBounds` if real_index >= ring size
/// - `RingSizeTooSmall` if ring has < 2 members
/// - `PartialSignatureFailed` for other signing errors
#[allow(clippy::too_many_arguments)]
pub fn sign_clsag_partial(
    spend_share_1_hex: &str,
    lagrange_1_hex: &str,
    derivation_scalar_hex: &str,
    partial_key_image_1_hex: &str,
    alpha_1_hex: &str,
    mask_delta: u64,
    ring_keys_bytes: &[[u8; 32]],
    ring_commitments_bytes: &[[u8; 32]],
    tx_prefix_hash: [u8; 32],
    real_index: usize,
    output_amount: u64,
) -> CryptoResult<PartialClsagSignature> {
    let ring_size = ring_keys_bytes.len();

    // Validate inputs
    if ring_size < 2 {
        return Err(CryptoError::RingSizeTooSmall {
            actual: ring_size,
            minimum: 2,
        });
    }

    if real_index >= ring_size {
        return Err(CryptoError::SignerIndexOutOfBounds {
            index: real_index,
            ring_size,
        });
    }

    // Parse spend share 1
    let spend_bytes = hex::decode(spend_share_1_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("spend_share_1: {}", e)))?;
    if spend_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "spend_share_1".into(),
            expected: 32,
            actual: spend_bytes.len(),
        });
    }
    let mut spend_arr = [0u8; 32];
    spend_arr.copy_from_slice(&spend_bytes);
    let spend_1 = Scalar::from_bytes_mod_order(spend_arr);

    // Parse lagrange 1
    let lambda_bytes = hex::decode(lagrange_1_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("lagrange_1: {}", e)))?;
    if lambda_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "lagrange_1".into(),
            expected: 32,
            actual: lambda_bytes.len(),
        });
    }
    let mut lambda_arr = [0u8; 32];
    lambda_arr.copy_from_slice(&lambda_bytes);
    let lambda_1 = Scalar::from_bytes_mod_order(lambda_arr);

    // Parse derivation scalar
    let deriv_bytes = hex::decode(derivation_scalar_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("derivation_scalar: {}", e)))?;
    if deriv_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "derivation_scalar".into(),
            expected: 32,
            actual: deriv_bytes.len(),
        });
    }
    let mut deriv_arr = [0u8; 32];
    deriv_arr.copy_from_slice(&deriv_bytes);
    let derivation = Scalar::from_bytes_mod_order(deriv_arr);

    // Parse partial key image 1
    let pki1_bytes = hex::decode(partial_key_image_1_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("partial_key_image_1: {}", e)))?;
    if pki1_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "partial_key_image_1".into(),
            expected: 32,
            actual: pki1_bytes.len(),
        });
    }
    let mut pki1_arr = [0u8; 32];
    pki1_arr.copy_from_slice(&pki1_bytes);
    let pki1_point = CompressedEdwardsY(pki1_arr).decompress().ok_or_else(|| {
        CryptoError::InvalidPublicKey("partial_key_image_1 decompression failed".into())
    })?;

    // Parse alpha 1
    let alpha_bytes = hex::decode(alpha_1_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("alpha_1: {}", e)))?;
    if alpha_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "alpha_1".into(),
            expected: 32,
            actual: alpha_bytes.len(),
        });
    }
    let mut alpha_arr = [0u8; 32];
    alpha_arr.copy_from_slice(&alpha_bytes);
    let alpha_1 = Scalar::from_bytes_mod_order(alpha_arr);

    // Parse ring keys and commitments
    let mut ring_keys = Vec::with_capacity(ring_size);
    let mut ring_commitments = Vec::with_capacity(ring_size);

    for (i, key_bytes) in ring_keys_bytes.iter().enumerate() {
        let key = CompressedEdwardsY(*key_bytes).decompress().ok_or_else(|| {
            CryptoError::InvalidPublicKey(format!("ring_key[{}] decompression failed", i))
        })?;
        ring_keys.push(key);
    }

    for (i, commit_bytes) in ring_commitments_bytes.iter().enumerate() {
        let commit = CompressedEdwardsY(*commit_bytes)
            .decompress()
            .ok_or_else(|| {
                CryptoError::InvalidPublicKey(format!(
                    "ring_commitment[{}] decompression failed",
                    i
                ))
            })?;
        ring_commitments.push(commit);
    }

    // Compute effective spend key: x_eff = derivation + λ₁ * s₁
    let weighted_spend = lambda_1 * spend_1;
    let x_eff_1 = derivation + weighted_spend;

    // Compute pseudo-output: pseudo_out = amount * H + output_mask * G
    let h_point = CompressedEdwardsY(H_BYTES)
        .decompress()
        .ok_or_else(|| CryptoError::InternalError("H generator decompression failed".into()))?;

    let amount_scalar = Scalar::from(output_amount);
    let mask_delta_scalar = Scalar::from(mask_delta);
    let pseudo_out = &amount_scalar * h_point + &mask_delta_scalar * ED25519_BASEPOINT_TABLE;
    let pseudo_out_bytes = pseudo_out.compress().to_bytes();

    // Compute D point: D = (mask_delta * Hp(P_real)) / 8
    let p_real = ring_keys[real_index];
    let hp_real = hash_to_point(p_real.compress().to_bytes());

    let eight_inv = Scalar::from(8u64).invert();
    let d_inv8 = mask_delta_scalar * hp_real * eight_inv;
    let d_inv8_bytes = d_inv8.compress().to_bytes();

    // Compute mixing coefficients (MUST be stored for signer 2)
    let (mu_p, mu_c) = compute_mixing_coefficients(
        &ring_keys,
        &ring_commitments,
        &pki1_point, // Using partial KI from signer 1 (will be replaced later)
        &d_inv8,
        &pseudo_out,
    );

    // Precompute Hp(P[i]) for all ring members
    let mut hp_values: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);
    for key in &ring_keys {
        hp_values.push(hash_to_point(key.compress().to_bytes()));
    }

    // Generate fake s-values for non-real indices
    let mut s_values_scalar = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        if i == real_index {
            // Placeholder, will be computed at the end
            s_values_scalar.push(Scalar::from(0u64));
        } else {
            // Random fake s-value
            let mut s_bytes = [0u8; 32];
            getrandom::getrandom(&mut s_bytes)
                .map_err(|e| CryptoError::PartialSignatureFailed(format!("RNG error: {}", e)))?;
            s_values_scalar.push(Scalar::from_bytes_mod_order(s_bytes));
        }
    }

    // Ring loop to compute c1
    // Start from (real_index + 1) and loop around
    let mut c = Scalar::from(0u64); // Will be set to c_l after loop

    // L_l and R_l computations (at real index)
    let l_l = &alpha_1 * ED25519_BASEPOINT_TABLE;
    let r_l = alpha_1 * hp_values[real_index];

    // Compute c_{l+1}
    c = compute_round_hash(
        &ring_keys,
        &ring_commitments,
        &pseudo_out,
        &tx_prefix_hash,
        &pki1_point,
        &d_inv8,
        &l_l,
        &r_l,
    );

    // D_original = D_inv8 * 8
    let d_original = d_inv8 * Scalar::from(8u64);

    // Loop through remaining indices (CLSAG order: l+1, l+2, ..., n-1, 0, 1, ..., l-1)
    for offset in 1..ring_size {
        let idx = (real_index + offset) % ring_size;
        let s_i = s_values_scalar[idx];
        let p_i = ring_keys[idx];
        let c_i = ring_commitments[idx];
        let hp_i = hp_values[idx];

        let c_p = mu_p * c;
        let c_c = mu_c * c;

        // L[idx] = s*G + c_p*P[idx] + c_c*(C[idx] - pseudo_out)
        let c_adjusted = c_i - pseudo_out;
        let l_point = &s_i * ED25519_BASEPOINT_TABLE + c_p * p_i + c_c * c_adjusted;

        // R[idx] = s*Hp(P[idx]) + c_p*I + c_c*D
        let r_point = s_i * hp_i + c_p * pki1_point + c_c * d_original;

        // Compute next challenge
        c = compute_round_hash(
            &ring_keys,
            &ring_commitments,
            &pseudo_out,
            &tx_prefix_hash,
            &pki1_point,
            &d_inv8,
            &l_point,
            &r_point,
        );
    }

    // Now c is c_l (challenge at real index)
    let c_l = c;
    let c1 = c_l.to_bytes(); // Store c1 for verification

    // Compute partial s[l]: s[l]_partial = α₁ - c_l * x_eff_1
    let s_l_partial = alpha_1 - c_l * x_eff_1;
    s_values_scalar[real_index] = s_l_partial;

    // Convert s-values to hex
    let s_values: Vec<String> = s_values_scalar
        .iter()
        .map(|s| hex::encode(s.to_bytes()))
        .collect();

    // Zeroize sensitive data
    spend_arr.zeroize();
    lambda_arr.zeroize();
    deriv_arr.zeroize();
    alpha_arr.zeroize();

    Ok(PartialClsagSignature {
        s_values,
        c1: hex::encode(c1),
        d: hex::encode(d_inv8_bytes),
        pseudo_out: hex::encode(pseudo_out_bytes),
        partial_key_image_1: partial_key_image_1_hex.to_string(),
        mu_p: hex::encode(mu_p.to_bytes()),
        mu_c: hex::encode(mu_c.to_bytes()),
        real_index,
    })
}

/// Complete CLSAG signature (second signer).
///
/// This function implements the second phase of 2-of-3 FROST CLSAG signing.
///
/// # Arguments
/// * `partial_sig` - Partial signature from first signer
/// * `spend_share_2_hex` - Second signer's private spend share (hex, 32 bytes)
/// * `lagrange_2_hex` - Lagrange coefficient for signer 2 (hex, 32 bytes)
/// * `partial_key_image_2_hex` - Partial key image from signer 2 (hex, 32 bytes)
/// * `alpha_2_hex` - Random nonce for signer 2 (hex, 32 bytes)
/// * `ring_keys_bytes` - Public keys in the ring (must match partial_sig)
/// * `ring_commitments_bytes` - Pedersen commitments (must match partial_sig)
/// * `tx_prefix_hash` - Transaction prefix hash (must match partial_sig)
///
/// # Returns
/// Completed CLSAG signature ready for verification
///
/// # Errors
/// - `InvalidLength` if any input has incorrect length
/// - `HexDecodeFailed` if hex parsing fails
/// - `SignatureCompletionFailed` if verification of completed signature fails
#[allow(clippy::too_many_arguments)]
pub fn sign_clsag_complete(
    partial_sig: &PartialClsagSignature,
    spend_share_2_hex: &str,
    lagrange_2_hex: &str,
    partial_key_image_2_hex: &str,
    alpha_2_hex: &str,
    ring_keys_bytes: &[[u8; 32]],
    ring_commitments_bytes: &[[u8; 32]],
    tx_prefix_hash: [u8; 32],
) -> CryptoResult<ClsagSignature> {
    let ring_size = ring_keys_bytes.len();
    let real_index = partial_sig.real_index;

    // Validate ring size consistency
    if partial_sig.s_values.len() != ring_size {
        return Err(CryptoError::SignatureCompletionFailed(format!(
            "Ring size mismatch: partial has {}, provided {}",
            partial_sig.s_values.len(),
            ring_size
        )));
    }

    // Parse spend share 2
    let spend_bytes = hex::decode(spend_share_2_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("spend_share_2: {}", e)))?;
    if spend_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "spend_share_2".into(),
            expected: 32,
            actual: spend_bytes.len(),
        });
    }
    let mut spend_arr = [0u8; 32];
    spend_arr.copy_from_slice(&spend_bytes);
    let spend_2 = Scalar::from_bytes_mod_order(spend_arr);

    // Parse lagrange 2
    let lambda_bytes = hex::decode(lagrange_2_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("lagrange_2: {}", e)))?;
    if lambda_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "lagrange_2".into(),
            expected: 32,
            actual: lambda_bytes.len(),
        });
    }
    let mut lambda_arr = [0u8; 32];
    lambda_arr.copy_from_slice(&lambda_bytes);
    let lambda_2 = Scalar::from_bytes_mod_order(lambda_arr);

    // Parse partial key image 2
    let pki2_bytes = hex::decode(partial_key_image_2_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("partial_key_image_2: {}", e)))?;
    if pki2_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "partial_key_image_2".into(),
            expected: 32,
            actual: pki2_bytes.len(),
        });
    }
    let mut pki2_arr = [0u8; 32];
    pki2_arr.copy_from_slice(&pki2_bytes);
    let pki2_point = CompressedEdwardsY(pki2_arr).decompress().ok_or_else(|| {
        CryptoError::InvalidPublicKey("partial_key_image_2 decompression failed".into())
    })?;

    // Parse partial key image 1
    let pki1_bytes = hex::decode(&partial_sig.partial_key_image_1)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("partial_key_image_1: {}", e)))?;
    let mut pki1_arr = [0u8; 32];
    pki1_arr.copy_from_slice(&pki1_bytes);
    let pki1_point = CompressedEdwardsY(pki1_arr).decompress().ok_or_else(|| {
        CryptoError::InvalidPublicKey("partial_key_image_1 decompression failed".into())
    })?;

    // Parse alpha 2
    let alpha_bytes = hex::decode(alpha_2_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("alpha_2: {}", e)))?;
    if alpha_bytes.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "alpha_2".into(),
            expected: 32,
            actual: alpha_bytes.len(),
        });
    }
    let mut alpha_arr = [0u8; 32];
    alpha_arr.copy_from_slice(&alpha_bytes);
    let alpha_2 = Scalar::from_bytes_mod_order(alpha_arr);

    // Parse stored mu values (CRITICAL: reuse from signer 1)
    let mu_p_bytes = hex::decode(&partial_sig.mu_p)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("mu_p: {}", e)))?;
    let mut mu_p_arr = [0u8; 32];
    mu_p_arr.copy_from_slice(&mu_p_bytes);
    let mu_p = Scalar::from_bytes_mod_order(mu_p_arr);

    let mu_c_bytes = hex::decode(&partial_sig.mu_c)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("mu_c: {}", e)))?;
    let mut mu_c_arr = [0u8; 32];
    mu_c_arr.copy_from_slice(&mu_c_bytes);
    let mu_c = Scalar::from_bytes_mod_order(mu_c_arr);

    // Parse c1
    let c1_bytes = hex::decode(&partial_sig.c1)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("c1: {}", e)))?;
    let mut c1_arr = [0u8; 32];
    c1_arr.copy_from_slice(&c1_bytes);
    let c_l = Scalar::from_bytes_mod_order(c1_arr);

    // Aggregate key image: KI = pKI₁ + pKI₂
    let key_image = pki1_point + pki2_point;
    let key_image_bytes = key_image.compress().to_bytes();

    // Parse pseudo_out and d_inv8
    let pseudo_out_bytes = hex::decode(&partial_sig.pseudo_out)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("pseudo_out: {}", e)))?;
    let mut pseudo_out_arr = [0u8; 32];
    pseudo_out_arr.copy_from_slice(&pseudo_out_bytes);
    let pseudo_out = CompressedEdwardsY(pseudo_out_arr)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("pseudo_out decompression failed".into()))?;

    let d_inv8_bytes = hex::decode(&partial_sig.d)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("d: {}", e)))?;
    let mut d_inv8_arr = [0u8; 32];
    d_inv8_arr.copy_from_slice(&d_inv8_bytes);
    let d_inv8 = CompressedEdwardsY(d_inv8_arr)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("d decompression failed".into()))?;

    // Parse ring keys and commitments
    let mut ring_keys = Vec::with_capacity(ring_size);
    let mut ring_commitments = Vec::with_capacity(ring_size);

    for (i, key_bytes) in ring_keys_bytes.iter().enumerate() {
        let key = CompressedEdwardsY(*key_bytes).decompress().ok_or_else(|| {
            CryptoError::InvalidPublicKey(format!("ring_key[{}] decompression failed", i))
        })?;
        ring_keys.push(key);
    }

    for (i, commit_bytes) in ring_commitments_bytes.iter().enumerate() {
        let commit = CompressedEdwardsY(*commit_bytes)
            .decompress()
            .ok_or_else(|| {
                CryptoError::InvalidPublicKey(format!(
                    "ring_commitment[{}] decompression failed",
                    i
                ))
            })?;
        ring_commitments.push(commit);
    }

    // Compute signer 2 effective spend: x_eff₂ = λ₂ * s₂ (NO derivation)
    let x_eff_2 = lambda_2 * spend_2;

    // Parse partial s-values
    let mut s_values_scalar = Vec::with_capacity(ring_size);
    for (i, s_hex) in partial_sig.s_values.iter().enumerate() {
        let s_bytes = hex::decode(s_hex)
            .map_err(|e| CryptoError::HexDecodeFailed(format!("s[{}]: {}", i, e)))?;
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&s_bytes);
        s_values_scalar.push(Scalar::from_bytes_mod_order(s_arr));
    }

    // Complete s[l]: s[l] = s[l]_partial + (α₂ - c_l * x_eff₂)
    let s_l_partial = s_values_scalar[real_index];
    let s_l_contribution_2 = alpha_2 - c_l * x_eff_2;
    let s_l_final = s_l_partial + s_l_contribution_2;
    s_values_scalar[real_index] = s_l_final;

    // Verify the signature by running the ring loop
    // Precompute Hp(P[i])
    let mut hp_values: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);
    for key in &ring_keys {
        hp_values.push(hash_to_point(key.compress().to_bytes()));
    }

    // D_original = D_inv8 * 8
    let d_original = d_inv8 * Scalar::from(8u64);

    // Run verification loop (CLSAG order: 1, 2, ..., n-1, 0)
    let mut c = c_l;

    for offset in 0..ring_size {
        let idx = (real_index + offset) % ring_size;
        let s_i = s_values_scalar[idx];
        let p_i = ring_keys[idx];
        let c_i = ring_commitments[idx];
        let hp_i = hp_values[idx];

        let c_p = mu_p * c;
        let c_c = mu_c * c;

        // L[idx] = s*G + c_p*P[idx] + c_c*(C[idx] - pseudo_out)
        let c_adjusted = c_i - pseudo_out;
        let l_point = &s_i * ED25519_BASEPOINT_TABLE + c_p * p_i + c_c * c_adjusted;

        // R[idx] = s*Hp(P[idx]) + c_p*KI + c_c*D
        let r_point = s_i * hp_i + c_p * key_image + c_c * d_original;

        // Compute next challenge
        c = compute_round_hash(
            &ring_keys,
            &ring_commitments,
            &pseudo_out,
            &tx_prefix_hash,
            &key_image,
            &d_inv8,
            &l_point,
            &r_point,
        );
    }

    // Verify c matches c_l
    if c != c_l {
        return Err(CryptoError::SignatureCompletionFailed(format!(
            "Signature verification failed: c_computed != c_expected"
        )));
    }

    // Convert s-values to hex
    let s_values: Vec<String> = s_values_scalar
        .iter()
        .map(|s| hex::encode(s.to_bytes()))
        .collect();

    // Zeroize sensitive data
    spend_arr.zeroize();
    lambda_arr.zeroize();
    alpha_arr.zeroize();

    Ok(ClsagSignature {
        s_values,
        c1: partial_sig.c1.clone(),
        d: partial_sig.d.clone(),
        pseudo_out: partial_sig.pseudo_out.clone(),
        key_image: hex::encode(key_image_bytes),
    })
}

/// Compute pseudo-output commitment.
///
/// Formula: `pseudo_out = amount * H + mask * G`
///
/// # Arguments
/// * `amount` - Output amount in atomic units
/// * `mask` - Commitment mask (output_mask - sum_input_masks)
///
/// # Returns
/// Pseudo-output point (hex, 32 bytes compressed)
pub fn compute_pseudo_out(amount: u64, mask: u64) -> CryptoResult<String> {
    let h_point = CompressedEdwardsY(H_BYTES)
        .decompress()
        .ok_or_else(|| CryptoError::InternalError("H generator decompression failed".into()))?;

    let amount_scalar = Scalar::from(amount);
    let mask_scalar = Scalar::from(mask);

    let pseudo_out = &amount_scalar * h_point + &mask_scalar * ED25519_BASEPOINT_TABLE;
    Ok(hex::encode(pseudo_out.compress().to_bytes()))
}

/// Compute mask delta for CLSAG.
///
/// Formula: `mask_delta = output_mask - sum(input_masks)`
///
/// # Arguments
/// * `output_mask` - Output commitment mask
/// * `input_masks` - Input commitment masks
///
/// # Returns
/// Mask delta as u64 (modulo operations applied)
pub fn compute_mask_delta(output_mask: u64, input_masks: &[u64]) -> u64 {
    let sum_inputs: u64 = input_masks.iter().sum();
    output_mask.wrapping_sub(sum_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SPEND_1: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const TEST_SPEND_2: &str = "0200000000000000000000000000000000000000000000000000000000000000";
    const TEST_LAMBDA_1: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const TEST_LAMBDA_2: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const TEST_DERIVATION: &str =
        "0300000000000000000000000000000000000000000000000000000000000000";
    const TEST_ALPHA_1: &str = "0400000000000000000000000000000000000000000000000000000000000000";
    const TEST_ALPHA_2: &str = "0500000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_compute_pseudo_out() {
        let result = compute_pseudo_out(1000000000000, 123456789).unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_compute_mask_delta() {
        let delta = compute_mask_delta(1000, &[300, 400]);
        assert_eq!(delta, 300);
    }

    #[test]
    fn test_compute_mask_delta_underflow() {
        // Should wrap
        let delta = compute_mask_delta(100, &[200]);
        assert_eq!(delta, u64::MAX - 99);
    }

    #[test]
    fn test_sign_clsag_partial_invalid_ring_size() {
        let ring_keys = [[0u8; 32]; 1]; // Only 1 member
        let ring_commits = [[0u8; 32]; 1];
        let tx_hash = [0u8; 32];

        let result = sign_clsag_partial(
            TEST_SPEND_1,
            TEST_LAMBDA_1,
            TEST_DERIVATION,
            "5866666666666666666666666666666666666666666666666666666666666666",
            TEST_ALPHA_1,
            100,
            &ring_keys,
            &ring_commits,
            tx_hash,
            0,
            1000000000000,
        );

        assert!(matches!(result, Err(CryptoError::RingSizeTooSmall { .. })));
    }

    #[test]
    fn test_sign_clsag_partial_index_out_of_bounds() {
        let ring_keys = [[0u8; 32]; 2];
        let ring_commits = [[0u8; 32]; 2];
        let tx_hash = [0u8; 32];

        let result = sign_clsag_partial(
            TEST_SPEND_1,
            TEST_LAMBDA_1,
            TEST_DERIVATION,
            "5866666666666666666666666666666666666666666666666666666666666666",
            TEST_ALPHA_1,
            100,
            &ring_keys,
            &ring_commits,
            tx_hash,
            5, // Out of bounds
            1000000000000,
        );

        assert!(matches!(
            result,
            Err(CryptoError::SignerIndexOutOfBounds { .. })
        ));
    }

    #[test]
    fn test_partial_signature_has_correct_fields() {
        // Use valid test vectors
        let ring_keys = [
            [0u8; 32], // Identity point
            [0u8; 32],
        ];
        let ring_commits = [[0u8; 32], [0u8; 32]];
        let tx_hash = [0u8; 32];

        let partial = sign_clsag_partial(
            TEST_SPEND_1,
            TEST_LAMBDA_1,
            TEST_DERIVATION,
            "0000000000000000000000000000000000000000000000000000000000000000", // Identity
            TEST_ALPHA_1,
            100,
            &ring_keys,
            &ring_commits,
            tx_hash,
            0,
            1000000000000,
        )
        .unwrap();

        assert_eq!(partial.s_values.len(), 2);
        assert_eq!(partial.c1.len(), 64);
        assert_eq!(partial.d.len(), 64);
        assert_eq!(partial.pseudo_out.len(), 64);
        assert_eq!(partial.mu_p.len(), 64);
        assert_eq!(partial.mu_c.len(), 64);
        assert_eq!(partial.real_index, 0);
    }

    #[test]
    fn test_sign_clsag_complete_ring_size_mismatch() {
        let partial = PartialClsagSignature {
            s_values: vec!["00".repeat(32); 3], // 3 members
            c1: "00".repeat(32),
            d: "00".repeat(32),
            pseudo_out: "00".repeat(32),
            partial_key_image_1: "00".repeat(32),
            mu_p: "00".repeat(32),
            mu_c: "00".repeat(32),
            real_index: 0,
        };

        let ring_keys = [[0u8; 32]; 2]; // Only 2 members (mismatch)
        let ring_commits = [[0u8; 32]; 2];
        let tx_hash = [0u8; 32];

        let result = sign_clsag_complete(
            &partial,
            TEST_SPEND_2,
            TEST_LAMBDA_2,
            "0000000000000000000000000000000000000000000000000000000000000000",
            TEST_ALPHA_2,
            &ring_keys,
            &ring_commits,
            tx_hash,
        );

        assert!(matches!(
            result,
            Err(CryptoError::SignatureCompletionFailed(_))
        ));
    }
}
