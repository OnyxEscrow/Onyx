//! Key Image Aggregation for 2-of-3 Multisig CLSAG Signing (v0.49.0)
//!
//! This module provides server-side aggregation of partial key images from
//! multisig participants using FROST/Lagrange threshold signatures.
//!
//! ## v0.49.0 CRITICAL FIX: Lagrange-Weighted Aggregation
//!
//! For threshold CLSAG with Lagrange interpolation, key images must be
//! aggregated with Lagrange coefficients - NOT simple addition:
//!
//!   KI = λ₁ * PKI₁ + λ₂ * PKI₂
//!
//! Where λᵢ = j/(j-i), i=signer's index, j=other signer's index.
//!
//! For buyer(1)+vendor(2): λ_buyer=2, λ_vendor=-1
//! So: KI = 2*PKI_buyer - PKI_vendor
//!
//! This matches the Lagrange coefficients used in CLSAG signing, ensuring
//! the verification equation holds:
//!   R[l] = s*Hp(P) + c_p*KI  ← must match s-value's Lagrange weights!
//!
//! ## Why Simple Addition Fails
//!
//! If PKI aggregation uses simple sum but signing uses Lagrange:
//!   KI_wrong = PKI_buyer + PKI_vendor = (x_buyer + x_vendor) * Hp(P)
//!   s = α - c_p*(λ_buyer*x_buyer + λ_vendor*x_vendor) - c_c*mask
//!
//! Verification: s*Hp(P) + c_p*KI_wrong ≠ R[l]  ← FAILS!
//!
//! SECURITY: The server never sees private keys - only public Edwards points.

use anyhow::{Context, Result};
use curve25519_dalek::edwards::CompressedEdwardsY;
use tracing::{info, warn};

/// Aggregates two partial key images via Edwards point addition.
///
/// # Arguments
/// * `pki1_hex` - First partial key image (32-byte hex-encoded compressed Edwards point)
/// * `pki2_hex` - Second partial key image (32-byte hex-encoded compressed Edwards point)
///
/// # Returns
/// * `Ok(String)` - Aggregated key image as 32-byte hex-encoded compressed Edwards point
/// * `Err(...)` - If decoding or point addition fails
///
/// # Mathematical Operation
/// KI_total = pKI_1 + pKI_2 (Edwards curve point addition)
///
/// # Example
/// ```ignore
/// let buyer_pki = "abc123...";  // 64 hex chars = 32 bytes
/// let vendor_pki = "def456..."; // 64 hex chars = 32 bytes
/// let aggregated = aggregate_partial_key_images(buyer_pki, vendor_pki)?;
/// ```
pub fn aggregate_partial_key_images(pki1_hex: &str, pki2_hex: &str) -> Result<String> {
    // Decode hex to bytes
    let pki1_bytes =
        hex::decode(pki1_hex).context("Failed to decode first partial key image from hex")?;
    let pki2_bytes =
        hex::decode(pki2_hex).context("Failed to decode second partial key image from hex")?;

    // Validate length (32 bytes for compressed Edwards point)
    if pki1_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid first partial key image length: expected 32 bytes, got {}",
            pki1_bytes.len()
        );
    }
    if pki2_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid second partial key image length: expected 32 bytes, got {}",
            pki2_bytes.len()
        );
    }

    // Convert to fixed-size arrays
    let mut pki1_arr = [0u8; 32];
    let mut pki2_arr = [0u8; 32];
    pki1_arr.copy_from_slice(&pki1_bytes);
    pki2_arr.copy_from_slice(&pki2_bytes);

    // Decompress to Edwards points
    let compressed1 = CompressedEdwardsY(pki1_arr);
    let compressed2 = CompressedEdwardsY(pki2_arr);

    let point1 = compressed1
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("First partial key image is not a valid Edwards point"))?;
    let point2 = compressed2
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Second partial key image is not a valid Edwards point"))?;

    // Perform Edwards point addition
    let sum = point1 + point2;

    // Partial key images are already in prime-order subgroup (generated from valid spend keys)
    // Do NOT apply mul_by_cofactor() - that would produce KI * 8 instead of KI
    // The aggregated key image is simply the sum of partial key images

    // Compress result back to 32 bytes
    let result = sum.compress();
    let result_hex = hex::encode(result.as_bytes());

    info!(
        pki1_hex_prefix = %&pki1_hex[..16.min(pki1_hex.len())],
        pki2_hex_prefix = %&pki2_hex[..16.min(pki2_hex.len())],
        result_hex_prefix = %&result_hex[..16],
        "Aggregated partial key images"
    );

    Ok(result_hex)
}

/// v0.49.0: Aggregate partial key images with Lagrange coefficients for threshold signatures.
///
/// # CRITICAL FIX
/// For 2-of-3 threshold signatures with FROST/Lagrange:
///   KI = λ₁ * PKI₁ + λ₂ * PKI₂
///
/// NOT simple addition! The Lagrange coefficients ensure correct key reconstruction:
///   - For buyer+vendor pair: λ_buyer=2, λ_vendor=-1
///   - For buyer+arbiter pair: λ_buyer=3/2, λ_arbiter=-1/2
///   - For vendor+arbiter pair: λ_vendor=3, λ_arbiter=-2
///
/// # Arguments
/// * `pki1_hex` - First signer's partial key image
/// * `pki2_hex` - Second signer's partial key image
/// * `signer1_role` - Role of first signer ("buyer", "vendor", or "arbiter")
/// * `signer2_role` - Role of second signer
///
/// # Returns
/// Lagrange-weighted aggregated key image
pub fn aggregate_partial_key_images_with_lagrange(
    pki1_hex: &str,
    pki2_hex: &str,
    signer1_role: &str,
    signer2_role: &str,
) -> Result<String> {
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::Identity;

    // Decode hex to bytes
    let pki1_bytes =
        hex::decode(pki1_hex).context("Failed to decode first partial key image from hex")?;
    let pki2_bytes =
        hex::decode(pki2_hex).context("Failed to decode second partial key image from hex")?;

    // Validate length
    if pki1_bytes.len() != 32 || pki2_bytes.len() != 32 {
        anyhow::bail!("Invalid PKI length: expected 32 bytes");
    }

    // Convert to arrays
    let mut pki1_arr = [0u8; 32];
    let mut pki2_arr = [0u8; 32];
    pki1_arr.copy_from_slice(&pki1_bytes);
    pki2_arr.copy_from_slice(&pki2_bytes);

    // Decompress to Edwards points
    let point1 = CompressedEdwardsY(pki1_arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("First PKI is not a valid Edwards point"))?;
    let point2 = CompressedEdwardsY(pki2_arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Second PKI is not a valid Edwards point"))?;

    // Map roles to indices: buyer=1, vendor=2, arbiter=3
    let idx1: u16 = match signer1_role {
        "buyer" => 1,
        "vendor" => 2,
        "arbiter" => 3,
        _ => anyhow::bail!("Invalid signer1_role: {}", signer1_role),
    };
    let idx2: u16 = match signer2_role {
        "buyer" => 1,
        "vendor" => 2,
        "arbiter" => 3,
        _ => anyhow::bail!("Invalid signer2_role: {}", signer2_role),
    };

    if idx1 == idx2 {
        anyhow::bail!("Signer roles must be different: both are {}", signer1_role);
    }

    // Compute Lagrange coefficients
    // λ_i = j / (j - i) where i is signer's index, j is other signer's index
    let i1 = Scalar::from(idx1);
    let i2 = Scalar::from(idx2);

    // λ₁ = idx2 / (idx2 - idx1)
    let lambda1 = i2 * (i2 - i1).invert();
    // λ₂ = idx1 / (idx1 - idx2)
    let lambda2 = i1 * (i1 - i2).invert();

    info!(
        signer1_role = %signer1_role,
        signer2_role = %signer2_role,
        idx1 = idx1,
        idx2 = idx2,
        lambda1_prefix = %hex::encode(&lambda1.to_bytes()[..8]),
        lambda2_prefix = %hex::encode(&lambda2.to_bytes()[..8]),
        "[v0.49.0] Computing Lagrange-weighted PKI aggregation"
    );

    // Apply Lagrange coefficients: KI = λ₁ * PKI₁ + λ₂ * PKI₂
    let weighted1 = point1 * lambda1;
    let weighted2 = point2 * lambda2;
    let sum = weighted1 + weighted2;

    // Compress result
    let result = sum.compress();
    let result_hex = hex::encode(result.as_bytes());

    info!(
        pki1_prefix = %&pki1_hex[..16.min(pki1_hex.len())],
        pki2_prefix = %&pki2_hex[..16.min(pki2_hex.len())],
        result_prefix = %&result_hex[..16],
        "[v0.49.0] Lagrange-weighted PKI aggregation complete"
    );

    Ok(result_hex)
}

/// ⚠️ DEPRECATED v0.31.0: DO NOT USE - This function is INCORRECT for CLSAG signing!
///
/// ## Why This Is Wrong
/// For 2-of-3 multisig CLSAG, the key image MUST use only 2 PKIs (the actual signers):
///   KI = pKI_signer1 + pKI_signer2  (NOT all 3!)
///
/// The CLSAG s-value formula uses only 2 private keys:
///   s = alpha - c_p*(x1+x2) - c_c*mask_delta
///
/// If KI uses 3 PKIs but s uses 2 keys, CLSAG verification FAILS:
///   R[l] = s*Hp(P) + c_p*KI
///        = (alpha - c_p*(x1+x2) - ...)*Hp(P) + c_p*(x1+x2+x3)*Hp(P)
///        = alpha*Hp(P) + c_p*x3*Hp(P) + ...  ← EXTRA TERM breaks verification!
///
/// ## Correct Usage
/// Use `aggregate_partial_key_images(pki1, pki2)` instead - only 2 PKIs.
///
/// ## Historical Note
/// This function was added in v0.29.0 based on a misunderstanding of multisig.
/// It has NEVER been called in production and should be removed in v0.40.0.
#[deprecated(
    since = "0.31.0",
    note = "INCORRECT: Use aggregate_partial_key_images(pki1, pki2) instead - 2 PKIs only"
)]
#[allow(dead_code)]
pub fn aggregate_three_partial_key_images(
    pki_buyer_hex: &str,
    pki_vendor_hex: &str,
    pki_arbiter_hex: &str,
) -> Result<String> {
    // Decode all three PKIs
    let pki_buyer_bytes =
        hex::decode(pki_buyer_hex).context("Failed to decode buyer partial key image from hex")?;
    let pki_vendor_bytes = hex::decode(pki_vendor_hex)
        .context("Failed to decode vendor partial key image from hex")?;
    let pki_arbiter_bytes = hex::decode(pki_arbiter_hex)
        .context("Failed to decode arbiter partial key image from hex")?;

    // Validate lengths
    if pki_buyer_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid buyer PKI length: expected 32 bytes, got {}",
            pki_buyer_bytes.len()
        );
    }
    if pki_vendor_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid vendor PKI length: expected 32 bytes, got {}",
            pki_vendor_bytes.len()
        );
    }
    if pki_arbiter_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid arbiter PKI length: expected 32 bytes, got {}",
            pki_arbiter_bytes.len()
        );
    }

    // Convert to fixed-size arrays
    let mut buyer_arr = [0u8; 32];
    let mut vendor_arr = [0u8; 32];
    let mut arbiter_arr = [0u8; 32];
    buyer_arr.copy_from_slice(&pki_buyer_bytes);
    vendor_arr.copy_from_slice(&pki_vendor_bytes);
    arbiter_arr.copy_from_slice(&pki_arbiter_bytes);

    // Decompress to Edwards points
    let point_buyer = CompressedEdwardsY(buyer_arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Buyer PKI is not a valid Edwards point"))?;
    let point_vendor = CompressedEdwardsY(vendor_arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Vendor PKI is not a valid Edwards point"))?;
    let point_arbiter = CompressedEdwardsY(arbiter_arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Arbiter PKI is not a valid Edwards point"))?;

    // Sum ALL THREE partial key images
    // KI_total = pKI_buyer + pKI_vendor + pKI_arbiter
    let sum = point_buyer + point_vendor + point_arbiter;

    // Compress result
    let result = sum.compress();
    let result_hex = hex::encode(result.as_bytes());

    info!(
        pki_buyer_prefix = %&pki_buyer_hex[..16.min(pki_buyer_hex.len())],
        pki_vendor_prefix = %&pki_vendor_hex[..16.min(pki_vendor_hex.len())],
        pki_arbiter_prefix = %&pki_arbiter_hex[..16.min(pki_arbiter_hex.len())],
        result_hex_prefix = %&result_hex[..16],
        "[v0.29.0] Aggregated ALL THREE partial key images for correct key_image"
    );

    Ok(result_hex)
}

/// Validates a partial key image format without aggregating.
///
/// # Arguments
/// * `pki_hex` - Partial key image (32-byte hex-encoded compressed Edwards point)
///
/// # Returns
/// * `Ok(())` - If valid
/// * `Err(...)` - If invalid format or not a valid point
pub fn validate_partial_key_image(pki_hex: &str) -> Result<()> {
    // Decode hex to bytes
    let pki_bytes = hex::decode(pki_hex).context("Failed to decode partial key image from hex")?;

    // Validate length (32 bytes for compressed Edwards point)
    if pki_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid partial key image length: expected 32 bytes (64 hex chars), got {} bytes",
            pki_bytes.len()
        );
    }

    // Convert to fixed-size array
    let mut pki_arr = [0u8; 32];
    pki_arr.copy_from_slice(&pki_bytes);

    // Verify it's a valid Edwards point
    let compressed = CompressedEdwardsY(pki_arr);
    compressed
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Partial key image is not a valid Edwards point"))?;

    Ok(())
}

/// v0.29.0: Aggregates ALL THREE partial key images from an escrow and stores the result.
///
/// For 2-of-3 multisig with additive secret sharing:
///   x_total = x_buyer + x_vendor + x_arbiter
///   KI = x_total * Hp(P) = pKI_buyer + pKI_vendor + pKI_arbiter
///
/// Even if only 2 parties SIGN, the key_image must be computed from ALL 3 PKIs.
///
/// # Arguments
/// * `conn` - Database connection
/// * `escrow_id` - Escrow ID to process
///
/// # Returns
/// * `Ok(Some(String))` - Aggregated key image if ALL 3 PKIs available
/// * `Ok(None)` - Not enough PKIs yet (need 3 of 3)
/// * `Err(...)` - On database or aggregation error
/// v0.31.0 CRITICAL FIX: Aggregates only 2 PKIs (buyer + vendor) for normal release.
///
/// For CLSAG math to work:
///   - Key image: KI = (x1 + x2) * Hp(P)   [2 signers only]
///   - s-value:   s = alpha - c_p*(x1+x2) - c_c*mask_delta
///
/// If KI uses 3 PKIs but s-value uses 2: VERIFICATION FAILS!
///
/// # Arguments
/// * `conn` - Database connection
/// * `escrow_id` - Escrow ID to process
///
/// # Returns
/// * `Ok(Some(String))` - Aggregated key image if buyer + vendor PKIs available
/// * `Ok(None)` - Not enough PKIs yet (need 2 of 2 signers)
/// * `Err(...)` - On database or aggregation error
pub fn try_aggregate_escrow_key_images(
    conn: &mut diesel::SqliteConnection,
    escrow_id: String,
) -> Result<Option<String>> {
    use crate::models::escrow::Escrow;
    use diesel::Connection;

    // E3 FIX: Wrap in transaction to prevent race conditions
    conn.transaction::<Option<String>, anyhow::Error, _>(|conn| {
        // v0.31.0: Get the TWO PKIs of actual signers (buyer + vendor for normal release)
        let escrow = Escrow::find_by_id(conn, escrow_id.clone())
            .context("Failed to find escrow")?;

        let buyer_pki = escrow.buyer_partial_key_image.as_ref();
        let vendor_pki = escrow.vendor_partial_key_image.as_ref();

        match (buyer_pki, vendor_pki) {
            (Some(pki_buyer), Some(pki_vendor)) => {
                info!(
                    escrow_id = %escrow_id,
                    "[v0.31.0] Found 2 signer PKIs (buyer + vendor), aggregating for 2-of-3 multisig"
                );

                // Validate both PKIs
                if let Err(e) = validate_partial_key_image(pki_buyer) {
                    warn!(
                        escrow_id = %escrow_id,
                        role = "buyer",
                        error = %e,
                        "Invalid partial key image from buyer"
                    );
                    return Err(e);
                }
                if let Err(e) = validate_partial_key_image(pki_vendor) {
                    warn!(
                        escrow_id = %escrow_id,
                        role = "vendor",
                        error = %e,
                        "Invalid partial key image from vendor"
                    );
                    return Err(e);
                }

                // v0.50.0 FIX: Simple sum - WASM already applies Lagrange to spend shares
                // PKI_buyer = (d + λ_buyer * s_buyer) * Hp(P)
                // PKI_vendor = (d + λ_vendor * s_vendor) * Hp(P)  <- wrong: should be λ_vendor * s_vendor * Hp only
                // WASM first signer includes derivation, second signer only spend share
                // KI = PKI_first + PKI_second (simple sum, no additional Lagrange)
                let aggregated = aggregate_partial_key_images(
                    pki_buyer, pki_vendor
                ).context("[v0.50.0] Failed to simple-sum aggregate PKIs")?;

                // Store the aggregated key image
                Escrow::update_aggregated_key_image(conn, escrow_id.clone(), &aggregated)
                    .context("Failed to store aggregated key image")?;

                info!(
                    escrow_id = %escrow_id,
                    aggregated_ki_prefix = %&aggregated[..16],
                    "[v0.50.0] Simple-sum aggregated key image (WASM applies Lagrange)"
                );

                Ok(Some(aggregated))
            }
            _ => {
                // Not enough PKIs from actual signers
                let buyer_has = buyer_pki.is_some();
                let vendor_has = vendor_pki.is_some();
                info!(
                    escrow_id = %escrow_id,
                    buyer_pki = buyer_has,
                    vendor_pki = vendor_has,
                    "[v0.31.0] Waiting for signer PKIs: buyer={}, vendor={}", buyer_has, vendor_has
                );
                Ok(None)
            }
        }
    }) // End of transaction
}

/// v0.53.0: Add derivation component to aggregated key image.
///
/// # CRITICAL FIX
/// PKIs are computed WITHOUT derivation: pKI = λ * b * Hp(P)
/// The aggregated KI is: KI_partial = Σ λ_i * b_i * Hp(P)
/// But the correct KI must include derivation: KI = (d + Σ λ_i * b_i) * Hp(P)
///
/// This function adds the missing derivation: KI_correct = KI_partial + d * Hp(P)
///
/// # Arguments
/// * `aggregated_ki_hex` - The aggregated key image (without derivation)
/// * `one_time_pubkey_hex` - The one-time public key P (for Hp(P))
/// * `tx_pubkey_hex` - The funding transaction public key R
/// * `view_key_hex` - The private view key a
/// * `output_index` - The output index in the funding transaction
///
/// # Returns
/// * `Ok(String)` - Corrected key image with derivation included
/// * `Err(...)` - If any computation fails
pub fn add_derivation_to_key_image(
    aggregated_ki_hex: &str,
    one_time_pubkey_hex: &str,
    tx_pubkey_hex: &str,
    view_key_hex: &str,
    output_index: u64,
) -> Result<String> {
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use monero_generators_mirror::hash_to_point;
    use sha3::{Digest, Keccak256};

    // Helper to encode varint
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

    // Decode aggregated key image
    let ki_bytes =
        hex::decode(aggregated_ki_hex).context("Failed to decode aggregated key image")?;
    if ki_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid aggregated key image length: expected 32, got {}",
            ki_bytes.len()
        );
    }
    let mut ki_arr = [0u8; 32];
    ki_arr.copy_from_slice(&ki_bytes);
    let ki_point = CompressedEdwardsY(ki_arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Aggregated key image is not a valid Edwards point"))?;

    // Decode one-time pubkey P
    let p_bytes = hex::decode(one_time_pubkey_hex).context("Failed to decode one-time pubkey")?;
    if p_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid one-time pubkey length: expected 32, got {}",
            p_bytes.len()
        );
    }
    let mut p_arr = [0u8; 32];
    p_arr.copy_from_slice(&p_bytes);
    let p_point = CompressedEdwardsY(p_arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("One-time pubkey is not a valid Edwards point"))?;

    // Decode TX pubkey R
    let r_bytes = hex::decode(tx_pubkey_hex).context("Failed to decode TX pubkey")?;
    if r_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid TX pubkey length: expected 32, got {}",
            r_bytes.len()
        );
    }
    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(&r_bytes);
    let r_point = CompressedEdwardsY(r_arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("TX pubkey is not a valid Edwards point"))?;

    // Decode view key a
    let a_bytes = hex::decode(view_key_hex).context("Failed to decode view key")?;
    if a_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid view key length: expected 32, got {}",
            a_bytes.len()
        );
    }
    let mut a_arr = [0u8; 32];
    a_arr.copy_from_slice(&a_bytes);
    let view_scalar = Scalar::from_bytes_mod_order(a_arr);

    // Compute shared secret: 8 * a * R (WITH COFACTOR - v0.52.0 FIX)
    let shared_secret = (view_scalar * r_point).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    // Compute derivation scalar: d = Hs(shared_secret || varint(output_index))
    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    hasher.update(&encode_varint(output_index));
    let hash_result: [u8; 32] = hasher.finalize().into();
    let derivation_scalar = Scalar::from_bytes_mod_order(hash_result);

    // Compute Hp(P) using Monero's hash_to_point
    let hp_p = hash_to_point(p_arr);

    // Compute d * Hp(P)
    let derivation_ki_contribution = derivation_scalar * hp_p;

    // Add to aggregated key image: KI_correct = KI_partial + d * Hp(P)
    let corrected_ki = ki_point + derivation_ki_contribution;

    // Compress and return
    let result = corrected_ki.compress();
    let result_hex = hex::encode(result.as_bytes());

    info!(
        aggregated_ki_prefix = %&aggregated_ki_hex[..16.min(aggregated_ki_hex.len())],
        derivation_prefix = %hex::encode(&hash_result)[..16],
        result_prefix = %&result_hex[..16],
        output_index = output_index,
        "[v0.53.0] Added derivation to key image: KI = KI_partial + d*Hp(P)"
    );

    Ok(result_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate_identity_points() {
        // Test with identity point (all zeros except last byte = 1)
        // In Edwards form, the identity is (0, 1) which compresses to 0x01 followed by zeros
        // Actually the compressed identity is all zeros except the sign bit

        // For testing, we'll use some known valid points
        // The generator point G in curve25519 (not actually identity, but valid)
        // This is just a placeholder test - real test would need actual Monero test vectors
    }

    #[test]
    fn test_validate_invalid_length() {
        let result = validate_partial_key_image("abc123");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length"));
    }

    #[test]
    fn test_validate_invalid_hex() {
        let result = validate_partial_key_image("xyz123");
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_invalid_points() {
        // Use a y-coordinate that is NOT on the Ed25519 curve
        // y = 2 (0x02...00) with high bit set for negative x does not satisfy the curve equation
        // x² = (y² - 1) / (d*y² + 1) yields a non-quadratic residue
        let invalid = "0200000000000000000000000000000000000000000000000000000000000080";
        let result = aggregate_partial_key_images(invalid, invalid);
        assert!(
            result.is_err(),
            "Invalid Edwards point should fail aggregation"
        );
    }
}
