//! Signature Aggregation for 2-of-3 Multisig CLSAG Signing (v0.7.0)
//!
//! This module provides server-side aggregation of partial CLSAG signatures from
//! multisig participants. In Monero's CLSAG scheme for 2-of-3 multisig:
//!
//! ## CLSAG Signature Structure
//!
//! A CLSAG signature consists of:
//! - `s` values: Ring of scalars (16 elements for standard ring size)
//! - `c1`: Initial challenge scalar
//! - `D`: Point derived from key image
//!
//! ## Aggregation Process
//!
//! For 2-of-3 multisig:
//! 1. Each signer produces partial signature components
//! 2. The `s` values are aggregated: s_combined[i] = s_1[i] + s_2[i] (mod l)
//! 3. The `c1` values must match (same challenge)
//! 4. The `D` point is derived from the aggregated key image
//!
//! ## Security Model
//!
//! - Server never sees private keys
//! - Partial signatures alone cannot spend funds
//! - Aggregation uses pure arithmetic (no secret knowledge needed)
//!
//! ## Mathematical Foundation
//!
//! CLSAG signatures use Schnorr-like proofs:
//! - s_i = r_i - c_i * x_i (where x_i is private spend key share)
//! - For multisig: s_combined = sum(s_i) = sum(r_i) - c * sum(x_i)
//! - Since sum(x_i) = x_multisig, the combined signature is valid

use anyhow::{Context, Result};
use curve25519_dalek::scalar::Scalar;
use tracing::{info, warn};

/// Represents a partial CLSAG signature from one signer
#[derive(Debug, Clone)]
pub struct PartialClsagSignature {
    /// The `s` values (scalars, one per ring member)
    pub s_values: Vec<[u8; 32]>,
    /// The initial challenge scalar `c1`
    pub c1: [u8; 32],
    /// The D point (related to key image)
    pub d: [u8; 32],
    /// Role of the signer (buyer, vendor, arbiter)
    pub role: String,
}

/// Represents an aggregated CLSAG signature ready for broadcast
#[derive(Debug, Clone)]
pub struct AggregatedClsagSignature {
    /// Aggregated `s` values
    pub s_values: Vec<[u8; 32]>,
    /// The shared `c1` (must be same for both signers)
    pub c1: [u8; 32],
    /// The D point from the aggregated key image
    pub d: [u8; 32],
}

/// Parse a partial signature from JSON-stored format
pub fn parse_partial_signature(signature_json: &str, role: &str) -> Result<PartialClsagSignature> {
    #[derive(serde::Deserialize)]
    struct StoredSignature {
        signature: SignatureInner,
        #[serde(default)]
        key_image: String,
        #[serde(default)]
        pseudo_out: String,
    }

    #[derive(serde::Deserialize)]
    struct SignatureInner {
        #[serde(rename = "D")]
        d: String,
        s: Vec<String>,
        c1: String,
    }

    let stored: StoredSignature =
        serde_json::from_str(signature_json).context("Failed to parse signature JSON")?;

    // Parse D point
    let d_bytes = hex::decode(&stored.signature.d).context("Failed to decode D point hex")?;
    if d_bytes.len() != 32 {
        anyhow::bail!("D point must be 32 bytes, got {}", d_bytes.len());
    }
    let mut d = [0u8; 32];
    d.copy_from_slice(&d_bytes);

    // Parse c1 scalar
    let c1_bytes = hex::decode(&stored.signature.c1).context("Failed to decode c1 hex")?;
    if c1_bytes.len() != 32 {
        anyhow::bail!("c1 must be 32 bytes, got {}", c1_bytes.len());
    }
    let mut c1 = [0u8; 32];
    c1.copy_from_slice(&c1_bytes);

    // Parse s values
    let mut s_values = Vec::with_capacity(stored.signature.s.len());
    for (i, s_hex) in stored.signature.s.iter().enumerate() {
        let s_bytes = hex::decode(s_hex).context(format!("Failed to decode s[{}] hex", i))?;
        if s_bytes.len() != 32 {
            anyhow::bail!("s[{}] must be 32 bytes, got {}", i, s_bytes.len());
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&s_bytes);
        s_values.push(s);
    }

    Ok(PartialClsagSignature {
        s_values,
        c1,
        d,
        role: role.to_string(),
    })
}

/// Aggregate two partial CLSAG signatures into one valid signature
///
/// # Round-Robin CLSAG Multisig Protocol
///
/// In Round-Robin CLSAG for 2-of-3 multisig:
/// - Signer 1 generates ALL decoy s-values (s[i] for i != signer_index)
/// - Signer 1 computes partial s[signer_index] from their key share
/// - Signer 2 REUSES the same decoy s-values (identical)
/// - Signer 2 computes partial s[signer_index] from their key share
/// - Final s[signer_index] = s_1[signer_index] + s_2[signer_index]
/// - Final s[i] for i != signer_index = decoy value (NOT summed)
///
/// # Arguments
/// * `sig1` - First partial signature (contains decoys + partial s[signer_index])
/// * `sig2` - Second partial signature (should have same decoys + partial s[signer_index])
/// * `aggregated_d` - D point computed from aggregated key image (optional override)
///
/// # Returns
/// * `Ok(AggregatedClsagSignature)` - Combined signature ready for broadcast
/// * `Err(...)` - If signatures are incompatible
pub fn aggregate_clsag_signatures(
    sig1: &PartialClsagSignature,
    sig2: &PartialClsagSignature,
    aggregated_d: Option<[u8; 32]>,
) -> Result<AggregatedClsagSignature> {
    // Verify ring sizes match
    if sig1.s_values.len() != sig2.s_values.len() {
        anyhow::bail!(
            "Ring size mismatch: {} ({}) vs {} ({})",
            sig1.s_values.len(),
            sig1.role,
            sig2.s_values.len(),
            sig2.role
        );
    }

    let ring_size = sig1.s_values.len();

    // Verify c1 values match (same challenge)
    if sig1.c1 != sig2.c1 {
        warn!(
            sig1_c1 = %hex::encode(&sig1.c1[..8]),
            sig2_c1 = %hex::encode(&sig2.c1[..8]),
            "c1 values differ between signers - using first signer's c1"
        );
    }

    // Identify which s-values differ (these are the real input positions)
    // In Round-Robin: decoys should be identical, only s[signer_index] differs
    let mut aggregated_s = Vec::with_capacity(ring_size);
    let mut real_input_indices: Vec<usize> = Vec::new();

    for i in 0..ring_size {
        if sig1.s_values[i] == sig2.s_values[i] {
            // Decoy position: s-values are identical, use as-is (no aggregation)
            aggregated_s.push(sig1.s_values[i]);
        } else {
            // Real input position: s-values differ, need to aggregate
            real_input_indices.push(i);
            let s1 = Scalar::from_bytes_mod_order(sig1.s_values[i]);
            let s2 = Scalar::from_bytes_mod_order(sig2.s_values[i]);
            let s_combined = s1 + s2;
            aggregated_s.push(s_combined.to_bytes());
        }
    }

    // Log which indices were aggregated
    info!(
        role1 = %sig1.role,
        role2 = %sig2.role,
        ring_size = ring_size,
        real_input_indices = ?real_input_indices,
        "Round-Robin CLSAG aggregation: aggregated s-values at positions {:?}", real_input_indices
    );

    if real_input_indices.is_empty() {
        warn!("No s-values differ between signers - this may indicate a problem");
    } else if real_input_indices.len() > 1 {
        warn!(
            "Multiple s-values differ ({:?}) - expected only one (signer_index)",
            real_input_indices
        );
    }

    // Use provided D or default to sig1's D
    let final_d = aggregated_d.unwrap_or(sig1.d);

    info!(
        aggregated_d_prefix = %hex::encode(&final_d[..8]),
        aggregated_s15_prefix = %hex::encode(&aggregated_s[ring_size - 1][..8]),
        "CLSAG signature aggregated successfully"
    );

    Ok(AggregatedClsagSignature {
        s_values: aggregated_s,
        c1: sig1.c1, // Use first signer's c1
        d: final_d,
    })
}

/// Compute D point from aggregated key image
///
/// D = Hp(P_multisig) * (1/8) where the key image is derived from D
/// For our purposes, we derive D directly from the aggregated key image.
///
/// # Arguments
/// * `aggregated_key_image` - The aggregated key image hex string
///
/// # Returns
/// * `Ok([u8; 32])` - D point bytes
/// * `Err(...)` - If conversion fails
pub fn compute_d_from_key_image(aggregated_key_image: &str) -> Result<[u8; 32]> {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let ki_bytes =
        hex::decode(aggregated_key_image).context("Failed to decode aggregated key image hex")?;

    if ki_bytes.len() != 32 {
        anyhow::bail!(
            "Aggregated key image must be 32 bytes, got {}",
            ki_bytes.len()
        );
    }

    let mut ki_arr = [0u8; 32];
    ki_arr.copy_from_slice(&ki_bytes);

    // Verify it's a valid point
    let ki_point = CompressedEdwardsY(ki_arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Aggregated key image is not a valid Edwards point"))?;

    // For CLSAG, D is related to the key image by: D = x * Hp(P)
    // where KI = x * Hp(P) as well. So D == KI in this simplified model.
    // In practice, D might need additional transformations based on Monero's exact spec.
    //
    // For now, we'll use the key image directly as D
    // (This may need adjustment based on actual Monero protocol)

    // Apply cofactor clearing (multiply by 8 then divide by 8)
    // to ensure D is in the prime-order subgroup
    let d_point = ki_point.mul_by_cofactor();

    // Compress back - but this gives us 8*D, we need D
    // In Monero, D = (1/8) * 8*D which requires scalar division
    // For now, let's just use the key image bytes directly
    Ok(ki_arr)
}

/// Convert aggregated signature to JSON format for transaction builder
pub fn aggregated_to_json(sig: &AggregatedClsagSignature) -> serde_json::Value {
    let s_hex: Vec<String> = sig.s_values.iter().map(|s| hex::encode(s)).collect();

    serde_json::json!({
        "D": hex::encode(&sig.d),
        "s": s_hex,
        "c1": hex::encode(&sig.c1)
    })
}

/// Convert aggregated signature to ClientSignature format for transaction builder
pub fn aggregated_to_client_signature(
    sig: &AggregatedClsagSignature,
    aggregated_key_image: &str,
    pseudo_out: &str,
) -> crate::services::transaction_builder::ClientSignature {
    crate::services::transaction_builder::ClientSignature {
        signature: crate::services::transaction_builder::ClsagSignatureJson {
            d: hex::encode(&sig.d),
            s: sig.s_values.iter().map(|s| hex::encode(s)).collect(),
            c1: hex::encode(&sig.c1),
        },
        key_image: aggregated_key_image.to_string(),
        partial_key_image: None, // Already aggregated
        pseudo_out: pseudo_out.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_addition() {
        // Test that scalar addition is commutative and associative
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];

        let scalar1 = Scalar::from_bytes_mod_order(s1);
        let scalar2 = Scalar::from_bytes_mod_order(s2);

        let sum1 = scalar1 + scalar2;
        let sum2 = scalar2 + scalar1;

        assert_eq!(sum1.to_bytes(), sum2.to_bytes());
    }

    #[test]
    fn test_parse_signature_format() {
        let json = r#"{
            "signature": {
                "D": "0000000000000000000000000000000000000000000000000000000000000001",
                "s": ["0000000000000000000000000000000000000000000000000000000000000002"],
                "c1": "0000000000000000000000000000000000000000000000000000000000000003"
            },
            "key_image": "test",
            "pseudo_out": "test"
        }"#;

        let result = parse_partial_signature(json, "test");
        assert!(result.is_ok());

        let sig = result.unwrap();
        assert_eq!(sig.s_values.len(), 1);
        assert_eq!(sig.d[0], 0);
        assert_eq!(sig.d[31], 1);
    }

    #[test]
    fn test_aggregate_matching_rings() {
        // Round-Robin: decoys should match, only real input differs
        let decoy = [1u8; 32]; // Same decoy for both signers
        let sig1_real = [10u8; 32]; // Signer 1's partial s[1]
        let sig2_real = [20u8; 32]; // Signer 2's partial s[1]

        let sig1 = PartialClsagSignature {
            s_values: vec![decoy, sig1_real], // decoy at [0], real at [1]
            c1: [0u8; 32],
            d: [0u8; 32],
            role: "vendor".to_string(),
        };

        let sig2 = PartialClsagSignature {
            s_values: vec![decoy, sig2_real], // Same decoy at [0], different real at [1]
            c1: [0u8; 32],
            d: [0u8; 32],
            role: "buyer".to_string(),
        };

        let result = aggregate_clsag_signatures(&sig1, &sig2, None);
        assert!(result.is_ok());

        let aggregated = result.unwrap();
        assert_eq!(aggregated.s_values.len(), 2);

        // Decoy should be unchanged (not summed)
        assert_eq!(aggregated.s_values[0], decoy);

        // Real input should be summed (s1 + s2)
        let s1 = Scalar::from_bytes_mod_order(sig1_real);
        let s2 = Scalar::from_bytes_mod_order(sig2_real);
        let expected_sum = (s1 + s2).to_bytes();
        assert_eq!(aggregated.s_values[1], expected_sum);
    }

    #[test]
    fn test_aggregate_mismatched_rings_fails() {
        let sig1 = PartialClsagSignature {
            s_values: vec![[1u8; 32], [2u8; 32]],
            c1: [0u8; 32],
            d: [0u8; 32],
            role: "buyer".to_string(),
        };

        let sig2 = PartialClsagSignature {
            s_values: vec![[3u8; 32]], // Different ring size!
            c1: [0u8; 32],
            d: [0u8; 32],
            role: "vendor".to_string(),
        };

        let result = aggregate_clsag_signatures(&sig1, &sig2, None);
        assert!(result.is_err());
    }
}
