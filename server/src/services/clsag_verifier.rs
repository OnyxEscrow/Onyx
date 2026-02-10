//! Server-side CLSAG verification for debugging signature issues
//!
//! This module replicates Monero's CLSAG verification to catch
//! signature errors BEFORE broadcast to daemon.
//!
//! Reference: monero/src/ringct/rctSigs.cpp verRctCLSAGSimple()

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha3::{Digest, Keccak256};
use tracing::{debug, error, info, warn};

// v0.15.0 FIX: Use the correct Monero hash_to_point implementation
// This uses ge_fromfe_frombytes_vartime (Elligator-like field-to-curve mapping)
// NOT naive "decompress hash as Edwards point" which produces wrong results
use monero_generators_mirror::hash_to_point;

/// Result of CLSAG verification with detailed debug info
#[derive(Debug)]
pub struct ClsagVerificationResult {
    pub valid: bool,
    pub c_computed: [u8; 32],
    pub c_expected: [u8; 32],
    pub mu_p: [u8; 32],
    pub mu_c: [u8; 32],
    pub failure_step: Option<String>,
    pub debug_info: Vec<String>,
}

/// Monero H generator constant from rctTypes.h
const H_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// CLSAG domain separator
const CLSAG_DOMAIN: &[u8] = b"CLSAG_round";
const CLSAG_AGG_0: &[u8] = b"CLSAG_agg_0";
const CLSAG_AGG_1: &[u8] = b"CLSAG_agg_1";

// v0.15.0: Custom hash_to_point REMOVED - was fundamentally incorrect
// Now using monero_generators_mirror::hash_to_point which implements
// the correct ge_fromfe_frombytes_vartime algorithm from Monero

/// Compute mixing coefficients mu_P and mu_C
/// Reference: clsag_hash_agg() in rctSigs.cpp
fn compute_mixing_coefficients(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    // v0.13.1 FIX: Domain separators MUST be 32 bytes padded (Monero uses 32-byte key slots)

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

    // mu_C = H(CLSAG_agg_1 || ring_keys || ring_commitments || I || D || pseudo_out)
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

/// Compute CLSAG round hash (challenge for next position)
/// Reference: clsag_hash() in rctSigs.cpp
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

    // Domain separator - MUST be 32 bytes padded (Monero uses 32-byte key slots)
    // v0.13.1 FIX: Was using 11-byte unpadded, now matches WASM and Monero spec
    let mut domain_sep = [0u8; 32];
    domain_sep[..CLSAG_DOMAIN.len()].copy_from_slice(CLSAG_DOMAIN);
    hasher.update(&domain_sep);

    // Ring keys
    for key in ring_keys {
        hasher.update(key.compress().as_bytes());
    }

    // Ring commitments
    for commitment in ring_commitments {
        hasher.update(commitment.compress().as_bytes());
    }

    // Pseudo output
    hasher.update(pseudo_out.compress().as_bytes());

    // TX prefix hash (message)
    hasher.update(tx_prefix_hash);

    // Key image
    hasher.update(key_image.compress().as_bytes());

    // D point
    hasher.update(d_inv8.compress().as_bytes());

    // L and R points for this round
    hasher.update(l_point.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());

    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);

    Scalar::from_bytes_mod_order(hash_bytes)
}

/// Verify a CLSAG signature
///
/// This replicates Monero's verRctCLSAGSimple() function.
///
/// Verification equation:
/// For each ring member i:
///   L[i] = s[i]*G + c * (mu_P * P[i] + mu_C * (C[i] - pseudo_out))
///   R[i] = s[i]*Hp(P[i]) + c * (mu_P * I + mu_C * D_original)
///   c[i+1] = H(CLSAG_round || ... || L[i] || R[i])
///
/// Valid if c_computed (after full loop) == c1
pub fn verify_clsag(
    s_values: &[[u8; 32]],
    c1: [u8; 32],
    d_inv8_bytes: [u8; 32],
    key_image_bytes: [u8; 32],
    pseudo_out_bytes: [u8; 32],
    ring_keys_bytes: &[[u8; 32]],
    ring_commitments_bytes: &[[u8; 32]],
    tx_prefix_hash: [u8; 32],
) -> ClsagVerificationResult {
    let mut debug_info = Vec::new();
    let ring_size = ring_keys_bytes.len();

    debug_info.push(format!("Ring size: {}", ring_size));
    debug_info.push(format!("c1: {}...", hex::encode(&c1[..8])));
    debug_info.push(format!("D_inv8: {}...", hex::encode(&d_inv8_bytes[..8])));
    debug_info.push(format!(
        "Key image: {}...",
        hex::encode(&key_image_bytes[..8])
    ));
    debug_info.push(format!(
        "Pseudo out: {}...",
        hex::encode(&pseudo_out_bytes[..8])
    ));
    debug_info.push(format!(
        "TX prefix hash: {}...",
        hex::encode(&tx_prefix_hash[..8])
    ));

    // Parse all points
    let d_inv8 = match CompressedEdwardsY(d_inv8_bytes).decompress() {
        Some(p) => p,
        None => {
            return ClsagVerificationResult {
                valid: false,
                c_computed: [0u8; 32],
                c_expected: c1,
                mu_p: [0u8; 32],
                mu_c: [0u8; 32],
                failure_step: Some("Failed to decompress D_inv8".to_string()),
                debug_info,
            };
        }
    };

    let key_image = match CompressedEdwardsY(key_image_bytes).decompress() {
        Some(p) => p,
        None => {
            return ClsagVerificationResult {
                valid: false,
                c_computed: [0u8; 32],
                c_expected: c1,
                mu_p: [0u8; 32],
                mu_c: [0u8; 32],
                failure_step: Some("Failed to decompress key_image".to_string()),
                debug_info,
            };
        }
    };

    let pseudo_out = match CompressedEdwardsY(pseudo_out_bytes).decompress() {
        Some(p) => p,
        None => {
            return ClsagVerificationResult {
                valid: false,
                c_computed: [0u8; 32],
                c_expected: c1,
                mu_p: [0u8; 32],
                mu_c: [0u8; 32],
                failure_step: Some("Failed to decompress pseudo_out".to_string()),
                debug_info,
            };
        }
    };

    // Parse ring keys and commitments
    let mut ring_keys = Vec::with_capacity(ring_size);
    let mut ring_commitments = Vec::with_capacity(ring_size);

    for i in 0..ring_size {
        let key = match CompressedEdwardsY(ring_keys_bytes[i]).decompress() {
            Some(p) => p,
            None => {
                return ClsagVerificationResult {
                    valid: false,
                    c_computed: [0u8; 32],
                    c_expected: c1,
                    mu_p: [0u8; 32],
                    mu_c: [0u8; 32],
                    failure_step: Some(format!("Failed to decompress ring_key[{}]", i)),
                    debug_info,
                };
            }
        };

        let commitment = match CompressedEdwardsY(ring_commitments_bytes[i]).decompress() {
            Some(p) => p,
            None => {
                return ClsagVerificationResult {
                    valid: false,
                    c_computed: [0u8; 32],
                    c_expected: c1,
                    mu_p: [0u8; 32],
                    mu_c: [0u8; 32],
                    failure_step: Some(format!("Failed to decompress ring_commitment[{}]", i)),
                    debug_info,
                };
            }
        };

        ring_keys.push(key);
        ring_commitments.push(commitment);
    }

    // Parse s values
    let mut s_scalars = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        s_scalars.push(Scalar::from_bytes_mod_order(s_values[i]));
    }

    // Compute mixing coefficients
    let (mu_p, mu_c) = compute_mixing_coefficients(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );

    debug_info.push(format!("mu_P: {}...", hex::encode(&mu_p.to_bytes()[..8])));
    debug_info.push(format!("mu_C: {}...", hex::encode(&mu_c.to_bytes()[..8])));

    // D_original = D_inv8 * 8 (undo the /8 from signing)
    let d_original = d_inv8 * Scalar::from(8u64);
    debug_info.push(format!(
        "D_original: {}...",
        hex::encode(&d_original.compress().to_bytes()[..8])
    ));

    // Precompute Hp(P[i]) for all ring members
    let mut hp_values: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);
    for key in &ring_keys {
        hp_values.push(hash_to_point(key.compress().to_bytes()));
    }

    // Start verification loop
    // v0.42.0 FIX: CLSAG verification processes indices in order: 1, 2, ..., n-1, 0
    // c1 is the challenge going INTO index 1 (not index 0!)
    let mut c = Scalar::from_bytes_mod_order(c1);

    for i in 0..ring_size {
        // v0.42.0 FIX: Process in CLSAG order (1, 2, ..., n-1, 0)
        let idx = (i + 1) % ring_size;
        let s = s_scalars[idx];
        let p_i = ring_keys[idx];
        let c_i = ring_commitments[idx];
        let hp_i = hp_values[idx];

        // c_p = mu_P * c
        let c_p = mu_p * c;
        // c_c = mu_C * c
        let c_c = mu_c * c;

        // L[idx] = s*G + c_p*P[idx] + c_c*(C[idx] - pseudo_out)
        let c_adjusted = c_i - pseudo_out;
        let l_point = &s * ED25519_BASEPOINT_TABLE + c_p * p_i + c_c * c_adjusted;

        // R[idx] = s*Hp(P[idx]) + c_p*I + c_c*D_original
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

        if idx < 3 || idx == ring_size - 1 {
            debug_info.push(format!(
                "Round {} (idx={}): L={}..., R={}..., c_next={}...",
                i,
                idx,
                hex::encode(&l_point.compress().to_bytes()[..8]),
                hex::encode(&r_point.compress().to_bytes()[..8]),
                hex::encode(&c_next.to_bytes()[..8])
            ));
        }
        // v0.32.0 DEBUG: Show c value going INTO signer position
        if idx == ring_size - 1 {
            debug_info.push(format!(
                "Round {} (idx={}) INPUT: c={}, s={}..., c_p={}..., c_c={}...",
                i,
                idx,
                hex::encode(&c.to_bytes()),
                hex::encode(&s.to_bytes()[..8]),
                hex::encode(&c_p.to_bytes()[..8]),
                hex::encode(&c_c.to_bytes()[..8])
            ));
        }

        c = c_next;
    }

    // After full loop, c should equal c1
    let c_computed = c.to_bytes();
    let valid = c_computed == c1;

    debug_info.push(format!("c_computed: {}", hex::encode(&c_computed)));
    debug_info.push(format!("c_expected: {}", hex::encode(&c1)));
    debug_info.push(format!("MATCH: {}", valid));

    ClsagVerificationResult {
        valid,
        c_computed,
        c_expected: c1,
        mu_p: mu_p.to_bytes(),
        mu_c: mu_c.to_bytes(),
        failure_step: if valid {
            None
        } else {
            Some("c_computed != c1".to_string())
        },
        debug_info,
    }
}

/// v0.37.0: Verify CLSAG with externally provided mu_P/mu_C
///
/// This version uses STORED mu values from the first signer instead of recomputing.
/// CRITICAL: If mu values were computed by the first signer and stored in the escrow,
/// they MUST be passed here to ensure verification uses the exact same values as signing.
///
/// If stored_mu_p and stored_mu_c are None, falls back to recomputation (legacy behavior).
pub fn verify_clsag_with_mu(
    s_values: &[[u8; 32]],
    c1: [u8; 32],
    d_inv8_bytes: [u8; 32],
    key_image_bytes: [u8; 32],
    pseudo_out_bytes: [u8; 32],
    ring_keys_bytes: &[[u8; 32]],
    ring_commitments_bytes: &[[u8; 32]],
    tx_prefix_hash: [u8; 32],
    stored_mu_p: Option<[u8; 32]>,
    stored_mu_c: Option<[u8; 32]>,
) -> ClsagVerificationResult {
    let mut debug_info = Vec::new();
    let ring_size = ring_keys_bytes.len();

    debug_info.push(format!("Ring size: {}", ring_size));
    debug_info.push(format!("c1: {}...", hex::encode(&c1[..8])));
    debug_info.push(format!("D_inv8: {}...", hex::encode(&d_inv8_bytes[..8])));
    debug_info.push(format!(
        "Key image: {}...",
        hex::encode(&key_image_bytes[..8])
    ));
    debug_info.push(format!(
        "Pseudo out: {}...",
        hex::encode(&pseudo_out_bytes[..8])
    ));
    debug_info.push(format!(
        "TX prefix hash: {}...",
        hex::encode(&tx_prefix_hash[..8])
    ));
    debug_info.push(format!(
        "[v0.37.0] stored_mu_p: {}, stored_mu_c: {}",
        stored_mu_p
            .map(|m| format!("{}...", hex::encode(&m[..8])))
            .unwrap_or_else(|| "NONE".to_string()),
        stored_mu_c
            .map(|m| format!("{}...", hex::encode(&m[..8])))
            .unwrap_or_else(|| "NONE".to_string())
    ));

    // Parse all points
    let d_inv8 = match CompressedEdwardsY(d_inv8_bytes).decompress() {
        Some(p) => p,
        None => {
            return ClsagVerificationResult {
                valid: false,
                c_computed: [0u8; 32],
                c_expected: c1,
                mu_p: [0u8; 32],
                mu_c: [0u8; 32],
                failure_step: Some("Failed to decompress D_inv8".to_string()),
                debug_info,
            };
        }
    };

    let key_image = match CompressedEdwardsY(key_image_bytes).decompress() {
        Some(p) => p,
        None => {
            return ClsagVerificationResult {
                valid: false,
                c_computed: [0u8; 32],
                c_expected: c1,
                mu_p: [0u8; 32],
                mu_c: [0u8; 32],
                failure_step: Some("Failed to decompress key_image".to_string()),
                debug_info,
            };
        }
    };

    let pseudo_out = match CompressedEdwardsY(pseudo_out_bytes).decompress() {
        Some(p) => p,
        None => {
            return ClsagVerificationResult {
                valid: false,
                c_computed: [0u8; 32],
                c_expected: c1,
                mu_p: [0u8; 32],
                mu_c: [0u8; 32],
                failure_step: Some("Failed to decompress pseudo_out".to_string()),
                debug_info,
            };
        }
    };

    // Parse ring keys and commitments
    let mut ring_keys = Vec::with_capacity(ring_size);
    let mut ring_commitments = Vec::with_capacity(ring_size);

    for i in 0..ring_size {
        let key = match CompressedEdwardsY(ring_keys_bytes[i]).decompress() {
            Some(p) => p,
            None => {
                return ClsagVerificationResult {
                    valid: false,
                    c_computed: [0u8; 32],
                    c_expected: c1,
                    mu_p: [0u8; 32],
                    mu_c: [0u8; 32],
                    failure_step: Some(format!("Failed to decompress ring_key[{}]", i)),
                    debug_info,
                };
            }
        };

        let commitment = match CompressedEdwardsY(ring_commitments_bytes[i]).decompress() {
            Some(p) => p,
            None => {
                return ClsagVerificationResult {
                    valid: false,
                    c_computed: [0u8; 32],
                    c_expected: c1,
                    mu_p: [0u8; 32],
                    mu_c: [0u8; 32],
                    failure_step: Some(format!("Failed to decompress ring_commitment[{}]", i)),
                    debug_info,
                };
            }
        };

        ring_keys.push(key);
        ring_commitments.push(commitment);
    }

    // Parse s values
    let mut s_scalars = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        s_scalars.push(Scalar::from_bytes_mod_order(s_values[i]));
    }

    // v0.37.0: Use stored mu values if provided, otherwise compute
    let (mu_p, mu_c) = match (stored_mu_p, stored_mu_c) {
        (Some(mu_p_bytes), Some(mu_c_bytes)) => {
            debug_info.push("[v0.37.0] Using STORED mu_p/mu_c from first signer".to_string());
            (
                Scalar::from_bytes_mod_order(mu_p_bytes),
                Scalar::from_bytes_mod_order(mu_c_bytes),
            )
        }
        _ => {
            debug_info.push(
                "[v0.37.0] FALLBACK: Recomputing mu_p/mu_c (stored values not available)"
                    .to_string(),
            );
            compute_mixing_coefficients(
                &ring_keys,
                &ring_commitments,
                &key_image,
                &d_inv8,
                &pseudo_out,
            )
        }
    };

    debug_info.push(format!("mu_P: {}...", hex::encode(&mu_p.to_bytes()[..8])));
    debug_info.push(format!("mu_C: {}...", hex::encode(&mu_c.to_bytes()[..8])));

    // v0.41.0 DIAGNOSTIC: Log FULL mu values for comparison with WASM
    debug_info.push(format!(
        "[v0.41.0 DIAG] VERIFIER mu_p FULL: {}",
        hex::encode(&mu_p.to_bytes())
    ));
    debug_info.push(format!(
        "[v0.41.0 DIAG] VERIFIER mu_c FULL: {}",
        hex::encode(&mu_c.to_bytes())
    ));

    // v0.41.0 DIAGNOSTIC: Log all s values for comparison
    debug_info.push(format!(
        "[v0.41.0 DIAG] VERIFIER s[0] FULL: {}",
        hex::encode(&s_scalars[0].to_bytes())
    ));
    if ring_size > 1 {
        debug_info.push(format!(
            "[v0.41.0 DIAG] VERIFIER s[1] FULL: {}",
            hex::encode(&s_scalars[1].to_bytes())
        ));
    }

    // D_original = D_inv8 * 8 (undo the /8 from signing)
    let d_original = d_inv8 * Scalar::from(8u64);
    debug_info.push(format!(
        "D_original: {}...",
        hex::encode(&d_original.compress().to_bytes()[..8])
    ));

    // Precompute Hp(P[i]) for all ring members
    let mut hp_values: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);
    for key in &ring_keys {
        hp_values.push(hash_to_point(key.compress().to_bytes()));
    }

    // v0.41.0 DIAGNOSTIC: Log Hp(P[0]) for comparison with WASM
    if !hp_values.is_empty() {
        debug_info.push(format!(
            "[v0.41.0 DIAG] VERIFIER Hp(P[0]) FULL: {}",
            hex::encode(&hp_values[0].compress().to_bytes())
        ));
        debug_info.push(format!(
            "[v0.41.0 DIAG] VERIFIER P[0] (ring_key[0]) FULL: {}",
            hex::encode(&ring_keys[0].compress().to_bytes())
        ));
    }

    // Start verification loop
    // v0.42.0 FIX: CLSAG verification processes indices in order: 1, 2, ..., n-1, 0
    // c1 is the challenge going INTO index 1 (not index 0!)
    let mut c = Scalar::from_bytes_mod_order(c1);

    for i in 0..ring_size {
        // v0.42.0 FIX: Process in CLSAG order (1, 2, ..., n-1, 0)
        let idx = (i + 1) % ring_size;
        let s = s_scalars[idx];
        let p_i = ring_keys[idx];
        let c_i = ring_commitments[idx];
        let hp_i = hp_values[idx];

        // c_p = mu_P * c
        let c_p = mu_p * c;
        // c_c = mu_C * c
        let c_c = mu_c * c;

        // L[idx] = s*G + c_p*P[idx] + c_c*(C[idx] - pseudo_out)
        let c_adjusted = c_i - pseudo_out;
        let l_point = &s * ED25519_BASEPOINT_TABLE + c_p * p_i + c_c * c_adjusted;

        // R[idx] = s*Hp(P[idx]) + c_p*I + c_c*D_original
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

        // v0.41.0 DIAGNOSTIC: Log FULL values at first iteration (idx=1)
        if i == 0 {
            debug_info.push(format!(
                "[v0.42.0] VERIFIER Round {} (idx={}) c (input c1): {}",
                i,
                idx,
                hex::encode(&c.to_bytes())
            ));
            debug_info.push(format!(
                "[v0.42.0] VERIFIER Round {} c_p FULL (mu_p * c): {}",
                i,
                hex::encode(&c_p.to_bytes())
            ));
            debug_info.push(format!(
                "[v0.42.0] VERIFIER Round {} c_c FULL (mu_c * c): {}",
                i,
                hex::encode(&c_c.to_bytes())
            ));
            debug_info.push(format!(
                "[v0.42.0] VERIFIER Round {} L: {}",
                i,
                hex::encode(&l_point.compress().to_bytes())
            ));
            debug_info.push(format!(
                "[v0.42.0] VERIFIER Round {} R: {}",
                i,
                hex::encode(&r_point.compress().to_bytes())
            ));
        }

        if idx < 3 || idx == ring_size - 1 {
            debug_info.push(format!(
                "Round {} (idx={}): L={}..., R={}..., c_next={}...",
                i,
                idx,
                hex::encode(&l_point.compress().to_bytes()[..8]),
                hex::encode(&r_point.compress().to_bytes()[..8]),
                hex::encode(&c_next.to_bytes()[..8])
            ));
        }
        if idx == ring_size - 1 {
            debug_info.push(format!(
                "Round {} (idx={}) INPUT: c={}, s={}..., c_p={}..., c_c={}...",
                i,
                idx,
                hex::encode(&c.to_bytes()),
                hex::encode(&s.to_bytes()[..8]),
                hex::encode(&c_p.to_bytes()[..8]),
                hex::encode(&c_c.to_bytes()[..8])
            ));
            // v0.41.1 DIAGNOSTIC: Show ring commitment at signer position
            debug_info.push(format!(
                "[v0.41.1 DIAG] SIGNER_POS ring_commitment[{}] = {}",
                idx,
                hex::encode(&c_i.compress().to_bytes())
            ));
            debug_info.push(format!(
                "[v0.41.1 DIAG] SIGNER_POS C[{}] - pseudo_out = {}",
                idx,
                hex::encode(&c_adjusted.compress().to_bytes())
            ));
        }

        c = c_next;
    }

    // After full loop, c should equal c1
    let c_computed = c.to_bytes();
    let valid = c_computed == c1;

    debug_info.push(format!("c_computed: {}", hex::encode(&c_computed)));
    debug_info.push(format!("c_expected: {}", hex::encode(&c1)));
    debug_info.push(format!("MATCH: {}", valid));

    ClsagVerificationResult {
        valid,
        c_computed,
        c_expected: c1,
        mu_p: mu_p.to_bytes(),
        mu_c: mu_c.to_bytes(),
        failure_step: if valid {
            None
        } else {
            Some("c_computed != c1".to_string())
        },
        debug_info,
    }
}

/// Log verification result with all debug info
pub fn log_verification_result(result: &ClsagVerificationResult, escrow_id: &str) {
    if result.valid {
        info!(
            escrow_id = %escrow_id,
            "CLSAG verification PASSED"
        );
    } else {
        error!(
            escrow_id = %escrow_id,
            c_computed = %hex::encode(&result.c_computed),
            c_expected = %hex::encode(&result.c_expected),
            mu_p = %hex::encode(&result.mu_p),
            mu_c = %hex::encode(&result.mu_c),
            failure_step = ?result.failure_step,
            "CLSAG verification FAILED"
        );
    }

    for line in &result.debug_info {
        if result.valid {
            debug!(escrow_id = %escrow_id, "{}", line);
        } else {
            warn!(escrow_id = %escrow_id, "[CLSAG-DEBUG] {}", line);
        }
    }
}

/// Compute mixing coefficients mu_P and mu_C from hex strings
///
/// This is the PUBLIC function used by prepare_sign to compute
/// the mixing coefficients that will be sent to BOTH signers,
/// ensuring they use identical values.
///
/// Returns: (mu_p_hex, mu_c_hex) as 64-char hex strings
pub fn compute_mu_from_hex(
    ring_keys_hex: &[String],
    ring_commitments_hex: &[String],
    key_image_hex: &str,
    d_inv8_hex: &str,
    pseudo_out_hex: &str,
) -> Result<(String, String), String> {
    // Parse helper
    let parse_point = |hex_str: &str, name: &str| -> Result<EdwardsPoint, String> {
        let bytes =
            hex::decode(hex_str).map_err(|e| format!("Failed to decode {} hex: {}", name, e))?;
        if bytes.len() != 32 {
            return Err(format!("{} must be 32 bytes, got {}", name, bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        CompressedEdwardsY(arr)
            .decompress()
            .ok_or_else(|| format!("Failed to decompress {} point", name))
    };

    // Parse all ring keys
    let ring_keys: Vec<EdwardsPoint> = ring_keys_hex
        .iter()
        .enumerate()
        .map(|(i, hex)| parse_point(hex, &format!("ring_key[{}]", i)))
        .collect::<Result<Vec<_>, _>>()?;

    // Parse all ring commitments
    let ring_commitments: Vec<EdwardsPoint> = ring_commitments_hex
        .iter()
        .enumerate()
        .map(|(i, hex)| parse_point(hex, &format!("ring_commitment[{}]", i)))
        .collect::<Result<Vec<_>, _>>()?;

    // Parse key image, D, pseudo_out
    let key_image = parse_point(key_image_hex, "key_image")?;
    let d_inv8 = parse_point(d_inv8_hex, "d_inv8")?;
    let pseudo_out = parse_point(pseudo_out_hex, "pseudo_out")?;

    // Compute mixing coefficients
    let (mu_p, mu_c) = compute_mixing_coefficients(
        &ring_keys,
        &ring_commitments,
        &key_image,
        &d_inv8,
        &pseudo_out,
    );

    Ok((hex::encode(mu_p.to_bytes()), hex::encode(mu_c.to_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_point_encoding() {
        let identity = EdwardsPoint::identity();
        let compressed = identity.compress().to_bytes();
        println!("Identity point compressed: {}", hex::encode(&compressed));

        // Identity point should be (0, 1) which compresses to specific bytes
        // y = 1 encoded in little-endian, with sign bit clear
        assert_eq!(compressed[0], 0x01);
        for i in 1..32 {
            assert_eq!(compressed[i], 0x00);
        }
    }

    #[test]
    fn test_mixing_coefficients_deterministic() {
        // Test that mixing coefficients are deterministic
        let ring_keys = vec![EdwardsPoint::identity(); 2];
        let ring_commitments = vec![EdwardsPoint::identity(); 2];
        let key_image = EdwardsPoint::identity();
        let d_inv8 = EdwardsPoint::identity();
        let pseudo_out = EdwardsPoint::identity();

        let (mu_p1, mu_c1) = compute_mixing_coefficients(
            &ring_keys,
            &ring_commitments,
            &key_image,
            &d_inv8,
            &pseudo_out,
        );

        let (mu_p2, mu_c2) = compute_mixing_coefficients(
            &ring_keys,
            &ring_commitments,
            &key_image,
            &d_inv8,
            &pseudo_out,
        );

        assert_eq!(mu_p1.to_bytes(), mu_p2.to_bytes());
        assert_eq!(mu_c1.to_bytes(), mu_c2.to_bytes());
    }
}
