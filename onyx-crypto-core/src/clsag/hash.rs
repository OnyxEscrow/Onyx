//! CLSAG hashing functions for mixing coefficients and round challenges.
//!
//! These functions implement the hash computations used in CLSAG signatures,
//! matching Monero's rctSigs.cpp implementation.

use curve25519_dalek::{edwards::EdwardsPoint, Scalar};
use sha3::{Digest, Keccak256};

use super::constants::{pad_domain_separator, CLSAG_AGG_0, CLSAG_AGG_1, CLSAG_DOMAIN};

/// Compute mixing coefficients `μ_P` and `μ_C` for CLSAG.
///
/// Reference: `clsag_hash_agg()` in Monero's rctSigs.cpp
///
/// # Formula
/// ```text
/// μ_P = H(CLSAG_agg_0 || ring_keys || ring_commitments || I || D || pseudo_out)
/// μ_C = H(CLSAG_agg_1 || ring_keys || ring_commitments || I || D || pseudo_out)
/// ```
///
/// # Arguments
/// * `ring_keys` - Public keys in the ring
/// * `ring_commitments` - Pedersen commitments in the ring
/// * `key_image` - Key image I = x * Hp(P)
/// * `d_inv8` - D point divided by 8 (as stored in signature)
/// * `pseudo_out` - Pseudo-output commitment
///
/// # Returns
/// Tuple `(μ_P, μ_C)` as scalars
#[must_use]
pub fn compute_mixing_coefficients(
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    // μ_P = H(CLSAG_agg_0 || ring || I || D || pseudo_out)
    let mut hasher_p = Keccak256::new();
    hasher_p.update(pad_domain_separator(CLSAG_AGG_0));

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

    // μ_C = H(CLSAG_agg_1 || ring || I || D || pseudo_out)
    let mut hasher_c = Keccak256::new();
    hasher_c.update(pad_domain_separator(CLSAG_AGG_1));

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

/// Compute CLSAG round hash (challenge for next ring position).
///
/// Reference: `clsag_hash()` in Monero's rctSigs.cpp
///
/// # Formula
/// ```text
/// c[i+1] = H(CLSAG_round || ring_keys || ring_commitments || pseudo_out ||
///            tx_prefix_hash || I || D || L[i] || R[i])
/// ```
///
/// # Arguments
/// * `ring_keys` - Public keys in the ring
/// * `ring_commitments` - Pedersen commitments in the ring
/// * `pseudo_out` - Pseudo-output commitment
/// * `tx_prefix_hash` - Transaction prefix hash (message being signed)
/// * `key_image` - Key image I
/// * `d_inv8` - D point divided by 8
/// * `l_point` - L point for current round
/// * `r_point` - R point for current round
///
/// # Returns
/// Challenge scalar for the next ring position
#[must_use]
pub fn compute_round_hash(
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

    // Domain separator (32 bytes padded)
    hasher.update(pad_domain_separator(CLSAG_DOMAIN));

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

/// Compute hash-to-scalar (Monero's Hs function).
///
/// This is Keccak256 with the result interpreted as a scalar mod l.
#[inline]
#[must_use]
pub fn keccak256_to_scalar(data: &[u8]) -> Scalar {
    let hash = Keccak256::digest(data);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    #[test]
    fn test_mixing_coefficients_deterministic() {
        let key = ED25519_BASEPOINT_POINT;
        let ring_keys = vec![key, key];
        let ring_commitments = vec![key, key];

        let (mu_p1, mu_c1) =
            compute_mixing_coefficients(&ring_keys, &ring_commitments, &key, &key, &key);

        let (mu_p2, mu_c2) =
            compute_mixing_coefficients(&ring_keys, &ring_commitments, &key, &key, &key);

        assert_eq!(mu_p1, mu_p2);
        assert_eq!(mu_c1, mu_c2);
    }

    #[test]
    fn test_round_hash_deterministic() {
        let key = ED25519_BASEPOINT_POINT;
        let ring_keys = vec![key, key];
        let ring_commitments = vec![key, key];
        let tx_hash = [0u8; 32];

        let c1 = compute_round_hash(
            &ring_keys,
            &ring_commitments,
            &key,
            &tx_hash,
            &key,
            &key,
            &key,
            &key,
        );

        let c2 = compute_round_hash(
            &ring_keys,
            &ring_commitments,
            &key,
            &tx_hash,
            &key,
            &key,
            &key,
            &key,
        );

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_keccak256_to_scalar() {
        let data = b"test data";
        let scalar = keccak256_to_scalar(data);

        // Should be deterministic
        let scalar2 = keccak256_to_scalar(data);
        assert_eq!(scalar, scalar2);

        // Different data should give different scalar
        let scalar3 = keccak256_to_scalar(b"different");
        assert_ne!(scalar, scalar3);
    }
}
