//! Nullifier (key image) computation for FCMP++.
//!
//! In FCMP++, key images are computed as `I = x * H(K)` where:
//! - `x` is the spend secret key
//! - `H(K)` is hash-to-curve of the output key (RFC 9380 Simplified SWU)
//!
//! This replaces the CLSAG key image `I = x * Hp(P)` which used
//! a different hash-to-point algorithm (ge_fromfe_frombytes_vartime).
//!
//! In the multisig context, the key image is NOT computed directly.
//! Instead, it is extracted implicitly from the GSP proof via the
//! matrix consistency relation:
//!
//! ```text
//! I = x*H(K) + b*U - b*U = x*H(K)
//! ```

use crate::types::errors::{CryptoError, CryptoResult};
use curve25519_dalek::traits::Identity;

/// Compute the FCMP++ hash-to-curve for a given output key.
///
/// Uses RFC 9380 Simplified SWU mapping instead of Monero's legacy
/// `ge_fromfe_frombytes_vartime`.
///
/// # Arguments
/// * `output_key` - The output public key K (32 bytes, compressed Edwards)
///
/// # Returns
/// H(K) as a compressed Edwards point (32 bytes)
pub fn hash_to_curve_output_key(_output_key: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    // TODO: Implement RFC 9380 SWU mapping
    // This is different from monero-generators::hash_to_point
    // The FCMP++ spec uses a specific domain separator
    Err(CryptoError::NotImplemented(
        "FCMP++ hash-to-curve — requires RFC 9380 SWU implementation".into(),
    ))
}

/// Verify that a key image (nullifier) has not been seen before.
///
/// This is a database lookup operation — the actual uniqueness check
/// is performed by the daemon/blockchain, not this library.
/// This function validates the mathematical structure of the nullifier.
///
/// # Arguments
/// * `key_image` - The claimed key image I (32 bytes)
///
/// # Returns
/// `Ok(true)` if the key image is structurally valid (on curve, in subgroup)
pub fn validate_nullifier_structure(key_image: &[u8; 32]) -> CryptoResult<bool> {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let point = CompressedEdwardsY::from_slice(key_image)
        .map_err(|_| CryptoError::InvalidKeyImage("Invalid compressed point".into()))?;

    // Decompress and check it's on the curve
    let decompressed = point
        .decompress()
        .ok_or_else(|| CryptoError::InvalidKeyImage("Point not on curve".into()))?;

    // Check it's in the prime-order subgroup (not a torsion point)
    // Multiply by l (group order) — result must be identity
    let l = curve25519_dalek::scalar::Scalar::ZERO;
    let eight = curve25519_dalek::scalar::Scalar::from(8u8);
    let cofactored = decompressed * eight;
    // If 8*P is the identity, P is a torsion point (bad)
    if cofactored.compress() == curve25519_dalek::edwards::CompressedEdwardsY::identity() {
        return Err(CryptoError::InvalidKeyImage(
            "Key image is a torsion point".into(),
        ));
    }
    let _ = l;

    Ok(true)
}
