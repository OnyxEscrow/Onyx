//! Lagrange Coefficient Computation
//!
//! Computes Lagrange coefficients for threshold signature reconstruction.
//! For 2-of-3 threshold signing, the Lagrange coefficient determines how to
//! reconstruct the group secret from the participating shares.

use alloc::format;
use alloc::string::String;

use curve25519_dalek::scalar::Scalar;

use crate::types::errors::{CryptoError, CryptoResult};

/// Compute Lagrange coefficient for a signer in a signing session
///
/// For 2-of-3 threshold signing, the Lagrange coefficient determines how to
/// reconstruct the group secret from the participating shares.
///
/// # Arguments
/// * `signer_index` - The index of the signer computing their coefficient (1, 2, or 3)
/// * `signer1_index` - First participating signer index
/// * `signer2_index` - Second participating signer index
///
/// # Returns
/// * `Ok(String)` - The Lagrange coefficient as a 64-character hex scalar
/// * `Err(CryptoError)` - If the signer is not one of the participants
///
/// # Mathematical Background
/// For 2-of-3 with signers i and j participating:
/// - `λ_i` = j / (j - i)
/// - `λ_j` = i / (i - j)
///
/// These coefficients satisfy: `λ_i` + `λ_j` = 1 (at x=0)
///
/// # Example
/// ```rust
/// use onyx_crypto_core::frost::compute_lagrange_coefficient;
///
/// // For signers 1 and 2 participating:
/// let lambda_1 = compute_lagrange_coefficient(1, 1, 2)?;
/// let lambda_2 = compute_lagrange_coefficient(2, 1, 2)?;
/// # Ok::<(), onyx_crypto_core::CryptoError>(())
/// ```
pub fn compute_lagrange_coefficient(
    signer_index: u16,
    signer1_index: u16,
    signer2_index: u16,
) -> CryptoResult<String> {
    // Validate that signer_index is one of the participants
    if signer_index != signer1_index && signer_index != signer2_index {
        return Err(CryptoError::FrostDkgError(format!(
            "signer_index {signer_index} must be one of the participating indices [{signer1_index}, {signer2_index}]"
        )));
    }

    // Compute Lagrange coefficient: λ_i = ∏(0 - j) / (i - j) for j ≠ i
    // For 2-of-3 with indices i and j participating:
    // λ_i = (0 - j) / (i - j) = -j / (i - j) = j / (j - i)

    let i = i64::from(signer_index);
    let j = i64::from(if signer_index == signer1_index {
        signer2_index
    } else {
        signer1_index
    });

    // λ_i = j / (j - i)
    // In scalar field: λ_i = j * inverse(j - i)

    let numerator = Scalar::from(j as u64);
    let denominator_val = j - i;

    let denominator = if denominator_val < 0 {
        -Scalar::from((-denominator_val) as u64)
    } else {
        Scalar::from(denominator_val as u64)
    };

    let denominator_inv = denominator.invert();
    let lambda = numerator * denominator_inv;

    Ok(hex::encode(lambda.as_bytes()))
}

/// Convert a role string to participant index
///
/// # Arguments
/// * `role` - One of "buyer", "vendor", "arbiter" (case insensitive)
///
/// # Returns
/// * `Ok(u16)` - The index (1, 2, or 3)
/// * `Err(CryptoError)` - If the role is unknown
pub fn role_to_index(role: &str) -> CryptoResult<u16> {
    match role.to_lowercase().as_str() {
        "buyer" => Ok(1),
        "vendor" => Ok(2),
        "arbiter" => Ok(3),
        _ => Err(CryptoError::FrostDkgError(format!("Unknown role: {role}"))),
    }
}

/// Convert a participant index to role string
///
/// # Arguments
/// * `index` - The participant index (1, 2, or 3)
///
/// # Returns
/// * `Ok(&'static str)` - The role name
/// * `Err(CryptoError)` - If the index is invalid
pub fn index_to_role(index: u16) -> CryptoResult<&'static str> {
    match index {
        1 => Ok("buyer"),
        2 => Ok("vendor"),
        3 => Ok("arbiter"),
        _ => Err(CryptoError::FrostDkgError(format!(
            "Invalid index: {index}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lagrange_coefficients_1_2() {
        // For 2-of-3 with signers 1 and 2:
        // λ_1 = 2 / (2 - 1) = 2
        // λ_2 = 1 / (1 - 2) = 1 / (-1) = -1

        let lambda1 = compute_lagrange_coefficient(1, 1, 2).expect("lambda1");
        let lambda2 = compute_lagrange_coefficient(2, 1, 2).expect("lambda2");

        // Verify they're non-empty hex strings
        assert_eq!(lambda1.len(), 64);
        assert_eq!(lambda2.len(), 64);

        // They should be different
        assert_ne!(lambda1, lambda2);
    }

    #[test]
    fn test_lagrange_coefficients_1_3() {
        // For signers 1 and 3:
        // λ_1 = 3 / (3 - 1) = 3/2
        // λ_3 = 1 / (1 - 3) = 1 / (-2) = -1/2

        let lambda1 = compute_lagrange_coefficient(1, 1, 3).expect("lambda1");
        let lambda3 = compute_lagrange_coefficient(3, 1, 3).expect("lambda3");

        assert_eq!(lambda1.len(), 64);
        assert_eq!(lambda3.len(), 64);
        assert_ne!(lambda1, lambda3);
    }

    #[test]
    fn test_lagrange_coefficients_2_3() {
        // For signers 2 and 3:
        // λ_2 = 3 / (3 - 2) = 3
        // λ_3 = 2 / (2 - 3) = 2 / (-1) = -2

        let lambda2 = compute_lagrange_coefficient(2, 2, 3).expect("lambda2");
        let lambda3 = compute_lagrange_coefficient(3, 2, 3).expect("lambda3");

        assert_eq!(lambda2.len(), 64);
        assert_eq!(lambda3.len(), 64);
        assert_ne!(lambda2, lambda3);
    }

    #[test]
    fn test_lagrange_invalid_signer() {
        // Signer 3 trying to compute coefficient when only 1 and 2 are participating
        let result = compute_lagrange_coefficient(3, 1, 2);
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::FrostDkgError(_))));
    }

    #[test]
    fn test_role_to_index() {
        assert_eq!(role_to_index("buyer").unwrap(), 1);
        assert_eq!(role_to_index("BUYER").unwrap(), 1);
        assert_eq!(role_to_index("vendor").unwrap(), 2);
        assert_eq!(role_to_index("Vendor").unwrap(), 2);
        assert_eq!(role_to_index("arbiter").unwrap(), 3);
        assert_eq!(role_to_index("ARBITER").unwrap(), 3);
    }

    #[test]
    fn test_role_to_index_invalid() {
        let result = role_to_index("unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_index_to_role() {
        assert_eq!(index_to_role(1).unwrap(), "buyer");
        assert_eq!(index_to_role(2).unwrap(), "vendor");
        assert_eq!(index_to_role(3).unwrap(), "arbiter");
    }

    #[test]
    fn test_index_to_role_invalid() {
        assert!(index_to_role(0).is_err());
        assert!(index_to_role(4).is_err());
    }
}
