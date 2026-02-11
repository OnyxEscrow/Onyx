//! CLSAG types for signatures and verification.

use alloc::string::String;
use alloc::vec::Vec;

/// A completed CLSAG signature.
///
/// This represents a valid CLSAG ring signature that can be included
/// in a Monero transaction.
#[derive(Debug, Clone)]
pub struct ClsagSignature {
    /// S values for each ring member (hex, 32 bytes each).
    pub s_values: Vec<String>,

    /// Initial challenge c1 (hex, 32 bytes).
    pub c1: String,

    /// D point (hex, 32 bytes compressed).
    ///
    /// D = z * Hp(P) where z is the mask delta.
    /// Stored as `D_inv8` = D / 8 in the signature.
    pub d: String,

    /// Pseudo-output commitment (hex, 32 bytes compressed).
    ///
    /// `pseudo_out` = amount * H + `output_mask` * G
    pub pseudo_out: String,

    /// Key image (hex, 32 bytes compressed).
    ///
    /// KI = x * Hp(P) where x is the effective spend key.
    pub key_image: String,
}

/// Result of CLSAG signature verification.
///
/// Contains detailed debugging information for diagnosing
/// signature verification failures.
#[derive(Debug)]
pub struct ClsagVerificationResult {
    /// Whether the signature is valid.
    pub valid: bool,

    /// Computed challenge after completing the ring loop.
    pub c_computed: [u8; 32],

    /// Expected challenge (c1 from the signature).
    pub c_expected: [u8; 32],

    /// Mixing coefficient `μ_P` used in verification.
    pub mu_p: [u8; 32],

    /// Mixing coefficient `μ_C` used in verification.
    pub mu_c: [u8; 32],

    /// Description of the step where verification failed (if any).
    pub failure_step: Option<String>,

    /// Detailed debug information from each verification step.
    pub debug_info: Vec<String>,
}

impl ClsagVerificationResult {
    /// Create a successful verification result.
    #[must_use]
    pub fn success(
        c_computed: [u8; 32],
        c_expected: [u8; 32],
        mu_p: [u8; 32],
        mu_c: [u8; 32],
        debug_info: Vec<String>,
    ) -> Self {
        Self {
            valid: true,
            c_computed,
            c_expected,
            mu_p,
            mu_c,
            failure_step: None,
            debug_info,
        }
    }

    /// Create a failed verification result.
    #[must_use]
    pub fn failure(
        c_computed: [u8; 32],
        c_expected: [u8; 32],
        mu_p: [u8; 32],
        mu_c: [u8; 32],
        failure_step: String,
        debug_info: Vec<String>,
    ) -> Self {
        Self {
            valid: false,
            c_computed,
            c_expected,
            mu_p,
            mu_c,
            failure_step: Some(failure_step),
            debug_info,
        }
    }

    /// Create an early failure result (before mu computation).
    #[must_use]
    pub fn early_failure(
        c_expected: [u8; 32],
        failure_step: String,
        debug_info: Vec<String>,
    ) -> Self {
        Self {
            valid: false,
            c_computed: [0u8; 32],
            c_expected,
            mu_p: [0u8; 32],
            mu_c: [0u8; 32],
            failure_step: Some(failure_step),
            debug_info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clsag_verification_result_success() {
        let result = ClsagVerificationResult::success(
            [1u8; 32],
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            vec!["test".into()],
        );
        assert!(result.valid);
        assert!(result.failure_step.is_none());
    }

    #[test]
    fn test_clsag_verification_result_failure() {
        let result = ClsagVerificationResult::failure(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            "c mismatch".to_string(),
            vec![],
        );
        assert!(!result.valid);
        assert_eq!(result.failure_step.as_deref(), Some("c mismatch"));
    }
}
