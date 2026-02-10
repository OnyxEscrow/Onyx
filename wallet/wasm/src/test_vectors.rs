//! CLSAG Test Vector Validation
//!
//! This module validates the WASM CLSAG implementation against known test vectors.
//! Each checkpoint is compared to ensure the implementation matches the reference.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar,
};
use monero_generators::hash_to_point;
use sha3::{Digest, Keccak256};

/// Reference test vectors (from server/src/bin/clsag_test_vectors.rs)
pub struct ClsagTestVectors {
    // Inputs
    pub x1: [u8; 32],
    pub x2: [u8; 32],
    pub alpha1: [u8; 32],
    pub alpha2: [u8; 32],
    pub z_funding_mask: [u8; 32],
    pub pseudo_out_mask: [u8; 32],
    pub ring_size: usize,
    pub real_index: usize,

    // Expected intermediate values (hex strings for easy comparison)
    pub expected_lambda1: &'static str,
    pub expected_lambda2: &'static str,
    pub expected_x_agg: &'static str,
    pub expected_p_agg: &'static str,
    pub expected_hp_p: &'static str,
    pub expected_key_image: &'static str,
    pub expected_mask_delta: &'static str,
    pub expected_d: &'static str,
    pub expected_mu_p: &'static str,
    pub expected_mu_c: &'static str,
    pub expected_s_agg: &'static str,
}

impl Default for ClsagTestVectors {
    fn default() -> Self {
        Self {
            // Input values
            x1: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x00,
            ],
            x2: [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
                0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
                0x3d, 0x3e, 0x3f, 0x00,
            ],
            alpha1: [
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0x0a,
            ],
            alpha2: [
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0x0b,
            ],
            z_funding_mask: [
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x01,
            ],
            pseudo_out_mask: [
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x02,
            ],
            ring_size: 16,
            real_index: 7,

            // Expected values from reference generator
            expected_lambda1: "0200000000000000000000000000000000000000000000000000000000000000",
            expected_lambda2: "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            expected_x_agg: "ceb5d840ff48f93fbf86e28ecbe7cd04f1f1f2f3f4f5f6f7f8f9fafbfcfdfe0f",
            expected_p_agg: "dd611640798731ceb7502e3a5a1034e88466ccec25c601ee32f50daaecea0c92",
            expected_hp_p: "6f89b3312247e92386ef288dbc422051ec96899fe8df8ebfc4e7f15ba49a1e7b",
            expected_key_image: "16316dab2228419abdcbb037fe6ae0b8d75ce860c3b76f6f1a4190e273cf2adf",
            expected_mask_delta: "dcc2e44b09520147c58be691cde8cd03efeeeeeeeeeeeeeeeeeeeeeeeeeeee0e",
            expected_d: "fcac7acc5428d9c2aef5989e82af20fb0cea9b69e2db706f18bc8c916a29c1b0",
            expected_mu_p: "e4d3761e447ee77c646f3e34fc867e6e3a9bfc2eab51a1987b9d281236481d03",
            expected_mu_c: "1387850e916729153da9fcba821abdef2a3fd1e766cdd9920a4d0a4c34d00d08",
            expected_s_agg: "87e21a94b2b21df8a027eed8f06e469b077fc9be88891a12c168794bd24fd00a",
        }
    }
}

/// Compute Lagrange coefficient for index i given set of indices
fn lagrange_coefficient(i: u32, indices: &[u32]) -> Scalar {
    let mut result = Scalar::ONE;
    let i_scalar = Scalar::from(i);

    for &j in indices {
        if j != i {
            let j_scalar = Scalar::from(j);
            let numerator = j_scalar;
            let denominator = j_scalar - i_scalar;
            result *= numerator * denominator.invert();
        }
    }
    result
}

/// Validation result for a single checkpoint
#[derive(Debug)]
pub struct CheckpointResult {
    pub name: &'static str,
    pub expected: String,
    pub actual: String,
    pub matches: bool,
}

/// Run all checkpoint validations and return results
pub fn validate_clsag_checkpoints() -> Vec<CheckpointResult> {
    let tv = ClsagTestVectors::default();
    let mut results = Vec::new();

    // Parse scalars
    let x1 = Scalar::from_bytes_mod_order(tv.x1);
    let x2 = Scalar::from_bytes_mod_order(tv.x2);
    let alpha1 = Scalar::from_bytes_mod_order(tv.alpha1);
    let alpha2 = Scalar::from_bytes_mod_order(tv.alpha2);
    let z = Scalar::from_bytes_mod_order(tv.z_funding_mask);
    let pseudo_out_mask = Scalar::from_bytes_mod_order(tv.pseudo_out_mask);

    // ═══════════════════════════════════════════════════════════════════════════
    // CHECKPOINT 1: Lagrange coefficients
    // ═══════════════════════════════════════════════════════════════════════════
    let indices = [1u32, 2u32];
    let lambda1 = lagrange_coefficient(1, &indices);
    let lambda2 = lagrange_coefficient(2, &indices);

    results.push(CheckpointResult {
        name: "λ1 (Lagrange buyer)",
        expected: tv.expected_lambda1.to_string(),
        actual: hex::encode(lambda1.as_bytes()),
        matches: hex::encode(lambda1.as_bytes()) == tv.expected_lambda1,
    });

    results.push(CheckpointResult {
        name: "λ2 (Lagrange vendor)",
        expected: tv.expected_lambda2.to_string(),
        actual: hex::encode(lambda2.as_bytes()),
        matches: hex::encode(lambda2.as_bytes()) == tv.expected_lambda2,
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // CHECKPOINT 2: Aggregated private key
    // ═══════════════════════════════════════════════════════════════════════════
    let x_agg = lambda1 * x1 + lambda2 * x2;

    results.push(CheckpointResult {
        name: "x_agg (aggregated private key)",
        expected: tv.expected_x_agg.to_string(),
        actual: hex::encode(x_agg.as_bytes()),
        matches: hex::encode(x_agg.as_bytes()) == tv.expected_x_agg,
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // CHECKPOINT 3: Aggregated public key
    // ═══════════════════════════════════════════════════════════════════════════
    let p_agg = x_agg * G;

    results.push(CheckpointResult {
        name: "P_agg (aggregated public key)",
        expected: tv.expected_p_agg.to_string(),
        actual: hex::encode(p_agg.compress().as_bytes()),
        matches: hex::encode(p_agg.compress().as_bytes()) == tv.expected_p_agg,
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // CHECKPOINT 4: Hash-to-point Hp(P)
    // ═══════════════════════════════════════════════════════════════════════════
    let hp_p = hash_to_point(p_agg.compress().to_bytes());

    results.push(CheckpointResult {
        name: "Hp(P_agg) (hash-to-point)",
        expected: tv.expected_hp_p.to_string(),
        actual: hex::encode(hp_p.compress().as_bytes()),
        matches: hex::encode(hp_p.compress().as_bytes()) == tv.expected_hp_p,
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // CHECKPOINT 5: Key image
    // ═══════════════════════════════════════════════════════════════════════════
    let key_image = x_agg * hp_p;

    results.push(CheckpointResult {
        name: "I (key image)",
        expected: tv.expected_key_image.to_string(),
        actual: hex::encode(key_image.compress().as_bytes()),
        matches: hex::encode(key_image.compress().as_bytes()) == tv.expected_key_image,
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // CHECKPOINT 6: mask_delta
    // ═══════════════════════════════════════════════════════════════════════════
    let mask_delta = z - pseudo_out_mask;

    results.push(CheckpointResult {
        name: "mask_delta (z - pseudo_out_mask)",
        expected: tv.expected_mask_delta.to_string(),
        actual: hex::encode(mask_delta.as_bytes()),
        matches: hex::encode(mask_delta.as_bytes()) == tv.expected_mask_delta,
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // CHECKPOINT 7: D point
    // ═══════════════════════════════════════════════════════════════════════════
    let d = mask_delta * hp_p;

    results.push(CheckpointResult {
        name: "D (mask_delta * Hp(P))",
        expected: tv.expected_d.to_string(),
        actual: hex::encode(d.compress().as_bytes()),
        matches: hex::encode(d.compress().as_bytes()) == tv.expected_d,
    });

    results
}

/// Print validation results in a nice format
pub fn print_validation_results(results: &[CheckpointResult]) {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║         CLSAG CHECKPOINT VALIDATION RESULTS                      ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let mut all_pass = true;
    let mut first_fail: Option<&str> = None;

    for result in results {
        let status = if result.matches { "✅" } else { "❌" };
        println!("{} {}", status, result.name);

        if !result.matches {
            all_pass = false;
            if first_fail.is_none() {
                first_fail = Some(result.name);
            }
            println!("   Expected: {}", result.expected);
            println!("   Actual:   {}", result.actual);
        }
    }

    println!("\n══════════════════════════════════════════════════════════════════");
    if all_pass {
        println!("✅ ALL CHECKPOINTS PASS - Implementation matches reference");
    } else {
        println!(
            "❌ DIVERGENCE DETECTED at: {}",
            first_fail.unwrap_or("unknown")
        );
    }
    println!("══════════════════════════════════════════════════════════════════");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clsag_checkpoints() {
        let results = validate_clsag_checkpoints();
        print_validation_results(&results);

        // Assert all checkpoints pass
        for result in &results {
            assert!(
                result.matches,
                "Checkpoint '{}' failed:\n  Expected: {}\n  Actual: {}",
                result.name, result.expected, result.actual
            );
        }
    }

    #[test]
    fn test_lagrange_coefficients() {
        let indices = [1u32, 2u32];
        let lambda1 = lagrange_coefficient(1, &indices);
        let lambda2 = lagrange_coefficient(2, &indices);

        // λ1 + λ2 should equal 1
        let sum = lambda1 + lambda2;
        assert_eq!(
            hex::encode(sum.as_bytes()),
            "0100000000000000000000000000000000000000000000000000000000000000",
            "λ1 + λ2 should equal 1"
        );
    }

    #[test]
    fn test_key_image_aggregation() {
        let tv = ClsagTestVectors::default();

        let x1 = Scalar::from_bytes_mod_order(tv.x1);
        let x2 = Scalar::from_bytes_mod_order(tv.x2);

        let indices = [1u32, 2u32];
        let lambda1 = lagrange_coefficient(1, &indices);
        let lambda2 = lagrange_coefficient(2, &indices);

        let x_agg = lambda1 * x1 + lambda2 * x2;
        let p_agg = x_agg * G;
        let hp_p = hash_to_point(p_agg.compress().to_bytes());

        // Full key image
        let key_image = x_agg * hp_p;

        // Partial key images
        let pki1 = x1 * hp_p;
        let pki2 = x2 * hp_p;

        // Aggregated from partials: λ1*PKI1 + λ2*PKI2 should equal I
        let ki_from_partials = lambda1 * pki1 + lambda2 * pki2;

        assert_eq!(
            key_image.compress(),
            ki_from_partials.compress(),
            "Key image aggregation should match"
        );
    }
}
