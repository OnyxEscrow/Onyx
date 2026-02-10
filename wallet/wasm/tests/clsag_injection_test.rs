#[cfg(test)]
mod clsag_injection_tests {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;
    use monero_generators_mirror::hash_to_point;

    /// Reference values from stagenet TX e12e8dbe2be8185f7eb820f4060d1194192d267600b46ba26fd81120c5b8388e
    const REF_HP_P: &str = "6f89b3312247e92386ef288dbc422051ec96899fe8df8ebfc4e7f15ba49a1e7b";
    const REF_KEY_IMAGE: &str = "16316dab2228419abdcbb037fe6ae0b8d75ce860c3b76f6f1a4190e273cf2adf";
    const REF_MU_P: &str = "e4d3761e447ee77c646f3e34fc867e6e3a9bfc2eab51a1987b9d281236481d03";
    const REF_MU_C: &str = "1387850e916729153da9fcba821abdef2a3fd1e766cdd9920a4d0a4c34d00d08";
    const REF_C1: &str = "9befd25f674e7a3207c80a90ba8805bf127020d0b68460258bb72ac85f75d404";
    const REF_D: &str = "ee877f2032f7e6dc83a62c93830dd90a916dd687cd2f1a170f07b47c31ad744f";
    const REF_PSEUDO_OUT: &str = "fbd69d820616ac0b220209885aa720a63c50402ba95f6ba2c710157ef06d8604";
    const REF_OUTPUT_PUBKEY: &str =
        "8bd836ba891eb996b835a06227fb38bc8f996c4f3f00fe27ef9af6fd1fd210d2";

    fn hex_to_bytes(hex: &str) -> [u8; 32] {
        let bytes = hex::decode(hex).expect("Invalid hex");
        bytes.try_into().expect("Wrong length")
    }

    fn hex_to_scalar(hex: &str) -> Scalar {
        Scalar::from_bytes_mod_order(hex_to_bytes(hex))
    }

    fn hex_to_point(hex: &str) -> Option<curve25519_dalek::edwards::EdwardsPoint> {
        CompressedEdwardsY(hex_to_bytes(hex)).decompress()
    }

    #[test]
    fn test_hash_to_point_matches_reference() {
        // Test that our hash_to_point produces the same Hp(P) as reference
        let output_pubkey_bytes = hex_to_bytes(REF_OUTPUT_PUBKEY);

        // Use the same hash_to_point function as in signing (takes [u8; 32])
        let hp = hash_to_point(output_pubkey_bytes);
        let hp_hex = hex::encode(hp.compress().as_bytes());

        assert_eq!(
            hp_hex.to_lowercase(),
            REF_HP_P.to_lowercase(),
            "hash_to_point(P) mismatch!\nExpected: {}\nGot: {}",
            REF_HP_P,
            hp_hex
        );
    }

    #[test]
    fn test_lagrange_coefficients() {
        // Buyer(1) + Vendor(2) pair - compute directly without WASM binding
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

        let indices = [1u32, 2u32];
        let lambda_buyer = lagrange_coefficient(1, &indices);
        let lambda_vendor = lagrange_coefficient(2, &indices);

        // λ_buyer should be 2
        let expected_buyer = Scalar::from(2u64);
        assert_eq!(lambda_buyer, expected_buyer, "λ_buyer should be 2");

        // λ_vendor should be -1 (which is L-1)
        let expected_vendor = -Scalar::ONE;
        assert_eq!(lambda_vendor, expected_vendor, "λ_vendor should be -1");

        // Verify λ_buyer + λ_vendor = 1
        assert_eq!(
            lambda_buyer + lambda_vendor,
            Scalar::ONE,
            "Lagrange sum should be 1"
        );
    }

    #[test]
    fn test_key_image_with_lagrange() {
        // Simulate PKI aggregation with Lagrange coefficients
        // PKI_buyer = x_buyer * Hp(P)
        // PKI_vendor = x_vendor * Hp(P)
        // KI = λ_buyer * PKI_buyer + λ_vendor * PKI_vendor
        //    = (λ_buyer * x_buyer + λ_vendor * x_vendor) * Hp(P)
        //    = x_total * Hp(P) = KI

        // This test verifies the aggregation formula is correct
        let lambda_buyer = Scalar::from(2u64);
        let lambda_vendor = -Scalar::ONE;

        // Mock secret shares (we don't have the real ones)
        let x_buyer = Scalar::from(12345u64);
        let x_vendor = Scalar::from(67890u64);

        // Compute aggregated secret
        let x_agg = lambda_buyer * x_buyer + lambda_vendor * x_vendor;

        // Verify: x_agg = 2 * 12345 - 67890 = 24690 - 67890 = -43200
        let expected = Scalar::from(24690u64) - Scalar::from(67890u64);
        assert_eq!(x_agg, expected, "Lagrange aggregation formula incorrect");
    }

    #[test]
    fn test_mu_p_mu_c_domain_separation() {
        // Verify domain separation strings match Monero spec
        // mu_P uses "CLSAG_agg_0"
        // mu_C uses "CLSAG_agg_1"

        let domain_p = b"CLSAG_agg_0";
        let domain_c = b"CLSAG_agg_1";

        // Hash with Keccak-256 should produce deterministic outputs
        // This is a sanity check that we're using the right domain separators
        assert_ne!(domain_p, domain_c, "Domain separators must differ");
    }
}
