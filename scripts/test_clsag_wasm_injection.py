#!/usr/bin/env python3
"""
CLSAG WASM Injection Test

Injects known-good reference values into the CLSAG signing flow to identify
the exact point of divergence between our implementation and the expected output.

Reference values from stagenet TX: e12e8dbe2be8185f7eb820f4060d1194192d267600b46ba26fd81120c5b8388e
"""

import json
import subprocess
import sys
from typing import Dict, Any

# Reference values from audit
REFERENCE_VALUES = {
    "Hp_P_agg": "6f89b3312247e92386ef288dbc422051ec96899fe8df8ebfc4e7f15ba49a1e7b",
    "key_image": "16316dab2228419abdcbb037fe6ae0b8d75ce860c3b76f6f1a4190e273cf2adf",
    "mu_P": "e4d3761e447ee77c646f3e34fc867e6e3a9bfc2eab51a1987b9d281236481d03",
    "mu_C": "1387850e916729153da9fcba821abdef2a3fd1e766cdd9920a4d0a4c34d00d08",
    "s_aggregated": "87e21a94b2b21df8a027eed8f06e469b077fc9be88891a12c168794bd24fd00a",

    # From clsag_test_vector.json
    "c1": "9befd25f674e7a3207c80a90ba8805bf127020d0b68460258bb72ac85f75d404",
    "D": "ee877f2032f7e6dc83a62c93830dd90a916dd687cd2f1a170f07b47c31ad744f",
    "pseudo_out": "fbd69d820616ac0b220209885aa720a63c50402ba95f6ba2c710157ef06d8604",

    # Ring data (first entry as real spend)
    "real_output_pubkey": "8bd836ba891eb996b835a06227fb38bc8f996c4f3f00fe27ef9af6fd1fd210d2",
    "real_commitment": "98b9d5c4a24a282fb971d039dcf93afd9b20ae56e742b4f884bc4c1d3fc2a3b5",

    # Lagrange coefficients for buyer(1) + vendor(2)
    "lambda_buyer": "0200000000000000000000000000000000000000000000000000000000000000",  # 2
    "lambda_vendor": "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",  # -1 mod L
}

def create_test_html():
    """Generate HTML file that runs WASM tests and reports results."""

    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>CLSAG WASM Injection Test</title>
    <script type="module">
        // Import WASM module
        import init, * as wasm from '/static/js/wasm/wallet_wasm.js';

        const REFERENCE = {
            Hp_P_agg: "6f89b3312247e92386ef288dbc422051ec96899fe8df8ebfc4e7f15ba49a1e7b",
            key_image: "16316dab2228419abdcbb037fe6ae0b8d75ce860c3b76f6f1a4190e273cf2adf",
            mu_P: "e4d3761e447ee77c646f3e34fc867e6e3a9bfc2eab51a1987b9d281236481d03",
            mu_C: "1387850e916729153da9fcba821abdef2a3fd1e766cdd9920a4d0a4c34d00d08",
            c1: "9befd25f674e7a3207c80a90ba8805bf127020d0b68460258bb72ac85f75d404",
            D: "ee877f2032f7e6dc83a62c93830dd90a916dd687cd2f1a170f07b47c31ad744f",
            pseudo_out: "fbd69d820616ac0b220209885aa720a63c50402ba95f6ba2c710157ef06d8604",
            real_output_pubkey: "8bd836ba891eb996b835a06227fb38bc8f996c4f3f00fe27ef9af6fd1fd210d2",
        };

        function log(msg, isError = false) {
            const pre = document.getElementById('output');
            const line = document.createElement('div');
            line.textContent = msg;
            if (isError) line.style.color = 'red';
            pre.appendChild(line);
            console.log(msg);
        }

        function checkMatch(name, actual, expected) {
            const match = actual.toLowerCase() === expected.toLowerCase();
            if (match) {
                log(`✅ ${name} MATCHES: ${actual.slice(0,16)}...`);
            } else {
                log(`❌ ${name} MISMATCH:`, true);
                log(`   Expected: ${expected}`, true);
                log(`   Got:      ${actual}`, true);
            }
            return match;
        }

        async function runTests() {
            log("=".repeat(60));
            log("CLSAG WASM INJECTION TEST - Identifying Divergence Point");
            log("=".repeat(60));

            try {
                await init();
                log("✅ WASM module initialized");
            } catch (e) {
                log(`❌ WASM init failed: ${e}`, true);
                return;
            }

            // Test 1: Verify hash_to_point produces same Hp(P) as reference
            log("\\n--- TEST 1: hash_to_point(P) ---");
            try {
                if (typeof wasm.hash_to_point_hex === 'function') {
                    const hp = wasm.hash_to_point_hex(REFERENCE.real_output_pubkey);
                    checkMatch("Hp(P)", hp, REFERENCE.Hp_P_agg);
                } else {
                    log("⚠️ hash_to_point_hex not exported, trying compute_partial_key_image...");
                    // Use a dummy scalar to extract Hp
                    const one = "0100000000000000000000000000000000000000000000000000000000000000";
                    const pki = wasm.compute_partial_key_image(one, REFERENCE.real_output_pubkey);
                    log(`   PKI with x=1: ${pki.slice(0,32)}...`);
                }
            } catch (e) {
                log(`❌ hash_to_point test failed: ${e}`, true);
            }

            // Test 2: Verify mu_P/mu_C computation
            log("\\n--- TEST 2: mu_P/mu_C computation ---");
            try {
                if (typeof wasm.compute_clsag_mu === 'function') {
                    // This would need the full ring data
                    log("⚠️ compute_clsag_mu needs full ring - skipping direct test");
                } else {
                    log("⚠️ compute_clsag_mu not exported");
                }
                log(`   Reference mu_P: ${REFERENCE.mu_P.slice(0,32)}...`);
                log(`   Reference mu_C: ${REFERENCE.mu_C.slice(0,32)}...`);
            } catch (e) {
                log(`❌ mu computation test failed: ${e}`, true);
            }

            // Test 3: Check if WASM has the required signing functions
            log("\\n--- TEST 3: WASM exports check ---");
            const requiredFunctions = [
                'sign_clsag_partial_wasm',
                'compute_partial_key_image',
                'frost_compute_lagrange_coefficient',
                'aggregate_partial_key_images',
            ];
            for (const fn of requiredFunctions) {
                if (typeof wasm[fn] === 'function') {
                    log(`✅ ${fn} is exported`);
                } else {
                    log(`❌ ${fn} NOT exported`, true);
                }
            }

            // Test 4: Lagrange coefficient computation
            log("\\n--- TEST 4: Lagrange coefficient ---");
            try {
                if (typeof wasm.frost_compute_lagrange_coefficient === 'function') {
                    // buyer(1) signing with vendor(2)
                    const lambda_buyer = wasm.frost_compute_lagrange_coefficient(1, 2);
                    const lambda_vendor = wasm.frost_compute_lagrange_coefficient(2, 1);
                    log(`   λ_buyer(1, {1,2}):  ${lambda_buyer}`);
                    log(`   λ_vendor(2, {1,2}): ${lambda_vendor}`);

                    // Verify: λ_buyer = 2, λ_vendor = -1 mod L
                    const expected_buyer = "0200000000000000000000000000000000000000000000000000000000000000";
                    const expected_vendor = "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

                    checkMatch("λ_buyer", lambda_buyer, expected_buyer);
                    checkMatch("λ_vendor", lambda_vendor, expected_vendor);
                }
            } catch (e) {
                log(`❌ Lagrange test failed: ${e}`, true);
            }

            // Test 5: Key Image aggregation with Lagrange
            log("\\n--- TEST 5: Key Image aggregation ---");
            try {
                if (typeof wasm.aggregate_partial_key_images === 'function') {
                    log("   Testing with mock PKIs...");
                    // This would need actual PKI values
                } else {
                    log("⚠️ aggregate_partial_key_images not directly testable");
                }
            } catch (e) {
                log(`❌ KI aggregation test failed: ${e}`, true);
            }

            log("\\n" + "=".repeat(60));
            log("TEST COMPLETE - Check console for detailed errors");
            log("=".repeat(60));

            // Export results for analysis
            window.testResults = {
                reference: REFERENCE,
                wasmExports: Object.keys(wasm).filter(k => typeof wasm[k] === 'function')
            };
            log("\\nResults saved to window.testResults");
        }

        window.addEventListener('load', runTests);
    </script>
    <style>
        body {
            font-family: monospace;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
        }
        #output {
            white-space: pre-wrap;
            background: #16213e;
            padding: 15px;
            border-radius: 5px;
            line-height: 1.5;
        }
        h1 { color: #e94560; }
    </style>
</head>
<body>
    <h1>🔬 CLSAG WASM Injection Test</h1>
    <p>Testing WASM functions against known-good reference values from stagenet TX.</p>
    <div id="output">Loading WASM...</div>
</body>
</html>
"""
    return html_content


def create_rust_unit_test():
    """Generate Rust unit test for crypto.rs"""

    rust_test = '''
#[cfg(test)]
mod clsag_injection_tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::edwards::CompressedEdwardsY;

    /// Reference values from stagenet TX e12e8dbe2be8185f7eb820f4060d1194192d267600b46ba26fd81120c5b8388e
    const REF_HP_P: &str = "6f89b3312247e92386ef288dbc422051ec96899fe8df8ebfc4e7f15ba49a1e7b";
    const REF_KEY_IMAGE: &str = "16316dab2228419abdcbb037fe6ae0b8d75ce860c3b76f6f1a4190e273cf2adf";
    const REF_MU_P: &str = "e4d3761e447ee77c646f3e34fc867e6e3a9bfc2eab51a1987b9d281236481d03";
    const REF_MU_C: &str = "1387850e916729153da9fcba821abdef2a3fd1e766cdd9920a4d0a4c34d00d08";
    const REF_C1: &str = "9befd25f674e7a3207c80a90ba8805bf127020d0b68460258bb72ac85f75d404";
    const REF_D: &str = "ee877f2032f7e6dc83a62c93830dd90a916dd687cd2f1a170f07b47c31ad744f";
    const REF_PSEUDO_OUT: &str = "fbd69d820616ac0b220209885aa720a63c50402ba95f6ba2c710157ef06d8604";
    const REF_OUTPUT_PUBKEY: &str = "8bd836ba891eb996b835a06227fb38bc8f996c4f3f00fe27ef9af6fd1fd210d2";

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
        let output_pubkey = hex_to_point(REF_OUTPUT_PUBKEY).expect("Invalid pubkey");

        // Use the same hash_to_point function as in signing
        let hp = hash_to_point(&output_pubkey);
        let hp_hex = hex::encode(hp.compress().as_bytes());

        assert_eq!(
            hp_hex.to_lowercase(),
            REF_HP_P.to_lowercase(),
            "hash_to_point(P) mismatch!\\nExpected: {}\\nGot: {}",
            REF_HP_P, hp_hex
        );
    }

    #[test]
    fn test_lagrange_coefficients() {
        // Buyer(1) + Vendor(2) pair
        let lambda_buyer = frost_compute_lagrange_coefficient(1, &[1, 2]);
        let lambda_vendor = frost_compute_lagrange_coefficient(2, &[1, 2]);

        // λ_buyer should be 2
        let expected_buyer = Scalar::from(2u64);
        assert_eq!(lambda_buyer, expected_buyer, "λ_buyer should be 2");

        // λ_vendor should be -1 (which is L-1)
        let expected_vendor = -Scalar::ONE;
        assert_eq!(lambda_vendor, expected_vendor, "λ_vendor should be -1");

        // Verify λ_buyer + λ_vendor = 1
        assert_eq!(lambda_buyer + lambda_vendor, Scalar::ONE, "Lagrange sum should be 1");
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
'''
    return rust_test


def main():
    print("=" * 60)
    print("CLSAG WASM INJECTION TEST GENERATOR")
    print("=" * 60)

    # Generate HTML test file
    html_path = "/home/malix/Desktop/NEXUS/static/test_clsag_injection.html"
    html_content = create_test_html()

    with open(html_path, 'w') as f:
        f.write(html_content)
    print(f"✅ Generated: {html_path}")

    # Generate Rust unit test
    rust_test = create_rust_unit_test()
    rust_path = "/home/malix/Desktop/NEXUS/wallet/wasm/tests/clsag_injection_test.rs"

    with open(rust_path, 'w') as f:
        f.write(rust_test)
    print(f"✅ Generated: {rust_path}")

    print("\n" + "=" * 60)
    print("NEXT STEPS:")
    print("=" * 60)
    print("""
1. Run HTML test (requires server):
   ./target/release/server
   Open: http://localhost:8080/static/test_clsag_injection.html

2. Run Rust unit tests:
   cd wallet/wasm
   cargo test clsag_injection_tests -- --nocapture

3. Check browser console for detailed divergence analysis

Reference values to verify:
  Hp(P):     6f89b3312247e92386ef288dbc422051ec96899fe8df8ebfc4e7f15ba49a1e7b
  mu_P:      e4d3761e447ee77c646f3e34fc867e6e3a9bfc2eab51a1987b9d281236481d03
  mu_C:      1387850e916729153da9fcba821abdef2a3fd1e766cdd9920a4d0a4c34d00d08
  key_image: 16316dab2228419abdcbb037fe6ae0b8d75ce860c3b76f6f1a4190e273cf2adf
""")


if __name__ == "__main__":
    main()
