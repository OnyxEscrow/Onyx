//! Verify hash_to_point against official Monero test vectors

use monero_generators::hash_to_point;

fn main() {
    println!("=== Verifying hash_to_point against Monero test vectors ===\n");

    // Test vectors from monero-project/monero tests.txt
    let test_vectors = vec![
        (
            "da66e9ba613919dec28ef367a125bb310d6d83fb9052e71034164b6dc4f392d0",
            "52b3f38753b4e13b74624862e253072cf12f745d43fcfafbe8c217701a6e5875",
        ),
        (
            "a7fbdeeccb597c2d5fdaf2ea2e10cbfcd26b5740903e7f6d46bcbf9a90384fc6",
            "f055ba2d0d9828ce2e203d9896bfda494d7830e7e3a27fa27d5eaa825a79a19c",
        ),
        (
            "ed6e6579368caba2cc4851672972e949c0ee586fee4d6d6a9476d4a908f64070",
            "da3ceda9a2ef6316bf9272566e6dffd785ac71f57855c0202f422bbb86af4ec0",
        ),
        (
            "9ae78e5620f1c4e6b29d03da006869465b3b16dae87ab0a51f4e1b74bc8aa48b",
            "72d8720da66f797f55fbb7fa538af0b4a4f5930c8289c991472c37dc5ec16853",
        ),
        (
            "ab49eb4834d24db7f479753217b763f70604ecb79ed37e6c788528720f424e5b",
            "45914ba926a1a22c8146459c7f050a51ef5f560f5b74bae436b93a379866e6b8",
        ),
    ];

    let mut all_pass = true;
    for (input, expected) in test_vectors {
        let input_bytes: [u8; 32] = hex::decode(input).unwrap().try_into().unwrap();
        let result = hash_to_point(input_bytes);
        let result_hex = hex::encode(result.compress().to_bytes());

        let pass = result_hex == expected;
        let status = if pass { "✅" } else { "❌" };

        if !pass {
            all_pass = false;
            println!("{} Input:    {}", status, input);
            println!("   Expected: {}", expected);
            println!("   Got:      {}", result_hex);
            println!();
        } else {
            println!(
                "{} hash_to_ec({}) = {}",
                status,
                &input[..16],
                &expected[..16]
            );
        }
    }

    println!();
    if all_pass {
        println!("✅ ALL TEST VECTORS PASS - hash_to_point matches Monero!");
    } else {
        println!("❌ SOME TEST VECTORS FAIL - hash_to_point DOES NOT match Monero!");
    }
}
