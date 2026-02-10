//! Bug Regression: Hash Algorithm Mismatch (Bug #2.9)
//!
//! ## Original Bug
//! Transaction hashes were computed using wrong algorithm or component order,
//! causing TXID mismatches between our implementation and the network.
//!
//! ## Root Cause
//! Monero uses Keccak256 (not SHA256 or SHA3-256) for transaction hashes.
//! The TXID is computed as: H(prefix_hash || base_hash || prunable_hash)
//! NOT just H(prefix_hash) or H(entire_tx).
//!
//! ## Fix
//! Use correct Keccak256 with proper component ordering.
//!
//! ## Reference
//! - monero/src/cryptonote_basic/cryptonote_format_utils.cpp
//! - server/src/services/transaction_builder.rs

use sha3::{Digest, Keccak256};

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// HASH FUNCTIONS
// ============================================================================

/// BUG: Use SHA256 instead of Keccak256
fn compute_txid_buggy_sha256(prefix: &[u8], base: &[u8], prunable: &[u8]) -> [u8; 32] {
    use sha2::Sha256;

    let prefix_hash: [u8; 32] = Sha256::digest(prefix).into();
    let base_hash: [u8; 32] = Sha256::digest(base).into();
    let prunable_hash: [u8; 32] = Sha256::digest(prunable).into();

    let mut hasher = Sha256::new();
    hasher.update(&prefix_hash);
    hasher.update(&base_hash);
    hasher.update(&prunable_hash);
    hasher.finalize().into()
}

/// BUG: Use Keccak but wrong order (base || prefix || prunable)
fn compute_txid_buggy_order(prefix: &[u8], base: &[u8], prunable: &[u8]) -> [u8; 32] {
    let prefix_hash: [u8; 32] = Keccak256::digest(prefix).into();
    let base_hash: [u8; 32] = Keccak256::digest(base).into();
    let prunable_hash: [u8; 32] = Keccak256::digest(prunable).into();

    // BUG: Wrong order!
    let mut hasher = Keccak256::new();
    hasher.update(&base_hash);    // Should be prefix
    hasher.update(&prefix_hash);  // Should be base
    hasher.update(&prunable_hash);
    hasher.finalize().into()
}

/// BUG: Hash entire TX as one blob instead of components
fn compute_txid_buggy_blob(prefix: &[u8], base: &[u8], prunable: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(prefix);
    hasher.update(base);
    hasher.update(prunable);
    // BUG: Single hash of concatenated data, not H(H(p) || H(b) || H(r))
    hasher.finalize().into()
}

/// FIXED: Correct Keccak256 with proper component ordering
fn compute_txid_fixed(prefix: &[u8], base: &[u8], prunable: &[u8]) -> [u8; 32] {
    let prefix_hash: [u8; 32] = Keccak256::digest(prefix).into();
    let base_hash: [u8; 32] = Keccak256::digest(base).into();
    let prunable_hash: [u8; 32] = Keccak256::digest(prunable).into();

    // Correct order: prefix || base || prunable
    let mut hasher = Keccak256::new();
    hasher.update(&prefix_hash);
    hasher.update(&base_hash);
    hasher.update(&prunable_hash);
    hasher.finalize().into()
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

#[test]
fn test_sha256_produces_different_result() {
    let mut rng = DeterministicRng::with_name("sha256_diff");

    let prefix = rng.gen_32_bytes();
    let base = rng.gen_32_bytes();
    let prunable = rng.gen_32_bytes();

    let buggy_hash = compute_txid_buggy_sha256(&prefix, &base, &prunable);
    let fixed_hash = compute_txid_fixed(&prefix, &base, &prunable);

    assert_ne!(
        buggy_hash, fixed_hash,
        "SHA256 should produce different result than Keccak256"
    );
}

#[test]
fn test_wrong_order_produces_different_result() {
    let mut rng = DeterministicRng::with_name("order_diff");

    let prefix = rng.gen_32_bytes();
    let base = rng.gen_32_bytes();
    let prunable = rng.gen_32_bytes();

    let buggy_hash = compute_txid_buggy_order(&prefix, &base, &prunable);
    let fixed_hash = compute_txid_fixed(&prefix, &base, &prunable);

    assert_ne!(
        buggy_hash, fixed_hash,
        "Wrong component order should produce different result"
    );
}

#[test]
fn test_blob_hash_produces_different_result() {
    let mut rng = DeterministicRng::with_name("blob_diff");

    let prefix = rng.gen_32_bytes();
    let base = rng.gen_32_bytes();
    let prunable = rng.gen_32_bytes();

    let buggy_hash = compute_txid_buggy_blob(&prefix, &base, &prunable);
    let fixed_hash = compute_txid_fixed(&prefix, &base, &prunable);

    assert_ne!(
        buggy_hash, fixed_hash,
        "Single blob hash should differ from component hash"
    );
}

// ============================================================================
// KECCAK256 VERIFICATION TESTS
// ============================================================================

#[test]
fn test_keccak256_empty_input() {
    // Known value: Keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    let hash: [u8; 32] = Keccak256::digest(b"").into();
    let expected = hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap();

    assert_eq!(&hash[..], &expected[..], "Keccak256 empty hash should match known value");
}

#[test]
fn test_keccak256_test_vector() {
    // Known value: Keccak256("test") = 9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658
    let hash: [u8; 32] = Keccak256::digest(b"test").into();
    let expected = hex::decode("9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658").unwrap();

    assert_eq!(&hash[..], &expected[..], "Keccak256 'test' hash should match known value");
}

#[test]
fn test_keccak256_not_sha3() {
    // Keccak256 (Monero) != SHA3-256 (NIST)
    // SHA3-256("test") = 36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80
    let keccak_hash: [u8; 32] = Keccak256::digest(b"test").into();
    let sha3_expected = hex::decode("36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80").unwrap();

    assert_ne!(
        &keccak_hash[..],
        &sha3_expected[..],
        "Keccak256 should differ from SHA3-256"
    );
}

// ============================================================================
// COMPONENT ORDER TESTS
// ============================================================================

#[test]
fn test_component_order_matters() {
    let mut rng = DeterministicRng::with_name("order_matters");

    let a = rng.gen_32_bytes();
    let b = rng.gen_32_bytes();
    let c = rng.gen_32_bytes();

    // Different orderings
    let hash_abc = compute_txid_fixed(&a, &b, &c);
    let hash_acb = compute_txid_fixed(&a, &c, &b);
    let hash_bac = compute_txid_fixed(&b, &a, &c);
    let hash_cba = compute_txid_fixed(&c, &b, &a);

    // All should be different
    let hashes = [hash_abc, hash_acb, hash_bac, hash_cba];
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "Different orderings should produce different hashes"
            );
        }
    }
}

// ============================================================================
// COMPONENT HASH TESTS
// ============================================================================

#[test]
fn test_prefix_hash_computation() {
    let mut rng = DeterministicRng::with_name("prefix_hash");

    let prefix = rng.gen_32_bytes().to_vec();
    let prefix_hash: [u8; 32] = Keccak256::digest(&prefix).into();

    // Verify hash is deterministic
    let prefix_hash2: [u8; 32] = Keccak256::digest(&prefix).into();
    assert_eq!(prefix_hash, prefix_hash2);
}

#[test]
fn test_each_component_hashed_separately() {
    let mut rng = DeterministicRng::with_name("separate_hash");

    let prefix = rng.gen_32_bytes();
    let base = rng.gen_32_bytes();
    let prunable = rng.gen_32_bytes();

    let prefix_hash: [u8; 32] = Keccak256::digest(&prefix).into();
    let base_hash: [u8; 32] = Keccak256::digest(&base).into();
    let prunable_hash: [u8; 32] = Keccak256::digest(&prunable).into();

    // All component hashes should be different (for random data)
    assert_ne!(prefix_hash, base_hash);
    assert_ne!(base_hash, prunable_hash);
    assert_ne!(prefix_hash, prunable_hash);
}

// ============================================================================
// DETERMINISM TESTS
// ============================================================================

#[test]
fn test_txid_deterministic() {
    let mut rng = DeterministicRng::with_name("txid_det");

    let prefix = rng.gen_32_bytes();
    let base = rng.gen_32_bytes();
    let prunable = rng.gen_32_bytes();

    let hash1 = compute_txid_fixed(&prefix, &base, &prunable);
    let hash2 = compute_txid_fixed(&prefix, &base, &prunable);

    assert_eq!(hash1, hash2, "TXID computation should be deterministic");
}

#[test]
fn test_hash_sensitivity() {
    let mut rng = DeterministicRng::with_name("hash_sensitive");

    let prefix = rng.gen_32_bytes();
    let base = rng.gen_32_bytes();
    let prunable = rng.gen_32_bytes();

    let original = compute_txid_fixed(&prefix, &base, &prunable);

    // Change one byte in prefix
    let mut modified_prefix = prefix;
    modified_prefix[0] ^= 0xFF;
    let hash_changed_prefix = compute_txid_fixed(&modified_prefix, &base, &prunable);

    // Change one byte in base
    let mut modified_base = base;
    modified_base[0] ^= 0xFF;
    let hash_changed_base = compute_txid_fixed(&prefix, &modified_base, &prunable);

    // Change one byte in prunable
    let mut modified_prunable = prunable;
    modified_prunable[0] ^= 0xFF;
    let hash_changed_prunable = compute_txid_fixed(&prefix, &base, &modified_prunable);

    // All should be different
    assert_ne!(original, hash_changed_prefix);
    assert_ne!(original, hash_changed_base);
    assert_ne!(original, hash_changed_prunable);
}

// ============================================================================
// ALL BUG VARIANTS DIFFER FROM CORRECT
// ============================================================================

#[test]
fn test_all_bugs_produce_different_results() {
    let mut rng = DeterministicRng::with_name("all_bugs");

    for _ in 0..100 {
        let prefix = rng.gen_32_bytes();
        let base = rng.gen_32_bytes();
        let prunable = rng.gen_32_bytes();

        let correct = compute_txid_fixed(&prefix, &base, &prunable);
        let bug_sha256 = compute_txid_buggy_sha256(&prefix, &base, &prunable);
        let bug_order = compute_txid_buggy_order(&prefix, &base, &prunable);
        let bug_blob = compute_txid_buggy_blob(&prefix, &base, &prunable);

        assert_ne!(correct, bug_sha256, "SHA256 bug should differ");
        assert_ne!(correct, bug_order, "Order bug should differ");
        assert_ne!(correct, bug_blob, "Blob bug should differ");
    }
}

// ============================================================================
// TXID FORMAT TESTS
// ============================================================================

#[test]
fn test_txid_hex_format() {
    let mut rng = DeterministicRng::with_name("txid_hex");

    let prefix = rng.gen_32_bytes();
    let base = rng.gen_32_bytes();
    let prunable = rng.gen_32_bytes();

    let txid = compute_txid_fixed(&prefix, &base, &prunable);
    let txid_hex = hex::encode(&txid);

    // TXID hex should be 64 characters (32 bytes * 2)
    assert_eq!(txid_hex.len(), 64);

    // Should be valid lowercase hex
    assert!(txid_hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_txid_not_all_zeros() {
    let mut rng = DeterministicRng::with_name("txid_nonzero");

    let prefix = rng.gen_32_bytes();
    let base = rng.gen_32_bytes();
    let prunable = rng.gen_32_bytes();

    let txid = compute_txid_fixed(&prefix, &base, &prunable);

    assert_ne!(txid, [0u8; 32], "TXID should not be all zeros");
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_empty_components() {
    let txid = compute_txid_fixed(&[], &[], &[]);

    // Should produce valid hash even with empty inputs
    assert_ne!(txid, [0u8; 32]);

    // Verify determinism
    let txid2 = compute_txid_fixed(&[], &[], &[]);
    assert_eq!(txid, txid2);
}

#[test]
fn test_identical_components() {
    let component = [0x42u8; 32];

    let txid = compute_txid_fixed(&component, &component, &component);

    // Even with identical components, order matters
    // prefix_hash = base_hash = prunable_hash
    // But TXID = H(h || h || h) should be well-defined
    assert_ne!(txid, [0u8; 32]);
}

#[test]
fn test_large_components() {
    let mut rng = DeterministicRng::with_name("large_components");

    // Large prefix (1KB)
    let prefix: Vec<u8> = (0..1024).map(|_| rng.gen_range(256) as u8).collect();
    // Large base (500 bytes)
    let base: Vec<u8> = (0..500).map(|_| rng.gen_range(256) as u8).collect();
    // Large prunable (2KB)
    let prunable: Vec<u8> = (0..2048).map(|_| rng.gen_range(256) as u8).collect();

    let txid = compute_txid_fixed(&prefix, &base, &prunable);

    // Should produce valid 32-byte hash
    assert_eq!(txid.len(), 32);
    assert_ne!(txid, [0u8; 32]);
}
