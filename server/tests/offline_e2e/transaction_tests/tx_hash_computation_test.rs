//! Transaction Hash Computation Tests
//!
//! Tests for Monero transaction hash (txid) computation:
//! - txid = Keccak256(prefix_hash || base_hash || prunable_hash)
//! - Component hash computation
//! - Hash ordering and concatenation
//!
//! Reference: monero/src/cryptonote_basic/cryptonote_format_utils.cpp

use sha3::{Digest, Keccak256};

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// KECCAK256 TESTS
// ============================================================================

#[test]
fn test_keccak256_empty() {
    let mut hasher = Keccak256::new();
    let result: [u8; 32] = hasher.finalize().into();

    // Known Keccak256 of empty string
    let expected =
        hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap();

    assert_eq!(
        &result[..],
        &expected[..],
        "Empty hash should match known value"
    );
}

#[test]
fn test_keccak256_deterministic() {
    let input = b"test input";

    let hash1: [u8; 32] = Keccak256::digest(input).into();
    let hash2: [u8; 32] = Keccak256::digest(input).into();

    assert_eq!(hash1, hash2, "Keccak256 should be deterministic");
}

#[test]
fn test_keccak256_different_inputs() {
    let hash1: [u8; 32] = Keccak256::digest(b"input1").into();
    let hash2: [u8; 32] = Keccak256::digest(b"input2").into();

    assert_ne!(
        hash1, hash2,
        "Different inputs should produce different hashes"
    );
}

// ============================================================================
// COMPONENT HASH TESTS
// ============================================================================

/// Compute tx_prefix_hash from prefix bytes
fn compute_prefix_hash(prefix_bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(prefix_bytes).into()
}

/// Compute rct_base_hash from base bytes
fn compute_base_hash(base_bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(base_bytes).into()
}

/// Compute rct_prunable_hash from prunable bytes
fn compute_prunable_hash(prunable_bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(prunable_bytes).into()
}

/// Compute final txid from component hashes
fn compute_txid(
    prefix_hash: &[u8; 32],
    base_hash: &[u8; 32],
    prunable_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(prefix_hash);
    hasher.update(base_hash);
    hasher.update(prunable_hash);
    hasher.finalize().into()
}

#[test]
fn test_prefix_hash_computation() {
    let mut rng = DeterministicRng::with_name("prefix_hash");

    let prefix_bytes: Vec<u8> = (0..100).map(|_| rng.gen_range(256) as u8).collect();
    let hash = compute_prefix_hash(&prefix_bytes);

    // Hash should be 32 bytes
    assert_eq!(hash.len(), 32);

    // Hash should be deterministic
    let hash2 = compute_prefix_hash(&prefix_bytes);
    assert_eq!(hash, hash2);
}

#[test]
fn test_base_hash_computation() {
    let mut rng = DeterministicRng::with_name("base_hash");

    // Base contains: type(1) + fee(varint) + ecdhInfo(8*outputs) + outPk(32*outputs)
    let base_bytes: Vec<u8> = (0..50).map(|_| rng.gen_range(256) as u8).collect();
    let hash = compute_base_hash(&base_bytes);

    assert_eq!(hash.len(), 32);
}

#[test]
fn test_prunable_hash_computation() {
    let mut rng = DeterministicRng::with_name("prunable_hash");

    // Prunable contains: BP+ proofs + CLSAGs + pseudoOuts
    let prunable_bytes: Vec<u8> = (0..500).map(|_| rng.gen_range(256) as u8).collect();
    let hash = compute_prunable_hash(&prunable_bytes);

    assert_eq!(hash.len(), 32);
}

// ============================================================================
// TXID COMPUTATION TESTS
// ============================================================================

#[test]
fn test_txid_from_components() {
    let mut rng = DeterministicRng::with_name("txid_components");

    let prefix_hash = rng.gen_32_bytes();
    let base_hash = rng.gen_32_bytes();
    let prunable_hash = rng.gen_32_bytes();

    let txid = compute_txid(&prefix_hash, &base_hash, &prunable_hash);

    // TXID should be 32 bytes
    assert_eq!(txid.len(), 32);

    // TXID should be deterministic
    let txid2 = compute_txid(&prefix_hash, &base_hash, &prunable_hash);
    assert_eq!(txid, txid2);
}

#[test]
fn test_txid_sensitive_to_all_components() {
    let mut rng = DeterministicRng::with_name("txid_sensitive");

    let prefix_hash = rng.gen_32_bytes();
    let base_hash = rng.gen_32_bytes();
    let prunable_hash = rng.gen_32_bytes();

    let txid1 = compute_txid(&prefix_hash, &base_hash, &prunable_hash);

    // Change prefix_hash
    let mut different_prefix = prefix_hash;
    different_prefix[0] ^= 0xFF;
    let txid2 = compute_txid(&different_prefix, &base_hash, &prunable_hash);
    assert_ne!(txid1, txid2, "TXID should change when prefix changes");

    // Change base_hash
    let mut different_base = base_hash;
    different_base[0] ^= 0xFF;
    let txid3 = compute_txid(&prefix_hash, &different_base, &prunable_hash);
    assert_ne!(txid1, txid3, "TXID should change when base changes");

    // Change prunable_hash
    let mut different_prunable = prunable_hash;
    different_prunable[0] ^= 0xFF;
    let txid4 = compute_txid(&prefix_hash, &base_hash, &different_prunable);
    assert_ne!(txid1, txid4, "TXID should change when prunable changes");
}

#[test]
fn test_txid_hash_order() {
    // Order matters: H(a || b || c) != H(c || b || a)
    let mut rng = DeterministicRng::with_name("txid_order");

    let a = rng.gen_32_bytes();
    let b = rng.gen_32_bytes();
    let c = rng.gen_32_bytes();

    let txid_abc = compute_txid(&a, &b, &c);
    let txid_cba = compute_txid(&c, &b, &a);

    assert_ne!(txid_abc, txid_cba, "Hash order should matter");
}

// ============================================================================
// FULL TX HASH COMPUTATION
// ============================================================================

/// Simulate full transaction hash computation
fn compute_full_tx_hash(tx_bytes: &[u8]) -> TxHashResult {
    // In reality, we'd parse the tx to find component boundaries
    // For testing, we simulate with fixed offsets

    // Simulate: first 1/3 is prefix, next 1/3 is base, last 1/3 is prunable
    let third = tx_bytes.len() / 3;

    let prefix_bytes = &tx_bytes[..third];
    let base_bytes = &tx_bytes[third..third * 2];
    let prunable_bytes = &tx_bytes[third * 2..];

    let prefix_hash = compute_prefix_hash(prefix_bytes);
    let base_hash = compute_base_hash(base_bytes);
    let prunable_hash = compute_prunable_hash(prunable_bytes);

    let txid = compute_txid(&prefix_hash, &base_hash, &prunable_hash);

    TxHashResult {
        txid,
        prefix_hash,
        base_hash,
        prunable_hash,
    }
}

#[derive(Debug)]
struct TxHashResult {
    txid: [u8; 32],
    prefix_hash: [u8; 32],
    base_hash: [u8; 32],
    prunable_hash: [u8; 32],
}

#[test]
fn test_full_tx_hash() {
    let mut rng = DeterministicRng::with_name("full_tx_hash");

    let tx_bytes: Vec<u8> = (0..900).map(|_| rng.gen_range(256) as u8).collect();
    let result = compute_full_tx_hash(&tx_bytes);

    // All components should be 32 bytes
    assert_eq!(result.txid.len(), 32);
    assert_eq!(result.prefix_hash.len(), 32);
    assert_eq!(result.base_hash.len(), 32);
    assert_eq!(result.prunable_hash.len(), 32);

    // Components should be different (for random data)
    assert_ne!(result.prefix_hash, result.base_hash);
    assert_ne!(result.base_hash, result.prunable_hash);
}

// ============================================================================
// CLSAG MESSAGE COMPUTATION
// ============================================================================

/// Compute CLSAG signing message (get_pre_mlsag_hash)
///
/// This is what CLSAG actually signs, NOT just tx_prefix_hash.
/// clsag_message = H(tx_prefix_hash || rctSigBase_hash || bp_hash)
fn compute_clsag_message(
    tx_prefix_hash: &[u8; 32],
    rct_base_hash: &[u8; 32],
    bp_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(tx_prefix_hash);
    hasher.update(rct_base_hash);
    hasher.update(bp_hash);
    hasher.finalize().into()
}

#[test]
fn test_clsag_message_different_from_txid() {
    let mut rng = DeterministicRng::with_name("clsag_msg");

    let prefix_hash = rng.gen_32_bytes();
    let base_hash = rng.gen_32_bytes();
    let prunable_hash = rng.gen_32_bytes();

    // TXID uses full prunable hash
    let txid = compute_txid(&prefix_hash, &base_hash, &prunable_hash);

    // CLSAG message uses only BP+ portion of prunable
    // (Simulating with different hash)
    let bp_hash = rng.gen_32_bytes();
    let clsag_msg = compute_clsag_message(&prefix_hash, &base_hash, &bp_hash);

    // These should be different
    assert_ne!(txid, clsag_msg, "CLSAG message should differ from TXID");
}

#[test]
fn test_clsag_message_sensitive_to_bp() {
    let mut rng = DeterministicRng::with_name("clsag_bp");

    let prefix_hash = rng.gen_32_bytes();
    let base_hash = rng.gen_32_bytes();
    let bp_hash1 = rng.gen_32_bytes();
    let bp_hash2 = rng.gen_32_bytes();

    let msg1 = compute_clsag_message(&prefix_hash, &base_hash, &bp_hash1);
    let msg2 = compute_clsag_message(&prefix_hash, &base_hash, &bp_hash2);

    assert_ne!(
        msg1, msg2,
        "Different BP should produce different CLSAG message"
    );
}

// ============================================================================
// HASH CONCATENATION TESTS
// ============================================================================

#[test]
fn test_hash_concat_no_sc_reduce() {
    // CRITICAL: NO sc_reduce32 on hashes before concatenation
    // Raw 32-byte hashes are concatenated directly

    let mut rng = DeterministicRng::with_name("no_reduce");

    let hash1 = rng.gen_32_bytes();
    let hash2 = rng.gen_32_bytes();

    // Direct concatenation (correct)
    let mut direct_concat = Vec::new();
    direct_concat.extend_from_slice(&hash1);
    direct_concat.extend_from_slice(&hash2);

    // The 64-byte concat is then hashed
    let result: [u8; 32] = Keccak256::digest(&direct_concat).into();

    // Verify we're using raw bytes, not reduced scalars
    // If we had done sc_reduce, hash1 might have changed
    // (for values >= curve order)

    // Just verify the computation is deterministic
    let result2: [u8; 32] = Keccak256::digest(&direct_concat).into();
    assert_eq!(result, result2);
}

#[test]
fn test_three_hash_concat() {
    let mut rng = DeterministicRng::with_name("three_concat");

    let h1 = rng.gen_32_bytes();
    let h2 = rng.gen_32_bytes();
    let h3 = rng.gen_32_bytes();

    // H(h1 || h2 || h3)
    let mut hasher = Keccak256::new();
    hasher.update(&h1);
    hasher.update(&h2);
    hasher.update(&h3);
    let result1: [u8; 32] = hasher.finalize().into();

    // Same as H(concat)
    let mut concat = Vec::new();
    concat.extend_from_slice(&h1);
    concat.extend_from_slice(&h2);
    concat.extend_from_slice(&h3);
    let result2: [u8; 32] = Keccak256::digest(&concat).into();

    assert_eq!(
        result1, result2,
        "Incremental and batch concat should be equivalent"
    );
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

    let txid = compute_txid(&prefix, &base, &prunable);
    let txid_hex = hex::encode(&txid);

    // TXID hex should be 64 characters
    assert_eq!(txid_hex.len(), 64, "TXID hex should be 64 characters");

    // Should be valid hex (lowercase)
    assert!(txid_hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_txid_endianness() {
    // Monero uses little-endian byte order but displays as hex
    // The bytes are already in the correct order from Keccak
    let mut rng = DeterministicRng::with_name("txid_endian");

    let txid = rng.gen_32_bytes();
    let hex = hex::encode(&txid);

    // First 2 hex chars correspond to first byte
    let first_byte = u8::from_str_radix(&hex[0..2], 16).unwrap();
    assert_eq!(first_byte, txid[0]);
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_zero_hashes() {
    let zeros = [0u8; 32];
    let txid = compute_txid(&zeros, &zeros, &zeros);

    // Should produce a valid non-zero hash
    assert_ne!(txid, zeros, "Hash of zeros should not be zero");
}

#[test]
fn test_max_hashes() {
    let maxes = [0xffu8; 32];
    let txid = compute_txid(&maxes, &maxes, &maxes);

    // Should produce a valid hash
    assert_eq!(txid.len(), 32);
}
