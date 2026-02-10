//! Bug Regression: MuSig2 Commitment Validation (Bug #1.3)
//!
//! ## Original Bug
//! Partial signatures were accepted without verifying commitment consistency,
//! allowing malicious signers to manipulate the final signature.
//!
//! ## Root Cause
//! The MuSig2 protocol requires that each signer commits to their nonce
//! before revealing it. Without this check, a rogue signer could choose
//! their nonce after seeing others', breaking security.
//!
//! ## Fix
//! Validate that revealed nonces match previously committed hashes.
//!
//! ## Reference
//! - BIP-0327: MuSig2
//! - server/src/services/round_robin_signing.rs

use sha3::{Digest, Keccak256};

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// COMMITMENT TYPES
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct NonceCommitment {
    pub signer_id: String,
    pub commitment_hash: [u8; 32],
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NonceReveal {
    pub signer_id: String,
    pub nonce_r: [u8; 32], // R component
    pub nonce_s: [u8; 32], // S component (for MuSig2)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CommitmentError {
    MissingCommitment,
    HashMismatch,
    DuplicateReveal,
    InvalidNonce,
}

// ============================================================================
// COMMITMENT FUNCTIONS
// ============================================================================

/// Compute commitment hash: H(nonce_r || nonce_s)
fn compute_commitment(nonce_r: &[u8; 32], nonce_s: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(nonce_r);
    hasher.update(nonce_s);
    hasher.finalize().into()
}

/// BUG: Accept reveal without checking commitment (vulnerable)
fn validate_reveal_buggy(
    _commitment: &NonceCommitment,
    _reveal: &NonceReveal,
) -> Result<(), CommitmentError> {
    // BUG: No validation at all!
    Ok(())
}

/// FIXED: Properly validate commitment before accepting reveal
fn validate_reveal_fixed(
    commitment: &NonceCommitment,
    reveal: &NonceReveal,
) -> Result<(), CommitmentError> {
    // Verify signer matches
    if commitment.signer_id != reveal.signer_id {
        return Err(CommitmentError::MissingCommitment);
    }

    // Recompute commitment from revealed nonces
    let computed_hash = compute_commitment(&reveal.nonce_r, &reveal.nonce_s);

    // Verify hash matches committed value
    if computed_hash != commitment.commitment_hash {
        return Err(CommitmentError::HashMismatch);
    }

    Ok(())
}

// ============================================================================
// SESSION STATE
// ============================================================================

#[derive(Debug)]
pub struct SigningSession {
    pub commitments: Vec<NonceCommitment>,
    pub reveals: Vec<NonceReveal>,
}

impl SigningSession {
    pub fn new() -> Self {
        Self {
            commitments: Vec::new(),
            reveals: Vec::new(),
        }
    }

    /// Add a commitment
    pub fn add_commitment(&mut self, commitment: NonceCommitment) {
        self.commitments.push(commitment);
    }

    /// Process a reveal (fixed version)
    pub fn process_reveal(&mut self, reveal: NonceReveal) -> Result<(), CommitmentError> {
        // Find matching commitment
        let commitment = self
            .commitments
            .iter()
            .find(|c| c.signer_id == reveal.signer_id)
            .ok_or(CommitmentError::MissingCommitment)?;

        // Check for duplicate reveal
        if self.reveals.iter().any(|r| r.signer_id == reveal.signer_id) {
            return Err(CommitmentError::DuplicateReveal);
        }

        // Validate reveal matches commitment
        validate_reveal_fixed(commitment, &reveal)?;

        self.reveals.push(reveal);
        Ok(())
    }

    /// Check if all commitments have been revealed
    pub fn all_revealed(&self) -> bool {
        self.commitments.len() == self.reveals.len()
    }
}

impl Default for SigningSession {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

#[test]
fn test_valid_commitment_reveal_succeeds() {
    let mut rng = DeterministicRng::with_name("valid_commitment");

    let nonce_r = rng.gen_32_bytes();
    let nonce_s = rng.gen_32_bytes();
    let commitment_hash = compute_commitment(&nonce_r, &nonce_s);

    let commitment = NonceCommitment {
        signer_id: "buyer".to_string(),
        commitment_hash,
        timestamp: 1000,
    };

    let reveal = NonceReveal {
        signer_id: "buyer".to_string(),
        nonce_r,
        nonce_s,
    };

    let result = validate_reveal_fixed(&commitment, &reveal);
    assert!(result.is_ok(), "Valid reveal should succeed");
}

#[test]
fn test_mismatched_reveal_rejected() {
    let mut rng = DeterministicRng::with_name("mismatched_reveal");

    // Create commitment with one set of nonces
    let nonce_r1 = rng.gen_32_bytes();
    let nonce_s1 = rng.gen_32_bytes();
    let commitment_hash = compute_commitment(&nonce_r1, &nonce_s1);

    let commitment = NonceCommitment {
        signer_id: "buyer".to_string(),
        commitment_hash,
        timestamp: 1000,
    };

    // Reveal with DIFFERENT nonces (attack)
    let nonce_r2 = rng.gen_32_bytes();
    let nonce_s2 = rng.gen_32_bytes();

    let reveal = NonceReveal {
        signer_id: "buyer".to_string(),
        nonce_r: nonce_r2,
        nonce_s: nonce_s2,
    };

    // Fixed version should reject
    let result = validate_reveal_fixed(&commitment, &reveal);
    assert_eq!(result, Err(CommitmentError::HashMismatch));

    // Buggy version would accept!
    let buggy_result = validate_reveal_buggy(&commitment, &reveal);
    assert!(buggy_result.is_ok(), "Bug: accepts mismatched reveal");
}

#[test]
fn test_wrong_signer_rejected() {
    let mut rng = DeterministicRng::with_name("wrong_signer");

    let nonce_r = rng.gen_32_bytes();
    let nonce_s = rng.gen_32_bytes();
    let commitment_hash = compute_commitment(&nonce_r, &nonce_s);

    let commitment = NonceCommitment {
        signer_id: "buyer".to_string(),
        commitment_hash,
        timestamp: 1000,
    };

    // Reveal from different signer
    let reveal = NonceReveal {
        signer_id: "vendor".to_string(), // Wrong signer!
        nonce_r,
        nonce_s,
    };

    let result = validate_reveal_fixed(&commitment, &reveal);
    assert_eq!(result, Err(CommitmentError::MissingCommitment));
}

// ============================================================================
// SESSION TESTS
// ============================================================================

#[test]
fn test_session_happy_path() {
    let mut rng = DeterministicRng::with_name("session_happy");
    let mut session = SigningSession::new();

    // Buyer commits
    let buyer_r = rng.gen_32_bytes();
    let buyer_s = rng.gen_32_bytes();
    session.add_commitment(NonceCommitment {
        signer_id: "buyer".to_string(),
        commitment_hash: compute_commitment(&buyer_r, &buyer_s),
        timestamp: 1000,
    });

    // Vendor commits
    let vendor_r = rng.gen_32_bytes();
    let vendor_s = rng.gen_32_bytes();
    session.add_commitment(NonceCommitment {
        signer_id: "vendor".to_string(),
        commitment_hash: compute_commitment(&vendor_r, &vendor_s),
        timestamp: 1001,
    });

    assert!(!session.all_revealed());

    // Buyer reveals
    let result1 = session.process_reveal(NonceReveal {
        signer_id: "buyer".to_string(),
        nonce_r: buyer_r,
        nonce_s: buyer_s,
    });
    assert!(result1.is_ok());

    // Vendor reveals
    let result2 = session.process_reveal(NonceReveal {
        signer_id: "vendor".to_string(),
        nonce_r: vendor_r,
        nonce_s: vendor_s,
    });
    assert!(result2.is_ok());

    assert!(session.all_revealed());
}

#[test]
fn test_session_duplicate_reveal_rejected() {
    let mut rng = DeterministicRng::with_name("duplicate_reveal");
    let mut session = SigningSession::new();

    let buyer_r = rng.gen_32_bytes();
    let buyer_s = rng.gen_32_bytes();

    session.add_commitment(NonceCommitment {
        signer_id: "buyer".to_string(),
        commitment_hash: compute_commitment(&buyer_r, &buyer_s),
        timestamp: 1000,
    });

    // First reveal succeeds
    let reveal = NonceReveal {
        signer_id: "buyer".to_string(),
        nonce_r: buyer_r,
        nonce_s: buyer_s,
    };
    assert!(session.process_reveal(reveal.clone()).is_ok());

    // Duplicate reveal fails
    let result = session.process_reveal(reveal);
    assert_eq!(result, Err(CommitmentError::DuplicateReveal));
}

#[test]
fn test_session_reveal_without_commitment_rejected() {
    let mut rng = DeterministicRng::with_name("no_commitment");
    let mut session = SigningSession::new();

    // No commitment added, try to reveal
    let result = session.process_reveal(NonceReveal {
        signer_id: "buyer".to_string(),
        nonce_r: rng.gen_32_bytes(),
        nonce_s: rng.gen_32_bytes(),
    });

    assert_eq!(result, Err(CommitmentError::MissingCommitment));
}

// ============================================================================
// ATTACK SCENARIO TESTS
// ============================================================================

#[test]
fn test_rogue_key_attack_prevented() {
    let mut rng = DeterministicRng::with_name("rogue_key");

    // Scenario: Attacker waits to see honest signer's nonce, then crafts malicious one

    // Honest signer commits first
    let honest_r = rng.gen_32_bytes();
    let honest_s = rng.gen_32_bytes();
    let honest_commitment = compute_commitment(&honest_r, &honest_s);

    // Attacker sees honest commitment (can't derive nonce from hash)
    // Attacker must also commit BEFORE seeing honest reveal
    let attacker_r = rng.gen_32_bytes();
    let attacker_s = rng.gen_32_bytes();
    let attacker_commitment = compute_commitment(&attacker_r, &attacker_s);

    let mut session = SigningSession::new();
    session.add_commitment(NonceCommitment {
        signer_id: "honest".to_string(),
        commitment_hash: honest_commitment,
        timestamp: 1000,
    });
    session.add_commitment(NonceCommitment {
        signer_id: "attacker".to_string(),
        commitment_hash: attacker_commitment,
        timestamp: 1001,
    });

    // Now honest reveals
    session.process_reveal(NonceReveal {
        signer_id: "honest".to_string(),
        nonce_r: honest_r,
        nonce_s: honest_s,
    }).unwrap();

    // Attacker tries to reveal different nonces (to manipulate final sig)
    let malicious_r = rng.gen_32_bytes();
    let malicious_s = rng.gen_32_bytes();

    let attack_result = session.process_reveal(NonceReveal {
        signer_id: "attacker".to_string(),
        nonce_r: malicious_r, // Different from committed!
        nonce_s: malicious_s,
    });

    // Attack prevented by commitment check
    assert_eq!(attack_result, Err(CommitmentError::HashMismatch));
}

// ============================================================================
// COMMITMENT HASH TESTS
// ============================================================================

#[test]
fn test_commitment_hash_deterministic() {
    let mut rng = DeterministicRng::with_name("hash_det");

    let r = rng.gen_32_bytes();
    let s = rng.gen_32_bytes();

    let hash1 = compute_commitment(&r, &s);
    let hash2 = compute_commitment(&r, &s);

    assert_eq!(hash1, hash2, "Commitment hash should be deterministic");
}

#[test]
fn test_different_nonces_different_hashes() {
    let mut rng = DeterministicRng::with_name("hash_diff");

    let r1 = rng.gen_32_bytes();
    let s1 = rng.gen_32_bytes();
    let r2 = rng.gen_32_bytes();
    let s2 = rng.gen_32_bytes();

    let hash1 = compute_commitment(&r1, &s1);
    let hash2 = compute_commitment(&r2, &s2);

    assert_ne!(hash1, hash2, "Different nonces should produce different hashes");
}

#[test]
fn test_commitment_order_matters() {
    let mut rng = DeterministicRng::with_name("hash_order");

    let r = rng.gen_32_bytes();
    let s = rng.gen_32_bytes();

    let hash_rs = compute_commitment(&r, &s);
    let hash_sr = compute_commitment(&s, &r); // Swapped order

    assert_ne!(hash_rs, hash_sr, "Order of r,s should matter in commitment");
}

// ============================================================================
// ZERO VALUE TESTS
// ============================================================================

#[test]
fn test_zero_nonces_handled() {
    let zeros_r = [0u8; 32];
    let zeros_s = [0u8; 32];

    let hash = compute_commitment(&zeros_r, &zeros_s);

    // Should produce a valid hash (though zero nonces are bad in practice)
    assert_ne!(hash, [0u8; 32], "Hash of zeros should not be zeros");

    // Verification should still work
    let commitment = NonceCommitment {
        signer_id: "test".to_string(),
        commitment_hash: hash,
        timestamp: 1000,
    };

    let reveal = NonceReveal {
        signer_id: "test".to_string(),
        nonce_r: zeros_r,
        nonce_s: zeros_s,
    };

    let result = validate_reveal_fixed(&commitment, &reveal);
    assert!(result.is_ok());
}
