//! Round Robin Signing Tests
//!
//! Tests for 2-of-3 multisig signing workflow:
//! - Signing flow state machine
//! - Partial signature handling
//! - Role-based signing order
//! - Signature completion detection
//!
//! Reference: server/src/services/round_robin_signing.rs

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// SIGNING FLOW TYPES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningRole {
    Buyer,
    Vendor,
    Arbiter,
}

impl SigningRole {
    /// Get the Lagrange index for this role (1-indexed)
    pub fn lagrange_index(&self) -> u16 {
        match self {
            SigningRole::Buyer => 1,
            SigningRole::Vendor => 2,
            SigningRole::Arbiter => 3,
        }
    }

    /// Get display name
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningRole::Buyer => "buyer",
            SigningRole::Vendor => "vendor",
            SigningRole::Arbiter => "arbiter",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningFlowStatus {
    NotStarted,
    AwaitingFirstSigner,
    FirstSignerSigned,
    AwaitingSecondSigner,
    SecondSignerSigned,
    Complete,
    Failed,
}

#[derive(Debug)]
pub struct PartialSignature {
    pub role: SigningRole,
    pub partial_key_image: [u8; 32],
    pub clsag_s: [u8; 32],
    pub timestamp: u64,
}

#[derive(Debug)]
pub struct SigningSession {
    pub escrow_id: String,
    pub status: SigningFlowStatus,
    pub required_signers: (SigningRole, SigningRole),
    pub first_signer: Option<SigningRole>,
    pub signatures: Vec<PartialSignature>,
    pub tx_hash: [u8; 32],
}

#[derive(Debug, PartialEq)]
pub enum SigningError {
    NotYourTurn(SigningRole),
    AlreadySigned(SigningRole),
    InvalidRole(SigningRole),
    SessionComplete,
    InvalidSignature,
    SignatureVerificationFailed,
}

impl SigningSession {
    pub fn new(
        escrow_id: String,
        signer1: SigningRole,
        signer2: SigningRole,
        tx_hash: [u8; 32],
    ) -> Self {
        Self {
            escrow_id,
            status: SigningFlowStatus::AwaitingFirstSigner,
            required_signers: (signer1, signer2),
            first_signer: None,
            signatures: Vec::new(),
            tx_hash,
        }
    }

    /// Check if a role is one of the required signers
    pub fn is_required_signer(&self, role: SigningRole) -> bool {
        self.required_signers.0 == role || self.required_signers.1 == role
    }

    /// Check if a role has already signed
    pub fn has_signed(&self, role: SigningRole) -> bool {
        self.signatures.iter().any(|s| s.role == role)
    }

    /// Submit a partial signature
    pub fn submit_signature(&mut self, sig: PartialSignature) -> Result<(), SigningError> {
        // Check if session is complete
        if self.status == SigningFlowStatus::Complete {
            return Err(SigningError::SessionComplete);
        }

        // Check if role is valid
        if !self.is_required_signer(sig.role) {
            return Err(SigningError::InvalidRole(sig.role));
        }

        // Check if already signed
        if self.has_signed(sig.role) {
            return Err(SigningError::AlreadySigned(sig.role));
        }

        // Update state based on current status
        match self.status {
            SigningFlowStatus::AwaitingFirstSigner => {
                self.first_signer = Some(sig.role);
                self.signatures.push(sig);
                self.status = SigningFlowStatus::FirstSignerSigned;
                Ok(())
            }
            SigningFlowStatus::FirstSignerSigned | SigningFlowStatus::AwaitingSecondSigner => {
                // Verify it's the other signer
                let first = self.first_signer.unwrap();
                if sig.role == first {
                    return Err(SigningError::AlreadySigned(sig.role));
                }

                self.signatures.push(sig);
                self.status = SigningFlowStatus::SecondSignerSigned;
                Ok(())
            }
            _ => Err(SigningError::SessionComplete),
        }
    }

    /// Mark session as complete (after signature aggregation)
    pub fn mark_complete(&mut self) {
        self.status = SigningFlowStatus::Complete;
    }

    /// Check if ready for aggregation
    pub fn ready_for_aggregation(&self) -> bool {
        self.signatures.len() == 2
    }

    /// Get the other required signer
    pub fn other_signer(&self, role: SigningRole) -> Option<SigningRole> {
        if self.required_signers.0 == role {
            Some(self.required_signers.1)
        } else if self.required_signers.1 == role {
            Some(self.required_signers.0)
        } else {
            None
        }
    }
}

// ============================================================================
// BASIC SIGNING FLOW TESTS
// ============================================================================

#[test]
fn test_new_session_status() {
    let session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        [0u8; 32],
    );

    assert_eq!(session.status, SigningFlowStatus::AwaitingFirstSigner);
    assert!(session.signatures.is_empty());
    assert!(session.first_signer.is_none());
}

#[test]
fn test_buyer_vendor_happy_path() {
    let mut rng = DeterministicRng::with_name("signing_bv");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    // Buyer signs first
    let buyer_sig = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    assert!(session.submit_signature(buyer_sig).is_ok());
    assert_eq!(session.status, SigningFlowStatus::FirstSignerSigned);
    assert_eq!(session.first_signer, Some(SigningRole::Buyer));

    // Vendor signs second
    let vendor_sig = PartialSignature {
        role: SigningRole::Vendor,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    assert!(session.submit_signature(vendor_sig).is_ok());
    assert_eq!(session.status, SigningFlowStatus::SecondSignerSigned);

    // Ready for aggregation
    assert!(session.ready_for_aggregation());
    assert_eq!(session.signatures.len(), 2);
}

#[test]
fn test_vendor_signs_first() {
    let mut rng = DeterministicRng::with_name("signing_vb");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    // Vendor signs first (order doesn't matter)
    let vendor_sig = PartialSignature {
        role: SigningRole::Vendor,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    assert!(session.submit_signature(vendor_sig).is_ok());
    assert_eq!(session.first_signer, Some(SigningRole::Vendor));

    // Buyer signs second
    let buyer_sig = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    assert!(session.submit_signature(buyer_sig).is_ok());

    assert!(session.ready_for_aggregation());
}

#[test]
fn test_buyer_arbiter_signing() {
    let mut rng = DeterministicRng::with_name("signing_ba");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Arbiter,
        rng.gen_32_bytes(),
    );

    // Buyer signs
    let buyer_sig = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    assert!(session.submit_signature(buyer_sig).is_ok());

    // Arbiter signs
    let arbiter_sig = PartialSignature {
        role: SigningRole::Arbiter,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    assert!(session.submit_signature(arbiter_sig).is_ok());

    assert!(session.ready_for_aggregation());
}

#[test]
fn test_vendor_arbiter_signing() {
    let mut rng = DeterministicRng::with_name("signing_va");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Vendor,
        SigningRole::Arbiter,
        rng.gen_32_bytes(),
    );

    // Vendor signs
    let vendor_sig = PartialSignature {
        role: SigningRole::Vendor,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    assert!(session.submit_signature(vendor_sig).is_ok());

    // Arbiter signs
    let arbiter_sig = PartialSignature {
        role: SigningRole::Arbiter,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    assert!(session.submit_signature(arbiter_sig).is_ok());

    assert!(session.ready_for_aggregation());
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

#[test]
fn test_double_signing_rejected() {
    let mut rng = DeterministicRng::with_name("double_sign");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    // Buyer signs
    let sig1 = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    session.submit_signature(sig1).unwrap();

    // Buyer tries to sign again
    let sig2 = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    let result = session.submit_signature(sig2);

    assert_eq!(result, Err(SigningError::AlreadySigned(SigningRole::Buyer)));
}

#[test]
fn test_invalid_role_rejected() {
    let mut rng = DeterministicRng::with_name("invalid_role");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    // Arbiter is not a required signer
    let sig = PartialSignature {
        role: SigningRole::Arbiter,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    let result = session.submit_signature(sig);

    assert_eq!(result, Err(SigningError::InvalidRole(SigningRole::Arbiter)));
}

#[test]
fn test_signing_after_complete_rejected() {
    let mut rng = DeterministicRng::with_name("after_complete");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    // Complete signing
    let sig1 = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    session.submit_signature(sig1).unwrap();

    let sig2 = PartialSignature {
        role: SigningRole::Vendor,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    session.submit_signature(sig2).unwrap();

    // Mark complete
    session.mark_complete();

    // Try to submit another signature
    let sig3 = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1002,
    };
    let result = session.submit_signature(sig3);

    assert_eq!(result, Err(SigningError::SessionComplete));
}

// ============================================================================
// ROLE VALIDATION TESTS
// ============================================================================

#[test]
fn test_is_required_signer() {
    let session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        [0u8; 32],
    );

    assert!(session.is_required_signer(SigningRole::Buyer));
    assert!(session.is_required_signer(SigningRole::Vendor));
    assert!(!session.is_required_signer(SigningRole::Arbiter));
}

#[test]
fn test_other_signer() {
    let session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        [0u8; 32],
    );

    assert_eq!(
        session.other_signer(SigningRole::Buyer),
        Some(SigningRole::Vendor)
    );
    assert_eq!(
        session.other_signer(SigningRole::Vendor),
        Some(SigningRole::Buyer)
    );
    assert_eq!(session.other_signer(SigningRole::Arbiter), None);
}

#[test]
fn test_lagrange_indices() {
    assert_eq!(SigningRole::Buyer.lagrange_index(), 1);
    assert_eq!(SigningRole::Vendor.lagrange_index(), 2);
    assert_eq!(SigningRole::Arbiter.lagrange_index(), 3);
}

// ============================================================================
// ALL SIGNER COMBINATIONS
// ============================================================================

#[test]
fn test_all_valid_signer_pairs() {
    let mut rng = DeterministicRng::with_name("all_pairs");

    // All valid 2-of-3 combinations
    let pairs = [
        (SigningRole::Buyer, SigningRole::Vendor),
        (SigningRole::Buyer, SigningRole::Arbiter),
        (SigningRole::Vendor, SigningRole::Arbiter),
    ];

    for (signer1, signer2) in pairs {
        let mut session = SigningSession::new(
            format!("escrow_{}_{}", signer1.as_str(), signer2.as_str()),
            signer1,
            signer2,
            rng.gen_32_bytes(),
        );

        // First signer
        let sig1 = PartialSignature {
            role: signer1,
            partial_key_image: rng.gen_32_bytes(),
            clsag_s: rng.gen_32_bytes(),
            timestamp: 1000,
        };
        assert!(
            session.submit_signature(sig1).is_ok(),
            "First signer {:?} should succeed",
            signer1
        );

        // Second signer
        let sig2 = PartialSignature {
            role: signer2,
            partial_key_image: rng.gen_32_bytes(),
            clsag_s: rng.gen_32_bytes(),
            timestamp: 1001,
        };
        assert!(
            session.submit_signature(sig2).is_ok(),
            "Second signer {:?} should succeed",
            signer2
        );

        assert!(
            session.ready_for_aggregation(),
            "Session for {:?}+{:?} should be ready",
            signer1,
            signer2
        );
    }
}

// ============================================================================
// SIGNATURE AGGREGATION READINESS
// ============================================================================

#[test]
fn test_not_ready_with_zero_signatures() {
    let session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        [0u8; 32],
    );

    assert!(!session.ready_for_aggregation());
}

#[test]
fn test_not_ready_with_one_signature() {
    let mut rng = DeterministicRng::with_name("one_sig");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    let sig = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    session.submit_signature(sig).unwrap();

    assert!(!session.ready_for_aggregation());
}

#[test]
fn test_ready_with_two_signatures() {
    let mut rng = DeterministicRng::with_name("two_sig");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    let sig1 = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    session.submit_signature(sig1).unwrap();

    let sig2 = PartialSignature {
        role: SigningRole::Vendor,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    session.submit_signature(sig2).unwrap();

    assert!(session.ready_for_aggregation());
}

// ============================================================================
// SIGNATURE DATA INTEGRITY
// ============================================================================

#[test]
fn test_signature_data_preserved() {
    let mut rng = DeterministicRng::with_name("data_preserve");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    let pki = rng.gen_32_bytes();
    let clsag_s = rng.gen_32_bytes();
    let timestamp = 12345u64;

    let sig = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: pki,
        clsag_s,
        timestamp,
    };
    session.submit_signature(sig).unwrap();

    // Verify data is preserved
    let stored = &session.signatures[0];
    assert_eq!(stored.role, SigningRole::Buyer);
    assert_eq!(stored.partial_key_image, pki);
    assert_eq!(stored.clsag_s, clsag_s);
    assert_eq!(stored.timestamp, timestamp);
}

#[test]
fn test_signatures_ordered_by_submission() {
    let mut rng = DeterministicRng::with_name("sig_order");

    let mut session = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    // Vendor signs first
    let sig1 = PartialSignature {
        role: SigningRole::Vendor,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    session.submit_signature(sig1).unwrap();

    // Buyer signs second
    let sig2 = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    session.submit_signature(sig2).unwrap();

    // Signatures are in submission order
    assert_eq!(session.signatures[0].role, SigningRole::Vendor);
    assert_eq!(session.signatures[1].role, SigningRole::Buyer);
}

// ============================================================================
// MULTI-SESSION ISOLATION
// ============================================================================

#[test]
fn test_sessions_are_isolated() {
    let mut rng = DeterministicRng::with_name("isolation");

    let mut session1 = SigningSession::new(
        "escrow_001".to_string(),
        SigningRole::Buyer,
        SigningRole::Vendor,
        rng.gen_32_bytes(),
    );

    let mut session2 = SigningSession::new(
        "escrow_002".to_string(),
        SigningRole::Buyer,
        SigningRole::Arbiter,
        rng.gen_32_bytes(),
    );

    // Sign in session1
    let sig1 = PartialSignature {
        role: SigningRole::Buyer,
        partial_key_image: rng.gen_32_bytes(),
        clsag_s: rng.gen_32_bytes(),
        timestamp: 1000,
    };
    session1.submit_signature(sig1).unwrap();

    // Session2 is unaffected
    assert_eq!(session2.signatures.len(), 0);
    assert_eq!(session2.status, SigningFlowStatus::AwaitingFirstSigner);
}

// ============================================================================
// ROLE STRING CONVERSION
// ============================================================================

#[test]
fn test_role_as_str() {
    assert_eq!(SigningRole::Buyer.as_str(), "buyer");
    assert_eq!(SigningRole::Vendor.as_str(), "vendor");
    assert_eq!(SigningRole::Arbiter.as_str(), "arbiter");
}
