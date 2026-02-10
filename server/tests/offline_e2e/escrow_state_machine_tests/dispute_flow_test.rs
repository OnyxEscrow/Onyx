//! Dispute Flow Tests
//!
//! Tests for escrow dispute resolution:
//! - Dispute opening conditions
//! - Evidence submission
//! - Arbiter resolution
//! - Outcome enforcement
//!
//! Reference: server/src/handlers/escrow.rs

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// DISPUTE TYPES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeReason {
    ItemNotReceived,
    ItemNotAsDescribed,
    ItemDamaged,
    WrongItem,
    QualityIssue,
    CommunicationFailure,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeStatus {
    Opened,
    EvidenceCollection,
    UnderReview,
    ResolutionProposed,
    Resolved,
    Appealed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeResolution {
    FullRefund,
    PartialRefund(u64), // Amount to refund
    ReleaseToVendor,
    Split(u64, u64),    // (vendor_amount, buyer_refund)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartyRole {
    Buyer,
    Vendor,
    Arbiter,
}

// ============================================================================
// EVIDENCE TYPES
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub submitted_by: PartyRole,
    pub evidence_type: EvidenceType,
    pub description: String,
    pub hash: [u8; 32], // Hash of evidence data
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceType {
    TrackingNumber,
    DeliveryPhoto,
    ChatLog,
    ProductPhoto,
    Receipt,
    Other,
}

// ============================================================================
// DISPUTE STATE MACHINE
// ============================================================================

#[derive(Debug, PartialEq)]
pub struct Dispute {
    pub escrow_id: String,
    pub status: DisputeStatus,
    pub reason: DisputeReason,
    pub opened_by: PartyRole,
    pub evidence: Vec<Evidence>,
    pub resolution: Option<DisputeResolution>,
    pub opened_at: u64,
    pub resolved_at: Option<u64>,
    pub arbiter_notes: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum DisputeError {
    AlreadyResolved,
    InvalidStatus(DisputeStatus),
    UnauthorizedAction(PartyRole),
    EvidenceSubmissionClosed,
    InvalidResolution,
    NoEvidenceProvided,
}

impl Dispute {
    pub fn open(
        escrow_id: String,
        reason: DisputeReason,
        opened_by: PartyRole,
        timestamp: u64,
    ) -> Result<Self, DisputeError> {
        // Only buyer or vendor can open dispute
        if opened_by == PartyRole::Arbiter {
            return Err(DisputeError::UnauthorizedAction(PartyRole::Arbiter));
        }

        Ok(Self {
            escrow_id,
            status: DisputeStatus::Opened,
            reason,
            opened_by,
            evidence: Vec::new(),
            resolution: None,
            opened_at: timestamp,
            resolved_at: None,
            arbiter_notes: None,
        })
    }

    /// Submit evidence to the dispute
    pub fn submit_evidence(&mut self, evidence: Evidence) -> Result<(), DisputeError> {
        // Can only submit during evidence collection or opened
        if !matches!(
            self.status,
            DisputeStatus::Opened | DisputeStatus::EvidenceCollection
        ) {
            return Err(DisputeError::EvidenceSubmissionClosed);
        }

        // Arbiter cannot submit evidence
        if evidence.submitted_by == PartyRole::Arbiter {
            return Err(DisputeError::UnauthorizedAction(PartyRole::Arbiter));
        }

        self.evidence.push(evidence);

        // Transition to evidence collection if first evidence
        if self.status == DisputeStatus::Opened {
            self.status = DisputeStatus::EvidenceCollection;
        }

        Ok(())
    }

    /// Move to arbiter review
    pub fn start_review(&mut self) -> Result<(), DisputeError> {
        if self.status != DisputeStatus::EvidenceCollection {
            return Err(DisputeError::InvalidStatus(self.status));
        }

        if self.evidence.is_empty() {
            return Err(DisputeError::NoEvidenceProvided);
        }

        self.status = DisputeStatus::UnderReview;
        Ok(())
    }

    /// Arbiter proposes a resolution
    pub fn propose_resolution(
        &mut self,
        resolution: DisputeResolution,
        notes: String,
    ) -> Result<(), DisputeError> {
        if self.status != DisputeStatus::UnderReview {
            return Err(DisputeError::InvalidStatus(self.status));
        }

        self.resolution = Some(resolution);
        self.arbiter_notes = Some(notes);
        self.status = DisputeStatus::ResolutionProposed;
        Ok(())
    }

    /// Finalize the resolution
    pub fn finalize(&mut self, timestamp: u64) -> Result<(), DisputeError> {
        if self.status != DisputeStatus::ResolutionProposed {
            return Err(DisputeError::InvalidStatus(self.status));
        }

        if self.resolution.is_none() {
            return Err(DisputeError::InvalidResolution);
        }

        self.status = DisputeStatus::Resolved;
        self.resolved_at = Some(timestamp);
        Ok(())
    }

    /// Appeal the resolution (within time limit)
    pub fn appeal(&mut self) -> Result<(), DisputeError> {
        if self.status != DisputeStatus::ResolutionProposed {
            return Err(DisputeError::InvalidStatus(self.status));
        }

        self.status = DisputeStatus::Appealed;
        Ok(())
    }

    /// Get evidence count by party
    pub fn evidence_count_by_party(&self, party: PartyRole) -> usize {
        self.evidence.iter().filter(|e| e.submitted_by == party).count()
    }
}

// ============================================================================
// DISPUTE OPENING TESTS
// ============================================================================

#[test]
fn test_buyer_can_open_dispute() {
    let dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    );

    assert!(dispute.is_ok());
    let dispute = dispute.unwrap();
    assert_eq!(dispute.status, DisputeStatus::Opened);
    assert_eq!(dispute.opened_by, PartyRole::Buyer);
    assert_eq!(dispute.reason, DisputeReason::ItemNotReceived);
}

#[test]
fn test_vendor_can_open_dispute() {
    let dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::CommunicationFailure,
        PartyRole::Vendor,
        1000,
    );

    assert!(dispute.is_ok());
    let dispute = dispute.unwrap();
    assert_eq!(dispute.opened_by, PartyRole::Vendor);
}

#[test]
fn test_arbiter_cannot_open_dispute() {
    let result = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Arbiter,
        1000,
    );

    assert_eq!(result, Err(DisputeError::UnauthorizedAction(PartyRole::Arbiter)));
}

#[test]
fn test_all_dispute_reasons() {
    let reasons = [
        DisputeReason::ItemNotReceived,
        DisputeReason::ItemNotAsDescribed,
        DisputeReason::ItemDamaged,
        DisputeReason::WrongItem,
        DisputeReason::QualityIssue,
        DisputeReason::CommunicationFailure,
        DisputeReason::Other,
    ];

    for reason in reasons {
        let dispute = Dispute::open(
            "escrow_001".to_string(),
            reason,
            PartyRole::Buyer,
            1000,
        );
        assert!(dispute.is_ok(), "Should open dispute with reason {:?}", reason);
    }
}

// ============================================================================
// EVIDENCE SUBMISSION TESTS
// ============================================================================

#[test]
fn test_buyer_can_submit_evidence() {
    let mut rng = DeterministicRng::with_name("evidence_buyer");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    let evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::ChatLog,
        description: "Chat showing no response".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };

    assert!(dispute.submit_evidence(evidence).is_ok());
    assert_eq!(dispute.evidence.len(), 1);
    assert_eq!(dispute.status, DisputeStatus::EvidenceCollection);
}

#[test]
fn test_vendor_can_submit_evidence() {
    let mut rng = DeterministicRng::with_name("evidence_vendor");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    let evidence = Evidence {
        submitted_by: PartyRole::Vendor,
        evidence_type: EvidenceType::TrackingNumber,
        description: "Tracking shows delivered".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };

    assert!(dispute.submit_evidence(evidence).is_ok());
    assert_eq!(dispute.evidence[0].submitted_by, PartyRole::Vendor);
}

#[test]
fn test_arbiter_cannot_submit_evidence() {
    let mut rng = DeterministicRng::with_name("evidence_arbiter");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    let evidence = Evidence {
        submitted_by: PartyRole::Arbiter,
        evidence_type: EvidenceType::Other,
        description: "Arbiter notes".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };

    let result = dispute.submit_evidence(evidence);
    assert_eq!(result, Err(DisputeError::UnauthorizedAction(PartyRole::Arbiter)));
}

#[test]
fn test_multiple_evidence_submissions() {
    let mut rng = DeterministicRng::with_name("multi_evidence");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotAsDescribed,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    // Buyer submits 2 pieces of evidence
    for i in 0..2 {
        let evidence = Evidence {
            submitted_by: PartyRole::Buyer,
            evidence_type: EvidenceType::ProductPhoto,
            description: format!("Photo {}", i),
            hash: rng.gen_32_bytes(),
            timestamp: 1001 + i as u64,
        };
        dispute.submit_evidence(evidence).unwrap();
    }

    // Vendor submits 1 piece
    let vendor_evidence = Evidence {
        submitted_by: PartyRole::Vendor,
        evidence_type: EvidenceType::ProductPhoto,
        description: "Original listing photo".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1003,
    };
    dispute.submit_evidence(vendor_evidence).unwrap();

    assert_eq!(dispute.evidence.len(), 3);
    assert_eq!(dispute.evidence_count_by_party(PartyRole::Buyer), 2);
    assert_eq!(dispute.evidence_count_by_party(PartyRole::Vendor), 1);
}

#[test]
fn test_cannot_submit_evidence_after_review() {
    let mut rng = DeterministicRng::with_name("evidence_closed");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    // Submit evidence and start review
    let evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::ChatLog,
        description: "Chat log".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    dispute.submit_evidence(evidence).unwrap();
    dispute.start_review().unwrap();

    // Try to submit more evidence
    let late_evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::Other,
        description: "Late evidence".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1002,
    };
    let result = dispute.submit_evidence(late_evidence);

    assert_eq!(result, Err(DisputeError::EvidenceSubmissionClosed));
}

// ============================================================================
// REVIEW AND RESOLUTION TESTS
// ============================================================================

#[test]
fn test_start_review_requires_evidence_collection_status() {
    // To start review, must be in EvidenceCollection status
    // When no evidence submitted, status is still Opened
    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    // Status is Opened, not EvidenceCollection
    assert_eq!(dispute.status, DisputeStatus::Opened);

    // start_review() fails because wrong status (must be EvidenceCollection)
    let result = dispute.start_review();
    assert_eq!(result, Err(DisputeError::InvalidStatus(DisputeStatus::Opened)));
}

#[test]
fn test_happy_path_full_refund() {
    let mut rng = DeterministicRng::with_name("full_refund");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    // Submit evidence
    let evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::ChatLog,
        description: "Evidence".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    dispute.submit_evidence(evidence).unwrap();

    // Start review
    dispute.start_review().unwrap();
    assert_eq!(dispute.status, DisputeStatus::UnderReview);

    // Propose resolution
    dispute.propose_resolution(
        DisputeResolution::FullRefund,
        "Item was never shipped".to_string(),
    ).unwrap();
    assert_eq!(dispute.status, DisputeStatus::ResolutionProposed);
    assert_eq!(dispute.resolution, Some(DisputeResolution::FullRefund));

    // Finalize
    dispute.finalize(2000).unwrap();
    assert_eq!(dispute.status, DisputeStatus::Resolved);
    assert_eq!(dispute.resolved_at, Some(2000));
}

#[test]
fn test_happy_path_release_to_vendor() {
    let mut rng = DeterministicRng::with_name("release_vendor");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    // Submit vendor evidence
    let evidence = Evidence {
        submitted_by: PartyRole::Vendor,
        evidence_type: EvidenceType::TrackingNumber,
        description: "Tracking shows delivered".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    dispute.submit_evidence(evidence).unwrap();

    // Review and resolve
    dispute.start_review().unwrap();
    dispute.propose_resolution(
        DisputeResolution::ReleaseToVendor,
        "Item was delivered according to tracking".to_string(),
    ).unwrap();
    dispute.finalize(2000).unwrap();

    assert_eq!(dispute.resolution, Some(DisputeResolution::ReleaseToVendor));
}

#[test]
fn test_partial_refund_resolution() {
    let mut rng = DeterministicRng::with_name("partial_refund");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemDamaged,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    let evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::ProductPhoto,
        description: "Photo of damage".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    dispute.submit_evidence(evidence).unwrap();

    dispute.start_review().unwrap();
    dispute.propose_resolution(
        DisputeResolution::PartialRefund(500_000_000_000), // 0.5 XMR
        "Partial damage warrants 50% refund".to_string(),
    ).unwrap();
    dispute.finalize(2000).unwrap();

    assert_eq!(
        dispute.resolution,
        Some(DisputeResolution::PartialRefund(500_000_000_000))
    );
}

#[test]
fn test_split_resolution() {
    let mut rng = DeterministicRng::with_name("split");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::QualityIssue,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    let evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::ProductPhoto,
        description: "Photo".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    dispute.submit_evidence(evidence).unwrap();

    dispute.start_review().unwrap();
    dispute.propose_resolution(
        DisputeResolution::Split(700_000_000_000, 300_000_000_000), // 70/30 split
        "Both parties share responsibility".to_string(),
    ).unwrap();
    dispute.finalize(2000).unwrap();

    assert_eq!(
        dispute.resolution,
        Some(DisputeResolution::Split(700_000_000_000, 300_000_000_000))
    );
}

// ============================================================================
// APPEAL TESTS
// ============================================================================

#[test]
fn test_can_appeal_before_finalization() {
    let mut rng = DeterministicRng::with_name("appeal");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    let evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::ChatLog,
        description: "Evidence".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    dispute.submit_evidence(evidence).unwrap();

    dispute.start_review().unwrap();
    dispute.propose_resolution(
        DisputeResolution::ReleaseToVendor,
        "Release to vendor".to_string(),
    ).unwrap();

    // Appeal instead of finalize
    assert!(dispute.appeal().is_ok());
    assert_eq!(dispute.status, DisputeStatus::Appealed);
}

#[test]
fn test_cannot_appeal_after_finalization() {
    let mut rng = DeterministicRng::with_name("appeal_late");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    let evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::ChatLog,
        description: "Evidence".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    dispute.submit_evidence(evidence).unwrap();

    dispute.start_review().unwrap();
    dispute.propose_resolution(DisputeResolution::FullRefund, "Refund".to_string()).unwrap();
    dispute.finalize(2000).unwrap();

    // Cannot appeal after resolved
    let result = dispute.appeal();
    assert_eq!(result, Err(DisputeError::InvalidStatus(DisputeStatus::Resolved)));
}

// ============================================================================
// STATE TRANSITION VALIDATION
// ============================================================================

#[test]
fn test_cannot_finalize_without_resolution() {
    let mut rng = DeterministicRng::with_name("no_resolution");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    let evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::ChatLog,
        description: "Evidence".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    dispute.submit_evidence(evidence).unwrap();

    dispute.start_review().unwrap();

    // Try to finalize without proposing resolution
    let result = dispute.finalize(2000);
    assert_eq!(result, Err(DisputeError::InvalidStatus(DisputeStatus::UnderReview)));
}

#[test]
fn test_cannot_propose_resolution_twice() {
    let mut rng = DeterministicRng::with_name("double_resolution");

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotReceived,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    let evidence = Evidence {
        submitted_by: PartyRole::Buyer,
        evidence_type: EvidenceType::ChatLog,
        description: "Evidence".to_string(),
        hash: rng.gen_32_bytes(),
        timestamp: 1001,
    };
    dispute.submit_evidence(evidence).unwrap();

    dispute.start_review().unwrap();
    dispute.propose_resolution(DisputeResolution::FullRefund, "Refund".to_string()).unwrap();

    // Try to propose again
    let result = dispute.propose_resolution(
        DisputeResolution::ReleaseToVendor,
        "Changed mind".to_string(),
    );
    assert_eq!(result, Err(DisputeError::InvalidStatus(DisputeStatus::ResolutionProposed)));
}

// ============================================================================
// EVIDENCE TYPE TESTS
// ============================================================================

#[test]
fn test_all_evidence_types() {
    let mut rng = DeterministicRng::with_name("all_evidence_types");

    let evidence_types = [
        EvidenceType::TrackingNumber,
        EvidenceType::DeliveryPhoto,
        EvidenceType::ChatLog,
        EvidenceType::ProductPhoto,
        EvidenceType::Receipt,
        EvidenceType::Other,
    ];

    let mut dispute = Dispute::open(
        "escrow_001".to_string(),
        DisputeReason::ItemNotAsDescribed,
        PartyRole::Buyer,
        1000,
    ).unwrap();

    for (i, etype) in evidence_types.iter().enumerate() {
        let evidence = Evidence {
            submitted_by: PartyRole::Buyer,
            evidence_type: *etype,
            description: format!("Evidence type {:?}", etype),
            hash: rng.gen_32_bytes(),
            timestamp: 1001 + i as u64,
        };
        assert!(
            dispute.submit_evidence(evidence).is_ok(),
            "Should accept evidence type {:?}",
            etype
        );
    }

    assert_eq!(dispute.evidence.len(), evidence_types.len());
}
