//! State Transition Tests
//!
//! Tests for escrow state machine transitions:
//! - Valid state transitions
//! - Invalid state transitions (blocked)
//! - Terminal states
//! - State invariants
//!
//! Reference: server/src/models/escrow.rs

use std::collections::HashSet;

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// ESCROW STATUS ENUM
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EscrowStatus {
    // Initial states
    Created,
    AwaitingMultisigSetup,

    // Setup states
    MultisigInfoExchanged,
    WalletReady,

    // Funding states
    AwaitingFunding,
    Funded,
    Confirmed,

    // Active states
    AwaitingDelivery,
    DeliveryConfirmed,

    // Signing states
    AwaitingRelease,
    AwaitingRefund,
    SigningInProgress,

    // Dispute states
    DisputeOpened,
    DisputeUnderReview,
    DisputeResolved,

    // Terminal states
    Released,
    Refunded,
    Cancelled,
    Expired,
    Failed,
}

impl EscrowStatus {
    /// Check if this is a terminal (final) state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            EscrowStatus::Released
                | EscrowStatus::Refunded
                | EscrowStatus::Cancelled
                | EscrowStatus::Expired
                | EscrowStatus::Failed
        )
    }

    /// Get all valid next states from current state
    pub fn valid_transitions(&self) -> Vec<EscrowStatus> {
        use EscrowStatus::*;
        match self {
            Created => vec![AwaitingMultisigSetup, Cancelled],
            AwaitingMultisigSetup => vec![MultisigInfoExchanged, Cancelled, Expired],
            MultisigInfoExchanged => vec![WalletReady, Cancelled, Expired],
            WalletReady => vec![AwaitingFunding, Cancelled],
            AwaitingFunding => vec![Funded, Cancelled, Expired],
            Funded => vec![Confirmed, Cancelled],
            Confirmed => vec![AwaitingDelivery],
            AwaitingDelivery => vec![DeliveryConfirmed, DisputeOpened, Expired],
            DeliveryConfirmed => vec![AwaitingRelease, DisputeOpened],
            AwaitingRelease => vec![SigningInProgress, DisputeOpened],
            AwaitingRefund => vec![SigningInProgress, DisputeOpened],
            SigningInProgress => vec![Released, Refunded, Failed],
            DisputeOpened => vec![DisputeUnderReview],
            DisputeUnderReview => vec![DisputeResolved],
            DisputeResolved => vec![AwaitingRelease, AwaitingRefund],
            Released => vec![], // Terminal
            Refunded => vec![], // Terminal
            Cancelled => vec![], // Terminal
            Expired => vec![], // Terminal
            Failed => vec![], // Terminal
        }
    }

    /// Get human-readable name
    pub fn as_str(&self) -> &'static str {
        use EscrowStatus::*;
        match self {
            Created => "created",
            AwaitingMultisigSetup => "awaiting_multisig_setup",
            MultisigInfoExchanged => "multisig_info_exchanged",
            WalletReady => "wallet_ready",
            AwaitingFunding => "awaiting_funding",
            Funded => "funded",
            Confirmed => "confirmed",
            AwaitingDelivery => "awaiting_delivery",
            DeliveryConfirmed => "delivery_confirmed",
            AwaitingRelease => "awaiting_release",
            AwaitingRefund => "awaiting_refund",
            SigningInProgress => "signing_in_progress",
            DisputeOpened => "dispute_opened",
            DisputeUnderReview => "dispute_under_review",
            DisputeResolved => "dispute_resolved",
            Released => "released",
            Refunded => "refunded",
            Cancelled => "cancelled",
            Expired => "expired",
            Failed => "failed",
        }
    }
}

// ============================================================================
// STATE MACHINE
// ============================================================================

#[derive(Debug)]
pub struct EscrowStateMachine {
    pub status: EscrowStatus,
    pub transition_history: Vec<(EscrowStatus, EscrowStatus)>,
}

#[derive(Debug, PartialEq)]
pub enum TransitionError {
    InvalidTransition { from: EscrowStatus, to: EscrowStatus },
    AlreadyTerminal(EscrowStatus),
}

impl EscrowStateMachine {
    pub fn new() -> Self {
        Self {
            status: EscrowStatus::Created,
            transition_history: Vec::new(),
        }
    }

    pub fn with_status(status: EscrowStatus) -> Self {
        Self {
            status,
            transition_history: Vec::new(),
        }
    }

    /// Attempt to transition to a new state
    pub fn transition(&mut self, to: EscrowStatus) -> Result<(), TransitionError> {
        if self.status.is_terminal() {
            return Err(TransitionError::AlreadyTerminal(self.status));
        }

        let valid = self.status.valid_transitions();
        if !valid.contains(&to) {
            return Err(TransitionError::InvalidTransition {
                from: self.status,
                to,
            });
        }

        let from = self.status;
        self.status = to;
        self.transition_history.push((from, to));
        Ok(())
    }

    /// Check if a transition is valid without performing it
    pub fn can_transition(&self, to: EscrowStatus) -> bool {
        if self.status.is_terminal() {
            return false;
        }
        self.status.valid_transitions().contains(&to)
    }
}

impl Default for EscrowStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// VALID TRANSITION TESTS
// ============================================================================

#[test]
fn test_happy_path_release() {
    let mut sm = EscrowStateMachine::new();

    // Complete happy path: Created -> Released
    let transitions = [
        EscrowStatus::AwaitingMultisigSetup,
        EscrowStatus::MultisigInfoExchanged,
        EscrowStatus::WalletReady,
        EscrowStatus::AwaitingFunding,
        EscrowStatus::Funded,
        EscrowStatus::Confirmed,
        EscrowStatus::AwaitingDelivery,
        EscrowStatus::DeliveryConfirmed,
        EscrowStatus::AwaitingRelease,
        EscrowStatus::SigningInProgress,
        EscrowStatus::Released,
    ];

    for target in transitions {
        assert!(
            sm.transition(target).is_ok(),
            "Should transition to {:?} from {:?}",
            target,
            sm.status
        );
    }

    assert_eq!(sm.status, EscrowStatus::Released);
    assert!(sm.status.is_terminal());
}

#[test]
fn test_refund_path() {
    let mut sm = EscrowStateMachine::new();

    // Refund path via dispute
    let transitions = [
        EscrowStatus::AwaitingMultisigSetup,
        EscrowStatus::MultisigInfoExchanged,
        EscrowStatus::WalletReady,
        EscrowStatus::AwaitingFunding,
        EscrowStatus::Funded,
        EscrowStatus::Confirmed,
        EscrowStatus::AwaitingDelivery,
        EscrowStatus::DisputeOpened,
        EscrowStatus::DisputeUnderReview,
        EscrowStatus::DisputeResolved,
        EscrowStatus::AwaitingRefund,
        EscrowStatus::SigningInProgress,
        EscrowStatus::Refunded,
    ];

    for target in transitions {
        assert!(
            sm.transition(target).is_ok(),
            "Should transition to {:?}",
            target
        );
    }

    assert_eq!(sm.status, EscrowStatus::Refunded);
}

#[test]
fn test_early_cancellation() {
    let mut sm = EscrowStateMachine::new();

    // Can cancel from Created
    assert!(sm.transition(EscrowStatus::Cancelled).is_ok());
    assert_eq!(sm.status, EscrowStatus::Cancelled);
    assert!(sm.status.is_terminal());
}

#[test]
fn test_cancellation_during_setup() {
    let mut sm = EscrowStateMachine::new();

    sm.transition(EscrowStatus::AwaitingMultisigSetup).unwrap();
    sm.transition(EscrowStatus::Cancelled).unwrap();

    assert_eq!(sm.status, EscrowStatus::Cancelled);
}

#[test]
fn test_expiration_during_funding() {
    let mut sm = EscrowStateMachine::new();

    sm.transition(EscrowStatus::AwaitingMultisigSetup).unwrap();
    sm.transition(EscrowStatus::MultisigInfoExchanged).unwrap();
    sm.transition(EscrowStatus::WalletReady).unwrap();
    sm.transition(EscrowStatus::AwaitingFunding).unwrap();
    sm.transition(EscrowStatus::Expired).unwrap();

    assert_eq!(sm.status, EscrowStatus::Expired);
}

// ============================================================================
// INVALID TRANSITION TESTS
// ============================================================================

#[test]
fn test_invalid_skip_steps() {
    let mut sm = EscrowStateMachine::new();

    // Cannot skip directly to Funded
    let result = sm.transition(EscrowStatus::Funded);
    assert!(
        matches!(result, Err(TransitionError::InvalidTransition { .. })),
        "Should not skip from Created to Funded"
    );
}

#[test]
fn test_invalid_backwards() {
    let mut sm = EscrowStateMachine::new();

    sm.transition(EscrowStatus::AwaitingMultisigSetup).unwrap();
    sm.transition(EscrowStatus::MultisigInfoExchanged).unwrap();

    // Cannot go backwards
    let result = sm.transition(EscrowStatus::AwaitingMultisigSetup);
    assert!(
        matches!(result, Err(TransitionError::InvalidTransition { .. })),
        "Should not go backwards"
    );
}

#[test]
fn test_invalid_from_terminal() {
    let mut sm = EscrowStateMachine::with_status(EscrowStatus::Released);

    // Cannot transition from terminal state
    let result = sm.transition(EscrowStatus::AwaitingRelease);
    assert!(
        matches!(result, Err(TransitionError::AlreadyTerminal(_))),
        "Should not transition from terminal state"
    );
}

#[test]
fn test_all_terminal_states_block_transitions() {
    let terminals = [
        EscrowStatus::Released,
        EscrowStatus::Refunded,
        EscrowStatus::Cancelled,
        EscrowStatus::Expired,
        EscrowStatus::Failed,
    ];

    for terminal in terminals {
        let mut sm = EscrowStateMachine::with_status(terminal);

        for target in [EscrowStatus::Created, EscrowStatus::Funded] {
            let result = sm.transition(target);
            assert!(
                result.is_err(),
                "Terminal state {:?} should block transition to {:?}",
                terminal,
                target
            );
        }
    }
}

#[test]
fn test_cannot_release_without_delivery() {
    let mut sm = EscrowStateMachine::new();

    // Get to AwaitingDelivery
    sm.transition(EscrowStatus::AwaitingMultisigSetup).unwrap();
    sm.transition(EscrowStatus::MultisigInfoExchanged).unwrap();
    sm.transition(EscrowStatus::WalletReady).unwrap();
    sm.transition(EscrowStatus::AwaitingFunding).unwrap();
    sm.transition(EscrowStatus::Funded).unwrap();
    sm.transition(EscrowStatus::Confirmed).unwrap();
    sm.transition(EscrowStatus::AwaitingDelivery).unwrap();

    // Cannot skip to AwaitingRelease without DeliveryConfirmed
    let result = sm.transition(EscrowStatus::AwaitingRelease);
    assert!(
        result.is_err(),
        "Should not skip delivery confirmation"
    );
}

// ============================================================================
// DISPUTE PATH TESTS
// ============================================================================

#[test]
fn test_dispute_from_awaiting_delivery() {
    let mut sm = EscrowStateMachine::with_status(EscrowStatus::AwaitingDelivery);

    assert!(sm.transition(EscrowStatus::DisputeOpened).is_ok());
    assert!(sm.transition(EscrowStatus::DisputeUnderReview).is_ok());
    assert!(sm.transition(EscrowStatus::DisputeResolved).is_ok());

    // Can go to either release or refund after dispute
    assert!(sm.can_transition(EscrowStatus::AwaitingRelease));
    assert!(sm.can_transition(EscrowStatus::AwaitingRefund));
}

#[test]
fn test_dispute_from_delivery_confirmed() {
    let mut sm = EscrowStateMachine::with_status(EscrowStatus::DeliveryConfirmed);

    assert!(sm.can_transition(EscrowStatus::DisputeOpened));
    assert!(sm.transition(EscrowStatus::DisputeOpened).is_ok());
}

#[test]
fn test_dispute_from_awaiting_release() {
    let mut sm = EscrowStateMachine::with_status(EscrowStatus::AwaitingRelease);

    // Can still open dispute even when awaiting release
    assert!(sm.can_transition(EscrowStatus::DisputeOpened));
}

#[test]
fn test_cannot_dispute_after_signing_started() {
    let mut sm = EscrowStateMachine::with_status(EscrowStatus::SigningInProgress);

    // Cannot open dispute once signing has begun
    let result = sm.transition(EscrowStatus::DisputeOpened);
    assert!(result.is_err());
}

// ============================================================================
// STATE INVARIANTS
// ============================================================================

#[test]
fn test_all_states_have_defined_transitions() {
    let all_states = [
        EscrowStatus::Created,
        EscrowStatus::AwaitingMultisigSetup,
        EscrowStatus::MultisigInfoExchanged,
        EscrowStatus::WalletReady,
        EscrowStatus::AwaitingFunding,
        EscrowStatus::Funded,
        EscrowStatus::Confirmed,
        EscrowStatus::AwaitingDelivery,
        EscrowStatus::DeliveryConfirmed,
        EscrowStatus::AwaitingRelease,
        EscrowStatus::AwaitingRefund,
        EscrowStatus::SigningInProgress,
        EscrowStatus::DisputeOpened,
        EscrowStatus::DisputeUnderReview,
        EscrowStatus::DisputeResolved,
        EscrowStatus::Released,
        EscrowStatus::Refunded,
        EscrowStatus::Cancelled,
        EscrowStatus::Expired,
        EscrowStatus::Failed,
    ];

    for state in &all_states {
        let transitions = state.valid_transitions();

        // Terminal states should have no transitions
        if state.is_terminal() {
            assert!(
                transitions.is_empty(),
                "Terminal state {:?} should have no transitions",
                state
            );
        }
        // Non-terminal states should have at least one transition
        else {
            assert!(
                !transitions.is_empty(),
                "Non-terminal state {:?} should have transitions",
                state
            );
        }
    }
}

#[test]
fn test_all_states_reachable() {
    // BFS to find all reachable states from Created
    let mut visited = HashSet::new();
    let mut queue = vec![EscrowStatus::Created];

    while let Some(state) = queue.pop() {
        if visited.contains(&state) {
            continue;
        }
        visited.insert(state);

        for next in state.valid_transitions() {
            if !visited.contains(&next) {
                queue.push(next);
            }
        }
    }

    // All non-terminal states should be reachable
    let expected_reachable = [
        EscrowStatus::Created,
        EscrowStatus::AwaitingMultisigSetup,
        EscrowStatus::MultisigInfoExchanged,
        EscrowStatus::WalletReady,
        EscrowStatus::AwaitingFunding,
        EscrowStatus::Funded,
        EscrowStatus::Confirmed,
        EscrowStatus::AwaitingDelivery,
        EscrowStatus::DeliveryConfirmed,
        EscrowStatus::AwaitingRelease,
        EscrowStatus::SigningInProgress,
        EscrowStatus::DisputeOpened,
        EscrowStatus::DisputeUnderReview,
        EscrowStatus::DisputeResolved,
        EscrowStatus::Released,
        EscrowStatus::Refunded,
        EscrowStatus::Cancelled,
        EscrowStatus::Expired,
        EscrowStatus::Failed,
    ];

    for state in expected_reachable {
        assert!(
            visited.contains(&state),
            "State {:?} should be reachable from Created",
            state
        );
    }
}

#[test]
fn test_no_cycles_except_terminal() {
    // Verify no state can reach itself (would indicate a cycle)
    let all_states = [
        EscrowStatus::Created,
        EscrowStatus::AwaitingMultisigSetup,
        EscrowStatus::MultisigInfoExchanged,
        EscrowStatus::WalletReady,
        EscrowStatus::AwaitingFunding,
        EscrowStatus::Funded,
        EscrowStatus::Confirmed,
        EscrowStatus::AwaitingDelivery,
        EscrowStatus::DeliveryConfirmed,
        EscrowStatus::AwaitingRelease,
        EscrowStatus::AwaitingRefund,
        EscrowStatus::SigningInProgress,
        EscrowStatus::DisputeOpened,
        EscrowStatus::DisputeUnderReview,
        EscrowStatus::DisputeResolved,
    ];

    for state in &all_states {
        let transitions = state.valid_transitions();
        assert!(
            !transitions.contains(state),
            "State {:?} should not transition to itself",
            state
        );
    }
}

// ============================================================================
// TRANSITION HISTORY TESTS
// ============================================================================

#[test]
fn test_transition_history_recorded() {
    let mut sm = EscrowStateMachine::new();

    sm.transition(EscrowStatus::AwaitingMultisigSetup).unwrap();
    sm.transition(EscrowStatus::MultisigInfoExchanged).unwrap();
    sm.transition(EscrowStatus::WalletReady).unwrap();

    assert_eq!(sm.transition_history.len(), 3);
    assert_eq!(
        sm.transition_history[0],
        (EscrowStatus::Created, EscrowStatus::AwaitingMultisigSetup)
    );
    assert_eq!(
        sm.transition_history[1],
        (EscrowStatus::AwaitingMultisigSetup, EscrowStatus::MultisigInfoExchanged)
    );
    assert_eq!(
        sm.transition_history[2],
        (EscrowStatus::MultisigInfoExchanged, EscrowStatus::WalletReady)
    );
}

#[test]
fn test_failed_transitions_not_recorded() {
    let mut sm = EscrowStateMachine::new();

    // Attempt invalid transition
    let _ = sm.transition(EscrowStatus::Released);

    assert!(
        sm.transition_history.is_empty(),
        "Failed transitions should not be recorded"
    );
    assert_eq!(sm.status, EscrowStatus::Created);
}

// ============================================================================
// RANDOM PATH TESTING
// ============================================================================

#[test]
fn test_random_valid_paths() {
    let mut rng = DeterministicRng::with_name("random_paths");

    // Run 100 random walks through the state machine
    for _ in 0..100 {
        let mut sm = EscrowStateMachine::new();

        // Walk until terminal state
        while !sm.status.is_terminal() {
            let valid = sm.status.valid_transitions();
            if valid.is_empty() {
                break;
            }

            let idx = rng.gen_range(valid.len() as u64) as usize;
            let next = valid[idx];
            sm.transition(next).unwrap();
        }

        // Should end in a terminal state
        assert!(
            sm.status.is_terminal(),
            "Random walk should end in terminal state, got {:?}",
            sm.status
        );
    }
}

#[test]
fn test_can_transition_predicate() {
    let sm = EscrowStateMachine::new();

    // Valid transitions from Created
    assert!(sm.can_transition(EscrowStatus::AwaitingMultisigSetup));
    assert!(sm.can_transition(EscrowStatus::Cancelled));

    // Invalid transitions from Created
    assert!(!sm.can_transition(EscrowStatus::Funded));
    assert!(!sm.can_transition(EscrowStatus::Released));
    assert!(!sm.can_transition(EscrowStatus::Created)); // Same state
}

// ============================================================================
// STATUS STRING CONVERSION
// ============================================================================

#[test]
fn test_status_as_str() {
    assert_eq!(EscrowStatus::Created.as_str(), "created");
    assert_eq!(EscrowStatus::AwaitingFunding.as_str(), "awaiting_funding");
    assert_eq!(EscrowStatus::SigningInProgress.as_str(), "signing_in_progress");
    assert_eq!(EscrowStatus::Released.as_str(), "released");
}

#[test]
fn test_all_statuses_have_unique_strings() {
    let all_states = [
        EscrowStatus::Created,
        EscrowStatus::AwaitingMultisigSetup,
        EscrowStatus::MultisigInfoExchanged,
        EscrowStatus::WalletReady,
        EscrowStatus::AwaitingFunding,
        EscrowStatus::Funded,
        EscrowStatus::Confirmed,
        EscrowStatus::AwaitingDelivery,
        EscrowStatus::DeliveryConfirmed,
        EscrowStatus::AwaitingRelease,
        EscrowStatus::AwaitingRefund,
        EscrowStatus::SigningInProgress,
        EscrowStatus::DisputeOpened,
        EscrowStatus::DisputeUnderReview,
        EscrowStatus::DisputeResolved,
        EscrowStatus::Released,
        EscrowStatus::Refunded,
        EscrowStatus::Cancelled,
        EscrowStatus::Expired,
        EscrowStatus::Failed,
    ];

    let strings: Vec<_> = all_states.iter().map(|s| s.as_str()).collect();
    let unique: HashSet<_> = strings.iter().collect();

    assert_eq!(
        strings.len(),
        unique.len(),
        "All status strings should be unique"
    );
}
