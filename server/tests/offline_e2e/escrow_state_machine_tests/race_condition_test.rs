//! Race Condition Tests
//!
//! Tests for concurrent operation handling:
//! - Only one of release/refund can succeed
//! - Double-spend prevention
//! - Concurrent state updates
//! - Atomic operations
//!
//! Reference: server/src/handlers/escrow.rs

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// SIMULATED ESCROW STATE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowAction {
    Release,
    Refund,
    Dispute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionResult {
    Success,
    AlreadyProcessed,
    InvalidState,
    RaceConditionDetected,
}

/// Thread-safe escrow state for testing race conditions
#[derive(Debug)]
pub struct AtomicEscrow {
    pub id: String,
    /// 0 = Pending, 1 = Released, 2 = Refunded, 3 = Disputed
    state: AtomicU64,
    /// Tracks number of attempted state changes
    change_attempts: AtomicU64,
    /// Tracks successful state changes
    successful_changes: AtomicU64,
}

impl AtomicEscrow {
    const PENDING: u64 = 0;
    const RELEASED: u64 = 1;
    const REFUNDED: u64 = 2;
    const DISPUTED: u64 = 3;

    pub fn new(id: String) -> Self {
        Self {
            id,
            state: AtomicU64::new(Self::PENDING),
            change_attempts: AtomicU64::new(0),
            successful_changes: AtomicU64::new(0),
        }
    }

    /// Get current state
    pub fn state(&self) -> u64 {
        self.state.load(Ordering::SeqCst)
    }

    /// Attempt atomic release
    pub fn try_release(&self) -> ActionResult {
        self.change_attempts.fetch_add(1, Ordering::SeqCst);

        // Compare-and-swap: only succeed if currently PENDING
        match self.state.compare_exchange(
            Self::PENDING,
            Self::RELEASED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                self.successful_changes.fetch_add(1, Ordering::SeqCst);
                ActionResult::Success
            }
            Err(current) => {
                if current == Self::RELEASED {
                    ActionResult::AlreadyProcessed
                } else if current == Self::REFUNDED {
                    ActionResult::RaceConditionDetected
                } else {
                    ActionResult::InvalidState
                }
            }
        }
    }

    /// Attempt atomic refund
    pub fn try_refund(&self) -> ActionResult {
        self.change_attempts.fetch_add(1, Ordering::SeqCst);

        match self.state.compare_exchange(
            Self::PENDING,
            Self::REFUNDED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                self.successful_changes.fetch_add(1, Ordering::SeqCst);
                ActionResult::Success
            }
            Err(current) => {
                if current == Self::REFUNDED {
                    ActionResult::AlreadyProcessed
                } else if current == Self::RELEASED {
                    ActionResult::RaceConditionDetected
                } else {
                    ActionResult::InvalidState
                }
            }
        }
    }

    /// Attempt atomic dispute
    pub fn try_dispute(&self) -> ActionResult {
        self.change_attempts.fetch_add(1, Ordering::SeqCst);

        match self.state.compare_exchange(
            Self::PENDING,
            Self::DISPUTED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                self.successful_changes.fetch_add(1, Ordering::SeqCst);
                ActionResult::Success
            }
            Err(_) => ActionResult::InvalidState,
        }
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64) {
        (
            self.change_attempts.load(Ordering::SeqCst),
            self.successful_changes.load(Ordering::SeqCst),
        )
    }

    /// Check if in terminal state
    pub fn is_terminal(&self) -> bool {
        let state = self.state();
        state == Self::RELEASED || state == Self::REFUNDED
    }
}

// ============================================================================
// SEQUENCE TRACKER FOR ORDERING
// ============================================================================

#[derive(Debug)]
pub struct SequenceTracker {
    operations: Arc<Mutex<Vec<(String, EscrowAction, ActionResult)>>>,
}

impl SequenceTracker {
    pub fn new() -> Self {
        Self {
            operations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn record(&self, escrow_id: &str, action: EscrowAction, result: ActionResult) {
        let mut ops = self.operations.lock().unwrap();
        ops.push((escrow_id.to_string(), action, result));
    }

    pub fn get_operations(&self) -> Vec<(String, EscrowAction, ActionResult)> {
        self.operations.lock().unwrap().clone()
    }

    pub fn count_successes(&self) -> usize {
        self.operations
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, _, r)| *r == ActionResult::Success)
            .count()
    }

    pub fn count_by_action(&self, action: EscrowAction) -> usize {
        self.operations
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, a, _)| *a == action)
            .count()
    }
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BASIC RACE CONDITION TESTS
// ============================================================================

#[test]
fn test_single_release_succeeds() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    let result = escrow.try_release();
    assert_eq!(result, ActionResult::Success);
    assert_eq!(escrow.state(), AtomicEscrow::RELEASED);
}

#[test]
fn test_single_refund_succeeds() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    let result = escrow.try_refund();
    assert_eq!(result, ActionResult::Success);
    assert_eq!(escrow.state(), AtomicEscrow::REFUNDED);
}

#[test]
fn test_double_release_rejected() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // First release
    let result1 = escrow.try_release();
    assert_eq!(result1, ActionResult::Success);

    // Second release
    let result2 = escrow.try_release();
    assert_eq!(result2, ActionResult::AlreadyProcessed);

    // Only one successful change
    let (attempts, successes) = escrow.stats();
    assert_eq!(attempts, 2);
    assert_eq!(successes, 1);
}

#[test]
fn test_double_refund_rejected() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // First refund
    let result1 = escrow.try_refund();
    assert_eq!(result1, ActionResult::Success);

    // Second refund
    let result2 = escrow.try_refund();
    assert_eq!(result2, ActionResult::AlreadyProcessed);
}

#[test]
fn test_release_then_refund_rejected() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // Release first
    let result1 = escrow.try_release();
    assert_eq!(result1, ActionResult::Success);

    // Refund attempt
    let result2 = escrow.try_refund();
    assert_eq!(result2, ActionResult::RaceConditionDetected);

    // State should still be Released
    assert_eq!(escrow.state(), AtomicEscrow::RELEASED);
}

#[test]
fn test_refund_then_release_rejected() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // Refund first
    let result1 = escrow.try_refund();
    assert_eq!(result1, ActionResult::Success);

    // Release attempt
    let result2 = escrow.try_release();
    assert_eq!(result2, ActionResult::RaceConditionDetected);

    // State should still be Refunded
    assert_eq!(escrow.state(), AtomicEscrow::REFUNDED);
}

// ============================================================================
// SIMULATED CONCURRENT ACCESS
// ============================================================================

#[test]
fn test_multiple_release_attempts() {
    let escrow = Arc::new(AtomicEscrow::new("escrow_001".to_string()));
    let tracker = Arc::new(SequenceTracker::new());

    // Simulate 10 concurrent release attempts
    let mut results = Vec::new();
    for _ in 0..10 {
        let result = escrow.try_release();
        tracker.record("escrow_001", EscrowAction::Release, result);
        results.push(result);
    }

    // Exactly one should succeed
    let successes = results.iter().filter(|r| **r == ActionResult::Success).count();
    assert_eq!(successes, 1, "Exactly one release should succeed");

    // Final state is Released
    assert_eq!(escrow.state(), AtomicEscrow::RELEASED);
}

#[test]
fn test_interleaved_release_refund() {
    let escrow = Arc::new(AtomicEscrow::new("escrow_001".to_string()));
    let tracker = Arc::new(SequenceTracker::new());

    // Simulate alternating release and refund attempts
    let mut results = Vec::new();
    for i in 0..10 {
        let result = if i % 2 == 0 {
            let r = escrow.try_release();
            tracker.record("escrow_001", EscrowAction::Release, r);
            r
        } else {
            let r = escrow.try_refund();
            tracker.record("escrow_001", EscrowAction::Refund, r);
            r
        };
        results.push(result);
    }

    // Exactly one should succeed (the first one)
    let successes = results.iter().filter(|r| **r == ActionResult::Success).count();
    assert_eq!(successes, 1, "Exactly one action should succeed");

    // First action wins (release at index 0)
    assert_eq!(escrow.state(), AtomicEscrow::RELEASED);
}

#[test]
fn test_first_action_wins() {
    let mut rng = DeterministicRng::with_name("first_wins");

    for _ in 0..100 {
        let escrow = AtomicEscrow::new("test".to_string());

        // Randomly choose first action
        let first_action = if rng.gen_range(2) == 0 {
            escrow.try_release();
            AtomicEscrow::RELEASED
        } else {
            escrow.try_refund();
            AtomicEscrow::REFUNDED
        };

        // Try the opposite action
        if first_action == AtomicEscrow::RELEASED {
            let result = escrow.try_refund();
            assert_eq!(result, ActionResult::RaceConditionDetected);
        } else {
            let result = escrow.try_release();
            assert_eq!(result, ActionResult::RaceConditionDetected);
        }

        // State matches first action
        assert_eq!(escrow.state(), first_action);
    }
}

// ============================================================================
// DISPUTE INTERACTION TESTS
// ============================================================================

#[test]
fn test_dispute_blocks_release() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // Dispute first
    let result1 = escrow.try_dispute();
    assert_eq!(result1, ActionResult::Success);

    // Release attempt fails
    let result2 = escrow.try_release();
    assert_eq!(result2, ActionResult::InvalidState);
}

#[test]
fn test_dispute_blocks_refund() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // Dispute first
    escrow.try_dispute();

    // Refund attempt fails
    let result = escrow.try_refund();
    assert_eq!(result, ActionResult::InvalidState);
}

#[test]
fn test_release_blocks_dispute() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // Release first
    escrow.try_release();

    // Dispute attempt fails
    let result = escrow.try_dispute();
    assert_eq!(result, ActionResult::InvalidState);
}

// ============================================================================
// STATISTICS TESTS
// ============================================================================

#[test]
fn test_stats_accuracy() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // 5 release attempts
    for _ in 0..5 {
        escrow.try_release();
    }

    // 3 refund attempts
    for _ in 0..3 {
        escrow.try_refund();
    }

    let (attempts, successes) = escrow.stats();
    assert_eq!(attempts, 8);
    assert_eq!(successes, 1);
}

#[test]
fn test_sequence_tracker_counts() {
    let tracker = SequenceTracker::new();

    tracker.record("e1", EscrowAction::Release, ActionResult::Success);
    tracker.record("e1", EscrowAction::Refund, ActionResult::RaceConditionDetected);
    tracker.record("e2", EscrowAction::Release, ActionResult::Success);

    assert_eq!(tracker.count_successes(), 2);
    assert_eq!(tracker.count_by_action(EscrowAction::Release), 2);
    assert_eq!(tracker.count_by_action(EscrowAction::Refund), 1);
}

// ============================================================================
// TERMINAL STATE TESTS
// ============================================================================

#[test]
fn test_is_terminal_released() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());
    assert!(!escrow.is_terminal());

    escrow.try_release();
    assert!(escrow.is_terminal());
}

#[test]
fn test_is_terminal_refunded() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());
    assert!(!escrow.is_terminal());

    escrow.try_refund();
    assert!(escrow.is_terminal());
}

#[test]
fn test_disputed_not_terminal() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());
    escrow.try_dispute();

    // Disputed is not terminal (can still be resolved)
    assert!(!escrow.is_terminal());
}

// ============================================================================
// IDEMPOTENCY TESTS
// ============================================================================

#[test]
fn test_release_idempotent_result() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // First release
    let r1 = escrow.try_release();
    assert_eq!(r1, ActionResult::Success);

    // Repeated releases get consistent result
    for _ in 0..10 {
        let result = escrow.try_release();
        assert_eq!(result, ActionResult::AlreadyProcessed);
    }

    // State unchanged
    assert_eq!(escrow.state(), AtomicEscrow::RELEASED);
}

#[test]
fn test_operation_count_tracks_all_attempts() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    for _ in 0..100 {
        escrow.try_release();
    }

    let (attempts, successes) = escrow.stats();
    assert_eq!(attempts, 100);
    assert_eq!(successes, 1);
}

// ============================================================================
// MULTI-ESCROW ISOLATION TESTS
// ============================================================================

#[test]
fn test_escrows_independent() {
    let escrow1 = AtomicEscrow::new("escrow_001".to_string());
    let escrow2 = AtomicEscrow::new("escrow_002".to_string());

    // Release first, refund second
    let r1 = escrow1.try_release();
    let r2 = escrow2.try_refund();

    assert_eq!(r1, ActionResult::Success);
    assert_eq!(r2, ActionResult::Success);

    assert_eq!(escrow1.state(), AtomicEscrow::RELEASED);
    assert_eq!(escrow2.state(), AtomicEscrow::REFUNDED);
}

#[test]
fn test_many_escrows_parallel_simulation() {
    let mut rng = DeterministicRng::with_name("many_escrows");
    let tracker = SequenceTracker::new();

    // Create 100 escrows
    let escrows: Vec<AtomicEscrow> = (0..100)
        .map(|i| AtomicEscrow::new(format!("escrow_{:03}", i)))
        .collect();

    // Randomly release or refund each
    for escrow in &escrows {
        let action = if rng.gen_range(2) == 0 {
            let result = escrow.try_release();
            tracker.record(&escrow.id, EscrowAction::Release, result);
            EscrowAction::Release
        } else {
            let result = escrow.try_refund();
            tracker.record(&escrow.id, EscrowAction::Refund, result);
            EscrowAction::Refund
        };
    }

    // All should succeed (each escrow only gets one action)
    assert_eq!(tracker.count_successes(), 100);

    // Each escrow in terminal state
    for escrow in &escrows {
        assert!(escrow.is_terminal(), "Escrow {} should be terminal", escrow.id);
    }
}

// ============================================================================
// ORDERING GUARANTEES
// ============================================================================

#[test]
fn test_deterministic_ordering() {
    // Same sequence should produce same results
    let results1: Vec<ActionResult> = {
        let escrow = AtomicEscrow::new("test".to_string());
        let mut results = Vec::new();
        results.push(escrow.try_release());
        results.push(escrow.try_refund());
        results.push(escrow.try_release());
        results
    };

    let results2: Vec<ActionResult> = {
        let escrow = AtomicEscrow::new("test".to_string());
        let mut results = Vec::new();
        results.push(escrow.try_release());
        results.push(escrow.try_refund());
        results.push(escrow.try_release());
        results
    };

    assert_eq!(results1, results2);
    assert_eq!(results1[0], ActionResult::Success);
    assert_eq!(results1[1], ActionResult::RaceConditionDetected);
    assert_eq!(results1[2], ActionResult::AlreadyProcessed);
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_no_operations() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    let (attempts, successes) = escrow.stats();
    assert_eq!(attempts, 0);
    assert_eq!(successes, 0);
    assert!(!escrow.is_terminal());
}

#[test]
fn test_state_read_consistency() {
    let escrow = AtomicEscrow::new("escrow_001".to_string());

    // Multiple reads should be consistent
    let state1 = escrow.state();
    let state2 = escrow.state();
    let state3 = escrow.state();

    assert_eq!(state1, state2);
    assert_eq!(state2, state3);
}
