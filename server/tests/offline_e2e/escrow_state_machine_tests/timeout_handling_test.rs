//! Timeout Handling Tests
//!
//! Tests for escrow timeout and expiration logic:
//! - 48-hour grace period
//! - Auto-escalation to dispute
//! - Funding timeout
//! - Delivery timeout
//!
//! Reference: server/src/models/escrow.rs

use crate::mock_infrastructure::DeterministicRng;

// ============================================================================
// TIME CONSTANTS
// ============================================================================

/// 1 hour in seconds
const HOUR: u64 = 3600;

/// 24 hours in seconds
const DAY: u64 = 24 * HOUR;

/// Standard grace period (48 hours)
const GRACE_PERIOD: u64 = 48 * HOUR;

/// Multisig setup timeout (72 hours)
const MULTISIG_TIMEOUT: u64 = 72 * HOUR;

/// Funding timeout (168 hours = 7 days)
const FUNDING_TIMEOUT: u64 = 7 * DAY;

/// Delivery timeout (14 days default)
const DELIVERY_TIMEOUT: u64 = 14 * DAY;

/// Dispute resolution timeout (7 days)
const DISPUTE_TIMEOUT: u64 = 7 * DAY;

// ============================================================================
// TIMEOUT TRACKER
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutType {
    MultisigSetup,
    Funding,
    Delivery,
    ReleaseConfirmation,
    DisputeResolution,
    SigningCompletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutAction {
    Cancel,
    Expire,
    Escalate,
    AutoRefund,
    AutoRelease,
    NoAction,
}

#[derive(Debug)]
pub struct TimeoutTracker {
    pub escrow_id: String,
    pub timeout_type: TimeoutType,
    pub started_at: u64,
    pub deadline: u64,
    pub grace_period_ends: Option<u64>,
    pub action: TimeoutAction,
    pub triggered: bool,
}

impl TimeoutTracker {
    pub fn new(escrow_id: String, timeout_type: TimeoutType, started_at: u64) -> Self {
        let (deadline, grace_period_ends, action) = match timeout_type {
            TimeoutType::MultisigSetup => {
                (started_at + MULTISIG_TIMEOUT, None, TimeoutAction::Cancel)
            }
            TimeoutType::Funding => (started_at + FUNDING_TIMEOUT, None, TimeoutAction::Expire),
            TimeoutType::Delivery => (
                started_at + DELIVERY_TIMEOUT,
                Some(started_at + DELIVERY_TIMEOUT + GRACE_PERIOD),
                TimeoutAction::Escalate,
            ),
            TimeoutType::ReleaseConfirmation => {
                (started_at + GRACE_PERIOD, None, TimeoutAction::AutoRelease)
            }
            TimeoutType::DisputeResolution => (
                started_at + DISPUTE_TIMEOUT,
                Some(started_at + DISPUTE_TIMEOUT + GRACE_PERIOD),
                TimeoutAction::AutoRefund,
            ),
            TimeoutType::SigningCompletion => {
                (started_at + 24 * HOUR, None, TimeoutAction::Escalate)
            }
        };

        Self {
            escrow_id,
            timeout_type,
            started_at,
            deadline,
            grace_period_ends,
            action,
            triggered: false,
        }
    }

    /// Check timeout status at a given time
    pub fn check(&self, current_time: u64) -> TimeoutStatus {
        if self.triggered {
            return TimeoutStatus::AlreadyTriggered;
        }

        if current_time < self.deadline {
            let remaining = self.deadline - current_time;
            return TimeoutStatus::Pending { remaining };
        }

        // Past deadline
        if let Some(grace_end) = self.grace_period_ends {
            if current_time < grace_end {
                let grace_remaining = grace_end - current_time;
                return TimeoutStatus::InGracePeriod { grace_remaining };
            }
        }

        TimeoutStatus::Expired {
            action: self.action,
        }
    }

    /// Trigger the timeout action
    pub fn trigger(&mut self) -> Result<TimeoutAction, TimeoutError> {
        if self.triggered {
            return Err(TimeoutError::AlreadyTriggered);
        }

        self.triggered = true;
        Ok(self.action)
    }

    /// Extend the deadline
    pub fn extend(&mut self, additional_time: u64) -> Result<(), TimeoutError> {
        if self.triggered {
            return Err(TimeoutError::AlreadyTriggered);
        }

        self.deadline += additional_time;
        if let Some(ref mut grace) = self.grace_period_ends {
            *grace += additional_time;
        }

        Ok(())
    }

    /// Cancel the timeout (escrow progressed to next state)
    pub fn cancel(&mut self) {
        self.triggered = true;
        self.action = TimeoutAction::NoAction;
    }

    /// Time remaining until deadline
    pub fn time_remaining(&self, current_time: u64) -> Option<u64> {
        if current_time >= self.deadline {
            None
        } else {
            Some(self.deadline - current_time)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimeoutStatus {
    Pending { remaining: u64 },
    InGracePeriod { grace_remaining: u64 },
    Expired { action: TimeoutAction },
    AlreadyTriggered,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimeoutError {
    AlreadyTriggered,
}

// ============================================================================
// BASIC TIMEOUT TESTS
// ============================================================================

#[test]
fn test_timeout_not_expired_before_deadline() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    // Check before deadline
    let status = tracker.check(1000 + 3 * DAY);
    assert!(matches!(status, TimeoutStatus::Pending { .. }));
}

#[test]
fn test_timeout_expired_after_deadline() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    // Check after deadline (7 days + 1 second)
    let status = tracker.check(1000 + FUNDING_TIMEOUT + 1);
    assert!(matches!(
        status,
        TimeoutStatus::Expired {
            action: TimeoutAction::Expire
        }
    ));
}

#[test]
fn test_time_remaining_calculation() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    let remaining = tracker.time_remaining(1000 + 3 * DAY);
    assert_eq!(remaining, Some(FUNDING_TIMEOUT - 3 * DAY));

    let remaining_after = tracker.time_remaining(1000 + FUNDING_TIMEOUT + 1);
    assert_eq!(remaining_after, None);
}

// ============================================================================
// GRACE PERIOD TESTS
// ============================================================================

#[test]
fn test_delivery_has_grace_period() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Delivery, 1000);

    // Just after deadline but within grace
    let status = tracker.check(1000 + DELIVERY_TIMEOUT + 1 * HOUR);

    assert!(
        matches!(status, TimeoutStatus::InGracePeriod { grace_remaining } if grace_remaining < GRACE_PERIOD),
        "Should be in grace period"
    );
}

#[test]
fn test_delivery_expired_after_grace() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Delivery, 1000);

    // After grace period
    let status = tracker.check(1000 + DELIVERY_TIMEOUT + GRACE_PERIOD + 1);

    assert!(
        matches!(
            status,
            TimeoutStatus::Expired {
                action: TimeoutAction::Escalate
            }
        ),
        "Should escalate after grace period"
    );
}

#[test]
fn test_funding_no_grace_period() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    // Immediately after deadline
    let status = tracker.check(1000 + FUNDING_TIMEOUT + 1);

    // Should expire directly, no grace
    assert!(matches!(
        status,
        TimeoutStatus::Expired {
            action: TimeoutAction::Expire
        }
    ));
}

// ============================================================================
// TIMEOUT TYPE SPECIFIC TESTS
// ============================================================================

#[test]
fn test_multisig_setup_timeout() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::MultisigSetup, 1000);

    assert_eq!(tracker.deadline, 1000 + MULTISIG_TIMEOUT);
    assert_eq!(tracker.action, TimeoutAction::Cancel);
    assert!(tracker.grace_period_ends.is_none());
}

#[test]
fn test_release_confirmation_timeout() {
    let tracker = TimeoutTracker::new(
        "escrow_001".to_string(),
        TimeoutType::ReleaseConfirmation,
        1000,
    );

    // 48 hour auto-release
    assert_eq!(tracker.deadline, 1000 + GRACE_PERIOD);
    assert_eq!(tracker.action, TimeoutAction::AutoRelease);
}

#[test]
fn test_dispute_resolution_timeout() {
    let tracker = TimeoutTracker::new(
        "escrow_001".to_string(),
        TimeoutType::DisputeResolution,
        1000,
    );

    // 7 day resolution + 48h grace
    assert_eq!(tracker.deadline, 1000 + DISPUTE_TIMEOUT);
    assert_eq!(
        tracker.grace_period_ends,
        Some(1000 + DISPUTE_TIMEOUT + GRACE_PERIOD)
    );
    assert_eq!(tracker.action, TimeoutAction::AutoRefund);
}

#[test]
fn test_signing_completion_timeout() {
    let tracker = TimeoutTracker::new(
        "escrow_001".to_string(),
        TimeoutType::SigningCompletion,
        1000,
    );

    // 24 hour signing window
    assert_eq!(tracker.deadline, 1000 + 24 * HOUR);
    assert_eq!(tracker.action, TimeoutAction::Escalate);
}

// ============================================================================
// TRIGGER TESTS
// ============================================================================

#[test]
fn test_trigger_timeout() {
    let mut tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    let action = tracker.trigger();
    assert_eq!(action, Ok(TimeoutAction::Expire));
    assert!(tracker.triggered);
}

#[test]
fn test_cannot_trigger_twice() {
    let mut tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    tracker.trigger().unwrap();
    let result = tracker.trigger();

    assert_eq!(result, Err(TimeoutError::AlreadyTriggered));
}

#[test]
fn test_check_after_trigger() {
    let mut tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    tracker.trigger().unwrap();
    let status = tracker.check(1000 + FUNDING_TIMEOUT + 1);

    assert_eq!(status, TimeoutStatus::AlreadyTriggered);
}

// ============================================================================
// EXTEND TESTS
// ============================================================================

#[test]
fn test_extend_deadline() {
    let mut tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Delivery, 1000);

    let original_deadline = tracker.deadline;
    let original_grace = tracker.grace_period_ends.unwrap();

    tracker.extend(2 * DAY).unwrap();

    assert_eq!(tracker.deadline, original_deadline + 2 * DAY);
    assert_eq!(tracker.grace_period_ends, Some(original_grace + 2 * DAY));
}

#[test]
fn test_cannot_extend_after_trigger() {
    let mut tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Delivery, 1000);

    tracker.trigger().unwrap();
    let result = tracker.extend(2 * DAY);

    assert_eq!(result, Err(TimeoutError::AlreadyTriggered));
}

#[test]
fn test_extend_brings_back_from_expired() {
    let mut tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    // Currently expired
    let check_time = 1000 + FUNDING_TIMEOUT + 1 * HOUR;
    assert!(matches!(
        tracker.check(check_time),
        TimeoutStatus::Expired { .. }
    ));

    // Extend by 2 hours
    tracker.extend(2 * HOUR).unwrap();

    // Now pending again
    let status = tracker.check(check_time);
    assert!(matches!(status, TimeoutStatus::Pending { .. }));
}

// ============================================================================
// CANCEL TESTS
// ============================================================================

#[test]
fn test_cancel_timeout() {
    let mut tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    tracker.cancel();

    assert!(tracker.triggered);
    assert_eq!(tracker.action, TimeoutAction::NoAction);
}

#[test]
fn test_cancelled_shows_triggered() {
    let mut tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    tracker.cancel();
    let status = tracker.check(1000 + FUNDING_TIMEOUT + 1);

    assert_eq!(status, TimeoutStatus::AlreadyTriggered);
}

// ============================================================================
// 48-HOUR GRACE PERIOD SPECIFIC TESTS
// ============================================================================

#[test]
fn test_48h_grace_exact_boundary() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Delivery, 1000);

    let deadline = 1000 + DELIVERY_TIMEOUT;
    let grace_end = deadline + GRACE_PERIOD;

    // Exactly at deadline
    let status_at_deadline = tracker.check(deadline);
    assert!(matches!(
        status_at_deadline,
        TimeoutStatus::InGracePeriod { .. }
    ));

    // 1 second before grace ends
    let status_before_grace_end = tracker.check(grace_end - 1);
    assert!(matches!(
        status_before_grace_end,
        TimeoutStatus::InGracePeriod { .. }
    ));

    // Exactly at grace end
    let status_at_grace_end = tracker.check(grace_end);
    assert!(matches!(status_at_grace_end, TimeoutStatus::Expired { .. }));
}

#[test]
fn test_grace_remaining_decreases() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Delivery, 1000);

    let deadline = 1000 + DELIVERY_TIMEOUT;

    // At deadline, full 48h grace remaining
    if let TimeoutStatus::InGracePeriod { grace_remaining } = tracker.check(deadline) {
        assert_eq!(grace_remaining, GRACE_PERIOD);
    } else {
        panic!("Expected InGracePeriod");
    }

    // 24 hours later
    if let TimeoutStatus::InGracePeriod { grace_remaining } = tracker.check(deadline + 24 * HOUR) {
        assert_eq!(grace_remaining, 24 * HOUR);
    } else {
        panic!("Expected InGracePeriod");
    }
}

// ============================================================================
// AUTO-ACTION TESTS
// ============================================================================

#[test]
fn test_auto_release_after_48h() {
    let mut tracker = TimeoutTracker::new(
        "escrow_001".to_string(),
        TimeoutType::ReleaseConfirmation,
        1000,
    );

    // After 48 hours
    let status = tracker.check(1000 + GRACE_PERIOD + 1);
    assert!(matches!(
        status,
        TimeoutStatus::Expired {
            action: TimeoutAction::AutoRelease
        }
    ));

    let action = tracker.trigger().unwrap();
    assert_eq!(action, TimeoutAction::AutoRelease);
}

#[test]
fn test_auto_refund_on_dispute_timeout() {
    let mut tracker = TimeoutTracker::new(
        "escrow_001".to_string(),
        TimeoutType::DisputeResolution,
        1000,
    );

    // After dispute timeout + grace
    let status = tracker.check(1000 + DISPUTE_TIMEOUT + GRACE_PERIOD + 1);
    assert!(matches!(
        status,
        TimeoutStatus::Expired {
            action: TimeoutAction::AutoRefund
        }
    ));

    let action = tracker.trigger().unwrap();
    assert_eq!(action, TimeoutAction::AutoRefund);
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_timeout_at_exactly_start() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 1000);

    // Check at start time
    let status = tracker.check(1000);
    if let TimeoutStatus::Pending { remaining } = status {
        assert_eq!(remaining, FUNDING_TIMEOUT);
    } else {
        panic!("Expected Pending at start time");
    }
}

#[test]
fn test_timeout_with_zero_start() {
    let tracker = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Funding, 0);

    // Should work with epoch start
    let status = tracker.check(FUNDING_TIMEOUT - 1);
    assert!(matches!(status, TimeoutStatus::Pending { .. }));
}

#[test]
fn test_all_timeout_types_have_actions() {
    let types = [
        TimeoutType::MultisigSetup,
        TimeoutType::Funding,
        TimeoutType::Delivery,
        TimeoutType::ReleaseConfirmation,
        TimeoutType::DisputeResolution,
        TimeoutType::SigningCompletion,
    ];

    for ttype in types {
        let tracker = TimeoutTracker::new("test".to_string(), ttype, 0);

        // All types should have a defined action
        assert!(
            tracker.action != TimeoutAction::NoAction,
            "Timeout type {:?} should have an action",
            ttype
        );
    }
}

#[test]
fn test_deterministic_timeout_calculation() {
    let tracker1 = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Delivery, 1000);
    let tracker2 = TimeoutTracker::new("escrow_001".to_string(), TimeoutType::Delivery, 1000);

    assert_eq!(tracker1.deadline, tracker2.deadline);
    assert_eq!(tracker1.grace_period_ends, tracker2.grace_period_ends);
}
