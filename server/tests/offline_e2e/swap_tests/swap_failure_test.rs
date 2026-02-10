//! Swap Failure Scenario E2E Tests
//!
//! Tests failure modes for BTC → XMR swaps using MockSwapProvider.
//! Validates:
//! - Failed swaps
//! - Expired swaps
//! - Partial payments
//! - Refund flows
//! - Error handling

use server::services::mock_swap_provider::{MockScenario, MockSwapConfig, MockSwapProvider};
use server::services::swap_provider::{SwapProvider, SwapQuoteRequest, SwapStatus, SwapError};

// =============================================================================
// Failed Swap Tests
// =============================================================================

#[tokio::test]
async fn test_swap_fails_during_exchange() {
    let provider = MockSwapProvider::fail_during_swap();

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.expect("Quote should succeed");

    // Progress through states until failure
    let status1 = provider.check_status(&quote.provider_order_id).await.unwrap();
    assert_eq!(status1.status, SwapStatus::DepositDetected);

    let status2 = provider.check_status(&quote.provider_order_id).await.unwrap();
    assert_eq!(status2.status, SwapStatus::DepositConfirmed);

    let status3 = provider.check_status(&quote.provider_order_id).await.unwrap();
    assert_eq!(status3.status, SwapStatus::Swapping);

    // Failure occurs here
    let status4 = provider.check_status(&quote.provider_order_id).await.unwrap();
    assert_eq!(status4.status, SwapStatus::Failed);
    assert!(status4.error_message.is_some(), "Error message should be present");
    assert!(status4.xmr_tx_hash.is_none(), "No XMR tx hash on failure");
}

#[tokio::test]
async fn test_swap_expires_before_deposit() {
    let config = MockSwapConfig {
        scenario: MockScenario::ExpireBeforeDeposit,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.expect("Quote should succeed");

    // First check should show expired (no deposit within window)
    let status = provider.check_status(&quote.provider_order_id).await.unwrap();
    assert_eq!(status.status, SwapStatus::Expired, "Should expire before deposit");
    assert!(status.error_message.is_some(), "Expiration message should be present");
}

#[tokio::test]
async fn test_deposit_never_confirms() {
    let config = MockSwapConfig {
        scenario: MockScenario::DepositNeverConfirms,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.expect("Quote should succeed");

    // Deposit is detected
    let status1 = provider.check_status(&quote.provider_order_id).await.unwrap();
    assert_eq!(status1.status, SwapStatus::DepositDetected);

    // But it eventually expires/fails without confirmation
    let status2 = provider.check_status(&quote.provider_order_id).await.unwrap();
    assert!(
        matches!(status2.status, SwapStatus::Expired | SwapStatus::Failed),
        "Should eventually fail or expire"
    );
}

// =============================================================================
// Partial Payment Tests
// =============================================================================

#[tokio::test]
async fn test_partial_payment_detected() {
    let config = MockSwapConfig {
        scenario: MockScenario::PartialPayment,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.expect("Quote should succeed");

    // Check status - should show partial payment situation
    let status = provider.check_status(&quote.provider_order_id).await.unwrap();

    // Partial payments typically lead to failure with specific message
    // or the provider refunds the partial amount
    assert!(
        matches!(status.status, SwapStatus::Failed | SwapStatus::Refunded | SwapStatus::DepositDetected),
        "Partial payment should result in failure, refund, or stuck at detected"
    );
}

// =============================================================================
// Refund Flow Tests
// =============================================================================

#[tokio::test]
async fn test_refund_scenario() {
    let config = MockSwapConfig {
        scenario: MockScenario::Refunded,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.expect("Quote should succeed");

    // Progress through states
    let _ = provider.check_status(&quote.provider_order_id).await.unwrap(); // DepositDetected
    let _ = provider.check_status(&quote.provider_order_id).await.unwrap(); // DepositConfirmed
    let _ = provider.check_status(&quote.provider_order_id).await.unwrap(); // Swapping

    // Refund happens
    let status = provider.check_status(&quote.provider_order_id).await.unwrap();
    assert_eq!(status.status, SwapStatus::Refunded);
    assert!(status.btc_tx_hash.is_some(), "BTC refund tx hash should be present");
}

// =============================================================================
// Provider Error Tests
// =============================================================================

#[tokio::test]
async fn test_quote_error_scenario() {
    let config = MockSwapConfig {
        scenario: MockScenario::QuoteError,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let result = provider.get_quote(&request).await;
    assert!(result.is_err(), "QuoteError scenario should return error");

    match result {
        Err(SwapError::ProviderUnreachable(_)) => {
            // Expected error type
        }
        Err(e) => panic!("Unexpected error type: {:?}", e),
        Ok(_) => panic!("Should have failed"),
    }
}

#[tokio::test]
async fn test_status_check_error_scenario() {
    let config = MockSwapConfig {
        scenario: MockScenario::StatusCheckError,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    // Quote succeeds
    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.expect("Quote should succeed");

    // Status check fails
    let result = provider.check_status(&quote.provider_order_id).await;
    assert!(result.is_err(), "StatusCheckError scenario should fail status check");
}

#[tokio::test]
async fn test_unknown_order_id() {
    let provider = MockSwapProvider::success();

    // Check status for non-existent order
    let result = provider.check_status("non_existent_order_123").await;
    assert!(result.is_err(), "Unknown order ID should fail");

    // The mock returns InvalidResponse for unknown orders
    match result {
        Err(SwapError::InvalidResponse(msg)) => {
            assert!(msg.contains("Unknown order"), "Error should mention unknown order");
        }
        Err(e) => panic!("Unexpected error type: {:?}", e),
        Ok(_) => panic!("Should have failed"),
    }
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[tokio::test]
async fn test_maximum_amount() {
    let config = MockSwapConfig {
        max_btc_sats: 50_000_000, // 0.5 BTC max
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    // Try to swap more than max
    let request = SwapQuoteRequest::btc(
        100_000_000, // 1 BTC - above max
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let result = provider.get_quote(&request).await;
    assert!(result.is_err(), "Should reject amount above max");

    match result {
        Err(SwapError::AmountTooHigh { .. }) => {
            // Expected error type
        }
        Err(e) => panic!("Unexpected error type: {:?}", e),
        Ok(_) => panic!("Should have failed"),
    }
}

#[tokio::test]
async fn test_minimum_amount() {
    let config = MockSwapConfig {
        min_btc_sats: 50_000, // 0.0005 BTC min
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    // Try to swap less than min
    let request = SwapQuoteRequest::btc(
        10_000, // 0.0001 BTC - below min
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let result = provider.get_quote(&request).await;
    assert!(result.is_err(), "Should reject amount below min");

    match result {
        Err(SwapError::AmountTooLow { .. }) => {
            // Expected error type
        }
        Err(e) => panic!("Unexpected error type: {:?}", e),
        Ok(_) => panic!("Should have failed"),
    }
}

#[tokio::test]
async fn test_empty_destination_address() {
    let provider = MockSwapProvider::success();

    let request = SwapQuoteRequest::btc(
        100_000,
        "".to_string(), // Empty address
        None,
    );

    let result = provider.get_quote(&request).await;
    assert!(result.is_err(), "Should reject empty address");
}

// =============================================================================
// State Machine Validation Tests
// =============================================================================

#[tokio::test]
async fn test_terminal_states_are_stable() {
    let provider = MockSwapProvider::fail_during_swap();

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.unwrap();

    // Progress to failed state
    for _ in 0..10 {
        let status = provider.check_status(&quote.provider_order_id).await.unwrap();
        if status.status == SwapStatus::Failed {
            break;
        }
    }

    // Multiple subsequent checks should stay in Failed state
    let status1 = provider.check_status(&quote.provider_order_id).await.unwrap();
    let status2 = provider.check_status(&quote.provider_order_id).await.unwrap();
    let status3 = provider.check_status(&quote.provider_order_id).await.unwrap();

    assert_eq!(status1.status, SwapStatus::Failed);
    assert_eq!(status2.status, SwapStatus::Failed);
    assert_eq!(status3.status, SwapStatus::Failed);
}

#[tokio::test]
async fn test_completed_state_is_stable() {
    let provider = MockSwapProvider::success();

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.unwrap();

    // Progress to completed state
    for _ in 0..10 {
        let status = provider.check_status(&quote.provider_order_id).await.unwrap();
        if status.status == SwapStatus::Completed {
            break;
        }
    }

    // Multiple subsequent checks should stay in Completed state
    let status1 = provider.check_status(&quote.provider_order_id).await.unwrap();
    let status2 = provider.check_status(&quote.provider_order_id).await.unwrap();

    assert_eq!(status1.status, SwapStatus::Completed);
    assert_eq!(status2.status, SwapStatus::Completed);
    // XMR tx hash should be preserved
    assert_eq!(status1.xmr_tx_hash, status2.xmr_tx_hash);
}
