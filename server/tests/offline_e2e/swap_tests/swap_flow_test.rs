//! Swap Flow E2E Tests
//!
//! Tests the complete BTC → XMR swap lifecycle using MockSwapProvider.
//! Validates:
//! - Quote generation
//! - Status transitions
//! - Auto-funding integration

use std::sync::Arc;

use server::services::mock_swap_provider::{MockScenario, MockSwapConfig, MockSwapProvider};
use server::services::swap_provider::{SwapProvider, SwapQuoteRequest, SwapStatus};

// =============================================================================
// Successful Flow Tests
// =============================================================================

#[tokio::test]
async fn test_mock_swap_success_flow_isolated() {
    // Test the MockSwapProvider in isolation (no DB required)
    let provider = MockSwapProvider::success();

    // Step 1: Get quote
    let request = SwapQuoteRequest::btc(
        100_000, // 0.001 BTC
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.expect("Quote should succeed");

    assert!(!quote.provider_order_id.is_empty(), "Order ID should be set");
    assert!(quote.to_amount_atomic > 0, "XMR amount should be positive");
    assert!(!quote.deposit_address.is_empty(), "BTC address should be set");
    assert!(quote.from_amount_sats() == 100_000, "BTC amount should match request");

    // Step 2: Simulate status progression
    let order_id = &quote.provider_order_id;

    let status1 = provider.check_status(order_id).await.expect("Status check 1");
    assert_eq!(status1.status, SwapStatus::DepositDetected);

    let status2 = provider.check_status(order_id).await.expect("Status check 2");
    assert_eq!(status2.status, SwapStatus::DepositConfirmed);

    let status3 = provider.check_status(order_id).await.expect("Status check 3");
    assert_eq!(status3.status, SwapStatus::Swapping);

    let status4 = provider.check_status(order_id).await.expect("Status check 4");
    assert_eq!(status4.status, SwapStatus::SwapComplete);
    assert!(status4.xmr_tx_hash.is_some(), "XMR tx hash should be set on completion");

    let status5 = provider.check_status(order_id).await.expect("Status check 5");
    assert_eq!(status5.status, SwapStatus::Completed);
}

#[tokio::test]
async fn test_quote_amount_validation() {
    let provider = MockSwapProvider::new();

    // Test amount too low
    let low_request = SwapQuoteRequest::btc(
        100, // Below minimum
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let result = provider.get_quote(&low_request).await;
    assert!(result.is_err(), "Should reject amount too low");

    // Test valid amount
    let valid_request = SwapQuoteRequest::btc(
        50_000, // 0.0005 BTC - above minimum
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let result = provider.get_quote(&valid_request).await;
    assert!(result.is_ok(), "Should accept valid amount");
}

#[tokio::test]
async fn test_exchange_rate_calculation() {
    let config = MockSwapConfig {
        rate_btc_per_xmr: 0.007, // 0.007 BTC = 1 XMR
        fee_percent: 0.5,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    let request = SwapQuoteRequest::btc(
        1_000_000, // 0.01 BTC
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.expect("Quote should succeed");

    // 0.01 BTC at 0.007 BTC/XMR = ~1.43 XMR (minus 0.5% fee)
    // Expected: 1.43 * 0.995 * 1e12 = ~1.42e12 piconeros
    let expected_xmr_atomic = (0.01 / 0.007 * 0.995 * 1_000_000_000_000.0) as u64;

    // Allow 1% tolerance for rounding
    let tolerance = expected_xmr_atomic / 100;
    assert!(
        (quote.to_amount_atomic as i64 - expected_xmr_atomic as i64).abs() < tolerance as i64,
        "XMR amount {} should be close to expected {}",
        quote.to_amount_atomic,
        expected_xmr_atomic
    );
}

// =============================================================================
// Multiple Quote Tests
// =============================================================================

#[tokio::test]
async fn test_multiple_concurrent_quotes() {
    let provider = Arc::new(MockSwapProvider::success());

    // Spawn multiple concurrent quotes
    let mut handles = Vec::new();

    for i in 0..5 {
        let provider = Arc::clone(&provider);
        let handle = tokio::spawn(async move {
            let request = SwapQuoteRequest::btc(
                50_000 + (i * 10_000) as u64,
                format!("4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn{}", i),
                None,
            );
            provider.get_quote(&request).await
        });
        handles.push(handle);
    }

    // All should succeed with unique order IDs
    let mut order_ids = std::collections::HashSet::new();
    for handle in handles {
        let quote = handle.await.expect("Task should complete").expect("Quote should succeed");
        assert!(!order_ids.contains(&quote.provider_order_id), "Order IDs should be unique");
        order_ids.insert(quote.provider_order_id);
    }

    assert_eq!(order_ids.len(), 5, "Should have 5 unique order IDs");
}

// =============================================================================
// Provider Availability Tests
// =============================================================================

#[tokio::test]
async fn test_provider_availability() {
    // Available provider
    let available = MockSwapProvider::success();
    assert!(available.is_available().await, "Success provider should be available");

    // Unavailable provider (QuoteError scenario)
    let unavailable = MockSwapProvider::with_config(MockSwapConfig {
        scenario: MockScenario::QuoteError,
        ..Default::default()
    });
    assert!(!unavailable.is_available().await, "QuoteError provider should not be available");
}

#[tokio::test]
async fn test_provider_rate() {
    let config = MockSwapConfig {
        rate_btc_per_xmr: 0.0065,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);
    let rate = provider.get_rate().await.expect("Rate should be available");

    assert_eq!(rate, 0.0065, "Rate should match config");
}

#[tokio::test]
async fn test_provider_limits() {
    let config = MockSwapConfig {
        min_btc_sats: 50_000,
        max_btc_sats: 50_000_000,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);
    let limits = provider.get_limits().await.expect("Limits should be available");

    assert_eq!(limits.min_btc_sats, 50_000);
    assert_eq!(limits.max_btc_sats, 50_000_000);
}

// =============================================================================
// Slow Swap Scenario
// =============================================================================

#[tokio::test]
async fn test_slow_swap_many_checks() {
    let config = MockSwapConfig {
        scenario: MockScenario::SlowSwap,
        checks_until_complete: 5,
        ..Default::default()
    };

    let provider = MockSwapProvider::with_config(config);

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote = provider.get_quote(&request).await.expect("Quote should succeed");

    // With checks_until_complete=5, we need at least 5 status checks
    // before transitioning to SwapComplete
    let mut status = provider.check_status(&quote.provider_order_id).await.unwrap();
    let mut check_count = 1;

    while status.status != SwapStatus::Completed && check_count < 20 {
        status = provider.check_status(&quote.provider_order_id).await.unwrap();
        check_count += 1;
    }

    assert!(check_count >= 5, "Slow swap should require at least {} checks, got {}", 5, check_count);
    assert_eq!(status.status, SwapStatus::Completed, "Should eventually complete");
}

// =============================================================================
// Determinism Tests
// =============================================================================

#[tokio::test]
async fn test_deterministic_behavior() {
    // Same config should produce same behavior
    let config = MockSwapConfig {
        rate_btc_per_xmr: 0.007,
        fee_percent: 0.5,
        ..Default::default()
    };

    let provider1 = MockSwapProvider::with_config(config.clone());
    let provider2 = MockSwapProvider::with_config(config);

    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTn".to_string(),
        None,
    );

    let quote1 = provider1.get_quote(&request).await.expect("Quote 1");
    let quote2 = provider2.get_quote(&request).await.expect("Quote 2");

    // Amounts should be identical (deterministic calculation)
    assert_eq!(quote1.to_amount_atomic, quote2.to_amount_atomic, "XMR amounts should match");
    assert_eq!(quote1.from_amount_sats(), quote2.from_amount_sats(), "BTC amounts should match");
    assert_eq!(quote1.rate_btc_per_xmr(), quote2.rate_btc_per_xmr(), "Exchange rates should match");
}

// =============================================================================
// XMR Address Prefix Handling
// =============================================================================

#[tokio::test]
async fn test_mainnet_address_prefix() {
    let provider = MockSwapProvider::success();

    // Mainnet address (starts with 4)
    let request = SwapQuoteRequest::btc(
        100_000,
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTnmainnet".to_string(),
        None,
    );

    let result = provider.get_quote(&request).await;
    assert!(result.is_ok(), "Should accept mainnet address");
}

#[tokio::test]
async fn test_stagenet_address_prefix() {
    let provider = MockSwapProvider::success();

    // Stagenet address (starts with 5)
    let request = SwapQuoteRequest::btc(
        100_000,
        "5AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfFfPYDe9LMbkjTnstagenet".to_string(),
        None,
    );

    let result = provider.get_quote(&request).await;
    assert!(result.is_ok(), "Should accept stagenet address");
}
