//! Swap E2E Tests
//!
//! Tests the complete BTC → XMR swap flow using MockSwapProvider.
//! 100% offline, no external dependencies.
//!
//! ## Test Coverage
//! - Successful swap lifecycle
//! - Failed swap scenarios
//! - Expired swaps
//! - Partial payment handling
//! - Provider failover
//! - State machine validation

pub mod swap_failure_test;
pub mod swap_flow_test;
