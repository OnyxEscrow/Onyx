//! Offline E2E Test Suite for NEXUS Monero Marketplace
//!
//! ## Purpose
//! Comprehensive offline testing to find ALL code flaws before manual testing.
//! 100% deterministic, zero external dependencies (no Tor, no Monero RPC, no network).
//!
//! ## Test Categories
//! - **Crypto Tests**: CLSAG verification, key image aggregation, Lagrange coefficients
//! - **Transaction Tests**: Structure validation, hash computation, fee calculation
//! - **Escrow State Machine**: State transitions, race conditions, timeout handling
//! - **Validation Tests**: Address validation, amount validation
//! - **Regression Tests**: Bug fixes for documented issues
//!
//! ## Running Tests
//! ```bash
//! # Run all offline E2E tests
//! cargo test --package server --test offline_e2e -- --test-threads=1
//!
//! # Run specific category
//! cargo test --package server --test offline_e2e crypto_tests
//!
//! # Run with output
//! cargo test --package server --test offline_e2e -- --nocapture
//! ```
//!
//! ## Success Criteria
//! - All 50+ test cases pass
//! - Suite completes in <60 seconds
//! - Zero external dependencies
//! - Deterministic (same results every run)

pub mod mock_infrastructure;
pub mod crypto_tests;
pub mod transaction_tests;
pub mod escrow_state_machine_tests;
pub mod validation_tests;
pub mod regression_tests;
pub mod swap_tests;

// Re-export common test utilities
pub use mock_infrastructure::*;
