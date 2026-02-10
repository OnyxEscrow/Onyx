//! Common types and utilities for Monero Marketplace
//!
//! This crate contains shared types, error definitions, and utilities
//! used across the entire Monero Marketplace application.

pub mod error;
pub mod types;
pub mod utils;

pub use error::{Error, Result};
pub use types::*;

// ============================================
// CONSTANTS - Monero Marketplace
// ============================================

/// Monero RPC default port (Testnet)
pub const MONERO_RPC_PORT: u16 = 18082;

/// Monero RPC default URL
pub const MONERO_RPC_URL: &str = "http://127.0.0.1:18082/json_rpc";

/// Monero Stagenet Daemon RPC port
pub const MONERO_STAGE_DAEMON_PORT: u16 = 38081;

/// Monero Stagenet Wallet RPC default port
pub const MONERO_STAGE_RPC_PORT: u16 = 38082;

/// Monero Stagenet Wallet RPC base port (buyer wallet)
/// Vendor: 38084, Arbiter: 38085
pub const MONERO_STAGE_RPC_PORT_BUYER: u16 = 38083;

/// Monero Stagenet RPC URL (buyer wallet)
pub const MONERO_STAGENET_RPC_URL: &str = "http://127.0.0.1:38083/json_rpc";

/// Conversion factor from XMR to atomic units (1 XMR = 10^12 atomic units)
pub const XMR_TO_ATOMIC: u64 = 1_000_000_000_000;

/// Maximum length for multisig info validation
pub const MAX_MULTISIG_INFO_LEN: usize = 5000;

/// Minimum length for multisig info validation
pub const MIN_MULTISIG_INFO_LEN: usize = 100;

/// Test RPC port for integration tests
pub const TEST_RPC_PORT: u16 = 9999;

/// Test RPC URL for integration tests
pub const TEST_RPC_URL: &str = "http://127.0.0.1:9999/json_rpc";

/// Invalid RPC port for testing error handling
pub const INVALID_RPC_PORT: u16 = 19999;

/// Invalid RPC URL for testing error handling
pub const INVALID_RPC_URL: &str = "http://127.0.0.1:19999/json_rpc";
