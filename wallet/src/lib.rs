//! Monero wallet integration and multisig functionality
//!
//! This crate provides the core functionality for interacting with
//! Monero wallets, including multisig operations for escrow.

pub mod circuit_breaker;
pub mod client;
pub mod daemon_pool;
pub mod escrow;
pub mod fee_estimation;
pub mod health_checker;
pub mod multisig;
pub mod rpc;
pub mod tor;
pub mod transaction;
pub mod validation;

pub use circuit_breaker::{
    with_circuit_breaker, CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError,
    CircuitOpenError, CircuitState,
};
pub use client::MoneroClient;
pub use daemon_pool::{DaemonConfig, DaemonPool};
pub use escrow::EscrowManager;
pub use fee_estimation::{FeeEstimate, FeeEstimator, FeePriority};
pub use health_checker::{HealthCheckResult, HealthChecker, PoolHealthSummary};
pub use multisig::MultisigManager;
pub use rpc::MoneroRpcClient;
pub use transaction::TransactionManager;
