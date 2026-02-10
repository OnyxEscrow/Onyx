//! Error types for Monero Marketplace

use thiserror::Error;

/// Main error type for the Monero Marketplace
#[derive(Error, Debug)]
pub enum Error {
    #[error("Monero RPC error: {0}")]
    MoneroRpc(String),

    #[error("Wallet error: {0}")]
    Wallet(String),

    #[error("Multisig error: {0}")]
    Multisig(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),

    // Escrow-specific errors
    #[error("Escrow not found: {0}")]
    EscrowNotFound(String),

    #[error("Invalid escrow state: {0}")]
    InvalidState(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Invalid user: {0}")]
    InvalidUser(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Security violation: {0}")]
    Security(String),
}

/// Tor-specific errors
#[derive(Error, Debug)]
pub enum TorError {
    #[error("Tor proxy unreachable (is Tor running?)")]
    ProxyUnreachable,

    #[error("Not using Tor (potential IP leak!)")]
    NotUsingTor,

    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Monero RPC specific errors
#[derive(Error, Debug)]
pub enum MoneroError {
    #[error("Monero RPC unreachable (is wallet RPC running?)")]
    RpcUnreachable,

    #[error("Wallet already in multisig mode")]
    AlreadyMultisig,

    #[error("Wallet not in multisig mode")]
    NotMultisig,

    #[error("Wallet locked (password required)")]
    WalletLocked,

    #[error("Wallet busy (operation in progress)")]
    WalletBusy,

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Invalid RPC response: {0}")]
    InvalidResponse(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("RPC error: {0}")]
    RpcError(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;
