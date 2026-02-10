//! WalletRpcWatchdog error types
//!
//! Defines error types for the watchdog service that supervises wallet-rpc processes.

use std::time::Duration;
use thiserror::Error;

/// Errors that can occur in the WalletRpcWatchdog service
#[derive(Error, Debug)]
pub enum WatchdogError {
    /// Failed to spawn wallet-rpc process
    #[error("Process spawn failed for port {port}: {reason}")]
    SpawnFailed { port: u16, reason: String },

    /// Process not found in watchdog registry
    #[error("Process not found: port {0}")]
    ProcessNotFound(u16),

    /// Health check failed for a process
    #[error("Health check failed for port {port}: {reason}")]
    HealthCheckFailed { port: u16, reason: String },

    /// Circuit breaker is open - calls are being rejected
    #[error("Circuit breaker OPEN for port {0} - calls rejected")]
    CircuitOpen(u16),

    /// Maximum restart attempts exceeded
    #[error("Max restart attempts ({attempts}) exceeded for port {port}")]
    MaxRestartsExceeded { port: u16, attempts: u32 },

    /// RPC error from underlying Monero wallet-rpc
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Operation timed out
    #[error("Timeout: operation took longer than {0:?}")]
    Timeout(Duration),

    /// Process was killed (intentionally or by signal)
    #[error("Process killed: port {port}, reason: {reason}")]
    ProcessKilled { port: u16, reason: String },

    /// Port is already in use
    #[error("Port {0} is already in use")]
    PortInUse(u16),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// IO error (file operations, process management)
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// HTTP client error
    #[error("HTTP error: {0}")]
    HttpError(String),

    /// Internal error (unexpected state)
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl WatchdogError {
    /// Returns true if this error is transient and the operation should be retried
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            WatchdogError::HealthCheckFailed { .. }
                | WatchdogError::Timeout(_)
                | WatchdogError::HttpError(_)
                | WatchdogError::RpcError(_)
        )
    }

    /// Returns true if this error indicates a process failure requiring restart
    pub fn requires_restart(&self) -> bool {
        matches!(
            self,
            WatchdogError::HealthCheckFailed { .. }
                | WatchdogError::ProcessKilled { .. }
                | WatchdogError::Timeout(_)
        )
    }

    /// Returns true if this error is a permanent failure (no retry)
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            WatchdogError::MaxRestartsExceeded { .. }
                | WatchdogError::ConfigError(_)
                | WatchdogError::InternalError(_)
        )
    }

    /// Get the port associated with this error, if any
    pub fn port(&self) -> Option<u16> {
        match self {
            WatchdogError::SpawnFailed { port, .. } => Some(*port),
            WatchdogError::ProcessNotFound(port) => Some(*port),
            WatchdogError::HealthCheckFailed { port, .. } => Some(*port),
            WatchdogError::CircuitOpen(port) => Some(*port),
            WatchdogError::MaxRestartsExceeded { port, .. } => Some(*port),
            WatchdogError::ProcessKilled { port, .. } => Some(*port),
            WatchdogError::PortInUse(port) => Some(*port),
            _ => None,
        }
    }
}

/// Result type for watchdog operations
pub type WatchdogResult<T> = Result<T, WatchdogError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_transient() {
        assert!(WatchdogError::HealthCheckFailed {
            port: 38083,
            reason: "timeout".into()
        }
        .is_transient());

        assert!(WatchdogError::Timeout(Duration::from_secs(5)).is_transient());

        assert!(!WatchdogError::MaxRestartsExceeded {
            port: 38083,
            attempts: 5
        }
        .is_transient());
    }

    #[test]
    fn test_error_requires_restart() {
        assert!(WatchdogError::HealthCheckFailed {
            port: 38083,
            reason: "connection refused".into()
        }
        .requires_restart());

        assert!(!WatchdogError::CircuitOpen(38083).requires_restart());
    }

    #[test]
    fn test_error_port() {
        assert_eq!(WatchdogError::ProcessNotFound(38083).port(), Some(38083));

        assert_eq!(WatchdogError::ConfigError("bad config".into()).port(), None);
    }
}
