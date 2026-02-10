//! Circuit Breaker pattern for Monero RPC calls
//!
//! Implements the circuit breaker pattern to prevent cascading failures
//! when the Monero RPC becomes unavailable or unreliable.
//!
//! States:
//! - Closed: Normal operation, requests pass through
//! - Open: Failures exceeded threshold, requests fail fast
//! - HalfOpen: Testing if service recovered, limited requests allowed

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through
    Closed,
    /// Service unavailable - requests fail fast
    Open,
    /// Testing recovery - limited requests allowed
    HalfOpen,
}

/// Configuration for the circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Number of successes in half-open to close circuit
    pub success_threshold: u32,
    /// Time to wait before transitioning from open to half-open
    pub timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Circuit breaker for protecting RPC calls
pub struct CircuitBreaker {
    state: RwLock<CircuitState>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: RwLock<Option<Instant>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default configuration
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker with custom configuration
    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: RwLock::new(None),
            config,
        }
    }

    /// Check if a request can be executed
    ///
    /// Returns true if the circuit is closed or half-open (after timeout)
    /// Returns false if the circuit is open
    pub async fn can_execute(&self) -> bool {
        let state = *self.state.read().await;
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let last_failure = self.last_failure_time.read().await;
                if let Some(time) = *last_failure {
                    if time.elapsed() >= self.config.timeout {
                        // Transition to half-open
                        *self.state.write().await = CircuitState::HalfOpen;
                        self.success_count.store(0, Ordering::SeqCst);
                        tracing::info!(
                            "Circuit breaker transitioning to HALF-OPEN (timeout elapsed)"
                        );
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request
    ///
    /// In closed state: resets failure count
    /// In half-open state: increments success count, may close circuit
    pub async fn record_success(&self) {
        let state = *self.state.read().await;
        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.config.success_threshold {
                    *self.state.write().await = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                    tracing::info!(
                        "Circuit breaker CLOSED - service recovered after {} successes",
                        count
                    );
                }
            }
            CircuitState::Open => {
                // Should not happen - can_execute returns false when open
            }
        }
    }

    /// Record a failed request
    ///
    /// In closed state: increments failure count, may open circuit
    /// In half-open state: immediately opens circuit
    pub async fn record_failure(&self) {
        let state = *self.state.read().await;
        match state {
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.config.failure_threshold {
                    *self.state.write().await = CircuitState::Open;
                    *self.last_failure_time.write().await = Some(Instant::now());
                    tracing::warn!(
                        "Circuit breaker OPEN - {} consecutive failures exceeded threshold",
                        count
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open immediately opens the circuit
                *self.state.write().await = CircuitState::Open;
                *self.last_failure_time.write().await = Some(Instant::now());
                tracing::warn!("Circuit breaker OPEN - failure during half-open test");
            }
            CircuitState::Open => {
                // Update last failure time
                *self.last_failure_time.write().await = Some(Instant::now());
            }
        }
    }

    /// Get current circuit state
    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }

    /// Get current failure count
    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::SeqCst)
    }

    /// Get current success count (only relevant in half-open state)
    pub fn success_count(&self) -> u32 {
        self.success_count.load(Ordering::SeqCst)
    }

    /// Force reset the circuit breaker to closed state
    ///
    /// Use with caution - typically for manual intervention
    pub async fn reset(&self) {
        *self.state.write().await = CircuitState::Closed;
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        *self.last_failure_time.write().await = None;
        tracing::info!("Circuit breaker manually RESET to closed state");
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned when circuit is open
#[derive(Debug, Clone, thiserror::Error)]
#[error("Circuit breaker is open - service unavailable")]
pub struct CircuitOpenError;

/// Execute a future with circuit breaker protection
///
/// Returns CircuitOpenError if the circuit is open
/// Otherwise executes the future and records success/failure
pub async fn with_circuit_breaker<F, T, E>(
    circuit: &CircuitBreaker,
    operation: F,
) -> Result<T, CircuitBreakerError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    if !circuit.can_execute().await {
        return Err(CircuitBreakerError::CircuitOpen);
    }

    match operation.await {
        Ok(result) => {
            circuit.record_success().await;
            Ok(result)
        }
        Err(e) => {
            circuit.record_failure().await;
            Err(CircuitBreakerError::OperationFailed(e))
        }
    }
}

/// Error type for circuit breaker protected operations
#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError<E> {
    #[error("Circuit breaker is open - service unavailable")]
    CircuitOpen,
    #[error("Operation failed: {0}")]
    OperationFailed(#[source] E),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_starts_closed() {
        let cb = CircuitBreaker::new();
        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(cb.can_execute().await);
    }

    #[tokio::test]
    async fn test_circuit_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(30),
        };
        let cb = CircuitBreaker::with_config(config);

        // Record 3 failures
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
        assert!(!cb.can_execute().await);
    }

    #[tokio::test]
    async fn test_success_resets_failure_count() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(30),
        };
        let cb = CircuitBreaker::with_config(config);

        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.failure_count(), 2);

        cb.record_success().await;
        assert_eq!(cb.failure_count(), 0);
    }

    #[tokio::test]
    async fn test_half_open_closes_after_successes() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            timeout: Duration::from_millis(10),
        };
        let cb = CircuitBreaker::with_config(config);

        // Open the circuit
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Should transition to half-open
        assert!(cb.can_execute().await);
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Record successes
        cb.record_success().await;
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        cb.record_success().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_half_open_reopens_on_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            timeout: Duration::from_millis(10),
        };
        let cb = CircuitBreaker::with_config(config);

        // Open the circuit
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Transition to half-open
        assert!(cb.can_execute().await);
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Failure in half-open reopens
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_manual_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            timeout: Duration::from_secs(300),
        };
        let cb = CircuitBreaker::with_config(config);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);

        cb.reset().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(cb.can_execute().await);
    }
}
