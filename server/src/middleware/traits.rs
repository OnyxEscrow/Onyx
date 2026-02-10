use anyhow::Result;

/// Contract for connection limiting operations.
///
/// Implementations must ensure:
/// - Per-user connection limits are enforced
/// - Global connection limits are enforced
/// - Released connections properly decrement counters
/// - Memory is not leaked on connection cleanup
pub trait ConnectionLimiter {
    /// Attempt to acquire a new connection slot for a user.
    ///
    /// Returns Ok(()) if the connection is allowed.
    /// Returns Err if either per-user or global limits are exceeded.
    fn try_acquire(&self, user_id: &str) -> Result<()>;

    /// Release a connection slot previously acquired by try_acquire.
    ///
    /// Must be called exactly once when the WebSocket connection closes.
    fn release(&self, user_id: &str);

    /// Get the current global connection count.
    fn current_global_connections(&self) -> usize;

    /// Get the current connection count for a specific user.
    fn current_user_connections(&self, user_id: &str) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::ws_limiter::ConnectionManager;

    #[test]
    fn test_connection_limiter_trait() {
        let manager: Box<dyn ConnectionLimiter> = Box::new(ConnectionManager::new());

        // Should be able to acquire
        assert!(manager.try_acquire("user1").is_ok());
        assert_eq!(manager.current_user_connections("user1"), 1);
        assert_eq!(manager.current_global_connections(), 1);

        // Should be able to release
        manager.release("user1");
        assert_eq!(manager.current_user_connections("user1"), 0);
        assert_eq!(manager.current_global_connections(), 0);
    }
}
