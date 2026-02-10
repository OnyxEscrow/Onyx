use anyhow::{anyhow, Result};
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use super::traits::ConnectionLimiter;

/// Manages WebSocket connection limits per user and globally.
///
/// Prevents DoS attacks by enforcing:
/// - Maximum connections per user (default 3)
/// - Maximum global active connections (default 1000)
#[derive(Clone)]
pub struct ConnectionManager {
    /// Map of UserID -> active connection count
    user_connections: Arc<DashMap<String, u32>>,
    /// Global active connection counter
    global_connections: Arc<AtomicUsize>,
    /// Maximum concurrent connections per user
    max_per_user: u32,
    /// Maximum global concurrent connections
    max_global: usize,
}

impl ConnectionManager {
    /// Create a new ConnectionManager with default limits.
    pub fn new() -> Self {
        Self::with_limits(3, 1000)
    }

    /// Create a new ConnectionManager with custom limits.
    ///
    /// # Arguments
    /// - `max_per_user`: Maximum concurrent connections per user (usually 3)
    /// - `max_global`: Maximum global concurrent connections (usually 1000)
    pub fn with_limits(max_per_user: u32, max_global: usize) -> Self {
        Self {
            user_connections: Arc::new(DashMap::new()),
            global_connections: Arc::new(AtomicUsize::new(0)),
            max_per_user,
            max_global,
        }
    }

    /// Attempt to acquire a connection slot for a user.
    ///
    /// Returns Ok(()) if the connection is allowed.
    /// Returns Err if limits are exceeded.
    ///
    /// # Errors
    /// - "Server is at capacity" if global limit is exceeded
    /// - "Too many connections from this user" if per-user limit is exceeded
    pub fn try_acquire(&self, user_id: &str) -> Result<()> {
        // Check global connection limit
        let current_global = self.global_connections.load(Ordering::SeqCst);
        if current_global >= self.max_global {
            return Err(anyhow!("Server is at capacity (global limit: {})", self.max_global));
        }

        // Check per-user connection limit
        let mut user_entry = self.user_connections.entry(user_id.to_string()).or_insert(0);
        if *user_entry >= self.max_per_user {
            let current = *user_entry;
            return Err(anyhow!(
                "Too many connections from this user (limit: {}, current: {})",
                self.max_per_user,
                current
            ));
        }

        // Increment user counter
        *user_entry += 1;
        drop(user_entry);

        // Try to increment global counter
        // Use compare-and-swap to be atomic
        let mut global = self.global_connections.load(Ordering::SeqCst);
        loop {
            if global >= self.max_global {
                // Global limit was exceeded, roll back user increment
                self.user_connections
                    .alter(user_id, |_, mut v| {
                        v = v.saturating_sub(1);
                        v
                    });
                return Err(anyhow!("Server is at capacity (global limit: {})", self.max_global));
            }

            match self.global_connections.compare_exchange(
                global,
                global + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => global = actual,
            }
        }

        Ok(())
    }

    /// Release a connection slot for a user.
    ///
    /// Should be called when a WebSocket connection closes.
    pub fn release(&self, user_id: &str) {
        // Decrement global counter
        let _ = self.global_connections.fetch_sub(1, Ordering::SeqCst);

        // Decrement user counter, removing entry if it reaches 0
        if let Some(mut entry) = self.user_connections.get_mut(user_id) {
            if *entry > 0 {
                *entry -= 1;
            }
        }

        // Clean up zero entries to prevent unbounded memory growth
        self.user_connections.retain(|_, count| *count > 0);
    }

    /// Get current global connection count (for monitoring).
    pub fn current_global_connections(&self) -> usize {
        self.global_connections.load(Ordering::SeqCst)
    }

    /// Get current connection count for a user.
    pub fn current_user_connections(&self, user_id: &str) -> u32 {
        self.user_connections
            .get(user_id)
            .map(|entry| *entry)
            .unwrap_or(0)
    }

    /// Get maximum connections per user.
    pub fn max_per_user(&self) -> u32 {
        self.max_per_user
    }

    /// Get maximum global connections.
    pub fn max_global(&self) -> usize {
        self.max_global
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionLimiter for ConnectionManager {
    fn try_acquire(&self, user_id: &str) -> Result<()> {
        ConnectionManager::try_acquire(self, user_id)
    }

    fn release(&self, user_id: &str) {
        ConnectionManager::release(self, user_id)
    }

    fn current_global_connections(&self) -> usize {
        ConnectionManager::current_global_connections(self)
    }

    fn current_user_connections(&self, user_id: &str) -> u32 {
        ConnectionManager::current_user_connections(self, user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_and_release() {
        let manager = ConnectionManager::new();

        // First connection should succeed
        assert!(manager.try_acquire("user1").is_ok());
        assert_eq!(manager.current_user_connections("user1"), 1);
        assert_eq!(manager.current_global_connections(), 1);

        // Release and verify
        manager.release("user1");
        assert_eq!(manager.current_user_connections("user1"), 0);
        assert_eq!(manager.current_global_connections(), 0);
    }

    #[test]
    fn test_per_user_limit() {
        let manager = ConnectionManager::with_limits(3, 1000);

        // First 3 should succeed
        assert!(manager.try_acquire("user1").is_ok());
        assert!(manager.try_acquire("user1").is_ok());
        assert!(manager.try_acquire("user1").is_ok());
        assert_eq!(manager.current_user_connections("user1"), 3);

        // 4th should fail
        let result = manager.try_acquire("user1");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Too many connections"));
    }

    #[test]
    fn test_global_limit() {
        let manager = ConnectionManager::with_limits(100, 5);

        // Should allow 5 global connections
        assert!(manager.try_acquire("user1").is_ok());
        assert!(manager.try_acquire("user2").is_ok());
        assert!(manager.try_acquire("user3").is_ok());
        assert!(manager.try_acquire("user4").is_ok());
        assert!(manager.try_acquire("user5").is_ok());
        assert_eq!(manager.current_global_connections(), 5);

        // 6th should fail
        let result = manager.try_acquire("user6");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at capacity"));
    }

    #[test]
    fn test_different_users_independent() {
        let manager = ConnectionManager::with_limits(2, 1000);

        // Each user can have 2 connections
        assert!(manager.try_acquire("user1").is_ok());
        assert!(manager.try_acquire("user1").is_ok());
        assert!(manager.try_acquire("user2").is_ok());
        assert!(manager.try_acquire("user2").is_ok());

        assert_eq!(manager.current_user_connections("user1"), 2);
        assert_eq!(manager.current_user_connections("user2"), 2);
        assert_eq!(manager.current_global_connections(), 4);
    }

    #[test]
    fn test_cleanup_zero_entries() {
        let manager = ConnectionManager::with_limits(3, 1000);

        // Create and release a connection
        assert!(manager.try_acquire("user1").is_ok());
        manager.release("user1");

        // Verify cleanup: user1 should not be in the map anymore
        assert_eq!(manager.current_user_connections("user1"), 0);

        // The map should be clean after retention
        manager.user_connections.retain(|_, count| *count > 0);
        assert!(manager.user_connections.is_empty());
    }

    #[test]
    fn test_race_condition_on_global_limit() {
        let manager = Arc::new(ConnectionManager::with_limits(100, 2));

        // Test 1: Acquire at limit (2/2)
        assert!(manager.try_acquire("user1").is_ok());
        assert!(manager.try_acquire("user2").is_ok());

        // Test 2: Third acquisition should fail (over limit)
        assert!(manager.try_acquire("user3").is_err());

        // Test 3: After releasing one, new acquisition should work
        manager.release("user1");
        assert!(manager.try_acquire("user3").is_ok());

        // Test 4: Verify global counter is correct
        assert_eq!(manager.current_global_connections(), 2);
    }
}
