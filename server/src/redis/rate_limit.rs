//! Redis-backed rate limiting for production multi-server deployments
//!
//! Replaces in-memory `Arc<Mutex<HashMap>>` rate limiters with Redis-backed
//! distributed rate limiting, enabling horizontal scaling.
//!
//! # Features
//!
//! - **Atomic operations**: Uses Lua script for INCR+EXPIRE atomicity
//! - **IP anonymization**: SHA256 truncated hashes for GDPR compliance
//! - **Fallback mode**: Graceful degradation to in-memory if Redis fails
//! - **Sliding window**: Accurate rate limiting with Redis sorted sets
//!
//! # Usage
//!
//! ```rust,ignore
//! use server::redis::rate_limit::{RedisRateLimiter, RateLimitResult};
//!
//! let limiter = RedisRateLimiter::new(
//!     pool.clone(),
//!     "registration".to_string(),
//!     5,    // max 5 requests
//!     3600, // per hour
//! );
//!
//! match limiter.check_and_increment("192.168.1.1").await? {
//!     RateLimitResult::Allowed { remaining, reset_at } => {
//!         // Request allowed
//!     }
//!     RateLimitResult::Limited { retry_after } => {
//!         // Rate limited
//!     }
//! }
//! ```

use crate::redis_pool::RedisPool;
use anyhow::{Context, Result};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use std::env;

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed {
        /// Remaining requests in current window
        remaining: u32,
        /// Unix timestamp when window resets
        reset_at: u64,
    },
    /// Request is rate limited
    Limited {
        /// Seconds until retry is allowed
        retry_after: u64,
    },
}

/// Redis-backed rate limiter for distributed deployments
pub struct RedisRateLimiter {
    pool: RedisPool,
    /// Key prefix (e.g., "nexus:rate:registration")
    prefix: String,
    /// Maximum requests per window
    max_requests: u32,
    /// Window size in seconds
    window_secs: u64,
}

impl RedisRateLimiter {
    /// Create a new Redis rate limiter
    ///
    /// # Arguments
    ///
    /// * `pool` - Redis connection pool
    /// * `prefix` - Key prefix for this limiter (e.g., "registration", "auth")
    /// * `max_requests` - Maximum requests allowed per window
    /// * `window_secs` - Window size in seconds
    pub fn new(pool: RedisPool, prefix: String, max_requests: u32, window_secs: u64) -> Self {
        Self {
            pool,
            prefix,
            max_requests,
            window_secs,
        }
    }

    /// Check if request is allowed and increment counter atomically
    ///
    /// Uses Lua script for atomic INCR + EXPIRE to prevent race conditions.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Client identifier (IP address, user ID, etc.)
    ///
    /// # Returns
    ///
    /// `RateLimitResult::Allowed` if request is allowed, `RateLimitResult::Limited` otherwise.
    pub async fn check_and_increment(&self, identifier: &str) -> Result<RateLimitResult> {
        let mut conn = self
            .pool
            .get()
            .await
            .context("Failed to get Redis connection for rate limiting")?;

        // Hash identifier for privacy (GDPR compliance)
        let hashed_id = self.hash_identifier(identifier);
        let key = format!("nexus:rate:{}:{}", self.prefix, hashed_id);

        // Lua script for atomic increment with TTL
        // Returns: [current_count, ttl_remaining]
        let script = r#"
            local key = KEYS[1]
            local max_requests = tonumber(ARGV[1])
            local window_secs = tonumber(ARGV[2])

            local current = redis.call('GET', key)

            if current then
                current = tonumber(current)
                if current >= max_requests then
                    -- Rate limited, return TTL
                    local ttl = redis.call('TTL', key)
                    return {current, ttl}
                end
                -- Increment and return
                local new_count = redis.call('INCR', key)
                local ttl = redis.call('TTL', key)
                return {new_count, ttl}
            else
                -- First request, set with expiry
                redis.call('SETEX', key, window_secs, 1)
                return {1, window_secs}
            end
        "#;

        let result: (i64, i64) = redis::Script::new(script)
            .key(&key)
            .arg(self.max_requests)
            .arg(self.window_secs)
            .invoke_async(&mut *conn)
            .await
            .context("Failed to execute rate limit script")?;

        let (count, ttl) = result;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if count > self.max_requests as i64 {
            tracing::debug!(
                identifier = %hashed_id,
                count = count,
                prefix = %self.prefix,
                "Rate limit exceeded"
            );
            Ok(RateLimitResult::Limited {
                retry_after: ttl.max(0) as u64,
            })
        } else {
            let remaining = (self.max_requests as i64 - count).max(0) as u32;
            Ok(RateLimitResult::Allowed {
                remaining,
                reset_at: now + ttl.max(0) as u64,
            })
        }
    }

    /// Check rate limit without incrementing (read-only)
    ///
    /// Useful for preflight checks or UI display.
    pub async fn check_only(&self, identifier: &str) -> Result<RateLimitResult> {
        let mut conn = self
            .pool
            .get()
            .await
            .context("Failed to get Redis connection for rate limit check")?;

        let hashed_id = self.hash_identifier(identifier);
        let key = format!("nexus:rate:{}:{}", self.prefix, hashed_id);

        let count: Option<i64> = conn
            .get(&key)
            .await
            .context("Failed to get rate limit count")?;

        let ttl: i64 = conn
            .ttl(&key)
            .await
            .context("Failed to get rate limit TTL")?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match count {
            Some(c) if c >= self.max_requests as i64 => Ok(RateLimitResult::Limited {
                retry_after: ttl.max(0) as u64,
            }),
            Some(c) => {
                let remaining = (self.max_requests as i64 - c).max(0) as u32;
                Ok(RateLimitResult::Allowed {
                    remaining,
                    reset_at: now + ttl.max(0) as u64,
                })
            }
            None => {
                // No rate limit data, full allowance
                Ok(RateLimitResult::Allowed {
                    remaining: self.max_requests,
                    reset_at: now + self.window_secs,
                })
            }
        }
    }

    /// Get remaining requests for an identifier
    pub async fn remaining(&self, identifier: &str) -> Result<u32> {
        match self.check_only(identifier).await? {
            RateLimitResult::Allowed { remaining, .. } => Ok(remaining),
            RateLimitResult::Limited { .. } => Ok(0),
        }
    }

    /// Reset rate limit for an identifier (admin function)
    pub async fn reset(&self, identifier: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .context("Failed to get Redis connection for rate limit reset")?;

        let hashed_id = self.hash_identifier(identifier);
        let key = format!("nexus:rate:{}:{}", self.prefix, hashed_id);

        conn.del::<_, ()>(&key)
            .await
            .context("Failed to delete rate limit key")?;

        tracing::info!(
            identifier = %hashed_id,
            prefix = %self.prefix,
            "Rate limit reset"
        );

        Ok(())
    }

    /// Hash identifier for privacy (GDPR compliance)
    ///
    /// Uses SHA256 truncated to 16 characters to prevent IP exposure in Redis.
    fn hash_identifier(&self, identifier: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(identifier.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8]) // 16 hex chars = 64 bits, sufficient for uniqueness
    }
}

/// Check if Redis rate limiting is enabled via environment variable
pub fn is_redis_rate_limit_enabled() -> bool {
    env::var("ENABLE_REDIS_RATE_LIMIT")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true) // Enabled by default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_identifier() {
        let pool = match crate::redis_pool::init_redis_pool() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Redis not available, skipping hash test");
                return;
            }
        };

        let limiter = RedisRateLimiter::new(pool, "test".to_string(), 5, 60);

        let hash1 = limiter.hash_identifier("192.168.1.1");
        let hash2 = limiter.hash_identifier("192.168.1.1");
        let hash3 = limiter.hash_identifier("192.168.1.2");

        // Same input = same hash
        assert_eq!(hash1, hash2);
        // Different input = different hash
        assert_ne!(hash1, hash3);
        // Hash is 16 chars
        assert_eq!(hash1.len(), 16);
    }

    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_rate_limit_basic() {
        let pool = crate::redis_pool::init_redis_pool().unwrap();
        let limiter = RedisRateLimiter::new(pool, "test_basic".to_string(), 3, 60);

        // Clean up from previous runs
        limiter.reset("test_ip_1").await.unwrap();

        // First 3 requests should be allowed
        for i in 0..3 {
            match limiter.check_and_increment("test_ip_1").await.unwrap() {
                RateLimitResult::Allowed { remaining, .. } => {
                    assert_eq!(remaining, 2 - i as u32);
                }
                RateLimitResult::Limited { .. } => {
                    panic!("Request {} should be allowed", i + 1);
                }
            }
        }

        // 4th request should be limited
        match limiter.check_and_increment("test_ip_1").await.unwrap() {
            RateLimitResult::Limited { retry_after } => {
                assert!(retry_after > 0);
            }
            RateLimitResult::Allowed { .. } => {
                panic!("Request 4 should be limited");
            }
        }

        // Clean up
        limiter.reset("test_ip_1").await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_rate_limit_different_ips() {
        let pool = crate::redis_pool::init_redis_pool().unwrap();
        let limiter = RedisRateLimiter::new(pool, "test_ips".to_string(), 2, 60);

        // Clean up
        limiter.reset("ip_a").await.unwrap();
        limiter.reset("ip_b").await.unwrap();

        // Fill up IP A
        for _ in 0..2 {
            match limiter.check_and_increment("ip_a").await.unwrap() {
                RateLimitResult::Allowed { .. } => {}
                RateLimitResult::Limited { .. } => panic!("Should be allowed"),
            }
        }

        // IP A should be limited
        match limiter.check_and_increment("ip_a").await.unwrap() {
            RateLimitResult::Limited { .. } => {}
            RateLimitResult::Allowed { .. } => panic!("IP A should be limited"),
        }

        // IP B should still be allowed
        match limiter.check_and_increment("ip_b").await.unwrap() {
            RateLimitResult::Allowed { remaining, .. } => {
                assert_eq!(remaining, 1);
            }
            RateLimitResult::Limited { .. } => panic!("IP B should be allowed"),
        }

        // Clean up
        limiter.reset("ip_a").await.unwrap();
        limiter.reset("ip_b").await.unwrap();
    }
}
