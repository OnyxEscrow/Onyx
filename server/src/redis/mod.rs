//! Redis-backed services for production-ready multi-server deployments
//!
//! This module provides Redis-backed implementations of services that
//! were previously in-memory, enabling horizontal scaling and crash resilience.
//!
//! # Features
//!
//! - **Rate Limiting**: Distributed rate limiting with sliding windows
//! - **Challenge Store**: Re-exported from redis_pool (BE-001)
//! - **WASM Multisig Info**: Re-exported from redis_pool (BE-002)
//!
//! # Configuration
//!
//! Set these environment variables in .env:
//!
//! ```bash
//! REDIS_URL=redis://127.0.0.1:6379
//! REDIS_PASSWORD=  # Optional, empty = no auth
//! REDIS_POOL_SIZE=10
//! REDIS_TIMEOUT_SECS=5
//! ENABLE_REDIS_RATE_LIMIT=true
//! ```

pub mod rate_limit;

// Re-export rate limiter for convenience
pub use rate_limit::{RateLimitResult, RedisRateLimiter};

// Re-export from redis_pool for backwards compatibility
pub use crate::redis_pool::{
    delete_wasm_infos, get_all_wasm_infos, get_and_delete_challenge, get_wasm_peer_infos,
    init_redis_pool, store_challenge, submit_wasm_multisig_info, RedisPool,
};
