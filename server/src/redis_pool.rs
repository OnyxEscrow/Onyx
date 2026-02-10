//! Redis connection pool for production-ready session/challenge stores
//!
//! Replaces in-memory HashMaps and SQLite-backed stores with Redis.
//! Provides TTL-based automatic expiration for challenges and session data.

use deadpool_redis::{Config, Connection, Pool, Runtime};
use redis::AsyncCommands;
use std::env;

pub type RedisPool = Pool;

/// Initialize Redis connection pool from environment
///
/// Expects REDIS_URL env var (e.g., "redis://127.0.0.1:6379")
/// Falls back to localhost if not set.
pub fn init_redis_pool() -> Result<RedisPool, anyhow::Error> {
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let cfg = Config::from_url(redis_url);
    let pool = cfg.create_pool(Some(Runtime::Tokio1))?;

    tracing::info!("Redis pool initialized");
    Ok(pool)
}

/// Get a connection from the pool
pub async fn get_conn(pool: &RedisPool) -> Result<Connection, anyhow::Error> {
    let conn = pool.get().await?;
    Ok(conn)
}

// ============================================================================
// Challenge Store (BE-001)
// ============================================================================

const CHALLENGE_PREFIX: &str = "nexus:challenge:";
const CHALLENGE_TTL_SECS: i64 = 300; // 5 minutes

/// Store a challenge for user/escrow pair with automatic TTL expiration
pub async fn store_challenge(
    pool: &RedisPool,
    user_id: &str,
    escrow_id: &str,
    nonce: &[u8; 32],
) -> Result<(), anyhow::Error> {
    let mut conn = get_conn(pool).await?;
    let key = format!("{}{}:{}", CHALLENGE_PREFIX, user_id, escrow_id);

    // Store nonce as hex with TTL
    let nonce_hex = hex::encode(nonce);
    conn.set_ex::<_, _, ()>(&key, &nonce_hex, CHALLENGE_TTL_SECS as u64)
        .await?;

    tracing::debug!(key = %key, "Challenge stored with {}s TTL", CHALLENGE_TTL_SECS);
    Ok(())
}

/// Retrieve and delete challenge (one-time use)
pub async fn get_and_delete_challenge(
    pool: &RedisPool,
    user_id: &str,
    escrow_id: &str,
) -> Result<Option<[u8; 32]>, anyhow::Error> {
    let mut conn = get_conn(pool).await?;
    let key = format!("{}{}:{}", CHALLENGE_PREFIX, user_id, escrow_id);

    // Atomic get + delete
    let nonce_hex: Option<String> = redis::cmd("GETDEL")
        .arg(&key)
        .query_async(&mut *conn)
        .await?;

    match nonce_hex {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str)?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

// ============================================================================
// WASM Multisig Info Store (BE-002)
// ============================================================================

const WASM_INFO_PREFIX: &str = "nexus:wasm_multisig:";
const WASM_INFO_TTL_SECS: i64 = 3600; // 1 hour (multisig setup timeout)

/// Submit multisig info for a participant
/// Returns the count of participants for this escrow
pub async fn submit_wasm_multisig_info(
    pool: &RedisPool,
    escrow_id: &str,
    role: &str,
    multisig_info: &str,
    view_key_component: Option<&str>,
) -> Result<usize, anyhow::Error> {
    let mut conn = get_conn(pool).await?;
    let hash_key = format!("{}{}", WASM_INFO_PREFIX, escrow_id);

    // Store as JSON in a hash field
    let value = serde_json::json!({
        "multisig_info": multisig_info,
        "view_key_component": view_key_component,
    });

    conn.hset::<_, _, _, ()>(&hash_key, role, value.to_string())
        .await?;

    // Set/refresh TTL on the hash
    conn.expire::<_, ()>(&hash_key, WASM_INFO_TTL_SECS).await?;

    // Get count of participants
    let count: usize = conn.hlen(&hash_key).await?;

    tracing::debug!(escrow_id = %escrow_id, role = %role, count = %count, "WASM multisig info stored");
    Ok(count)
}

/// Get peer infos (excluding the requesting role)
pub async fn get_wasm_peer_infos(
    pool: &RedisPool,
    escrow_id: &str,
    my_role: &str,
) -> Result<Vec<(String, String, Option<String>)>, anyhow::Error> {
    let mut conn = get_conn(pool).await?;
    let hash_key = format!("{}{}", WASM_INFO_PREFIX, escrow_id);

    let all: std::collections::HashMap<String, String> = conn.hgetall(&hash_key).await?;

    let mut peers = Vec::new();
    for (role, json_str) in all {
        if role != my_role {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json_str) {
                let info = parsed["multisig_info"].as_str().unwrap_or("").to_string();
                let view_key = parsed["view_key_component"].as_str().map(String::from);
                peers.push((role, info, view_key));
            }
        }
    }

    // Sort by role alphabetically: "arbiter" < "buyer" < "vendor"
    peers.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(peers)
}

/// Get all infos for an escrow
pub async fn get_all_wasm_infos(
    pool: &RedisPool,
    escrow_id: &str,
) -> Result<Vec<(String, String, Option<String>)>, anyhow::Error> {
    let mut conn = get_conn(pool).await?;
    let hash_key = format!("{}{}", WASM_INFO_PREFIX, escrow_id);

    let all: std::collections::HashMap<String, String> = conn.hgetall(&hash_key).await?;

    let mut infos = Vec::new();
    for (role, json_str) in all {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json_str) {
            let info = parsed["multisig_info"].as_str().unwrap_or("").to_string();
            let view_key = parsed["view_key_component"].as_str().map(String::from);
            infos.push((role, info, view_key));
        }
    }

    infos.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(infos)
}

/// Delete all infos for an escrow (cleanup after finalization)
pub async fn delete_wasm_infos(pool: &RedisPool, escrow_id: &str) -> Result<(), anyhow::Error> {
    let mut conn = get_conn(pool).await?;
    let hash_key = format!("{}{}", WASM_INFO_PREFIX, escrow_id);

    conn.del::<_, ()>(&hash_key).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_challenge_store() {
        let pool = init_redis_pool().unwrap();
        let nonce = [42u8; 32];

        store_challenge(&pool, "user1", "escrow1", &nonce)
            .await
            .unwrap();

        let retrieved = get_and_delete_challenge(&pool, "user1", "escrow1")
            .await
            .unwrap();
        assert_eq!(retrieved, Some(nonce));

        // Should be deleted after get
        let second = get_and_delete_challenge(&pool, "user1", "escrow1")
            .await
            .unwrap();
        assert_eq!(second, None);
    }
}
