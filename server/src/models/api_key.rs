//! API Key model for B2B EaaS authentication
//!
//! Provides secure API key management with:
//! - SHA256 hashing (plaintext keys never stored)
//! - Tiered rate limiting (Free/Pro/Enterprise)
//! - Key rotation support
//! - Expiration handling
//! - Usage tracking

use anyhow::{Context, Result};
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::schema::api_keys;

/// API Key tier determines rate limits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyTier {
    Free,
    Pro,
    Enterprise,
}

impl ApiKeyTier {
    /// Get the default rate limit (requests per minute) for this tier
    pub fn default_rate_limit(&self) -> u32 {
        match self {
            ApiKeyTier::Free => 60,
            ApiKeyTier::Pro => 300,
            ApiKeyTier::Enterprise => 1000,
        }
    }

    /// Parse tier from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "free" => Some(ApiKeyTier::Free),
            "pro" => Some(ApiKeyTier::Pro),
            "enterprise" => Some(ApiKeyTier::Enterprise),
            _ => None,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiKeyTier::Free => "free",
            ApiKeyTier::Pro => "pro",
            ApiKeyTier::Enterprise => "enterprise",
        }
    }
}

impl Default for ApiKeyTier {
    fn default() -> Self {
        ApiKeyTier::Free
    }
}

/// B2B API key scopes for granular permission control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    EscrowCreate,
    EscrowRead,
    EscrowRelease,
    EscrowRefund,
    EscrowDispute,
    WebhookManage,
    AnalyticsRead,
}

impl ApiKeyScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiKeyScope::EscrowCreate => "escrow:create",
            ApiKeyScope::EscrowRead => "escrow:read",
            ApiKeyScope::EscrowRelease => "escrow:release",
            ApiKeyScope::EscrowRefund => "escrow:refund",
            ApiKeyScope::EscrowDispute => "escrow:dispute",
            ApiKeyScope::WebhookManage => "webhook:manage",
            ApiKeyScope::AnalyticsRead => "analytics:read",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "escrow:create" => Some(ApiKeyScope::EscrowCreate),
            "escrow:read" => Some(ApiKeyScope::EscrowRead),
            "escrow:release" => Some(ApiKeyScope::EscrowRelease),
            "escrow:refund" => Some(ApiKeyScope::EscrowRefund),
            "escrow:dispute" => Some(ApiKeyScope::EscrowDispute),
            "webhook:manage" => Some(ApiKeyScope::WebhookManage),
            "analytics:read" => Some(ApiKeyScope::AnalyticsRead),
            _ => None,
        }
    }

    /// All scopes (used for Enterprise keys with full access)
    pub fn all() -> Vec<Self> {
        vec![
            ApiKeyScope::EscrowCreate,
            ApiKeyScope::EscrowRead,
            ApiKeyScope::EscrowRelease,
            ApiKeyScope::EscrowRefund,
            ApiKeyScope::EscrowDispute,
            ApiKeyScope::WebhookManage,
            ApiKeyScope::AnalyticsRead,
        ]
    }
}

/// Database model for API keys
#[derive(Clone, Queryable, Identifiable, Serialize)]
#[diesel(table_name = api_keys)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub key_prefix: String,
    pub tier: String,
    pub rate_limit_override: Option<i32>,
    pub is_active: i32,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub total_requests: i32,
    pub metadata: Option<String>,
    pub scopes: Option<String>,
    pub allowed_origins: Option<String>,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("key_hash", &"<redacted>")
            .field("key_prefix", &self.key_prefix)
            .field("tier", &self.tier)
            .field("is_active", &self.is_active)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Insertable struct for creating new API keys
#[derive(Insertable)]
#[diesel(table_name = api_keys)]
pub struct NewApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub tier: String,
    pub rate_limit_override: Option<i32>,
    pub is_active: i32,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub total_requests: i32,
    pub metadata: Option<String>,
    pub scopes: Option<String>,
    pub allowed_origins: Option<String>,
}

/// Response returned when creating a new API key
/// IMPORTANT: The raw_key is only shown once at creation time
#[derive(Debug, Serialize)]
pub struct ApiKeyCreationResponse {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub tier: String,
    /// The actual API key - only returned at creation, never stored or retrievable
    pub raw_key: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// Public API key info (for listing)
#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub tier: String,
    pub is_active: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub total_requests: i32,
}

impl From<ApiKey> for ApiKeyInfo {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            key_prefix: key.key_prefix,
            tier: key.tier,
            is_active: key.is_active != 0,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
            expires_at: key.expires_at,
            total_requests: key.total_requests,
        }
    }
}

impl ApiKey {
    /// Generate a new API key with `nxs_` prefix
    /// Returns (raw_key, key_hash, key_prefix)
    pub fn generate_key() -> (String, String, String) {
        let uuid = Uuid::new_v4().to_string().replace("-", "");
        let raw_key = format!("nxs_{}", uuid);
        let key_hash = Self::hash_key(&raw_key);
        // Key prefix is "nxs_" + first 8 chars of UUID
        let key_prefix = format!("nxs_{}...", &uuid[..8]);
        (raw_key, key_hash, key_prefix)
    }

    /// Hash an API key using SHA256
    pub fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Create a new API key in the database
    /// Returns the creation response with the raw key (only time it's available)
    pub fn create(
        conn: &mut SqliteConnection,
        user_id: &str,
        name: &str,
        tier: ApiKeyTier,
        expires_at: Option<String>,
        metadata: Option<String>,
    ) -> Result<ApiKeyCreationResponse> {
        let (raw_key, key_hash, key_prefix) = Self::generate_key();
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let new_key = NewApiKey {
            id: id.clone(),
            user_id: user_id.to_string(),
            name: name.to_string(),
            key_hash,
            key_prefix: key_prefix.clone(),
            tier: tier.as_str().to_string(),
            rate_limit_override: None,
            is_active: 1,
            expires_at: expires_at.clone(),
            created_at: created_at.clone(),
            total_requests: 0,
            metadata,
            scopes: None,
            allowed_origins: None,
        };

        diesel::insert_into(api_keys::table)
            .values(&new_key)
            .execute(conn)
            .context("Failed to insert API key")?;

        Ok(ApiKeyCreationResponse {
            id,
            name: name.to_string(),
            key_prefix,
            tier: tier.as_str().to_string(),
            raw_key,
            created_at,
            expires_at,
        })
    }

    /// Find API key by its hash (used during authentication)
    pub fn find_by_hash(conn: &mut SqliteConnection, hash: &str) -> Result<Option<ApiKey>> {
        api_keys::table
            .filter(api_keys::key_hash.eq(hash))
            .first(conn)
            .optional()
            .context("Failed to query API key by hash")
    }

    /// Find API key by ID
    pub fn find_by_id(conn: &mut SqliteConnection, key_id: &str) -> Result<Option<ApiKey>> {
        api_keys::table
            .filter(api_keys::id.eq(key_id))
            .first(conn)
            .optional()
            .context("Failed to query API key by ID")
    }

    /// List all API keys for a user
    pub fn list_by_user(conn: &mut SqliteConnection, user_id: &str) -> Result<Vec<ApiKey>> {
        api_keys::table
            .filter(api_keys::user_id.eq(user_id))
            .order(api_keys::created_at.desc())
            .load(conn)
            .context("Failed to list API keys for user")
    }

    /// Validate an API key and return the key record if valid
    /// Checks: hash match, is_active, expiration
    pub fn validate(conn: &mut SqliteConnection, raw_key: &str) -> Result<Option<ApiKey>> {
        let key_hash = Self::hash_key(raw_key);

        let key = match Self::find_by_hash(conn, &key_hash)? {
            Some(k) => k,
            None => return Ok(None),
        };

        // Check if active
        if key.is_active == 0 {
            return Ok(None);
        }

        // Check expiration
        if let Some(ref expires_at) = key.expires_at {
            let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
            if expires_at < &now {
                return Ok(None);
            }
        }

        Ok(Some(key))
    }

    /// Update last_used_at and increment total_requests
    pub fn record_usage(conn: &mut SqliteConnection, key_id: &str) -> Result<()> {
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        diesel::update(api_keys::table.filter(api_keys::id.eq(key_id)))
            .set((
                api_keys::last_used_at.eq(Some(now)),
                api_keys::total_requests.eq(api_keys::total_requests + 1),
            ))
            .execute(conn)
            .context("Failed to update API key usage")?;

        Ok(())
    }

    /// Deactivate an API key (soft delete)
    pub fn deactivate(conn: &mut SqliteConnection, key_id: &str, user_id: &str) -> Result<bool> {
        let updated = diesel::update(
            api_keys::table
                .filter(api_keys::id.eq(key_id))
                .filter(api_keys::user_id.eq(user_id)),
        )
        .set(api_keys::is_active.eq(0))
        .execute(conn)
        .context("Failed to deactivate API key")?;

        Ok(updated > 0)
    }

    /// Delete an API key permanently
    pub fn delete(conn: &mut SqliteConnection, key_id: &str, user_id: &str) -> Result<bool> {
        let deleted = diesel::delete(
            api_keys::table
                .filter(api_keys::id.eq(key_id))
                .filter(api_keys::user_id.eq(user_id)),
        )
        .execute(conn)
        .context("Failed to delete API key")?;

        Ok(deleted > 0)
    }

    /// Get effective rate limit for this key
    pub fn effective_rate_limit(&self) -> u32 {
        if let Some(override_limit) = self.rate_limit_override {
            return override_limit as u32;
        }

        ApiKeyTier::from_str(&self.tier)
            .unwrap_or_default()
            .default_rate_limit()
    }

    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(ref expires_at) = self.expires_at {
            let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
            return expires_at < &now;
        }
        false
    }

    /// Update the tier of an API key (admin function)
    pub fn update_tier(
        conn: &mut SqliteConnection,
        key_id: &str,
        new_tier: ApiKeyTier,
    ) -> Result<bool> {
        let updated = diesel::update(api_keys::table.filter(api_keys::id.eq(key_id)))
            .set(api_keys::tier.eq(new_tier.as_str()))
            .execute(conn)
            .context("Failed to update API key tier")?;

        Ok(updated > 0)
    }

    /// Set a custom rate limit override
    pub fn set_rate_limit_override(
        conn: &mut SqliteConnection,
        key_id: &str,
        limit: Option<i32>,
    ) -> Result<bool> {
        let updated = diesel::update(api_keys::table.filter(api_keys::id.eq(key_id)))
            .set(api_keys::rate_limit_override.eq(limit))
            .execute(conn)
            .context("Failed to update rate limit override")?;

        Ok(updated > 0)
    }

    /// Check if this key has a specific scope
    ///
    /// If scopes is NULL, all scopes are granted (backward-compatible default).
    /// Otherwise, scopes is a comma-separated string of scope identifiers.
    pub fn has_scope(&self, scope: ApiKeyScope) -> bool {
        match &self.scopes {
            None => true, // NULL = all scopes (backward-compatible)
            Some(scopes_str) => scopes_str
                .split(',')
                .map(|s| s.trim())
                .any(|s| s == scope.as_str() || s == "*"),
        }
    }

    /// Get parsed scopes list
    pub fn parsed_scopes(&self) -> Vec<ApiKeyScope> {
        match &self.scopes {
            None => ApiKeyScope::all(),
            Some(scopes_str) => scopes_str
                .split(',')
                .filter_map(|s| ApiKeyScope::from_str(s.trim()))
                .collect(),
        }
    }

    /// Update scopes for an API key
    pub fn update_scopes(
        conn: &mut SqliteConnection,
        key_id: &str,
        scopes: Option<&str>,
    ) -> Result<bool> {
        let updated = diesel::update(api_keys::table.filter(api_keys::id.eq(key_id)))
            .set(api_keys::scopes.eq(scopes))
            .execute(conn)
            .context("Failed to update API key scopes")?;
        Ok(updated > 0)
    }

    /// Update allowed origins for an API key
    pub fn update_allowed_origins(
        conn: &mut SqliteConnection,
        key_id: &str,
        origins: Option<&str>,
    ) -> Result<bool> {
        let updated = diesel::update(api_keys::table.filter(api_keys::id.eq(key_id)))
            .set(api_keys::allowed_origins.eq(origins))
            .execute(conn)
            .context("Failed to update API key allowed origins")?;
        Ok(updated > 0)
    }

    /// Check if a request origin is allowed for this key
    ///
    /// If allowed_origins is NULL, all origins are allowed.
    /// Otherwise, comma-separated list of allowed origin patterns.
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        match &self.allowed_origins {
            None => true,
            Some(origins_str) => origins_str
                .split(',')
                .map(|s| s.trim())
                .any(|allowed| allowed == "*" || allowed == origin),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_format() {
        let (raw_key, hash, prefix) = ApiKey::generate_key();

        // Check prefix format
        assert!(raw_key.starts_with("nxs_"), "Key should start with nxs_");
        assert_eq!(raw_key.len(), 36, "Key should be nxs_ + 32 hex chars");

        // Check hash is valid hex
        assert_eq!(hash.len(), 64, "SHA256 hash should be 64 hex chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Check key_prefix format
        assert!(prefix.starts_with("nxs_"));
        assert!(prefix.ends_with("..."));
    }

    #[test]
    fn test_hash_consistency() {
        let key = "nxs_test1234567890abcdef12345678";
        let hash1 = ApiKey::hash_key(key);
        let hash2 = ApiKey::hash_key(key);

        assert_eq!(hash1, hash2, "Same key should produce same hash");
    }

    #[test]
    fn test_tier_rate_limits() {
        assert_eq!(ApiKeyTier::Free.default_rate_limit(), 60);
        assert_eq!(ApiKeyTier::Pro.default_rate_limit(), 300);
        assert_eq!(ApiKeyTier::Enterprise.default_rate_limit(), 1000);
    }

    #[test]
    fn test_tier_parsing() {
        assert_eq!(ApiKeyTier::from_str("free"), Some(ApiKeyTier::Free));
        assert_eq!(ApiKeyTier::from_str("FREE"), Some(ApiKeyTier::Free));
        assert_eq!(ApiKeyTier::from_str("pro"), Some(ApiKeyTier::Pro));
        assert_eq!(
            ApiKeyTier::from_str("enterprise"),
            Some(ApiKeyTier::Enterprise)
        );
        assert_eq!(ApiKeyTier::from_str("invalid"), None);
    }
}
