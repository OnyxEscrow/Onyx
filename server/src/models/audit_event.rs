//! Audit Event model for SOC2/GDPR compliance
//!
//! Provides tamper-evident, append-only audit logging with:
//! - Blockchain-style hash chaining for integrity verification
//! - IP hashing for GDPR compliance (never stores raw IPs)
//! - Structured event types for SIEM integration
//! - Request tracing via X-Request-ID
//!
//! SECURITY: This module NEVER logs sensitive data:
//! - No private keys, view keys, spend keys
//! - No raw IP addresses (always hashed)
//! - No .onion addresses
//! - No passwords or session tokens

use anyhow::{Context, Result};
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::schema::audit_events;

/// Actor type - who performed the action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// Authenticated user via session
    User,
    /// API key authentication
    ApiKey,
    /// System/automated process
    System,
    /// Arbiter (human or auto)
    Arbiter,
    /// Unauthenticated/anonymous
    Anonymous,
}

impl ActorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActorType::User => "user",
            ActorType::ApiKey => "api_key",
            ActorType::System => "system",
            ActorType::Arbiter => "arbiter",
            ActorType::Anonymous => "anonymous",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "user" => Some(ActorType::User),
            "api_key" => Some(ActorType::ApiKey),
            "system" => Some(ActorType::System),
            "arbiter" => Some(ActorType::Arbiter),
            "anonymous" => Some(ActorType::Anonymous),
            _ => None,
        }
    }
}

/// Audit action type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Create,
    Read,
    Update,
    Delete,
    Login,
    Logout,
    LoginFailed,
    Export,
    Fund,
    Release,
    Dispute,
    Cancel,
    Timeout,
    Sign,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Create => "create",
            AuditAction::Read => "read",
            AuditAction::Update => "update",
            AuditAction::Delete => "delete",
            AuditAction::Login => "login",
            AuditAction::Logout => "logout",
            AuditAction::LoginFailed => "login_failed",
            AuditAction::Export => "export",
            AuditAction::Fund => "fund",
            AuditAction::Release => "release",
            AuditAction::Dispute => "dispute",
            AuditAction::Cancel => "cancel",
            AuditAction::Timeout => "timeout",
            AuditAction::Sign => "sign",
        }
    }
}

/// Database model for audit events (Queryable)
#[derive(Debug, Clone, Queryable, Identifiable, Serialize)]
#[diesel(table_name = audit_events)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub actor_id: Option<String>,
    pub actor_type: String,
    pub org_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub action: String,
    pub ip_hash: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub metadata: Option<String>,
    pub prev_hash: Option<String>,
    pub record_hash: String,
}

/// Insertable struct for new audit events
#[derive(Debug, Insertable)]
#[diesel(table_name = audit_events)]
pub struct NewAuditEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub actor_id: Option<String>,
    pub actor_type: String,
    pub org_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub action: String,
    pub ip_hash: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub metadata: Option<String>,
    pub prev_hash: Option<String>,
    pub record_hash: String,
}

/// Builder pattern for creating audit events
#[derive(Debug, Clone)]
pub struct AuditEventBuilder {
    pub(crate) event_type: String,
    pub(crate) actor_id: Option<String>,
    pub(crate) actor_type: ActorType,
    pub(crate) org_id: Option<String>,
    pub(crate) resource_type: Option<String>,
    pub(crate) resource_id: Option<String>,
    pub(crate) action: AuditAction,
    pub(crate) ip_hash: Option<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) request_id: Option<String>,
    pub(crate) old_value: Option<serde_json::Value>,
    pub(crate) new_value: Option<serde_json::Value>,
    pub(crate) metadata: serde_json::Value,
}

impl AuditEventBuilder {
    /// Create a new audit event builder
    ///
    /// # Arguments
    /// * `event_type` - Dot-notation event type (e.g., "escrow.created", "auth.login")
    /// * `action` - The action being performed
    pub fn new(event_type: impl Into<String>, action: AuditAction) -> Self {
        Self {
            event_type: event_type.into(),
            actor_id: None,
            actor_type: ActorType::Anonymous,
            org_id: None,
            resource_type: None,
            resource_id: None,
            action,
            ip_hash: None,
            user_agent: None,
            request_id: None,
            old_value: None,
            new_value: None,
            metadata: serde_json::json!({}),
        }
    }

    /// Set the actor (who performed the action)
    pub fn actor(mut self, id: impl Into<String>, actor_type: ActorType) -> Self {
        self.actor_id = Some(id.into());
        self.actor_type = actor_type;
        self
    }

    /// Set actor for system actions
    pub fn system_actor(mut self) -> Self {
        self.actor_id = Some("system".to_string());
        self.actor_type = ActorType::System;
        self
    }

    /// Set the resource being acted upon
    pub fn resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Set organization ID (for multi-tenancy)
    pub fn org(mut self, org_id: impl Into<String>) -> Self {
        self.org_id = Some(org_id.into());
        self
    }

    /// Set IP address (will be hashed - GDPR compliant)
    /// SECURITY: Raw IP is never stored, only SHA256 hash
    pub fn ip(mut self, ip: &str) -> Self {
        // Never store raw IP - always hash for GDPR compliance
        let mut hasher = Sha256::new();
        hasher.update(ip.as_bytes());
        self.ip_hash = Some(format!("{:x}", hasher.finalize()));
        self
    }

    /// Set user agent string
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Set request ID for distributed tracing
    pub fn request_id(mut self, rid: impl Into<String>) -> Self {
        self.request_id = Some(rid.into());
        self
    }

    /// Set before/after values for change tracking
    /// SECURITY: Caller must ensure no sensitive data in old/new values
    pub fn diff<T: Serialize>(mut self, old: Option<&T>, new: Option<&T>) -> Self {
        self.old_value = old.and_then(|v| serde_json::to_value(v).ok());
        self.new_value = new.and_then(|v| serde_json::to_value(v).ok());
        self
    }

    /// Add metadata key-value pair
    pub fn metadata(mut self, key: &str, value: impl Serialize) -> Self {
        if let serde_json::Value::Object(ref mut map) = self.metadata {
            if let Ok(v) = serde_json::to_value(value) {
                map.insert(key.to_string(), v);
            }
        }
        self
    }

    /// Build and persist the audit event
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `prev_hash` - Hash of the previous audit event (for chain integrity)
    pub fn build(
        self,
        conn: &mut SqliteConnection,
        prev_hash: Option<String>,
    ) -> Result<AuditEvent> {
        let now = Utc::now();
        let event_id = ulid::Ulid::new().to_string();
        let timestamp = now.to_rfc3339();

        // Compute tamper-evident hash (includes all fields + previous hash)
        let hash_input = format!(
            "{}|{}|{}|{:?}|{}|{:?}|{:?}|{:?}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{:?}",
            event_id,
            timestamp,
            self.event_type,
            self.actor_id,
            self.actor_type.as_str(),
            self.org_id,
            self.resource_type,
            self.resource_id,
            self.action.as_str(),
            self.ip_hash,
            self.user_agent,
            self.request_id,
            self.old_value,
            self.new_value,
            self.metadata,
            prev_hash
        );

        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        let computed_hash = format!("{:x}", hasher.finalize());

        let new_event = NewAuditEvent {
            id: event_id.clone(),
            timestamp: timestamp.clone(),
            event_type: self.event_type.clone(),
            actor_id: self.actor_id.clone(),
            actor_type: self.actor_type.as_str().to_string(),
            org_id: self.org_id.clone(),
            resource_type: self.resource_type.clone(),
            resource_id: self.resource_id.clone(),
            action: self.action.as_str().to_string(),
            ip_hash: self.ip_hash.clone(),
            user_agent: self.user_agent.clone(),
            request_id: self.request_id.clone(),
            old_value: self.old_value.as_ref().map(|v| v.to_string()),
            new_value: self.new_value.as_ref().map(|v| v.to_string()),
            metadata: Some(self.metadata.to_string()),
            prev_hash: prev_hash.clone(),
            record_hash: computed_hash.clone(),
        };

        diesel::insert_into(audit_events::table)
            .values(&new_event)
            .execute(conn)
            .context("Failed to insert audit event")?;

        Ok(AuditEvent {
            id: event_id,
            timestamp,
            event_type: self.event_type,
            actor_id: self.actor_id,
            actor_type: self.actor_type.as_str().to_string(),
            org_id: self.org_id,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            action: self.action.as_str().to_string(),
            ip_hash: self.ip_hash,
            user_agent: self.user_agent,
            request_id: self.request_id,
            old_value: self.old_value.map(|v| v.to_string()),
            new_value: self.new_value.map(|v| v.to_string()),
            metadata: Some(self.metadata.to_string()),
            prev_hash,
            record_hash: computed_hash,
        })
    }
}

impl AuditEvent {
    /// Get the last audit event hash (for chain continuation)
    pub fn get_last_hash(conn: &mut SqliteConnection) -> Result<Option<String>> {
        audit_events::table
            .select(audit_events::record_hash)
            .order(audit_events::timestamp.desc())
            .first::<String>(conn)
            .optional()
            .context("Failed to get last audit hash")
    }

    /// Find audit events by actor
    pub fn find_by_actor(
        conn: &mut SqliteConnection,
        actor_id: &str,
        limit: i64,
    ) -> Result<Vec<AuditEvent>> {
        audit_events::table
            .filter(audit_events::actor_id.eq(actor_id))
            .order(audit_events::timestamp.desc())
            .limit(limit)
            .load(conn)
            .context("Failed to find audit events by actor")
    }

    /// Find audit events by resource
    pub fn find_by_resource(
        conn: &mut SqliteConnection,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<Vec<AuditEvent>> {
        audit_events::table
            .filter(audit_events::resource_type.eq(resource_type))
            .filter(audit_events::resource_id.eq(resource_id))
            .order(audit_events::timestamp.asc())
            .load(conn)
            .context("Failed to find audit events by resource")
    }

    /// Find audit events by event type
    pub fn find_by_event_type(
        conn: &mut SqliteConnection,
        event_type: &str,
        limit: i64,
    ) -> Result<Vec<AuditEvent>> {
        audit_events::table
            .filter(audit_events::event_type.eq(event_type))
            .order(audit_events::timestamp.desc())
            .limit(limit)
            .load(conn)
            .context("Failed to find audit events by event type")
    }

    /// Find audit events in time range
    pub fn find_in_range(
        conn: &mut SqliteConnection,
        start: &str,
        end: &str,
        limit: i64,
    ) -> Result<Vec<AuditEvent>> {
        audit_events::table
            .filter(audit_events::timestamp.ge(start))
            .filter(audit_events::timestamp.le(end))
            .order(audit_events::timestamp.asc())
            .limit(limit)
            .load(conn)
            .context("Failed to find audit events in range")
    }

    /// Verify chain integrity (detect tampering)
    /// Returns list of events with broken chain links
    pub fn verify_chain_integrity(conn: &mut SqliteConnection) -> Result<Vec<String>> {
        let events: Vec<AuditEvent> = audit_events::table
            .order(audit_events::timestamp.asc())
            .load(conn)
            .context("Failed to load audit events for integrity check")?;

        let mut broken_links = Vec::new();
        let mut expected_prev_hash: Option<String> = None;

        for event in events {
            // Check if prev_hash matches expected
            if event.prev_hash != expected_prev_hash {
                broken_links.push(event.id.clone());
            }
            expected_prev_hash = Some(event.record_hash.clone());
        }

        Ok(broken_links)
    }

    /// Count events by type (for metrics)
    pub fn count_by_type(conn: &mut SqliteConnection, event_type: &str) -> Result<i64> {
        audit_events::table
            .filter(audit_events::event_type.eq(event_type))
            .count()
            .get_result(conn)
            .context("Failed to count audit events by type")
    }

    /// Get failed login attempts in last N minutes (security monitoring)
    pub fn get_recent_login_failures(
        conn: &mut SqliteConnection,
        minutes: i64,
    ) -> Result<Vec<AuditEvent>> {
        let cutoff = Utc::now()
            .checked_sub_signed(chrono::Duration::minutes(minutes))
            .map(|t| t.to_rfc3339())
            .unwrap_or_default();

        audit_events::table
            .filter(audit_events::event_type.eq("auth.login_failed"))
            .filter(audit_events::timestamp.ge(&cutoff))
            .order(audit_events::timestamp.desc())
            .load(conn)
            .context("Failed to get recent login failures")
    }
}

/// Standard event type constants
pub mod event_types {
    // Auth events
    pub const AUTH_LOGIN: &str = "auth.login";
    pub const AUTH_LOGOUT: &str = "auth.logout";
    pub const AUTH_LOGIN_FAILED: &str = "auth.login_failed";
    pub const AUTH_PASSWORD_CHANGED: &str = "auth.password_changed";
    pub const AUTH_MFA_ENABLED: &str = "auth.mfa_enabled";
    pub const AUTH_MFA_DISABLED: &str = "auth.mfa_disabled";
    pub const AUTH_SESSION_REVOKED: &str = "auth.session_revoked";

    // Escrow events
    pub const ESCROW_CREATED: &str = "escrow.created";
    pub const ESCROW_FUNDED: &str = "escrow.funded";
    pub const ESCROW_RELEASED: &str = "escrow.released";
    pub const ESCROW_DISPUTED: &str = "escrow.disputed";
    pub const ESCROW_CANCELLED: &str = "escrow.cancelled";
    pub const ESCROW_TIMEOUT: &str = "escrow.timeout";
    pub const ESCROW_SIGNED: &str = "escrow.signed";
    pub const ESCROW_ARBITER_ASSIGNED: &str = "escrow.arbiter_assigned";

    // API events
    pub const API_KEY_CREATED: &str = "api_key.created";
    pub const API_KEY_REVOKED: &str = "api_key.revoked";
    pub const API_KEY_ROTATED: &str = "api_key.rotated";

    // Webhook events
    pub const WEBHOOK_CREATED: &str = "webhook.created";
    pub const WEBHOOK_DELETED: &str = "webhook.deleted";
    pub const WEBHOOK_DELIVERY_FAILED: &str = "webhook.delivery_failed";

    // User events
    pub const USER_CREATED: &str = "user.created";
    pub const USER_UPDATED: &str = "user.updated";
    pub const USER_DELETED: &str = "user.deleted";
    pub const USER_SUSPENDED: &str = "user.suspended";
    pub const USER_EXPORT_REQUESTED: &str = "user.export_requested";
    pub const USER_DELETION_REQUESTED: &str = "user.deletion_requested";

    // Admin events
    pub const ADMIN_SETTINGS_CHANGED: &str = "admin.settings_changed";
    pub const ADMIN_ORG_CREATED: &str = "admin.org_created";
    pub const ADMIN_USER_IMPERSONATED: &str = "admin.user_impersonated";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actor_type_serialization() {
        assert_eq!(ActorType::User.as_str(), "user");
        assert_eq!(ActorType::ApiKey.as_str(), "api_key");
        assert_eq!(ActorType::System.as_str(), "system");
        assert_eq!(ActorType::Arbiter.as_str(), "arbiter");
        assert_eq!(ActorType::Anonymous.as_str(), "anonymous");
    }

    #[test]
    fn test_actor_type_parsing() {
        assert_eq!(ActorType::from_str("user"), Some(ActorType::User));
        assert_eq!(ActorType::from_str("api_key"), Some(ActorType::ApiKey));
        assert_eq!(ActorType::from_str("invalid"), None);
    }

    #[test]
    fn test_ip_hashing() {
        let builder = AuditEventBuilder::new("test", AuditAction::Create).ip("192.168.1.1");

        // IP should be hashed, not stored raw
        assert!(builder.ip_hash.is_some());
        assert!(!builder.ip_hash.as_ref().unwrap().contains("192"));

        // Same IP should produce same hash
        let builder2 = AuditEventBuilder::new("test", AuditAction::Create).ip("192.168.1.1");
        assert_eq!(builder.ip_hash, builder2.ip_hash);
    }

    #[test]
    fn test_builder_chaining() {
        let builder = AuditEventBuilder::new("escrow.created", AuditAction::Create)
            .actor("user_123", ActorType::User)
            .resource("escrow", "esc_456")
            .org("org_789")
            .ip("127.0.0.1")
            .user_agent("Mozilla/5.0")
            .request_id("req_abc")
            .metadata("amount_xmr", 1.5);

        assert_eq!(builder.event_type, "escrow.created");
        assert_eq!(builder.actor_id, Some("user_123".to_string()));
        assert_eq!(builder.actor_type, ActorType::User);
        assert_eq!(builder.resource_type, Some("escrow".to_string()));
        assert_eq!(builder.resource_id, Some("esc_456".to_string()));
        assert_eq!(builder.org_id, Some("org_789".to_string()));
        assert!(builder.ip_hash.is_some());
        assert_eq!(builder.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(builder.request_id, Some("req_abc".to_string()));
    }

    #[test]
    fn test_metadata_accumulation() {
        let builder = AuditEventBuilder::new("test", AuditAction::Create)
            .metadata("key1", "value1")
            .metadata("key2", 42)
            .metadata("key3", true);

        if let serde_json::Value::Object(map) = &builder.metadata {
            assert_eq!(map.get("key1"), Some(&serde_json::json!("value1")));
            assert_eq!(map.get("key2"), Some(&serde_json::json!(42)));
            assert_eq!(map.get("key3"), Some(&serde_json::json!(true)));
        } else {
            panic!("Metadata should be an object");
        }
    }
}
