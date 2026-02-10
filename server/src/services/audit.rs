//! Audit Service for SOC2/GDPR compliance
//!
//! Provides centralized audit logging with:
//! - Thread-safe chain integrity (hash linking)
//! - Async-friendly API
//! - Request context extraction
//! - Batch operations for high-throughput scenarios
//!
//! SECURITY GUARANTEES:
//! - IP addresses are ALWAYS hashed before storage
//! - No sensitive data (keys, passwords, .onion addresses) is ever logged
//! - Append-only: audit records cannot be modified or deleted

use actix_web::HttpRequest;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::db::DbPool;
use crate::models::audit_event::{ActorType, AuditAction, AuditEvent, AuditEventBuilder};

/// Audit service for centralized logging
#[derive(Clone)]
pub struct AuditService {
    pool: DbPool,
    /// Last hash for chain integrity (thread-safe)
    last_hash: Arc<Mutex<Option<String>>>,
}

impl AuditService {
    /// Create a new audit service
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            last_hash: Arc::new(Mutex::new(None)),
        }
    }

    /// Initialize the service by loading the last hash from DB
    pub async fn initialize(&self) -> Result<()> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        let hash = AuditEvent::get_last_hash(&mut conn)?;
        let mut last_hash = self.last_hash.lock().await;
        *last_hash = hash;
        Ok(())
    }

    /// Log an audit event with chain integrity
    pub async fn log(&self, builder: AuditEventBuilder) -> Result<AuditEvent> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        let mut last_hash = self.last_hash.lock().await;

        let event = builder.build(&mut conn, last_hash.clone())?;
        *last_hash = Some(event.record_hash.clone());

        Ok(event)
    }

    /// Log without waiting (fire-and-forget for non-critical events)
    /// Uses spawn_blocking to not block async runtime
    pub fn log_async(&self, builder: AuditEventBuilder) {
        let pool = self.pool.clone();
        let last_hash = self.last_hash.clone();

        tokio::spawn(async move {
            let result = async {
                let mut conn = pool.get().context("Failed to get DB connection")?;
                let mut hash_guard = last_hash.lock().await;
                let event = builder.build(&mut conn, hash_guard.clone())?;
                *hash_guard = Some(event.record_hash.clone());
                Ok::<_, anyhow::Error>(())
            }
            .await;

            if let Err(e) = result {
                tracing::error!("Failed to log audit event: {}", e);
            }
        });
    }

    /// Extract request context for audit logging
    /// Returns (ip, user_agent, request_id)
    pub fn extract_request_context(req: &HttpRequest) -> RequestContext {
        let ip = req
            .connection_info()
            .realip_remote_addr()
            .map(|s| s.to_string());

        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        RequestContext {
            ip,
            user_agent,
            request_id,
        }
    }

    /// Verify audit log integrity
    pub async fn verify_integrity(&self) -> Result<IntegrityReport> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        let broken_links = AuditEvent::verify_chain_integrity(&mut conn)?;

        Ok(IntegrityReport {
            is_valid: broken_links.is_empty(),
            broken_links,
            checked_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Get recent security events (login failures, etc.)
    pub async fn get_security_events(&self, minutes: i64) -> Result<Vec<AuditEvent>> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        AuditEvent::get_recent_login_failures(&mut conn, minutes)
    }

    /// Get audit trail for a specific resource
    pub async fn get_resource_audit_trail(
        &self,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<Vec<AuditEvent>> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        AuditEvent::find_by_resource(&mut conn, resource_type, resource_id)
    }

    /// Get audit events for a specific actor
    pub async fn get_actor_events(&self, actor_id: &str, limit: i64) -> Result<Vec<AuditEvent>> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        AuditEvent::find_by_actor(&mut conn, actor_id, limit)
    }
}

/// Request context extracted from HTTP request
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

impl RequestContext {
    /// Apply context to an audit event builder
    pub fn apply_to(self, mut builder: AuditEventBuilder) -> AuditEventBuilder {
        if let Some(ip) = self.ip {
            builder = builder.ip(&ip);
        }
        if let Some(ua) = self.user_agent {
            builder = builder.user_agent(ua);
        }
        if let Some(rid) = self.request_id {
            builder = builder.request_id(rid);
        }
        builder
    }
}

/// Integrity verification report
#[derive(Debug, Clone, serde::Serialize)]
pub struct IntegrityReport {
    pub is_valid: bool,
    pub broken_links: Vec<String>,
    pub checked_at: String,
}

/// Convenience functions for common audit patterns
impl AuditService {
    /// Log a successful login
    pub async fn log_login(&self, user_id: &str, ctx: RequestContext) -> Result<AuditEvent> {
        let builder = AuditEventBuilder::new("auth.login", AuditAction::Login)
            .actor(user_id, ActorType::User)
            .resource("session", user_id);

        self.log(ctx.apply_to(builder)).await
    }

    /// Log a failed login attempt
    pub async fn log_login_failed(
        &self,
        username: &str,
        reason: &str,
        ctx: RequestContext,
    ) -> Result<AuditEvent> {
        let builder = AuditEventBuilder::new("auth.login_failed", AuditAction::LoginFailed)
            .metadata("username_hash", sha256_hash(username))
            .metadata("reason", reason);

        self.log(ctx.apply_to(builder)).await
    }

    /// Log escrow creation
    pub async fn log_escrow_created(
        &self,
        escrow_id: &str,
        user_id: &str,
        amount: i64,
        ctx: RequestContext,
    ) -> Result<AuditEvent> {
        let builder = AuditEventBuilder::new("escrow.created", AuditAction::Create)
            .actor(user_id, ActorType::User)
            .resource("escrow", escrow_id)
            .metadata("amount_atomic", amount);

        self.log(ctx.apply_to(builder)).await
    }

    /// Log escrow status change
    pub async fn log_escrow_status_change(
        &self,
        escrow_id: &str,
        actor_id: &str,
        actor_type: ActorType,
        old_status: &str,
        new_status: &str,
        action: AuditAction,
        ctx: RequestContext,
    ) -> Result<AuditEvent> {
        let event_type = match action {
            AuditAction::Fund => "escrow.funded",
            AuditAction::Release => "escrow.released",
            AuditAction::Dispute => "escrow.disputed",
            AuditAction::Cancel => "escrow.cancelled",
            AuditAction::Timeout => "escrow.timeout",
            _ => "escrow.updated",
        };

        let builder = AuditEventBuilder::new(event_type, action)
            .actor(actor_id, actor_type)
            .resource("escrow", escrow_id)
            .metadata("old_status", old_status)
            .metadata("new_status", new_status);

        self.log(ctx.apply_to(builder)).await
    }

    /// Log API key creation
    pub async fn log_api_key_created(
        &self,
        key_id: &str,
        user_id: &str,
        tier: &str,
        ctx: RequestContext,
    ) -> Result<AuditEvent> {
        let builder = AuditEventBuilder::new("api_key.created", AuditAction::Create)
            .actor(user_id, ActorType::User)
            .resource("api_key", key_id)
            .metadata("tier", tier);

        self.log(ctx.apply_to(builder)).await
    }

    /// Log API key usage (lightweight - async fire-and-forget)
    pub fn log_api_key_used(&self, key_id: &str, endpoint: &str, ctx: RequestContext) {
        let builder = AuditEventBuilder::new("api_key.used", AuditAction::Read)
            .actor(key_id, ActorType::ApiKey)
            .metadata("endpoint", endpoint);

        self.log_async(ctx.apply_to(builder));
    }
}

/// Helper to hash sensitive strings for logging
fn sha256_hash(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_context_extraction() {
        // Context should handle None values gracefully
        let ctx = RequestContext {
            ip: None,
            user_agent: None,
            request_id: None,
        };

        let builder = AuditEventBuilder::new("test", AuditAction::Create);
        let builder = ctx.apply_to(builder);

        // Should not panic with None values
        assert!(builder.ip_hash.is_none());
        assert!(builder.user_agent.is_none());
        assert!(builder.request_id.is_none());
    }

    #[test]
    fn test_sha256_hash_consistency() {
        let hash1 = sha256_hash("test_input");
        let hash2 = sha256_hash("test_input");
        assert_eq!(hash1, hash2);

        let hash3 = sha256_hash("different_input");
        assert_ne!(hash1, hash3);
    }
}
