//! Webhook model for B2B EaaS Integration
//!
//! Stores webhook endpoint registrations with HMAC-SHA256 signing.
//! Supports event subscriptions and automatic disable on consecutive failures.

use anyhow::Result;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::webhooks;

/// Maximum consecutive failures before auto-disable
pub const MAX_CONSECUTIVE_FAILURES: i32 = 5;

/// Webhook event types for subscription filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    // Escrow lifecycle events
    EscrowCreated,
    EscrowFunded,
    EscrowReleased,
    EscrowRefunded,
    EscrowDisputed,
    EscrowResolved,
    EscrowExpired,
    // Multisig events
    MultisigSetupStarted,
    MultisigSetupComplete,
    MultisigSigningRequired,
    // Shipping events
    EscrowShipped,
    EscrowCancelled,
    // Payment events
    PaymentReceived,
    PaymentConfirmed,
    // All events wildcard
    All,
}

impl WebhookEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EscrowCreated => "escrow.created",
            Self::EscrowFunded => "escrow.funded",
            Self::EscrowReleased => "escrow.released",
            Self::EscrowRefunded => "escrow.refunded",
            Self::EscrowDisputed => "escrow.disputed",
            Self::EscrowResolved => "escrow.resolved",
            Self::EscrowExpired => "escrow.expired",
            Self::MultisigSetupStarted => "multisig.setup_started",
            Self::MultisigSetupComplete => "multisig.setup_complete",
            Self::MultisigSigningRequired => "multisig.signing_required",
            Self::EscrowShipped => "escrow.shipped",
            Self::EscrowCancelled => "escrow.cancelled",
            Self::PaymentReceived => "payment.received",
            Self::PaymentConfirmed => "payment.confirmed",
            Self::All => "*",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "escrow.created" => Some(Self::EscrowCreated),
            "escrow.funded" => Some(Self::EscrowFunded),
            "escrow.released" => Some(Self::EscrowReleased),
            "escrow.refunded" => Some(Self::EscrowRefunded),
            "escrow.disputed" => Some(Self::EscrowDisputed),
            "escrow.resolved" => Some(Self::EscrowResolved),
            "escrow.expired" => Some(Self::EscrowExpired),
            "multisig.setup_started" => Some(Self::MultisigSetupStarted),
            "multisig.setup_complete" => Some(Self::MultisigSetupComplete),
            "multisig.signing_required" => Some(Self::MultisigSigningRequired),
            "escrow.shipped" => Some(Self::EscrowShipped),
            "escrow.cancelled" => Some(Self::EscrowCancelled),
            "payment.received" => Some(Self::PaymentReceived),
            "payment.confirmed" => Some(Self::PaymentConfirmed),
            "*" => Some(Self::All),
            _ => None,
        }
    }

    /// Get all event types (excluding All wildcard)
    pub fn all_types() -> Vec<Self> {
        vec![
            Self::EscrowCreated,
            Self::EscrowFunded,
            Self::EscrowReleased,
            Self::EscrowRefunded,
            Self::EscrowDisputed,
            Self::EscrowResolved,
            Self::EscrowExpired,
            Self::MultisigSetupStarted,
            Self::MultisigSetupComplete,
            Self::MultisigSigningRequired,
            Self::EscrowShipped,
            Self::EscrowCancelled,
            Self::PaymentReceived,
            Self::PaymentConfirmed,
        ]
    }
}

/// Webhook database model
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = webhooks)]
pub struct Webhook {
    pub id: String,
    pub api_key_id: String,
    pub url: String,
    pub secret: String, // Encrypted HMAC secret
    pub events: String, // Comma-separated event types or '*'
    pub is_active: i32,
    pub consecutive_failures: i32,
    pub last_failure_reason: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// New webhook for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = webhooks)]
pub struct NewWebhook {
    pub id: String,
    pub api_key_id: String,
    pub url: String,
    pub secret: String,
    pub events: String,
    pub is_active: i32,
    pub consecutive_failures: i32,
    pub description: Option<String>,
}

impl NewWebhook {
    /// Create a new webhook registration
    pub fn new(
        api_key_id: String,
        url: String,
        secret: String,
        events: Vec<WebhookEventType>,
        description: Option<String>,
    ) -> Self {
        let events_str = if events.is_empty() || events.contains(&WebhookEventType::All) {
            "*".to_string()
        } else {
            events
                .iter()
                .map(|e| e.as_str())
                .collect::<Vec<_>>()
                .join(",")
        };

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            api_key_id,
            url,
            secret,
            events: events_str,
            is_active: 1,
            consecutive_failures: 0,
            description,
        }
    }
}

/// API response format for webhooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookResponse {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub is_active: bool,
    pub consecutive_failures: i32,
    pub last_failure_reason: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Webhook> for WebhookResponse {
    fn from(w: Webhook) -> Self {
        let events = if w.events == "*" {
            vec!["*".to_string()]
        } else {
            w.events.split(',').map(|s| s.to_string()).collect()
        };

        Self {
            id: w.id,
            url: w.url,
            events,
            is_active: w.is_active != 0,
            consecutive_failures: w.consecutive_failures,
            last_failure_reason: w.last_failure_reason,
            description: w.description,
            created_at: w.created_at,
            updated_at: w.updated_at,
        }
    }
}

impl Webhook {
    /// Check if this webhook is subscribed to an event type
    pub fn is_subscribed_to(&self, event_type: &str) -> bool {
        if self.events == "*" {
            return true;
        }
        self.events.split(',').any(|e| e.trim() == event_type)
    }

    /// Find webhook by ID
    pub fn find_by_id(webhook_id: &str, conn: &mut SqliteConnection) -> Result<Option<Webhook>> {
        use crate::schema::webhooks::dsl::*;

        let result = webhooks
            .find(webhook_id)
            .first::<Webhook>(conn)
            .optional()?;

        Ok(result)
    }

    /// Get all webhooks for an API key
    pub fn get_by_api_key(key_id: &str, conn: &mut SqliteConnection) -> Result<Vec<Webhook>> {
        use crate::schema::webhooks::dsl::*;

        let results = webhooks
            .filter(api_key_id.eq(key_id))
            .order(created_at.desc())
            .load::<Webhook>(conn)?;

        Ok(results)
    }

    /// Get all active webhooks subscribed to an event type
    pub fn get_active_for_event(
        event_type: &str,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<Webhook>> {
        use crate::schema::webhooks::dsl::*;

        // Get all active webhooks
        let active_hooks = webhooks.filter(is_active.eq(1)).load::<Webhook>(conn)?;

        // Filter by event subscription
        let subscribed: Vec<Webhook> = active_hooks
            .into_iter()
            .filter(|w| w.is_subscribed_to(event_type))
            .collect();

        Ok(subscribed)
    }

    /// Create a new webhook
    pub fn create(new_webhook: NewWebhook, conn: &mut SqliteConnection) -> Result<Webhook> {
        use crate::schema::webhooks::dsl::*;

        diesel::insert_into(webhooks)
            .values(&new_webhook)
            .execute(conn)?;

        let webhook = webhooks.find(&new_webhook.id).first::<Webhook>(conn)?;

        Ok(webhook)
    }

    /// Update webhook URL and events
    pub fn update(
        webhook_id: &str,
        new_url: Option<String>,
        new_events: Option<String>,
        new_description: Option<String>,
        conn: &mut SqliteConnection,
    ) -> Result<()> {
        use crate::schema::webhooks::dsl::*;

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        if let Some(u) = new_url {
            diesel::update(webhooks.find(webhook_id))
                .set((url.eq(u), updated_at.eq(&now)))
                .execute(conn)?;
        }

        if let Some(e) = new_events {
            diesel::update(webhooks.find(webhook_id))
                .set((events.eq(e), updated_at.eq(&now)))
                .execute(conn)?;
        }

        if let Some(d) = new_description {
            diesel::update(webhooks.find(webhook_id))
                .set((description.eq(d), updated_at.eq(&now)))
                .execute(conn)?;
        }

        Ok(())
    }

    /// Increment consecutive failures and disable if threshold reached
    pub fn record_failure(
        webhook_id: &str,
        failure_reason: &str,
        conn: &mut SqliteConnection,
    ) -> Result<bool> {
        use crate::schema::webhooks::dsl::*;

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // Get current failure count
        let current: Webhook = webhooks.find(webhook_id).first(conn)?;
        let new_failures = current.consecutive_failures + 1;

        let should_disable = new_failures >= MAX_CONSECUTIVE_FAILURES;

        diesel::update(webhooks.find(webhook_id))
            .set((
                consecutive_failures.eq(new_failures),
                last_failure_reason.eq(failure_reason),
                is_active.eq(if should_disable { 0 } else { 1 }),
                updated_at.eq(&now),
            ))
            .execute(conn)?;

        Ok(should_disable)
    }

    /// Reset consecutive failures on successful delivery
    pub fn record_success(webhook_id: &str, conn: &mut SqliteConnection) -> Result<()> {
        use crate::schema::webhooks::dsl::*;

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        diesel::update(webhooks.find(webhook_id))
            .set((
                consecutive_failures.eq(0),
                last_failure_reason.eq(None::<String>),
                updated_at.eq(&now),
            ))
            .execute(conn)?;

        Ok(())
    }

    /// Activate a webhook
    pub fn activate(webhook_id: &str, conn: &mut SqliteConnection) -> Result<()> {
        use crate::schema::webhooks::dsl::*;

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        diesel::update(webhooks.find(webhook_id))
            .set((
                is_active.eq(1),
                consecutive_failures.eq(0),
                updated_at.eq(&now),
            ))
            .execute(conn)?;

        Ok(())
    }

    /// Deactivate a webhook
    pub fn deactivate(webhook_id: &str, conn: &mut SqliteConnection) -> Result<()> {
        use crate::schema::webhooks::dsl::*;

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        diesel::update(webhooks.find(webhook_id))
            .set((is_active.eq(0), updated_at.eq(&now)))
            .execute(conn)?;

        Ok(())
    }

    /// Delete a webhook
    pub fn delete(webhook_id: &str, conn: &mut SqliteConnection) -> Result<()> {
        use crate::schema::webhooks::dsl::*;

        diesel::delete(webhooks.find(webhook_id)).execute(conn)?;

        Ok(())
    }

    /// Rotate webhook secret
    pub fn rotate_secret(
        webhook_id: &str,
        new_secret: &str,
        conn: &mut SqliteConnection,
    ) -> Result<()> {
        use crate::schema::webhooks::dsl::*;

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        diesel::update(webhooks.find(webhook_id))
            .set((secret.eq(new_secret), updated_at.eq(&now)))
            .execute(conn)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_serialization() {
        assert_eq!(WebhookEventType::EscrowCreated.as_str(), "escrow.created");
        assert_eq!(WebhookEventType::All.as_str(), "*");
    }

    #[test]
    fn test_event_type_deserialization() {
        assert_eq!(
            WebhookEventType::from_str("escrow.created"),
            Some(WebhookEventType::EscrowCreated)
        );
        assert_eq!(WebhookEventType::from_str("*"), Some(WebhookEventType::All));
        assert_eq!(WebhookEventType::from_str("unknown"), None);
    }

    #[test]
    fn test_is_subscribed_to() {
        let webhook = Webhook {
            id: "test".to_string(),
            api_key_id: "key".to_string(),
            url: "https://example.com".to_string(),
            secret: "secret".to_string(),
            events: "escrow.created,escrow.funded".to_string(),
            is_active: 1,
            consecutive_failures: 0,
            last_failure_reason: None,
            description: None,
            created_at: "2026-01-01".to_string(),
            updated_at: "2026-01-01".to_string(),
        };

        assert!(webhook.is_subscribed_to("escrow.created"));
        assert!(webhook.is_subscribed_to("escrow.funded"));
        assert!(!webhook.is_subscribed_to("escrow.released"));

        // Test wildcard
        let wildcard_webhook = Webhook {
            events: "*".to_string(),
            ..webhook
        };
        assert!(wildcard_webhook.is_subscribed_to("escrow.created"));
        assert!(wildcard_webhook.is_subscribed_to("anything"));
    }
}
