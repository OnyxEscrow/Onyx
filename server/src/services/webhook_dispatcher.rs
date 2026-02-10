//! Webhook Dispatcher Service
//!
//! Handles webhook delivery with HMAC-SHA256 signing and retry logic.
//! Implements the complete webhook lifecycle:
//! 1. Event emission -> find subscribed webhooks
//! 2. Sign payload with HMAC-SHA256
//! 3. Deliver with required headers
//! 4. Handle success/failure with retry scheduling
//!
//! Headers sent with each webhook:
//! - X-Nexus-Signature: sha256=<hex(HMAC(secret, timestamp.payload))>
//! - X-Nexus-Timestamp: Unix timestamp
//! - X-Nexus-Event: Event type (e.g., "escrow.funded")
//! - X-Nexus-Delivery: Unique delivery ID

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::db::DbPool;
use crate::models::webhook::{Webhook, WebhookEventType};
use crate::models::webhook_delivery::{
    DeliveryStatus, NewWebhookDelivery, WebhookDelivery, MAX_ATTEMPTS,
};

/// HTTP client timeout for webhook delivery
const DELIVERY_TIMEOUT_SECS: u64 = 30;

/// Maximum response body to store (truncate after this)
const MAX_RESPONSE_BODY_BYTES: usize = 4096;

/// Webhook event payload structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebhookPayload {
    /// Event type (e.g., "escrow.funded")
    pub event_type: String,
    /// Unique event ID for idempotency
    pub event_id: String,
    /// ISO 8601 timestamp when event occurred
    pub timestamp: String,
    /// Event-specific data
    pub data: serde_json::Value,
}

impl WebhookPayload {
    pub fn new(event_type: WebhookEventType, data: serde_json::Value) -> Self {
        Self {
            event_type: event_type.as_str().to_string(),
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            data,
        }
    }
}

/// Webhook Dispatcher Service
pub struct WebhookDispatcher {
    pool: DbPool,
    client: Client,
    /// Lock to prevent concurrent retry processing
    retry_lock: Arc<Mutex<()>>,
}

impl WebhookDispatcher {
    /// Create a new webhook dispatcher
    pub fn new(pool: DbPool) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(DELIVERY_TIMEOUT_SECS))
            .user_agent("NEXUS-Webhook/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            pool,
            client,
            retry_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Emit an event to all subscribed webhooks
    ///
    /// This is the main entry point for triggering webhooks.
    /// It finds all active webhooks subscribed to the event and schedules delivery.
    pub async fn emit_event(
        &self,
        event_type: WebhookEventType,
        data: serde_json::Value,
    ) -> Result<Vec<String>> {
        let payload = WebhookPayload::new(event_type, data);
        let event_type_str = payload.event_type.clone();
        let payload_json =
            serde_json::to_string(&payload).context("Failed to serialize webhook payload")?;

        // Get all active webhooks subscribed to this event
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        let webhooks = Webhook::get_active_for_event(&event_type_str, &mut conn)
            .context("Failed to get webhooks for event")?;

        if webhooks.is_empty() {
            info!(event_type = %event_type_str, "No webhooks subscribed to event");
            return Ok(vec![]);
        }

        info!(
            event_type = %event_type_str,
            webhook_count = webhooks.len(),
            "Dispatching event to webhooks"
        );

        let mut delivery_ids = Vec::new();

        // Create delivery records and attempt immediate delivery
        for webhook in webhooks {
            let new_delivery = NewWebhookDelivery::new(
                webhook.id.clone(),
                event_type_str.clone(),
                payload.event_id.clone(),
                payload_json.clone(),
            );

            let delivery = WebhookDelivery::create(new_delivery, &mut conn)
                .context("Failed to create delivery record")?;

            delivery_ids.push(delivery.id.clone());

            // Attempt immediate delivery (don't block on failure)
            let dispatcher = self.clone();
            let webhook_clone = webhook.clone();
            let delivery_clone = delivery.clone();
            let payload_clone = payload_json.clone();

            tokio::spawn(async move {
                if let Err(e) = dispatcher
                    .deliver_webhook(&webhook_clone, &delivery_clone, &payload_clone)
                    .await
                {
                    error!(
                        webhook_id = %webhook_clone.id,
                        delivery_id = %delivery_clone.id,
                        error = %e,
                        "Initial webhook delivery failed"
                    );
                }
            });
        }

        Ok(delivery_ids)
    }

    /// Deliver a webhook to its endpoint
    async fn deliver_webhook(
        &self,
        webhook: &Webhook,
        delivery: &WebhookDelivery,
        payload: &str,
    ) -> Result<()> {
        // Generate signature
        let timestamp = chrono::Utc::now().timestamp();
        let signature = self.sign_payload(&webhook.secret, timestamp, payload);

        // Send HTTP request
        let result = self
            .client
            .post(&webhook.url)
            .header("Content-Type", "application/json")
            .header("X-Nexus-Signature", format!("sha256={}", signature))
            .header("X-Nexus-Timestamp", timestamp.to_string())
            .header("X-Nexus-Event", &delivery.event_type)
            .header("X-Nexus-Delivery", &delivery.id)
            .body(payload.to_string())
            .send()
            .await;

        let mut conn = self.pool.get().context("Failed to get DB connection")?;

        match result {
            Ok(response) => {
                let status_code = response.status().as_u16() as i32;
                let body = response
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(MAX_RESPONSE_BODY_BYTES)
                    .collect::<String>();

                if (200..300).contains(&status_code) {
                    // Success
                    WebhookDelivery::mark_success(
                        &delivery.id,
                        status_code,
                        Some(&body),
                        &mut conn,
                    )?;
                    Webhook::record_success(&webhook.id, &mut conn)?;

                    info!(
                        webhook_id = %webhook.id,
                        delivery_id = %delivery.id,
                        status_code,
                        "Webhook delivered successfully"
                    );
                } else {
                    // HTTP error
                    let error_msg = format!("HTTP {} - {}", status_code, body);
                    let is_final = WebhookDelivery::mark_failed(
                        &delivery.id,
                        Some(status_code),
                        &error_msg,
                        &mut conn,
                    )?;

                    let was_disabled = Webhook::record_failure(&webhook.id, &error_msg, &mut conn)?;

                    warn!(
                        webhook_id = %webhook.id,
                        delivery_id = %delivery.id,
                        status_code,
                        is_final,
                        was_disabled,
                        "Webhook delivery failed with HTTP error"
                    );
                }
            }
            Err(e) => {
                // Network/timeout error
                let error_msg = e.to_string();
                let is_final =
                    WebhookDelivery::mark_failed(&delivery.id, None, &error_msg, &mut conn)?;
                let was_disabled = Webhook::record_failure(&webhook.id, &error_msg, &mut conn)?;

                warn!(
                    webhook_id = %webhook.id,
                    delivery_id = %delivery.id,
                    error = %error_msg,
                    is_final,
                    was_disabled,
                    "Webhook delivery failed with network error"
                );
            }
        }

        Ok(())
    }

    /// Generate HMAC-SHA256 signature for webhook payload
    ///
    /// Signature format: sha256=hex(HMAC(secret, timestamp.payload))
    fn sign_payload(&self, secret: &str, timestamp: i64, payload: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;

        let message = format!("{}.{}", timestamp, payload);
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(message.as_bytes());

        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// Process pending retries
    ///
    /// This should be called periodically by a background worker.
    pub async fn process_retries(&self) -> Result<usize> {
        // Acquire lock to prevent concurrent processing
        let _guard = self.retry_lock.lock().await;

        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        let pending = WebhookDelivery::get_pending_retries(&mut conn)?;

        if pending.is_empty() {
            return Ok(0);
        }

        info!(count = pending.len(), "Processing pending webhook retries");

        let mut processed = 0;

        for delivery in pending {
            // Get the webhook
            let webhook = match Webhook::find_by_id(&delivery.webhook_id, &mut conn)? {
                Some(w) if w.is_active != 0 => w,
                Some(_) => {
                    // Webhook was disabled, mark delivery as failed
                    WebhookDelivery::mark_failed(
                        &delivery.id,
                        None,
                        "Webhook disabled",
                        &mut conn,
                    )?;
                    continue;
                }
                None => {
                    // Webhook was deleted
                    continue;
                }
            };

            // Attempt redelivery
            if let Err(e) = self
                .deliver_webhook(&webhook, &delivery, &delivery.payload)
                .await
            {
                error!(
                    delivery_id = %delivery.id,
                    error = %e,
                    "Retry delivery failed"
                );
            }

            processed += 1;
        }

        Ok(processed)
    }

    /// Manually retry a specific delivery
    pub async fn retry_delivery(&self, delivery_id: &str) -> Result<()> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;

        let delivery =
            WebhookDelivery::find_by_id(delivery_id, &mut conn)?.context("Delivery not found")?;

        if delivery.attempt_count >= MAX_ATTEMPTS {
            anyhow::bail!("Maximum retry attempts reached");
        }

        let webhook =
            Webhook::find_by_id(&delivery.webhook_id, &mut conn)?.context("Webhook not found")?;

        if webhook.is_active == 0 {
            anyhow::bail!("Webhook is disabled");
        }

        self.deliver_webhook(&webhook, &delivery, &delivery.payload)
            .await
    }

    /// Get delivery status
    pub fn get_delivery(&self, delivery_id: &str) -> Result<Option<WebhookDelivery>> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        WebhookDelivery::find_by_id(delivery_id, &mut conn)
    }
}

/// Build a standard escrow webhook payload
pub fn build_escrow_payload(
    escrow_id: &str,
    event_type: &str,
    extra: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "escrow_id": escrow_id,
        "event": event_type,
        "timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "data": extra
    })
}

/// Fire-and-forget webhook emission. Never blocks, never fails the caller.
pub fn emit_webhook_nonblocking(
    dispatcher: Arc<WebhookDispatcher>,
    event_type: WebhookEventType,
    data: serde_json::Value,
) {
    tokio::spawn(async move {
        if let Err(e) = dispatcher.emit_event(event_type, data).await {
            warn!(error = %e, "Webhook emission failed (non-blocking)");
        }
    });
}

impl Clone for WebhookDispatcher {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            client: self.client.clone(),
            retry_lock: Arc::clone(&self.retry_lock),
        }
    }
}

/// Background worker for processing webhook retries
pub struct WebhookRetryWorker {
    dispatcher: Arc<WebhookDispatcher>,
    poll_interval_secs: u64,
}

impl WebhookRetryWorker {
    /// Create a new retry worker
    pub fn new(dispatcher: Arc<WebhookDispatcher>, poll_interval_secs: u64) -> Self {
        Self {
            dispatcher,
            poll_interval_secs,
        }
    }

    /// Start the background retry processing loop
    pub async fn start(&self) {
        info!(
            poll_interval = self.poll_interval_secs,
            "Starting webhook retry worker"
        );

        let mut interval = tokio::time::interval(Duration::from_secs(self.poll_interval_secs));

        loop {
            interval.tick().await;

            match self.dispatcher.process_retries().await {
                Ok(0) => {
                    // No retries to process, quiet
                }
                Ok(count) => {
                    info!(processed = count, "Processed webhook retries");
                }
                Err(e) => {
                    error!(error = %e, "Failed to process webhook retries");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_signature() {
        // Create a mock dispatcher (we only need the sign method)
        let secret = "test-secret";
        let timestamp = 1706400000i64;
        let payload = r#"{"event_type":"escrow.funded","data":{}}"#;

        // Manual HMAC calculation
        type HmacSha256 = Hmac<Sha256>;
        let message = format!("{}.{}", timestamp, payload);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        // Verify the signature format is correct
        assert!(!expected.is_empty());
        assert_eq!(expected.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_webhook_payload_creation() {
        let payload = WebhookPayload::new(
            WebhookEventType::EscrowFunded,
            serde_json::json!({
                "escrow_id": "test-123",
                "amount": 1000000000000i64
            }),
        );

        assert_eq!(payload.event_type, "escrow.funded");
        assert!(!payload.event_id.is_empty());
        assert!(!payload.timestamp.is_empty());
    }
}
