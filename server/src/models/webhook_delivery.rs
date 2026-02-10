//! Webhook delivery model for tracking delivery attempts and retries
//!
//! Implements exponential backoff retry strategy:
//! Attempt 1: immediate
//! Attempt 2: +60s (1 min)
//! Attempt 3: +300s (5 min)
//! Attempt 4: +900s (15 min)
//! Attempt 5: +3600s (1 hour)
//! Attempt 6: +7200s (2 hours) - final attempt

use anyhow::Result;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::webhook_deliveries;

/// Retry delays in seconds for exponential backoff
pub const RETRY_DELAYS: [i64; 5] = [60, 300, 900, 3600, 7200];

/// Maximum retry attempts (including initial attempt)
pub const MAX_ATTEMPTS: i32 = 6;

/// Delivery status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Success,
    Failed,
    Retrying,
}

impl DeliveryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Retrying => "retrying",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "success" => Self::Success,
            "failed" => Self::Failed,
            "retrying" => Self::Retrying,
            _ => Self::Pending,
        }
    }
}

/// Webhook delivery database model
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = webhook_deliveries)]
pub struct WebhookDelivery {
    pub id: String,
    pub webhook_id: String,
    pub event_type: String,
    pub event_id: String,
    pub payload: String,
    pub status: String,
    pub http_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub error_message: Option<String>,
    pub attempt_count: i32,
    pub next_retry_at: Option<String>,
    pub created_at: String,
    pub delivered_at: Option<String>,
}

/// New webhook delivery for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = webhook_deliveries)]
pub struct NewWebhookDelivery {
    pub id: String,
    pub webhook_id: String,
    pub event_type: String,
    pub event_id: String,
    pub payload: String,
    pub status: String,
    pub attempt_count: i32,
}

impl NewWebhookDelivery {
    /// Create a new webhook delivery record
    pub fn new(webhook_id: String, event_type: String, event_id: String, payload: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            webhook_id,
            event_type,
            event_id,
            payload,
            status: DeliveryStatus::Pending.as_str().to_string(),
            attempt_count: 0,
        }
    }
}

/// API response format for webhook deliveries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDeliveryResponse {
    pub id: String,
    pub webhook_id: String,
    pub event_type: String,
    pub event_id: String,
    pub status: String,
    pub http_status_code: Option<i32>,
    pub error_message: Option<String>,
    pub attempt_count: i32,
    pub next_retry_at: Option<String>,
    pub created_at: String,
    pub delivered_at: Option<String>,
}

impl From<WebhookDelivery> for WebhookDeliveryResponse {
    fn from(d: WebhookDelivery) -> Self {
        Self {
            id: d.id,
            webhook_id: d.webhook_id,
            event_type: d.event_type,
            event_id: d.event_id,
            status: d.status,
            http_status_code: d.http_status_code,
            error_message: d.error_message,
            attempt_count: d.attempt_count,
            next_retry_at: d.next_retry_at,
            created_at: d.created_at,
            delivered_at: d.delivered_at,
        }
    }
}

impl WebhookDelivery {
    /// Find delivery by ID
    pub fn find_by_id(
        delivery_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<Option<WebhookDelivery>> {
        use crate::schema::webhook_deliveries::dsl::*;

        let result = webhook_deliveries
            .find(delivery_id)
            .first::<WebhookDelivery>(conn)
            .optional()?;

        Ok(result)
    }

    /// Get deliveries for a webhook
    pub fn get_by_webhook(
        hook_id: &str,
        limit: i64,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<WebhookDelivery>> {
        use crate::schema::webhook_deliveries::dsl::*;

        let results = webhook_deliveries
            .filter(webhook_id.eq(hook_id))
            .order(created_at.desc())
            .limit(limit)
            .load::<WebhookDelivery>(conn)?;

        Ok(results)
    }

    /// Get pending retries that are due
    pub fn get_pending_retries(conn: &mut SqliteConnection) -> Result<Vec<WebhookDelivery>> {
        use crate::schema::webhook_deliveries::dsl::*;

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let results = webhook_deliveries
            .filter(status.eq(DeliveryStatus::Retrying.as_str()))
            .filter(next_retry_at.le(&now))
            .order(next_retry_at.asc())
            .load::<WebhookDelivery>(conn)?;

        Ok(results)
    }

    /// Create a new delivery record
    pub fn create(
        new_delivery: NewWebhookDelivery,
        conn: &mut SqliteConnection,
    ) -> Result<WebhookDelivery> {
        use crate::schema::webhook_deliveries::dsl::*;

        diesel::insert_into(webhook_deliveries)
            .values(&new_delivery)
            .execute(conn)?;

        let delivery = webhook_deliveries
            .find(&new_delivery.id)
            .first::<WebhookDelivery>(conn)?;

        Ok(delivery)
    }

    /// Mark delivery as successful
    pub fn mark_success(
        delivery_id: &str,
        status_code: i32,
        response: Option<&str>,
        conn: &mut SqliteConnection,
    ) -> Result<()> {
        use crate::schema::webhook_deliveries::dsl::*;

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        diesel::update(webhook_deliveries.find(delivery_id))
            .set((
                status.eq(DeliveryStatus::Success.as_str()),
                http_status_code.eq(status_code),
                response_body.eq(response),
                delivered_at.eq(&now),
                next_retry_at.eq(None::<String>),
            ))
            .execute(conn)?;

        Ok(())
    }

    /// Mark delivery as failed with retry scheduling
    /// Returns true if this was the final attempt (no more retries)
    pub fn mark_failed(
        delivery_id: &str,
        status_code: Option<i32>,
        error_msg: &str,
        conn: &mut SqliteConnection,
    ) -> Result<bool> {
        use crate::schema::webhook_deliveries::dsl::*;

        // Get current attempt count
        let current: WebhookDelivery = webhook_deliveries.find(delivery_id).first(conn)?;
        let new_attempt_count = current.attempt_count + 1;

        let is_final = new_attempt_count >= MAX_ATTEMPTS;

        if is_final {
            // Final failure - no more retries
            diesel::update(webhook_deliveries.find(delivery_id))
                .set((
                    status.eq(DeliveryStatus::Failed.as_str()),
                    http_status_code.eq(status_code),
                    error_message.eq(error_msg),
                    attempt_count.eq(new_attempt_count),
                    next_retry_at.eq(None::<String>),
                ))
                .execute(conn)?;
        } else {
            // Schedule retry with exponential backoff
            let retry_delay = RETRY_DELAYS[(new_attempt_count - 1) as usize];
            let retry_time = chrono::Utc::now() + chrono::Duration::seconds(retry_delay);
            let retry_at = retry_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();

            diesel::update(webhook_deliveries.find(delivery_id))
                .set((
                    status.eq(DeliveryStatus::Retrying.as_str()),
                    http_status_code.eq(status_code),
                    error_message.eq(error_msg),
                    attempt_count.eq(new_attempt_count),
                    next_retry_at.eq(&retry_at),
                ))
                .execute(conn)?;
        }

        Ok(is_final)
    }

    /// Delete old successful deliveries (keep last N per webhook)
    pub fn cleanup_old_deliveries(
        hook_id: &str,
        keep_count: i64,
        conn: &mut SqliteConnection,
    ) -> Result<usize> {
        use crate::schema::webhook_deliveries::dsl::*;

        // Get IDs to keep (most recent successful ones)
        let ids_to_keep: Vec<String> = webhook_deliveries
            .filter(webhook_id.eq(hook_id))
            .filter(status.eq(DeliveryStatus::Success.as_str()))
            .order(created_at.desc())
            .limit(keep_count)
            .select(id)
            .load(conn)?;

        // Delete the rest of successful deliveries
        let deleted = diesel::delete(
            webhook_deliveries
                .filter(webhook_id.eq(hook_id))
                .filter(status.eq(DeliveryStatus::Success.as_str()))
                .filter(id.ne_all(&ids_to_keep)),
        )
        .execute(conn)?;

        Ok(deleted)
    }

    /// Get delivery statistics for a webhook
    pub fn get_stats(hook_id: &str, conn: &mut SqliteConnection) -> Result<WebhookDeliveryStats> {
        use crate::schema::webhook_deliveries::dsl::*;

        let total: i64 = webhook_deliveries
            .filter(webhook_id.eq(hook_id))
            .count()
            .get_result(conn)?;

        let successful: i64 = webhook_deliveries
            .filter(webhook_id.eq(hook_id))
            .filter(status.eq(DeliveryStatus::Success.as_str()))
            .count()
            .get_result(conn)?;

        let failed: i64 = webhook_deliveries
            .filter(webhook_id.eq(hook_id))
            .filter(status.eq(DeliveryStatus::Failed.as_str()))
            .count()
            .get_result(conn)?;

        let pending: i64 = webhook_deliveries
            .filter(webhook_id.eq(hook_id))
            .filter(status.eq_any(&[
                DeliveryStatus::Pending.as_str(),
                DeliveryStatus::Retrying.as_str(),
            ]))
            .count()
            .get_result(conn)?;

        Ok(WebhookDeliveryStats {
            total_deliveries: total,
            successful,
            failed,
            pending,
        })
    }
}

/// Statistics for webhook deliveries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDeliveryStats {
    pub total_deliveries: i64,
    pub successful: i64,
    pub failed: i64,
    pub pending: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delivery_status_serialization() {
        assert_eq!(DeliveryStatus::Pending.as_str(), "pending");
        assert_eq!(DeliveryStatus::Success.as_str(), "success");
        assert_eq!(DeliveryStatus::Failed.as_str(), "failed");
        assert_eq!(DeliveryStatus::Retrying.as_str(), "retrying");
    }

    #[test]
    fn test_delivery_status_deserialization() {
        assert_eq!(DeliveryStatus::from_str("pending"), DeliveryStatus::Pending);
        assert_eq!(DeliveryStatus::from_str("success"), DeliveryStatus::Success);
        assert_eq!(DeliveryStatus::from_str("failed"), DeliveryStatus::Failed);
        assert_eq!(
            DeliveryStatus::from_str("retrying"),
            DeliveryStatus::Retrying
        );
        assert_eq!(DeliveryStatus::from_str("unknown"), DeliveryStatus::Pending);
    }

    #[test]
    fn test_retry_delays() {
        assert_eq!(RETRY_DELAYS[0], 60); // 1 min
        assert_eq!(RETRY_DELAYS[1], 300); // 5 min
        assert_eq!(RETRY_DELAYS[2], 900); // 15 min
        assert_eq!(RETRY_DELAYS[3], 3600); // 1 hour
        assert_eq!(RETRY_DELAYS[4], 7200); // 2 hours
    }
}
