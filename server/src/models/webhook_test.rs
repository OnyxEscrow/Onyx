//! Tests for webhook and webhook_delivery models

#[cfg(test)]
mod tests {
    use crate::models::webhook::{NewWebhook, Webhook, WebhookEventType, MAX_CONSECUTIVE_FAILURES};
    use crate::models::webhook_delivery::{DeliveryStatus, NewWebhookDelivery, RETRY_DELAYS, MAX_ATTEMPTS};

    #[test]
    fn test_webhook_event_types() {
        // Test serialization
        assert_eq!(WebhookEventType::EscrowCreated.as_str(), "escrow.created");
        assert_eq!(WebhookEventType::EscrowFunded.as_str(), "escrow.funded");
        assert_eq!(WebhookEventType::EscrowReleased.as_str(), "escrow.released");
        assert_eq!(WebhookEventType::EscrowDisputed.as_str(), "escrow.disputed");
        assert_eq!(WebhookEventType::All.as_str(), "*");

        // Test deserialization
        assert_eq!(
            WebhookEventType::from_str("escrow.created"),
            Some(WebhookEventType::EscrowCreated)
        );
        assert_eq!(
            WebhookEventType::from_str("payment.confirmed"),
            Some(WebhookEventType::PaymentConfirmed)
        );
        assert_eq!(WebhookEventType::from_str("invalid"), None);
    }

    #[test]
    fn test_new_webhook_creation() {
        let webhook = NewWebhook::new(
            "api_key_123".to_string(),
            "https://example.com/webhook".to_string(),
            "secret123".to_string(),
            vec![WebhookEventType::EscrowCreated, WebhookEventType::EscrowFunded],
            Some("Test webhook".to_string()),
        );

        assert!(!webhook.id.is_empty());
        assert_eq!(webhook.api_key_id, "api_key_123");
        assert_eq!(webhook.url, "https://example.com/webhook");
        assert_eq!(webhook.events, "escrow.created,escrow.funded");
        assert_eq!(webhook.is_active, 1);
        assert_eq!(webhook.consecutive_failures, 0);
    }

    #[test]
    fn test_webhook_wildcard_events() {
        let webhook = NewWebhook::new(
            "api_key_123".to_string(),
            "https://example.com/webhook".to_string(),
            "secret123".to_string(),
            vec![WebhookEventType::All],
            None,
        );

        assert_eq!(webhook.events, "*");
    }

    #[test]
    fn test_delivery_status() {
        assert_eq!(DeliveryStatus::Pending.as_str(), "pending");
        assert_eq!(DeliveryStatus::Success.as_str(), "success");
        assert_eq!(DeliveryStatus::Failed.as_str(), "failed");
        assert_eq!(DeliveryStatus::Retrying.as_str(), "retrying");

        assert_eq!(DeliveryStatus::from_str("pending"), DeliveryStatus::Pending);
        assert_eq!(DeliveryStatus::from_str("success"), DeliveryStatus::Success);
        assert_eq!(DeliveryStatus::from_str("unknown"), DeliveryStatus::Pending);
    }

    #[test]
    fn test_retry_delays() {
        // Verify retry delays match specification
        assert_eq!(RETRY_DELAYS[0], 60);      // 1 minute
        assert_eq!(RETRY_DELAYS[1], 300);     // 5 minutes
        assert_eq!(RETRY_DELAYS[2], 900);     // 15 minutes
        assert_eq!(RETRY_DELAYS[3], 3600);    // 1 hour
        assert_eq!(RETRY_DELAYS[4], 7200);    // 2 hours
    }

    #[test]
    fn test_max_attempts() {
        assert_eq!(MAX_ATTEMPTS, 6); // Initial + 5 retries
    }

    #[test]
    fn test_max_consecutive_failures() {
        assert_eq!(MAX_CONSECUTIVE_FAILURES, 5);
    }

    #[test]
    fn test_new_delivery_creation() {
        let delivery = NewWebhookDelivery::new(
            "webhook_123".to_string(),
            "escrow.funded".to_string(),
            "event_456".to_string(),
            r#"{"escrow_id":"abc"}"#.to_string(),
        );

        assert!(!delivery.id.is_empty());
        assert_eq!(delivery.webhook_id, "webhook_123");
        assert_eq!(delivery.event_type, "escrow.funded");
        assert_eq!(delivery.event_id, "event_456");
        assert_eq!(delivery.status, "pending");
        assert_eq!(delivery.attempt_count, 0);
    }
}
