-- Rollback webhooks tables
DROP INDEX IF EXISTS idx_webhook_deliveries_event_type;
DROP INDEX IF EXISTS idx_webhook_deliveries_next_retry_at;
DROP INDEX IF EXISTS idx_webhook_deliveries_status;
DROP INDEX IF EXISTS idx_webhook_deliveries_webhook_id;
DROP INDEX IF EXISTS idx_webhooks_is_active;
DROP INDEX IF EXISTS idx_webhooks_api_key_id;
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhooks;
