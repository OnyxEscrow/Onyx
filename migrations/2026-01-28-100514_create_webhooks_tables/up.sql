-- Webhooks System for B2B EaaS Integration
-- Supports: event subscriptions, HMAC-SHA256 signatures, retry logic with exponential backoff

-- Webhook endpoint registrations
CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY NOT NULL,
    -- Owner identification (API key holder)
    api_key_id TEXT NOT NULL,
    -- Webhook configuration
    url TEXT NOT NULL,
    secret TEXT NOT NULL,  -- HMAC-SHA256 secret (encrypted at rest)
    -- Event subscription (comma-separated list or '*' for all)
    events TEXT NOT NULL DEFAULT '*',
    -- Status tracking
    is_active INTEGER NOT NULL DEFAULT 1,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_failure_reason TEXT,
    -- Metadata
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- Foreign key (if api_keys table exists, add constraint)
    UNIQUE(api_key_id, url)
);

-- Webhook delivery attempts and history
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY NOT NULL,
    webhook_id TEXT NOT NULL,
    -- Event information
    event_type TEXT NOT NULL,
    event_id TEXT NOT NULL,  -- Unique event ID for idempotency
    payload TEXT NOT NULL,   -- JSON payload sent
    -- Delivery status
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, success, failed, retrying
    -- HTTP response details
    http_status_code INTEGER,
    response_body TEXT,
    error_message TEXT,
    -- Retry tracking
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT,  -- NULL if no retry scheduled
    -- Timing
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    delivered_at TEXT,
    -- Foreign key
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);

-- Indices for efficient queries
CREATE INDEX IF NOT EXISTS idx_webhooks_api_key_id ON webhooks(api_key_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_is_active ON webhooks(is_active);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_next_retry_at ON webhook_deliveries(next_retry_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_event_type ON webhook_deliveries(event_type);
