-- API Keys table for B2B EaaS authentication
-- Stores SHA256 hashes of API keys (never plaintext)
-- Supports tiered rate limiting: Free (60/min), Pro (300/min), Enterprise (1000/min)

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    -- User who owns this API key
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Human-readable name for the key (e.g., "Production Server", "Dev Testing")
    name TEXT NOT NULL,
    -- SHA256 hash of the actual key (nxs_{uuid})
    -- CRITICAL: Never store plaintext keys
    key_hash TEXT NOT NULL UNIQUE,
    -- Truncated key for display (first 8 chars after prefix)
    key_prefix TEXT NOT NULL,
    -- Tier determines rate limits: 'free', 'pro', 'enterprise'
    tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'enterprise')),
    -- Rate limit override (requests per minute), NULL uses tier default
    rate_limit_override INTEGER,
    -- Key status
    is_active INTEGER NOT NULL DEFAULT 1,
    -- Optional expiration (NULL = never expires)
    expires_at TEXT,
    -- Audit timestamps
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    -- Usage statistics
    total_requests INTEGER NOT NULL DEFAULT 0,
    -- Optional metadata (JSON)
    metadata TEXT
);

-- Index for fast key lookup during authentication
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);

-- Index for user's keys listing
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);

-- Index for active keys lookup
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = 1;
