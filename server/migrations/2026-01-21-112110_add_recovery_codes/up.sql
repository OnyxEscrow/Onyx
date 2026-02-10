-- P0 Security: High-entropy one-time recovery codes
-- Each user gets 10 codes at registration, each can only be used once

CREATE TABLE recovery_codes (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Store hashed code (Argon2id), NOT plaintext
    code_hash TEXT NOT NULL,
    -- Track usage - NULL means unused
    used_at TIMESTAMP NULL,
    -- Track creation for audit
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Unique constraint: each code hash must be unique per user
    UNIQUE(user_id, code_hash)
);

-- Index for quick lookup during recovery
CREATE INDEX idx_recovery_codes_user_id ON recovery_codes(user_id);
-- Index to find unused codes
CREATE INDEX idx_recovery_codes_unused ON recovery_codes(user_id, used_at) WHERE used_at IS NULL;
