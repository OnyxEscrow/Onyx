-- Add wallet_address_history table for audit trail
CREATE TABLE wallet_address_history (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    old_address TEXT,
    new_address TEXT NOT NULL,
    changed_at INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for fast user lookups
CREATE INDEX idx_wallet_history_user_id ON wallet_address_history(user_id);
CREATE INDEX idx_wallet_history_changed_at ON wallet_address_history(changed_at DESC);
