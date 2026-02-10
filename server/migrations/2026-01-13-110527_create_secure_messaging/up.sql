-- Secure E2E Encrypted Messaging System
-- Tables already exist - making migration idempotent

CREATE TABLE IF NOT EXISTS message_keypairs (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    key_salt TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    is_active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_message_keypairs_user ON message_keypairs(user_id);

CREATE TABLE IF NOT EXISTS secure_messages (
    id TEXT PRIMARY KEY NOT NULL,
    conversation_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    nonce TEXT NOT NULL,
    sender_ephemeral_pubkey TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    is_deleted_by_sender INTEGER NOT NULL DEFAULT 0,
    is_deleted_by_recipient INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_secure_messages_conversation ON secure_messages(conversation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secure_messages_recipient ON secure_messages(recipient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secure_messages_sender ON secure_messages(sender_id, created_at DESC);

CREATE TABLE IF NOT EXISTS message_read_receipts (
    message_id TEXT PRIMARY KEY NOT NULL,
    read_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (message_id) REFERENCES secure_messages(id) ON DELETE CASCADE
);
