-- E2E Encrypted Messaging Tables for NEXUS
-- Per-recipient encryption using X25519 ECDH + ChaCha20Poly1305

-- User messaging keypairs (X25519)
CREATE TABLE IF NOT EXISTS message_keypairs (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    key_salt TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    is_active INTEGER NOT NULL DEFAULT 1,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for keypair lookups
CREATE INDEX IF NOT EXISTS idx_message_keypairs_user ON message_keypairs(user_id);
CREATE INDEX IF NOT EXISTS idx_message_keypairs_user_active ON message_keypairs(user_id, is_active);

-- E2E encrypted messages (server is blind relay)
CREATE TABLE IF NOT EXISTS secure_messages (
    id TEXT PRIMARY KEY NOT NULL,
    conversation_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    nonce TEXT NOT NULL,
    sender_ephemeral_pubkey TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    expires_at TEXT,
    is_deleted_by_sender INTEGER NOT NULL DEFAULT 0,
    is_deleted_by_recipient INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for message queries
CREATE INDEX IF NOT EXISTS idx_secure_messages_conversation ON secure_messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_secure_messages_sender ON secure_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_secure_messages_recipient ON secure_messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_secure_messages_created ON secure_messages(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secure_messages_expires ON secure_messages(expires_at) WHERE expires_at IS NOT NULL;

-- Read receipts for messages
CREATE TABLE IF NOT EXISTS message_read_receipts (
    message_id TEXT PRIMARY KEY NOT NULL,
    read_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),

    FOREIGN KEY (message_id) REFERENCES secure_messages(id) ON DELETE CASCADE
);

-- Escrow-specific group messaging (3-way E2EE)
-- Each message is encrypted separately for each participant
CREATE TABLE IF NOT EXISTS escrow_messages (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_role TEXT NOT NULL CHECK(sender_role IN ('buyer', 'vendor', 'arbiter')),

    -- Per-recipient encryption (3 copies of same plaintext)
    encrypted_content_buyer TEXT NOT NULL,
    encrypted_content_vendor TEXT NOT NULL,
    encrypted_content_arbiter TEXT NOT NULL,

    -- Sender's ephemeral key for this message (used with each recipient's pubkey)
    sender_ephemeral_pubkey TEXT NOT NULL,
    nonce TEXT NOT NULL,

    -- Optional FROST signature for non-repudiation
    frost_signature TEXT,

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),

    -- Soft delete per participant
    is_deleted_by_buyer INTEGER NOT NULL DEFAULT 0,
    is_deleted_by_vendor INTEGER NOT NULL DEFAULT 0,
    is_deleted_by_arbiter INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (escrow_id) REFERENCES escrows(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for escrow message queries
CREATE INDEX IF NOT EXISTS idx_escrow_messages_escrow ON escrow_messages(escrow_id);
CREATE INDEX IF NOT EXISTS idx_escrow_messages_sender ON escrow_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_escrow_messages_created ON escrow_messages(created_at DESC);

-- Escrow messaging keypairs (X25519 per-escrow)
CREATE TABLE IF NOT EXISTS escrow_message_keypairs (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('buyer', 'vendor', 'arbiter')),
    public_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),

    FOREIGN KEY (escrow_id) REFERENCES escrows(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(escrow_id, user_id)
);

-- Indexes for escrow keypair lookups
CREATE INDEX IF NOT EXISTS idx_escrow_message_keypairs_escrow ON escrow_message_keypairs(escrow_id);
CREATE INDEX IF NOT EXISTS idx_escrow_message_keypairs_user ON escrow_message_keypairs(user_id);

-- Escrow message read receipts
CREATE TABLE IF NOT EXISTS escrow_message_read_receipts (
    id TEXT PRIMARY KEY NOT NULL,
    message_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    read_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),

    FOREIGN KEY (message_id) REFERENCES escrow_messages(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(message_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_escrow_read_receipts_message ON escrow_message_read_receipts(message_id);
CREATE INDEX IF NOT EXISTS idx_escrow_read_receipts_user ON escrow_message_read_receipts(user_id);
