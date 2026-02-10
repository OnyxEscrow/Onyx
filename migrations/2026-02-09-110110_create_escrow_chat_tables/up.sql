-- Escrow E2EE Chat: 3 tables for X25519 key exchange + encrypted group messaging

-- 1. Keypair registry: each participant registers their X25519 public key per escrow
CREATE TABLE escrow_chat_keypairs (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL REFERENCES escrows(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    role TEXT NOT NULL CHECK(role IN ('buyer', 'vendor', 'arbiter')),
    public_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(escrow_id, user_id),
    UNIQUE(escrow_id, role)
);

-- 2. Encrypted messages: 3 ciphertexts per message (one per participant)
CREATE TABLE secure_escrow_messages (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL REFERENCES escrows(id),
    sender_id TEXT NOT NULL,
    sender_role TEXT NOT NULL,
    encrypted_content_buyer TEXT NOT NULL,
    encrypted_content_vendor TEXT NOT NULL,
    encrypted_content_arbiter TEXT NOT NULL,
    sender_ephemeral_pubkey TEXT NOT NULL,
    nonce TEXT NOT NULL,
    frost_signature TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_secure_escrow_messages_escrow ON secure_escrow_messages(escrow_id);
CREATE INDEX idx_secure_escrow_messages_created ON secure_escrow_messages(escrow_id, created_at DESC);

-- 3. Read receipts per user per message
CREATE TABLE escrow_chat_read_receipts (
    id TEXT PRIMARY KEY NOT NULL,
    message_id TEXT NOT NULL REFERENCES secure_escrow_messages(id),
    user_id TEXT NOT NULL,
    read_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(message_id, user_id)
);
