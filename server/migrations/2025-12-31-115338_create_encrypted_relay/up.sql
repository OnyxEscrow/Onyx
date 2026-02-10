-- Encrypted relay table for 100% non-custodial FROST signing
-- Stores opaque encrypted blobs that the server cannot read
CREATE TABLE encrypted_relay (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    encrypted_blob TEXT NOT NULL,
    first_signer_role TEXT NOT NULL,
    first_signer_pubkey TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    FOREIGN KEY (escrow_id) REFERENCES escrows(id)
);

-- Ensure only one pending relay per escrow
CREATE UNIQUE INDEX idx_relay_escrow_pending
ON encrypted_relay(escrow_id) WHERE status = 'pending';

-- Index for cleanup of expired relays
CREATE INDEX idx_relay_expires_at ON encrypted_relay(expires_at);
