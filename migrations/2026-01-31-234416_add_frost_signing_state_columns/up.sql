-- Add FROST signing state columns to escrows table
-- These columns are required for the 2-of-3 threshold signing workflow

-- Round-robin signing coordination (non-custodial)
ALTER TABLE escrows ADD COLUMN multisig_txset TEXT;
ALTER TABLE escrows ADD COLUMN partial_signed_txset TEXT;
ALTER TABLE escrows ADD COLUMN current_signer_id TEXT;

-- Signing coordination
ALTER TABLE escrows ADD COLUMN first_signer_role TEXT;
ALTER TABLE escrows ADD COLUMN dispute_signing_pair TEXT;
ALTER TABLE escrows ADD COLUMN evidence_count INTEGER NOT NULL DEFAULT 0;

-- MuSig2 challenge coefficients for CLSAG aggregation
ALTER TABLE escrows ADD COLUMN mu_p TEXT;
ALTER TABLE escrows ADD COLUMN mu_c TEXT;

-- Nonce commitments and public nonces (per-party)
ALTER TABLE escrows ADD COLUMN vendor_nonce_commitment TEXT;
ALTER TABLE escrows ADD COLUMN buyer_nonce_commitment TEXT;
ALTER TABLE escrows ADD COLUMN arbiter_nonce_commitment TEXT;
ALTER TABLE escrows ADD COLUMN vendor_nonce_public TEXT;
ALTER TABLE escrows ADD COLUMN buyer_nonce_public TEXT;
ALTER TABLE escrows ADD COLUMN arbiter_nonce_public TEXT;

-- Aggregated nonce and state flags
ALTER TABLE escrows ADD COLUMN nonce_aggregated TEXT;
ALTER TABLE escrows ADD COLUMN first_signer_had_r_agg INTEGER NOT NULL DEFAULT 0;

-- Broadcast tracking
ALTER TABLE escrows ADD COLUMN broadcast_tx_hash TEXT;
ALTER TABLE escrows ADD COLUMN broadcast_at INTEGER;

-- Signing round tracking for FROST
ALTER TABLE escrows ADD COLUMN signing_round INTEGER NOT NULL DEFAULT 0;
ALTER TABLE escrows ADD COLUMN signing_nonce_round INTEGER NOT NULL DEFAULT 0;

-- Dispute auto-escalation tracking
ALTER TABLE escrows ADD COLUMN auto_escalated_at TIMESTAMP;
ALTER TABLE escrows ADD COLUMN escalation_reason TEXT;

-- Create dispute_evidence table (IPFS-based evidence for disputes)
CREATE TABLE IF NOT EXISTS dispute_evidence (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL REFERENCES escrows(id),
    uploader_id TEXT NOT NULL REFERENCES users(id),
    uploader_role TEXT NOT NULL,
    ipfs_cid TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_dispute_evidence_escrow ON dispute_evidence(escrow_id);

-- Create encrypted_relay table (for FROST signing blind relay)
CREATE TABLE IF NOT EXISTS encrypted_relay (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL REFERENCES escrows(id),
    encrypted_blob TEXT NOT NULL,
    first_signer_role TEXT NOT NULL,
    first_signer_pubkey TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_encrypted_relay_escrow ON encrypted_relay(escrow_id);
CREATE INDEX IF NOT EXISTS idx_encrypted_relay_status ON encrypted_relay(escrow_id, status);

-- Create frost_dkg_state table (tracks 3-round DKG protocol)
-- One row per escrow, columns for each party's packages
CREATE TABLE IF NOT EXISTS frost_dkg_state (
    escrow_id TEXT PRIMARY KEY NOT NULL REFERENCES escrows(id),

    -- Round 1 packages (public commitments from each party)
    buyer_round1_package TEXT,
    vendor_round1_package TEXT,
    arbiter_round1_package TEXT,
    round1_complete INTEGER NOT NULL DEFAULT 0,

    -- Round 2 packages (secret shares sent between parties)
    buyer_to_vendor_round2 TEXT,
    buyer_to_arbiter_round2 TEXT,
    vendor_to_buyer_round2 TEXT,
    vendor_to_arbiter_round2 TEXT,
    arbiter_to_buyer_round2 TEXT,
    arbiter_to_vendor_round2 TEXT,
    round2_complete INTEGER NOT NULL DEFAULT 0,

    -- Timestamps
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Create login_attempts table (per-username brute-force protection)
CREATE TABLE IF NOT EXISTS login_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL,
    ip_address TEXT,
    attempt_type TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(created_at);

-- Create notifications table (persistent user notifications)
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    notification_type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    link TEXT,
    data TEXT,
    read INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(user_id, read);

-- Create recovery_codes table (2FA backup codes)
CREATE TABLE IF NOT EXISTS recovery_codes (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    code_hash TEXT NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id);
