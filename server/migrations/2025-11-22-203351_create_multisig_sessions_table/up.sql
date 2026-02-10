-- Multisig Sessions Table
-- Stores coordination state for non-custodial multisig setup
CREATE TABLE multisig_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL UNIQUE,
    stage TEXT NOT NULL CHECK(stage IN ('initialization', 'round1_complete', 'key_exchange', 'ready', 'signing')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    timeout_at INTEGER, -- Unix timestamp when session expires
    multisig_address TEXT, -- Final multisig address (populated when stage = 'ready')

    FOREIGN KEY (escrow_id) REFERENCES escrows(id) ON DELETE CASCADE
);

-- Multisig Participants Table
-- Tracks individual participant state within a session
CREATE TABLE multisig_participants (
    id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('buyer', 'vendor', 'arbiter')),
    participant_type TEXT NOT NULL CHECK(participant_type IN ('local_managed', 'remote')),

    -- Participant identifiers
    wallet_id TEXT, -- UUID for LocalManaged participants
    user_id TEXT, -- User ID for Remote participants

    -- Submission tracking
    has_submitted_round1 BOOLEAN NOT NULL DEFAULT 0,
    has_submitted_round2 BOOLEAN NOT NULL DEFAULT 0,

    -- Cryptographic data (encrypted blobs)
    public_spend_key TEXT, -- For identity verification
    multisig_info_round1 TEXT, -- Blob from prepare_multisig
    multisig_info_round2 TEXT, -- Blob from export_multisig_info

    submitted_at_round1 INTEGER, -- Timestamp of Round 1 submission
    submitted_at_round2 INTEGER, -- Timestamp of Round 2 submission

    FOREIGN KEY (session_id) REFERENCES multisig_sessions(id) ON DELETE CASCADE,
    UNIQUE(session_id, role) -- Each role appears once per session
);

-- Indexes for performance
CREATE INDEX idx_multisig_sessions_escrow ON multisig_sessions(escrow_id);
CREATE INDEX idx_multisig_sessions_stage ON multisig_sessions(stage);
CREATE INDEX idx_multisig_sessions_timeout ON multisig_sessions(timeout_at);
CREATE INDEX idx_multisig_participants_session ON multisig_participants(session_id);
CREATE INDEX idx_multisig_participants_user ON multisig_participants(user_id);
