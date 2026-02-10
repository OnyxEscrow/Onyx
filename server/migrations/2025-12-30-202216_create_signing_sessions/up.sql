-- Atomic Signing Sessions for FROST 2-of-3 Threshold Signatures
-- Mirrors full_offline_broadcast.rs flow exactly
-- All ephemeral data stored together, used together, deleted together

CREATE TABLE signing_sessions (
    -- Primary key: random UUID for session isolation
    session_id TEXT PRIMARY KEY NOT NULL,

    -- Foreign key to escrow being signed
    escrow_id TEXT NOT NULL,

    -- Ephemeral secrets (AES-256-GCM encrypted with DB_ENCRYPTION_KEY)
    -- These MUST be generated ONCE and reused throughout the session
    tx_secret_key_encrypted TEXT NOT NULL,      -- r: random scalar for tx outputs

    -- Derived parameters (computed ONCE from tx_secret_key)
    tx_pubkey TEXT NOT NULL,                    -- R = r*G (32 bytes hex)
    derivation TEXT NOT NULL,                   -- d = Hs(8*v*R || varint(idx)) (32 bytes hex)
    output_mask TEXT NOT NULL,                  -- mask for output commitment
    pseudo_out_mask TEXT NOT NULL,              -- mask for pseudo output
    mask_delta TEXT NOT NULL,                   -- pseudo_out_mask - output_mask (mod L)

    -- Ring data (fetched ONCE from daemon)
    ring_data_json TEXT NOT NULL,               -- Full ring with decoys
    real_ring_index INTEGER NOT NULL,           -- Index of real output in ring

    -- Expected values for validation (computed from funding transaction)
    expected_one_time_pubkey TEXT NOT NULL,     -- P = Hs(d)*G + B (stealth address)
    expected_key_image TEXT NOT NULL,           -- KI = x*Hp(P) where x = d + sum(λᵢbᵢ)

    -- Transaction hashes (computed ONCE with BulletproofPlus)
    tx_prefix_hash TEXT NOT NULL,               -- H(tx_prefix) - 32 bytes hex
    clsag_message TEXT NOT NULL,                -- H(tx_prefix || ss_hash || bp_hash) - FULL message!

    -- BulletproofPlus data (generated ONCE, reused for broadcast)
    bulletproof_plus_json TEXT NOT NULL,        -- Serialized BP+ proof

    -- Destination addresses (for output construction)
    dest_spend_pubkey TEXT NOT NULL,            -- Recipient's spend public key
    dest_view_pubkey TEXT NOT NULL,             -- Recipient's view public key

    -- Funding input data
    funding_tx_hash TEXT NOT NULL,              -- Hash of funding transaction
    funding_output_index INTEGER NOT NULL,      -- Output index in funding tx
    funding_amount INTEGER NOT NULL,            -- Amount in atomic units

    -- Output data
    output_commitment TEXT NOT NULL,            -- C = mask*G + amount*H
    pseudo_out TEXT NOT NULL,                   -- C' for input commitment

    -- Signature collection state
    buyer_partial_sig TEXT,                     -- Buyer's CLSAG partial (when submitted)
    vendor_partial_sig TEXT,                    -- Vendor's CLSAG partial (when submitted)
    buyer_partial_ki TEXT,                      -- Buyer's partial key image
    vendor_partial_ki TEXT,                     -- Vendor's partial key image

    -- Session lifecycle
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,                   -- 5 minute TTL
    status TEXT NOT NULL DEFAULT 'pending',     -- pending, signing, completed, expired

    -- Audit trail
    initiator_role TEXT NOT NULL,               -- 'buyer' or 'vendor' who started signing

    FOREIGN KEY (escrow_id) REFERENCES escrows(id)
);

-- Index for fast lookup by escrow_id
CREATE INDEX idx_signing_sessions_escrow_id ON signing_sessions(escrow_id);

-- Index for cleanup of expired sessions
CREATE INDEX idx_signing_sessions_expires_at ON signing_sessions(expires_at);

-- Index for status queries
CREATE INDEX idx_signing_sessions_status ON signing_sessions(status);

-- Ensure only one active session per escrow
CREATE UNIQUE INDEX idx_signing_sessions_active_escrow
ON signing_sessions(escrow_id)
WHERE status IN ('pending', 'signing');
