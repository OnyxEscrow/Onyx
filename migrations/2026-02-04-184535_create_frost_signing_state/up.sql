-- Create table for FROST signing state coordination (Phase 2 signing)
CREATE TABLE frost_signing_state (
    escrow_id TEXT PRIMARY KEY,

    -- TX data (computed once at initialization)
    tx_prefix_hash TEXT NOT NULL,
    clsag_message_hash TEXT NOT NULL,
    ring_data_json TEXT NOT NULL,
    pseudo_out TEXT,
    recipient_address TEXT NOT NULL,
    amount_atomic TEXT NOT NULL,

    -- Round 1: Nonce commitments (MuSig2-style)
    buyer_nonce_commitment TEXT,
    buyer_r_public TEXT,
    buyer_r_prime_public TEXT,
    vendor_nonce_commitment TEXT,
    vendor_r_public TEXT,
    vendor_r_prime_public TEXT,
    aggregated_r TEXT,
    aggregated_r_prime TEXT,

    -- Round 2: Partial signatures status
    buyer_partial_submitted BOOLEAN DEFAULT FALSE,
    vendor_partial_submitted BOOLEAN DEFAULT FALSE,
    arbiter_partial_submitted BOOLEAN DEFAULT FALSE,

    -- Round 3: Final aggregation
    aggregated_key_image TEXT,
    final_clsag_json TEXT,
    broadcasted_tx_hash TEXT,

    -- TX construction extras (needed for broadcast)
    bulletproof_bytes TEXT,
    pseudo_out_hex TEXT,
    tx_secret_key TEXT,
    ring_indices_json TEXT,

    -- Signing session state
    status TEXT NOT NULL DEFAULT 'initialized',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (escrow_id) REFERENCES escrows(id) ON DELETE CASCADE
);

-- Index for polling pending signatures
CREATE INDEX idx_frost_signing_status ON frost_signing_state(status);
CREATE INDEX idx_frost_signing_partial_ready ON frost_signing_state(
    buyer_partial_submitted,
    vendor_partial_submitted,
    arbiter_partial_submitted
);
