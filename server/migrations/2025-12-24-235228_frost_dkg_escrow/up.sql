-- FROST DKG for 2-of-3 Threshold CLSAG (RFC 9591)

-- Add FROST columns to escrows table
ALTER TABLE escrows ADD COLUMN frost_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE escrows ADD COLUMN frost_group_pubkey TEXT;
ALTER TABLE escrows ADD COLUMN frost_dkg_complete BOOLEAN NOT NULL DEFAULT FALSE;

-- Create FROST DKG state table for tracking round packages
CREATE TABLE IF NOT EXISTS frost_dkg_state (
    escrow_id TEXT PRIMARY KEY NOT NULL,
    buyer_round1_package TEXT,
    vendor_round1_package TEXT,
    arbiter_round1_package TEXT,
    round1_complete BOOLEAN NOT NULL DEFAULT FALSE,
    buyer_to_vendor_round2 TEXT,
    buyer_to_arbiter_round2 TEXT,
    vendor_to_buyer_round2 TEXT,
    vendor_to_arbiter_round2 TEXT,
    arbiter_to_buyer_round2 TEXT,
    arbiter_to_vendor_round2 TEXT,
    round2_complete BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (escrow_id) REFERENCES escrows(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_frost_dkg_state_round1 ON frost_dkg_state(round1_complete);
CREATE INDEX IF NOT EXISTS idx_frost_dkg_state_round2 ON frost_dkg_state(round2_complete);
