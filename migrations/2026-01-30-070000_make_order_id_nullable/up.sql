-- Make order_id nullable for EaaS escrows (standalone, no order required)
-- SQLite doesn't support ALTER COLUMN, so we recreate the table

-- Step 1: Create temporary table with nullable order_id and FROST columns
CREATE TABLE escrows_new (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT,  -- Now nullable for EaaS
    buyer_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    arbiter_id TEXT NOT NULL,
    amount BIGINT NOT NULL,
    multisig_address TEXT,
    status TEXT NOT NULL DEFAULT 'init',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    buyer_wallet_info BLOB,
    vendor_wallet_info BLOB,
    arbiter_wallet_info BLOB,
    transaction_hash TEXT,
    expires_at TIMESTAMP,
    last_activity_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    multisig_phase TEXT NOT NULL DEFAULT 'none',
    multisig_state_json TEXT,
    multisig_updated_at INTEGER NOT NULL DEFAULT 0,
    recovery_mode TEXT NOT NULL DEFAULT 'none',
    buyer_temp_wallet_id TEXT,
    vendor_temp_wallet_id TEXT,
    arbiter_temp_wallet_id TEXT,
    dispute_reason TEXT,
    dispute_created_at TIMESTAMP,
    dispute_resolved_at TIMESTAMP,
    resolution_decision TEXT,
    vendor_signature TEXT,
    buyer_signature TEXT,
    unsigned_tx_hex TEXT,
    vendor_signed_at INTEGER,
    buyer_signed_at INTEGER,
    vendor_payout_address TEXT,
    buyer_refund_address TEXT,
    vendor_payout_set_at INTEGER,
    buyer_refund_set_at INTEGER,
    multisig_view_key TEXT,
    funding_commitment_mask TEXT,
    funding_tx_hash TEXT,
    funding_output_index INTEGER,
    funding_global_index INTEGER,
    ring_data_json TEXT,
    buyer_partial_key_image TEXT,
    vendor_partial_key_image TEXT,
    arbiter_partial_key_image TEXT,
    aggregated_key_image TEXT,
    partial_tx TEXT,
    partial_tx_initiator TEXT,
    completed_clsag TEXT,
    signing_started_at INTEGER,
    signing_phase TEXT,
    balance_received BIGINT NOT NULL DEFAULT 0,
    grace_period_ends_at TIMESTAMP,
    refund_requested_at TIMESTAMP,
    external_reference TEXT,
    description TEXT,
    -- New FROST columns
    frost_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    frost_group_pubkey TEXT,
    frost_dkg_complete BOOLEAN NOT NULL DEFAULT FALSE,
    frost_dkg_state TEXT DEFAULT 'pending'
);

-- Step 2: Copy existing data (only columns that exist in old table)
INSERT INTO escrows_new (
    id, order_id, buyer_id, vendor_id, arbiter_id, amount, multisig_address,
    status, created_at, updated_at, buyer_wallet_info, vendor_wallet_info,
    arbiter_wallet_info, transaction_hash, expires_at, last_activity_at,
    multisig_phase, multisig_state_json, multisig_updated_at, recovery_mode,
    buyer_temp_wallet_id, vendor_temp_wallet_id, arbiter_temp_wallet_id,
    dispute_reason, dispute_created_at, dispute_resolved_at, resolution_decision,
    vendor_signature, buyer_signature, unsigned_tx_hex, vendor_signed_at,
    buyer_signed_at, vendor_payout_address, buyer_refund_address,
    vendor_payout_set_at, buyer_refund_set_at, multisig_view_key,
    funding_commitment_mask, funding_tx_hash, funding_output_index,
    funding_global_index, ring_data_json, buyer_partial_key_image,
    vendor_partial_key_image, arbiter_partial_key_image, aggregated_key_image,
    partial_tx, partial_tx_initiator, completed_clsag, signing_started_at,
    signing_phase, balance_received, grace_period_ends_at, refund_requested_at,
    external_reference, description
)
SELECT
    id, order_id, buyer_id, vendor_id, arbiter_id, amount, multisig_address,
    status, created_at, updated_at, buyer_wallet_info, vendor_wallet_info,
    arbiter_wallet_info, transaction_hash, expires_at, last_activity_at,
    multisig_phase, multisig_state_json, multisig_updated_at, recovery_mode,
    buyer_temp_wallet_id, vendor_temp_wallet_id, arbiter_temp_wallet_id,
    dispute_reason, dispute_created_at, dispute_resolved_at, resolution_decision,
    vendor_signature, buyer_signature, unsigned_tx_hex, vendor_signed_at,
    buyer_signed_at, vendor_payout_address, buyer_refund_address,
    vendor_payout_set_at, buyer_refund_set_at, multisig_view_key,
    funding_commitment_mask, funding_tx_hash, funding_output_index,
    funding_global_index, ring_data_json, buyer_partial_key_image,
    vendor_partial_key_image, arbiter_partial_key_image, aggregated_key_image,
    partial_tx, partial_tx_initiator, completed_clsag, signing_started_at,
    signing_phase, balance_received, grace_period_ends_at, refund_requested_at,
    external_reference, description
FROM escrows;

-- Step 3: Drop old table
DROP TABLE escrows;

-- Step 4: Rename new table
ALTER TABLE escrows_new RENAME TO escrows;

-- Step 5: Recreate indexes
CREATE INDEX idx_escrows_order ON escrows(order_id);
CREATE INDEX idx_escrows_buyer ON escrows(buyer_id);
CREATE INDEX idx_escrows_vendor ON escrows(vendor_id);
CREATE INDEX idx_escrows_arbiter ON escrows(arbiter_id);
CREATE INDEX idx_escrows_status ON escrows(status);
CREATE INDEX idx_escrows_frost_dkg ON escrows(frost_dkg_state);
