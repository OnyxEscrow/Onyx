-- Rollback FROST DKG migration
-- v0.46.0: Fixed to preserve ALL escrow columns (previous version would cause data loss!)

-- Drop indexes
DROP INDEX IF EXISTS idx_frost_dkg_state_round1;
DROP INDEX IF EXISTS idx_frost_dkg_state_round2;

-- Drop FROST DKG state table
DROP TABLE IF EXISTS frost_dkg_state;

-- Remove FROST columns from escrows
-- SQLite doesn't support DROP COLUMN, so we need to recreate the table
-- CRITICAL: Must preserve ALL existing columns except the 3 new FROST ones

-- Create temp table with ALL columns EXCEPT frost_enabled, frost_group_pubkey, frost_dkg_complete
CREATE TABLE escrows_backup AS SELECT
    id,
    order_id,
    buyer_id,
    vendor_id,
    arbiter_id,
    amount,
    multisig_address,
    status,
    created_at,
    updated_at,
    buyer_wallet_info,
    vendor_wallet_info,
    arbiter_wallet_info,
    transaction_hash,
    expires_at,
    last_activity_at,
    multisig_phase,
    multisig_state_json,
    multisig_updated_at,
    recovery_mode,
    buyer_temp_wallet_id,
    vendor_temp_wallet_id,
    arbiter_temp_wallet_id,
    dispute_reason,
    dispute_created_at,
    dispute_resolved_at,
    resolution_decision,
    vendor_signature,
    buyer_signature,
    unsigned_tx_hex,
    vendor_signed_at,
    buyer_signed_at,
    vendor_payout_address,
    buyer_refund_address,
    vendor_payout_set_at,
    buyer_refund_set_at,
    multisig_view_key,
    funding_commitment_mask,
    funding_tx_hash,
    funding_output_index,
    funding_global_index,
    ring_data_json,
    buyer_partial_key_image,
    vendor_partial_key_image,
    arbiter_partial_key_image,
    aggregated_key_image,
    partial_tx,
    partial_tx_initiator,
    completed_clsag,
    signing_started_at,
    signing_phase,
    funding_output_pubkey,
    funding_tx_pubkey,
    vendor_nonce_commitment,
    buyer_nonce_commitment,
    vendor_nonce_public,
    buyer_nonce_public,
    nonce_aggregated,
    first_signer_role,
    mu_p,
    mu_c,
    first_signer_had_r_agg,
    multisig_txset,
    signing_round,
    current_signer_id,
    partial_signed_txset,
    signing_initiated_at,
    broadcast_tx_hash
    -- Excluded: frost_enabled, frost_group_pubkey, frost_dkg_complete
FROM escrows;

-- Drop original table
DROP TABLE escrows;

-- Rename backup to escrows
ALTER TABLE escrows_backup RENAME TO escrows;

-- Recreate indexes (if any were on escrows)
CREATE INDEX IF NOT EXISTS idx_escrows_status ON escrows(status);
CREATE INDEX IF NOT EXISTS idx_escrows_buyer_id ON escrows(buyer_id);
CREATE INDEX IF NOT EXISTS idx_escrows_vendor_id ON escrows(vendor_id);
