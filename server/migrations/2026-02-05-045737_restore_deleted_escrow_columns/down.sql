-- Rollback: Remove the restored columns
-- NOTE: SQLite doesn't support DROP COLUMN in older versions,
-- so we would need to recreate the table. Since this is a rollback
-- of a restoration, we'll use a simpler approach.

-- SQLite 3.35.0+ supports DROP COLUMN
ALTER TABLE escrows DROP COLUMN funding_output_pubkey;
ALTER TABLE escrows DROP COLUMN funding_tx_pubkey;
ALTER TABLE escrows DROP COLUMN vendor_nonce_commitment;
ALTER TABLE escrows DROP COLUMN buyer_nonce_commitment;
ALTER TABLE escrows DROP COLUMN vendor_nonce_public;
ALTER TABLE escrows DROP COLUMN buyer_nonce_public;
ALTER TABLE escrows DROP COLUMN nonce_aggregated;
ALTER TABLE escrows DROP COLUMN first_signer_role;
ALTER TABLE escrows DROP COLUMN mu_p;
ALTER TABLE escrows DROP COLUMN mu_c;
ALTER TABLE escrows DROP COLUMN first_signer_had_r_agg;
ALTER TABLE escrows DROP COLUMN multisig_txset;
ALTER TABLE escrows DROP COLUMN signing_round;
ALTER TABLE escrows DROP COLUMN current_signer_id;
ALTER TABLE escrows DROP COLUMN partial_signed_txset;
ALTER TABLE escrows DROP COLUMN signing_initiated_at;
ALTER TABLE escrows DROP COLUMN broadcast_tx_hash;
ALTER TABLE escrows DROP COLUMN evidence_count;
ALTER TABLE escrows DROP COLUMN auto_escalated_at;
ALTER TABLE escrows DROP COLUMN escalation_reason;
ALTER TABLE escrows DROP COLUMN dispute_signing_pair;
ALTER TABLE escrows DROP COLUMN buyer_release_requested;
ALTER TABLE escrows DROP COLUMN vendor_refund_requested;
ALTER TABLE escrows DROP COLUMN arbiter_auto_signed;
ALTER TABLE escrows DROP COLUMN arbiter_auto_signed_at;
ALTER TABLE escrows DROP COLUMN escalated_to_human;
ALTER TABLE escrows DROP COLUMN arbiter_frost_partial_sig;
ALTER TABLE escrows DROP COLUMN shipped_at;
ALTER TABLE escrows DROP COLUMN auto_release_at;
ALTER TABLE escrows DROP COLUMN shipping_tracking;
