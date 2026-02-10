-- Revert FROST signing state columns and tables

-- Drop new tables
DROP TABLE IF EXISTS recovery_codes;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS frost_dkg_state;
DROP TABLE IF EXISTS encrypted_relay;
DROP TABLE IF EXISTS dispute_evidence;

-- SQLite doesn't support DROP COLUMN directly in older versions
-- For SQLite 3.35.0+, we can use ALTER TABLE DROP COLUMN
-- These columns would need to be removed via table recreation for older SQLite

-- Note: In production, you'd want to recreate the table without these columns
-- For development, leaving them is acceptable as they're nullable

-- ALTER TABLE escrows DROP COLUMN signing_nonce_round;
-- ALTER TABLE escrows DROP COLUMN signing_round;
-- ALTER TABLE escrows DROP COLUMN broadcast_at;
-- ALTER TABLE escrows DROP COLUMN broadcast_tx_hash;
-- ALTER TABLE escrows DROP COLUMN first_signer_had_r_agg;
-- ALTER TABLE escrows DROP COLUMN nonce_aggregated;
-- ALTER TABLE escrows DROP COLUMN arbiter_nonce_public;
-- ALTER TABLE escrows DROP COLUMN buyer_nonce_public;
-- ALTER TABLE escrows DROP COLUMN vendor_nonce_public;
-- ALTER TABLE escrows DROP COLUMN arbiter_nonce_commitment;
-- ALTER TABLE escrows DROP COLUMN buyer_nonce_commitment;
-- ALTER TABLE escrows DROP COLUMN vendor_nonce_commitment;
-- ALTER TABLE escrows DROP COLUMN mu_c;
-- ALTER TABLE escrows DROP COLUMN mu_p;
-- ALTER TABLE escrows DROP COLUMN evidence_count;
-- ALTER TABLE escrows DROP COLUMN dispute_signing_pair;
-- ALTER TABLE escrows DROP COLUMN first_signer_role;
