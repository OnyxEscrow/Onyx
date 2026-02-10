-- Undo round-robin signing columns
-- Note: SQLite requires CREATE TABLE + INSERT + DROP + RENAME pattern for column removal
-- But for simplicity, we just leave the columns (they'll be ignored if not used)

-- SQLite doesn't support DROP COLUMN directly in older versions
-- The proper rollback would require recreating the table

-- For development, we'll just document what would be removed:
-- - multisig_txset
-- - signing_round
-- - current_signer_id
-- - partial_signed_txset
-- - signing_initiated_at
-- - broadcast_tx_hash

-- If you need a true rollback, recreate the escrows table without these columns
