-- Remove funding_tx_pubkey column
-- SQLite doesn't support DROP COLUMN directly, so we need to recreate
-- For development, this is acceptable; production would need proper migration
ALTER TABLE escrows DROP COLUMN funding_tx_pubkey;
