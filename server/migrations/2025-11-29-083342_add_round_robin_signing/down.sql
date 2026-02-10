-- Remove round-robin signing columns

-- SQLite doesn't support DROP COLUMN directly in older versions
-- This migration is best-effort for SQLite compatibility
-- In production, these columns are permanent once added

-- For SQLite 3.35.0+ (March 2021):
ALTER TABLE escrows DROP COLUMN partial_tx;
ALTER TABLE escrows DROP COLUMN partial_tx_initiator;
ALTER TABLE escrows DROP COLUMN completed_clsag;
ALTER TABLE escrows DROP COLUMN signing_started_at;
ALTER TABLE escrows DROP COLUMN signing_phase;
