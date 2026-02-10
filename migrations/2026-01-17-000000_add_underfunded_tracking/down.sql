-- Revert underfunded tracking columns

-- SQLite doesn't support DROP COLUMN directly in older versions
-- These columns will be removed by recreating the table in a fresh migration if needed

-- For SQLite 3.35.0+ (2021-03-12), DROP COLUMN is supported:
ALTER TABLE escrows DROP COLUMN balance_received;
ALTER TABLE escrows DROP COLUMN grace_period_ends_at;
ALTER TABLE escrows DROP COLUMN refund_requested_at;
