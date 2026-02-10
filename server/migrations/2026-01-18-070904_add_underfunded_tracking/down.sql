-- SQLite doesn't support DROP COLUMN directly
-- This requires recreating the table without the columns
-- For simplicity, we'll use ALTER TABLE DROP COLUMN (SQLite 3.35.0+)

ALTER TABLE escrows DROP COLUMN balance_received;
ALTER TABLE escrows DROP COLUMN grace_period_ends_at;
ALTER TABLE escrows DROP COLUMN refund_requested_at;
