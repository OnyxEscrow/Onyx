-- Rollback Arbiter Watchdog Fields Migration

-- SQLite does not support DROP COLUMN before version 3.35.0
-- For older versions, we need to recreate the table
-- Since NEXUS uses SQLite 3.35+, we can use DROP COLUMN directly

ALTER TABLE escrows DROP COLUMN buyer_release_requested;
ALTER TABLE escrows DROP COLUMN vendor_refund_requested;
ALTER TABLE escrows DROP COLUMN arbiter_auto_signed;
ALTER TABLE escrows DROP COLUMN arbiter_auto_signed_at;
ALTER TABLE escrows DROP COLUMN escalated_to_human;
ALTER TABLE escrows DROP COLUMN arbiter_frost_partial_sig;
