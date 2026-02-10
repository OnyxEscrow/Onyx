-- Rollback shipped tracking columns
ALTER TABLE escrows DROP COLUMN shipped_at;
ALTER TABLE escrows DROP COLUMN auto_release_at;
ALTER TABLE escrows DROP COLUMN shipping_tracking;
