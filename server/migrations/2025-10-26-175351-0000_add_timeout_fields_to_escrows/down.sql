-- Rollback timeout fields from escrows table

-- Remove the timeout index first
DROP INDEX IF EXISTS idx_escrows_timeout;

-- Remove the timeout tracking columns
ALTER TABLE escrows DROP COLUMN last_activity_at;
ALTER TABLE escrows DROP COLUMN expires_at;
