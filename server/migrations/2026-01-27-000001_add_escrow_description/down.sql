-- Remove external_reference and description columns
-- Note: SQLite doesn't support DROP COLUMN before 3.35.0
-- For older SQLite, this migration cannot be reverted cleanly

-- This is a best-effort rollback - may not work on older SQLite
ALTER TABLE escrows DROP COLUMN external_reference;
ALTER TABLE escrows DROP COLUMN description;
