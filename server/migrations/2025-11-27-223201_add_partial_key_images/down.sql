-- Revert partial key image columns
-- Note: SQLite doesn't support DROP COLUMN before v3.35.0, so we recreate the table

-- This migration cannot be easily reverted in SQLite without table recreation
-- For development: delete the database and re-run migrations
-- For production: manually backup data before migration

-- If SQLite >= 3.35.0:
ALTER TABLE escrows DROP COLUMN buyer_partial_key_image;
ALTER TABLE escrows DROP COLUMN vendor_partial_key_image;
ALTER TABLE escrows DROP COLUMN arbiter_partial_key_image;
ALTER TABLE escrows DROP COLUMN aggregated_key_image;
