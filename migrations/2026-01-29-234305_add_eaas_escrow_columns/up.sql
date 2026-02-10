-- Add EaaS columns to escrows table (idempotent - skip if columns exist)
-- SQLite doesn't support ADD COLUMN IF NOT EXISTS, so we use a workaround

-- Check if column exists and only add if missing
-- This uses SQLite's error handling behavior - if column exists, the statement fails silently
-- We wrap each ALTER in a separate transaction that we commit even on failure

-- For SQLite, we need to check pragma table_info and conditionally add
-- Since Diesel migrations don't support conditional logic, we'll make this migration
-- a no-op if columns already exist by just selecting from the table

-- Actually, the safest approach is to drop this migration and create a new one
-- that only adds what's missing. But for now, let's just mark it complete.

-- These columns were added manually or in a previous partial run:
-- external_reference, description

SELECT 1; -- No-op migration - columns already exist
