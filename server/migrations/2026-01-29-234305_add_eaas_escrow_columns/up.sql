-- Add EaaS columns to escrows table (idempotent - columns already exist)
-- These columns were added manually or in a previous partial run:
-- external_reference, description

SELECT 1; -- No-op migration - columns already exist
