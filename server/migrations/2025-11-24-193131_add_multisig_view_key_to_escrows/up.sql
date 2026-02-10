-- Add multisig_view_key column to escrows table
-- This stores the SHARED private view key for multisig address monitoring
-- The view key allows server to check balance but NOT spend funds

ALTER TABLE escrows ADD COLUMN multisig_view_key TEXT;
