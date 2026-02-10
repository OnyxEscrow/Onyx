-- Add first_signer_role column to track which role signed first
-- This prevents race conditions when both parties sign within the same second
-- Values: 'buyer', 'vendor', or NULL (no one signed yet)
ALTER TABLE escrows ADD COLUMN first_signer_role TEXT DEFAULT NULL;
